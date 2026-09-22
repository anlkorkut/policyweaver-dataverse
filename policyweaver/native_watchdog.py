"""Independent, stateless retention watchdog for native OneLake policies.

This process needs Fabric credentials and deployment configuration, not the
publisher host, SQLite journal, Dataverse access, or staged business records.
Generation numbers are UTC Unix microseconds, as emitted by Journal.create.
Timed retention withdraws expired generations. Explicit manual retention keeps
valid owned generations regardless of age, within this configuration's exact
deployment namespace and item inventory; integrity checks remain active.

Run every five minutes on an independent host. Native policies do not expire
themselves: a Fabric API outage or an engine cache can still prevent bounded
revocation. Structured critical results must feed an external alerting system.
No notification service is silently configured by this module.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from .config import AdapterConfig, load_config
from .fabric_native import (
    FabricNativeClient, FabricRequestError, NativePolicyError, RoleSnapshot,
    TableSpec, _reader_role, _semantic_roles,
)

MIN_GENERATION = 1_577_836_800_000_000  # 2020-01-01 UTC
MAX_GENERATION = 4_102_444_800_000_000  # 2100-01-01 UTC (exclusive)


class WatchdogError(RuntimeError):
    """An owned namespace cannot be safely interpreted or modified."""

    @property
    def code(self):
        value = str(self)
        return value if re.fullmatch(r"[a-z0-9_]{1,100}", value) else "watchdog_error"


@dataclass(frozen=True)
class Assessment:
    owned_names: frozenset[str]
    generations: tuple[int, ...]
    reason: str
    requires_withdrawal: bool
    unmanaged_overlap: bool


def _overlapping_unmanaged(role, paths):
    """Report any unmanaged permit affecting the serving surface, without deleting it."""
    rules = role.get("decisionRules")
    if not isinstance(rules, list):
        return True
    for rule in rules:
        if not isinstance(rule, dict):
            return True
        scopes = rule.get("permission", [])
        found = False
        for scope in scopes:
            if not isinstance(scope, dict):
                return True
            if scope.get("attributeName") == "Path":
                found = True
                values = scope.get("attributeValueIncludedIn")
                if not isinstance(values, list) or not values:
                    return True
                for value in values:
                    if not isinstance(value, str) or "*" in value:
                        return True
                    path = "/" + value.strip("/").lower()
                    if any(p == path or p.startswith(path + "/") or path.startswith(p + "/") for p in paths):
                        return True
        if not found:
            return True
    return False


def assess(snapshot: RoleSnapshot, fabric: FabricNativeClient, config: AdapterConfig,
           now: float) -> Assessment:
    """Require the exact policy encoding; never interpret arbitrary SQL."""
    owned, others, generations, paths = set(), [], set(), set()
    configured_paths = {f"/tables/dbo/{config.deployment_name}_{t.name}".lower() for t in config.tables}
    owned_table_path = re.compile(r"/Tables/dbo/" + re.escape(config.deployment_name) + r"_[a-z][a-z0-9_]{0,99}\Z")
    for role in snapshot.roles:
        if not fabric._owned(role, config.role_prefix):
            others.append(role)
            continue
        name = role["name"]
        reader = role["members"]["microsoftEntraMembers"][0]["objectId"]
        rules = role.get("decisionRules")
        if not isinstance(rules, list) or not rules:
            raise WatchdogError("unknown_owned_policy_shape")
        tables, role_generations, expected_rules = [], set(), []
        for rule in rules:
            if not isinstance(rule, dict):
                raise WatchdogError("unknown_owned_policy_shape")
            constraints = rule.get("constraints", {})
            if not isinstance(constraints, dict):
                raise WatchdogError("unknown_owned_policy_shape")
            rows, columns = constraints.get("rows"), constraints.get("columns")
            if (not isinstance(rows, list) or not rows or not isinstance(columns, list)
                    or len(rows) != len(columns)):
                raise WatchdogError("unknown_owned_policy_shape")
            rule_tables, rule_generations = [], []
            for row, column in zip(rows, columns):
                if not isinstance(row, dict) or not isinstance(column, dict):
                    raise WatchdogError("unknown_owned_policy_shape")
                expression = row.get("value", "")
                match = re.search(r"\b__pw_generation = (-?[0-9]+)$", expression) if isinstance(expression, str) else None
                if not match:
                    raise WatchdogError("unknown_owned_generation_encoding")
                generation = int(match[1])
                role_generations.add(generation)
                rule_generations.append(generation)
                table = TableSpec(row.get("tablePath"), column.get("columnNames", ()))
                # Removed source tables must still expire. Only this deployment's
                # canonical namespace is eligible for watchdog interpretation.
                if not owned_table_path.fullmatch(table.path):
                    raise WatchdogError("owned_policy_table_scope_outside_deployment")
                rule_tables.append(table)
                tables.append(table)
                paths.add(table.path.lower())
            canonical = _reader_role(config.tenant_id, reader, tuple(rule_tables),
                                     rule_generations[0], config.role_prefix)["decisionRules"][0]
            # Recognize otherwise canonical mixed generations for withdrawal,
            # never as fresh. Regenerate every predicate without trusting SQL.
            canonical["constraints"]["rows"] = [
                _reader_role(config.tenant_id, reader, (table,), generation,
                             config.role_prefix)["decisionRules"][0]["constraints"]["rows"][0]
                for table, generation in zip(rule_tables, rule_generations)]
            expected_rules.append(canonical)
        # Accept the legacy one-table-per-rule encoding solely for assessment
        # and withdrawal. The publisher emits only one rule with all paths.
        expected = _reader_role(config.tenant_id, reader, (), 1, config.role_prefix)
        # _owned already bound either supported name format to this exact
        # deployment, tenant and full reader GUID. Human labels are not needed
        # by this stateless watchdog and may never change the policy checks.
        expected["name"] = name
        expected["decisionRules"] = expected_rules
        if _semantic_roles([role]) != _semantic_roles([expected]):
            raise WatchdogError("unknown_owned_policy_shape")
        if len({t.path.lower() for t in tables}) != len(tables):
            raise WatchdogError("duplicate_owned_table_rules")
        owned.add(name)
        generations.update(role_generations)
    # Include configured table paths even when all owned roles were withdrawn.
    paths.update(configured_paths)
    overlap = any(_overlapping_unmanaged(r, paths) for r in others)
    if not owned:
        return Assessment(frozenset(), (), "no_owned_roles", False, overlap)
    values = tuple(sorted(generations))
    if any(g < MIN_GENERATION or g >= MAX_GENERATION for g in values):
        reason = "invalid_generation_timestamp"
    elif any(g / 1_000_000 > now for g in values):
        reason = "future_generation_timestamp"
    elif len(values) != 1:
        reason = "mixed_generations"
    elif config.retention_mode == "manual":
        # Retention is an explicit controller configuration, never inferred
        # from a distant expiry timestamp or an arbitrary policy annotation.
        # The checks above still reject invalid/mixed/future generations.
        return Assessment(frozenset(owned), values, "manual_retention_active", False, overlap)
    elif values[0] / 1_000_000 + config.generation_lifetime_seconds <= now:
        reason = "expired_generation"
    else:
        return Assessment(frozenset(owned), values, "fresh_generation", False, overlap)
    return Assessment(frozenset(owned), values, reason, True, overlap)


def inspect_item(fabric, config, *, inspect_only, now=time.time):
    snapshot = fabric.list_roles()
    assessment = assess(snapshot, fabric, config, now())
    result = {"status": assessment.reason, "critical": assessment.unmanaged_overlap,
              "retention_mode": config.retention_mode,
              "age_based_withdrawal_enabled": config.retention_mode == "timed",
              "owned_role_count": len(assessment.owned_names),
              "unmanaged_overlap": assessment.unmanaged_overlap,
              "mutation_attempted": False, "control_plane_verified": False,
              "engine_revocation_verified": False}
    if not assessment.requires_withdrawal:
        return result
    if inspect_only:
        result.update(status="would_withdraw_" + assessment.reason, critical=True)
        return result
    remaining = [copy.deepcopy(r) for r in snapshot.roles if r["name"] not in assessment.owned_names]
    result["mutation_attempted"] = True
    try:
        # Do NOT call fabric.withdraw(): its second snapshot could include a new
        # fresh generation published after this stale assessment.
        fabric._request("PUT", fabric.roles_url, payload={"value": remaining}, etag=snapshot.etag)
    except FabricRequestError as exc:
        if exc.status_code != 412:
            raise
        current = assess(fabric.list_roles(), fabric, config, now())
        result.update(status="concurrent_publication_preserved",
                      critical=current.requires_withdrawal or current.unmanaged_overlap,
                      owned_role_count=len(current.owned_names), unmanaged_overlap=current.unmanaged_overlap)
        return result
    after = fabric.list_roles()
    if _semantic_roles(after.roles) != _semantic_roles(remaining):
        # Another publication can legitimately follow withdrawal. Assess it but
        # never overwrite it using an ETag that was not reviewed.
        current = assess(after, fabric, config, now())
        result.update(status="withdrawal_followed_by_concurrent_change",
                      critical=current.requires_withdrawal or current.unmanaged_overlap,
                      owned_role_count=len(current.owned_names), unmanaged_overlap=current.unmanaged_overlap)
        return result
    result.update(status="withdrawn_" + assessment.reason, control_plane_verified=True,
                  critical=assessment.unmanaged_overlap)
    return result


def run_watchdog(config: AdapterConfig, *, inspect_only=False, credential=None,
                 client_factory=FabricNativeClient, now=time.time):
    """Visit every managed item, continuing after individual failures.

    Returned critical events contain item/shard identifiers and error classes,
    never tokens, usernames, role members, SQL text, or Dataverse records.
    """
    owns_credential = credential is None
    if owns_credential:
        from .runtime import make_credential
        credential = make_credential(config)
    results = {}
    try:
        for shard_key, item_id in sorted(config.serving_items.items()):
            try:
                with client_factory(config.tenant_id, config.workspace_id, item_id, credential=credential) as fabric:
                    result = inspect_item(fabric, config, inspect_only=inspect_only, now=now)
            except Exception as exc:
                result = {"status": "critical_watchdog_error", "critical": True,
                          "error_type": type(exc).__name__, "error_code": getattr(exc, "code", type(exc).__name__),
                          "control_plane_verified": False,
                          "engine_revocation_verified": False}
            results[shard_key] = {"item_id": item_id, **result}
    finally:
        if owns_credential:
            credential.close()
    critical = not results or any(r["critical"] for r in results.values())
    return {"status": "critical" if critical else "ok", "critical": critical,
            "retention_mode": config.retention_mode,
            "inspected_at": datetime.fromtimestamp(now(), timezone.utc).isoformat(),
            "inspect_only": inspect_only, "items": results,
            "independent_of_publisher_state": True, "engine_revocation_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", "--configfile", dest="config")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true", help="Inspect retention and apply required owned-policy withdrawals once")
    mode.add_argument("--inspect", action="store_true", help="Read and assess only; do not mutate")
    args = parser.parse_args(argv)
    try:
        if args.config:
            config = load_config(args.config)
        else:
            raw = os.environ.get("POLICYWEAVER_CONFIG_JSON")
            if not raw:
                raise WatchdogError("missing_configuration")
            config = AdapterConfig.model_validate_json(raw)
        result = run_watchdog(config, inspect_only=args.inspect)
        print(json.dumps(result, sort_keys=True))
        return 2 if result["critical"] else 0
    except Exception as exc:
        print(json.dumps({"status": "critical", "critical": True, "error_type": type(exc).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
