"""Clone-first onboarding: discover explicitly scoped metadata and create local plans.

No command in this module provisions items, prepares business data, publishes
roles, grants access, or signs in. Configuration generation is intentionally a
separate, offline operation over an inventory and the customer's selections.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field, ValidationError, field_validator, model_validator

from .config import AdapterConfig, Settings, TableSelection
from .onboarding_discovery import DiscoveryError, discover_environment


class OnboardingError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _guid(value: str) -> str:
    result = UUID(value)
    if result.int == 0:
        raise ValueError("A nonzero GUID is required")
    return str(result)


def _upn(value: str) -> str:
    if (not re.fullmatch(r"[^\s@]+@[^\s@]+", value) or len(value) > 320
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError("An explicit user principal name is required")
    return value


class DiscoveryTable(Settings):
    name: str
    columns: tuple[str, ...] = ()

    _name = field_validator("name")(TableSelection.identifier.__func__)
    _columns = field_validator("columns")(TableSelection.column_names.__func__)


class OnboardingRequest(Settings):
    schema_version: Literal[1] = 1
    tenant_id: str
    environment_url: str
    operator_upn: str
    operator_entra_id: str | None = None
    environment_id: str | None = None
    workspace_id: str | None = None
    reader_upns: tuple[str, ...] = Field(default=(), max_length=1000)
    tables: tuple[DiscoveryTable, ...] = Field(default=(), max_length=3000)

    @field_validator("tenant_id", "operator_entra_id", "environment_id", "workspace_id")
    @classmethod
    def guid(cls, value):
        return _guid(value) if value is not None else None

    @field_validator("environment_url")
    @classmethod
    def environment(cls, value):
        if not re.fullmatch(r"https://[a-zA-Z0-9-]+\.crm\d*\.dynamics\.com/?", value):
            raise ValueError("Only a Microsoft public-cloud Dataverse HTTPS origin is supported")
        return value.rstrip("/").lower()

    @field_validator("operator_upn")
    @classmethod
    def upn(cls, value):
        return _upn(value)

    @field_validator("reader_upns")
    @classmethod
    def cohort(cls, value):
        normalized = tuple(_upn(v) for v in value)
        if len({v.casefold() for v in normalized}) != len(normalized):
            raise ValueError("Duplicate reader UPN")
        return normalized

    @model_validator(mode="after")
    def unique_tables(self):
        if len({t.name for t in self.tables}) != len(self.tables):
            raise ValueError("Duplicate discovery table")
        return self


class ClientSelections(Settings):
    schema_version: Literal[1] = 1
    workspace_id: str
    deployment_name: str
    reader_entra_ids: tuple[str, ...] = Field(min_length=1, max_length=1000)
    tables: tuple[TableSelection, ...] = Field(min_length=1, max_length=3000)
    required_access_paths: tuple[Literal["onelake", "spark", "sql", "direct_lake"], ...] = Field(min_length=1)
    identity_verification: Literal["fetchxml", "custom_api"] = "fetchxml"
    identity_api_name: str = "pw_ReadContext"
    identity_api_assembly_sha256: str | None = None
    retention_mode: Literal["timed", "manual"] = "timed"
    role_limit: int = Field(default=250, ge=2, le=1000, strict=True)
    reserved_roles: int = Field(default=10, ge=0, le=100, strict=True)
    tables_per_shard: int = Field(default=100, ge=1, le=500, strict=True)
    quota_exception_reference: str | None = Field(default=None, min_length=1, max_length=500)

    _workspace = field_validator("workspace_id")(AdapterConfig.guid.__func__)
    _deployment = field_validator("deployment_name")(AdapterConfig.deployment.__func__)
    _readers = field_validator("reader_entra_ids")(AdapterConfig.ids.__func__)
    _api = field_validator("identity_api_name")(AdapterConfig.custom_api_identifier.__func__)
    _digest = field_validator("identity_api_assembly_sha256")(AdapterConfig.assembly_digest.__func__)

    @model_validator(mode="after")
    def decisions(self):
        if len({t.name for t in self.tables}) != len(self.tables):
            raise ValueError("Duplicate selected table")
        if len(set(self.required_access_paths)) != len(self.required_access_paths):
            raise ValueError("Duplicate access path")
        if self.reserved_roles >= self.role_limit:
            raise ValueError("Role reserve must be below quota")
        if self.role_limit > 250 and not self.quota_exception_reference:
            raise ValueError("Record the target-specific Microsoft quota exception before using more than 250 roles")
        if self.quota_exception_reference is not None and (
                not self.quota_exception_reference.strip()
                or any(ord(c) < 32 for c in self.quota_exception_reference)):
            raise ValueError("Use a short support reference without credentials or control characters")
        if self.identity_verification == "custom_api" and not self.identity_api_assembly_sha256:
            raise ValueError("Custom API mode requires an independently trusted assembly digest")
        if self.identity_verification == "fetchxml" and self.identity_api_assembly_sha256:
            raise ValueError("An assembly digest applies only to custom_api verification")
        return self


REQUEST_TEMPLATE = {
    "schema_version": 1, "tenant_id": None, "environment_url": None,
    "operator_upn": None, "operator_entra_id": None, "environment_id": None,
    "workspace_id": None, "reader_upns": [], "tables": [],
}
SELECTIONS_TEMPLATE = {
    "schema_version": 1, "workspace_id": None, "deployment_name": None,
    "reader_entra_ids": [], "tables": [], "required_access_paths": [],
    "identity_verification": "fetchxml", "identity_api_name": "pw_ReadContext",
    "identity_api_assembly_sha256": None, "retention_mode": "timed",
    "role_limit": 250, "reserved_roles": 10, "tables_per_shard": 100,
    "quota_exception_reference": None,
}
ENV_TEMPLATE = """# Reference only: Policy Weaver does NOT load dotenv files.
# AdapterConfig JSON is the source of truth for deployment settings.
# No passwords, access tokens, client secrets, or real identities belong here.
# AZURE_CONFIG_DIR: optional isolated Azure CLI token cache (private directory).
# PYTHONUNBUFFERED=1: optional unbuffered terminal output.
# POLICYWEAVER_CONFIG: used by the local console; CLI still uses --config PATH.
# For local use: run az login --tenant YOUR_TENANT_ID (interactive MFA).
# Subscription is not required by the local Dataverse/Fabric adapter.
# Cloud deployment inputs (subscription/resource group/region/managed identity)
# belong in the reviewed infrastructure deployment, not this local template.
"""


def _json_bytes(value) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _digest(value) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _read_json(path: Path, limit: int = 50_000_000):
    if path.stat().st_size > limit:
        raise OnboardingError("input_file_too_large")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise OnboardingError("duplicate_json_key")
            result[key] = value
        return result
    value = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(OnboardingError("nonfinite_json_number")))
    if not isinstance(value, dict):
        raise OnboardingError("json_object_required")
    return value


def _exclusive_write(path: Path, data: bytes):
    # A customer inventory may contain personnel metadata. POSIX file mode is
    # private; Windows inherits the containing directory ACL, documented explicitly.
    import os
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def _new_directory(path: Path):
    # Do not merge into a live deployment, follow a link, or overwrite old input.
    if path.exists() or path.is_symlink():
        raise OnboardingError("output_directory_exists_choose_new_directory")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir(mode=0o700)


def initialize(path: Path):
    _new_directory(path)
    for name, data in (("request.json", _json_bytes(REQUEST_TEMPLATE)),
                       ("selections.json", _json_bytes(SELECTIONS_TEMPLATE)),
                       ("env.example", ENV_TEMPLATE.encode())):
        _exclusive_write(path / name, data)
    return {"status": "templates_created", "output_directory": str(path.resolve()),
            "required_before_discovery": ["tenant_id", "environment_url", "operator_upn"],
            "remote_changes": False}


def _inventory_guid(value):
    try:
        return _guid(value)
    except (ValueError, TypeError, AttributeError):
        raise OnboardingError("invalid_inventory_identifier") from None


def _index(rows, key, code):
    if not isinstance(rows, list) or any(not isinstance(r, dict) or key not in r for r in rows):
        raise OnboardingError(code)
    result = {}
    for row in rows:
        identity = row[key]
        if not isinstance(identity, str) or identity in result:
            raise OnboardingError(code)
        result[identity] = row
    return result


def create_configuration(request: OnboardingRequest, inventory: dict,
                         selections: ClientSelections, *, now: datetime | None = None):
    """Build a new-deployment config, never adopt an existing lakehouse or journal."""
    now = now or datetime.now(timezone.utc)
    if (inventory.get("schema_version") != 1 or inventory.get("cloud") != "public"
            or inventory.get("tenant_id") != request.tenant_id
            or inventory.get("environment_url") != request.environment_url):
        raise OnboardingError("inventory_request_scope_mismatch")
    try:
        observed = datetime.fromisoformat(inventory["observed_at"])
        completed = datetime.fromisoformat(inventory["completed_at"])
        if (observed.tzinfo is None or completed.tzinfo is None or completed < observed
                or (now - observed).total_seconds() > 86400 or (completed - now).total_seconds() > 60):
            raise ValueError
    except (KeyError, ValueError, TypeError):
        raise OnboardingError("inventory_stale_or_timestamp_invalid_rediscover") from None
    operator = inventory.get("operator")
    if (not isinstance(operator, dict) or not isinstance(operator.get("upn"), str)
            or operator["upn"].casefold() != request.operator_upn.casefold()
            or (request.operator_entra_id and operator.get("entra_id") != request.operator_entra_id)):
        raise OnboardingError("inventory_operator_mismatch")
    _inventory_guid(operator.get("entra_id"))
    _inventory_guid(operator.get("dataverse_id"))
    org = _inventory_guid(inventory.get("organization_id"))
    discovery = inventory.get("discovery", {})
    if (not isinstance(discovery, dict) or discovery.get("remote_methods") != ["GET"]
            or discovery.get("business_records_read") is not False
            or discovery.get("reader_candidates_are_selected") is not False
            or discovery.get("publication_boundary_verified") is not False
            or discovery.get("operator_permissions_verified") is not False):
        raise OnboardingError("invalid_inventory_provenance")
    env = inventory.get("environment_id", {})
    if not isinstance(env, dict) or env.get("value") != request.environment_id or env.get("verified") is not False:
        raise OnboardingError("inventory_environment_reference_mismatch")
    if request.workspace_id != selections.workspace_id:
        raise OnboardingError("set_request_workspace_and_rediscover")
    workspace = inventory.get("selected_workspace")
    if not isinstance(workspace, dict) or workspace.get("id") != selections.workspace_id:
        raise OnboardingError("selected_workspace_not_inventoried_rediscover")
    workspaces = _index(inventory.get("workspaces"), "id", "invalid_workspace_inventory")
    if workspaces.get(selections.workspace_id) != workspace:
        raise OnboardingError("workspace_inventory_mismatch")
    # Fabric provisioning will re-check scope, uniqueness and ownership receipts.
    # A capacity ID is informational, never interpreted as a sufficient SKU.
    readers = _index(inventory.get("readers"), "entra_id", "invalid_reader_inventory")
    seen_dv, seen_upn = set(), set()
    for reader in readers.values():
        _inventory_guid(reader["entra_id"])
        dv = _inventory_guid(reader.get("dataverse_id"))
        try:
            upn = _upn(reader.get("upn", "")).casefold()
        except (ValueError, TypeError):
            raise OnboardingError("invalid_reader_inventory") from None
        if (dv in seen_dv or upn in seen_upn or type(reader.get("accessmode")) is not int
                or reader["accessmode"] not in (0, 2)):
            raise OnboardingError("ambiguous_or_ineligible_reader_inventory")
        seen_dv.add(dv); seen_upn.add(upn)
    if request.reader_upns and seen_upn != {n.casefold() for n in request.reader_upns}:
        raise OnboardingError("inventory_reader_cohort_mismatch")
    if any(r not in readers for r in selections.reader_entra_ids):
        raise OnboardingError("selected_reader_not_in_inventory")
    if operator["entra_id"] in selections.reader_entra_ids:
        raise OnboardingError("operator_cannot_be_a_representative_consumer")

    tables = _index(inventory.get("tables"), "name", "invalid_table_inventory")
    requested = {t.name: t for t in request.tables}
    output_tables, notes = [], []
    for selection in selections.tables:
        table = tables.get(selection.name)
        if (not isinstance(table, dict) or selection.name not in requested
                or table.get("attributes_verified") is not True):
            raise OnboardingError("selected_table_attributes_unverified_rediscover_explicit_columns")
        _inventory_guid(table.get("read_privilege_id"))
        attrs = _index(table.get("attributes"), "logical_name", "invalid_attribute_inventory")
        properties = {}
        for logical, attribute in attrs.items():
            prop = attribute.get("property_name")
            kind = attribute.get("attribute_type")
            if (kind not in {"Boolean", "DateTime", "Decimal", "Double", "Integer", "BigInt", "Memo", "Money", "String",
                             "Uniqueidentifier", "Lookup", "Owner", "Customer", "Picklist", "State", "Status", "EntityName", "MultiSelectPicklist"}
                    or prop != (f"_{logical}_value" if kind in {"Lookup", "Owner", "Customer"} else logical)
                    or prop in properties or type(attribute.get("is_secured")) is not bool
                    or type(attribute.get("is_masked")) is not bool):
                raise OnboardingError("unsupported_or_unverified_attribute")
            properties[prop] = attribute
        if table.get("columns") != [a["property_name"] for a in attrs.values()]:
            raise OnboardingError("attribute_property_mapping_mismatch")
        resolved = []
        # Always include the primary key, explicitly documented in the plan.
        primary = table.get("primary_key")
        if primary not in attrs or attrs[primary]["attribute_type"] != "Uniqueidentifier":
            raise OnboardingError("selected_primary_key_unverified")
        request_columns = requested[selection.name].columns
        normalized_request = {c[1:-6] if c.startswith("_") and c.endswith("_value") else c for c in request_columns}
        if not request_columns or set(attrs) != normalized_request | {primary}:
            raise OnboardingError("inventory_columns_differ_from_request_rediscover")
        for column in (primary, *selection.columns):
            attr = attrs.get(column) or properties.get(column)
            if attr is None:
                raise OnboardingError("selected_column_not_in_verified_inventory")
            prop = attr["property_name"]
            if prop not in resolved:
                resolved.append(prop)
        selected_props = []
        for column in selection.columns:
            attr = attrs.get(column) or properties.get(column)
            selected_props.append(attr["property_name"])
        if len(set(selected_props)) != len(selected_props):
            raise OnboardingError("duplicate_selected_column_alias")
        output_tables.append(TableSelection(name=selection.name, columns=tuple(resolved)))
        notes.append({"name": selection.name, "primary_key": primary,
                      "primary_key_added": primary not in selection.columns, "columns": resolved,
                      "secured_columns": [c for c in resolved if properties[c]["is_secured"]],
                      "masked_columns": [c for c in resolved if properties[c]["is_masked"]],
                      "read_privilege_id": table["read_privilege_id"]})
    config = AdapterConfig(environment_url=request.environment_url, tenant_id=request.tenant_id,
        organization_id=org, workspace_id=selections.workspace_id, deployment_name=selections.deployment_name,
        authentication="azure_cli", identity_verification=selections.identity_verification,
        identity_api_name=selections.identity_api_name, identity_api_assembly_sha256=selections.identity_api_assembly_sha256,
        readers=selections.reader_entra_ids, discover_readers=False, excluded_readers=(), max_readers=1000,
        tables=tuple(output_tables), role_limit=selections.role_limit, reserved_roles=selections.reserved_roles,
        tables_per_shard=selections.tables_per_shard, serving_items={}, role_naming="readable",
        source_workers=1, retention_mode=selections.retention_mode, state_directory="state")
    # Reuse native planner validation for destination names, policy limits and
    # shards. Configuration validation alone only validates source identifiers.
    from .fabric_native import TableSpec, plan_roles, NativePolicyError
    try:
        native_plan = plan_roles(config.tenant_id,
            [TableSpec(f"/Tables/dbo/{config.deployment_name}_{t.name}", t.columns) for t in config.tables],
            config.readers, 1, role_limit=config.role_limit, reserve_roles=config.reserved_roles,
            max_table_permissions=config.tables_per_shard, ownership_prefix=config.role_prefix)
    except (ValueError, NativePolicyError):
        raise OnboardingError("native_policy_plan_invalid_check_destination_names_and_limits") from None
    audience_shards = math.ceil(len(config.readers) / (config.role_limit - config.reserved_roles))
    table_shards = math.ceil(len(config.tables) / config.tables_per_shard)
    items = [{"shard": f"a{a:03d}_t{t:03d}", "name": f"{config.deployment_name}_a{a:03d}_t{t:03d}", "id": None}
             for a in range(audience_shards) for t in range(table_shards)]
    if [i["shard"] for i in items] != [s.key for s in native_plan.shards]:
        raise OnboardingError("native_shard_plan_mismatch")
    inventory_items = inventory.get("lakehouses")
    if not isinstance(inventory_items, list):
        raise OnboardingError("missing_lakehouse_inventory")
    planned_names = {i["name"].casefold() for i in items}
    for item in inventory_items:
        if not isinstance(item, dict) or item.get("workspace_id") != selections.workspace_id:
            raise OnboardingError("lakehouse_inventory_scope_mismatch")
        if not isinstance(item.get("name"), str):
            raise OnboardingError("invalid_lakehouse_inventory")
        if item["name"].casefold() in planned_names:
            raise OnboardingError("serving_name_already_exists_choose_new_deployment_or_resume_original_config")
    plan = {
        "schema_version": 1, "status": "configured_not_provisioned", "created_at": now.isoformat(),
        "repository": "https://github.com/anlkorkut/policyweaver-dataverse",
        "request_sha256": _digest(request.model_dump(mode="json")), "inventory_sha256": _digest(inventory),
        "selections_sha256": _digest(selections.model_dump(mode="json")), "config_hash": config.fingerprint,
        "scope": {"tenant_id": config.tenant_id, "organization_id": org, "environment_url": config.environment_url,
                  "environment_id": request.environment_id, "environment_id_verified": False,
                  "workspace_id": config.workspace_id, "deployment_name": config.deployment_name},
        "operator": operator, "authentication": config.authentication,
        "operator_binding_scope": "discovery_only_recheck_active_cli_identity_before_operations",
        "reader_count": len(config.readers), "table_count": len(config.tables),
        "reader_bindings": [readers[r] for r in config.readers], "table_selections": notes,
        "required_access_paths": list(selections.required_access_paths),
        "capacity_plan": {"audience_shards": audience_shards, "table_shards": table_shards,
            "required_lakehouses": len(items), "planned_items": items, "role_limit": config.role_limit,
            "reserved_roles": config.reserved_roles, "quota_exception_reference": selections.quota_exception_reference,
            "quota_verified_live": False, "throughput_estimate_available": False},
        "retention_mode": config.retention_mode, "remote_changes": False,
        "boundary_verified": False, "source_permissions_verified": False, "production_certified": False,
        "native_expiry_self_enforcing": False,
        "remaining_gates": ["Verify operator impersonation, data/field access and reader identity proof.",
            "Provision new receipt-owned serving lakehouses; never adopt raw source items.",
            "Inspect OneLake enablement, inherited access and every requested consumer path.",
            "Grant exact consumers base item Read; avoid workspace access that bypasses isolation.",
            "Verify SQL User's identity mode and a supported human lakehouse owner when SQL is enabled.",
            "Prepare a fresh generation, inspect dry-run output and supply a fresh boundary attestation.",
            "For timed publication, have the independent watchdog running and monitored before granting consumer access.",
            "Publish, then compare actual reader results to Dataverse, including POA/POAA and negative controls.",
            "Measure refresh, publication, propagation and revocation under the client's load and outages."],
        "operating_limits": ["Discovery is metadata, not an authorization or permission attestation.",
            "Current preparation performs complete selected reader/table scans, not Dataverse security CDC.",
            "Readable role names summarize cumulative grants; they do not copy Dataverse roles one for one.",
            "Manual retention requires explicit operations for revocation; static OneLake roles never self-expire.",
            "Timed watchdog withdrawal depends on API availability and does not guarantee a hard 60-minute outage bound.",
            "Fully unattended publication needs a fresh external boundary inspector; this release does not implement one.",
            "State contains sensitive per-reader data; protect it with ACLs, encryption, backup and retention policy."],
    }
    return config, plan


NEXT_STEPS = """# Client deployment: next steps

This directory is private deployment material. Configuration was generated locally;
no cloud resource, role, grant or business-data snapshot has been created. The plan
records your selected scope and outstanding gates, not a production certificate.
Use the repository's docs/CLIENT-ONBOARDING.md and repository agent skill.

Run commands from this directory using the Python executable in the clone's .venv
(an absolute path or activate that environment first). The explicit config path
is required; environment variables do not replace its fields.

Discovery binds the expected UPN/OID, but runtime Azure CLI credentials are only
tenant-bound. Use an isolated AZURE_CONFIG_DIR and verify the active operator
account before each operation; plan.operator is an audit observation, not a
runtime account restriction.

```text
python -m policyweaver.onboarding validate --config policyweaver.config.json
python -m policyweaver.adapter_cli --config policyweaver.config.json doctor
```

Doctor reads source metadata and does not establish consumer parity. Resolve any
impersonation/field-access/identity-proof failure before provisioning. FetchXML
proof needs reader systemuser access; readers without that privilege require the
reviewed pw_ReadContext deployment and its trusted assembly hash, not broader roles
or a fallback to admin results. Reconfigure before provisioning if that choice changes.

Once creation of the plan's isolated serving items is within the authorized scope:

```text
python -m policyweaver.adapter_cli --config policyweaver.config.json --progress provision
```

Provision persists new item IDs and ownership receipts. Complete any portal actions
it reports and rerun provision as instructed. Do not reuse the source lakehouse.
SQL mode changes can interrupt queries across the workspace; coordinate the actual
scope. Complete base item Read sharing, owner/mode checks and bypass review.

Prepare AFTER provisioning because item IDs change the configuration fingerprint:

```text
python -m policyweaver.adapter_cli --config policyweaver.config.json --progress prepare
python -m policyweaver.adapter_cli --config policyweaver.config.json status
```

Preparation writes sensitive data to ./state. It does not publish. Use the generation
from this successful run in each following command; GENERATION is a placeholder.
Do not use run/worker as a read-only substitute: those commands invoke watchdog work.

```text
python -m policyweaver.adapter_cli --config policyweaver.config.json dry-run --generation GENERATION
python -m policyweaver.adapter_cli --config policyweaver.config.json boundary-template --generation GENERATION
```

Save boundary-template stdout as boundary.json. Inspect every boundary fact and fill
the exact template with real, current evidence. Never auto-mark the assertions true
or repeatedly change timestamps. Boundary evidence must be fresh at publication.

Before first timed publication, deploy and monitor the independent watchdog
according to deploy/README.md. Manual retention persists until explicit withdrawal
or replacement; it does not make old prepared data publishable or provide automatic
revocation.

```text
python -m policyweaver.adapter_cli --config policyweaver.config.json --progress publish --generation GENERATION --boundary boundary.json
```

Inspect persisted roles and Delta data, then qualify every selected path using actual
consumer sign-ins. Record POA/POAA evidence as table/row/field/value results against
Dataverse, including denied rows/NULL/masking and revocations. An admin query is not
an RLS test. Production scheduling, SLA and recovery require client qualification.

On authorized retirement or incident containment:

```text
python -m policyweaver.adapter_cli --config policyweaver.config.json withdraw
```

Never delete state/receipts to recover a run. Resume with this config, keep one writer,
and use the operations runbook for recovery. Do not commit this directory to Git.
"""


def configure(request_path: Path, inventory_path: Path, selections_path: Path, output_directory: Path):
    request = OnboardingRequest.model_validate(_read_json(request_path))
    inventory = _read_json(inventory_path)
    selections = ClientSelections.model_validate(_read_json(selections_path))
    config, plan = create_configuration(request, inventory, selections)
    _new_directory(output_directory)
    _exclusive_write(output_directory / "policyweaver.config.json", (config.model_dump_json(indent=2) + "\n").encode())
    _exclusive_write(output_directory / "deployment-plan.json", _json_bytes(plan))
    _exclusive_write(output_directory / "NEXT-STEPS.md", NEXT_STEPS.encode())
    # Preserve the exact non-secret input evidence locally for audit/reconfiguration.
    for name, value in (("request.json", request.model_dump(mode="json")), ("inventory.json", inventory),
                        ("selections.json", selections.model_dump(mode="json"))):
        _exclusive_write(output_directory / name, _json_bytes(value))
    return {"status": plan["status"], "output_directory": str(output_directory.resolve()),
            "config_hash": config.fingerprint, "reader_count": len(config.readers), "table_count": len(config.tables),
            "required_lakehouses": plan["capacity_plan"]["required_lakehouses"],
            "remote_changes": False, "boundary_verified": False, "production_certified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create inert request/selection templates in a NEW private directory")
    init.add_argument("--output-dir", type=Path, required=True)
    discovery = commands.add_parser("discover", help="GET-only tenant/account-bound metadata inventory; no business rows")
    discovery.add_argument("--request", type=Path, required=True)
    discovery.add_argument("--output", type=Path, required=True)
    for option, default in (("pages", 20), ("readers", 5000), ("tables", 3000), ("workspaces", 100), ("items", 200), ("seconds", 300)):
        discovery.add_argument("--max-" + option, type=int, default=default)
    build = commands.add_parser("configure", help="Create local config and reviewable plan; no cloud changes")
    for flag in ("request", "inventory", "selections"):
        build.add_argument("--" + flag, type=Path, required=True)
    build.add_argument("--output-dir", type=Path, required=True)
    validate = commands.add_parser("validate", help="Offline config validation only; does not attest cloud permissions")
    validate.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            result = initialize(args.output_dir)
        elif args.command == "discover":
            request = OnboardingRequest.model_validate(_read_json(args.request))
            if args.output.exists() or args.output.is_symlink():
                raise OnboardingError("inventory_output_exists_choose_new_file")
            from azure.identity import AzureCliCredential
            from .auth import CachedCredential
            # Avoid spawning Azure CLI for every metadata GET. BoundCredential
            # still validates cached claims before each request, by audience.
            credential = CachedCredential(AzureCliCredential(tenant_id=request.tenant_id))
            try:
                result = discover_environment(tenant_id=request.tenant_id, dataverse_url=request.environment_url,
                    operator_upn=request.operator_upn, operator_entra_id=request.operator_entra_id,
                    credential=credential, requested_tables={t.name: t.columns for t in request.tables},
                    workspace_id=request.workspace_id, environment_id=request.environment_id,
                    reader_upns=request.reader_upns or None, max_pages=args.max_pages, max_readers=args.max_readers,
                    max_tables=args.max_tables, max_workspaces=args.max_workspaces, max_items=args.max_items, max_seconds=args.max_seconds)
            finally:
                credential.close()
            args.output.parent.mkdir(parents=True, exist_ok=True)
            _exclusive_write(args.output, _json_bytes(result))
            result = {"status": "inventory_created", "output": str(args.output.resolve()),
                      "reader_candidates": len(result["readers"]), "tables": len(result["tables"]),
                      "workspaces": len(result["workspaces"]), "requests": result["discovery"]["requests"],
                      "remote_changes": False, "publication_boundary_verified": False}
        elif args.command == "configure":
            result = configure(args.request, args.inventory, args.selections, args.output_dir)
        else:
            # JSON strictness applies even to offline validation.
            config = AdapterConfig.model_validate(_read_json(args.config))
            result = {"status": "valid_configuration_only", "config_hash": config.fingerprint,
                "reader_count": len(config.readers), "table_count": len(config.tables),
                "serving_item_count": len(config.serving_items), "retention_mode": config.retention_mode,
                "cloud_permissions_verified": False, "boundary_verified": False, "production_certified": False}
        print(json.dumps(result, indent=2), flush=True)
        return 0
    except ValidationError as exc:
        # Pydantic's normal error includes input values. Emit only field paths and
        # type codes, so a pasted secret/connection string is never echoed back.
        errors = [{"field": ".".join(map(str, e["loc"])), "type": e["type"]}
                  for e in exc.errors(include_input=False, include_context=False, include_url=False)]
        print(json.dumps({"status": "failed", "error_code": "invalid_input", "fields": errors}), file=sys.stderr)
    except (OnboardingError, DiscoveryError) as exc:
        print(json.dumps({"status": "failed", "error_code": exc.code}), file=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"status": "failed", "error_code": "local_input_or_output_error"}), file=sys.stderr)
    except Exception:
        print(json.dumps({"status": "failed", "error_code": "onboarding_failed_inspect_local_prerequisites"}), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
