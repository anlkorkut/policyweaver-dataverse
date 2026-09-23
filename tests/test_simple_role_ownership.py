"""Simple visible names must not weaken ownership, replacement or withdrawal."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest

from policyweaver.config import AdapterConfig, TableSelection
from policyweaver.fabric_native import (
    BoundaryAttestation, DataReadyReceipt, FabricNativeClient, NativePolicyError,
    RoleSnapshot, TableSpec, plan_roles,
)
from policyweaver.native_watchdog import inspect_item, run_watchdog


def uid(value):
    return str(UUID(int=value))


TENANT, WORKSPACE, ITEM, ORG = (uid(n) for n in range(9001, 9005))
READERS = [uid(101), uid(102)]
NOW = 1_789_743_600.0
NOW_UTC = datetime.fromtimestamp(NOW, timezone.utc)
PREFIX = "pw_client_"


def config(retention_mode="timed"):
    return AdapterConfig(environment_url="https://client.crm.dynamics.com", tenant_id=TENANT,
        workspace_id=WORKSPACE, organization_id=ORG, deployment_name="pw_client",
        readers=tuple(READERS), tables=(TableSelection(name="account", columns=("accountid", "name")),),
        serving_items={"a000_t000": ITEM}, role_naming="user_business_role", retention_mode=retention_mode)


def shard(*, age=60, mode="user_business_role", prefix=PREFIX, alias="reader", two_tables=True):
    tables = [TableSpec(f"/Tables/dbo/{prefix}account", ("accountid", "name"))]
    if two_tables:
        tables.append(TableSpec(f"/Tables/dbo/{prefix}contact", ("contactid", "fullname")))
    labels = {reader: {"alias": f"{alias}{i:03d}", "business_unit": {"name": "Custody East"},
                      "effective_roles": [{"name": "Client Contact Reader", "root_role_id": uid(20)}]}
              for i, reader in enumerate(READERS, 1)}
    return plan_roles(TENANT, tables, READERS, int((NOW - age) * 1_000_000),
        ownership_prefix=prefix, reader_labels=None if mode == "legacy" else labels,
        role_naming=mode).shards[0]


class MemoryFabric(FabricNativeClient):
    """Exercise real ownership/merge/publication against an ETag-aware store."""
    tenant_id, workspace_id, item_id = TENANT, WORKSPACE, ITEM
    roles_url = "https://api.fabric.microsoft.com/test/dataAccessRoles"

    def __init__(self, roles):
        self.roles = copy.deepcopy(roles)
        self.etag, self.puts = '"initial"', []
        self.clock = lambda: NOW_UTC

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def get_item(self):
        return {"id": ITEM, "type": "Lakehouse"}

    def list_roles(self):
        return RoleSnapshot(tuple(copy.deepcopy(self.roles)), self.etag)

    def inspect_workspace_boundary(self, readers):
        return SimpleNamespace(closed=True)

    def _request(self, method, url, payload, etag):
        assert method == "PUT" and etag == self.etag
        assert url in {self.roles_url, self.roles_url + "?dryRun=true"}
        self.puts.append((url, copy.deepcopy(payload)))
        if not url.endswith("?dryRun=true"):
            self.roles = copy.deepcopy(payload["value"])
            self.etag = f'"version{len(self.puts)}"'


def assertions(plan):
    return (
        DataReadyReceipt(WORKSPACE, ITEM, plan.key, plan.generation, plan.plan_digest, "a" * 64,
            NOW_UTC - timedelta(minutes=5), NOW_UTC, NOW_UTC + timedelta(minutes=40)),
        BoundaryAttestation(WORKSPACE, ITEM, plan.reader_ids, NOW_UTC, True, True, "UserIdentity"),
    )


def foreign_role(name="UnrelatedAuditor"):
    return {"name": name, "kind": "Policy", "decisionRules": [{"effect": "Permit", "permission": [
        {"attributeName": "Path", "attributeValueIncludedIn": ["/Tables/dbo/unrelated"]},
        {"attributeName": "Action", "attributeValueIncludedIn": ["Read"]}]}],
        "members": {"microsoftEntraMembers": [{"tenantId": TENANT, "objectId": uid(888), "objectType": "User"}]}}


def test_human_label_rename_keeps_exact_ownership_and_withdrawal_preserves_foreign_roles():
    owned = shard(age=3000).roles
    owned[0]["name"] = "RenamedUsernameNewBusinessUnitNewSourceRole"
    other_namespace = shard(age=3000, prefix="pw_other_", alias="elsewhere").roles
    foreign = [foreign_role(), *other_namespace]
    fabric = MemoryFabric([*owned, *foreign])
    assert all(fabric._owned(role, PREFIX) for role in owned)
    assert not any(fabric._owned(role, PREFIX) for role in foreign)
    result = fabric.withdraw(PREFIX)
    assert result.status == "withdrawn_control_plane_verified"
    assert fabric.roles == foreign and len(fabric.puts) == 1


@pytest.mark.parametrize("fault", [
    "reader", "tenant", "service_principal", "duplicate_member", "extra_member_type",
    "extra_predicate", "row_path", "column_path", "helper_column", "write_action", "deny_effect",
    "missing_row", "extra_rule", "alter_one_marker",
])
def test_marked_policy_damage_blocks_publication_and_watchdog_without_any_put(fault):
    roles = shard(age=3000).roles
    role = roles[0]
    rule = role["decisionRules"][0]
    constraints = rule["constraints"]
    member = role["members"]["microsoftEntraMembers"][0]
    if fault == "reader":
        member["objectId"] = uid(777)
    elif fault == "tenant":
        member["tenantId"] = uid(777)
    elif fault == "service_principal":
        member["objectType"] = "ServicePrincipal"
    elif fault == "duplicate_member":
        role["members"]["microsoftEntraMembers"].append(copy.deepcopy(member))
    elif fault == "extra_member_type":
        role["members"]["fabricItemMembers"] = []
    elif fault == "extra_predicate":
        constraints["rows"][0]["value"] += " OR 1 = 1"
    elif fault == "row_path":
        constraints["rows"][0]["tablePath"] = "/Tables/dbo/unrelated"
    elif fault == "column_path":
        constraints["columns"][0]["tablePath"] = "/Tables/dbo/unrelated"
    elif fault == "helper_column":
        constraints["columns"][0]["columnNames"].append("__pw_reader")
    elif fault == "write_action":
        rule["permission"][1]["attributeValueIncludedIn"].append("Write")
    elif fault == "deny_effect":
        rule["effect"] = "Deny"
    elif fault == "missing_row":
        constraints["rows"].pop()
    elif fault == "extra_rule":
        role["decisionRules"].append(copy.deepcopy(rule))
    elif fault == "alter_one_marker":
        constraints["rows"][0]["value"] = constraints["rows"][0]["value"].replace("PolicyWeaverOwnerV1", "OtherOwnerV1")
    fabric = MemoryFabric(roles)
    with pytest.raises(NativePolicyError):
        fabric.dry_run(shard(age=0))
    assert not fabric.puts
    result = run_watchdog(config(), credential=object(), client_factory=lambda *_a, **_k: fabric, now=lambda: NOW)
    assert result["critical"] and result["items"]["a000_t000"]["status"] == "critical_watchdog_error"
    assert not fabric.puts and fabric.roles == roles


@pytest.mark.parametrize("change", ["remove", "alter"])
def test_missing_or_changed_ownership_marker_is_foreign_and_reports_critical_overlap(change):
    roles = shard(age=3000).roles
    for role in roles:
        for row in role["decisionRules"][0]["constraints"]["rows"]:
            expression = row["value"]
            if change == "alter":
                row["value"] = expression.replace("PolicyWeaverOwnerV1", "OtherOwnerV1")
            else:
                before, remaining = expression.split(" AND __pw_reader <>", 1)
                row["value"] = before + " AND __pw_generation" + remaining.split(" AND __pw_generation", 1)[1]
    fabric = MemoryFabric(roles)
    assert not any(fabric._owned(role, PREFIX) for role in roles)
    result = inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)
    assert result["status"] == "no_owned_roles" and result["critical"] and result["unmanaged_overlap"]
    assert not fabric.puts
    with pytest.raises(NativePolicyError, match="Unmanaged overlapping"):
        fabric.dry_run(shard(age=0))
    assert not fabric.puts and fabric.roles == roles


def test_unmanaged_case_insensitive_display_name_collision_blocks_before_put():
    planned = shard(age=0)
    other = foreign_role(planned.roles[0]["name"].upper())
    fabric = MemoryFabric([other])
    with pytest.raises(NativePolicyError, match="collides with an unmanaged"):
        fabric.dry_run(planned)
    assert fabric.roles == [other] and not fabric.puts


@pytest.mark.parametrize("age,retention,expected,withdraw", [
    (60, "timed", "fresh_generation", False),
    (2700, "timed", "withdrawn_expired_generation", True),
    (3000, "timed", "withdrawn_expired_generation", True),
    (-5, "timed", "withdrawn_future_generation_timestamp", True),
    (-5, "manual", "withdrawn_future_generation_timestamp", True),
    (3000, "manual", "manual_retention_active", False),
    (60 * 60 * 24 * 365, "manual", "manual_retention_active", False),
])
def test_simple_roles_obey_stateless_temporal_rules_and_preserve_foreign_roles(age, retention, expected, withdraw):
    other = foreign_role()
    roles = shard(age=age).roles
    fabric = MemoryFabric([*roles, other])
    result = inspect_item(fabric, config(retention), inspect_only=False, now=lambda: NOW)
    assert result["status"] == expected and not result["critical"]
    assert result["engine_revocation_verified"] is False
    assert bool(fabric.puts) == withdraw
    assert fabric.roles == ([other] if withdraw else [*roles, other])


@pytest.mark.parametrize("within_role", [False, True])
@pytest.mark.parametrize("retention", ["timed", "manual"])
def test_mixed_simple_generations_withdraw_even_if_every_timestamp_is_fresh(within_role, retention):
    roles = shard(age=60).roles
    alternate = shard(age=120).roles
    if within_role:
        roles[0]["decisionRules"][0]["constraints"]["rows"][1] = alternate[0]["decisionRules"][0]["constraints"]["rows"][1]
    else:
        roles[1] = alternate[1]
    fabric = MemoryFabric(roles)
    result = inspect_item(fabric, config(retention), inspect_only=False, now=lambda: NOW)
    assert result["status"] == "withdrawn_mixed_generations"
    assert len(fabric.puts) == 1 and not fabric.roles


@pytest.mark.parametrize("previous_mode", ["legacy", "readable", "user_business_role"])
def test_naming_migration_requires_new_generation_and_preserves_unrelated_roles(previous_mode):
    previous = shard(age=60, mode=previous_mode, alias="oldreader").roles
    other = foreign_role()
    fabric = MemoryFabric([*previous, other])
    same_generation = shard(age=60, alias="newreader")
    with pytest.raises(NativePolicyError, match="generation is immutable"):
        fabric.publish(same_generation, *assertions(same_generation))
    assert not fabric.puts and fabric.roles == [*previous, other]
    fresh = shard(age=0, alias="newreader")
    result = fabric.publish(fresh, *assertions(fresh))
    assert result.status == "published_control_plane_verified"
    assert fabric.roles == [other, *fresh.roles]
    assert len(fabric.puts) == 2  # One dry run, one conditional publication.


def test_known_fabric_get_normalization_preserves_marked_ownership():
    roles = shard(age=3000).roles
    for index, role in enumerate(roles):
        role["members"]["microsoftEntraMembers"][0].pop("objectType")
        role["eTag"] = "server-assigned"
        role["id"] = uid(990 + index)
        for row in role["decisionRules"][0]["constraints"]["rows"]:
            row["type"] = "Fabric"
    fabric = MemoryFabric(roles)
    result = inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)
    assert result["status"] == "withdrawn_expired_generation" and not fabric.roles


def collision_labels(fault):
    labels = {reader: {"alias": "pwtest001", "business_unit": {"name": "Custody East"},
                      "effective_roles": [{"name": "Contact Owner", "root_role_id": uid(20 + i)}]}
              for i, reader in enumerate(READERS)}
    first, second = (labels[reader] for reader in READERS)
    if fault == "action_stripping":
        first["effective_roles"][0]["name"] = "Contact Read"
        second["effective_roles"][0]["name"] = "Contact Write"
    elif fault == "punctuation":
        first["alias"] = "pw.test-001"
    elif fault == "diacritic":
        first["alias"] = "pwtestJos\u00e9"
        second["alias"] = "pwtestJose"
    elif fault == "casefold":
        first["alias"] = "PWTEST001"
    elif fault == "username_truncation":
        first["alias"], second["alias"] = "a" * 32 + "1", "a" * 32 + "2"
    elif fault == "business_unit_truncation":
        first["business_unit"]["name"] = "Custody " * 20 + "East"
        second["business_unit"]["name"] = "Custody " * 20 + "West"
    elif fault == "role_truncation":
        first["effective_roles"][0]["name"] = "X" * 200 + "Alpha"
        second["effective_roles"][0]["name"] = "X" * 200 + "Beta"
    else:
        raise AssertionError("unknown fixture")
    return labels


@pytest.mark.parametrize("fault", ["action_stripping", "punctuation", "diacritic", "casefold",
                                  "username_truncation", "business_unit_truncation", "role_truncation"])
def test_planner_rejects_label_collisions_before_creating_an_ambiguous_policy(fault):
    with pytest.raises(NativePolicyError, match="collide after normalization or truncation"):
        plan_roles(TENANT, [TableSpec(f"/Tables/dbo/{PREFIX}account", ("accountid",))], READERS,
            int(NOW * 1_000_000), ownership_prefix=PREFIX, reader_labels=collision_labels(fault),
            role_naming="user_business_role")


def test_collision_check_uses_only_roles_that_will_be_emitted_and_never_merges_readers():
    table = TableSpec(f"/Tables/dbo/{PREFIX}account", ("accountid",))
    labels = collision_labels("action_stripping")
    allowed = {READERS[0]: [table.path], READERS[1]: []}
    plan = plan_roles(TENANT, [table], READERS, int(NOW * 1_000_000), ownership_prefix=PREFIX,
        reader_labels=labels, reader_table_paths=allowed, role_naming="user_business_role")
    assert len(plan.shards[0].roles) == 1
    role = plan.shards[0].roles[0]
    assert role["members"]["microsoftEntraMembers"][0]["objectId"] == READERS[0]
    assert role["name"] == "pwtest001CustodyEastContact"
    # A later grant to the second identity must stop for a naming collision;
    # it cannot fold two distinct readers into a shared native policy.
    allowed[READERS[1]] = [table.path]
    with pytest.raises(NativePolicyError, match="collide"):
        plan_roles(TENANT, [table], READERS, int((NOW + 1) * 1_000_000), ownership_prefix=PREFIX,
            reader_labels=labels, reader_table_paths=allowed, role_naming="user_business_role")


def test_identical_labels_on_different_table_shards_remain_independent_reader_roles():
    account = TableSpec(f"/Tables/dbo/{PREFIX}account", ("accountid",))
    contact = TableSpec(f"/Tables/dbo/{PREFIX}contact", ("contactid",))
    allowed = {READERS[0]: [account.path], READERS[1]: [contact.path]}
    plan = plan_roles(TENANT, [account, contact], READERS, int(NOW * 1_000_000), ownership_prefix=PREFIX,
        reader_labels=collision_labels("action_stripping"), reader_table_paths=allowed,
        max_table_permissions=1, role_naming="user_business_role")
    assert len(plan.shards) == 2 and [len(item.roles) for item in plan.shards] == [1, 1]
    assert [item.roles[0]["members"]["microsoftEntraMembers"][0]["objectId"] for item in plan.shards] == READERS


@pytest.mark.parametrize("path", ["/Tables/account", "/Tables/other/pw_client_account",
    "/Tables/dbo/account", "/Tables/dbo/pw_other_account", "/Tables/dbo/pw_clientx_account",
    "/Tables/dbo/pw_client_Account"])
def test_simple_named_plans_require_canonical_deployment_owned_table_scope(path):
    with pytest.raises(NativePolicyError, match="canonical deployment-owned table paths"):
        plan_roles(TENANT, [TableSpec(path, ("accountid",))], READERS, int(NOW * 1_000_000),
            ownership_prefix=PREFIX, reader_labels=collision_labels("action_stripping"),
            role_naming="user_business_role")
