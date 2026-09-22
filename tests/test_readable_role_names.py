"""Readable labels must neither collide nor alter the native authorization boundary."""
import copy
import re

import pytest

from policyweaver.fabric_native import (
    NativePolicyError, _role_namespace, plan_roles,
)
from policyweaver.role_naming import MAX_ROLE_NAME_LENGTH, ReaderRoleLabel
from test_fabric_native import (
    TABLE, TENANT, FabricMock, admin_role, assertions, client, reader, shard,
)
from test_native_watchdog import (
    NOW, READERS, Fabric, config, inspect_item, roles, run_watchdog,
)


def label(alias="pwtest078", unit="BNY Wealth", names=("BNYM Contact Owner Role",)):
    return {"alias": alias, "display_name": "Policy Weaver Test Reader",
            "business_unit": {"name": unit},
            "effective_roles": [{"name": name, "root_role_id": reader(900 + n)}
                                for n, name in enumerate(names)]}


def named_shard(count=2, generation=7, *, labels=None):
    return plan_roles(TENANT, [TABLE], [reader(n) for n in range(count)], generation,
        reader_labels=labels or {reader(n): label(f"pwtest{n + 1:03d}") for n in range(count)}).shards[0]


def test_name_budget_matches_sql_limit_and_keeps_alias_bu_identity():
    value = label(alias="pwtest078" * 10, unit="BNY Wealth " * 30,
                  names=("BNYM Contact Owner Role " * 80, "Basic", "ECRM Client"))
    role = named_shard(1, labels={reader(0): value}).roles[0]
    name = role["name"]
    assert len(name) == MAX_ROLE_NAME_LENGTH == 124
    assert re.fullmatch(r"[A-Za-z][A-Za-z0-9]+", name)
    assert "Plus2" in name and "pwtest078" in name and "BUBNYWealth" in name
    assert name.endswith("N" + _role_namespace("PolicyWeaver_")[2:] + "R" + reader(0).replace("-", ""))


def test_role_priority_and_root_dedup_are_deterministic():
    value = label(names=("Basic", "Other", "ECRM Adviser", "BNY Pershing", "BNYM Owner"))
    # Duplicate BU instance and team-derived grant count as the same root.
    value["effective_roles"].append({**value["effective_roles"][-1], "role_id": reader(990)})
    normalized = ReaderRoleLabel.from_mapping(value)
    assert normalized.role_names == ("BNYM Owner", "BNY Pershing", "ECRM Adviser", "Other", "Basic")
    reordered = copy.deepcopy(value)
    reordered["effective_roles"].reverse()
    assert ReaderRoleLabel.from_mapping(reordered) == normalized
    assert "BNYMOwnerPlus4" in normalized.readable_token()


@pytest.mark.parametrize("marker", ["(Deprecated)", "(Do Not Use)", "(Legacy)"])
def test_active_business_role_label_precedes_deprecated_bny_role_without_dropping_audit(marker):
    old = "BNYM Account Owner " + marker
    normalized = ReaderRoleLabel.from_mapping(label(names=(old, "ECRM Active Adviser", "Basic")))
    assert normalized.primary_role_name == "ECRM Active Adviser"
    assert old in normalized.audit()["role_names"] and len(normalized.role_names) == 3
    assert normalized.readable_token().startswith("ECRMActiveAdviserPlus2")


def test_punctuation_unicode_and_empty_labels_are_safe_with_audit_originals():
    value = label(alias="pwtest078@example.com", unit="财富", names=("BNYM rôle -- O'Brien / 名",))
    s = named_shard(1, labels={reader(0): value})
    name = s.roles[0]["name"]
    assert name.startswith("PWBNYMRoleOBrienpwtest078BUUnknownN")
    assert "example" not in name
    assert s.role_name_map[0]["role_names"] == ["BNYM rôle -- O'Brien / 名"]
    assert s.role_name_map[0]["business_unit_name"] == "财富"
    empty = ReaderRoleLabel.from_mapping({})
    assert empty.readable_token() == "UnroledReaderBUUnknown"


def test_identical_labels_remain_case_insensitively_unique_for_1000_readers():
    ids = [reader(n) for n in range(1000)]
    plan = plan_roles(TENANT, [TABLE], ids, 7, reader_labels={r: label() for r in ids})
    names = [role["name"] for s in plan.shards for role in s.roles]
    assert len({name.casefold() for name in names}) == 1000
    assert all(len(name) <= 124 for name in names)


def test_labels_change_names_only_and_never_members_rows_columns_or_absence():
    plain = shard(2).roles
    named = named_shard().roles
    assert [{k: v for k, v in role.items() if k != "name"} for role in plain] == [
        {k: v for k, v in role.items() if k != "name"} for role in named]
    plan = plan_roles(TENANT, [TABLE], [reader(0), reader(1)], 7,
        reader_labels={reader(0): label(), reader(1): label(names=("System Administrator",))},
        reader_table_paths={reader(0): [TABLE.path], reader(1): []})
    assert len(plan.shards[0].roles) == 1
    assert [r["entra_id"] for r in plan.as_dict()["shards"][0]["role_name_map"]] == [reader(0)]


@pytest.mark.parametrize("labels", [{}, {reader(0): {}}, {reader(0): {}, reader(1): "bad"},
    {reader(0): {}, reader(1): {"effective_roles": "bad"}},
    {reader(0): {}, reader(1): {"effective_roles": [{"name": "Bad", "root_role_id": "not-guid"}]}}])
def test_missing_or_malformed_provenance_is_rejected(labels):
    with pytest.raises(NativePolicyError):
        plan_roles(TENANT, [TABLE], [reader(0), reader(1)], 7, reader_labels=labels)


def test_ownership_accepts_old_and_new_case_variants_but_not_another_namespace():
    old, new = shard(1).roles[0], named_shard(1).roles[0]
    c = client(FabricMock())
    for role in (old, new):
        assert c._owned(role, "PolicyWeaver_")
        role["name"] = role["name"].upper()
        assert c._owned(role, "PolicyWeaver_")
        assert not c._owned(role, "OtherWeaver_")


@pytest.mark.parametrize("fault", ["short_guid", "long_label", "bad_punctuation", "damaged_marker", "member"])
def test_malformed_owned_names_or_wrong_member_are_never_adopted(fault):
    role = named_shard(1).roles[0]
    if fault == "short_guid":
        role["name"] = role["name"][:-1]
    elif fault == "long_label":
        role["name"] = "PW" + "A" * 73 + role["name"][-50:]
    elif fault == "bad_punctuation":
        role["name"] = "PW-" + role["name"][2:]
    elif fault == "damaged_marker":
        role["name"] = role["name"][:-33] + "Q" + role["name"][-32:]
    else:
        role["members"]["microsoftEntraMembers"][0]["objectId"] = reader(55)
    with pytest.raises(NativePolicyError):
        client(FabricMock())._owned(role, "PolicyWeaver_")


def test_rename_migrates_old_roles_atomically_preserving_unrelated_roles():
    other = admin_role(scope="/Tables/dbo/other")
    mock = FabricMock([other, *shard(2, generation=6).roles])
    target = named_shard()
    result = client(mock).publish(target, *assertions(target))
    assert result.control_plane_verified
    assert {r["name"] for r in mock.roles} == {other["name"], *(r["name"] for r in target.roles)}
    assert len(mock.roles) == 3


def test_renaming_same_generation_is_rejected_and_explicit_withdraw_handles_both_formats():
    mock = FabricMock(shard(2, generation=7).roles)
    with pytest.raises(NativePolicyError, match="immutable"):
        client(mock).dry_run(named_shard())
    mock = FabricMock([*shard(1, generation=6).roles, *named_shard(2).roles])
    result = client(mock).withdraw()
    assert result.control_plane_verified and mock.roles == []


def watchdog_named_roles(age=0):
    existing = roles(age=age)
    for n, role in enumerate(existing):
        role["name"] = plan_roles(TENANT, [TABLE], [READERS[n]], 1,
            ownership_prefix="pw_demo_", reader_labels={READERS[n]: label()}).shards[0].roles[0]["name"]
    return existing


@pytest.mark.parametrize("age,manual,status", [(60, False, "fresh_generation"),
    (3000, False, "withdrawn_expired_generation"), (3000, True, "manual_retention_active")])
def test_stateless_watchdog_keeps_or_withdraws_readable_roles_without_label_provenance(age, manual, status):
    fabric = Fabric(watchdog_named_roles(age))
    result = inspect_item(fabric, config(retention_mode="manual" if manual else "timed"),
                          inspect_only=False, now=lambda: NOW)
    assert result["status"] == status and not result["critical"]
    assert bool(fabric.roles) == (status != "withdrawn_expired_generation")


def test_readable_name_cannot_hide_modified_native_policy_from_watchdog():
    existing = watchdog_named_roles(60)
    existing[0]["decisionRules"][0]["constraints"]["rows"][0]["value"] += " OR 1=1"
    fabric = Fabric(existing)
    result = run_watchdog(config(retention_mode="manual"), credential=object(),
                          client_factory=lambda *a, **k: fabric, now=lambda: NOW)
    assert result["critical"] and not fabric.puts


def test_case_insensitive_duplicate_role_inventory_fails_closed():
    one = named_shard(1).roles[0]
    other = copy.deepcopy(one)
    other["name"] = one["name"].upper()
    with pytest.raises(NativePolicyError, match="duplicate"):
        client(FabricMock([one, other])).list_roles()
