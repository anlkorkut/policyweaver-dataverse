"""Local synthetic specification/regression probes. Never calls Dataverse/Fabric.

Independent set-based oracle for direct privilege depth; characterization tests
make implementation limitations explicit rather than claiming live parity.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from itertools import product
from math import ceil
from uuid import UUID

import pytest
from pydantic import ValidationError

from policyweaver.engine import AccessEngine
from policyweaver.models import Snapshot
from policyweaver.planner import plan


NOW = datetime(2026, 9, 18, 12, tzinfo=timezone.utc)


def uid(number):
    return str(UUID(int=number))


def fixture():
    return {
        "tenant_id": uid(9000), "organization_id": uid(9001),
        "observed_at": NOW, "valid_until": NOW + timedelta(minutes=5), "source_kind": "synthetic",
        "business_units": [
            {"id": uid(1), "name": "root"},
            {"id": uid(2), "name": "A", "parent_id": uid(1)},
            {"id": uid(3), "name": "A-child", "parent_id": uid(2)},
            {"id": uid(4), "name": "B", "parent_id": uid(1)},
            {"id": uid(5), "name": "B-child", "parent_id": uid(4)},
        ],
        "users": [{"id": uid(n), "name": str(n), "entra_object_id": uid(n + 100), "bu_id": uid(2)}
                  for n in (10, 11, 12)],
        "teams": [{"id": uid(20), "name": "owner team", "bu_id": uid(2)}],
        "memberships": [{"user_id": uid(10), "team_id": uid(20)}],
        "tables": [{"name": "account", "ownership": "user_team", "columns": [
            {"name": "name"}, {"name": "secret", "secured": True}]}],
        "roles": [], "assignments": [],
        # Cartesian owner x owning-BU explicitly exercises modernized ownership.
        "records": [{"id": uid(1000 + owner * 10 + bu), "table": "account",
                     "owner_id": uid(owner), "owning_bu_id": uid(bu)}
                    for owner, bu in product((10, 11, 20), range(1, 6))],
    }


def add_grant(data, depth, anchor=2, principal=10, kind="user", member_basic=False):
    role_id = uid(500 + len(data["roles"]))
    data["roles"].append({"id": role_id, "name": "intentionally same display name",
                          "bu_id": uid(anchor), "member_basic": member_basic,
                          "grants": [{"table": "account", "depth": depth}]})
    data["assignments"].append({"principal_id": uid(principal), "principal_type": kind, "role_id": role_id})


def visible(data, user=10, column=None):
    evaluator = AccessEngine(Snapshot.model_validate(data))
    return {r["id"] for r in data["records"]
            if evaluator.evaluate(uid(user), "account", r["id"], column, now=NOW)["allowed"]}


def scope_oracle(data, depth, anchor):
    # Independent expected sets, not a clone of AccessEngine's branching order.
    descendants = {1: {1, 2, 3, 4, 5}, 2: {2, 3}, 3: {3}, 4: {4, 5}, 5: {5}}
    bu_sets = {"Basic": set(), "Local": {anchor}, "Deep": descendants[anchor], "Global": descendants[1]}
    return {r["id"] for r in data["records"]
            if r["owner_id"] in {uid(10), uid(20)} or r["owning_bu_id"] in {uid(n) for n in bu_sets[depth]}}


@pytest.mark.parametrize("left,right", list(product(("Basic", "Local", "Deep", "Global"), repeat=2)))
def test_cumulative_contextual_union_matches_independent_set_oracle(left, right):
    data = fixture()
    add_grant(data, left, anchor=2)
    add_grant(data, right, anchor=4)
    assert visible(data) == scope_oracle(data, left, 2) | scope_oracle(data, right, 4)


@pytest.mark.parametrize("anchor", range(1, 6))
def test_depth_nesting_with_same_anchor_is_monotonic(anchor):
    sets = []
    for depth in ("Basic", "Local", "Deep", "Global"):
        data = fixture()
        add_grant(data, depth, anchor=anchor)
        sets.append(visible(data))
    assert sets[0] <= sets[1] <= sets[2] <= sets[3]


def test_global_only_in_export_is_still_not_global_for_unassigned_users():
    data = fixture()
    add_grant(data, "Global")
    assert len(visible(data)) == 15
    assert not visible(data, user=11)


def test_owner_or_share_never_supplies_missing_table_privilege():
    data = fixture()
    data["record_access"] = [{"principal_id": uid(10), "principal_type": "user", "table": "account",
                              "record_id": uid(1111), "kind": "share", "evidence": "synthetic share"}]
    assert not visible(data)
    add_grant(data, "Basic")
    assert uid(1111) in visible(data)


def test_team_only_basic_is_contextual_and_does_not_become_personal_basic():
    data = fixture()
    add_grant(data, "Basic", principal=20, kind="team", member_basic=False)
    expected = {r["id"] for r in data["records"] if r["owner_id"] == uid(20)}
    assert visible(data) == expected


def test_characterize_team_only_basic_share_gap():
    """Detected undergrant candidate: confirm same-team share with source oracle."""
    data = fixture()
    add_grant(data, "Basic", principal=20, kind="team", member_basic=False)
    data["record_access"] = [{"principal_id": uid(20), "principal_type": "team", "table": "account",
                              "record_id": uid(1111), "kind": "share", "evidence": "synthetic team share"}]
    assert uid(1111) not in visible(data), "Characterization changed: re-audit team share semantics"


def test_column_union_is_independent_of_the_role_that_supplied_row_scope():
    data = fixture()
    add_grant(data, "Basic")
    data["profiles"] = [{"id": uid(800 + n), "name": str(n), "permissions": [
        {"table": "account", "column": "secret", "can_read": allow}]}
        for n, allow in enumerate((False, True))]
    data["profile_assignments"] = [
        {"profile_id": uid(800), "principal_id": uid(10), "principal_type": "user"},
        {"profile_id": uid(801), "principal_id": uid(20), "principal_type": "team"}]
    assert visible(data, column="secret") == visible(data)
    assert uid(1111) not in visible(data, column="secret")


def test_static_role_union_does_not_implement_independent_row_and_field_union():
    # Dataverse: (row_a OR row_b) AND (field_1 OR field_2).
    # A naive role translator may instead build only (a,1) and (b,2).
    rows_a, rows_b, fields_a, fields_b = {"a"}, {"b"}, {"1"}, {"2"}
    dataverse_cells = set(product(rows_a | rows_b, fields_a | fields_b))
    naive_cells = set(product(rows_a, fields_a)) | set(product(rows_b, fields_b))
    assert dataverse_cells - naive_cells == {("a", "2"), ("b", "1")}


def test_static_role_cannot_share_two_private_owner_predicates():
    # Each static role supplies a rectangle (members x predicate-visible rows).
    # In a diagonal policy, any rectangle spanning two diagonal grants leaks.
    diagonal = {("alice", "alice-row"), ("bob", "bob-row")}
    combined_role = set(product(("alice", "bob"), ("alice-row", "bob-row")))
    assert combined_role - diagonal == {("alice", "bob-row"), ("bob", "alice-row")}
    assert ceil(14500 / 1000) == 15  # minimum items for this specific counterexample


def test_diagonal_policy_requires_one_static_role_rectangle_per_principal():
    # Exhaustively check every candidate rectangle in a four-person diagonal.
    # Every nonempty valid rectangle has area exactly one; shared static roles
    # cannot encode distinct private Basic access without a dynamic predicate.
    principals = list(range(4))
    diagonal = {(p, p) for p in principals}
    masks = range(1, 1 << len(principals))
    valid_rectangles = []
    for user_mask, row_mask in product(masks, repeat=2):
        members = [p for p in principals if user_mask & (1 << p)]
        rows = [p for p in principals if row_mask & (1 << p)]
        rectangle = set(product(members, rows))
        if rectangle <= diagonal:
            valid_rectangles.append(rectangle)
            assert len(rectangle) == 1
    assert set.union(*valid_rectangles) == diagonal
    assert len(valid_rectangles) == len(principals)


def test_current_planner_over_splits_identical_global_access():
    data = fixture()
    add_grant(data, "Global")
    data["assignments"].append({**data["assignments"][0], "principal_id": uid(11)})
    data["memberships"] = []
    assert visible(data, 10) == visible(data, 11)
    result = plan(AccessEngine(Snapshot.model_validate(data)))
    assert result["candidate_signatures"] == 2  # conservative, not a minimum-role solver


def test_same_bu_names_never_merge_distinct_business_units():
    data = fixture()
    for bu in data["business_units"]:
        bu["name"] = "same display name"
    add_grant(data, "Local", anchor=2)
    assert uid(1112) in visible(data)
    assert uid(1114) not in visible(data)


def test_policy_expiry_denies_even_with_complete_global_privilege():
    data = fixture()
    add_grant(data, "Global")
    evaluator = AccessEngine(Snapshot.model_validate(data))
    assert not evaluator.evaluate(uid(10), "account", uid(1111), now=NOW + timedelta(minutes=5))["allowed"]


def test_membership_revocation_removes_team_profile_and_owner_access():
    data = fixture()
    add_grant(data, "Basic", principal=20, kind="team", member_basic=True)
    before = visible(data)
    after_data = deepcopy(data)
    after_data["memberships"] = []
    assert before
    assert not visible(after_data)


@pytest.mark.parametrize("missing_surface", ["record_parent_access", "record_field_permissions"])
def test_parent_inheritance_and_record_field_shares_are_not_supported_model_inputs(missing_surface):
    data = fixture()
    data[missing_surface] = [{"record_id": uid(1111), "evidence": "synthetic additional access"}]
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Snapshot.model_validate(data)
