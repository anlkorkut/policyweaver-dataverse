"""Independent adversarial review of cumulative read semantics.

These tests validate the local reference evaluator, not live Dataverse parity.
"""
from datetime import datetime, timedelta, timezone
from uuid import NAMESPACE_URL, uuid5

import pytest
from pydantic import ValidationError

from policyweaver.engine import AccessEngine
from policyweaver.models import Snapshot
from policyweaver.planner import plan


NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)


def guid(label):
    return str(uuid5(NAMESPACE_URL, "https://security-review.invalid/" + label))


def fixture_data():
    return {
        "tenant_id": guid("tenant"), "organization_id": guid("organization"),
        "source_kind": "synthetic", "observed_at": NOW,
        "valid_until": NOW + timedelta(minutes=5),
        "business_units": [
            {"id": guid("root"), "name": "Root"},
            {"id": guid("a"), "name": "A", "parent_id": guid("root")},
            {"id": guid("aa"), "name": "A child", "parent_id": guid("a")},
            {"id": guid("b"), "name": "B", "parent_id": guid("root")},
            {"id": guid("bb"), "name": "B child", "parent_id": guid("b")},
        ],
        "users": [
            {"id": guid(u), "name": u, "entra_object_id": guid(u + "-oid"),
             "bu_id": guid(b)} for u, b in [("alice", "a"), ("bob", "b"), ("other", "root")]
        ],
        "teams": [
            {"id": guid(t), "name": t, "bu_id": guid(b), "kind": "owner"}
            for t, b in [("team-a", "a"), ("team-b", "b")]
        ],
        "tables": [{"name": "account", "ownership": "user_team", "columns": [
            {"name": "name"}, {"name": "secret", "secured": True},
            {"name": "masked", "secured": True, "masked": True}]}],
        "roles": [], "assignments": [], "memberships": [],
        "records": [
            {"id": guid(r), "table": "account", "owner_id": guid(owner), "owning_bu_id": guid(b)}
            for r, owner, b in [
                ("alice-owned", "alice", "root"), ("bob-owned", "bob", "root"),
                ("team-a-owned", "team-a", "root"), ("team-b-owned", "team-b", "root"),
                ("a-row", "other", "a"), ("aa-row", "other", "aa"),
                ("b-row", "other", "b"), ("bb-row", "other", "bb"),
                ("root-row", "other", "root"),
            ]
        ],
    }


def grant(data, depth, *, who="alice", principal_type="user", anchor="a", member_basic=False):
    role_id = guid(f"{depth}-{who}-{anchor}-{member_basic}")
    data["roles"].append({"id": role_id, "name": "Repeated display role name", "bu_id": guid(anchor),
                          "member_basic": member_basic, "grants": [{"table": "account", "depth": depth}]})
    data["assignments"].append({"role_id": role_id, "principal_type": principal_type, "principal_id": guid(who)})


def member(data, user, team):
    data["memberships"].append({"user_id": guid(user), "team_id": guid(team)})


def engine(data):
    return AccessEngine(Snapshot.model_validate(data))


def read(evaluator, row, *, user="alice", column=None, **kwargs):
    return evaluator.evaluate(guid(user), "account", guid(row), column, now=NOW, **kwargs)


def test_teamonly_basic_does_not_leak_through_overlapping_memberships():
    data = fixture_data()
    member(data, "alice", "team-a")
    member(data, "alice", "team-b")
    grant(data, "Basic", who="team-a", principal_type="team")
    evaluator = engine(data)
    assert read(evaluator, "team-a-owned")["allowed"]
    assert not read(evaluator, "team-b-owned")["allowed"]
    assert not read(evaluator, "alice-owned")["allowed"]


def test_team_direct_basic_inheritance_expands_personal_ownership():
    data = fixture_data()
    member(data, "alice", "team-a")
    member(data, "alice", "team-b")
    grant(data, "Basic", who="team-a", principal_type="team", member_basic=True)
    evaluator = engine(data)
    assert read(evaluator, "alice-owned")["allowed"]
    assert read(evaluator, "team-b-owned")["allowed"]
    assert not read(evaluator, "bob-owned")["allowed"]


def test_distinct_bu_anchors_do_not_borrow_deep_from_another_role():
    data = fixture_data()
    grant(data, "Deep", anchor="a")
    grant(data, "Local", anchor="b")
    evaluator = engine(data)
    assert read(evaluator, "aa-row")["allowed"]
    assert read(evaluator, "b-row")["allowed"]
    assert not read(evaluator, "bb-row")["allowed"]
    assert not read(evaluator, "root-row")["allowed"]


def test_duplicate_membership_edges_do_not_change_access():
    data = fixture_data()
    member(data, "alice", "team-a")
    grant(data, "Basic", who="team-a", principal_type="team")
    before = read(engine(data), "team-a-owned")
    data["memberships"] *= 5
    data["assignments"] *= 5
    after = read(engine(data), "team-a-owned")
    assert before["allowed"] == after["allowed"]
    assert before["reasons"] == after["reasons"]


def test_share_cannot_supply_a_missing_table_privilege():
    data = fixture_data()
    data["record_access"] = [{"principal_id": guid("alice"), "principal_type": "user", "table": "account",
                              "record_id": guid("root-row"), "kind": "share", "evidence": "source access check"}]
    assert not read(engine(data), "root-row")["allowed"]
    grant(data, "Basic")
    assert read(engine(data), "root-row")["allowed"]


def test_profile_read_is_additive_across_direct_and_team_profiles():
    data = fixture_data()
    grant(data, "Global")
    member(data, "alice", "team-a")
    data["profiles"] = [
        {"id": guid("deny-profile"), "name": "No read here", "permissions": [
            {"table": "account", "column": "secret", "can_read": False}]},
        {"id": guid("read-profile"), "name": "Team read", "permissions": [
            {"table": "account", "column": "secret", "can_read": True}]},
    ]
    data["profile_assignments"] = [
        {"profile_id": guid("deny-profile"), "principal_id": guid("alice"), "principal_type": "user"},
        {"profile_id": guid("read-profile"), "principal_id": guid("team-a"), "principal_type": "team"},
    ]
    assert read(engine(data), "root-row", column="secret")["allowed"]
    assert not read(engine(data), "root-row", column="masked")["allowed"]


@pytest.mark.parametrize("unmask,expected", [("none", False), ("one", False), ("all", True)])
def test_bulk_masking_requires_all_records_unmask(unmask, expected):
    data = fixture_data()
    grant(data, "Global")
    data["profiles"] = [{"id": guid("profile"), "name": "Masked access", "permissions": [
        {"table": "account", "column": "masked", "can_read": True, "read_unmasked": unmask}]}]
    data["profile_assignments"] = [
        {"profile_id": guid("profile"), "principal_id": guid("alice"), "principal_type": "user"}]
    assert read(engine(data), "root-row", column="masked")["allowed"] is expected


@pytest.mark.parametrize("scope", ["tenant_id", "organization_id"])
@pytest.mark.parametrize("value", ["", guid("different-scope")])
def test_explicit_wrong_or_empty_security_scope_denied(scope, value):
    data = fixture_data()
    grant(data, "Global")
    assert not read(engine(data), "root-row", **{scope: value})["allowed"]


@pytest.mark.parametrize("seconds", [-1, 300, 301])
def test_snapshot_clock_boundaries_deny(seconds):
    data = fixture_data()
    grant(data, "Global")
    result = engine(data).evaluate(guid("alice"), "account", guid("root-row"),
                                   now=NOW + timedelta(seconds=seconds))
    assert not result["allowed"]


def test_incomplete_membership_is_conservative_denial_even_for_global_reader():
    data = fixture_data()
    grant(data, "Global")
    data["teams"][1]["membership_verified"] = False
    assert not read(engine(data), "root-row")["allowed"]


@pytest.mark.parametrize("corruption", ["duplicate-user", "duplicate-entra", "dangling-bu", "bu-cycle"])
def test_invalid_identity_and_bu_graphs_rejected(corruption):
    data = fixture_data()
    if corruption == "duplicate-user":
        data["users"].append(dict(data["users"][0]))
    elif corruption == "duplicate-entra":
        data["users"][1]["entra_object_id"] = data["users"][0]["entra_object_id"]
    elif corruption == "dangling-bu":
        data["users"][0]["bu_id"] = guid("absent")
    else:
        data["business_units"][1]["parent_id"] = guid("aa")
    with pytest.raises(ValidationError):
        Snapshot.model_validate(data)


@pytest.mark.parametrize("depth", ["Local", "Deep"])
def test_planner_keeps_personal_ownership_for_team_local_and_deep(depth):
    data = fixture_data()
    for user in ("alice", "bob"):
        member(data, user, "team-a")
    grant(data, depth, who="team-a", principal_type="team", member_basic=False)
    evaluator = engine(data)
    assert read(evaluator, "alice-owned", user="alice")["allowed"]
    assert not read(evaluator, "alice-owned", user="bob")["allowed"]
    # Same memberships/role labels do not make these two effective policies equal.
    assert plan(evaluator)["candidate_signatures"] == 2
