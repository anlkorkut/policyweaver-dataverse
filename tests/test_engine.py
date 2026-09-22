from datetime import timedelta

import pytest
from pydantic import ValidationError

from policyweaver.demo import demo_snapshot, example_queries, uid
from policyweaver.engine import AccessEngine
from policyweaver.models import Snapshot


def changed(mutator):
    raw = demo_snapshot().model_dump(mode="json")
    mutator(raw)
    return Snapshot.model_validate(raw)


@pytest.mark.parametrize("query", example_queries(), ids=lambda q: q["label"])
def test_reference_scenarios(query):
    engine = AccessEngine(demo_snapshot())
    assert engine.evaluate(**{k: query[k] for k in ("user_id", "table", "record_id", "column")})["allowed"] == query["expected_allowed"]


def test_deep_and_local_different_anchors_are_unioned_without_sibling_overgrant():
    engine = AccessEngine(demo_snapshot())
    assert engine.evaluate(uid("analyst"), "account", uid("market-account"))["allowed"]
    assert not engine.evaluate(uid("analyst"), "account", uid("outside-account"))["allowed"]


def test_deep_does_not_grant_sibling_without_local_role():
    snapshot = changed(lambda s: s["assignments"].pop(1))
    assert not AccessEngine(snapshot).evaluate(uid("analyst"), "account", uid("market-account"))["allowed"]


def test_direct_basic_inheritance_enables_personal_ownership():
    snapshot = changed(lambda s: s["roles"][2].update(member_basic=True))
    assert AccessEngine(snapshot).evaluate(uid("teamonly"), "account", uid("private-account"))["allowed"]


def test_cross_bu_owned_record_still_accessible_with_personal_read():
    snapshot = changed(lambda s: s["records"][-1].update(owner_id=uid("analyst")))
    assert AccessEngine(snapshot).evaluate(uid("analyst"), "account", uid("outside-account"))["allowed"]


def test_duplicate_assignments_do_not_multiply_grants():
    snapshot = changed(lambda s: s["assignments"].extend(s["assignments"][:]))
    assert len(AccessEngine(snapshot).scope_rows()) == len(AccessEngine(demo_snapshot()).scope_rows())


@pytest.mark.parametrize("offset", [-1, 31])
def test_time_gate_denies_future_or_expired(offset):
    snapshot = demo_snapshot()
    assert not AccessEngine(snapshot).evaluate(uid("reader"), "account", uid("fund-account"),
                                               now=snapshot.observed_at + timedelta(minutes=offset))["allowed"]


def test_wrong_tenant_and_org_fail_closed():
    engine = AccessEngine(demo_snapshot())
    for context in ({"tenant_id": uid("wrong")}, {"organization_id": uid("wrong")}):
        assert not engine.evaluate(uid("reader"), "account", uid("fund-account"), **context)["allowed"]


@pytest.mark.parametrize("mutation", [
    lambda s: s.update(blockers=["sharing not collected"]),
    lambda s: s["teams"][0].update(membership_verified=False),
    lambda s: s["users"][2].update(entra_object_id=None),
    lambda s: s["users"][2].update(application=True),
    lambda s: s["users"][2].update(access_mode=5),
])
def test_incomplete_evidence_and_ineligible_identities_fail_closed(mutation):
    assert not AccessEngine(changed(mutation)).evaluate(uid("reader"), "account", uid("fund-account"))["allowed"]


@pytest.mark.parametrize("mutation", [
    lambda s: s["roles"].append(s["roles"][0]),
    lambda s: s["business_units"][0].update(parent_id=uid("funds")),
    lambda s: s["business_units"][1].update(parent_id=uid("missing")),
    lambda s: s["assignments"][0].update(role_id=uid("missing")),
    lambda s: s["users"][0].update(entra_object_id=s["users"][1]["entra_object_id"]),
    lambda s: s["roles"][0]["grants"][0].update(depth="RecordFilter"),
    lambda s: s["assignments"][2].update(principal_id=uid("reviewers")),
    lambda s: s["records"][0].update(owner_id=uid("reviewers")),
])
def test_invalid_graph_rejected(mutation):
    with pytest.raises(ValidationError):
        changed(mutation)


def test_profile_union_is_additive_and_does_not_grant_row_access():
    def mutate(s):
        s["profiles"].append({"id": uid("denied-profile"), "name": "No credit permission",
                              "permissions": [{"table": "account", "column": "creditlimit", "can_read": False}]})
        s["profile_assignments"].append({"principal_type": "user", "principal_id": uid("analyst"), "profile_id": uid("denied-profile")})
    engine = AccessEngine(changed(mutate))
    assert engine.evaluate(uid("analyst"), "account", uid("fund-account"), "creditlimit")["allowed"]
    assert not engine.evaluate(uid("analyst"), "account", uid("outside-account"), "creditlimit")["allowed"]


def test_global_read_is_not_administrator_field_bypass():
    snapshot = changed(lambda s: s["roles"][3].update(name="System Administrator"))
    assert not AccessEngine(snapshot).evaluate(uid("reader"), "account", uid("fund-account"), "creditlimit")["allowed"]


def test_unmasked_all_allows_bulk_column_but_one_does_not():
    snapshot = changed(lambda s: s["profiles"][1]["permissions"][0].update(read_unmasked="all"))
    assert AccessEngine(snapshot).evaluate(uid("analyst"), "account", uid("fund-account"), "taxnumber")["allowed"]


def test_unknown_record_column_and_user_deny():
    engine = AccessEngine(demo_snapshot())
    assert not engine.evaluate(uid("unknown"), "account", uid("fund-account"))["allowed"]
    assert not engine.evaluate(uid("reader"), "account", uid("unknown"))["allowed"]
    assert not engine.evaluate(uid("reader"), "account", uid("fund-account"), "unknown")["allowed"]

