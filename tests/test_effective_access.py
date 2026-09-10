from conftest import add_role, add_team, add_user, assign, make_snapshot

from dvaccess.compile.effective_access import build_index, iter_user_scopes
from dvaccess.config import CompileConfig
from dvaccess.models import ALL_ROWS, Depth


def scopes_for(snapshot, cfg=None):
    index = build_index(snapshot, cfg or CompileConfig())
    return {user.id: scopes for user, scopes in iter_user_scopes(index)}, index


def test_multi_role_greatest_access_prevails():
    s = make_snapshot()
    add_user(s, "alice", "emea")
    add_role(s, "r-local", "emea", [("account", Depth.LOCAL)])
    add_role(s, "r-deep", "emea", [("account", Depth.DEEP)])
    assign(s, "alice", "r-local")
    assign(s, "alice", "r-deep")
    scopes, _ = scopes_for(s)
    assert scopes["alice"]["account"] == frozenset({"emea", "uk", "de"})


def test_team_and_direct_roles_union_bu_sets():
    s = make_snapshot()
    add_user(s, "bob", "uk")
    add_role(s, "r-uk", "uk", [("account", Depth.LOCAL)])
    add_role(s, "r-apac", "apac", [("account", Depth.LOCAL)])
    assign(s, "bob", "r-uk")
    add_team(s, "team-apac", "apac", members=["bob"], roles=["r-apac"])
    scopes, _ = scopes_for(s)
    assert scopes["bob"]["account"] == frozenset({"uk", "apac"})


def test_deep_at_root_collapses_to_all_rows():
    s = make_snapshot()
    add_user(s, "carol", "root")
    add_role(s, "r-root-deep", "root", [("account", Depth.DEEP)])
    assign(s, "carol", "r-root-deep")
    scopes, _ = scopes_for(s)
    assert scopes["carol"]["account"] == ALL_ROWS


def test_bu_union_covering_all_bus_normalizes_to_all_rows():
    s = make_snapshot()
    add_user(s, "dave", "emea")
    add_role(s, "r-emea-deep", "emea", [("account", Depth.DEEP)])
    add_role(s, "r-root-local", "root", [("account", Depth.LOCAL)])
    add_role(s, "r-apac-local", "apac", [("account", Depth.LOCAL)])
    for rid in ("r-emea-deep", "r-root-local", "r-apac-local"):
        assign(s, "dave", rid)
    scopes, _ = scopes_for(s)
    assert scopes["dave"]["account"] == ALL_ROWS


def test_org_owned_table_grants_all_rows_at_any_depth():
    s = make_snapshot()
    add_user(s, "erin", "uk")
    add_role(s, "r-prod", "uk", [("product", Depth.BASIC)])
    assign(s, "erin", "r-prod")
    scopes, index = scopes_for(s)
    assert scopes["erin"]["product"] == ALL_ROWS
    assert not index.diagnostics.basic_exclusions


def test_global_depth_grants_all_rows():
    s = make_snapshot()
    add_user(s, "frank", "de")
    add_role(s, "r-global", "de", [("contact", Depth.GLOBAL)])
    assign(s, "frank", "r-global")
    scopes, _ = scopes_for(s)
    assert scopes["frank"]["contact"] == ALL_ROWS


def test_basic_only_is_fail_closed_and_reported():
    s = make_snapshot()
    add_user(s, "gina", "uk")
    add_role(s, "r-basic", "uk", [("contact", Depth.BASIC)])
    assign(s, "gina", "r-basic")
    scopes, index = scopes_for(s)
    assert "contact" not in scopes["gina"]
    exclusions = index.diagnostics.basic_exclusions
    assert len(exclusions) == 1
    assert (exclusions[0].user_id, exclusions[0].table, exclusions[0].kind) == (
        "gina", "contact", "basic_only",
    )


def test_basic_subsumed_by_local_on_own_bu():
    s = make_snapshot()
    add_user(s, "hank", "uk")
    add_role(s, "r-both", "uk", [("contact", Depth.BASIC), ("contact", Depth.LOCAL)])
    assign(s, "hank", "r-both")
    scopes, index = scopes_for(s)
    assert scopes["hank"]["contact"] == frozenset({"uk"})
    assert not index.diagnostics.basic_exclusions


def test_basic_partial_when_own_bu_not_covered():
    s = make_snapshot()
    add_user(s, "iris", "uk")
    add_role(s, "r-basic-uk", "uk", [("contact", Depth.BASIC)])
    add_role(s, "r-local-apac", "apac", [("contact", Depth.LOCAL)])
    assign(s, "iris", "r-basic-uk")
    add_team(s, "t-apac", "apac", members=["iris"], roles=["r-local-apac"])
    scopes, index = scopes_for(s)
    assert scopes["iris"]["contact"] == frozenset({"apac"})
    assert [e.kind for e in index.diagnostics.basic_exclusions] == ["basic_partial"]


def test_duplicate_bu_role_copies_scope_to_their_own_bu():
    s = make_snapshot()
    add_user(s, "uk-user", "uk")
    add_user(s, "de-user", "de")
    add_role(s, "r-copy-uk", "uk", [("account", Depth.LOCAL)], root_role_id="root-copy")
    add_role(s, "r-copy-de", "de", [("account", Depth.LOCAL)], root_role_id="root-copy")
    assign(s, "uk-user", "r-copy-uk")
    assign(s, "de-user", "r-copy-de")
    scopes, _ = scopes_for(s)
    assert scopes["uk-user"]["account"] == frozenset({"uk"})
    assert scopes["de-user"]["account"] == frozenset({"de"})


def test_ineligible_users_are_skipped_with_reasons():
    s = make_snapshot()
    add_user(s, "ok", "uk")
    add_user(s, "disabled", "uk", disabled=True)
    add_user(s, "appuser", "uk", app_id="app-1")
    add_user(s, "noaad", "uk", aad=None)
    add_user(s, "support", "uk", access_mode=3)
    add_role(s, "r", "uk", [("account", Depth.LOCAL)])
    for uid in ("ok", "disabled", "appuser", "noaad", "support"):
        assign(s, uid, "r")
    scopes, index = scopes_for(s)
    assert set(scopes) == {"ok"}
    reasons = {sk.user_id: sk.reason for sk in index.diagnostics.skipped_users}
    assert "disabled" in reasons["disabled"]
    assert "application" in reasons["appuser"]
    assert "Entra" in reasons["noaad"]
    assert "access mode" in reasons["support"]


def test_business_owned_basic_depth_resolves_to_users_own_bu():
    """Business-owned rows belong to a BU, not a user, so Basic depth is expressible
    as static RLS and must NOT be fail-closed excluded."""
    s = make_snapshot()
    add_user(s, "liam", "de")
    add_role(s, "r-basic-biz", "uk", [("role", Depth.BASIC)])
    assign(s, "liam", "r-basic-biz")
    scopes, index = scopes_for(s)
    assert scopes["liam"]["role"] == frozenset({"de"})  # user's BU, not the role's BU
    assert not index.diagnostics.basic_exclusions


def test_ownership_parsing_covers_all_dataverse_types():
    from dvaccess.models import Ownership as O
    from dvaccess.models import parse_ownership as p

    assert p("UserOwned") is O.USER and p(1) is O.USER
    assert p("TeamOwned") is O.USER and p(2) is O.USER
    assert p("BusinessOwned") is O.BUSINESS and p(4) is O.BUSINESS
    assert p("BusinessParentChild") is O.BUSINESS and p(16) is O.BUSINESS
    assert p("OrganizationOwned") is O.ORG and p(8) is O.ORG
    assert p("None") is O.ORG and p(0) is O.ORG
    assert p(object()) is O.USER  # unknown metadata fails closed


def test_grants_stored_under_root_role_resolve_per_instance():
    """Extraction stores privileges once per root role; BU copies must inherit them
    while scoping Local/Deep to the copy's own BU."""
    s = make_snapshot()
    add_user(s, "uk-user", "uk")
    add_user(s, "de-user", "de")
    # two BU copies sharing one root; grants recorded ONLY under the root id
    from dvaccess.models import DvRole, RoleReadGrant
    s.roles.append(DvRole(id="copy-uk", name="Reader", bu_id="uk", root_role_id="root-reader"))
    s.roles.append(DvRole(id="copy-de", name="Reader", bu_id="de", root_role_id="root-reader"))
    s.role_grants.append(RoleReadGrant("root-reader", "account", Depth.LOCAL))
    assign(s, "uk-user", "copy-uk")
    assign(s, "de-user", "copy-de")
    scopes, _ = scopes_for(s)
    assert scopes["uk-user"]["account"] == frozenset({"uk"})
    assert scopes["de-user"]["account"] == frozenset({"de"})


def test_item_table_filter_drops_tables_not_synced_to_fabric():
    s = make_snapshot()
    add_user(s, "nina", "uk")
    add_role(s, "r", "uk", [("account", Depth.GLOBAL), ("contact", Depth.GLOBAL)])
    assign(s, "nina", "r")
    index = build_index(s, CompileConfig(), item_tables={"account"})
    scopes = {u.id: sc for u, sc in iter_user_scopes(index)}
    assert set(scopes["nina"]) == {"account"}
    assert index.diagnostics.tables_absent_from_item == ["contact"]


def test_table_filters_apply():
    s = make_snapshot()
    add_user(s, "kate", "uk")
    add_role(s, "r", "uk", [("account", Depth.GLOBAL), ("contact", Depth.GLOBAL)])
    assign(s, "kate", "r")
    cfg = CompileConfig(include_tables=["account"])
    scopes, index = scopes_for(s, cfg)
    assert set(scopes["kate"]) == {"account"}
    assert index.diagnostics.tables_excluded_by_filter == ["contact"]
