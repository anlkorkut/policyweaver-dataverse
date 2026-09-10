import pytest

from dvaccess.compile.onelake_model import (
    RoleBudgetExceeded,
    build_rls_predicates,
    compile_profile_roles,
    validate_role_budget,
)
from dvaccess.models import ALL_ROWS, Profile


def test_rls_predicate_format():
    predicates = build_rls_predicates("dbo", "account", "owningbusinessunit",
                                      frozenset({"bu-b", "bu-a"}), 1000)
    assert predicates == [
        "SELECT * FROM dbo.account WHERE owningbusinessunit IN ('bu-a','bu-b')"
    ]


def test_rls_predicate_without_schema():
    predicates = build_rls_predicates(None, "account", "owningbusinessunit",
                                      frozenset({"bu-a"}), 1000)
    assert predicates == ["SELECT * FROM account WHERE owningbusinessunit IN ('bu-a')"]


def test_rls_predicate_splits_at_char_limit_and_covers_all_values():
    bus = frozenset(f"00000000-0000-0000-0000-{i:012d}" for i in range(93))
    max_chars = 1000
    predicates = build_rls_predicates("dbo", "account", "owningbusinessunit", bus, max_chars)
    assert len(predicates) > 1
    assert all(len(p) <= max_chars for p in predicates)
    seen = set()
    for predicate in predicates:
        inner = predicate.split("IN (", 1)[1].rstrip(")")
        seen.update(v.strip("'") for v in inner.split(","))
    assert seen == set(bus)


def _profile(scopes, users=("u1",)):
    return Profile(profile_hash="a" * 64, scopes=scopes, user_ids=list(users))


def test_permission_cap_splits_tables_across_sibling_roles(app_config):
    app_config.limits.max_permissions_per_role = 500
    scopes = {f"table{i:04d}": ALL_ROWS for i in range(600)}
    roles = compile_profile_roles(_profile(scopes), app_config, ["aad-u1"])
    assert len(roles) == 2
    assert sum(len(r.table_paths) for r in roles) == 600
    assert all(len(r.table_paths) <= 500 for r in roles)
    names = {r.name for r in roles}
    assert names == {"dvaaaaaaaaaaaap00", "dvaaaaaaaaaaaap01"}


def test_rls_chunks_of_one_table_never_share_a_role(app_config):
    app_config.limits.max_rls_chars = 120  # force splitting with small GUID-ish values
    bus = frozenset(f"bu-{i:04d}" for i in range(40))
    roles = compile_profile_roles(_profile({"account": bus}), app_config, ["aad-u1"])
    assert len(roles) > 1
    for role in roles:
        tables_with_rls = [path for path, _ in role.row_constraints]
        assert len(tables_with_rls) == len(set(tables_with_rls))
        # a table carrying RLS chunks must never also appear unrestricted
        assert set(role.table_paths) == set(tables_with_rls)


def test_direct_membership_chunks_clone_role_family(app_config):
    app_config.entra.membership = "direct"
    app_config.limits.max_members_per_role = 500
    members = [f"aad-{i}" for i in range(1200)]
    roles = compile_profile_roles(_profile({"account": ALL_ROWS}, users=members), app_config, members)
    assert len(roles) == 3  # 1 permission bucket x 3 member chunks
    assert {len(r.entra_user_ids) for r in roles} == {500, 200}
    assert len({r.name for r in roles}) == 3


def test_group_membership_single_member(app_config):
    roles = compile_profile_roles(_profile({"account": ALL_ROWS}), app_config, ["aad-u1"])
    assert len(roles) == 1
    role = roles[0]
    assert role.entra_user_ids == []
    role.entra_group_id = "group-1"
    api = role.to_api("tenant-1")
    assert api["members"]["microsoftEntraMembers"] == [
        {"objectId": "group-1", "tenantId": "tenant-1", "objectType": "Group"}
    ]


def test_role_api_shape_with_rls(app_config):
    roles = compile_profile_roles(
        _profile({"account": frozenset({"bu-a"}), "product": ALL_ROWS}), app_config, ["aad-u1"]
    )
    api = roles[0].to_api("tenant-1")
    rule = api["decisionRules"][0]
    assert rule["effect"] == "Permit"
    path_scope = next(p for p in rule["permission"] if p["attributeName"] == "Path")
    assert path_scope["attributeValueIncludedIn"] == ["/Tables/dbo/account", "/Tables/dbo/product"]
    action_scope = next(p for p in rule["permission"] if p["attributeName"] == "Action")
    assert action_scope["attributeValueIncludedIn"] == ["Read"]
    assert rule["constraints"]["rows"] == [
        {
            "tablePath": "/Tables/dbo/account",
            "value": "SELECT * FROM dbo.account WHERE owningbusinessunit IN ('bu-a')",
        }
    ]


def test_business_owned_tables_use_businessunitid_column(app_config):
    from dvaccess.compile.onelake_model import rls_columns_for_tables
    from dvaccess.models import Ownership

    columns = rls_columns_for_tables(
        {"account": Ownership.USER, "role": Ownership.BUSINESS, "product": Ownership.ORG},
        app_config,
    )
    assert columns["account"] == "owningbusinessunit"
    assert columns["role"] == "businessunitid"

    roles = compile_profile_roles(
        _profile({"account": frozenset({"bu-a"}), "role": frozenset({"bu-a"})}),
        app_config, ["aad-u1"], columns,
    )
    predicates = dict(roles[0].row_constraints)
    assert predicates["/Tables/dbo/account"].endswith("owningbusinessunit IN ('bu-a')")
    assert predicates["/Tables/dbo/role"].endswith("businessunitid IN ('bu-a')")


def test_non_schema_lakehouse_paths_omit_schema(app_config):
    app_config.fabric.schema_name = None
    roles = compile_profile_roles(
        _profile({"account": frozenset({"bu-a"})}), app_config, ["aad-u1"]
    )
    assert roles[0].table_paths == ["/Tables/account"]
    assert roles[0].row_constraints == [
        ("/Tables/account", "SELECT * FROM account WHERE owningbusinessunit IN ('bu-a')")
    ]


def test_generated_role_names_satisfy_onelake_naming_rule(app_config):
    """OneLake rejects the entire payload if any role name is not alphanumeric
    starting with a letter (RequestBodyValidationFailed)."""
    app_config.entra.membership = "direct"
    app_config.limits.max_members_per_role = 2
    app_config.limits.max_permissions_per_role = 1
    members = [f"aad-{i}" for i in range(5)]
    roles = compile_profile_roles(
        _profile({"account": ALL_ROWS, "contact": ALL_ROWS}, users=members),
        app_config, members,
    )
    assert len(roles) > 1  # exercise both chunk suffixes
    for role in roles:
        assert role.name.isalnum(), role.name
        assert role.name[0].isalpha(), role.name


def test_invalid_role_prefix_is_rejected_at_config_load():
    import pytest as _pytest

    from dvaccess.config import AppConfig

    base = {
        "environment": {"name": "t", "dataverse_url": "https://x.crm.dynamics.com"},
        "auth": {"tenant_id": "t"},
        "fabric": {"workspace_id": "w", "item_id": "i", "role_prefix": "dv_"},
    }
    with _pytest.raises(ValueError, match="letters and numbers"):
        AppConfig.model_validate(base)


def test_role_budget_guardrail():
    with pytest.raises(RoleBudgetExceeded):
        validate_role_budget(desired_count=900, unmanaged_count=200, budget=1000)
    validate_role_budget(desired_count=900, unmanaged_count=100, budget=1000)
