"""Remote expiry decisions must survive host loss and publication races."""
import copy
import json
from uuid import UUID

import pytest

from policyweaver.config import AdapterConfig, TableSelection
from policyweaver.fabric_native import FabricNativeClient, FabricRequestError, RoleSnapshot, TableSpec, plan_roles
from policyweaver.native_watchdog import inspect_item, main, run_watchdog

TENANT = str(UUID(int=9001))
WORKSPACE = str(UUID(int=9002))
ORG = str(UUID(int=9003))
ITEM = str(UUID(int=201))
OTHER_ITEM = str(UUID(int=202))
READERS = [str(UUID(int=300 + n)) for n in range(2)]
NOW = 1_789_743_600.0


def config(items=None, *, retention_mode="timed"):
    return AdapterConfig(environment_url="https://example.crm.dynamics.com", tenant_id=TENANT,
        organization_id=ORG, workspace_id=WORKSPACE, readers=tuple(READERS),
        retention_mode=retention_mode,
        tables=(TableSelection(name="account", columns=("accountid", "name")),),
        serving_items=items if items is not None else {"a000_t000": ITEM})


def roles(age=0, readers=READERS):
    return plan_roles(TENANT, [TableSpec("/Tables/dbo/pw_demo_account", ("accountid", "name"))],
                      readers, int((NOW - age) * 1_000_000), ownership_prefix="pw_demo_").shards[0].roles


class Fabric:
    _owned = FabricNativeClient._owned
    tenant_id = TENANT
    roles_url = "https://api.fabric.microsoft.com/roles"

    def __init__(self, existing):
        self.roles = copy.deepcopy(existing)
        self.etag = '"old"'
        self.puts = []
        self.race = None
        self.failure = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def list_roles(self):
        if self.failure:
            raise RuntimeError("private customer token and record must not escape")
        return RoleSnapshot(tuple(copy.deepcopy(self.roles)), self.etag)

    def _request(self, method, url, payload, etag):
        assert method == "PUT" and url == self.roles_url
        self.puts.append((copy.deepcopy(payload), etag))
        if self.race is not None:
            self.roles = copy.deepcopy(self.race)
            self.etag = '"new"'
            raise FabricRequestError("Fabric PUT HTTP 412", status_code=412)
        assert etag == self.etag
        self.roles = copy.deepcopy(payload["value"])
        self.etag = '"withdrawn"'


def test_stale_roles_withdraw_without_any_local_journal_or_source_calls():
    fabric = Fabric(roles(age=3000))
    result = inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)
    assert result["status"] == "withdrawn_expired_generation"
    assert result["control_plane_verified"] and not result["critical"]
    assert not fabric.roles and len(fabric.puts) == 1


def test_live_fabric_get_normalization_retains_safe_expiry_withdrawal():
    existing = roles(age=3000)
    for role in existing:
        role["members"]["microsoftEntraMembers"][0].pop("objectType")
        role["decisionRules"][0]["constraints"]["rows"][0]["type"] = "Fabric"
        role["etag"] = '"service-role-version"'
    fabric = Fabric(existing)
    result = inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)
    assert result["status"] == "withdrawn_expired_generation"
    assert result["control_plane_verified"] and not fabric.roles


@pytest.mark.parametrize("changed", ["member", "row"])
def test_nondefault_server_discriminators_are_not_normalized(changed):
    existing = roles(age=3000)
    if changed == "member":
        existing[0]["members"]["microsoftEntraMembers"][0]["objectType"] = "ServicePrincipal"
    else:
        existing[0]["decisionRules"][0]["constraints"]["rows"][0]["type"] = "OtherEngine"
    fabric = Fabric(existing)
    result = run_watchdog(config(), credential=object(), client_factory=lambda *a, **k: fabric, now=lambda: NOW)
    assert result["critical"] and not fabric.puts


def test_fresh_roles_are_untouched():
    fabric = Fabric(roles(age=120))
    result = inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)
    assert result["status"] == "fresh_generation" and not fabric.puts


def test_exact_expiry_is_withdrawn():
    fabric = Fabric(roles(age=2700))
    assert inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)["status"] == "withdrawn_expired_generation"


@pytest.mark.parametrize("age", [60, 2700, 3000, 60 * 60 * 24 * 365])
@pytest.mark.parametrize("inspect_only", [False, True])
def test_manual_retention_keeps_valid_scoped_roles_past_age_deadline(age, inspect_only):
    existing = multi_table_roles(age)
    fabric = Fabric(existing)
    result = inspect_item(fabric, config(retention_mode="manual"),
                          inspect_only=inspect_only, now=lambda: NOW)
    assert result["status"] == "manual_retention_active"
    assert result["retention_mode"] == "manual"
    assert result["age_based_withdrawal_enabled"] is False
    assert not result["critical"] and not result["mutation_attempted"]
    assert fabric.roles == existing and not fabric.puts


def test_timed_mode_still_reports_age_withdrawal_enabled():
    result = inspect_item(Fabric(roles(age=60)), config(), inspect_only=False, now=lambda: NOW)
    assert result["retention_mode"] == "timed"
    assert result["age_based_withdrawal_enabled"] is True
    assert result["status"] == "fresh_generation"


@pytest.mark.parametrize("fault", ["future", "mixed", "implausible"])
def test_manual_retention_does_not_exempt_invalid_temporal_policy_state(fault):
    existing = roles(age=-5) if fault == "future" else roles(age=60)
    if fault == "mixed":
        existing[1] = roles(age=120)[1]
    elif fault == "implausible":
        for role in existing:
            row = role["decisionRules"][0]["constraints"]["rows"][0]
            row["value"] = row["value"].rsplit(" = ", 1)[0] + " = 7"
    expected = {"future": "future_generation_timestamp", "mixed": "mixed_generations",
                "implausible": "invalid_generation_timestamp"}[fault]
    fabric = Fabric(existing)
    result = inspect_item(fabric, config(retention_mode="manual"), inspect_only=False, now=lambda: NOW)
    assert result["status"] == "withdrawn_" + expected
    assert result["control_plane_verified"] and not fabric.roles and len(fabric.puts) == 1


def test_manual_retention_still_reports_unmanaged_overlap_without_deleting_owned_roles():
    unowned = {"name": "UnmanagedBroad", "decisionRules": [{"permission": [
        {"attributeName": "Path", "attributeValueIncludedIn": ["*"]}]}]}
    existing = [*roles(age=3000), unowned]
    fabric = Fabric(existing)
    result = inspect_item(fabric, config(retention_mode="manual"), inspect_only=False, now=lambda: NOW)
    assert result["status"] == "manual_retention_active"
    assert result["critical"] and result["unmanaged_overlap"]
    assert fabric.roles == existing and not fabric.puts


def test_manual_retention_does_not_hide_modified_owned_policy_shape():
    existing = roles(age=3000)
    existing[0]["decisionRules"][0].pop("constraints")
    fabric = Fabric(existing)
    result = run_watchdog(config(retention_mode="manual"), credential=object(),
                          client_factory=lambda *a, **k: fabric, now=lambda: NOW)
    assert result["critical"] and result["retention_mode"] == "manual"
    assert result["items"]["a000_t000"]["error_code"] == "unknown_owned_policy_shape"
    assert not fabric.puts


def test_manual_retention_is_not_a_global_disable_for_other_named_items():
    retained, timed = Fabric(roles(age=3000)), Fabric(roles(age=3000))
    visited = []
    clients = {ITEM: retained, OTHER_ITEM: timed}

    def factory(tenant, workspace, item, **kwargs):
        visited.append(item)
        return clients[item]

    manual_result = run_watchdog(config(retention_mode="manual"), credential=object(),
                                 client_factory=factory, now=lambda: NOW)
    assert visited == [ITEM] and manual_result["status"] == "ok"
    assert not retained.puts and timed.roles
    timed_result = run_watchdog(config({"a000_t000": OTHER_ITEM}), credential=object(),
                                client_factory=factory, now=lambda: NOW)
    assert visited == [ITEM, OTHER_ITEM]
    assert timed_result["items"]["a000_t000"]["status"] == "withdrawn_expired_generation"
    assert len(timed.puts) == 1 and not timed.roles and retained.roles


def test_manual_retention_respects_deployment_ownership_in_same_item():
    manual_roles = roles(age=3000)
    other_roles = plan_roles(TENANT, [TableSpec("/Tables/dbo/pw_other_account", ("accountid", "name"))],
        READERS, int((NOW - 3000) * 1_000_000), ownership_prefix="pw_other_").shards[0].roles
    fabric = Fabric([*manual_roles, *other_roles])
    retained = inspect_item(fabric, config(retention_mode="manual"), inspect_only=False, now=lambda: NOW)
    assert retained["status"] == "manual_retention_active" and not retained["critical"]
    other_config = config().model_copy(update={"deployment_name": "pw_other"})
    withdrawn = inspect_item(fabric, other_config, inspect_only=False, now=lambda: NOW)
    assert withdrawn["status"] == "withdrawn_expired_generation" and not withdrawn["critical"]
    assert fabric.roles == manual_roles


def test_returning_manual_deployment_to_timed_withdraws_an_already_old_generation():
    fabric = Fabric(roles(age=3000))
    manual = inspect_item(fabric, config(retention_mode="manual"), inspect_only=False, now=lambda: NOW)
    assert manual["status"] == "manual_retention_active" and not fabric.puts
    timed = inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)
    assert timed["status"] == "withdrawn_expired_generation" and not fabric.roles


def test_inspect_mode_reports_expired_without_mutating():
    fabric = Fabric(roles(age=3000))
    result = inspect_item(fabric, config(), inspect_only=True, now=lambda: NOW)
    assert result["status"] == "would_withdraw_expired_generation" and result["critical"]
    assert not fabric.puts


def test_future_generation_is_withdrawn():
    fabric = Fabric(roles(age=-5))
    assert inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)["status"] == "withdrawn_future_generation_timestamp"


@pytest.mark.parametrize("generation", [0, -1, 7, 4_102_444_800_000_000])
def test_implausible_generation_timestamp_is_withdrawn(generation):
    existing = roles()
    for role in existing:
        row = role["decisionRules"][0]["constraints"]["rows"][0]
        row["value"] = row["value"].rsplit(" = ", 1)[0] + " = " + str(generation)
    fabric = Fabric(existing)
    assert inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)["status"] == "withdrawn_invalid_generation_timestamp"


def test_mixed_generations_withdraw_even_if_each_is_individually_fresh():
    existing = [roles(age=60)[0], roles(age=120)[1]]
    fabric = Fabric(existing)
    assert inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)["status"] == "withdrawn_mixed_generations"


def multi_table_roles(age=0, *, legacy=False):
    tables = [TableSpec("/Tables/dbo/pw_demo_account", ("accountid", "name")),
              TableSpec("/Tables/dbo/pw_demo_contact", ("contactid", "fullname"))]
    result = plan_roles(TENANT, tables, READERS, int((NOW - age) * 1_000_000),
                        ownership_prefix="pw_demo_").shards[0].roles
    if legacy:
        for role in result:
            combined = role["decisionRules"][0]
            rules = []
            for row, column in zip(combined["constraints"]["rows"], combined["constraints"]["columns"]):
                rule = copy.deepcopy(combined)
                rule["permission"][0]["attributeValueIncludedIn"] = [row["tablePath"]]
                rule["constraints"] = {"rows": [copy.deepcopy(row)], "columns": [copy.deepcopy(column)]}
                rules.append(rule)
            role["decisionRules"] = rules
    return result


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("age,expected", [(60, "fresh_generation"), (2700, "withdrawn_expired_generation")])
def test_multi_table_canonical_current_and_legacy_policies_expire(legacy, age, expected):
    fabric = Fabric(multi_table_roles(age, legacy=legacy))
    result = inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)
    assert result["status"] == expected
    assert len(fabric.puts) == int(age == 2700)


@pytest.mark.parametrize("legacy", [False, True])
def test_mixed_generations_inside_multi_table_role_are_withdrawn(legacy):
    existing = multi_table_roles(60, legacy=legacy)
    rule = existing[0]["decisionRules"][1 if legacy else 0]
    row = rule["constraints"]["rows"][0 if legacy else 1]
    row["value"] = row["value"].rsplit(" = ", 1)[0] + " = " + str(int((NOW - 120) * 1_000_000))
    fabric = Fabric(existing)
    assert inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)["status"] == "withdrawn_mixed_generations"


@pytest.mark.parametrize("change", ["extra_path", "missing_path", "missing_row", "missing_column",
    "duplicate_row", "duplicate_column", "duplicate_table", "wrong_column_path", "swapped_columns",
    "wrong_reader", "broadened_predicate", "helper_column", "write_action"])
def test_multi_table_policy_rejects_non_bijective_or_broadened_security_scope(change):
    existing = multi_table_roles(3000)
    rule = existing[0]["decisionRules"][0]
    paths = rule["permission"][0]["attributeValueIncludedIn"]
    rows = rule["constraints"]["rows"]
    columns = rule["constraints"]["columns"]
    if change == "extra_path": paths.append("/Tables/dbo/pw_demo_unprotected")
    elif change == "missing_path": paths.pop()
    elif change == "missing_row": rows.pop()
    elif change == "missing_column": columns.pop()
    elif change == "duplicate_row": rows.append(copy.deepcopy(rows[0]))
    elif change == "duplicate_column": columns.append(copy.deepcopy(columns[0]))
    elif change == "duplicate_table":
        paths.append(paths[0]); rows.append(copy.deepcopy(rows[0])); columns.append(copy.deepcopy(columns[0]))
    elif change == "wrong_column_path": columns[1]["tablePath"] = columns[0]["tablePath"]
    elif change == "swapped_columns": columns.reverse()
    elif change == "wrong_reader": rows[1]["value"] = rows[1]["value"].replace(READERS[0], READERS[1])
    elif change == "broadened_predicate": rows[1]["value"] = rows[1]["value"].replace(" WHERE ", " WHERE 1=1 OR ")
    elif change == "helper_column": columns[1]["columnNames"].append("__pw_reader")
    elif change == "write_action": rule["permission"][1]["attributeValueIncludedIn"].append("Write")
    fabric = Fabric(existing)
    result = run_watchdog(config(), credential=object(), client_factory=lambda *a, **k: fabric, now=lambda: NOW)
    assert result["critical"] and not fabric.puts


def test_unowned_roles_preserved_and_broad_drift_reported_critical():
    unowned = {"name": "UnmanagedBroad", "decisionRules": [{"permission": [
        {"attributeName": "Path", "attributeValueIncludedIn": ["*"]}]}]}
    fabric = Fabric([*roles(age=3000), unowned])
    result = inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)
    assert fabric.roles == [unowned]
    assert result["critical"] and result["unmanaged_overlap"]


def test_unknown_owned_shape_blocks_with_critical_result_without_deleting_anything():
    fabric = Fabric([*roles(age=3000), {"name": "pw_demo_unrecognized_admin_role"}])
    result = run_watchdog(config(), credential=object(), client_factory=lambda *a, **k: fabric, now=lambda: NOW)
    assert result["critical"] and not fabric.puts
    assert result["items"]["a000_t000"]["error_type"] == "NativePolicyError"


def test_modified_canonical_role_without_rls_is_not_treated_as_fresh():
    existing = roles()
    existing[0]["decisionRules"][0].pop("constraints")
    fabric = Fabric(existing)
    result = run_watchdog(config(), credential=object(), client_factory=lambda *a, **k: fabric, now=lambda: NOW)
    assert result["critical"] and not fabric.puts


def test_otherwise_canonical_role_cannot_silently_add_unconfigured_table_scope():
    existing = plan_roles(TENANT, [TableSpec("/Tables/dbo/raw_account", ("accountid",))],
        READERS, int(NOW * 1_000_000), ownership_prefix="pw_demo_").shards[0].roles
    fabric = Fabric(existing)
    result = run_watchdog(config(), credential=object(), client_factory=lambda *a, **k: fabric, now=lambda: NOW)
    assert result["critical"] and not fabric.puts


def test_removed_table_still_expires_when_in_same_canonical_deployment_namespace():
    changed = config().model_copy(update={"tables": (TableSelection(name="contact", columns=("contactid",)),)})
    fabric = Fabric(roles(age=3000))
    result = inspect_item(fabric, changed, inspect_only=False, now=lambda: NOW)
    assert result["status"] == "withdrawn_expired_generation"
    assert result["control_plane_verified"] and not fabric.roles


def test_concurrent_fresh_publication_is_preserved_by_exact_etag():
    fabric = Fabric(roles(age=3000))
    fabric.race = roles(age=30)
    result = inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)
    assert result["status"] == "concurrent_publication_preserved" and not result["critical"]
    assert fabric.roles == fabric.race and len(fabric.puts) == 1
    assert fabric.puts[0][1] == '"old"'


def test_concurrent_stale_policy_change_remains_critical_without_retrying_put():
    fabric = Fabric(roles(age=3000))
    fabric.race = roles(age=3100)
    result = inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)
    assert result["critical"] and len(fabric.puts) == 1


def test_failure_on_one_item_does_not_skip_other_item_or_leak_error_details():
    first, second = Fabric(roles(age=3000)), Fabric(roles(age=3000))
    first.failure = True
    clients = {ITEM: first, OTHER_ITEM: second}
    result = run_watchdog(config({"a000_t000": ITEM, "a001_t000": OTHER_ITEM}), credential=object(),
                          client_factory=lambda tenant, workspace, item, **k: clients[item], now=lambda: NOW)
    assert result["critical"] and len(second.puts) == 1
    assert "private customer" not in json.dumps(result)
    assert result["independent_of_publisher_state"]


def test_no_owned_roles_needs_no_mutation():
    fabric = Fabric([])
    result = inspect_item(fabric, config(), inspect_only=False, now=lambda: NOW)
    assert result["status"] == "no_owned_roles" and not fabric.puts


def test_empty_serving_configuration_is_critical():
    result = run_watchdog(config({}), credential=object(), now=lambda: NOW)
    assert result["critical"]


def test_cli_env_config_and_inspect_mode(monkeypatch, capsys):
    monkeypatch.setenv("POLICYWEAVER_CONFIG_JSON", config().model_dump_json())
    captured = []
    def run(c, inspect_only):
        captured.append(inspect_only)
        return {"critical": False, "status": "ok"}
    monkeypatch.setattr("policyweaver.native_watchdog.run_watchdog", run)
    assert main(["--inspect"]) == 0
    assert captured == [True] and '"status": "ok"' in capsys.readouterr().out


def test_cli_bad_config_redacts_validation_details(monkeypatch, capsys):
    monkeypatch.setenv("POLICYWEAVER_CONFIG_JSON", '{"private-data":"secret"}')
    assert main(["--once"]) == 2
    assert "private-data" not in capsys.readouterr().out


def test_missing_fabric_permission_reports_actionable_sanitized_http_code():
    class Denied(Fabric):
        def list_roles(self):
            raise FabricRequestError("Fabric GET HTTP 403", status_code=403, error_code="InsufficientPrivileges")
    result = run_watchdog(config(), credential=object(), client_factory=lambda *a, **k: Denied([]), now=lambda: NOW)
    assert result["items"]["a000_t000"]["error_code"] == "fabric_403_InsufficientPrivileges"
