"""Customer onboarding must never inherit demo scope or publish implicitly."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from policyweaver.config import load_config, state_path
from policyweaver.onboarding import (ClientSelections, ENV_TEMPLATE, OnboardingError,
    OnboardingRequest, REQUEST_TEMPLATE, SELECTIONS_TEMPLATE, configure, create_configuration,
    initialize, main)


def gid(n):
    return str(UUID(int=n))


def fixtures(readers=2):
    now = datetime.now(timezone.utc).isoformat()
    request = {"tenant_id": gid(1), "environment_url": "https://customer.crm4.dynamics.com",
        "operator_upn": "operator@customer.example", "workspace_id": gid(3),
        "tables": [{"name": "account", "columns": ["name", "ownerid"]}]}
    selections = {"workspace_id": gid(3), "deployment_name": "pw_customer",
        "reader_entra_ids": [gid(100 + i) for i in range(readers)],
        "tables": [{"name": "account", "columns": ["name", "ownerid"]}],
        "required_access_paths": ["onelake", "sql"]}
    table = {"name": "account", "primary_key": "accountid", "entity_set": "accounts",
        "read_privilege_id": gid(20), "ownership_type": "UserOwned", "attributes_verified": True,
        "columns": ["accountid", "name", "_ownerid_value"],
        "attributes": [
            {"logical_name": "accountid", "property_name": "accountid", "attribute_type": "Uniqueidentifier", "is_secured": False, "is_masked": False},
            {"logical_name": "name", "property_name": "name", "attribute_type": "String", "is_secured": True, "is_masked": True},
            {"logical_name": "ownerid", "property_name": "_ownerid_value", "attribute_type": "Owner", "is_secured": False, "is_masked": False}]}
    workspace = {"id": gid(3), "name": "Client Serving", "type": "Workspace", "capacity_id": gid(5)}
    inventory = {"schema_version": 1, "cloud": "public", "observed_at": now, "completed_at": now,
        "tenant_id": gid(1), "environment_url": request["environment_url"], "organization_id": gid(2),
        "operator": {"upn": request["operator_upn"], "entra_id": gid(6), "dataverse_id": gid(7)},
        "environment_id": {"value": None, "verified": False, "source": "not_supplied"},
        "workspaces": [workspace], "selected_workspace": workspace, "lakehouses": [],
        "readers": [{"entra_id": gid(100 + i), "dataverse_id": gid(5000 + i), "upn": f"reader{i}@customer.example",
            "accessmode": 0, "name": f"Reader {i}", "business_unit_id": gid(12)} for i in range(readers)],
        "tables": [table], "discovery": {"remote_methods": ["GET"], "business_records_read": False,
            "reader_candidates_are_selected": False, "publication_boundary_verified": False,
            "operator_permissions_verified": False}}
    return request, inventory, selections


def build(request, inventory, selections, **kwargs):
    return create_configuration(OnboardingRequest.model_validate(request), inventory,
                                ClientSelections.model_validate(selections), **kwargs)


def save_inputs(directory, inputs):
    paths = []
    for name, value in zip(("request.json", "inventory.json", "selections.json"), inputs):
        path = directory / name
        path.write_text(json.dumps(value), encoding="utf-8")
        paths.append(path)
    return paths


def test_init_is_inert_and_templates_match_distribution(tmp_path):
    output = tmp_path / "onboarding"
    result = initialize(output)
    assert result["remote_changes"] is False
    assert json.loads((output / "request.json").read_text()) == REQUEST_TEMPLATE
    assert json.loads((output / "selections.json").read_text()) == SELECTIONS_TEMPLATE
    for name, expected in (("client-onboarding.request.example.json", REQUEST_TEMPLATE),
                           ("client-onboarding.selections.example.json", SELECTIONS_TEMPLATE)):
        assert json.loads((Path(__file__).parents[1] / "examples" / name).read_text()) == expected
    assert (output / "env.example").read_text() == ENV_TEMPLATE
    with pytest.raises(ValidationError):
        OnboardingRequest.model_validate(REQUEST_TEMPLATE)
    with pytest.raises(ValidationError):
        ClientSelections.model_validate(SELECTIONS_TEMPLATE)
    assert not (output / "policyweaver.config.json").exists()


def test_new_client_is_explicit_private_unprovisioned_and_account_pin_not_overclaimed():
    request, inventory, selections = fixtures()
    config, plan = build(request, inventory, selections)
    assert config.organization_id == gid(2)
    assert config.authentication == "azure_cli" and config.serving_items == {}
    assert config.readers == tuple(selections["reader_entra_ids"])
    assert config.discover_readers is False and config.role_naming == "user_business_role" and config.source_workers == 1
    assert plan["role_naming"] == "user_business_role"
    assert config.tables[0].columns == ("accountid", "name", "_ownerid_value")
    assert config.retention_mode == "timed" and config.state_directory == "state"
    assert plan["remote_changes"] is False and plan["boundary_verified"] is False
    assert plan["production_certified"] is False and plan["source_permissions_verified"] is False
    assert plan["operator_binding_scope"].startswith("discovery_only")
    assert plan["capacity_plan"]["required_lakehouses"] == 1
    assert plan["capacity_plan"]["planned_items"] == [{"shard": "a000_t000", "name": "pw_customer_a000_t000", "id": None}]
    assert plan["table_selections"][0]["primary_key_added"] is True
    assert plan["table_selections"][0]["masked_columns"] == ["name"]


def test_customer_scope_is_not_reused_between_deployments():
    r, i, s = fixtures()
    config_a, _ = build(r, i, s)
    r["tenant_id"] = i["tenant_id"] = gid(8000)
    r["workspace_id"] = s["workspace_id"] = i["selected_workspace"]["id"] = gid(8001)
    r["environment_url"] = i["environment_url"] = "https://anothercustomer.crm.dynamics.com"
    i["organization_id"] = gid(8002)
    s["deployment_name"] = "pw_another"
    config_b, _ = build(r, i, s)
    assert config_a.tenant_id != config_b.tenant_id
    assert config_a.workspace_id != config_b.workspace_id
    assert config_a.organization_id != config_b.organization_id
    assert config_a.fingerprint != config_b.fingerprint


@pytest.mark.parametrize("count,quota,reserve,tables_per_shard,expected", [
    (200, 250, 10, 100, 1), (500, 250, 10, 100, 3), (1000, 250, 10, 100, 5),
    (1000, 1000, 10, 100, 2), (240, 250, 10, 100, 1), (241, 250, 10, 100, 2)])
def test_native_quota_sharding_matches_runtime(count, quota, reserve, tables_per_shard, expected):
    r, i, s = fixtures(count)
    s.update(role_limit=quota, reserved_roles=reserve, tables_per_shard=tables_per_shard)
    if quota > 250:
        s["quota_exception_reference"] = "Client support case, scoped to serving items"
    _, plan = build(r, i, s)
    assert plan["capacity_plan"]["required_lakehouses"] == expected
    assert plan["capacity_plan"]["quota_verified_live"] is False


def test_table_shards_multiply_and_do_not_reuse_source_lakehouse():
    r, i, s = fixtures(500)
    second = deepcopy(i["tables"][0])
    second["name"] = "contact"
    i["tables"].append(second)
    for obj in (r, s):
        obj["tables"].append({"name": "contact", "columns": ["name"]})
    r["tables"][1]["columns"].append("ownerid")
    s["tables_per_shard"] = 1
    i["lakehouses"] = [{"id": gid(700), "name": "source_dataverse", "workspace_id": gid(3)}]
    config, plan = build(r, i, s)
    assert plan["capacity_plan"]["required_lakehouses"] == 6
    assert config.serving_items == {}


@pytest.mark.parametrize("change,code", [
    (lambda r,i,s: i.update(tenant_id=gid(99)), "inventory_request_scope_mismatch"),
    (lambda r,i,s: i.update(environment_url="https://other.crm.dynamics.com"), "inventory_request_scope_mismatch"),
    (lambda r,i,s: i.update(cloud="government"), "inventory_request_scope_mismatch"),
    (lambda r,i,s: i["operator"].update(upn="wrong@customer.example"), "inventory_operator_mismatch"),
    (lambda r,i,s: r.update(operator_entra_id=gid(99)), "inventory_operator_mismatch"),
    (lambda r,i,s: i.update(organization_id=gid(0)), "invalid_inventory_identifier"),
    (lambda r,i,s: r.update(workspace_id=None), "set_request_workspace_and_rediscover"),
    (lambda r,i,s: i.update(selected_workspace=None), "selected_workspace_not_inventoried_rediscover"),
    (lambda r,i,s: i["discovery"].update(publication_boundary_verified=True), "invalid_inventory_provenance"),
    (lambda r,i,s: i["discovery"].update(remote_methods=["POST"]), "invalid_inventory_provenance"),
    (lambda r,i,s: i["environment_id"].update(verified=True), "inventory_environment_reference_mismatch"),
    (lambda r,i,s: r.update(environment_id=gid(99)), "inventory_environment_reference_mismatch"),
    (lambda r,i,s: s.update(reader_entra_ids=[gid(999)]), "selected_reader_not_in_inventory"),
    (lambda r,i,s: i["readers"].append(i["readers"][0]), "invalid_reader_inventory"),
    (lambda r,i,s: i["readers"][1].update(dataverse_id=i["readers"][0]["dataverse_id"]), "ambiguous_or_ineligible_reader_inventory"),
    (lambda r,i,s: i["readers"][0].update(accessmode=False), "ambiguous_or_ineligible_reader_inventory"),
    (lambda r,i,s: r.update(reader_upns=["missing@customer.example"]), "inventory_reader_cohort_mismatch"),
    (lambda r,i,s: i["tables"][0].update(attributes_verified=False), "selected_table_attributes_unverified_rediscover_explicit_columns"),
    (lambda r,i,s: r.update(tables=[]), "selected_table_attributes_unverified_rediscover_explicit_columns"),
    (lambda r,i,s: r["tables"][0].update(columns=["name"]), "inventory_columns_differ_from_request_rediscover"),
    (lambda r,i,s: r["tables"][0].update(columns=[]), "inventory_columns_differ_from_request_rediscover"),
    (lambda r,i,s: s["tables"][0].update(columns=["secret"]), "selected_column_not_in_verified_inventory"),
    (lambda r,i,s: i["tables"][0]["attributes"][1].update(attribute_type="Image"), "unsupported_or_unverified_attribute"),
    (lambda r,i,s: i["tables"][0]["attributes"][1].update(is_secured=None), "unsupported_or_unverified_attribute"),
    (lambda r,i,s: i["tables"][0]["attributes"][2].update(property_name="ownerid"), "unsupported_or_unverified_attribute"),
    (lambda r,i,s: i["tables"][0]["attributes"][0].update(attribute_type="String"), "selected_primary_key_unverified"),
    (lambda r,i,s: s["tables"][0].update(columns=["ownerid", "_ownerid_value"]), "duplicate_selected_column_alias"),
    (lambda r,i,s: i["tables"][0].update(columns=["secret"]), "attribute_property_mapping_mismatch"),
    (lambda r,i,s: i["lakehouses"].append({"name":"pw_customer_a000_t000","workspace_id":gid(3)}), "serving_name_already_exists_choose_new_deployment_or_resume_original_config"),
    (lambda r,i,s: i["lakehouses"].append({"name":"unrelated","workspace_id":gid(99)}), "lakehouse_inventory_scope_mismatch"),
])
def test_fail_closed_inventory_and_selection_binding(change, code):
    r, i, s = fixtures()
    change(r, i, s)
    with pytest.raises(OnboardingError) as error:
        build(r, i, s)
    assert error.value.code == code


@pytest.mark.parametrize("offset", [-25, 1])
def test_old_and_future_inventory_rejected(offset):
    r, i, s = fixtures()
    timestamp = (datetime.now(timezone.utc) + timedelta(hours=offset)).isoformat()
    i["observed_at"] = i["completed_at"] = timestamp
    with pytest.raises(OnboardingError, match="inventory_stale"):
        build(r, i, s)


def test_operator_not_selected_for_consumer_validation():
    r, i, s = fixtures()
    i["operator"]["entra_id"] = i["readers"][0]["entra_id"]
    with pytest.raises(OnboardingError, match="operator_cannot_be"):
        build(r, i, s)


@pytest.mark.parametrize("field,value", [("reader_entra_ids", []), ("required_access_paths", []),
    ("tables", []), ("workspace_id", gid(0)), ("role_limit", 1000), ("role_limit", True),
    ("identity_verification", "custom_api"), ("identity_api_assembly_sha256", "a"*64),
    ("deployment_name", "client unsafe"), ("serving_items", {"a000_t000":gid(4)}),
    ("authentication", "managed_identity"), ("client_secret", "secret")])
def test_required_decisions_and_unknown_knobs_cannot_be_silently_defaulted(field, value):
    _, _, s = fixtures()
    s[field] = value
    with pytest.raises(ValidationError):
        ClientSelections.model_validate(s)


@pytest.mark.parametrize("field,value", [("tenant_id", None), ("tenant_id", gid(0)),
    ("environment_url", "http://customer.crm.dynamics.com"), ("environment_url", "https://localhost"),
    ("environment_url", "https://customer.crm.dynamics.com/api/data/v9.2"),
    ("environment_url", "https://customer.crm.microsoftdynamics.us"), ("operator_upn", "username"),
    ("reader_upns", ["one@customer.example", "ONE@CUSTOMER.EXAMPLE"]), ("access_token", "secret")])
def test_invalid_discovery_requests(field, value):
    r, _, _ = fixtures()
    r[field] = value
    with pytest.raises(ValidationError):
        OnboardingRequest.model_validate(r)


def test_manual_retention_and_custom_proof_are_explicit_with_finite_freshness():
    r, i, s = fixtures()
    s.update(retention_mode="manual", identity_verification="custom_api", identity_api_assembly_sha256="a"*64)
    config, plan = build(r, i, s)
    assert config.retention_mode == "manual" and config.identity_verification == "custom_api"
    assert config.generation_lifetime_seconds + config.publication_budget_seconds <= 3600
    assert plan["native_expiry_self_enforcing"] is False


def test_combined_destination_identifier_checked_before_creating_output():
    r, i, s = fixtures()
    name = "a" * 100
    r["tables"][0]["name"] = s["tables"][0]["name"] = i["tables"][0]["name"] = name
    s["deployment_name"] = "pw_" + "x" * 35
    with pytest.raises(OnboardingError, match="native_policy_plan_invalid"):
        build(r, i, s)


def test_cli_configure_writes_only_new_local_artifacts(tmp_path, capsys):
    paths = save_inputs(tmp_path, fixtures())
    output = tmp_path / "private client with spaces"
    assert main(["configure", "--request", str(paths[0]), "--inventory", str(paths[1]),
        "--selections", str(paths[2]), "--output-dir", str(output)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "configured_not_provisioned"
    assert set(p.name for p in output.iterdir()) == {"request.json", "inventory.json", "selections.json",
        "policyweaver.config.json", "deployment-plan.json", "NEXT-STEPS.md"}
    config_path = output / "policyweaver.config.json"
    config = load_config(config_path)
    next_steps = (output / "NEXT-STEPS.md").read_text()
    assert "role_naming=user_business_role" in next_steps
    assert "publisher and independent watchdog" in next_steps and "version 0.3.1" in next_steps
    operating_limits = json.loads((output / "deployment-plan.json").read_text())["operating_limits"]
    assert any("user_business_role" in limit for limit in operating_limits)
    assert any("watchdog version 0.3.1" in limit for limit in operating_limits)
    assert state_path(config, config_path) == output / "state"
    assert not (output / "state").exists()
    assert main(["validate", "--config", str(config_path)]) == 0
    validation = json.loads(capsys.readouterr().out)
    assert validation["cloud_permissions_verified"] is False
    before = config_path.read_bytes()
    with pytest.raises(OnboardingError, match="output_directory_exists"):
        configure(*paths, output)
    assert config_path.read_bytes() == before
    with pytest.raises(OnboardingError, match="output_directory_exists"):
        initialize(output)


def test_bad_config_has_no_output_side_effects(tmp_path):
    r, i, s = fixtures()
    s["tables"][0]["columns"] = ["unknown"]
    paths = save_inputs(tmp_path, (r, i, s))
    output = tmp_path / "client"
    with pytest.raises(OnboardingError):
        configure(*paths, output)
    assert not output.exists()


@pytest.mark.parametrize("content,code", [('{"tenant_id":"a","tenant_id":"b"}', "duplicate_json_key"),
    ('{"number":NaN}', "nonfinite_json_number"), ('[]', "json_object_required"),
    ('{"client_secret":"VERY-PRIVATE-CREDENTIAL"}', "invalid_input")])
def test_sanitized_cli_errors_never_echo_inputs(tmp_path, capsys, content, code):
    path = tmp_path / "invalid.json"
    path.write_text(content)
    assert main(["discover", "--request", str(path), "--output", str(tmp_path / "inventory.json")]) == 1
    result = capsys.readouterr()
    assert not result.out and "VERY-PRIVATE-CREDENTIAL" not in result.err
    assert json.loads(result.err)["error_code"] == code


def test_discover_cli_uses_injected_expected_scope_and_no_mutation(tmp_path, monkeypatch, capsys):
    r, i, _ = fixtures()
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(r))
    class Credential:
        def __init__(self, tenant_id):
            assert tenant_id == r["tenant_id"]
        def close(self):
            pass
    def fake_discover(**kwargs):
        from policyweaver.auth import CachedCredential
        assert isinstance(kwargs["credential"], CachedCredential)
        assert kwargs["operator_upn"] == r["operator_upn"]
        assert kwargs["workspace_id"] == r["workspace_id"]
        assert kwargs["requested_tables"] == {"account": ("name", "ownerid")}
        assert kwargs["max_readers"] == 5000
        return {**i, "discovery": {**i["discovery"], "requests": 9}}
    monkeypatch.setattr("azure.identity.AzureCliCredential", Credential)
    monkeypatch.setattr("policyweaver.onboarding.discover_environment", fake_discover)
    output = tmp_path / "inventory.json"
    args = ["discover", "--request", str(request_path), "--output", str(output)]
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["remote_changes"] is False and result["requests"] == 9
    before = output.read_bytes()
    assert main(args) == 1
    assert json.loads(capsys.readouterr().err)["error_code"] == "inventory_output_exists_choose_new_file"
    assert output.read_bytes() == before
