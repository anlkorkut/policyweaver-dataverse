"""Offline onboarding discovery: identity, scope, pagination and no-data invariants."""
import base64
import json
from types import SimpleNamespace
from urllib.parse import parse_qs
from uuid import UUID

import httpx
import pytest

from policyweaver.onboarding_discovery import BoundCredential, DiscoveryError, discover_environment


def gid(n):
    return str(UUID(int=n))


DV = "https://newcustomer.crm4.dynamics.com"
FAB = "https://api.fabric.microsoft.com"
UPN = "operator@customer.example"


def jwt(claims):
    enc = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return enc({"alg": "RS256"}) + "." + enc(claims) + ".test-signature"


class Credential:
    def __init__(self, changes=None):
        self.calls = []
        self.changes = changes or {}

    def get_token(self, scope):
        self.calls.append(scope)
        claims = {"tid": gid(1), "oid": gid(2), "upn": UPN, "scp": "user_impersonation",
                  "exp": 9999999999, "aud": scope.removesuffix("/.default")}
        claims.update(self.changes(scope) if callable(self.changes) else self.changes)
        return SimpleNamespace(token=jwt(claims), expires_on=9999999999)


def reader(n=3, upn="reader@customer.example"):
    return {"systemuserid": gid(n), "azureactivedirectoryobjectid": gid(n + 100), "domainname": upn,
            "fullname": "Example Reader", "_businessunitid_value": gid(11),
            "isdisabled": False, "applicationid": None, "accessmode": 0}


def entity(name="account"):
    return {"LogicalName": name, "PrimaryIdAttribute": name + "id", "EntitySetName": name + "s",
            "OwnershipType": "UserOwned", "Privileges": [{"PrivilegeId": gid(20), "PrivilegeType": "Read",
            "Name": "prvReadAccount", "CanBeBasic": True, "CanBeGlobal": True}]}


def attribute(name):
    kind = "Uniqueidentifier" if name == "accountid" else "Lookup" if name == "ownerid" else "String"
    return {"LogicalName": name, "AttributeType": kind,
            "AttributeTypeName": {"Value": kind + "Type"}, "IsSecured": name == "name", "IsValidForRead": True}


class Service:
    def __init__(self, override=None):
        self.requests, self.override = [], override

    def handle(self, request):
        self.requests.append(request)
        assert request.method == "GET"
        assert "CallerObjectId" not in request.headers
        if self.override:
            result = self.override(request)
            if result is not None:
                return result
        path = request.url.path
        if path.endswith("/WhoAmI"):
            body = {"OrganizationId": gid(10), "UserId": gid(12)}
        elif path.endswith("/systemusers(" + gid(12) + ")"):
            body = {"systemuserid": gid(12), "azureactivedirectoryobjectid": gid(2), "domainname": UPN,
                    "isdisabled": False, "applicationid": None}
        elif path.endswith("/systemusers"):
            body = {"value": [reader()]}
        elif "/Attributes(LogicalName='" in path:
            name = path.split("/Attributes(LogicalName='")[1].split("')")[0]
            body = attribute(name)
        elif path.endswith("/Attributes"):
            body = {"value": [attribute("accountid"), attribute("name"),
                              {**attribute("image"), "AttributeType": "Image"}]}
        elif path.endswith("/EntityDefinitions"):
            body = {"value": [entity()]}
        elif "/EntityDefinitions(LogicalName='" in path:
            body = entity(path.split("LogicalName='")[1].split("')")[0])
        elif path.endswith("/attributemaskingrules"):
            body = {"value": [{"entityname": "account", "attributelogicalname": "name", "_maskingruleid_value": gid(25)}]}
        elif path == "/v1/workspaces":
            body = {"value": [{"id": gid(30), "displayName": "Client Serving", "type": "Workspace", "capacityId": gid(31)}]}
        elif path == f"/v1/workspaces/{gid(30)}/lakehouses":
            body = {"value": [{"id": gid(32), "workspaceId": gid(30), "displayName": "serving_candidate", "type": "Lakehouse",
                             "properties": {"defaultSchema": "dbo", "sqlEndpointProperties": {"id": gid(33),
                             "connectionString": "client.datawarehouse.fabric.microsoft.com", "provisioningStatus": "Success"}}}]}
        else:
            pytest.fail("Unexpected endpoint (possible business-data request): " + path)
        return httpx.Response(200, json=body)


def discover(service=None, **changes):
    service = service or Service()
    args = {"tenant_id": gid(1), "dataverse_url": DV, "operator_upn": UPN,
            "credential": Credential(), "requested_tables": {"account": ["name", "_ownerid_value"]},
            "workspace_id": gid(30), "transport": httpx.MockTransport(service.handle)}
    args.update(changes)
    return discover_environment(**args)


def test_complete_inventory_derives_operator_and_org_and_does_not_select_anything():
    service = Service()
    result = discover(service, environment_id=gid(99))
    assert result["organization_id"] == gid(10)
    assert result["operator"] == {"entra_id": gid(2), "upn": UPN, "dataverse_id": gid(12)}
    assert result["environment_id"] == {"value": gid(99), "verified": False, "source": "user_supplied"}
    assert result["readers"][0]["entra_id"] == gid(103)
    assert result["tables"][0]["columns"] == ["accountid", "name", "_ownerid_value"]
    assert result["tables"][0]["attributes"][1]["is_masked"] is True
    assert result["lakehouses"][0]["sql_endpoint"]["id"] == gid(33)
    assert result["discovery"]["publication_boundary_verified"] is False
    assert result["discovery"]["operator_permissions_verified"] is False
    assert result["discovery"]["reader_candidates_are_selected"] is False
    assert result["discovery"]["business_records_read"] is False
    assert all("Attributes?" not in str(r.url) for r in service.requests)
    assert len(service.requests) == result["discovery"]["requests"]


def test_no_workspace_is_automatically_selected_and_empty_tables_only_catalog():
    service = Service()
    result = discover(service, workspace_id=None, requested_tables={})
    assert result["selected_workspace"] is None and result["lakehouses"] == []
    assert result["tables"][0]["attributes_verified"] is False
    assert "columns" not in result["tables"][0]
    assert not any("/Attributes" in r.url.path or "lakehouses" in r.url.path or "masking" in r.url.path for r in service.requests)


def test_empty_column_list_describes_only_explicit_table_candidates_without_selection():
    service = Service()
    result = discover(service, requested_tables={"account": []})
    table = result["tables"][0]
    assert table["attributes_verified"] is False
    assert "columns" not in table and "attributes" not in table
    candidates = {a["logical_name"]: a for a in table["attribute_candidates"]}
    assert candidates["name"]["supported_scalar"] is True
    assert candidates["image"]["supported_scalar"] is False
    assert not any("/Attributes(LogicalName=" in r.url.path or "masking" in r.url.path for r in service.requests)
    assert sum(r.url.path.endswith("/Attributes") for r in service.requests) == 1


@pytest.mark.parametrize("claims", [{"tid": gid(7)}, {"oid": gid(7)}, {"upn": "wrong@customer.example"},
    {"preferred_username": "wrong@customer.example"}, {"upn": None}, {"scp": ""}, {"idtyp": "app"},
    {"exp": 1}, {"exp": float("nan")}, {"aud": "https://evil.example"}, {"nbf": 9999999999}])
def test_wrong_token_is_refused_before_first_http(claims):
    service = Service()
    with pytest.raises(DiscoveryError, match="does not match"):
        discover(service, credential=Credential(claims), operator_entra_id=gid(2))
    assert service.requests == []


def test_operator_oid_is_pinned_when_resource_token_changes():
    service = Service()
    credential = Credential(lambda scope: {"oid": gid(44)} if scope.startswith(FAB) else {})
    with pytest.raises(DiscoveryError) as exc:
        discover(service, credential=credential)
    assert exc.value.code == "operator_token_binding_mismatch"
    assert not any(r.url.host == "api.fabric.microsoft.com" for r in service.requests)


def test_bound_credential_refuses_scope_overrides():
    credential = BoundCredential(Credential(), tenant_id=gid(1), dataverse_url=DV, operator_upn=UPN)
    with pytest.raises(DiscoveryError, match="unapproved"):
        credential.get_token(DV + "/.default", tenant_id=gid(8))
    with pytest.raises(DiscoveryError, match="unapproved"):
        credential.get_token("https://graph.microsoft.com/.default")


@pytest.mark.parametrize("url", ["https://org.crm.microsoftdynamics.us", "https://org.crm.dynamics.cn", "https://evil.example",
    "http://org.crm.dynamics.com", DV + "/api", "https://user:secret@newcustomer.crm4.dynamics.com", DV + "?token=x"])
def test_cloud_or_origin_mismatch_refused_without_http(url):
    service = Service()
    with pytest.raises(DiscoveryError, match="public-cloud"):
        discover(service, dataverse_url=url)
    assert service.requests == []


def test_whoami_must_match_delegated_operator_source_row():
    def override(request):
        if "/systemusers(" in request.url.path:
            return httpx.Response(200, json={"systemuserid": gid(12), "azureactivedirectoryobjectid": gid(99),
                                           "domainname": UPN, "isdisabled": False, "applicationid": None})
    with pytest.raises(DiscoveryError) as exc:
        discover(Service(override))
    assert exc.value.code == "source_operator_binding_mismatch"


@pytest.mark.parametrize("next_link", ["https://evil.example/api/data/v9.2/systemusers", DV + "/api/data/v9.2/accounts",
    DV + "/api/data/v9.2/systemusers?$filter=isdisabled%20eq%20true", DV + "/api/data/v9.2/%2e%2e/systemusers"])
def test_source_continuation_cannot_escape_origin_collection_or_filter(next_link):
    def override(request):
        if request.url.path.endswith("/systemusers"):
            return httpx.Response(200, json={"value": [], "@odata.nextLink": next_link})
    service = Service(override)
    with pytest.raises(DiscoveryError):
        discover(service)
    assert len(service.requests) == 3


def test_source_trusted_continuation_preserves_select_and_filter():
    def override(request):
        if request.url.path.endswith("/systemusers"):
            if "$skiptoken" not in request.url.params:
                return httpx.Response(200, json={"value": [reader()], "@odata.nextLink": str(request.url) + "&$skiptoken=next"})
            return httpx.Response(200, json={"value": [reader(4, "second@customer.example")]})
    result = discover(Service(override))
    assert len(result["readers"]) == 2


@pytest.mark.parametrize("suffix", ["https://evil.example/v1/workspaces", FAB + "/v1/capacities?continuationToken=x",
    FAB + "/v1/workspaces?unexpected=x", FAB + "/v1/workspaces?continuationToken=x&continuationToken=y"])
def test_fabric_continuation_is_bound_to_exact_collection(suffix):
    def override(request):
        if request.url.path == "/v1/workspaces":
            return httpx.Response(200, json={"value": [], "continuationUri": suffix})
    service = Service(override)
    with pytest.raises(DiscoveryError) as exc:
        discover(service)
    assert exc.value.code == "unsafe_fabric_continuation"
    assert sum(r.url.host == "api.fabric.microsoft.com" for r in service.requests) == 1


def test_fabric_continuation_token_only_and_port443_are_supported():
    def override(request):
        if request.url.path == "/v1/workspaces" and "continuationToken" not in request.url.params:
            return httpx.Response(200, json={"value": [], "continuationToken": "opaque+/="})
    result = discover(Service(override))
    assert len(result["workspaces"]) == 1


@pytest.mark.parametrize("status", [301, 302, 403, 429, 500])
def test_errors_are_sanitized_and_not_interpreted_as_empty_access(status):
    def override(request):
        return httpx.Response(status, headers={"Location": "https://evil.example"}, text="private-response-secret")
    service = Service(override)
    with pytest.raises(DiscoveryError) as exc:
        discover(service)
    assert "private-response-secret" not in str(exc.value)
    assert len(service.requests) == 1
    assert exc.value.status == status


@pytest.mark.parametrize("budget", [{"max_readers": 1}, {"max_pages": 1}])
def test_reader_or_page_caps_fail_instead_of_returning_partial_inventory(budget):
    def override(request):
        if request.url.path.endswith("/systemusers"):
            return httpx.Response(200, json={"value": [reader(), reader(4, "second@customer.example")],
                                            "@odata.nextLink": str(request.url) + "&$skiptoken=x"})
    with pytest.raises(DiscoveryError) as exc:
        discover(Service(override), **budget)
    assert exc.value.code in {"discovery_row_limit_exceeded", "discovery_page_limit_exceeded"}


@pytest.mark.parametrize("changes", [{"max_readers": True}, {"max_pages": 0}, {"max_seconds": float("inf")},
    {"requested_tables": {"account": "name"}}, {"requested_tables": {"account": ["name", "name"]}},
    {"requested_tables": {"account':malicious": []}}, {"reader_upns": []}])
def test_invalid_selection_or_budget_fails_before_network(changes):
    service = Service()
    with pytest.raises(DiscoveryError):
        discover(service, **changes)
    assert service.requests == []


def test_exact_upn_cohort_is_server_filtered_and_must_be_complete():
    service = Service()
    result = discover(service, reader_upns=["reader@customer.example"])
    query = next(r.url for r in service.requests if r.url.path.endswith("/systemusers"))
    assert "domainname eq 'reader@customer.example'" in query.params["$filter"]
    assert result["discovery"]["reader_scope"] == "explicit_upn_cohort"
    with pytest.raises(DiscoveryError) as exc:
        discover(reader_upns=["missing@customer.example"])
    assert exc.value.code == "reader_cohort_incomplete"


def test_duplicate_identity_is_rejected():
    def override(request):
        if request.url.path.endswith("/systemusers"):
            return httpx.Response(200, json={"value": [reader(), reader()]})
    with pytest.raises(DiscoveryError) as exc:
        discover(Service(override))
    assert exc.value.code == "duplicate_reader_identity"


def test_unknown_requested_workspace_is_never_replaced_with_first_candidate():
    with pytest.raises(DiscoveryError) as exc:
        discover(workspace_id=gid(999))
    assert exc.value.code == "workspace_not_visible"


def test_selected_attribute_unsupported_fails_before_fabric_discovery():
    def override(request):
        if "/Attributes(LogicalName='name')" in request.url.path:
            return httpx.Response(200, json={**attribute("name"), "AttributeType": "Image"})
    service = Service(override)
    with pytest.raises(DiscoveryError) as exc:
        discover(service)
    assert exc.value.code == "selected_attribute_unsupported"
    assert not any(r.url.host == "api.fabric.microsoft.com" for r in service.requests)


def test_alias_duplicates_are_rejected():
    with pytest.raises(DiscoveryError) as exc:
        discover(requested_tables={"account": ["ownerid", "_ownerid_value"]})
    assert exc.value.code == "duplicate_column_alias"


def test_deadline_is_checked_after_response():
    values = iter([0, 0, 0, 11])
    service = Service()
    with pytest.raises(DiscoveryError) as exc:
        discover(service, max_seconds=10, monotonic=lambda: next(values))
    assert exc.value.code == "discovery_deadline_exceeded"
    assert len(service.requests) == 1


def test_sql_connection_string_must_not_contain_credentials_or_arbitrary_endpoint():
    def override(request):
        if request.url.path.endswith("/lakehouses"):
            return httpx.Response(200, json={"value": [{"id": gid(32), "workspaceId": gid(30), "type": "Lakehouse",
                "displayName": "candidate", "properties": {"sqlEndpointProperties": {"id": gid(33),
                "connectionString": "Server=evil.example;Password=private-response-secret", "provisioningStatus": "Success"}}}]})
    with pytest.raises(DiscoveryError) as exc:
        discover(Service(override))
    assert exc.value.code == "unsupported_sql_connection_format"
    assert "private-response-secret" not in str(exc.value)


def test_mocked_discovery_to_client_configuration_matches_actual_runtime_plan():
    from policyweaver.onboarding import ClientSelections, OnboardingRequest, create_configuration
    from policyweaver.runtime import role_plan

    inventory = discover()
    request = OnboardingRequest(tenant_id=gid(1), environment_url=DV, operator_upn=UPN,
        workspace_id=gid(30), tables=[{"name": "account", "columns": ["name", "_ownerid_value"]}])
    selections = ClientSelections(workspace_id=gid(30), deployment_name="pw_customer",
        reader_entra_ids=[gid(103)], tables=[{"name": "account", "columns": ["name", "ownerid"]}],
        required_access_paths=["onelake", "sql"])
    config, review = create_configuration(request, inventory, selections)
    actual_plan = role_plan(config, config.tables, config.readers, generation=1)

    assert config.tenant_id == gid(1) and config.organization_id == gid(10)
    assert config.workspace_id == gid(30) and config.readers == (gid(103),)
    assert config.serving_items == {} and config.discover_readers is False
    assert config.tables[0].columns == ("accountid", "name", "_ownerid_value")
    assert config.state_directory == "state" and config.role_naming == "readable"
    assert review["capacity_plan"]["required_lakehouses"] == len(actual_plan.shards)
    assert [i["shard"] for i in review["capacity_plan"]["planned_items"]] == [s.key for s in actual_plan.shards]
    assert review["remote_changes"] is False and review["boundary_verified"] is False
    assert review["production_certified"] is False
