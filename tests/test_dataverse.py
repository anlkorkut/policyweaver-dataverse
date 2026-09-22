"""Offline adversarial tests for the collector's security and completeness gates."""

import json
import re
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest

from policyweaver.dataverse import (
    API_PATH, COLLECTIONS, DataverseClient, DataverseError,
)

DEFAULT_ENVIRONMENT_URL = "https://example.crm.dynamics.com"
DEFAULT_ORGANIZATION_ID = str(UUID(int=9001))
TEST_TENANT_ID = str(UUID(int=9002))


def uid(n):
    return str(UUID(int=n))


class Credential:
    def __init__(self):
        self.scopes = []

    def get_token(self, scope):
        self.scopes.append(scope)
        return SimpleNamespace(token=f"private-token-{len(self.scopes)}", expires_on=9999999999)


def client(handler, **kwargs):
    return DataverseClient(
        environment_url=DEFAULT_ENVIRONMENT_URL, tenant_id=TEST_TENANT_ID,
        expected_organization_id=DEFAULT_ORGANIZATION_ID,
        credential=Credential(), transport=httpx.MockTransport(handler),
        random_source=lambda: 0, **kwargs,
    )


@pytest.mark.parametrize("url", [
    "https://attacker.example/api/data/v9.2/systemusers",
    "//attacker.example/api/data/v9.2/systemusers",
    DEFAULT_ENVIRONMENT_URL + "/api/data/v9.1/systemusers",
    DEFAULT_ENVIRONMENT_URL + "/api/data/v9.2/../secret",
    DEFAULT_ENVIRONMENT_URL + "/api/data/v9.2/%2e%2e/secret",
    DEFAULT_ENVIRONMENT_URL + "/api/data/v9.2/%252e%252e/secret",
    DEFAULT_ENVIRONMENT_URL + "/api/data/v9.2/%2525252e%2525252e/secret",
    DEFAULT_ENVIRONMENT_URL + "/api/data/v9.2/systemusers#fragment",
    "https://person:secret@example.crm.dynamics.com/api/data/v9.2/systemusers",
    "https://example.crm.dynamics.com:evil/api/data/v9.2/systemusers",
    "https://[bad/api/data/v9.2/systemusers",
])
def test_untrusted_continuation_never_receives_token(url):
    sent = []
    with client(lambda request: sent.append(request)) as api:
        with pytest.raises(DataverseError, match="Continuation"):
            api.get_json(url)
        assert not sent
        assert not api.credential.scopes


def test_pagination_exhausts_and_renews_token():
    sent = []

    def handler(request):
        sent.append(request)
        assert request.method == "GET"
        assert "$filter" not in request.url.params
        if "$skiptoken" not in request.url.params:
            return httpx.Response(200, json={
                "value": [{"systemuserid": uid(1)}],
                "@odata.nextLink": DEFAULT_ENVIRONMENT_URL + API_PATH + "systemusers?$skiptoken=encoded%2Bcookie",
            })
        return httpx.Response(200, json={"value": [{"systemuserid": uid(2)}]})

    with client(handler) as api:
        assert len(list(api.iter_collection("systemusers"))) == 2
        assert api.credential.scopes == [DEFAULT_ENVIRONMENT_URL + "/.default"] * 2
    assert sent[0].headers["Authorization"] != sent[1].headers["Authorization"]
    assert sent[1].url.params["$skiptoken"] == "encoded+cookie"


def test_pagination_cycle_fails():
    with client(lambda _: httpx.Response(200, json={"value": [], "@odata.nextLink": "systemusers"})) as api:
        with pytest.raises(DataverseError) as error:
            list(api.iter_collection("systemusers"))
    assert error.value.code == "pagination_cycle"


def test_page_limit_is_not_silent_truncation():
    with client(lambda _: httpx.Response(200, json={"value": [], "@odata.nextLink": "systemusers?p=2"}), max_pages=1) as api:
        with pytest.raises(DataverseError) as error:
            list(api.iter_collection("systemusers"))
    assert error.value.code == "page_limit_exceeded"


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirect_is_refused_without_leaking_body(status):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(status, headers={"location": "https://evil.example"}, text="private-record-token")

    with client(handler) as api:
        with pytest.raises(DataverseError) as error:
            api.get_json("WhoAmI")
    assert len(requests) == 1
    assert error.value.code == "redirect_refused"
    assert "private" not in str(error.value)


@pytest.mark.parametrize("status", [429, 500, 503])
def test_transient_retry_obeys_retry_after_and_bound(status):
    requests, waits = [], []

    def handler(request):
        requests.append(request)
        return httpx.Response(status, headers={"Retry-After": "2"}, text="sensitive")

    with client(handler, max_retries=2, sleep=waits.append) as api:
        with pytest.raises(DataverseError) as error:
            api.get_json("WhoAmI")
    assert len(requests) == 3
    assert waits == [2, 2]
    assert error.value.status == status
    assert "sensitive" not in str(error.value)


def test_retry_after_http_date_and_budget():
    date = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=10), usegmt=True)
    with client(lambda _: None) as api:
        assert 8 <= api._retry_delay(httpx.Response(429, headers={"Retry-After": date}), 0) <= 10
        with pytest.raises(DataverseError) as error:
            api._retry_delay(httpx.Response(429, headers={"Retry-After": "120"}), 0)
        assert error.value.code == "retry_after_exceeds_budget"


def test_retry_after_too_long_never_retries_early():
    requests, waits = [], []

    def handler(request):
        requests.append(request)
        return httpx.Response(429, headers={"Retry-After": "3600"})

    with client(handler, sleep=waits.append) as api:
        with pytest.raises(DataverseError):
            api.get_json("WhoAmI")
    assert len(requests) == 1
    assert waits == []


def test_authentication_errors_are_sanitized():
    class FailingCredential:
        def get_token(self, *_):
            raise RuntimeError("password=SECRET")

    with DataverseClient(DEFAULT_ENVIRONMENT_URL, TEST_TENANT_ID, DEFAULT_ORGANIZATION_ID,
                         credential=FailingCredential(), transport=httpx.MockTransport(lambda _: None)) as api:
        with pytest.raises(DataverseError) as error:
            api.get_json("WhoAmI")
    assert error.value.code == "authentication_failed"
    assert "SECRET" not in str(error.value)


def test_wrong_organization_stops_before_inventory():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"OrganizationId": uid(999), "UserId": uid(1)})

    with client(handler) as api:
        snapshot = api.collect()
    assert len(requests) == 1
    assert snapshot["organization_id"] is None
    assert snapshot["complete"] is False
    assert snapshot["datasets"] == {}
    assert snapshot["diagnostics"][0]["code"] == "organization_mismatch"


class InventoryService:
    """A small genuine graph: duplicate labels, overlapping teams, paged links."""

    def __init__(self, fail=None, scope="Global", depth="Deep", bad_reference=False):
        self.fail = fail
        self.scope = scope
        self.depth = depth
        self.requests = []
        self.rows = {
            "systemusers": [
                {"systemuserid": uid(1), "fullname": "Same label", "_businessunitid_value": uid(10), "isdisabled": False},
                {"systemuserid": uid(2), "fullname": "Same label", "_businessunitid_value": uid(10), "isdisabled": True},
            ],
            "businessunits": [{"businessunitid": uid(10), "_parentbusinessunitid_value": None}],
            "roles": [
                {"roleid": uid(20), "name": "Same role", "_businessunitid_value": uid(10)},
                {"roleid": uid(21), "name": "Same role", "_businessunitid_value": uid(10)},
            ],
            "teams": [{"teamid": uid(30), "_businessunitid_value": uid(10), "teamtype": 0}],
            "fieldsecurityprofiles": [{"fieldsecurityprofileid": uid(40)}],
            "fieldpermissions": [{"fieldpermissionid": uid(50), "_fieldsecurityprofileid_value": uid(40), "canread": 4, "canreadunmasked": 0}],
            "privileges": [{"privilegeid": uid(60), "name": "prvReadAccount"}],
        }
        self.metadata = []
        for n, (_, (logical, entity_set, _)) in enumerate(COLLECTIONS.items()):
            self.metadata.append({
                "MetadataId": uid(100 + n), "LogicalName": logical,
                "EntitySetName": entity_set, "OwnershipType": "OrganizationOwned",
                "Privileges": [{"PrivilegeId": uid(200 + n), "PrivilegeType": "Read"}],
                "Attributes": [{"MetadataId": uid(300 + n), "LogicalName": "name", "IsSecured": False}],
            })
        self.metadata[0]["Attributes@odata.nextLink"] = DEFAULT_ENVIRONMENT_URL + API_PATH + f"EntityDefinitions({uid(100)})/Attributes?page=2"
        self.member_id = uid(9999) if bad_reference else uid(1)

    def __call__(self, request):
        self.requests.append(request)
        assert request.method == "GET"
        path = request.url.path.removeprefix(API_PATH)
        if self.fail and self.fail in path:
            return httpx.Response(403, text="sensitive diagnostic body")
        if path == "WhoAmI":
            return httpx.Response(200, json={"OrganizationId": DEFAULT_ORGANIZATION_ID, "UserId": uid(1)})
        if path == "EntityDefinitions":
            return httpx.Response(200, json={"value": self.metadata})
        if path.endswith("/Attributes"):
            return httpx.Response(200, json={"value": [{"MetadataId": uid(399), "LogicalName": "secured", "IsSecured": True}]})
        if path in self.rows:
            return httpx.Response(200, json={"value": self.rows[path]})
        if "RetrieveUserPrivilegeByPrivilegeId" in path:
            privilege_id = re.search(r"PrivilegeId=([0-9a-f-]+)", path).group(1)
            assert "ExcludeTeamBasic=false" in path
            return httpx.Response(200, json={"RolePrivileges": [{"PrivilegeId": privilege_id, "Depth": self.scope}]})
        if path.startswith("RetrieveRolePrivilegesRole"):
            return httpx.Response(200, json={"RolePrivileges": [{
                "PrivilegeId": uid(60), "Depth": self.depth, "BusinessUnitId": uid(10),
            }]})
        if path.endswith("/systemuserroles_association"):
            if "page" not in request.url.params:
                return httpx.Response(200, json={
                    "value": [{"systemuserid": self.member_id}],
                    "@odata.nextLink": DEFAULT_ENVIRONMENT_URL + API_PATH + path + "?page=2",
                })
            return httpx.Response(200, json={"value": [{"systemuserid": uid(2)}]})
        if path.endswith("/teamroles_association"):
            return httpx.Response(200, json={"value": [{"roleid": uid(20)}, {"roleid": uid(21)}]})
        if path.endswith("/teammembership_association") or path.endswith("/systemuserprofiles_association"):
            return httpx.Response(200, json={"value": [{"systemuserid": uid(1)}]})
        if path.endswith("/teamprofiles_association"):
            return httpx.Response(200, json={"value": [{"teamid": uid(30)}]})
        raise AssertionError(f"Unexpected endpoint {path}")


def test_inventory_preserves_identity_and_drains_nested_collections():
    service = InventoryService()
    with client(service) as api:
        snapshot = api.collect()
    assert snapshot["complete"], snapshot["diagnostics"]
    assert snapshot["authorization_complete"] is False
    assert snapshot["publication_ready"] is False
    assert snapshot["publication_blockers"]
    assert snapshot["counts"]["user_roles"] == 4
    assert snapshot["counts"]["roles"] == 2
    assert snapshot["counts"]["users"] == 2
    assert snapshot["counts"]["attributes"] == 8
    assert snapshot["datasets"]["role_privileges"][0]["Depth"] == "Deep"
    assert snapshot["datasets"]["role_privileges"][0]["BusinessUnitId"] == uid(10)
    assert snapshot["datasets"]["users"][1]["isdisabled"] is True
    assert snapshot["observed_start"] <= snapshot["observed_end"]
    assert "private-token" not in json.dumps(snapshot)


@pytest.mark.parametrize("failed_path,capability", [
    ("teams?", "teams"),  # Replaced below with collection-only failure.
    ("teamroles_association", "team_roles"),
    ("RetrieveRolePrivilegesRole", "role_privileges"),
    ("/Attributes", "attribute_metadata"),
    ("RetrieveUserPrivilegeByPrivilegeId", "global_read_scope"),
])
def test_unreadable_security_source_blocks_complete(failed_path, capability):
    service = InventoryService(fail=failed_path)

    def handler(request):
        if failed_path == "teams?" and request.url.path == API_PATH + "teams":
            return httpx.Response(403, text="secret")
        return service(request)

    with client(handler) as api:
        snapshot = api.collect()
    assert snapshot["complete"] is False
    assert snapshot["capabilities"][capability]["complete"] is False
    assert "inventory_incomplete" in snapshot["publication_blockers"]
    assert "secret" not in json.dumps(snapshot["diagnostics"])


def test_http_success_does_not_prove_global_scope():
    with client(InventoryService(scope="Basic")) as api:
        snapshot = api.collect()
    assert snapshot["complete"] is False
    assert any(d["code"] == "global_read_unverified" for d in snapshot["diagnostics"])


def test_record_filter_depth_is_preserved_and_blocks_publication():
    with client(InventoryService(depth="RecordFilter")) as api:
        snapshot = api.collect()
    assert snapshot["complete"] is True
    assert snapshot["datasets"]["role_privileges"][0]["Depth"] == "RecordFilter"
    assert "record_filter_or_unknown_privilege_depth_unresolved" in snapshot["publication_blockers"]


def test_omitted_attributes_are_explicitly_incomplete():
    with client(InventoryService()) as api:
        snapshot = api.collect(include_attributes=False)
    assert snapshot["complete"] is False
    assert snapshot["capabilities"]["attribute_metadata"]["complete"] is False


def test_dangling_reference_fails_closed():
    with client(InventoryService(bad_reference=True)) as api:
        snapshot = api.collect()
    assert snapshot["complete"] is False
    assert snapshot["capabilities"]["referential_integrity"]["complete"] is False


def test_duplicate_identity_is_not_merged_by_label_or_id():
    service = InventoryService()
    service.rows["systemusers"].append(dict(service.rows["systemusers"][0]))
    with client(service) as api:
        snapshot = api.collect()
    assert snapshot["complete"] is False
    assert snapshot["counts"]["users"] == 3
    assert any(d["code"] == "duplicate_identity" for d in snapshot["diagnostics"])
