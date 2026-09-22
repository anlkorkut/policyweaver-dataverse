"""Naming provenance is complete evidence, never an authorization gate."""
from collections import Counter
from copy import deepcopy
from uuid import UUID

import httpx
import pytest

from policyweaver.source_projection import SourceProjectionClient, SourceProjectionError, SourceReader


def uid(value):
    return str(UUID(int=value))


READERS = [SourceReader(uid(10), uid(20)), SourceReader(uid(11), uid(21))]


class Credential:
    def get_token(self, *_):
        return type("Token", (), {"token": "test-token"})()


class LabelsEndpoint:
    def __init__(self):
        self.calls = []
        self.team = {"teamid": uid(100), "name": "Cross BU Team", "teamtype": 0,
                     "_businessunitid_value": uid(31)}
        self.direct = {"roleid": uid(201), "name": "Basic", "_businessunitid_value": uid(30),
                       "_parentrootroleid_value": uid(200)}
        self.inherited = {"roleid": uid(203), "name": "BNYM Contact Owner Role",
                          "_businessunitid_value": uid(31), "_parentrootroleid_value": uid(202)}
        self.group = {"roleid": uid(205), "name": "ECRM Advisory", "_businessunitid_value": uid(32),
                      "_parentrootroleid_value": uid(204)}
        self.users = {r.dataverse_id: {"systemuserid": r.dataverse_id,
            "azureactivedirectoryobjectid": r.entra_id, "isdisabled": False, "applicationid": None,
            "accessmode": 0, "fullname": f"Test Reader {i}", "domainname": f"pwtest{i:03d}@example.com",
            "_businessunitid_value": uid(30)} for i, r in enumerate(READERS, 1)}
        self.fail_team_page = False
        self.paged_direct = False

    def __call__(self, request):
        assert request.method == "GET"
        assert "CallerObjectId" not in request.headers
        self.calls.append(request)
        path = request.url.path.rsplit("/", 1)[-1]
        if path == "WhoAmI":
            return httpx.Response(200, json={"OrganizationId": uid(2), "UserId": uid(3)})
        if path.startswith("systemusers("):
            return httpx.Response(200, json=deepcopy(self.users[path[12:-1]]))
        if path.startswith("businessunits("):
            identifier = path[14:-1]
            return httpx.Response(200, json={"businessunitid": identifier, "name": "BU " + identifier[-2:]})
        if path.startswith("roles("):
            assert path == f"roles({self.group['roleid']})"
            return httpx.Response(200, json=self.group)
        if path == "systemuserroles_association":
            assert request.headers["Prefer"] == "odata.maxpagesize=5000"
            result = {"value": [self.direct]}
            if self.paged_direct and "skiptoken" not in request.url.params:
                result["@odata.nextLink"] = str(request.url) + "&skiptoken=next"
            return httpx.Response(200, json=result)
        if path == "teammembership_association":
            return httpx.Response(200, json={"value": [self.team]})
        if path == "teamroles_association":
            if self.fail_team_page:
                return httpx.Response(403, json={"error": {"message": "private server information"}})
            return httpx.Response(200, json={"value": [self.inherited]})
        if path.startswith("RetrieveAadUserRoles("):
            assert "Prefer" not in request.headers
            assert request.url.params["$select"] == "roleid,name,_parentrootroleid_value"
            return httpx.Response(200, json={"value": [{k: r[k] for k in
                ("roleid", "name", "_parentrootroleid_value")} for r in (self.direct, self.inherited, self.group)]})
        raise AssertionError("Unexpected route: " + request.url.path)


def client(endpoint):
    return SourceProjectionClient("https://example.crm.dynamics.com", uid(1), uid(2),
        credential=Credential(), transport=httpx.MockTransport(endpoint), max_retries=0)


def test_complete_direct_team_group_labels_keep_bu_anchors_and_cache_team_requests():
    endpoint = LabelsEndpoint()
    endpoint.paged_direct = True
    with client(endpoint) as source:
        result = source.reader_role_labels(reversed(READERS))
    assert list(result) == sorted(r.entra_id for r in READERS)
    first = result[READERS[0].entra_id]
    assert first["alias"] == "pwtest001"
    assert first["business_unit"]["id"] == uid(30)
    roles = {r["role_id"]: r for r in first["effective_roles"]}
    assert len(roles) == 3
    assert roles[uid(201)]["root_role_id"] == uid(200)
    assert {o["kind"] for o in roles[uid(201)]["origins"]} == {"direct", "effective_role_function"}
    assert {o["kind"] for o in roles[uid(203)]["origins"]} == {"team", "effective_role_function"}
    team_origin = next(o for o in roles[uid(203)]["origins"] if o["kind"] == "team")
    assert team_origin["team"]["business_unit"]["id"] == uid(31)
    assert roles[uid(203)]["business_unit"]["id"] == uid(31)
    assert [o["kind"] for o in roles[uid(205)]["origins"]] == ["effective_role_function"]
    counts = Counter(r.url.path.rsplit("/", 1)[-1] for r in endpoint.calls)
    assert counts["teamroles_association"] == 1
    assert counts["systemuserroles_association"] == 4  # Each relationship followed its second page.
    assert sum(count for key, count in counts.items() if key.startswith("businessunits(")) == 3
    # Cached shared metadata must never share mutable origin lists across readers.
    roles[uid(203)]["origins"].clear()
    assert len(result[READERS[1].entra_id]["effective_roles"][1]["origins"]) == 2


def test_failed_label_page_raises_without_becoming_empty_grants():
    endpoint = LabelsEndpoint()
    endpoint.fail_team_page = True
    with client(endpoint) as source, pytest.raises(SourceProjectionError) as failure:
        source.reader_role_labels(READERS)
    assert failure.value.status == 403
    assert "private" not in str(failure.value)
    assert all("RetrieveUserPrivilege" not in r.url.path and not r.url.path.endswith("accounts")
               for r in endpoint.calls)


@pytest.mark.parametrize("field,value", [
    ("systemuserid", uid(99)), ("azureactivedirectoryobjectid", uid(99)),
    ("isdisabled", True), ("applicationid", uid(99)), ("accessmode", 1), ("accessmode", False),
])
def test_identity_mismatch_in_labels_aborts_before_role_queries(field, value):
    endpoint = LabelsEndpoint()
    endpoint.users[READERS[0].dataverse_id][field] = value
    with client(endpoint) as source, pytest.raises(SourceProjectionError):
        source.reader_role_labels([READERS[0]])
    assert not any("association" in r.url.path for r in endpoint.calls)


@pytest.mark.parametrize("field,value", [("name", ""), ("name", "bad\nlabel"), ("roleid", uid(0)),
                                        ("_businessunitid_value", None)])
def test_invalid_role_metadata_cannot_silently_fall_back(field, value):
    endpoint = LabelsEndpoint()
    endpoint.direct[field] = value
    with client(endpoint) as source, pytest.raises(SourceProjectionError):
        source.reader_role_labels([READERS[0]])


@pytest.mark.parametrize("domain,alias", [(None, "Test Reader 1"), ("DOMAIN\\reader", "reader")])
def test_alias_handles_absent_upn_and_domain_form(domain, alias):
    endpoint = LabelsEndpoint()
    endpoint.users[READERS[0].dataverse_id]["domainname"] = domain
    with client(endpoint) as source:
        result = source.reader_role_labels([READERS[0]])
    assert result[READERS[0].entra_id]["alias"] == alias


def test_duplicate_or_empty_audiences_fail_and_deadline_callback_is_used():
    endpoint = LabelsEndpoint()
    with client(endpoint) as source:
        for readers in ([], [READERS[0], READERS[0]]):
            with pytest.raises(SourceProjectionError, match="unique bounded"):
                source.reader_role_labels(readers)
        def expired():
            raise RuntimeError("test_deadline")
        with pytest.raises(RuntimeError, match="test_deadline"):
            source.reader_role_labels(READERS, deadline_check=expired)
    assert all(r.url.path.endswith("WhoAmI") for r in endpoint.calls)
