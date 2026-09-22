"""Adversarial offline contracts for the authoritative Dataverse adapter."""

from decimal import Decimal
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest

from policyweaver.dataverse import DataverseError
from policyweaver.source_projection import (
    SourceAttribute, SourceProjectionClient, SourceProjectionError, SourceReader, SourceTable,
    SYSTEM_ADMINISTRATOR_TEMPLATE,
)


def uid(n):
    return str(UUID(int=n))


ORIGIN = "https://source.crm.dynamics.com"
TENANT, ORG, OPERATOR, PRIVILEGE = uid(1), uid(2), uid(3), uid(4)
READER = SourceReader(uid(5), uid(6))
TABLE = SourceTable("account", "accounts", "accountid", ("accountid", "name", "secret"), attributes=(
    SourceAttribute("accountid", "accountid", "Uniqueidentifier", False),
    SourceAttribute("name", "name", "String", False),
    SourceAttribute("secret", "secret", "String", True),
), read_privilege_id=PRIVILEGE)
ASSEMBLY_HASH = "a" * 64


def reader_privilege_path(reader=READER, privilege_id=PRIVILEGE):
    return (f"systemusers({reader.dataverse_id})/Microsoft.Dynamics.CRM."
            f"RetrieveUserPrivilegeByPrivilegeId(PrivilegeId={privilege_id},ExcludeTeamBasic=false)")


def is_reader_privilege_request(request):
    return request.url.path.endswith("/" + reader_privilege_path())


@pytest.fixture(autouse=True)
def trusted_registration(monkeypatch):
    # Registration schema and DLL-content verification have independent tests.
    # These contracts isolate challenge binding and never waive it in the app.
    from policyweaver import read_context_deployment
    calls = []
    def verify(source, *, api_name, assembly_sha256):
        calls.append({"api_name": api_name, "assembly_sha256": assembly_sha256})
        assert assembly_sha256 == ASSEMBLY_HASH
        return {"verified": True, "assembly_sha256": assembly_sha256}
    monkeypatch.setattr(read_context_deployment, "verify_read_context_registration", verify)
    return calls


class Credential:
    def __init__(self):
        self.scopes = []

    def get_token(self, scope):
        self.scopes.append(scope)
        return SimpleNamespace(token="private-token-" + str(len(self.scopes)))


class Endpoint:
    """Routes control-plane GETs and delegates account data requests."""
    def __init__(self, data=None):
        self.requests = []
        self.data = data or (lambda _: httpx.Response(200, json={"value": []}))
        self.identity = {
            "systemuserid": READER.dataverse_id,
            "azureactivedirectoryobjectid": READER.entra_id,
            "isdisabled": False,
            "applicationid": None,
            "accessmode": 0,
        }
        self.administrative_identity = dict(self.identity)
        self.grants = [{"PrivilegeId": PRIVILEGE, "Depth": "Basic"}]
        self.general_grants = list(self.grants)
        self.operator_depth = "Global"
        self.operator_admin = True
        self.organization_id = ORG

    def __call__(self, request):
        self.requests.append(request)
        assert request.method == "GET"
        assert request.headers["Consistency"] == "Strong"
        assert "UnMaskedData" not in str(request.url)
        assert "MSCRMCallerID" not in request.headers
        if request.url.path.endswith("/WhoAmI"):
            assert "CallerObjectId" not in request.headers
            return httpx.Response(200, json={"OrganizationId": self.organization_id, "UserId": OPERATOR})
        if "fetchXml" in request.url.params:
            assert request.headers["CallerObjectId"] == READER.entra_id
            assert "eq-userid" in request.url.params["fetchXml"]
            return httpx.Response(200, json={"value": [self.identity]})
        if request.url.path.endswith(f"/systemusers({READER.dataverse_id})"):
            assert "CallerObjectId" not in request.headers
            return httpx.Response(200, json=self.administrative_identity)
        if request.url.path.endswith("RetrieveUserPrivileges"):
            assert "CallerObjectId" not in request.headers
            assert READER.dataverse_id in request.url.path
            return httpx.Response(200, json={"RolePrivileges": self.general_grants})
        if is_reader_privilege_request(request):
            assert "CallerObjectId" not in request.headers
            return httpx.Response(200, json={"RolePrivileges": self.grants})
        if "RetrieveUserPrivilegeByPrivilegeId" in request.url.path:
            assert "CallerObjectId" not in request.headers
            assert OPERATOR in request.url.path
            return httpx.Response(200, json={"RolePrivileges": [{"PrivilegeId": PRIVILEGE, "Depth": self.operator_depth}]})
        if request.url.path.endswith("/systemuserroles_association"):
            return httpx.Response(200, json={"value": [{"_roletemplateid_value": SYSTEM_ADMINISTRATOR_TEMPLATE}] if self.operator_admin else []})
        if request.url.path.endswith(("/systemuserprofiles_association", "/teammembership_association")):
            return httpx.Response(200, json={"value": []})
        if request.url.path.endswith("/accounts"):
            assert request.headers["CallerObjectId"] == READER.entra_id
            return self.data(request)
        raise AssertionError("Unexpected mock route: " + request.url.path)


def client(handler, **kwargs):
    if kwargs.get("identity_verification") == "custom_api":
        kwargs.setdefault("identity_api_assembly_sha256", ASSEMBLY_HASH)
    return SourceProjectionClient(
        ORIGIN, TENANT, ORG, credential=Credential(),
        transport=httpx.MockTransport(handler), random_source=lambda: 0, **kwargs,
    )


def identity_api_handler(endpoint, *, transform=lambda proof: proof, status=200,
                         name="pw_ReadContext", nonces=None):
    def handler(request):
        segment = request.url.path.rsplit("/", 1)[-1]
        if segment.startswith(name + "("):
            endpoint.requests.append(request)
            assert request.method == "GET"
            assert request.headers["CallerObjectId"] == READER.entra_id
            assert request.headers["Consistency"] == "Strong"
            nonce = segment.removeprefix(name + "(Nonce=").removesuffix(")")
            assert str(UUID(nonce)) == nonce
            if nonces is not None:
                nonces.append(nonce)
            if status != 200:
                return httpx.Response(status, json={"error": {"message": "private"}})
            proof = {"UserId": READER.dataverse_id, "OrganizationId": ORG,
                     "Nonce": nonce, "ProtocolVersion": "1"}
            return httpx.Response(200, json=transform(proof))
        if "fetchXml" in request.url.params:
            pytest.fail("Custom API mode must never query systemuser under the reader or fall back.")
        return endpoint(request)
    return handler


def test_custom_api_proves_reader_without_adding_systemuser_read_and_uses_fresh_nonce(trusted_registration):
    endpoint = Endpoint(lambda _: httpx.Response(200, json={"value": [{"accountid": uid(10), "secret": None}]}))
    nonces = []
    with client(identity_api_handler(endpoint, nonces=nonces), identity_verification="custom_api") as source:
        assert list(source.iter_rows(READER, TABLE)) == [{"accountid": uid(10), "name": None, "secret": None}]
        assert source.verify_identity(READER)["method"] == "Custom API pw_ReadContext"
    assert len(nonces) == 2 and len(set(nonces)) == 2
    assert trusted_registration == [{"api_name": "pw_ReadContext", "assembly_sha256": ASSEMBLY_HASH}]
    assert all("CallerObjectId" not in request.headers for request in endpoint.requests
               if request.url.path.endswith(f"/systemusers({READER.dataverse_id})"))


@pytest.mark.parametrize("field,value", [
    ("UserId", OPERATOR), ("OrganizationId", uid(90)), ("Nonce", uid(91)),
    ("UserId", uid(0)), ("OrganizationId", "invalid"), ("Nonce", None),
    ("ProtocolVersion", "2"), ("ProtocolVersion", 1), ("ProtocolVersion", True),
    ("ProtocolVersion", None), ("@odata.nextLink", "elsewhere"),
])
def test_custom_api_wrong_context_or_protocol_never_reaches_business_data(field, value):
    endpoint = Endpoint(lambda _: pytest.fail("Invalid identity proofs cannot read records."))
    def transform(proof):
        return {**proof, field: value}
    with client(identity_api_handler(endpoint, transform=transform), identity_verification="custom_api") as source:
        with pytest.raises(SourceProjectionError):
            list(source.iter_rows(READER, TABLE))
        assert source.metrics["completed_scans"] == 0
    assert not any(r.url.path.endswith("/accounts") for r in endpoint.requests)


@pytest.mark.parametrize("missing", ["UserId", "OrganizationId", "Nonce", "ProtocolVersion"])
def test_custom_api_requires_every_proof_component(missing):
    endpoint = Endpoint(lambda _: pytest.fail("Incomplete identity proofs cannot read records."))
    def transform(proof):
        return {key: value for key, value in proof.items() if key != missing}
    with client(identity_api_handler(endpoint, transform=transform), identity_verification="custom_api") as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "identity_proof_unverified"


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
def test_custom_api_error_cannot_fall_back_or_become_empty_read(status):
    endpoint = Endpoint(lambda _: pytest.fail("Failed identity proofs cannot read records."))
    with client(identity_api_handler(endpoint, status=status), identity_verification="custom_api", max_retries=0) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.status == status
        assert source.metrics["completed_scans"] == 0


def test_custom_api_replayed_successful_proof_is_rejected():
    endpoint = Endpoint()
    previous = []
    def replay(proof):
        if not previous:
            previous.append(proof)
        return previous[0]
    with client(identity_api_handler(endpoint, transform=replay), identity_verification="custom_api") as source:
        assert source.verify_identity(READER)["verified"] is True
        with pytest.raises(SourceProjectionError) as failure:
            source.verify_identity(READER)
        assert failure.value.code == "identity_proof_mismatch"


def test_custom_api_revalidates_eligibility_after_its_execution_proof():
    endpoint = Endpoint(lambda _: pytest.fail("Changed reader eligibility must block records."))
    def disable(proof):
        endpoint.administrative_identity["isdisabled"] = True
        return proof
    with client(identity_api_handler(endpoint, transform=disable), identity_verification="custom_api") as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "reader_binding_mismatch"


def test_verified_no_read_does_not_call_the_custom_api():
    endpoint = Endpoint(lambda _: pytest.fail("Absent Read cannot retrieve data."))
    endpoint.grants = []
    with client(endpoint, identity_verification="custom_api") as source:
        assert list(source.iter_rows(READER, TABLE)) == []
    assert all("CallerObjectId" not in request.headers for request in endpoint.requests)


def test_custom_api_name_is_explicit_and_validated_before_http():
    endpoint = Endpoint()
    with client(identity_api_handler(endpoint, name="bank_ReadContext"),
                identity_verification="custom_api", identity_api_name="bank_ReadContext") as source:
        assert source.verify_identity(READER)["method"] == "Custom API bank_ReadContext"
    with pytest.raises(SourceProjectionError):
        client(endpoint, identity_verification="custom_api", identity_api_name="pw_ReadContext(Nonce=other)")
    with pytest.raises(ValueError):
        client(endpoint, identity_verification="fallback")


def test_unverified_registration_prevents_any_custom_identity_or_data_request(monkeypatch):
    from policyweaver import read_context_deployment
    endpoint = Endpoint(lambda _: pytest.fail("Untrusted registration cannot retrieve data."))
    def reject(*args, **kwargs):
        raise SourceProjectionError("identity_registration_unverified", "Synthetic registration mismatch.")
    monkeypatch.setattr(read_context_deployment, "verify_read_context_registration", reject)
    with client(endpoint, identity_verification="custom_api") as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "identity_registration_unverified"
    assert all("CallerObjectId" not in request.headers for request in endpoint.requests)


@pytest.mark.parametrize("digest", [None, "", "a" * 63, "A" * 64, "z" * 64])
def test_custom_api_client_rejects_missing_or_invalid_assembly_pin(digest):
    endpoint = Endpoint()
    with pytest.raises(ValueError):
        client(endpoint, identity_verification="custom_api", identity_api_assembly_sha256=digest)
    assert endpoint.requests == []


def test_projection_is_selected_impersonated_ordered_paginated_and_null_preserving():
    def data(request):
        if "$skiptoken" not in request.url.params:
            assert request.url.params["$select"] == "accountid,name,secret"
            assert request.url.params["$orderby"] == "accountid asc"
            return httpx.Response(200, json={
                "value": [{"accountid": uid(10), "name": "Visible", "unrequested": "must not persist", "secret": None}],
                "@odata.nextLink": ORIGIN + "/api/data/v9.2/accounts?$skiptoken=opaque%2Btoken",
            })
        assert request.url.params["$skiptoken"] == "opaque+token"
        return httpx.Response(200, json={"value": [{"accountid": uid(11), "secret": "***456"}]})

    endpoint = Endpoint(data)
    with client(endpoint) as source:
        rows = list(source.iter_rows(READER, TABLE))
        assert rows == [
            {"accountid": uid(10), "name": "Visible", "secret": None},
            {"accountid": uid(11), "name": None, "secret": "***456"},
        ]
        assert source.metrics["completed_rows"] == 2
        assert source.metrics["completed_scans"] == 1
        assert len(source.credential.scopes) == len(endpoint.requests)
        assert all(s == ORIGIN + "/.default" for s in source.credential.scopes)


def test_money_json_number_does_not_pass_through_binary_float():
    table = SourceTable("account", "accounts", "accountid", ("accountid", "revenue"), attributes=(
        SourceAttribute("accountid", "accountid", "Uniqueidentifier", False),
        SourceAttribute("revenue", "revenue", "Money", False),
    ), read_privilege_id=PRIVILEGE)
    content = '{"value":[{"accountid":"' + uid(10) + '","revenue":123456789.123456789}]}'
    with client(Endpoint(lambda _: httpx.Response(200, content=content))) as source:
        row = list(source.iter_rows(READER, table))[0]
        assert row["revenue"] == Decimal("123456789.123456789")
        assert isinstance(row["revenue"], Decimal)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_nonfinite_json_numbers_are_rejected(constant):
    content = '{"value":[{"accountid":"' + uid(10) + '","name":' + constant + '}]}'
    with client(Endpoint(lambda _: httpx.Response(200, content=content))) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "invalid_json"


def test_consumer_pause_past_deadline_cannot_complete_scan():
    clock = [0.0]
    endpoint = Endpoint(lambda _: httpx.Response(200, json={"value": [{"accountid": uid(10)}]}))
    with client(endpoint, monotonic=lambda: clock[0], max_scan_seconds=10) as source:
        rows = source.iter_rows(READER, TABLE)
        assert next(rows)["accountid"] == uid(10)
        clock[0] = 11
        with pytest.raises(SourceProjectionError) as failure:
            next(rows)
        assert failure.value.code == "scan_deadline_exceeded"
        assert source.metrics["completed_scans"] == 0


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500, 503])
def test_failed_data_read_never_becomes_empty_authorized_result(status):
    endpoint = Endpoint(lambda _: httpx.Response(status, text="private record value and token"))
    with client(endpoint, max_retries=0) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.status == status
        assert "private" not in str(failure.value)
        assert source.metrics["completed_scans"] == 0


def test_verified_absent_table_read_is_the_only_empty_gate():
    endpoint = Endpoint(lambda _: pytest.fail("A user without table Read must not be queried."))
    endpoint.grants = []
    with client(endpoint) as source:
        assert list(source.iter_rows(READER, TABLE)) == []
        assert source.metrics["completed_scans"] == 1
    assert not any(f"systemusers({OPERATOR})" in r.url.path for r in endpoint.requests)


def test_unroled_reader_never_needs_forbidden_impersonated_identity_query():
    endpoint = Endpoint(lambda _: pytest.fail("Unroled readers must not reach a data query."))
    endpoint.grants = []
    attempted_identity = []
    def handler(request):
        if "fetchXml" in request.url.params:
            attempted_identity.append(request)
            return httpx.Response(403, json={"error": {"code": "0x80042f09"}})
        return endpoint(request)
    with client(handler) as source:
        assert source.can_read_table(READER, TABLE) is False
        assert list(source.iter_rows(READER, TABLE)) == []
        assert source.metrics["completed_scans"] == 1
    assert attempted_identity == []
    assert not any(r.headers.get("CallerObjectId") for r in endpoint.requests)


@pytest.mark.parametrize("field,value", [
    ("systemuserid", uid(200)), ("azureactivedirectoryobjectid", uid(200)),
    ("isdisabled", True), ("applicationid", uid(200)),
    ("accessmode", 1), ("accessmode", True), ("accessmode", None),
])
def test_no_read_cannot_hide_changed_or_ineligible_administrative_binding(field, value):
    endpoint = Endpoint(lambda _: pytest.fail("Invalid bindings cannot query source data."))
    endpoint.grants = []
    endpoint.administrative_identity[field] = value
    with client(endpoint) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "reader_binding_mismatch"
        assert source.metrics["completed_scans"] == 0
    assert not any(is_reader_privilege_request(r) for r in endpoint.requests)


@pytest.mark.parametrize("missing", ["systemuserid", "azureactivedirectoryobjectid", "isdisabled", "applicationid", "accessmode"])
def test_absent_binding_field_cannot_turn_into_verified_no_read(missing):
    endpoint = Endpoint()
    endpoint.grants = []
    del endpoint.administrative_identity[missing]
    with client(endpoint) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "reader_binding_unverified"


def test_administrative_binding_http_denial_is_not_empty_authorization():
    endpoint = Endpoint()
    endpoint.grants = []
    def handler(request):
        if request.url.path.endswith(f"/systemusers({READER.dataverse_id})"):
            return httpx.Response(403)
        return endpoint(request)
    with client(handler) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.status == 403


@pytest.mark.parametrize("first_grants", [[], [{"PrivilegeId": PRIVILEGE, "Depth": "Basic"}]])
def test_absent_read_requires_successful_complete_privilege_pagination(first_grants):
    endpoint = Endpoint()
    def handler(request):
        if is_reader_privilege_request(request):
            if "$skiptoken" in request.url.params:
                return httpx.Response(403)
            return httpx.Response(200, json={"RolePrivileges": first_grants, "RolePrivileges@odata.nextLink":
                reader_privilege_path() + "?$skiptoken=next"})
        return endpoint(request)
    with client(handler) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.status == 403
        assert source.metrics["completed_scans"] == 0


def test_grant_inventory_403_is_not_lack_of_table_read():
    endpoint = Endpoint()
    def handler(request):
        if is_reader_privilege_request(request):
            return httpx.Response(403, json={"error": {"message": "private"}})
        return endpoint(request)
    with client(handler) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.status == 403


def test_table_privilege_list_must_be_complete_and_well_formed():
    endpoint = Endpoint()
    def handler(request):
        if is_reader_privilege_request(request):
            return httpx.Response(200, json={"RolePrivileges": [{"Depth": "Basic"}]})
        return endpoint(request)
    with client(handler) as source:
        with pytest.raises(SourceProjectionError, match="identifier"):
            list(source.iter_rows(READER, TABLE))


@pytest.mark.parametrize("field,value", [
    ("systemuserid", uid(200)), ("azureactivedirectoryobjectid", uid(200)),
    ("isdisabled", True), ("applicationid", uid(200)),
])
def test_wrong_or_ineligible_execution_identity_blocks_all_record_queries(field, value):
    endpoint = Endpoint(lambda _: pytest.fail("No data queries after a failed identity check."))
    endpoint.identity[field] = value
    with client(endpoint) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "impersonation_mismatch"
    assert any(is_reader_privilege_request(r) for r in endpoint.requests)
    assert not any(r.url.path.endswith("/accounts") for r in endpoint.requests)


@pytest.mark.parametrize("identity_mode", ["fetchxml", "custom_api"])
def test_team_only_basic_read_uses_inclusive_specific_gate_and_keeps_source_rows(identity_mode):
    """General privileges can be empty while two team-only Basic grants exist."""
    endpoint = Endpoint(lambda _: httpx.Response(200, json={"value": [
        {"accountid": uid(10), "name": "team-owned", "secret": None},
    ]}))
    endpoint.general_grants = []
    endpoint.grants = [
        {"PrivilegeId": PRIVILEGE, "Depth": "Basic", "BusinessUnitId": uid(80)},
        {"PrivilegeId": PRIVILEGE, "Depth": "Basic", "BusinessUnitId": uid(81)},
    ]
    handler = identity_api_handler(endpoint) if identity_mode == "custom_api" else endpoint
    with client(handler, identity_verification=identity_mode) as source:
        scan = source.open_scan(READER, TABLE)
        assert scan.has_read is True
        assert list(scan.rows) == [{"accountid": uid(10), "name": "team-owned", "secret": None}]
        assert source.metrics["completed_scans"] == 1
        assert source.metrics["completed_rows"] == 1
    assert sum(is_reader_privilege_request(r) for r in endpoint.requests) == 1
    assert not any(r.url.path.endswith("RetrieveUserPrivileges") for r in endpoint.requests)


def test_empty_inclusive_lookup_overrides_nonempty_general_privilege_inventory():
    endpoint = Endpoint(lambda _: pytest.fail("Verified absent Read cannot query rows."))
    endpoint.grants = []
    assert endpoint.general_grants
    with client(endpoint, identity_verification="custom_api") as source:
        scan = source.open_scan(READER, TABLE)
        assert scan.has_read is False
        assert list(scan.rows) == []
        assert source.metrics["completed_scans"] == 1
    assert not any(r.headers.get("CallerObjectId") for r in endpoint.requests)


@pytest.mark.parametrize("grants,error_code", [
    (None, "invalid_collection"),
    ({}, "invalid_collection"),
    ([None], "invalid_collection"),
    ([{"Depth": "Basic"}], "invalid_guid"),
    ([{"PrivilegeId": "not-a-guid"}], "invalid_guid"),
    ([{"PrivilegeId": uid(99)}], "privilege_scope_changed"),
    ([{"PrivilegeId": PRIVILEGE}, {"PrivilegeId": uid(99)}], "privilege_scope_changed"),
])
def test_inclusive_lookup_malformed_or_foreign_grants_never_become_absent_or_allowed(grants, error_code):
    endpoint = Endpoint(lambda _: pytest.fail("Invalid grant evidence cannot query rows."))
    endpoint.grants = grants
    with client(endpoint) as source:
        with pytest.raises(SourceProjectionError) as failure:
            source.open_scan(READER, TABLE)
        assert failure.value.code == error_code
        assert source.metrics["completed_scans"] == 0
    assert not any(r.headers.get("CallerObjectId") for r in endpoint.requests)


def test_inclusive_lookup_finds_team_basic_on_later_page_before_deciding():
    endpoint = Endpoint(lambda _: httpx.Response(200, json={"value": [{"accountid": uid(10)}]}))
    pages = []
    def handler(request):
        if is_reader_privilege_request(request):
            pages.append(request)
            if "$skiptoken" in request.url.params:
                return httpx.Response(200, json={"RolePrivileges": [
                    {"PrivilegeId": PRIVILEGE, "Depth": "Basic"},
                ]})
            return httpx.Response(200, json={"RolePrivileges": [],
                "RolePrivileges@odata.nextLink": reader_privilege_path() + "?$skiptoken=next"})
        return endpoint(request)
    with client(handler) as source:
        scan = source.open_scan(READER, TABLE)
        assert scan.has_read is True
        assert len(list(scan.rows)) == 1
    assert len(pages) == 2


def test_inclusive_lookup_valid_first_page_cannot_hide_foreign_privilege_later():
    endpoint = Endpoint(lambda _: pytest.fail("Foreign later-page privilege cannot query rows."))
    def handler(request):
        if is_reader_privilege_request(request):
            if "$skiptoken" in request.url.params:
                return httpx.Response(200, json={"RolePrivileges": [{"PrivilegeId": uid(99)}]})
            return httpx.Response(200, json={"RolePrivileges": [{"PrivilegeId": PRIVILEGE}],
                "RolePrivileges@odata.nextLink": reader_privilege_path() + "?$skiptoken=next"})
        return endpoint(request)
    with client(handler) as source:
        with pytest.raises(SourceProjectionError) as failure:
            source.open_scan(READER, TABLE)
        assert failure.value.code == "privilege_scope_changed"
        assert source.metrics["completed_scans"] == 0
    assert not any(r.headers.get("CallerObjectId") for r in endpoint.requests)


@pytest.mark.parametrize("continuation", [
    reader_privilege_path(SourceReader(uid(70), uid(71))),
    reader_privilege_path(privilege_id=uid(72)),
    reader_privilege_path().replace("ExcludeTeamBasic=false", "ExcludeTeamBasic=true"),
])
def test_inclusive_privilege_continuation_cannot_change_reader_privilege_or_team_mode(continuation):
    endpoint = Endpoint(lambda _: pytest.fail("Changed grant scope cannot query rows."))
    def handler(request):
        if is_reader_privilege_request(request):
            return httpx.Response(200, json={"RolePrivileges": [],
                "RolePrivileges@odata.nextLink": continuation + "?$skiptoken=next"})
        return endpoint(request)
    with client(handler) as source:
        with pytest.raises(SourceProjectionError) as failure:
            source.open_scan(READER, TABLE)
        assert failure.value.code == "collection_scope_changed"
        assert source.metrics["completed_scans"] == 0


def test_single_positive_custom_api_scan_keeps_six_steady_state_security_and_data_requests():
    table = SourceTable("account", "accounts", "accountid", ("accountid",), (
        SourceAttribute("accountid", "accountid", "Uniqueidentifier", False),
    ), PRIVILEGE)
    endpoint = Endpoint(lambda _: httpx.Response(200, json={"value": [{"accountid": uid(10)}]}))
    with client(identity_api_handler(endpoint), identity_verification="custom_api") as source:
        source.verify_environment()
        endpoint.requests.clear()
        scan = source.open_scan(READER, table)
        assert scan.has_read is True
        assert list(scan.rows) == [{"accountid": uid(10)}]
    assert len(endpoint.requests) == 6
    assert sum(is_reader_privilege_request(r) for r in endpoint.requests) == 1
    assert sum(r.url.path.endswith(f"/systemusers({READER.dataverse_id})") for r in endpoint.requests) == 2
    assert sum("/pw_ReadContext(" in r.url.path for r in endpoint.requests) == 1
    assert sum(f"systemusers({OPERATOR})/Microsoft.Dynamics.CRM.RetrieveUserPrivilegeByPrivilegeId" in r.url.path
               for r in endpoint.requests) == 1
    assert sum(r.url.path.endswith("/accounts") and r.headers.get("CallerObjectId") == READER.entra_id
               for r in endpoint.requests) == 1


def test_shared_activity_privilege_is_freshly_checked_for_each_table_scan():
    tables = [SourceTable(name, name + "s", "activityid", ("activityid",), (
        SourceAttribute("activityid", "activityid", "Uniqueidentifier", False),
    ), PRIVILEGE) for name in ("task", "email")]
    endpoint = Endpoint()
    data_requests = []
    def handler(request):
        if request.url.path.endswith(("/tasks", "/emails")):
            data_requests.append(request)
            assert request.headers["CallerObjectId"] == READER.entra_id
            return httpx.Response(200, json={"value": [{"activityid": uid(10)}]})
        return endpoint(request)
    with client(handler) as source:
        first = source.open_scan(READER, tables[0])
        assert first.has_read is True and len(list(first.rows)) == 1
        endpoint.grants = []
        second = source.open_scan(READER, tables[1])
        assert second.has_read is False and list(second.rows) == []
        assert source.metrics["completed_scans"] == 2
    assert sum(is_reader_privilege_request(r) for r in endpoint.requests) == 2
    assert len(data_requests) == 1 and data_requests[0].url.path.endswith("/tasks")


@pytest.mark.parametrize("has_read", [False, True])
def test_opened_scan_cannot_be_consumed_after_its_original_deadline(has_read):
    clock = [0.0]
    endpoint = Endpoint(lambda _: pytest.fail("Expired open scan cannot query data."))
    if not has_read:
        endpoint.grants = []
    with client(endpoint, monotonic=lambda: clock[0], max_scan_seconds=10) as source:
        scan = source.open_scan(READER, TABLE)
        assert scan.has_read is has_read
        clock[0] = 11.0
        with pytest.raises(SourceProjectionError) as failure:
            list(scan.rows)
        assert failure.value.code == "scan_deadline_exceeded"
        assert source.metrics["completed_scans"] == 0
    assert not any(r.headers.get("CallerObjectId") for r in endpoint.requests)


def test_read_revoked_after_open_gate_is_data_failure_not_empty_authorization():
    endpoint = Endpoint(lambda _: httpx.Response(403))
    with client(endpoint, max_retries=0) as source:
        scan = source.open_scan(READER, TABLE)
        assert scan.has_read is True
        endpoint.grants = []
        with pytest.raises(SourceProjectionError) as failure:
            list(scan.rows)
        assert failure.value.status == 403
        assert source.metrics["completed_scans"] == 0
    assert sum(is_reader_privilege_request(r) for r in endpoint.requests) == 1


def test_identity_is_reverified_for_every_table_scan():
    endpoint = Endpoint()
    with client(endpoint) as source:
        assert list(source.iter_rows(READER, TABLE)) == []
        endpoint.identity["isdisabled"] = True
        with pytest.raises(SourceProjectionError, match="identity"):
            list(source.iter_rows(READER, TABLE))


def test_organization_mismatch_stops_before_impersonation():
    endpoint = Endpoint()
    endpoint.organization_id = uid(200)
    with client(endpoint) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "organization_mismatch"
    assert len(endpoint.requests) == 1


def test_operator_scope_must_include_global_read():
    endpoint = Endpoint()
    endpoint.operator_depth = "Local"
    with client(endpoint) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "operator_read_scope_unverified"


def test_operator_without_field_read_cannot_publish_reader_projection():
    endpoint = Endpoint(lambda _: pytest.fail("Operator field scope must block the data scan."))
    endpoint.operator_admin = False
    with client(endpoint) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "operator_field_scope_unverified"


def test_missing_attribute_metadata_cannot_certify_operator_field_scope():
    untyped = SourceTable("account", "accounts", "accountid", ("accountid",), read_privilege_id=PRIVILEGE)
    with client(Endpoint()) as source:
        with pytest.raises(SourceProjectionError) as failure:
            source.verify_operator_read_scope(untyped)
        assert failure.value.code == "operator_field_scope_unverified"


@pytest.mark.parametrize("via_team", [False, True])
def test_operator_reduced_role_qualifies_via_complete_field_profile_read(via_team):
    endpoint = Endpoint()
    endpoint.operator_admin = False
    profile, team = uid(70), uid(71)
    def handler(request):
        if request.url.path.endswith("/systemuserprofiles_association"):
            return httpx.Response(200, json={"value": [] if via_team else [{"fieldsecurityprofileid": profile}]})
        if request.url.path.endswith("/teammembership_association"):
            return httpx.Response(200, json={"value": [{"teamid": team}] if via_team else []})
        if request.url.path.endswith("/teamprofiles_association"):
            assert team in request.url.path
            return httpx.Response(200, json={"value": [{"fieldsecurityprofileid": profile}]})
        if request.url.path.endswith("/fieldpermissions"):
            assert profile in request.url.params["$filter"]
            return httpx.Response(200, json={"value": [{
                "_fieldsecurityprofileid_value": profile, "entityname": "account",
                "attributelogicalname": "secret", "canread": 4,
            }]})
        return endpoint(request)
    with client(handler) as source:
        assert source.verify_operator_read_scope(TABLE) == {"global_read_verified": True, "field_security_scope_verified": True}


@pytest.mark.parametrize("canread", [0, 1, None, False])
def test_operator_profile_must_have_known_allowed_read(canread):
    endpoint = Endpoint()
    endpoint.operator_admin = False
    profile = uid(70)
    def handler(request):
        if request.url.path.endswith("/systemuserprofiles_association"):
            return httpx.Response(200, json={"value": [{"fieldsecurityprofileid": profile}]})
        if request.url.path.endswith("/fieldpermissions"):
            return httpx.Response(200, json={"value": [{
                "_fieldsecurityprofileid_value": profile, "entityname": "account",
                "attributelogicalname": "secret", "canread": canread,
            }]})
        return endpoint(request)
    with client(handler) as source:
        with pytest.raises(SourceProjectionError) as failure:
            source.verify_operator_read_scope(TABLE)
        assert failure.value.code == "operator_field_scope_unverified"


@pytest.mark.parametrize("continuation", [
    "https://evil.example/api/data/v9.2/accounts",
    "//evil.example/api/data/v9.2/accounts",
    ORIGIN + "/api/data/v9.2/%2e%2e/secret",
    ORIGIN + "/api/data/v9.2/%252e%252e/secret",
    ORIGIN + "/api/data/v9.2/systemusers",
    ORIGIN + "/api/data/v9.2/accounts#fragment",
])
def test_continuation_cannot_change_origin_or_collection(continuation):
    endpoint = Endpoint(lambda _: httpx.Response(200, json={"value": [], "@odata.nextLink": continuation}))
    with client(endpoint) as source:
        with pytest.raises(DataverseError):
            list(source.iter_rows(READER, TABLE))
    assert len([r for r in endpoint.requests if r.url.path.endswith("/accounts")]) == 1


def test_same_scope_pagination_cycle_is_rejected():
    endpoint = Endpoint(lambda r: httpx.Response(200, json={"value": [], "@odata.nextLink": str(r.url)}))
    with client(endpoint) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "pagination_cycle"


def test_page_budget_does_not_truncate_successfully():
    endpoint = Endpoint(lambda _: httpx.Response(200, json={"value": [], "@odata.nextLink": "accounts?$skiptoken=2"}))
    with client(endpoint, max_pages=1) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "page_limit_exceeded"


@pytest.mark.parametrize("rows,code", [
    ([{"accountid": uid(10)}, {"accountid": uid(10)}], "duplicate_record"),
    ([{"accountid": uid(10)}, {"accountid": uid(11)}], "row_limit_exceeded"),
    ([{"accountid": uid(10), "name": {"unexpected": "complex"}}], "complex_value"),
    ([{"name": "missing key"}], "invalid_guid"),
])
def test_invalid_partial_scans_remain_incomplete(rows, code):
    endpoint = Endpoint(lambda _: httpx.Response(200, json={"value": rows}))
    with client(endpoint, max_rows_per_scan=1) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == code
        assert source.metrics["completed_rows"] == 0


def test_retry_renews_token_preserves_identity_and_obeys_retry_after():
    attempts, waits = [], []
    def data(request):
        attempts.append(request)
        if len(attempts) == 1:
            return httpx.Response(429, headers={"Retry-After": "2"})
        return httpx.Response(200, json={"value": []})
    with client(Endpoint(data), sleep=waits.append) as source:
        assert list(source.iter_rows(READER, TABLE)) == []
        assert source.metrics["retries"] == 1
    assert waits == [2]
    assert attempts[0].headers["Authorization"] != attempts[1].headers["Authorization"]
    assert all(r.headers["CallerObjectId"] == READER.entra_id for r in attempts)


def test_retry_cannot_outlive_scan_deadline():
    endpoint = Endpoint(lambda _: httpx.Response(429, headers={"Retry-After": "30"}))
    with client(endpoint, monotonic=lambda: 0, max_scan_seconds=20, sleep=lambda _: pytest.fail("Must not wait.")) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "scan_deadline_exceeded"


def metadata_handler(extra_attributes=(), masks=()):
    endpoint = Endpoint()
    def handle(request):
        if request.url.path.endswith("EntityDefinitions(LogicalName='account')"):
            return httpx.Response(200, json={
                "LogicalName": "account", "EntitySetName": "accounts", "PrimaryIdAttribute": "accountid",
                "Privileges": [{"PrivilegeType": "Read", "PrivilegeId": PRIVILEGE}],
            })
        if request.url.path.endswith("/Attributes"):
            return httpx.Response(200, json={"value": [
                {"LogicalName": "accountid", "AttributeType": "Uniqueidentifier", "IsValidForRead": True, "IsSecured": False},
                {"LogicalName": "name", "AttributeType": "String", "IsValidForRead": True, "IsSecured": False},
                {"LogicalName": "primarycontactid", "AttributeType": "Lookup", "IsValidForRead": True, "IsSecured": True},
                {"LogicalName": "secret", "AttributeType": "String", "IsValidForRead": True, "IsSecured": True},
                *extra_attributes,
            ]})
        if request.url.path.endswith("/attributemaskingrules"):
            return httpx.Response(200, json={"value": list(masks)})
        return endpoint(request)
    return handle


def test_metadata_maps_logical_lookup_and_security_and_auto_includes_key():
    masks = [{"entityname": "account", "attributelogicalname": "secret", "_maskingruleid_value": uid(50)}]
    with client(metadata_handler(masks=masks)) as source:
        table = source.table_metadata("account", ["name", "primarycontactid", "secret"])
    assert table.columns == ("accountid", "name", "_primarycontactid_value", "secret")
    assert table.read_privilege_id == PRIVILEGE
    assert table.attributes[2].is_secured is True
    assert table.attributes[3].is_masked is True
    assert table.attributes[1].is_masked is False


@pytest.mark.parametrize("unsupported", ["Image", "File", "PartyList", "ManagedProperty", "Virtual", None])
def test_default_projection_fails_for_unsupported_attributes(unsupported):
    extra = [{"LogicalName": "special", "AttributeType": unsupported, "IsValidForRead": True, "IsSecured": False}]
    with client(metadata_handler(extra)) as source:
        with pytest.raises(SourceProjectionError) as failure:
            source.table_metadata("account")
        assert failure.value.code == "unsupported_attribute"
        assert source.table_metadata("account", ["name"]).columns == ("accountid", "name")


def test_multiselect_picklist_is_a_supported_scalar_string():
    extra = [{"LogicalName": "choices", "AttributeType": "Virtual", "AttributeTypeName": {"Value": "MultiSelectPicklistType"}, "IsValidForRead": True, "IsSecured": False}]
    with client(metadata_handler(extra)) as source:
        table = source.table_metadata("account", ["choices"])
        assert table.attributes[1].attribute_type == "MultiSelectPicklist"


@pytest.mark.parametrize("columns", [["primarycontactid", "_primarycontactid_value"], ["unknown"], ["name", "name"], "name", []])
def test_bad_projection_is_rejected(columns):
    with client(metadata_handler()) as source:
        with pytest.raises(SourceProjectionError):
            source.table_metadata("account", columns)


def test_missing_security_metadata_is_not_assumed_unsecured():
    extra = [{"LogicalName": "unknownsecurity", "AttributeType": "String", "IsValidForRead": True}]
    with client(metadata_handler(extra)) as source:
        with pytest.raises(SourceProjectionError) as failure:
            source.table_metadata("account", ["unknownsecurity"])
        assert failure.value.code == "unreadable_attribute"


def test_mask_discovery_failure_is_not_assumed_no_masking():
    endpoint = metadata_handler()
    def handler(request):
        if request.url.path.endswith("/attributemaskingrules"):
            return httpx.Response(403)
        return endpoint(request)
    with client(handler) as source:
        with pytest.raises(SourceProjectionError) as failure:
            source.table_metadata("account", ["name"])
        assert failure.value.status == 403


def test_discovery_filters_without_collecting_names_and_requires_unique_mappings():
    endpoint = Endpoint()
    user = {"systemuserid": READER.dataverse_id, "azureactivedirectoryobjectid": READER.entra_id, "isdisabled": False, "applicationid": None, "accessmode": 0}
    def handler(request):
        if request.url.path.endswith("/systemusers"):
            assert "fullname" not in request.url.params["$select"]
            assert "isdisabled eq false" in request.url.params["$filter"]
            assert "(accessmode eq 0 or accessmode eq 2)" in request.url.params["$filter"]
            return httpx.Response(200, json={"value": [user]})
        return endpoint(request)
    with client(handler) as source:
        assert source.discover_readers() == [{"dataverse_id": READER.dataverse_id, "entra_id": READER.entra_id, "accessmode": 0}]


@pytest.mark.parametrize("mode", [0, 2])
def test_interactive_read_write_and_read_only_access_modes_are_eligible(mode):
    endpoint = Endpoint()
    endpoint.identity["accessmode"] = mode
    with client(endpoint) as source:
        assert source.verify_identity(READER)["verified"] is True


@pytest.mark.parametrize("mode", [1, 3, 4, 5, -1, True, None, "0"])
def test_special_or_unknown_access_mode_is_rejected_before_any_data_read(mode):
    endpoint = Endpoint(lambda _: pytest.fail("An ineligible reader must never reach a data query."))
    endpoint.identity["accessmode"] = mode
    with client(endpoint) as source:
        with pytest.raises(SourceProjectionError) as failure:
            list(source.iter_rows(READER, TABLE))
        assert failure.value.code == "impersonation_mismatch"


@pytest.mark.parametrize("mode", [1, 3, 4, 5, -1, True, None, "0"])
def test_discovery_defensively_rejects_special_modes_even_if_filter_is_ignored(mode):
    endpoint = Endpoint()
    user = {**endpoint.identity, "accessmode": mode}
    def handler(request):
        if request.url.path.endswith("/systemusers"):
            return httpx.Response(200, json={"value": [user]})
        return endpoint(request)
    with client(handler) as source:
        with pytest.raises(SourceProjectionError) as failure:
            source.discover_readers()
        assert failure.value.code == "invalid_reader_inventory"


@pytest.mark.parametrize("identifier", ["", "../accounts", "account')?$expand=secret", "account;drop", uid(0)])
def test_identifiers_are_validated_before_requests(identifier):
    with pytest.raises(SourceProjectionError):
        if identifier == uid(0):
            SourceReader(identifier, uid(1))
        else:
            SourceTable(identifier, "accounts", "accountid", ("accountid",))
