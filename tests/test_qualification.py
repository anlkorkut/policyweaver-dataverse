"""Offline actual-reader qualification tooling tests; no live acceptance claims."""
from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timezone
from decimal import Decimal
import importlib.util
import json
from pathlib import Path
import sqlite3
import struct
import time
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest

from policyweaver.qualification import (
    BoundUserCredential, DirectReaderSource, QualificationError, QualificationScenario,
    ReadOutcome, ReaderSqlTarget, canonical_value, load_scenario, normalize_rows,
    qualify, scenario_template,
)
from policyweaver.source_projection import SourceProjectionError


def uid(number):
    return str(UUID(int=number))


def raw_scenario():
    return {
        "schema_version": 1, "scenario_id": "test_acceptance", "tenant_id": uid(1), "organization_id": uid(2),
        "environment_url": "https://test.crm.dynamics.com",
        "sql": {"server": "test.datawarehouse.fabric.microsoft.com", "database": "reader_surface"},
        "tables": [{"source": {"name": "account", "entity_set": "accounts", "primary_key": "accountid",
                                "columns": ["accountid", "name", "secret", "amount"],
                                "attributes": [
                                    {"logical_name": "accountid", "property_name": "accountid", "attribute_type": "Uniqueidentifier", "is_secured": False},
                                    {"logical_name": "name", "property_name": "name", "attribute_type": "String", "is_secured": False},
                                    {"logical_name": "secret", "property_name": "secret", "attribute_type": "String", "is_secured": True},
                                    {"logical_name": "amount", "property_name": "amount", "attribute_type": "Integer", "is_secured": False},
                                ]}, "target_name": "pw_demo_account"}],
        "readers": [{"label": "basic_owner", "upn": "operator-must-fill-real-upn", "entra_id": uid(3),
                     "tables": {"account": {"table_denied": False, "records": [
                         {"record_id": uid(10), "visible": True, "null_fields": ["secret"], "non_null_fields": ["name"]},
                         {"record_id": uid(11), "visible": False}]}}}],
    }


def scenario():
    return QualificationScenario.from_mapping(raw_scenario(), "basic_owner")


def bound_identity_scenario():
    raw = raw_scenario()
    raw["readers"][0].update(identity_verification="bound_whoami", dataverse_id=uid(4))
    return QualificationScenario.from_mapping(raw, "basic_owner")


def rows():
    return ({"accountid": uid(10), "name": "PRIVATE_SENTINEL", "secret": None, "amount": 12},
            {"accountid": uid(12), "name": "VISIBLE", "secret": "ALLOWED_SECRET_SENTINEL", "amount": 7})


def jwt(claims):
    encode = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return encode({"alg": "RS256"}) + "." + encode(claims) + ".signature-not-used-in-unit-test"


class FakeCredential:
    def __init__(self, changes=None):
        self.changes = changes or {}
        self.scopes = []

    def get_token(self, scope, **_):
        self.scopes.append(scope)
        claims = {"tid": uid(1), "oid": uid(3), "scp": "user_impersonation", "exp": time.time() + 600,
                  "aud": scope.removesuffix("/.default")}
        claims.update(self.changes)
        return SimpleNamespace(token=jwt(claims), expires_on=claims["exp"])


def bound(changes=None):
    return BoundUserCredential(FakeCredential(changes), uid(1), uid(3), "https://test.crm.dynamics.com")


class MemorySource:
    def __init__(self, data=None, allowed=True):
        self.data = rows() if data is None else data
        self.allowed = allowed
        self.verified = False
        self.calls = 0
        self.after = None

    def verify_identity(self):
        self.verified = True

    def read(self, _):
        self.calls += 1
        return ReadOutcome(self.allowed, self.after if self.calls > 1 and self.after is not None else tuple(self.data))


class SqliteTarget:
    """Independent SQL filter/aggregate oracle over projected source values."""
    def __init__(self, data=None, allowed=True, helpers_denied=True):
        self.data = rows() if data is None else data
        self.allowed = allowed
        self.deny_helpers = helpers_denied
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE account(accountid TEXT,name TEXT,secret TEXT,amount INTEGER)")
        self.db.executemany("INSERT INTO account VALUES(?,?,?,?)", [tuple(r[c] for c in ("accountid", "name", "secret", "amount")) for r in self.data])

    def read(self, _):
        return ReadOutcome(self.allowed, tuple(self.data))

    def scalar(self, _, expression, where="", params=()):
        return self.db.execute("SELECT " + expression.replace("COUNT_BIG", "COUNT") + " FROM account" + where, params).fetchone()[0]

    def helpers_denied(self, _):
        return self.deny_helpers


def test_actual_reader_comparison_passes_rows_null_filters_aggregates_and_known_denials():
    source = MemorySource()
    result = qualify(scenario(), source, SqliteTarget())
    assert result["status"] == "passed_selected_sql_checks"
    assert source.verified and source.calls == 2
    assert result["production_certified"] is False and result["revocation_sla_verified"] is False
    table = result["tables"][0]
    assert table["source_row_count"] == table["target_row_count"] == 2
    assert table["source_fingerprint"] == table["target_fingerprint"]
    assert table["query_checks"] == 5
    serialized = json.dumps(result)
    assert "PRIVATE_SENTINEL" not in serialized and "ALLOWED_SECRET_SENTINEL" not in serialized
    assert uid(10) not in serialized and uid(3) not in serialized


def test_fingerprints_are_unlinkable_across_runs_and_never_export_key():
    first = qualify(scenario(), MemorySource(), SqliteTarget())
    second = qualify(scenario(), MemorySource(), SqliteTarget())
    assert first["tables"][0]["source_fingerprint"] != second["tables"][0]["source_fingerprint"]
    assert "key" not in first and "salt" not in first


@pytest.mark.parametrize("mutation,category", [
    (lambda data: (data[0],), "record_set_mismatch"),
    (lambda data: (*data, {**data[0], "accountid": uid(11)}), "target_fixture_expectation_mismatch"),
    (lambda data: ({**data[0], "secret": "LEAK"}, data[1]), "field_value_or_null_mismatch"),
    (lambda data: ({**data[0], "amount": 999}, data[1]), "numeric_aggregate_mismatch"),
])
def test_mismatches_are_reported_without_values(mutation, category):
    result = qualify(scenario(), MemorySource(), SqliteTarget(mutation(rows())))
    assert result["status"] == "failed"
    assert category in result["tables"][0]["mismatch_categories"]
    assert "LEAK" not in json.dumps(result)


def test_source_fixture_is_independently_required_not_just_two_equal_empty_sets():
    result = qualify(scenario(), MemorySource(data=()), SqliteTarget(data=()))
    assert "source_fixture_expectation_mismatch" in result["tables"][0]["mismatch_categories"]
    assert result["status"] == "failed"


def test_source_changes_during_probe_mark_result_unusable():
    source = MemorySource()
    source.after = ()
    result = qualify(scenario(), source, SqliteTarget())
    assert "source_changed_during_probe" in result["tables"][0]["mismatch_categories"]


def test_internal_helper_visibility_fails_even_if_business_data_matches():
    result = qualify(scenario(), MemorySource(), SqliteTarget(helpers_denied=False))
    assert "internal_helper_column_readable" in result["tables"][0]["mismatch_categories"]


def test_table_permission_denial_is_distinct_from_allowed_empty_rows():
    raw = raw_scenario()
    raw["readers"][0]["tables"]["account"] = {"table_denied": True, "records": []}
    denied = QualificationScenario.from_mapping(raw, "basic_owner")
    assert qualify(denied, MemorySource(data=(), allowed=False), SqliteTarget(data=(), allowed=False))["status"] == "passed_selected_sql_checks"
    mismatch = qualify(denied, MemorySource(data=(), allowed=False), SqliteTarget(data=(), allowed=True))
    assert "table_authorization_mismatch" in mismatch["tables"][0]["mismatch_categories"]


@pytest.mark.parametrize("change", [{"tid": uid(99)}, {"oid": uid(99)}, {"idtyp": "app"}, {"scp": ""},
                                    {"exp": 1}, {"aud": "https://attacker.example"}])
def test_wrong_tenant_user_app_expired_or_audience_token_is_rejected(change):
    with pytest.raises(QualificationError, match="token_identity_or_audience"):
        bound(change).get_token("https://test.crm.dynamics.com/.default")


def test_bound_credential_only_allows_two_selected_resource_scopes():
    credential = bound()
    assert credential.get_token("https://test.crm.dynamics.com/.default").token
    assert credential.get_token("https://database.windows.net/.default").token
    with pytest.raises(QualificationError, match="unexpected_token_scope"):
        credential.get_token("https://graph.microsoft.com/.default")


def test_direct_source_identity_and_reads_send_no_impersonation_headers():
    requests = []

    def handle(request):
        requests.append(request)
        assert request.method == "GET"
        assert "CallerObjectId" not in request.headers and "MSCRMCallerID" not in request.headers
        if request.url.path.endswith("WhoAmI"):
            return httpx.Response(200, json={"OrganizationId": uid(2), "UserId": uid(4)})
        if request.url.path.endswith("systemusers"):
            assert "eq-userid" in request.url.params["fetchXml"]
            return httpx.Response(200, json={"value": [{"systemuserid": uid(4), "azureactivedirectoryobjectid": uid(3),
                                                        "isdisabled": False, "applicationid": None, "accessmode": 0}]})
        return httpx.Response(200, json={"value": list(rows())})

    source = DirectReaderSource(scenario(), bound(), transport=httpx.MockTransport(handle))
    try:
        source.verify_identity()
        outcome = source.read(scenario().tables[0])
        assert outcome.allowed and len(outcome.rows) == 2
        assert len(requests) == 3
    finally:
        source.close()


def test_bound_whoami_qualifies_without_systemuser_read_or_custom_api_access():
    selected, requests = bound_identity_scenario(), []
    def handle(request):
        requests.append(request)
        assert request.method == "GET"
        assert "CallerObjectId" not in request.headers and "MSCRMCallerID" not in request.headers
        if request.url.path.endswith("WhoAmI"):
            return httpx.Response(200, json={"OrganizationId": uid(2), "UserId": uid(4)})
        if request.url.path.endswith("accounts"):
            return httpx.Response(200, json={"value": list(rows())})
        pytest.fail("Direct proof must not retrieve systemusers, registration metadata or a Custom API.")
    source = DirectReaderSource(selected, bound(), transport=httpx.MockTransport(handle))
    try:
        result = qualify(selected, source, SqliteTarget())
        assert result["status"] == "passed_selected_sql_checks"
        assert result["identity_verification"] == "bound_whoami"
        assert result["production_certified"] is False
        assert len(requests) == 3
    finally:
        source.close()


@pytest.mark.parametrize("response", [
    {"OrganizationId": uid(99), "UserId": uid(4)},
    {"OrganizationId": uid(2), "UserId": uid(99)},
    {"OrganizationId": uid(2), "UserId": uid(0)},
    {"OrganizationId": uid(2)}, {"UserId": uid(4)},
])
def test_bound_whoami_wrong_or_incomplete_identity_cannot_reach_business_data(response):
    selected, requests = bound_identity_scenario(), []
    def handle(request):
        requests.append(request)
        assert request.url.path.endswith("WhoAmI")
        return httpx.Response(200, json=response)
    source = DirectReaderSource(selected, bound(), transport=httpx.MockTransport(handle))
    try:
        with pytest.raises(QualificationError):
            source.verify_identity()
        with pytest.raises(QualificationError, match="identity_not_verified"):
            source.read(selected.tables[0])
        assert len(requests) == 1
    finally:
        source.close()


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_bound_whoami_http_failure_never_falls_back_to_another_identity_proof(status):
    selected, requests = bound_identity_scenario(), []
    def handle(request):
        requests.append(request)
        assert request.url.path.endswith("WhoAmI")
        return httpx.Response(status)
    source = DirectReaderSource(selected, bound(), transport=httpx.MockTransport(handle))
    try:
        with pytest.raises(SourceProjectionError) as failure:
            source.verify_identity()
        assert failure.value.status == status
        with pytest.raises(QualificationError, match="identity_not_verified"):
            source.read(selected.tables[0])
        assert len(requests) == 1
    finally:
        source.close()


@pytest.mark.parametrize("credential", [
    FakeCredential(),
    BoundUserCredential(FakeCredential(), uid(99), uid(3), "https://test.crm.dynamics.com"),
    BoundUserCredential(FakeCredential(), uid(1), uid(99), "https://test.crm.dynamics.com"),
    BoundUserCredential(FakeCredential(), uid(1), uid(3), "https://different.crm.dynamics.com"),
])
def test_bound_whoami_requires_a_matching_bound_delegated_credential(credential):
    with pytest.raises(QualificationError, match="bound_credential_required"):
        DirectReaderSource(bound_identity_scenario(), credential,
                           transport=httpx.MockTransport(lambda _: pytest.fail("No requests before credential binding.")))


@pytest.mark.parametrize("claims", [{"oid": uid(99)}, {"tid": uid(99)}, {"idtyp": "app"},
                                   {"scp": ""}, {"aud": "https://attacker.example"}])
def test_bound_whoami_checks_actual_token_claims_before_sending_any_request(claims):
    source = DirectReaderSource(bound_identity_scenario(), bound(claims),
                               transport=httpx.MockTransport(lambda _: pytest.fail("Wrong token must never be sent.")))
    try:
        with pytest.raises(SourceProjectionError) as failure:
            source.verify_identity()
        assert failure.value.code == "authentication_failed"
    finally:
        source.close()


def test_bound_whoami_requires_verification_and_clears_an_earlier_success_on_recheck_failure():
    selected, calls = bound_identity_scenario(), []
    def handle(request):
        calls.append(request)
        assert request.url.path.endswith("WhoAmI")
        return httpx.Response(200, json={"OrganizationId": uid(2), "UserId": uid(4) if len(calls) == 1 else uid(99)})
    source = DirectReaderSource(selected, bound(), transport=httpx.MockTransport(handle))
    try:
        with pytest.raises(QualificationError, match="identity_not_verified"):
            source.read(selected.tables[0])
        source.verify_identity()
        with pytest.raises(QualificationError, match="identity_not_verified"):
            source.verify_identity()
        with pytest.raises(QualificationError, match="identity_not_verified"):
            source.read(selected.tables[0])
    finally:
        source.close()


@pytest.mark.parametrize("reader_update", [
    {"identity_verification": "bound_whoami"},
    {"identity_verification": "bound_whoami", "dataverse_id": None},
    {"identity_verification": "bound_whoami", "dataverse_id": uid(0)},
    {"identity_verification": "automatic_fallback", "dataverse_id": uid(4)},
])
def test_direct_identity_mode_and_dataverse_binding_must_be_explicit_valid_input(reader_update):
    raw = raw_scenario()
    raw["readers"][0].update(reader_update)
    with pytest.raises(QualificationError):
        QualificationScenario.from_mapping(raw, "basic_owner")


def test_legacy_scenario_retains_fetchxml_identity_verification():
    selected = scenario()
    assert selected.identity_verification == "fetchxml"
    assert selected.reader_dataverse_id is None


@pytest.mark.parametrize("change", [{"isdisabled": True}, {"applicationid": uid(99)},
                                    {"accessmode": 4}, {"azureactivedirectoryobjectid": uid(99)}])
def test_direct_source_rejects_disabled_application_wrong_or_special_user(change):
    def handle(request):
        if request.url.path.endswith("WhoAmI"):
            return httpx.Response(200, json={"OrganizationId": uid(2), "UserId": uid(4)})
        record = {"systemuserid": uid(4), "azureactivedirectoryobjectid": uid(3), "isdisabled": False,
                  "applicationid": None, "accessmode": 0, **change}
        return httpx.Response(200, json={"value": [record]})
    source = DirectReaderSource(scenario(), bound(), transport=httpx.MockTransport(handle))
    try:
        with pytest.raises(QualificationError, match="identity_not_verified"):
            source.verify_identity()
    finally:
        source.close()


def test_source_permission_denial_is_not_generic_http_failure():
    for status, expected_denied in ((403, True), (400, False)):
        source = DirectReaderSource(scenario(), bound(), transport=httpx.MockTransport(lambda _: httpx.Response(status)))
        try:
            if expected_denied:
                assert source.read(scenario().tables[0]) == ReadOutcome(False, ())
            else:
                with pytest.raises(QualificationError, match="source_read_incomplete"):
                    source.read(scenario().tables[0])
        finally:
            source.close()


def test_decimal_guid_datetime_canonicalization_is_exact_and_null_preserving():
    value = Decimal("1234567890123456789012345678.1234567890")
    assert canonical_value(value, "Money") == "1234567890123456789012345678.123456789"
    assert canonical_value(Decimal("1.23000"), "Decimal") == "1.23"
    assert canonical_value(None, "Money") is None
    assert canonical_value("2026-09-18T14:00:00+02:00", "DateTime") == canonical_value(datetime(2026, 9, 18, 12), "DateTime")
    assert canonical_value(uid(123).upper(), "Uniqueidentifier") == uid(123)


@pytest.mark.parametrize("value,kind", [(float("nan"), "Double"), (Decimal("Infinity"), "Money"),
                                       ({"raw": 1}, "String"), ("1", "Boolean"), (1.5, "Integer")])
def test_invalid_or_complex_values_fail_without_printing_values(value, kind):
    with pytest.raises(QualificationError, match="unsupported_or_invalid_typed_value"):
        canonical_value(value, kind)


@pytest.mark.parametrize("mutate", [
    lambda r: r["sql"].update(server="attacker.example"),
    lambda r: r["sql"].update(database="db;Password=secret"),
    lambda r: r["tables"][0].update(target_name="account]; DROP TABLE account"),
    lambda r: r["readers"][0]["tables"]["account"].update(records=[]),
    lambda r: r["readers"][0]["tables"]["account"]["records"][0].update(null_fields=["raw_unknown"]),
    lambda r: r.update(max_seconds=10000),
])
def test_unsafe_or_incomplete_fixture_scenarios_fail(mutate):
    raw = raw_scenario()
    mutate(raw)
    with pytest.raises(QualificationError):
        QualificationScenario.from_mapping(raw, "basic_owner")


def test_four_reader_template_contains_no_fabricated_identities_or_acceptance(tmp_path):
    template = scenario_template()
    assert [r["label"] for r in template["readers"]] == ["basic_owner", "poa_recipient", "team_member", "bu_field_security"]
    assert all(r["entra_id"].startswith("REPLACE") for r in template["readers"])
    assert all(r["dataverse_id"].startswith("REPLACE") and r["identity_verification"] == "bound_whoami"
               for r in template["readers"])
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(template))
    with pytest.raises(QualificationError):
        load_scenario(path, "basic_owner")


class FakeSqlCursor:
    def __init__(self, connection):
        self.connection = connection
        self.description = [(c,) for c in ("accountid", "name", "secret", "amount")]
        self.sent = False

    def execute(self, sql, *params):
        self.connection.queries.append((sql, params))
        if "__pw_" in sql:
            raise Exception("42000", "Permission denied (229)")

    def fetchmany(self, _):
        if self.sent:
            return []
        self.sent = True
        return [tuple(r[c] for c in ("accountid", "name", "secret", "amount")) for r in rows()]

    def close(self):
        pass


class FakeSqlConnection:
    def __init__(self):
        self.queries = []
        self.timeout = None

    def cursor(self):
        return FakeSqlCursor(self)

    def close(self):
        pass


def test_sql_uses_same_user_token_tls_explicit_columns_parameters_and_helper_denials():
    connection = FakeSqlConnection()
    captured = {}

    def connect(connection_string, **kwargs):
        captured.update(connection_string=connection_string, **kwargs)
        return connection

    target = ReaderSqlTarget(scenario(), bound(), connect=connect)
    outcome = target.read(scenario().tables[0])
    assert outcome.allowed and len(outcome.rows) == 2
    assert target.helpers_denied(scenario().tables[0])
    assert "Encrypt=yes" in captured["connection_string"] and "TrustServerCertificate=no" in captured["connection_string"]
    assert "UID=" not in captured["connection_string"] and "PWD=" not in captured["connection_string"]
    packed = captured["attrs_before"][1256]
    assert struct.unpack("<I", packed[:4])[0] == len(packed[4:])
    claims = json.loads(base64.urlsafe_b64decode(packed[4:].decode("utf-16-le").split(".")[1] + "=="))
    assert claims["oid"] == uid(3) and claims["aud"] == "https://database.windows.net"
    assert all("SELECT *" not in sql for sql, _ in connection.queries)
    with pytest.raises(QualificationError, match="only_single_select"):
        target.query("DROP TABLE account")
    with pytest.raises(QualificationError, match="only_single_select"):
        target.query("SELECT 1; DELETE FROM account")


def test_sql_syntax_error_never_counts_as_permission_denial():
    class BadCursor(FakeSqlCursor):
        def execute(self, *_):
            raise Exception("42000", "Invalid column (207)")

    connection = FakeSqlConnection()
    connection.cursor = lambda: BadCursor(connection)
    target = ReaderSqlTarget(scenario(), bound(), connect=lambda *_, **__: connection)
    with pytest.raises(QualificationError, match="sql_query_failed"):
        target.helpers_denied(scenario().tables[0])


def test_cli_can_generate_unpopulated_template_without_authentication(tmp_path, capsys):
    path = Path(__file__).resolve().parents[1] / "scripts" / "qualify_reader.py"
    spec = importlib.util.spec_from_file_location("qualify_reader_script", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "fixtures.json"
    assert module.main(["--write-template", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["reader_scenarios"] == 4
    assert len(json.loads(output.read_text())["readers"]) == 4
