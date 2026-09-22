"""Actual-reader Dataverse/Fabric SQL differential qualification.

GET/SELECT only. No impersonation headers, role mutations or source mutations.
The same delegated Entra identity must obtain both tokens. A passing report is
evidence for its selected reader, fixtures, columns, time and SQL access path;
it does not certify Spark, time travel, cache revocation or every source rule.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import secrets
import struct
import time
from typing import Any, Mapping
from urllib.parse import quote, urlsplit
from uuid import UUID

from .source_projection import SourceAttribute, SourceProjectionClient, SourceProjectionError, SourceTable


class QualificationError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def guid(value):
    try:
        parsed = UUID(str(value))
        if parsed.int == 0:
            raise ValueError
        return str(parsed)
    except (ValueError, TypeError, AttributeError):
        raise QualificationError("invalid_identity") from None


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,127}", value):
        raise QualificationError("unsafe_identifier")
    return value


@dataclass(frozen=True)
class RecordExpectation:
    record_id: str
    visible: bool
    null_fields: tuple[str, ...] = ()
    non_null_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class QualificationTable:
    source: SourceTable
    target_schema: str
    target_name: str
    expect_denied: bool
    records: tuple[RecordExpectation, ...]

    @property
    def sql_name(self):
        return f"[{identifier(self.target_schema)}].[{identifier(self.target_name)}]"


@dataclass(frozen=True)
class QualificationScenario:
    scenario_id: str
    environment_url: str
    tenant_id: str
    organization_id: str
    reader_entra_id: str
    sql_server: str
    sql_database: str
    tables: tuple[QualificationTable, ...]
    max_rows: int = 100000
    max_seconds: int = 300
    identity_verification: str = "fetchxml"
    reader_dataverse_id: str | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], reader_label: str):
        if raw.get("schema_version") != 1 or not isinstance(raw.get("readers"), list):
            raise QualificationError("invalid_scenario_schema")
        readers = [r for r in raw["readers"] if r.get("label") == reader_label]
        if len(readers) != 1:
            raise QualificationError("reader_label_not_unique")
        reader = readers[0]
        identity_mode = reader.get("identity_verification", "fetchxml")
        if identity_mode not in ("fetchxml", "bound_whoami"):
            raise QualificationError("invalid_direct_identity_mode")
        dataverse_id = guid(reader["dataverse_id"]) if "dataverse_id" in reader else None
        if identity_mode == "bound_whoami" and dataverse_id is None:
            raise QualificationError("bound_whoami_requires_dataverse_identity")
        tables = []
        for raw_table in raw.get("tables", []):
            source_raw = raw_table["source"]
            source = SourceTable(**{**source_raw, "attributes": tuple(SourceAttribute(**a) for a in source_raw["attributes"])})
            identifier(source.name)
            attrs = {a.property_name: a for a in source.attributes}
            if set(attrs) != set(source.columns) or len(attrs) != len(source.attributes):
                raise QualificationError("incomplete_column_type_metadata")
            if any(c.startswith("__pw_") for c in source.columns):
                raise QualificationError("business_columns_include_helpers")
            expectation = reader["tables"][source.name]
            denied = expectation["table_denied"]
            if type(denied) is not bool:
                raise QualificationError("invalid_table_expectation")
            records = []
            for record in expectation.get("records", []):
                if type(record["visible"]) is not bool:
                    raise QualificationError("invalid_record_expectation")
                null_fields = tuple(record.get("null_fields", ()))
                non_null_fields = tuple(record.get("non_null_fields", ()))
                if (not set(null_fields + non_null_fields) <= set(source.columns)
                        or set(null_fields) & set(non_null_fields)):
                    raise QualificationError("invalid_field_expectation")
                if not record["visible"] and (null_fields or non_null_fields):
                    raise QualificationError("invisible_record_has_field_expectations")
                records.append(RecordExpectation(guid(record["record_id"]), record["visible"], null_fields, non_null_fields))
            if len({r.record_id for r in records}) != len(records):
                raise QualificationError("duplicate_fixture_record")
            if not denied and (not any(r.visible for r in records) or not any(not r.visible for r in records)):
                raise QualificationError("positive_and_negative_fixtures_required")
            if denied and records:
                raise QualificationError("denied_table_must_not_declare_visible_records")
            tables.append(QualificationTable(source, identifier(raw_table.get("target_schema", "dbo")),
                                              identifier(raw_table["target_name"]), denied, tuple(records)))
        server = raw["sql"]["server"]
        database = raw["sql"]["database"]
        if not isinstance(server, str) or not re.fullmatch(r"[a-zA-Z0-9-]+\.datawarehouse\.fabric\.microsoft\.com", server):
            raise QualificationError("invalid_fabric_sql_server")
        if not isinstance(database, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", database):
            raise QualificationError("invalid_sql_database")
        if not tables or len({t.source.name for t in tables}) != len(tables):
            raise QualificationError("invalid_scenario_tables")
        scenario_id = identifier(raw.get("scenario_id", "reader_qualification"))
        rows, seconds = raw.get("max_rows", 100000), raw.get("max_seconds", 300)
        if type(rows) is not int or not 1 <= rows <= 1000000 or type(seconds) is not int or not 1 <= seconds <= 600:
            raise QualificationError("invalid_qualification_budget")
        return cls(scenario_id, raw["environment_url"], guid(raw["tenant_id"]), guid(raw["organization_id"]),
                   guid(reader["entra_id"]), server, database, tuple(tables), rows, seconds,
                   identity_mode, dataverse_id)


def load_scenario(path: str | Path, reader_label: str) -> QualificationScenario:
    try:
        return QualificationScenario.from_mapping(json.loads(Path(path).read_text(encoding="utf-8-sig")), reader_label)
    except QualificationError:
        raise
    except Exception:
        raise QualificationError("invalid_scenario_document") from None


class BoundUserCredential:
    """Bind SDK-issued tokens to one delegated user before sending them.

    JWT claim inspection is a client-side mistake-prevention check, not signature
    verification. Dataverse/SQL validate the SDK-acquired token at their boundary.
    Arbitrary caller-supplied JWTs are never accepted by the command line tool.
    """
    def __init__(self, credential, tenant_id, reader_entra_id, environment_url):
        self.credential = credential
        self.tenant_id = guid(tenant_id)
        self.reader_entra_id = guid(reader_entra_id)
        self.environment_url = environment_url.rstrip("/")

    def get_token(self, *scopes, **kwargs):
        allowed = {self.environment_url + "/.default", "https://database.windows.net/.default"}
        if len(scopes) != 1 or scopes[0] not in allowed:
            raise QualificationError("unexpected_token_scope")
        try:
            token = self.credential.get_token(*scopes, **kwargs)
            parts = token.token.split(".")
            if len(parts) != 3:
                raise ValueError
            claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
            if (guid(claims.get("tid")) != self.tenant_id or guid(claims.get("oid")) != self.reader_entra_id
                    or claims.get("idtyp") == "app" or not isinstance(claims.get("scp"), str) or not claims["scp"]
                    or not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= time.time()):
                raise ValueError
            audience = str(claims.get("aud", "")).rstrip("/")
            expected = ("https://database.windows.net" if scopes[0].startswith("https://database.windows.net/")
                        else self.environment_url)
            if audience.lower() != expected.lower():
                raise ValueError
            return token
        except Exception:
            raise QualificationError("delegated_reader_token_identity_or_audience_mismatch") from None


@dataclass(frozen=True)
class ReadOutcome:
    allowed: bool
    rows: tuple[Mapping[str, Any], ...]


class DirectReaderSource:
    """No CallerObjectId; the existing guarded GET transport runs as the user."""
    def __init__(self, scenario, credential, *, transport=None):
        self.scenario = scenario
        if scenario.identity_verification not in ("fetchxml", "bound_whoami"):
            raise QualificationError("invalid_direct_identity_mode")
        if scenario.identity_verification == "bound_whoami":
            guid(scenario.reader_dataverse_id)
            if (not isinstance(credential, BoundUserCredential)
                    or credential.tenant_id != scenario.tenant_id
                    or credential.reader_entra_id != scenario.reader_entra_id
                    or credential.environment_url != scenario.environment_url.rstrip("/")):
                raise QualificationError("direct_reader_bound_credential_required")
        self._identity_verified = False
        self.client = SourceProjectionClient(scenario.environment_url, scenario.tenant_id, scenario.organization_id,
                                              credential=credential, transport=transport,
                                              max_rows_per_scan=scenario.max_rows, max_scan_seconds=scenario.max_seconds)
        self.deadline = time.monotonic() + scenario.max_seconds

    def close(self):
        self.client.close()

    def verify_identity(self):
        self._identity_verified = False
        who = self.client._request("WhoAmI", deadline=self.deadline)
        if guid(who.get("OrganizationId")) != self.scenario.organization_id:
            raise QualificationError("source_organization_mismatch")
        who_user = guid(who.get("UserId"))
        if (self.scenario.reader_dataverse_id is not None
                and who_user != self.scenario.reader_dataverse_id):
            raise QualificationError("direct_reader_identity_not_verified")
        if self.scenario.identity_verification == "bound_whoami":
            # This proof is valid only for direct SDK-acquired delegated tokens:
            # no impersonation header is sent anywhere by this reader client.
            # The controlled fixture binds the Entra and Dataverse identities;
            # the services validate the tokens, and WhoAmI confirms the caller.
            self._identity_verified = True
            return
        fetch = ('<fetch><entity name="systemuser"><attribute name="systemuserid"/>'
                 '<attribute name="azureactivedirectoryobjectid"/><attribute name="isdisabled"/>'
                 '<attribute name="applicationid"/><attribute name="accessmode"/>'
                 '<filter><condition attribute="systemuserid" operator="eq-userid"/></filter></entity></fetch>')
        rows = list(self.client._collection("systemusers?fetchXml=" + quote(fetch, safe=""), deadline=self.deadline))
        if (len(rows) != 1 or guid(rows[0].get("systemuserid")) != who_user
                or guid(rows[0].get("azureactivedirectoryobjectid")) != self.scenario.reader_entra_id
                or rows[0].get("isdisabled") is not False or rows[0].get("applicationid") is not None
                or type(rows[0].get("accessmode")) is not int or rows[0]["accessmode"] not in (0, 2)):
            raise QualificationError("direct_reader_identity_not_verified")
        self._identity_verified = True

    def read(self, table: QualificationTable):
        if self.scenario.identity_verification == "bound_whoami" and not self._identity_verified:
            raise QualificationError("direct_reader_identity_not_verified")
        source = table.source
        reference = f"{source.entity_set}?$select={','.join(source.columns)}&$orderby={source.primary_key} asc"
        rows, seen = [], set()
        try:
            for raw in self.client._collection(reference, deadline=self.deadline):
                pk = guid(raw.get(source.primary_key))
                if pk in seen or len(rows) >= self.scenario.max_rows:
                    raise QualificationError("source_duplicate_or_row_budget")
                seen.add(pk)
                row = {c: raw.get(c) for c in source.columns}
                row[source.primary_key] = pk
                rows.append(row)
        except SourceProjectionError as exc:
            if exc.status == 403 and not rows:
                return ReadOutcome(False, ())
            raise QualificationError("source_read_incomplete") from None
        return ReadOutcome(True, tuple(rows))


def _sql_permission_denial(exc):
    # Do not turn syntax failures, missing objects, transport or login errors into
    # a successful security test. Only explicit SQL permission errors qualify.
    args = getattr(exc, "args", ())
    return bool(args and str(args[0]) == "42000" and re.search(r"\((?:229|230|297|916)\)", " ".join(map(str, args[1:]))))


class ReaderSqlTarget:
    def __init__(self, scenario, credential, *, connect=None):
        self.scenario = scenario
        if not re.fullmatch(r"[a-zA-Z0-9-]+\.datawarehouse\.fabric\.microsoft\.com", scenario.sql_server):
            raise QualificationError("invalid_fabric_sql_server")
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", scenario.sql_database):
            raise QualificationError("invalid_sql_database")
        if connect is None:
            try:
                import pyodbc
                connect = pyodbc.connect
            except ImportError:
                raise QualificationError("install_pyodbc_and_odbc_driver_18") from None
        token = credential.get_token("https://database.windows.net/.default")
        token_bytes = token.token.encode("utf-16-le")
        token_attribute = struct.pack("<I", len(token_bytes)) + token_bytes
        connection_string = ("Driver={ODBC Driver 18 for SQL Server};"
                             f"Server=tcp:{scenario.sql_server},1433;Database={scenario.sql_database};"
                             "Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;")
        try:
            self.connection = connect(connection_string, attrs_before={1256: token_attribute}, autocommit=True)
            self.connection.timeout = min(60, scenario.max_seconds)
        except Exception:
            raise QualificationError("reader_sql_connection_failed") from None
        self.deadline = time.monotonic() + scenario.max_seconds

    def close(self):
        self.connection.close()

    def query(self, sql, params=()):
        if not isinstance(sql, str) or not sql.startswith("SELECT ") or any(part in sql for part in (";", "--", "/*", "*/")):
            raise QualificationError("only_single_select_is_permitted")
        if time.monotonic() >= self.deadline:
            raise QualificationError("qualification_deadline_exceeded")
        cursor = self.connection.cursor()
        try:
            cursor.execute(sql, *params)
            names = tuple(c[0] for c in cursor.description)
            rows = []
            while True:
                batch = cursor.fetchmany(1000)
                if not batch:
                    break
                if len(rows) + len(batch) > self.scenario.max_rows:
                    raise QualificationError("target_row_budget_exceeded")
                rows.extend(dict(zip(names, row)) for row in batch)
                if time.monotonic() >= self.deadline:
                    raise QualificationError("qualification_deadline_exceeded")
            return tuple(rows)
        except QualificationError:
            raise
        except Exception as exc:
            if _sql_permission_denial(exc):
                raise QualificationError("sql_permission_denied") from None
            raise QualificationError("sql_query_failed") from None
        finally:
            cursor.close()

    def read(self, table):
        columns = ",".join(f"[{identifier(c)}]" for c in table.source.columns)
        try:
            return ReadOutcome(True, self.query(f"SELECT {columns} FROM {table.sql_name}"))
        except QualificationError as exc:
            if exc.code == "sql_permission_denied":
                return ReadOutcome(False, ())
            raise

    def scalar(self, table, expression, where="", params=()):
        rows = self.query(f"SELECT {expression} AS [result] FROM {table.sql_name}{where}", params)
        if len(rows) != 1 or set(rows[0]) != {"result"}:
            raise QualificationError("invalid_scalar_result")
        return rows[0]["result"]

    def helpers_denied(self, table):
        denied = 0
        for helper in ("__pw_reader", "__pw_generation"):
            try:
                self.query(f"SELECT TOP (1) [{helper}] FROM {table.sql_name}")
            except QualificationError as exc:
                if exc.code != "sql_permission_denied":
                    raise
                denied += 1
        return denied == 2


def canonical_value(value, attribute_type):
    if value is None:
        return None
    try:
        if attribute_type in {"Uniqueidentifier", "Lookup", "Owner", "Customer"}:
            return guid(value)
        if attribute_type in {"Decimal", "Money"}:
            decimal = Decimal(str(value))
            if not decimal.is_finite():
                raise ValueError
            if not decimal:
                return "0"
            formatted = format(decimal, "f")
            return formatted.rstrip("0").rstrip(".") if "." in formatted else formatted
        if attribute_type in {"Integer", "BigInt", "Picklist", "State", "Status"}:
            if isinstance(value, bool) or Decimal(str(value)) != int(value):
                raise ValueError
            return int(value)
        if attribute_type == "Double":
            number = float(value)
            if not math.isfinite(number):
                raise ValueError
            return number.hex()
        if attribute_type == "Boolean":
            if type(value) not in (bool, int) or value not in (0, 1):
                raise ValueError
            return bool(value)
        if attribute_type == "DateTime":
            date = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
            if not isinstance(date, datetime):
                raise ValueError
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            return date.astimezone(timezone.utc).isoformat(timespec="microseconds")
        if attribute_type in {"String", "Memo", "EntityName", "MultiSelectPicklist"} and isinstance(value, str):
            return value
    except (ValueError, TypeError, InvalidOperation, OverflowError):
        pass
    raise QualificationError("unsupported_or_invalid_typed_value")


def normalize_rows(outcome, table):
    types = {a.property_name: a.attribute_type for a in table.source.attributes}
    rows = {}
    for row in outcome.rows:
        if set(row) != set(table.source.columns):
            raise QualificationError("projection_columns_changed")
        normalized = {c: canonical_value(row[c], types[c]) for c in table.source.columns}
        key = normalized[table.source.primary_key]
        if key is None or key in rows:
            raise QualificationError("duplicate_or_missing_target_record")
        rows[key] = normalized
    return rows


def _fingerprint(rows, secret):
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def qualify(scenario, source, target):
    """Run row/cell, known fixture, NULL predicate, aggregate and helper tests.

    Aggregate expectations derive from *projected* source values. This does not
    assert that Dataverse raw secured-field filter semantics equal SQL semantics.
    """
    start = time.monotonic()
    source.verify_identity()
    secret = secrets.token_bytes(32)  # Not exported: fingerprints cannot be dictionary-tested offline.
    results, failures = [], []
    for table in scenario.tables:
        before = source.read(table)
        actual = target.read(table)
        source_rows, target_rows = normalize_rows(before, table), normalize_rows(actual, table)
        categories = []
        if before.allowed != actual.allowed or before.allowed == table.expect_denied:
            categories.append("table_authorization_mismatch")
        if set(source_rows) != set(target_rows):
            categories.append("record_set_mismatch")
        if any(source_rows[k] != target_rows[k] for k in source_rows.keys() & target_rows.keys()):
            categories.append("field_value_or_null_mismatch")
        for fixture in table.records:
            present = fixture.record_id in source_rows
            if present != fixture.visible:
                categories.append("source_fixture_expectation_mismatch")
            if (fixture.record_id in target_rows) != fixture.visible:
                categories.append("target_fixture_expectation_mismatch")
            if present:
                source_record = source_rows[fixture.record_id]
                if any(source_record[c] is not None for c in fixture.null_fields) or any(source_record[c] is None for c in fixture.non_null_fields):
                    categories.append("source_field_fixture_expectation_mismatch")
        checks = 0
        if before.allowed and actual.allowed:
            if target.scalar(table, "COUNT_BIG(*)") != len(source_rows):
                categories.append("count_aggregate_mismatch")
            checks += 1
            for attribute in table.source.attributes:
                column = identifier(attribute.property_name)
                if attribute.is_secured:
                    expected_nulls = sum(r[column] is None for r in source_rows.values())
                    actual_nulls = target.scalar(table, "COUNT_BIG(*)", f" WHERE [{column}] IS NULL")
                    if actual_nulls != expected_nulls:
                        categories.append("null_filter_mismatch")
                    checks += 1
                if attribute.attribute_type in {"Money", "Decimal", "Integer", "BigInt"}:
                    values = [Decimal(str(r[column])) for r in source_rows.values() if r[column] is not None]
                    # High precision avoids silently rounding a Decimal(38,10) total.
                    from decimal import localcontext
                    with localcontext() as context:
                        context.prec = 80
                        expected_sum = sum(values, Decimal(0)) if values else None
                    actual_sum = target.scalar(table, f"SUM([{column}])")
                    if ((actual_sum is None) != (expected_sum is None)
                            or actual_sum is not None and Decimal(str(actual_sum)) != expected_sum):
                        categories.append("numeric_aggregate_mismatch")
                    checks += 1
            if not target.helpers_denied(table):
                categories.append("internal_helper_column_readable")
            for fixture in table.records:
                count = target.scalar(table, "COUNT_BIG(*)", f" WHERE [{identifier(table.source.primary_key)}] = ?", (fixture.record_id,))
                if count != int(fixture.visible):
                    categories.append("record_filter_mismatch")
                checks += 1
        after = source.read(table)
        if before.allowed != after.allowed or source_rows != normalize_rows(after, table):
            categories.append("source_changed_during_probe")
        if time.monotonic() - start > scenario.max_seconds:
            raise QualificationError("qualification_deadline_exceeded")
        categories = sorted(set(categories))
        failures.extend(categories)
        results.append({"source_row_count": len(source_rows), "target_row_count": len(target_rows),
                        "source_table_allowed": before.allowed, "target_table_allowed": actual.allowed,
                        "source_fingerprint": _fingerprint(source_rows, secret),
                        "target_fingerprint": _fingerprint(target_rows, secret),
                        "fixture_count": len(table.records), "query_checks": checks,
                        "mismatch_categories": categories})
    return {"schema_version": 1, "status": "passed_selected_sql_checks" if not failures else "failed",
            "identity_verified": True, "source_mode": "actual_user_without_impersonation",
            "identity_verification": scenario.identity_verification,
            "access_path": "Fabric_SQL", "production_certified": False,
            "revocation_sla_verified": False, "elapsed_seconds": round(time.monotonic() - start, 3), "tables": results}


def scenario_template(prepared_manifest=None):
    """Four unpopulated reader scenarios. Placeholders cannot accidentally pass."""
    if prepared_manifest is not None:
        source_tables = prepared_manifest["tables"]
    else:
        source_tables = [{"name": "account", "entity_set": "accounts", "primary_key": "accountid",
                          "columns": ["accountid", "name", "REPLACE_SECURED_COLUMN"],
                          "attributes": [{"logical_name": "accountid", "property_name": "accountid", "attribute_type": "Uniqueidentifier", "is_secured": False},
                                         {"logical_name": "name", "property_name": "name", "attribute_type": "String", "is_secured": False},
                                         {"logical_name": "REPLACE_SECURED_COLUMN", "property_name": "REPLACE_SECURED_COLUMN", "attribute_type": "String", "is_secured": True}]}]
    return {"schema_version": 1, "scenario_id": "reader_acceptance", "tenant_id": "REPLACE_TENANT_GUID",
            "organization_id": "REPLACE_ORGANIZATION_GUID", "environment_url": "https://REPLACE.crm.dynamics.com",
            "sql": {"server": "REPLACE.datawarehouse.fabric.microsoft.com", "database": "REPLACE_SERVING_DATABASE"},
            "max_rows": 100000, "max_seconds": 300,
            "tables": [{"source": t, "target_schema": "dbo", "target_name": "pw_demo_" + t["name"]} for t in source_tables],
            "readers": [{"label": label, "upn": "REPLACE_WITH_REAL_READER_UPN", "entra_id": "REPLACE_READER_ENTRA_GUID",
                         "dataverse_id": "REPLACE_READER_DATAVERSE_GUID", "identity_verification": "bound_whoami",
                         "tables": {t["name"]: {"table_denied": False, "records": [
                             {"record_id": "REPLACE_KNOWN_VISIBLE_RECORD_GUID", "visible": True,
                              "null_fields": [], "non_null_fields": []},
                             {"record_id": "REPLACE_KNOWN_DENIED_RECORD_GUID", "visible": False}]} for t in source_tables}}
                        for label in ("basic_owner", "poa_recipient", "team_member", "bu_field_security")]}
