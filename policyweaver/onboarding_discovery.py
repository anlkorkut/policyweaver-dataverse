"""Bounded, GET-only onboarding inventory for Microsoft public cloud.

This inventory is a selection aid, never a permission proof or a publication
boundary attestation. It does not read business rows, select a deployment target,
grant access, or infer that a successful inventory call confers administrator
rights. Credentials are injected; the CLI supplies AzureCliCredential, not JWTs.
"""
from __future__ import annotations

import base64
import json
import math
import re
import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import UUID

import httpx

from .source_projection import SourceProjectionClient
from .dataverse import DataverseError

FABRIC_ORIGIN = "https://api.fabric.microsoft.com"
FABRIC_ROOT = FABRIC_ORIGIN + "/v1"
_SCALAR_TYPES = frozenset({
    "Boolean", "DateTime", "Decimal", "Double", "Integer", "BigInt", "Memo", "Money", "String",
    "Uniqueidentifier", "Lookup", "Owner", "Customer", "Picklist", "State", "Status", "EntityName",
})


class DiscoveryError(RuntimeError):
    """A diagnostic without tokens, response bodies, or arbitrary server text."""
    def __init__(self, code: str, message: str | None = None, status: int | None = None):
        self.code, self.status = code, status
        super().__init__(message or code)


def _guid(value: Any) -> str:
    try:
        result = UUID(str(value))
        if not result.int:
            raise ValueError
        return str(result)
    except (ValueError, TypeError, AttributeError):
        raise DiscoveryError("invalid_identifier", "A required nonzero GUID is invalid.") from None


def _name(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,127}", value):
        raise DiscoveryError("invalid_logical_name", "A table or column logical name is invalid.")
    return value


def _text(value: Any, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if (not isinstance(value, str) or not value.strip() or len(value) > 2000
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise DiscoveryError("invalid_inventory_text", "Inventory naming metadata is invalid.")
    return value


def _upn(value: Any) -> str:
    value = _text(value)
    if not re.fullmatch(r"[^\s@]+@[^\s@]+", value) or value != value.strip():
        raise DiscoveryError("invalid_operator_upn", "An explicit user principal name is required.")
    return value


def _environment_url(value: Any) -> str:
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.port not in (None, 443) or parsed.query or parsed.fragment
                or parsed.path not in ("", "/")
                or not re.fullmatch(r"[a-zA-Z0-9-]+\.crm\d*\.dynamics\.com", parsed.hostname)):
            raise ValueError
        return "https://" + parsed.hostname.lower()
    except (ValueError, TypeError, AttributeError):
        raise DiscoveryError("unsupported_environment_origin", "Supply a Microsoft public-cloud Dataverse HTTPS origin.") from None


class BoundCredential:
    """Pin SDK tokens to the expected tenant, delegated UPN, OID and resource.

    JWT inspection prevents accidental account/resource mix-ups. It is not local
    signature validation; the destination services validate SDK-issued tokens.
    The command line never accepts a user-provided access token.
    """
    def __init__(self, credential, *, tenant_id: str, dataverse_url: str,
                 operator_upn: str, operator_entra_id: str | None = None, clock=time.time):
        self.credential = credential
        self.tenant_id = _guid(tenant_id)
        self.environment_url = _environment_url(dataverse_url)
        self.operator_upn = _upn(operator_upn)
        self.operator_entra_id = _guid(operator_entra_id) if operator_entra_id else None
        self.clock = clock

    def get_token(self, *scopes, **kwargs):
        audiences = {self.environment_url + "/.default": self.environment_url,
                     FABRIC_ORIGIN + "/.default": FABRIC_ORIGIN}
        if len(scopes) != 1 or scopes[0] not in audiences or kwargs:
            raise DiscoveryError("unexpected_token_scope", "Discovery requested an unapproved token scope or override.")
        try:
            token = self.credential.get_token(*scopes)
        except Exception:
            raise DiscoveryError("authentication_failed", "Azure CLI could not acquire the requested resource token.") from None
        try:
            parts = token.token.split(".")
            if len(parts) != 3 or len(parts[1]) > 100_000:
                raise ValueError
            claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
            if not isinstance(claims, dict):
                raise ValueError
            oid = _guid(claims.get("oid"))
            names = [claims[k] for k in ("upn", "preferred_username", "unique_name") if k in claims]
            # Some tokens include both UPN and unique_name. Require every present
            # username claim to agree; never choose whichever happens to match.
            if (not names or any(not isinstance(n, str) or n.casefold() != self.operator_upn.casefold() for n in names)
                    or _guid(claims.get("tid")) != self.tenant_id
                    or (self.operator_entra_id is not None and oid != self.operator_entra_id)
                    or claims.get("idtyp") == "app" or not isinstance(claims.get("scp"), str)
                    or not claims["scp"].strip()
                    or str(claims.get("aud", "")).rstrip("/").lower() != audiences[scopes[0]].lower()
                    or type(claims.get("exp")) not in (int, float) or not math.isfinite(claims["exp"])
                    or claims["exp"] <= self.clock()
                    or type(token.expires_on) not in (int, float) or not math.isfinite(token.expires_on)
                    or token.expires_on <= self.clock()):
                raise ValueError
            if "nbf" in claims and (type(claims["nbf"]) not in (int, float)
                    or not math.isfinite(claims["nbf"]) or claims["nbf"] > self.clock() + 60):
                raise ValueError
            self.operator_entra_id = oid
            return token
        except Exception:
            raise DiscoveryError("operator_token_binding_mismatch",
                                 "The delegated token does not match the expected tenant, UPN, identity, resource or validity period.") from None


def _limit(value: Any, name: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise DiscoveryError("invalid_discovery_budget", f"The {name} budget must be between 1 and {maximum}.")
    return value


class _ReadOnlySession:
    def __init__(self, credential, transport, *, max_seconds, max_pages, monotonic):
        self.credential, self.monotonic = credential, monotonic
        self.deadline = monotonic() + max_seconds
        self.max_pages, self.requests = max_pages, 0
        self.client = httpx.Client(transport=transport, follow_redirects=False, trust_env=False,
                                  timeout=min(30, max_seconds), headers={"Accept": "application/json"})

    def check(self):
        if self.monotonic() >= self.deadline:
            raise DiscoveryError("discovery_deadline_exceeded", "Discovery exceeded its time budget; no complete inventory was produced.")

    def get(self, url, *, scope):
        self.check()
        if len(url) > 32768:
            raise DiscoveryError("discovery_request_too_long", "A discovery URL exceeded the 32 KB request budget.")
        token = self.credential.get_token(scope)
        self.check()
        headers = {"Authorization": "Bearer " + token.token}
        if not scope.startswith(FABRIC_ORIGIN):
            headers.update({"OData-Version": "4.0", "OData-MaxVersion": "4.0", "Prefer": "odata.maxpagesize=500"})
        try:
            self.requests += 1
            with self.client.stream("GET", url, headers=headers) as response:
                self.check()
                if response.status_code != 200:
                    code = "redirect_refused" if 300 <= response.status_code < 400 else "discovery_http_error"
                    raise DiscoveryError(code, f"Discovery returned HTTP {response.status_code}; inventory is incomplete.", response.status_code)
                raw = bytearray()
                for chunk in response.iter_bytes():
                    self.check()
                    if len(raw) + len(chunk) > 20_000_000:
                        raise DiscoveryError("discovery_response_too_large", "An inventory response exceeded the 20 MB budget.")
                    raw.extend(chunk)
        except httpx.TransportError:
            raise DiscoveryError("discovery_transport_failed", "A discovery GET failed; no automatic request retry was made.") from None
        self.check()
        try:
            def bad_constant(_):
                raise ValueError
            payload = json.loads(raw, parse_constant=bad_constant)
            if not isinstance(payload, dict):
                raise ValueError
            return payload
        except ValueError:
            raise DiscoveryError("discovery_invalid_json", "Discovery returned an invalid JSON object.") from None

    def collection(self, first_url, *, scope, validator, max_rows):
        result, seen, reference = [], set(), first_url
        for _ in range(self.max_pages):
            url = validator(reference)
            if url in seen:
                raise DiscoveryError("discovery_pagination_cycle", "An inventory continuation repeated a page.")
            seen.add(url)
            body = self.get(url, scope=scope)
            values = body.get("value")
            if not isinstance(values, list) or any(not isinstance(v, dict) for v in values):
                raise DiscoveryError("discovery_invalid_collection", "Discovery returned an invalid collection.")
            if len(result) + len(values) > max_rows:
                raise DiscoveryError("discovery_row_limit_exceeded", "Inventory exceeded its explicit row budget; narrow the cohort or raise the reviewed budget.")
            result.extend(values)
            if scope.startswith(FABRIC_ORIGIN):
                reference = body.get("continuationUri")
                token = body.get("continuationToken")
                if reference is None and token is not None:
                    if not isinstance(token, str) or not token:
                        raise DiscoveryError("discovery_invalid_continuation")
                    reference = first_url + "?" + urlencode({"continuationToken": token})
            else:
                reference = body.get("@odata.nextLink")
            if reference is None:
                return result
            if not isinstance(reference, str) or not reference:
                raise DiscoveryError("discovery_invalid_continuation")
        raise DiscoveryError("discovery_page_limit_exceeded", "Inventory exceeded its page budget; no complete inventory was produced.")


def discover_environment(*, tenant_id: str, dataverse_url: str, operator_upn: str,
                         credential, requested_tables: Mapping[str, Sequence[str]],
                         operator_entra_id: str | None = None, workspace_id: str | None = None,
                         environment_id: str | None = None, reader_upns: Sequence[str] | None = None,
                         transport: httpx.BaseTransport | None = None, max_pages: int = 20,
                         max_readers: int = 5000, max_workspaces: int = 100,
                         max_items: int = 200, max_tables: int = 3000, max_seconds: float = 300,
                         monotonic=time.monotonic) -> dict[str, Any]:
    """Discover candidates without selecting them or changing either service.

    With no requested tables, return only a bounded table metadata catalog.
    With requested tables and nonempty columns, inspect only those requested
    attributes (plus primary keys). An empty column list describes attribute
    candidates for that explicit table without selecting any. Reader candidates
    are not selected readers.
    An optional exact UPN cohort prevents an unbounded tenant-wide user scan.
    The Power Platform environment ID is recorded as unverified user input.
    """
    bound = BoundCredential(credential, tenant_id=tenant_id, dataverse_url=dataverse_url,
                            operator_upn=operator_upn, operator_entra_id=operator_entra_id)
    workspace_id = _guid(workspace_id) if workspace_id else None
    environment_id = _guid(environment_id) if environment_id else None
    max_pages = _limit(max_pages, "page", 1000)
    max_readers = _limit(max_readers, "reader", 50_000)
    max_workspaces = _limit(max_workspaces, "workspace", 10_000)
    max_items = _limit(max_items, "lakehouse", 10_000)
    max_tables = _limit(max_tables, "table", 10_000)
    if type(max_seconds) not in (int, float) or not math.isfinite(max_seconds) or not 1 <= max_seconds <= 3600:
        raise DiscoveryError("invalid_discovery_budget", "The time budget must be 1..3600 seconds.")
    if not isinstance(requested_tables, Mapping) or len(requested_tables) > max_tables:
        raise DiscoveryError("invalid_table_selection")
    selections = {}
    for name, columns in requested_tables.items():
        name = _name(name)
        if isinstance(columns, (str, bytes)) or not isinstance(columns, Sequence) or len(columns) > 500:
            raise DiscoveryError("invalid_column_selection")
        columns = [_name(c) for c in columns]
        if len(columns) != len(set(columns)):
            raise DiscoveryError("duplicate_column_selection")
        selections[name] = columns
    cohort = None
    if reader_upns is not None:
        if (isinstance(reader_upns, (str, bytes)) or not isinstance(reader_upns, Sequence)
                or not 1 <= len(reader_upns) <= 1000):
            raise DiscoveryError("invalid_reader_cohort")
        cohort = [_upn(n) for n in reader_upns]
        if len({n.casefold() for n in cohort}) != len(cohort):
            raise DiscoveryError("duplicate_reader_cohort")
    observed_at = datetime.now(timezone.utc).isoformat()
    session = _ReadOnlySession(bound, transport, max_seconds=max_seconds, max_pages=max_pages, monotonic=monotonic)
    source = None
    try:
        source_scope = bound.environment_url + "/.default"
        who = session.get(bound.environment_url + "/api/data/v9.2/WhoAmI", scope=source_scope)
        organization_id, caller_id = _guid(who.get("OrganizationId")), _guid(who.get("UserId"))
        # The source URL validator is reused only after OrganizationId has been
        # independently observed. No constructor defaults can choose a tenant.
        source = SourceProjectionClient(bound.environment_url, bound.tenant_id, organization_id,
                                        credential=bound, transport=transport, max_pages=max_pages, max_retries=0)

        def source_get(reference):
            return session.get(source._safe_url(reference), scope=source_scope)

        def source_collection(reference, max_rows):
            first = source._safe_url(reference)
            expected_path = urlsplit(first).path
            expected_query = parse_qs(urlsplit(first).query, keep_blank_values=True)

            def validate(value):
                url = source._safe_url(value)
                if urlsplit(url).path != expected_path:
                    raise DiscoveryError("discovery_collection_scope_changed")
                query = parse_qs(urlsplit(url).query, keep_blank_values=True)
                stable_query = {k: v for k, v in query.items() if k not in {"$skiptoken", "$skip"}}
                if stable_query != expected_query:
                    raise DiscoveryError("discovery_collection_query_changed")
                return url
            return session.collection(first, scope=source_scope, validator=validate, max_rows=max_rows)

        operator_fields = "systemuserid,azureactivedirectoryobjectid,domainname,isdisabled,applicationid"
        operator = source_get(f"systemusers({caller_id})?$select={operator_fields}")
        if (not set(operator_fields.split(",")) <= operator.keys()
                or _guid(operator.get("systemuserid")) != caller_id
                or _guid(operator.get("azureactivedirectoryobjectid")) != bound.operator_entra_id
                or operator.get("isdisabled") is not False or operator.get("applicationid") is not None
                or _upn(operator.get("domainname")).casefold() != bound.operator_upn.casefold()):
            raise DiscoveryError("source_operator_binding_mismatch", "Dataverse WhoAmI and systemuser do not bind to the expected enabled delegated operator.")
        fields = ("systemuserid,azureactivedirectoryobjectid,domainname,fullname,_businessunitid_value,"
                  "isdisabled,applicationid,accessmode")
        predicate = ("isdisabled eq false and applicationid eq null and azureactivedirectoryobjectid ne null"
                     " and (accessmode eq 0 or accessmode eq 2)")
        # Batches keep request URLs small, while every exact requested identity
        # must be returned once. An omitted/disabled/unhydrated user is an error.
        batches = [None] if cohort is None else [cohort[i:i + 20] for i in range(0, len(cohort), 20)]
        raw_readers = []
        for batch in batches:
            extra = ""
            if batch:
                extra = " and (" + " or ".join("domainname eq '" + n.replace("'", "''") + "'" for n in batch) + ")"
            raw_readers.extend(source_collection("systemusers?" + urlencode({"$select": fields,
                "$filter": predicate + extra, "$orderby": "systemuserid asc"}), max_readers))
            if len(raw_readers) > max_readers:
                raise DiscoveryError("discovery_row_limit_exceeded")
        readers, seen_dv, seen_entra, seen_upn = [], set(), set(), set()
        for row in raw_readers:
            if (not set(fields.split(",")) <= row.keys() or row.get("isdisabled") is not False
                    or row.get("applicationid") is not None or type(row.get("accessmode")) is not int
                    or row["accessmode"] not in (0, 2)):
                raise DiscoveryError("invalid_reader_inventory")
            dv, entra, upn = _guid(row.get("systemuserid")), _guid(row.get("azureactivedirectoryobjectid")), _upn(row.get("domainname"))
            if dv in seen_dv or entra in seen_entra or upn.casefold() in seen_upn:
                raise DiscoveryError("duplicate_reader_identity")
            seen_dv.add(dv); seen_entra.add(entra); seen_upn.add(upn.casefold())
            readers.append({"dataverse_id": dv, "entra_id": entra, "upn": upn,
                            "name": _text(row.get("fullname")), "business_unit_id": _guid(row.get("_businessunitid_value")),
                            "accessmode": row["accessmode"]})
        if cohort is not None and seen_upn != {n.casefold() for n in cohort}:
            raise DiscoveryError("reader_cohort_incomplete", "The exact requested reader cohort is not fully hydrated, eligible and visible to the operator.")

        metadata_fields = "LogicalName,PrimaryIdAttribute,EntitySetName,OwnershipType,Privileges"
        entities = ([source_get(f"EntityDefinitions(LogicalName='{n}')?$select={metadata_fields}") for n in selections]
                    if selections else source_collection("EntityDefinitions?$select=" + metadata_fields, max_tables))
        tables, seen_tables = [], set()
        for entity in entities:
            name = _name(entity.get("LogicalName"))
            if name in seen_tables or (selections and name not in selections):
                raise DiscoveryError("table_metadata_scope_mismatch")
            seen_tables.add(name)
            primary = _name(entity.get("PrimaryIdAttribute"))
            entity_set = _name(entity.get("EntitySetName"))
            privileges = entity.get("Privileges")
            if not isinstance(privileges, list) or any(not isinstance(p, dict) for p in privileges):
                raise DiscoveryError("read_privilege_metadata_unavailable")
            read_privileges = [p for p in privileges if p.get("PrivilegeType") in ("Read", 2)]
            read_ids = {_guid(p.get("PrivilegeId")) for p in read_privileges}
            if selections and len(read_ids) != 1:
                raise DiscoveryError("selected_read_privilege_unmapped")
            table = {"name": name, "primary_key": primary, "entity_set": entity_set,
                     "ownership_type": _text(entity.get("OwnershipType")),
                     "read_privilege_id": next(iter(read_ids)) if len(read_ids) == 1 else None,
                     "read_privileges": [{k: p[k] for k in ("PrivilegeId", "Name", "CanBeBasic", "CanBeLocal", "CanBeDeep", "CanBeGlobal") if k in p}
                                         for p in read_privileges], "attributes_verified": False}
            if selections and not selections[name]:
                candidates = source_collection(f"EntityDefinitions(LogicalName='{name}')/Attributes"
                    "?$select=LogicalName,AttributeType,AttributeTypeName,IsSecured,IsValidForRead", 5000)
                candidate_names, candidate_attributes = set(), []
                for attribute in candidates:
                    column = _name(attribute.get("LogicalName"))
                    if column in candidate_names:
                        raise DiscoveryError("duplicate_attribute_metadata")
                    candidate_names.add(column)
                    kind = attribute.get("AttributeType")
                    if kind == "Virtual" and isinstance(attribute.get("AttributeTypeName"), dict) and attribute["AttributeTypeName"].get("Value") == "MultiSelectPicklistType":
                        kind = "MultiSelectPicklist"
                    readable, secured = attribute.get("IsValidForRead"), attribute.get("IsSecured")
                    candidate_attributes.append({"logical_name": column,
                        "property_name": f"_{column}_value" if kind in {"Lookup", "Owner", "Customer"} else column,
                        "attribute_type": _text(kind, nullable=True),
                        "is_valid_for_read": readable if type(readable) is bool else None,
                        "is_secured": secured if type(secured) is bool else None,
                        "supported_scalar": (kind in _SCALAR_TYPES or kind == "MultiSelectPicklist")
                            and readable is True and type(secured) is bool})
                table["attribute_candidates"] = sorted(candidate_attributes, key=lambda a: a["logical_name"])
            elif selections:
                requested = [c[1:-6] if c.startswith("_") and c.endswith("_value") else c for c in selections[name]]
                if len(requested) != len(set(requested)):
                    raise DiscoveryError("duplicate_column_alias")
                if primary not in requested:
                    requested.insert(0, primary)
                attributes = []
                for column in requested:
                    attribute = source_get(f"EntityDefinitions(LogicalName='{name}')/Attributes(LogicalName='{column}')"
                        "?$select=LogicalName,AttributeType,AttributeTypeName,IsSecured,IsValidForRead")
                    if (attribute.get("LogicalName") != column or attribute.get("IsValidForRead") is not True
                            or type(attribute.get("IsSecured")) is not bool):
                        raise DiscoveryError("selected_attribute_unverified")
                    kind = attribute.get("AttributeType")
                    if kind == "Virtual" and isinstance(attribute.get("AttributeTypeName"), dict) and attribute["AttributeTypeName"].get("Value") == "MultiSelectPicklistType":
                        kind = "MultiSelectPicklist"
                    elif kind not in _SCALAR_TYPES:
                        raise DiscoveryError("selected_attribute_unsupported")
                    attributes.append({"logical_name": column, "property_name": f"_{column}_value" if kind in {"Lookup", "Owner", "Customer"} else column,
                                       "attribute_type": kind, "is_secured": attribute["IsSecured"]})
                masking = source_collection("attributemaskingrules?" + urlencode({
                    "$select": "entityname,attributelogicalname,_maskingruleid_value", "$filter": f"entityname eq '{name}'"}), 5000)
                masked = set()
                for row in masking:
                    if row.get("entityname") != name:
                        raise DiscoveryError("masking_scope_mismatch")
                    masked.add(_name(row.get("attributelogicalname")))
                    _guid(row.get("_maskingruleid_value"))
                for attribute in attributes:
                    attribute["is_masked"] = attribute["logical_name"] in masked
                table.update({"attributes_verified": True, "attributes": attributes,
                              "columns": [a["property_name"] for a in attributes]})
            tables.append(table)
        if selections and seen_tables != set(selections):
            raise DiscoveryError("table_metadata_scope_mismatch")

        def fabric_collection(path, max_rows):
            first = FABRIC_ROOT + path
            expected_path = urlsplit(first).path
            def validate(value):
                try:
                    parsed = urlsplit(value)
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    if (parsed.scheme != "https" or parsed.hostname != "api.fabric.microsoft.com"
                            or parsed.port not in (None, 443) or parsed.username or parsed.password
                            or parsed.path != expected_path or parsed.fragment or "\\" in value
                            or any(ord(c) < 32 for c in value) or len(value) > 32768
                            or (query and (set(query) != {"continuationToken"}
                                or len(query["continuationToken"]) != 1 or not query["continuationToken"][0]))):
                        raise ValueError
                    return value
                except (ValueError, TypeError, AttributeError):
                    raise DiscoveryError("unsafe_fabric_continuation", "Fabric continuation escaped the exact requested collection.") from None
            return session.collection(first, scope=FABRIC_ORIGIN + "/.default", validator=validate, max_rows=max_rows)

        raw_workspaces = fabric_collection("/workspaces", max_workspaces)
        workspaces, seen_workspace = [], set()
        for row in raw_workspaces:
            identifier = _guid(row.get("id"))
            if identifier in seen_workspace:
                raise DiscoveryError("duplicate_workspace")
            seen_workspace.add(identifier)
            workspaces.append({"id": identifier, "name": _text(row.get("displayName")),
                               "type": _text(row.get("type")),
                               "capacity_id": _guid(row["capacityId"]) if row.get("capacityId") else None})
        selected = None
        lakehouses = []
        if workspace_id:
            selected = next((w for w in workspaces if w["id"] == workspace_id), None)
            if selected is None:
                raise DiscoveryError("workspace_not_visible", "The explicitly requested workspace was not returned for this operator.")
            seen_items = set()
            for row in fabric_collection(f"/workspaces/{workspace_id}/lakehouses", max_items):
                identifier = _guid(row.get("id"))
                if identifier in seen_items or _guid(row.get("workspaceId")) != workspace_id or row.get("type") != "Lakehouse":
                    raise DiscoveryError("lakehouse_scope_mismatch")
                seen_items.add(identifier)
                properties = row.get("properties")
                if not isinstance(properties, dict):
                    raise DiscoveryError("lakehouse_properties_unavailable")
                sql = properties.get("sqlEndpointProperties")
                endpoint = None
                if sql is not None:
                    if not isinstance(sql, dict):
                        raise DiscoveryError("sql_endpoint_properties_invalid")
                    server = sql.get("connectionString")
                    if server is not None and (not isinstance(server, str)
                            or not re.fullmatch(r"[a-zA-Z0-9-]+\.datawarehouse\.fabric\.microsoft\.com", server)):
                        raise DiscoveryError("unsupported_sql_connection_format", "SQL discovery accepts a public-cloud server hostname only, never credentials or arbitrary connection strings.")
                    endpoint = {"id": _guid(sql["id"]) if sql.get("id") else None, "server": server,
                                "provisioning_status": _text(sql.get("provisioningStatus"), nullable=True)}
                lakehouses.append({"id": identifier, "name": _text(row.get("displayName")), "workspace_id": workspace_id,
                                   "default_schema": _name(properties["defaultSchema"]) if properties.get("defaultSchema") else None,
                                   "sql_endpoint": endpoint})
        return {"schema_version": 1, "observed_at": observed_at,
                "completed_at": datetime.now(timezone.utc).isoformat(), "cloud": "public",
                "tenant_id": bound.tenant_id, "environment_url": bound.environment_url, "organization_id": organization_id,
                "operator": {"entra_id": bound.operator_entra_id, "upn": bound.operator_upn, "dataverse_id": caller_id},
                "environment_id": {"value": environment_id, "verified": False,
                                   "source": "user_supplied" if environment_id else "not_supplied"},
                "readers": sorted(readers, key=lambda r: r["upn"].casefold()),
                "tables": sorted(tables, key=lambda t: t["name"]), "workspaces": workspaces,
                "selected_workspace": selected, "lakehouses": lakehouses,
                "discovery": {"remote_methods": ["GET"], "requests": session.requests, "business_records_read": False,
                              "reader_candidates_are_selected": False, "publication_boundary_verified": False,
                              "operator_permissions_verified": False, "power_platform_environment_id_verified": False,
                              "table_scope": "explicit_selection" if selections else "metadata_catalog_only",
                              "reader_scope": "explicit_upn_cohort" if cohort else "eligible_candidate_inventory",
                              "budgets": {"max_pages": max_pages, "max_readers": max_readers, "max_tables": max_tables,
                                          "max_workspaces": max_workspaces, "max_items": max_items, "max_seconds": max_seconds}}}
    except DataverseError as exc:
        raise DiscoveryError(exc.code, "Dataverse discovery refused an incomplete or untrusted response.", exc.status) from None
    finally:
        session.client.close()
        if source is not None:
            source.close()
