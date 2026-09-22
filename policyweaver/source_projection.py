"""Authoritative, GET-only Dataverse reader projections.

Dataverse evaluates record and field authorization under CallerObjectId. This
module deliberately does not reconstruct POA, hierarchy, teams, or field rules.
Its output is an observation, not a transactional security snapshot: a publisher
must stage the entire scan and enforce a freshness deadline before activation.

The operator needs directly assigned impersonation permission and sufficient
source read/field privileges. Impersonation can be limited by the operator's
privileges; qualification against real reader sessions remains necessary.
"""

from __future__ import annotations

from copy import deepcopy
import math
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Iterable, Iterator
from urllib.parse import quote, unquote, urlsplit
from uuid import UUID, uuid4

import httpx

from .dataverse import DataverseClient, DataverseError, TokenCredential


class SourceProjectionError(DataverseError):
    """Safe error code and status; no records, credentials, or server bodies."""


def _guid(value: Any) -> str:
    try:
        parsed = UUID(str(value))
        if parsed.int == 0:
            raise ValueError
        return str(parsed)
    except (ValueError, AttributeError, TypeError):
        raise SourceProjectionError("invalid_guid", "A required nonzero identifier is invalid.") from None


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,127}", value):
        raise SourceProjectionError("invalid_identifier", "A source table or column identifier is invalid.")
    return value


@dataclass(frozen=True)
class SourceReader:
    dataverse_id: str
    entra_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "dataverse_id", _guid(self.dataverse_id))
        object.__setattr__(self, "entra_id", _guid(self.entra_id))


@dataclass(frozen=True)
class SourceAttribute:
    logical_name: str
    property_name: str
    attribute_type: str
    is_secured: bool
    is_masked: bool | None = None


@dataclass(frozen=True)
class SourceTable:
    name: str
    entity_set: str
    primary_key: str
    columns: tuple[str, ...]
    attributes: tuple[SourceAttribute, ...] = ()
    read_privilege_id: str | None = None

    def __post_init__(self) -> None:
        for value in (self.name, self.entity_set, self.primary_key, *self.columns):
            _identifier(value)
        if not self.columns or len(set(self.columns)) != len(self.columns) or self.primary_key not in self.columns:
            raise SourceProjectionError("invalid_projection", "Projection must include a unique primary key and unique columns.")
        object.__setattr__(self, "columns", tuple(self.columns))
        object.__setattr__(self, "attributes", tuple(self.attributes))
        if self.read_privilege_id is not None:
            object.__setattr__(self, "read_privilege_id", _guid(self.read_privilege_id))


@dataclass(frozen=True)
class SourceScan:
    """One freshly gated reader/table result and its single-use row iterator.

    The gate is not cached or accepted as an input to another scan. Consumers
    must exhaust rows successfully before using this result for publication.
    """

    has_read: bool
    rows: Iterator[dict[str, Any]]


_SCALAR_TYPES = frozenset({
    "Boolean", "DateTime", "Decimal", "Double", "Integer", "BigInt", "Memo",
    "Money", "String", "Uniqueidentifier", "Lookup", "Owner", "Customer",
    "Picklist", "State", "Status", "EntityName",
})
_LOOKUP_TYPES = frozenset({"Lookup", "Owner", "Customer"})
# Built-in immutable RoleTemplate identity, not a localized role display name.
SYSTEM_ADMINISTRATOR_TEMPLATE = "627090ff-40a3-4053-8790-584edc5be201"


class SourceProjectionClient(DataverseClient):
    """Sequential client with bounded retries, pages, rows, and scan duration.

    Credentials remain in memory and are acquired for every HTTP attempt. No
    response body is included in diagnostics. Do not share one instance between
    concurrent workers; use separately budgeted clients for bounded concurrency.
    """

    def __init__(
        self, environment_url: str, tenant_id: str, organization_id: str,
        credential: TokenCredential | None = None,
        transport: httpx.BaseTransport | None = None, *,
        max_rows_per_scan: int = 10_000_000,
        max_scan_seconds: float = 1800,
        monotonic: Callable[[], float] = time.monotonic,
        identity_verification: str = "fetchxml",
        identity_api_name: str = "pw_ReadContext",
        identity_api_assembly_sha256: str | None = None,
        **kwargs: Any,
    ):
        if identity_verification not in ("fetchxml", "custom_api"):
            raise ValueError("Identity verification must be fetchxml or custom_api.")
        self.identity_verification = identity_verification
        self.identity_api_name = _identifier(identity_api_name)
        if (identity_api_assembly_sha256 is not None
                and (not isinstance(identity_api_assembly_sha256, str)
                     or not re.fullmatch(r"[0-9a-f]{64}", identity_api_assembly_sha256))):
            raise ValueError("Custom API assembly SHA-256 must be a lowercase hexadecimal digest.")
        if identity_verification == "custom_api" and identity_api_assembly_sha256 is None:
            raise ValueError("Custom API identity verification requires a trusted assembly SHA-256 digest.")
        self.identity_api_assembly_sha256 = identity_api_assembly_sha256
        self._identity_registration: dict[str, Any] | None = None
        super().__init__(environment_url, tenant_id, organization_id, credential, transport, **kwargs)
        if (isinstance(max_rows_per_scan, bool) or not isinstance(max_rows_per_scan, int)
                or max_rows_per_scan < 1 or not math.isfinite(max_scan_seconds) or max_scan_seconds <= 0):
            self.close()
            raise ValueError("Source row and duration budgets must be positive and finite.")
        self.max_rows_per_scan = max_rows_per_scan
        self.max_scan_seconds = max_scan_seconds
        self._monotonic = monotonic
        self._environment: dict[str, str] | None = None
        self._metrics = {"requests": 0, "retries": 0, "completed_scans": 0, "completed_rows": 0}

    @property
    def metrics(self) -> dict[str, int]:
        return dict(self._metrics)

    def _check_deadline(self, deadline: float | None) -> None:
        if deadline is not None and self._monotonic() >= deadline:
            raise SourceProjectionError("scan_deadline_exceeded", "Source scan exceeded its freshness budget.")

    def _request(
        self, reference: str, reader: SourceReader | None = None,
        *, deadline: float | None = None, page_preference: bool = True,
    ) -> dict[str, Any]:
        # The inherited URL validator rejects cross-origin, traversal, redirects,
        # encoded separators, userinfo, non-HTTPS and non-API continuations.
        url = self._safe_url(reference)
        if len(url) > 32_768:
            raise SourceProjectionError("request_too_long", "Source projection exceeds the supported GET URL budget.")
        for attempt in range(self.max_retries + 1):
            self._check_deadline(deadline)
            try:
                token = self.credential.get_token(self.environment_url + "/.default")
            except Exception:
                raise SourceProjectionError("authentication_failed", "Dataverse token acquisition failed.") from None
            headers = {"Authorization": "Bearer " + token.token, "Consistency": "Strong"}
            if reader is not None:
                headers["CallerObjectId"] = reader.entra_id
            response = None
            try:
                self._metrics["requests"] += 1
                if page_preference:
                    response = self._client.get(url, headers=headers)
                else:
                    # Some composable Dataverse functions reject even a page
                    # size preference. Remove only this request's header, never
                    # mutate the shared client's ordinary collection settings.
                    request = self._client.build_request("GET", url, headers=headers)
                    request.headers.pop("Prefer", None)
                    response = self._client.send(request)
            except httpx.TransportError:
                if attempt == self.max_retries:
                    raise SourceProjectionError("transport_failed", "Dataverse request failed after bounded retries.") from None
            self._check_deadline(deadline)
            retry = response is None or response.status_code == 429 or 500 <= response.status_code <= 599
            if retry and attempt < self.max_retries:
                delay = self._retry_delay(response, attempt)
                if deadline is not None and self._monotonic() + delay >= deadline:
                    raise SourceProjectionError("scan_deadline_exceeded", "Source retry would exceed the freshness budget.")
                self._metrics["retries"] += 1
                self._sleep(delay)
                continue
            if response is None:
                raise SourceProjectionError("transport_failed", "Dataverse request failed after bounded retries.")
            if response.status_code != 200:
                code = "redirect_refused" if 300 <= response.status_code < 400 else "http_error"
                raise SourceProjectionError(code, f"Dataverse returned HTTP {response.status_code}; projection is incomplete.", response.status_code)
            try:
                def invalid_constant(_: str) -> None:
                    raise ValueError("Non-finite JSON number")
                payload = response.json(parse_float=Decimal, parse_constant=invalid_constant)
            except ValueError:
                raise SourceProjectionError("invalid_json", "Dataverse returned invalid JSON.") from None
            if not isinstance(payload, dict):
                raise SourceProjectionError("invalid_payload", "Dataverse response must be an object.")
            return payload
        raise AssertionError("Retry loop must return or raise.")

    def _collection(
        self, reference: str, reader: SourceReader | None = None, *,
        value_key: str = "value", deadline: float | None = None, page_preference: bool = True,
    ) -> Iterator[dict[str, Any]]:
        expected_path = unquote(urlsplit(self._safe_url(reference)).path)
        seen_urls: set[str] = set()
        for _ in range(self.max_pages):
            url = self._safe_url(reference)
            if unquote(urlsplit(url).path) != expected_path:
                raise SourceProjectionError("collection_scope_changed", "Continuation changed the source collection.")
            if url in seen_urls:
                raise SourceProjectionError("pagination_cycle", "Source collection repeated a continuation URL.")
            seen_urls.add(url)
            payload = self._request(url, reader, deadline=deadline,
                                    **({"page_preference": False} if not page_preference else {}))
            values = payload.get(value_key)
            if not isinstance(values, list) or any(not isinstance(v, dict) for v in values):
                raise SourceProjectionError("invalid_collection", "Source response lacks a valid row collection.")
            yield from values
            next_link = payload.get("@odata.nextLink", payload.get(value_key + "@odata.nextLink"))
            if next_link is None:
                return
            if not isinstance(next_link, str) or not next_link:
                raise SourceProjectionError("invalid_continuation", "Source continuation is malformed.")
            reference = next_link
        raise SourceProjectionError("page_limit_exceeded", "Source collection exceeded its page budget.")

    def verify_environment(self) -> dict[str, str]:
        if self._environment is None:
            who = self._request("WhoAmI")
            if _guid(who.get("OrganizationId")) != self.expected_organization_id:
                raise SourceProjectionError("organization_mismatch", "Dataverse organization does not match configuration.")
            self._environment = {
                "organization_id": self.expected_organization_id,
                "caller_user_id": _guid(who.get("UserId")),
            }
        return dict(self._environment)

    def discover_readers(self) -> list[dict[str, Any]]:
        self.verify_environment()
        reference = (
            "systemusers?$select=systemuserid,azureactivedirectoryobjectid,isdisabled,applicationid,accessmode"
            "&$filter=isdisabled eq false and applicationid eq null and azureactivedirectoryobjectid ne null"
            " and (accessmode eq 0 or accessmode eq 2)"
            "&$orderby=systemuserid asc"
        )
        readers: list[dict[str, Any]] = []
        seen_dv, seen_entra = set(), set()
        for row in self._collection(reference):
            if (row.get("isdisabled") is not False or row.get("applicationid") is not None
                    or type(row.get("accessmode")) is not int or row["accessmode"] not in (0, 2)):
                raise SourceProjectionError("invalid_reader_inventory", "Reader discovery returned an ineligible identity.")
            reader = SourceReader(row.get("systemuserid"), row.get("azureactivedirectoryobjectid"))
            if reader.dataverse_id in seen_dv or reader.entra_id in seen_entra:
                raise SourceProjectionError("duplicate_reader", "Reader identity mapping is not unique.")
            seen_dv.add(reader.dataverse_id)
            seen_entra.add(reader.entra_id)
            readers.append({"dataverse_id": reader.dataverse_id, "entra_id": reader.entra_id, "accessmode": row.get("accessmode")})
        return readers

    def verify_reader_binding(self, reader: SourceReader) -> dict[str, Any]:
        """Verify the current principal administratively before a privilege gate.

        A newly hydrated or fully unroled user cannot execute even the identity
        FetchXML query. An absent table privilege can still be established by
        the operator, but only after binding both immutable IDs and checking the
        user's current eligibility. This is not proof of an execution context.
        """
        self.verify_environment()
        fields = ("systemuserid", "azureactivedirectoryobjectid", "isdisabled",
                  "applicationid", "accessmode")
        row = self._request(f"systemusers({reader.dataverse_id})?$select={','.join(fields)}")
        if not set(fields) <= row.keys() or "@odata.nextLink" in row or "value" in row:
            raise SourceProjectionError("reader_binding_unverified", "Complete administrative reader identity is required.")
        if (_guid(row["systemuserid"]) != reader.dataverse_id
                or _guid(row["azureactivedirectoryobjectid"]) != reader.entra_id
                or row["isdisabled"] is not False or row["applicationid"] is not None
                or type(row["accessmode"]) is not int or row["accessmode"] not in (0, 2)):
            raise SourceProjectionError("reader_binding_mismatch", "Administrative reader identity is not the expected eligible human.")
        return {"verified": True, "method": "Administrative immutable identity binding"}

    def reader_role_labels(
        self, readers: Iterable[SourceReader], *, deadline_check: Callable[[], None] = lambda: None,
    ) -> dict[str, dict[str, Any]]:
        """Collect complete, read-only naming provenance, never permissions.

        Associations explain direct and observed team origins; the composable
        RetrieveAadUserRoles function additionally includes roles from Entra
        group teams. Unresolved origins are recorded explicitly rather than
        invented. These sequential observations are not an atomic snapshot and
        do not replace the fresh privilege/identity gates used by open_scan.
        """
        self.verify_environment()
        readers = tuple(readers)
        if (not readers or len(readers) > 1000
                or len({r.entra_id for r in readers}) != len(readers)
                or len({r.dataverse_id for r in readers}) != len(readers)):
            raise SourceProjectionError("invalid_label_audience", "Naming provenance requires a unique bounded audience.")
        deadline = self._monotonic() + self.max_scan_seconds
        units: dict[str, dict[str, str]] = {}
        team_roles: dict[str, list[dict[str, Any]]] = {}
        teams: dict[str, dict[str, Any]] = {}
        role_instances: dict[str, dict[str, Any]] = {}
        result: dict[str, dict[str, Any]] = {}
        role_fields = "roleid,name,_parentrootroleid_value,_businessunitid_value"

        def text(value, *, optional=False):
            if optional and value is None:
                return None
            if (not isinstance(value, str) or not value.strip() or len(value) > 2000
                    or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                raise SourceProjectionError("invalid_role_label", "Source naming metadata is incomplete or malformed.")
            return value

        def get(reference):
            deadline_check()
            return self._request(reference, deadline=deadline)

        def collect(reference, *, page_preference=True):
            deadline_check()
            return self._collection(reference, deadline=deadline, page_preference=page_preference)

        def unit(identifier):
            identifier = _guid(identifier)
            if identifier not in units:
                row = get(f"businessunits({identifier})?$select=businessunitid,name")
                if _guid(row.get("businessunitid")) != identifier:
                    raise SourceProjectionError("role_label_scope_mismatch", "Naming metadata returned a different business unit.")
                units[identifier] = {"id": identifier, "name": text(row.get("name"))}
            return dict(units[identifier])

        def role(row):
            required = {"roleid", "name", "_parentrootroleid_value", "_businessunitid_value"}
            if not required <= row.keys():
                raise SourceProjectionError("invalid_role_label", "Role naming metadata is incomplete.")
            identifier = _guid(row["roleid"])
            value = {"role_id": identifier, "name": text(row["name"]),
                     "root_role_id": _guid(row["_parentrootroleid_value"] or identifier),
                     "business_unit": unit(row["_businessunitid_value"])}
            if identifier in role_instances and value != role_instances[identifier]:
                raise SourceProjectionError("role_label_changed_during_scan", "Role naming metadata changed during collection.")
            role_instances[identifier] = value
            return deepcopy(value)

        for reader in sorted(readers, key=lambda r: r.entra_id):
            deadline_check()
            fields = ("systemuserid,azureactivedirectoryobjectid,isdisabled,applicationid,accessmode,"
                      "fullname,domainname,_businessunitid_value")
            row = get(f"systemusers({reader.dataverse_id})?$select={fields}")
            if not set(fields.split(",")) <= row.keys():
                raise SourceProjectionError("invalid_reader_label", "Reader naming metadata is incomplete.")
            if (_guid(row["systemuserid"]) != reader.dataverse_id
                    or _guid(row["azureactivedirectoryobjectid"]) != reader.entra_id
                    or row["isdisabled"] is not False or row["applicationid"] is not None
                    or type(row["accessmode"]) is not int or row["accessmode"] not in (0, 2)):
                raise SourceProjectionError("reader_binding_mismatch", "Naming metadata does not match the expected enabled human.")
            display_name = text(row["fullname"])
            domain = text(row["domainname"], optional=True)
            alias = domain.rsplit("\\", 1)[-1].split("@", 1)[0] if domain else display_name
            effective: dict[str, dict[str, Any]] = {}
            member_teams: list[dict[str, Any]] = []

            def add_role(value, origin):
                item = effective.setdefault(value["role_id"], {**deepcopy(value), "origins": []})
                if origin not in item["origins"]:
                    item["origins"].append(deepcopy(origin))

            for assigned in collect(f"systemusers({reader.dataverse_id})/systemuserroles_association?$select={role_fields}"):
                add_role(role(assigned), {"kind": "direct", "principal_id": reader.dataverse_id})
            for team in collect(f"systemusers({reader.dataverse_id})/teammembership_association"
                                "?$select=teamid,name,teamtype,_businessunitid_value"):
                team_id = _guid(team.get("teamid"))
                if type(team.get("teamtype")) is not int or team["teamtype"] not in (0, 1, 2, 3):
                    raise SourceProjectionError("invalid_team_label", "Team naming metadata has an unsupported type.")
                info = {"id": team_id, "name": text(team.get("name")), "team_type": team["teamtype"],
                        "business_unit": unit(team.get("_businessunitid_value"))}
                if team_id in teams and info != teams[team_id]:
                    raise SourceProjectionError("team_label_changed_during_scan", "Team naming metadata changed during collection.")
                teams[team_id] = info
                if info not in member_teams:
                    member_teams.append(deepcopy(info))
                if team_id not in team_roles:
                    team_roles[team_id] = [role(r) for r in collect(
                        f"teams({team_id})/teamroles_association?$select={role_fields}")]
                for assigned in team_roles[team_id]:
                    add_role(assigned, {"kind": "team", "principal_id": team_id, "team": info})
            # This function covers effective Entra group roles beyond explicit
            # teammembership rows. Its returned role identity is retained even
            # where the source does not expose a matching association origin.
            # Use the function's documented projection, then resolve role rows;
            # never infer their BU from the reader or suppress a failed read.
            # This function rejects Prefer: odata.maxpagesize, so suppress that
            # header for this call while preserving ordinary collection paging.
            for assigned in collect(f"RetrieveAadUserRoles(DirectoryObjectId={reader.entra_id})"
                                    "?$select=roleid,name,_parentrootroleid_value", page_preference=False):
                if not {"roleid", "name", "_parentrootroleid_value"} <= assigned.keys():
                    raise SourceProjectionError("invalid_role_label", "Effective role naming metadata is incomplete.")
                role_id = _guid(assigned["roleid"])
                value = deepcopy(role_instances[role_id]) if role_id in role_instances else role(
                    get(f"roles({role_id})?$select={role_fields}"))
                if (value["role_id"] != role_id or value["name"] != text(assigned["name"])
                        or value["root_role_id"] != _guid(assigned["_parentrootroleid_value"] or role_id)):
                    raise SourceProjectionError("role_label_changed_during_scan", "Effective role metadata does not match its role row.")
                origin = {"kind": "effective_role_function", "principal_id": reader.dataverse_id,
                          "function": "RetrieveAadUserRoles"}
                if assigned.get("t_x002e_teamid") is not None:
                    team_id = _guid(assigned["t_x002e_teamid"])
                    if team_id not in teams:
                        team = get(f"teams({team_id})?$select=teamid,name,teamtype,_businessunitid_value")
                        if (_guid(team.get("teamid")) != team_id or type(team.get("teamtype")) is not int
                                or team["teamtype"] not in (0, 1, 2, 3)):
                            raise SourceProjectionError("invalid_team_label", "Effective role team metadata is invalid.")
                        teams[team_id] = {"id": team_id, "name": text(team.get("name")),
                            "team_type": team["teamtype"], "business_unit": unit(team.get("_businessunitid_value"))}
                    origin["team"] = deepcopy(teams[team_id])
                    if teams[team_id] not in member_teams:
                        member_teams.append(deepcopy(teams[team_id]))
                add_role(value, origin)
            for value in effective.values():
                value["origins"].sort(key=lambda o: (o["kind"], o["principal_id"]))
            result[reader.entra_id] = {
                "schema_version": 1, "dataverse_id": reader.dataverse_id, "entra_id": reader.entra_id,
                "alias": alias, "display_name": display_name,
                "business_unit": unit(row["_businessunitid_value"]),
                "effective_roles": sorted(effective.values(), key=lambda r: (r["root_role_id"], r["role_id"])),
                "teams": sorted(member_teams, key=lambda t: t["id"]),
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "provenance_scope": "direct and observed team associations plus RetrieveAadUserRoles; not an authorization snapshot",
            }
        deadline_check()
        return result

    def verify_identity(self, reader: SourceReader) -> dict[str, Any]:
        self.verify_environment()
        if self.identity_verification == "custom_api":
            if self._identity_registration is None:
                from .read_context_deployment import verify_read_context_registration
                self._identity_registration = verify_read_context_registration(
                    self, api_name=self.identity_api_name,
                    assembly_sha256=self.identity_api_assembly_sha256)
            # The separately deployed read-only plug-in returns its execution
            # context without retrieving a systemuser row as the reader. A fresh
            # challenge prevents a cached or replayed identity response passing.
            nonce = str(uuid4())
            proof = self._request(f"{self.identity_api_name}(Nonce={nonce})", reader)
            required = {"UserId", "OrganizationId", "Nonce", "ProtocolVersion"}
            if (not required <= proof.keys() or "@odata.nextLink" in proof
                    or type(proof.get("ProtocolVersion")) is not str or proof["ProtocolVersion"] != "1"):
                raise SourceProjectionError("identity_proof_unverified", "Custom API returned an incomplete or unsupported identity proof.")
            if (_guid(proof["UserId"]) != reader.dataverse_id
                    or _guid(proof["OrganizationId"]) != self.expected_organization_id
                    or _guid(proof["Nonce"]) != nonce):
                raise SourceProjectionError("identity_proof_mismatch", "Custom API proof does not match the challenged reader and organization.")
            self.verify_reader_binding(reader)
            return {"verified": True, "method": "Custom API " + self.identity_api_name,
                    "verified_at": datetime.now(timezone.utc).isoformat()}
        # WhoAmI can report the operator even when data queries are impersonated.
        # eq-userid is evaluated in the actual RetrieveMultiple execution context.
        fetch = (
            "<fetch top='2'><entity name='systemuser'><attribute name='systemuserid'/>"
            "<attribute name='azureactivedirectoryobjectid'/><attribute name='isdisabled'/>"
            "<attribute name='applicationid'/><attribute name='accessmode'/><filter><condition attribute='systemuserid' "
            "operator='eq-userid'/></filter></entity></fetch>"
        )
        payload = self._request("systemusers?fetchXml=" + quote(fetch, safe=""), reader)
        values = payload.get("value")
        if (not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict)
                or "@odata.nextLink" in payload):
            raise SourceProjectionError("impersonation_unverified", "Reader execution context could not be verified.")
        row = values[0]
        if (_guid(row.get("systemuserid")) != reader.dataverse_id
                or _guid(row.get("azureactivedirectoryobjectid")) != reader.entra_id
                or row.get("isdisabled") is not False or row.get("applicationid") is not None
                or type(row.get("accessmode")) is not int or row["accessmode"] not in (0, 2)):
            raise SourceProjectionError("impersonation_mismatch", "Reader execution context does not match the enabled human identity.")
        return {"verified": True, "method": "FetchXML eq-userid", "verified_at": datetime.now(timezone.utc).isoformat()}

    def table_metadata(self, name: str, columns: Iterable[str] | None = None) -> SourceTable:
        self.verify_environment()
        name = _identifier(name)
        path = f"EntityDefinitions(LogicalName='{name}')"
        entity = self._request(path + "?$select=LogicalName,EntitySetName,PrimaryIdAttribute,Privileges")
        if entity.get("LogicalName") != name:
            raise SourceProjectionError("metadata_mismatch", "Source table metadata does not match the requested table.")
        entity_set = _identifier(entity.get("EntitySetName"))
        primary_key = _identifier(entity.get("PrimaryIdAttribute"))
        privileges = entity.get("Privileges")
        if not isinstance(privileges, list) or any(not isinstance(p, dict) for p in privileges):
            raise SourceProjectionError("read_privilege_unmapped", "Source metadata does not include read privileges.")
        read_ids = {_guid(p.get("PrivilegeId")) for p in privileges if p.get("PrivilegeType") in ("Read", 2)}
        if len(read_ids) != 1:
            raise SourceProjectionError("read_privilege_unmapped", "Source table requires exactly one authoritative read privilege mapping.")
        raw = list(self._collection(path + "/Attributes?$select=LogicalName,IsSecured,IsValidForRead,AttributeType,AttributeTypeName"))
        masking_columns = self.discover_masking_rules(name)
        attribute_map: dict[str, dict[str, Any]] = {}
        aliases: dict[str, str] = {}
        for a in raw:
            logical = _identifier(a.get("LogicalName"))
            if logical in attribute_map:
                raise SourceProjectionError("duplicate_attribute", "Source attribute metadata contains duplicates.")
            attribute_map[logical] = a
            prop = f"_{logical}_value" if a.get("AttributeType") in _LOOKUP_TYPES else logical
            aliases[prop] = logical
        if columns is None:
            selected = [n for n, a in attribute_map.items() if a.get("IsValidForRead") is True]
        else:
            if isinstance(columns, (str, bytes)):
                raise SourceProjectionError("invalid_projection", "Projection columns must be a collection of identifiers.")
            selected = [_identifier(c) for c in columns]
            if not selected or len(set(selected)) != len(selected):
                raise SourceProjectionError("invalid_projection", "Projection columns must be nonempty and unique.")
        selected = [aliases.get(c, c) for c in selected]
        if primary_key not in selected:
            selected.insert(0, primary_key)
        attributes: list[SourceAttribute] = []
        seen_props: set[str] = set()
        for logical in selected:
            a = attribute_map.get(logical)
            if a is None or a.get("IsValidForRead") is not True or not isinstance(a.get("IsSecured"), bool):
                raise SourceProjectionError("unreadable_attribute", "A selected attribute is unknown, unreadable, or lacks security metadata.")
            kind = a.get("AttributeType")
            type_name = a.get("AttributeTypeName")
            if kind == "Virtual" and isinstance(type_name, dict) and type_name.get("Value") == "MultiSelectPicklistType":
                kind = "MultiSelectPicklist"
            elif kind not in _SCALAR_TYPES:
                raise SourceProjectionError("unsupported_attribute", "A selected attribute requires an unsupported binary, complex, or special projection.")
            prop = f"_{logical}_value" if kind in _LOOKUP_TYPES else logical
            if prop in seen_props:
                raise SourceProjectionError("invalid_projection", "Projection repeats a logical column through multiple aliases.")
            seen_props.add(prop)
            attributes.append(SourceAttribute(logical, prop, kind, a["IsSecured"], logical in masking_columns))
        return SourceTable(name, entity_set, primary_key, tuple(a.property_name for a in attributes), tuple(attributes), next(iter(read_ids)))

    def discover_masking_rules(self, name: str) -> set[str]:
        """Return configured masking columns; unavailable metadata is an error.

        A mapping identifies configured masking, not the result for a particular
        reader. The impersonated data response remains authoritative. Neither
        this method nor iter_rows requests the UnMaskedData optional parameter.
        """
        self.verify_environment()
        name = _identifier(name)
        path = (
            "attributemaskingrules?$select=entityname,attributelogicalname,_maskingruleid_value"
            f"&$filter=entityname eq '{name}'"
        )
        columns: set[str] = set()
        for row in self._collection(path):
            if row.get("entityname") != name:
                raise SourceProjectionError("masking_scope_changed", "Masking metadata changed the requested source table.")
            column = _identifier(row.get("attributelogicalname"))
            _guid(row.get("_maskingruleid_value"))
            columns.add(column)
        return columns

    def can_read_table(self, reader: SourceReader, table: SourceTable) -> bool:
        self.verify_reader_binding(reader)
        if table.read_privilege_id is None:
            raise SourceProjectionError("read_privilege_unmapped", "Source table has no verified read privilege mapping.")
        path = (
            f"systemusers({reader.dataverse_id})/Microsoft.Dynamics.CRM."
            f"RetrieveUserPrivilegeByPrivilegeId(PrivilegeId={table.read_privilege_id},ExcludeTeamBasic=false)"
        )
        # The general RetrieveUserPrivileges inventory can omit Team-privileges-
        # only Basic grants. Include those explicitly in this per-privilege gate.
        # This proves presence only: Dataverse still evaluates every record's
        # effective access. Never use these returned depths to filter rows.
        grants = list(self._collection(path, value_key="RolePrivileges"))
        for grant in grants:
            if _guid(grant.get("PrivilegeId")) != table.read_privilege_id:
                raise SourceProjectionError("privilege_scope_changed", "Reader privilege lookup returned another privilege.")
        # Only a complete, well-formed empty response establishes absent Read.
        return bool(grants)

    def verify_operator_read_scope(self, table: SourceTable) -> dict[str, bool]:
        environment = self.verify_environment()
        if table.read_privilege_id is None:
            raise SourceProjectionError("read_privilege_unmapped", "Source table has no verified read privilege mapping.")
        path = (
            f"systemusers({environment['caller_user_id']})/Microsoft.Dynamics.CRM."
            f"RetrieveUserPrivilegeByPrivilegeId(PrivilegeId={table.read_privilege_id},ExcludeTeamBasic=false)"
        )
        grants = list(self._collection(path, value_key="RolePrivileges"))
        global_read = any(_guid(g.get("PrivilegeId")) == table.read_privilege_id and g.get("Depth") in ("Global", 3) for g in grants)
        if not global_read:
            raise SourceProjectionError("operator_read_scope_unverified", "The source operator does not have verified Global Read for the table.")
        attributes = {a.property_name: a for a in table.attributes}
        if (len(attributes) != len(table.attributes) or set(attributes) != set(table.columns)
                or any(not isinstance(a.is_secured, bool) for a in table.attributes)):
            raise SourceProjectionError("operator_field_scope_unverified", "Complete selected attribute security metadata is required to verify the operator.")
        secured = {a.logical_name for a in table.attributes if a.is_secured}
        if not secured:
            return {"global_read_verified": True, "field_security_scope_verified": True}
        operator = environment["caller_user_id"]
        roles = list(self._collection(f"systemusers({operator})/systemuserroles_association?$select=_roletemplateid_value"))
        if any(str(r.get("_roletemplateid_value", "")).lower() == SYSTEM_ADMINISTRATOR_TEMPLATE for r in roles):
            return {"global_read_verified": True, "field_security_scope_verified": True}
        # A reduced operator can qualify with all-record profile Read grants for
        # every selected secured field. A per-record POAA grant is insufficient
        # because an administrative projection must not hide another reader's
        # otherwise accessible value on a different record.
        profile_ids = {
            _guid(p.get("fieldsecurityprofileid")) for p in self._collection(
                f"systemusers({operator})/systemuserprofiles_association?$select=fieldsecurityprofileid"
            )
        }
        teams = list(self._collection(f"systemusers({operator})/teammembership_association?$select=teamid"))
        for team in teams:
            team_id = _guid(team.get("teamid"))
            profile_ids.update(_guid(p.get("fieldsecurityprofileid")) for p in self._collection(
                f"teams({team_id})/teamprofiles_association?$select=fieldsecurityprofileid"
            ))
        readable_fields: set[str] = set()
        for profile_id in sorted(profile_ids):
            permissions = self._collection(
                "fieldpermissions?$select=_fieldsecurityprofileid_value,entityname,attributelogicalname,canread"
                f"&$filter=_fieldsecurityprofileid_value eq {profile_id} and entityname eq '{table.name}'"
            )
            for permission in permissions:
                if (_guid(permission.get("_fieldsecurityprofileid_value")) != profile_id
                        or permission.get("entityname") != table.name):
                    raise SourceProjectionError("operator_field_scope_unverified", "Field permission discovery changed the requested operator scope.")
                field = _identifier(permission.get("attributelogicalname"))
                if type(permission.get("canread")) is not int or permission.get("canread") not in (0, 4):
                    raise SourceProjectionError("operator_field_scope_unverified", "Field permission Read state is unknown.")
                if permission["canread"] == 4:
                    readable_fields.add(field)
        if not secured <= readable_fields:
            raise SourceProjectionError("operator_field_scope_unverified", "The source operator lacks verified all-record Read for selected secured fields.")
        return {"global_read_verified": True, "field_security_scope_verified": True}

    def open_scan(self, reader: SourceReader, table: SourceTable) -> SourceScan:
        """Gate this pair once and expose that same scan's permission and rows.

        No caller-supplied authorization result or cross-pair cache is used.
        Execution identity and operator scope remain verified inside each
        positive iterator, immediately before reader-context data retrieval.
        """
        deadline = self._monotonic() + self.max_scan_seconds
        has_read = self.can_read_table(reader, table)
        self._check_deadline(deadline)
        rows = (self._iter_rows_with_verified_read(reader, table, deadline)
                if has_read else self._iter_empty_scan(deadline))
        return SourceScan(has_read, rows)

    def _iter_empty_scan(self, deadline: float) -> Iterator[dict[str, Any]]:
        self._check_deadline(deadline)
        self._metrics["completed_scans"] += 1
        yield from ()

    def iter_rows(self, reader: SourceReader, table: SourceTable) -> Iterator[dict[str, Any]]:
        """Yield a fully gated scan; callers must exhaust it before publication.

        A verified lack of table Read yields no rows. A denied/failed request,
        changed identity, malformed page, duplicate ID, or exceeded budget raises
        and invalidates the entire scan, including previously yielded rows.
        """
        yield from self.open_scan(reader, table).rows

    def _iter_rows_with_verified_read(
        self, reader: SourceReader, table: SourceTable, deadline: float,
    ) -> Iterator[dict[str, Any]]:
        self._check_deadline(deadline)
        self.verify_identity(reader)
        self._check_deadline(deadline)
        self.verify_operator_read_scope(table)
        self._check_deadline(deadline)
        reference = f"{table.entity_set}?$select={','.join(table.columns)}&$orderby={table.primary_key} asc"
        seen: set[str] = set()
        for row in self._collection(reference, reader, deadline=deadline):
            self._check_deadline(deadline)
            record_id = _guid(row.get(table.primary_key))
            if record_id in seen:
                raise SourceProjectionError("duplicate_record", "Source scan repeated a record; discard the incomplete scan.")
            if len(seen) >= self.max_rows_per_scan:
                raise SourceProjectionError("row_limit_exceeded", "Source scan exceeded its row budget.")
            seen.add(record_id)
            projected = {column: row.get(column) for column in table.columns}
            if any(isinstance(value, (dict, list)) for value in projected.values()):
                raise SourceProjectionError("complex_value", "Source returned a non-scalar value for the scalar projection.")
            projected[table.primary_key] = record_id
            yield projected
        self._check_deadline(deadline)
        self._metrics["completed_scans"] += 1
        self._metrics["completed_rows"] += len(seen)
