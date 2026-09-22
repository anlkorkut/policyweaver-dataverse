"""Read-only Dataverse security inventory; this is not an authorization snapshot.

Every collection and relationship follows its own continuation links. Identity
and collection scope are verified separately from successful HTTP responses.
Unknown or unavailable inputs are surfaced, never interpreted as empty grants.
"""

from __future__ import annotations

import math
import random
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Iterator, Protocol
from urllib.parse import unquote, urljoin, urlsplit
from uuid import UUID

import httpx
from azure.identity import AzureCliCredential, ManagedIdentityCredential


API_PATH = "/api/data/v9.2/"


class TokenCredential(Protocol):
    def get_token(self, *scopes: str, **kwargs: Any) -> Any: ...


class DataverseError(RuntimeError):
    """A safe diagnostic; never includes response bodies, tokens, or URLs."""

    def __init__(self, code: str, message: str, status: int | None = None):
        super().__init__(message)
        self.code = code
        self.status = status


def _guid(value: Any) -> str:
    try:
        return str(UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        raise DataverseError("invalid_guid", "A required identifier is not a GUID.") from None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Explicit projections avoid collecting unrelated user personal information.
# Do not add a status filter: disabled/application users remain part of evidence.
COLLECTIONS = {
    "users": (
        "systemuser", "systemusers",
        "systemuserid,fullname,domainname,azureactivedirectoryobjectid,"
        "_businessunitid_value,isdisabled,accessmode,applicationid,"
        "_parentsystemuserid_value,_positionid_value,modifiedon",
    ),
    "business_units": (
        "businessunit", "businessunits",
        "businessunitid,name,_parentbusinessunitid_value,isdisabled,modifiedon",
    ),
    "roles": (
        "role", "roles",
        "roleid,roleidunique,name,_businessunitid_value,_parentroleid_value,"
        "_parentrootroleid_value,_roletemplateid_value,isinherited,modifiedon",
    ),
    "teams": (
        "team", "teams",
        "teamid,name,_businessunitid_value,teamtype,membershiptype,isdefault,"
        "azureactivedirectoryobjectid,_teamtemplateid_value,modifiedon",
    ),
    "privileges": (
        "privilege", "privileges",
        "privilegeid,name,accessright,canbebasic,canbelocal,canbedeep,canbeglobal",
    ),
    "field_security_profiles": (
        "fieldsecurityprofile", "fieldsecurityprofiles",
        "fieldsecurityprofileid,name,modifiedon",
    ),
    "field_permissions": (
        "fieldpermission", "fieldpermissions",
        "fieldpermissionid,_fieldsecurityprofileid_value,entityname,"
        "attributelogicalname,canread,canreadunmasked",
    ),
}

PUBLICATION_BLOCKERS = [
    "record_sharing_and_cascaded_access_unresolved",
    "record_specific_secured_column_sharing_unresolved",
    "hierarchy_security_unresolved",
    "entra_group_membership_and_identity_lifecycle_unresolved",
    "data_security_watermarks_and_revocations_unreconciled",
    "destination_enforcement_and_differential_tests_required",
]


class DataverseClient:
    """Collect security evidence with GET requests only.

    CLI credentials are explicitly tenant-bound. Azure jobs should provide
    ManagedIdentityCredential or set authentication="managed_identity".
    Transport and sleep injection support deterministic offline tests.
    """

    def __init__(
        self,
        environment_url: str,
        tenant_id: str,
        expected_organization_id: str,
        credential: TokenCredential | None = None,
        transport: httpx.BaseTransport | None = None,
        *,
        authentication: str = "azure_cli",
        managed_identity_client_id: str | None = None,
        timeout: float = 90.0,
        max_retries: int = 5,
        max_retry_delay: float = 60.0,
        max_pages: int = 100_000,
        sleep: Callable[[float], None] = time.sleep,
        random_source: Callable[[], float] = random.random,
    ):
        parsed = urlsplit(environment_url)
        if (
            parsed.scheme != "https" or not parsed.hostname
            or parsed.username or parsed.password or parsed.port not in (None, 443)
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or not re.fullmatch(
                r"[a-zA-Z0-9-]+\.(?:crm\d*\.dynamics\.com|crm\.microsoftdynamics\.us|crm\.dynamics\.cn)",
                parsed.hostname,
            )
        ):
            raise ValueError("Use an HTTPS Dataverse environment origin with no path or credentials.")
        if not 0 <= max_retries <= 20 or not 0 < max_retry_delay <= 60:
            raise ValueError("Retries must be 0..20 and maximum delay must be 0..60 seconds.")
        if max_pages < 1 or timeout <= 0:
            raise ValueError("Page limit and request timeout must be positive.")
        self.environment_url = f"https://{parsed.hostname}"
        self.base_url = self.environment_url + API_PATH
        self.tenant_id = _guid(tenant_id)
        self.expected_organization_id = _guid(expected_organization_id)
        self._owns_credential = credential is None
        if credential is None:
            if authentication == "azure_cli":
                credential = AzureCliCredential(tenant_id=self.tenant_id)
            elif authentication == "managed_identity":
                credential = ManagedIdentityCredential(client_id=managed_identity_client_id)
            else:
                raise ValueError("Authentication must be azure_cli or managed_identity.")
        self.credential = credential
        self._client = httpx.Client(
            transport=transport, timeout=timeout, follow_redirects=False, trust_env=False,
            headers={
                "Accept": "application/json",
                "OData-Version": "4.0",
                "OData-MaxVersion": "4.0",
                "Prefer": "odata.maxpagesize=5000",
                "If-None-Match": "null",
            },
        )
        self.max_retries = max_retries
        self.max_retry_delay = max_retry_delay
        self.max_pages = max_pages
        self._sleep = sleep
        self._random = random_source

    def __enter__(self) -> DataverseClient:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()
        if self._owns_credential:
            close = getattr(self.credential, "close", None)
            if close:
                close()

    def _safe_url(self, reference: str) -> str:
        if not isinstance(reference, str) or not reference:
            raise DataverseError("unsafe_continuation", "Continuation URL is invalid.")
        if any(ord(c) < 32 for c in reference) or "\\" in reference:
            raise DataverseError("unsafe_continuation", "Continuation URL is invalid.")
        try:
            result = urljoin(self.base_url, reference)
            parsed = urlsplit(result)
            port = parsed.port
        except ValueError:
            raise DataverseError("unsafe_continuation", "Continuation URL is invalid.") from None
        decoded_path = parsed.path
        for _ in range(3):
            decoded_path = unquote(decoded_path)
        if (
            parsed.scheme != "https" or parsed.hostname != urlsplit(self.environment_url).hostname
            or port not in (None, 443) or parsed.username or parsed.password
            or parsed.fragment or not decoded_path.startswith(API_PATH)
            or "\\" in decoded_path or "%" in decoded_path
            or any(p in (".", "..") for p in decoded_path.split("/"))
            or any(ord(c) < 32 for c in decoded_path)
        ):
            raise DataverseError("unsafe_continuation", "Continuation escaped the Dataverse API origin or path.")
        return result

    def _retry_delay(self, response: httpx.Response | None, attempt: int) -> float:
        delay: float | None = None
        if response is not None:
            raw = response.headers.get("Retry-After")
            if raw:
                try:
                    delay = float(raw)
                except ValueError:
                    try:
                        date = parsedate_to_datetime(raw)
                        if date.tzinfo is None:
                            date = date.replace(tzinfo=timezone.utc)
                        delay = (date - datetime.now(timezone.utc)).total_seconds()
                    except (TypeError, ValueError, OverflowError):
                        pass
        if delay is not None and math.isfinite(delay):
            delay = max(0.0, delay)
            if delay > self.max_retry_delay:
                # Do not retry earlier than the server requested. Let the job
                # orchestrator reschedule instead of blocking indefinitely.
                raise DataverseError("retry_after_exceeds_budget", "Server retry delay exceeds the collection retry budget.")
        else:
            delay = min(2.0 ** attempt, self.max_retry_delay)
        return min(delay + self._random(), self.max_retry_delay)

    def get_json(self, reference: str) -> dict[str, Any]:
        url = self._safe_url(reference)  # Validate before requesting a token.
        for attempt in range(self.max_retries + 1):
            try:
                token = self.credential.get_token(self.environment_url + "/.default")
            except Exception:
                raise DataverseError("authentication_failed", "Dataverse token acquisition failed; check the configured identity.") from None
            try:
                response = self._client.get(url, headers={"Authorization": "Bearer " + token.token})
            except httpx.TransportError:
                if attempt < self.max_retries:
                    self._sleep(self._retry_delay(None, attempt))
                    continue
                raise DataverseError("transport_failed", "Dataverse request failed after bounded retries.") from None
            if response.status_code == 429 or 500 <= response.status_code <= 599:
                if attempt < self.max_retries:
                    self._sleep(self._retry_delay(response, attempt))
                    continue
            if response.status_code != 200:
                code = "redirect_refused" if 300 <= response.status_code < 400 else "http_error"
                raise DataverseError(code, f"Dataverse returned HTTP {response.status_code}.", response.status_code)
            try:
                payload = response.json()
            except ValueError:
                raise DataverseError("invalid_json", "Dataverse returned invalid JSON.") from None
            if not isinstance(payload, dict):
                raise DataverseError("invalid_payload", "Dataverse response must be an object.")
            return payload
        raise AssertionError("Retry loop must return or raise.")

    def iter_collection(self, reference: str, *, value_key: str = "value") -> Iterator[dict[str, Any]]:
        seen: set[str] = set()
        for _ in range(self.max_pages):
            url = self._safe_url(reference)
            if url in seen:
                raise DataverseError("pagination_cycle", "Dataverse repeated a continuation URL.")
            seen.add(url)
            payload = self.get_json(url)
            rows = payload.get(value_key)
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise DataverseError("invalid_collection", "Dataverse response lacks the expected row collection.")
            yield from rows
            next_link = payload.get("@odata.nextLink") or payload.get(value_key + "@odata.nextLink")
            if not next_link:
                return
            if not isinstance(next_link, str):
                raise DataverseError("invalid_continuation", "Dataverse continuation is not a string.")
            reference = next_link
        raise DataverseError("page_limit_exceeded", "Dataverse collection exceeded the configured page limit.")

    def collect(self, *, include_attributes: bool = True) -> dict[str, Any]:
        """Return raw evidence and explicit completeness/capability information.

        ``complete`` concerns enumerated inventory only, never effective access.
        This full scan is sequential and is not a transactional snapshot.
        """
        snapshot: dict[str, Any] = {
            "schema_version": "1.0",
            "environment_url": self.environment_url,
            "tenant_id": self.tenant_id,
            "organization_id": None,
            "observed_start": _now(),
            "observed_end": None,
            "complete": False,
            "authorization_complete": False,
            "publication_ready": False,
            "consistency": "sequential_nontransactional_reads",
            "datasets": {},
            "counts": {},
            "diagnostics": [],
            "capabilities": {},
            "publication_blockers": list(PUBLICATION_BLOCKERS),
        }
        data = snapshot["datasets"]
        capabilities = snapshot["capabilities"]

        def failure(name: str, exc: DataverseError) -> None:
            capabilities[name] = {"complete": False, "code": exc.code}
            snapshot["diagnostics"].append({
                "dataset": name, "severity": "error", "code": exc.code,
                "message": str(exc), "http_status": exc.status,
            })

        def scan(name: str, reference: str, *, value_key: str = "value") -> None:
            data[name] = []
            try:
                for row in self.iter_collection(reference, value_key=value_key):
                    data[name].append(row)
                capabilities[name] = {"complete": True}
            except DataverseError as exc:
                failure(name, exc)

        try:
            who = self.get_json("WhoAmI")
            organization_id = _guid(who.get("OrganizationId"))
            if organization_id != self.expected_organization_id:
                raise DataverseError("organization_mismatch", "WhoAmI organization does not match the configured organization.")
            caller_id = _guid(who.get("UserId"))
            snapshot["organization_id"] = organization_id
            snapshot["caller_user_id"] = caller_id
            capabilities["organization_identity"] = {"complete": True}
        except DataverseError as exc:
            failure("organization_identity", exc)
            snapshot["publication_blockers"].append("organization_identity_unverified")
            snapshot["observed_end"] = _now()
            return snapshot

        metadata_query = (
            "EntityDefinitions?$select=MetadataId,LogicalName,SchemaName,EntitySetName,"
            "PrimaryIdAttribute,OwnershipType,Privileges,IsIntersect,IsPrivate,IsLogicalEntity"
        )
        if include_attributes:
            metadata_query += (
                "&$expand=Attributes($select=MetadataId,LogicalName,SchemaName,"
                "IsSecured,IsValidForRead,AttributeType)"
            )
        scan("entity_definitions", metadata_query)
        capabilities["attribute_metadata"] = {"complete": include_attributes}
        if include_attributes:
            for entity in data["entity_definitions"]:
                try:
                    attributes = entity.get("Attributes")
                    if not isinstance(attributes, list) or any(not isinstance(a, dict) for a in attributes):
                        raise DataverseError("missing_attributes", "Entity metadata lacks its attribute collection.")
                    continuation = entity.get("Attributes@odata.nextLink")
                    if continuation:
                        attributes.extend(self.iter_collection(continuation))
                        entity.pop("Attributes@odata.nextLink", None)
                    seen_attributes: set[str] = set()
                    for attribute in attributes:
                        attribute_id = _guid(attribute.get("MetadataId"))
                        if (
                            attribute_id in seen_attributes
                            or not isinstance(attribute.get("IsSecured"), bool)
                            or not isinstance(attribute.get("LogicalName"), str)
                        ):
                            raise DataverseError("invalid_attribute_metadata", "Column security metadata is missing, malformed, or duplicated.")
                        seen_attributes.add(attribute_id)
                except DataverseError as exc:
                    failure("attribute_metadata", exc)
        else:
            snapshot["diagnostics"].append({
                "dataset": "attribute_metadata", "severity": "error",
                "code": "attributes_excluded", "message": "Column security metadata was excluded from this scan.",
            })

        for name, (_, entity_set, projection) in COLLECTIONS.items():
            scan(name, f"{entity_set}?$select={projection}")

        # Full-depth function is required: RetrieveUserPrivileges reports only
        # Basic depth for team-inherited grants even if the team's role is Global.
        data["caller_read_privileges"] = []
        metadata_by_name = {e.get("LogicalName"): e for e in data["entity_definitions"]}
        capabilities["global_read_scope"] = {"complete": True}
        for name, (logical_name, _, _) in COLLECTIONS.items():
            try:
                definition = metadata_by_name.get(logical_name)
                if definition is None:
                    raise DataverseError("scope_metadata_missing", "Cannot verify the inventory table's read scope without its metadata.")
                metadata_privileges = definition.get("Privileges")
                if not isinstance(metadata_privileges, list) or any(not isinstance(p, dict) for p in metadata_privileges):
                    raise DataverseError("scope_metadata_missing", "Entity metadata lacks the expected privilege collection.")
                read_privileges = [p for p in metadata_privileges if p.get("PrivilegeType") in ("Read", 2)]
                if not read_privileges:
                    # Some internal metadata tables have no own record-access
                    # privilege. Their successful GET is checked separately.
                    if definition.get("OwnershipType") == "None" and logical_name in ("privilege", "fieldpermission"):
                        continue
                    raise DataverseError("read_privilege_unmapped", "Cannot map the inventory table to an authoritative read privilege.")
                for privilege in read_privileges:
                    privilege_id = _guid(privilege.get("PrivilegeId"))
                    reference = (
                        f"systemusers({caller_id})/Microsoft.Dynamics.CRM."
                        "RetrieveUserPrivilegeByPrivilegeId("
                        f"PrivilegeId={privilege_id},ExcludeTeamBasic=false)"
                    )
                    grants = list(self.iter_collection(reference, value_key="RolePrivileges"))
                    data["caller_read_privileges"].extend(
                        dict(g, entity_logical_name=logical_name) for g in grants
                    )
                    if not any(
                        _guid(g.get("PrivilegeId")) == privilege_id
                        and g.get("Depth") in ("Global", 3)
                        for g in grants
                    ):
                        raise DataverseError("global_read_unverified", "Caller Global Read scope is not verified for an inventory table.")
            except DataverseError as exc:
                failure("global_read_scope", exc)
                snapshot["diagnostics"][-1]["source_dataset"] = name

        def edges(
            name: str, source: str, entity_set: str, source_key: str,
            navigation: str, target_key: str,
        ) -> None:
            data[name] = []
            capabilities[name] = {"complete": capabilities[source]["complete"]}
            seen: set[tuple[str, str]] = set()
            for parent in data[source]:
                try:
                    source_id = _guid(parent.get(source_key))
                    path = f"{entity_set}({source_id})/{navigation}?$select={target_key}"
                    for member in self.iter_collection(path):
                        target_id = _guid(member.get(target_key))
                        key = (source_id, target_id)
                        if key in seen:
                            # Duplicates can indicate concurrent changes. Keep
                            # raw evidence and block completeness, not overwrite.
                            raise DataverseError("duplicate_relationship", "A relationship repeated during the sequential scan.")
                        seen.add(key)
                        data[name].append(dict(member, **{source_key: source_id, target_key: target_id}))
                except DataverseError as exc:
                    failure(name, exc)

        edges("user_roles", "roles", "roles", "roleid", "systemuserroles_association", "systemuserid")
        edges("team_roles", "teams", "teams", "teamid", "teamroles_association", "roleid")
        edges("team_memberships", "teams", "teams", "teamid", "teammembership_association", "systemuserid")
        edges("profile_users", "field_security_profiles", "fieldsecurityprofiles", "fieldsecurityprofileid", "systemuserprofiles_association", "systemuserid")
        edges("profile_teams", "field_security_profiles", "fieldsecurityprofiles", "fieldsecurityprofileid", "teamprofiles_association", "teamid")

        data["role_privileges"] = []
        capabilities["role_privileges"] = {"complete": capabilities["roles"]["complete"]}
        for role in data["roles"]:
            try:
                role_id = _guid(role.get("roleid"))
                for grant in self.iter_collection(f"RetrieveRolePrivilegesRole(RoleId={role_id})", value_key="RolePrivileges"):
                    _guid(grant.get("PrivilegeId"))
                    data["role_privileges"].append(dict(grant, roleid=role_id))
                    if "Depth" not in grant:
                        raise DataverseError("missing_privilege_depth", "A role privilege lacks its actual granted depth.")
                    if grant.get("Depth") not in ("Basic", "Local", "Deep", "Global", 0, 1, 2, 3):
                        blocker = "record_filter_or_unknown_privilege_depth_unresolved"
                        if blocker not in snapshot["publication_blockers"]:
                            snapshot["publication_blockers"].append(blocker)
            except DataverseError as exc:
                failure("role_privileges", exc)

        # Identity keys, including metadata keys, must be stable across pages.
        key_fields = {
            "users": "systemuserid", "business_units": "businessunitid", "roles": "roleid",
            "teams": "teamid", "privileges": "privilegeid", "field_security_profiles": "fieldsecurityprofileid",
            "field_permissions": "fieldpermissionid", "entity_definitions": "MetadataId",
        }
        for name, key_field in key_fields.items():
            seen_ids: set[str] = set()
            try:
                for row in data[name]:
                    row_id = _guid(row.get(key_field))
                    if row_id in seen_ids:
                        raise DataverseError("duplicate_identity", "An inventory identifier repeated during the sequential scan.")
                    seen_ids.add(row_id)
            except DataverseError as exc:
                failure(name, exc)

        capabilities["referential_integrity"] = {"complete": True}
        identity_sets = {
            name: {str(r.get(field, "")).lower() for r in data[name]}
            for name, field in key_fields.items()
        }
        references = [
            ("users", "_businessunitid_value", "business_units", False),
            ("roles", "_businessunitid_value", "business_units", False),
            ("teams", "_businessunitid_value", "business_units", False),
            ("business_units", "_parentbusinessunitid_value", "business_units", True),
            ("user_roles", "systemuserid", "users", False),
            ("user_roles", "roleid", "roles", False),
            ("team_roles", "teamid", "teams", False),
            ("team_roles", "roleid", "roles", False),
            ("team_memberships", "teamid", "teams", False),
            ("team_memberships", "systemuserid", "users", False),
            ("profile_users", "fieldsecurityprofileid", "field_security_profiles", False),
            ("profile_users", "systemuserid", "users", False),
            ("profile_teams", "fieldsecurityprofileid", "field_security_profiles", False),
            ("profile_teams", "teamid", "teams", False),
            ("field_permissions", "_fieldsecurityprofileid_value", "field_security_profiles", False),
            ("role_privileges", "roleid", "roles", False),
            ("role_privileges", "PrivilegeId", "privileges", False),
        ]
        for source, field, target, nullable in references:
            for row in data[source]:
                value = row.get(field)
                if value is None and nullable:
                    continue
                if str(value).lower() not in identity_sets[target]:
                    failure("referential_integrity", DataverseError(
                        "unresolved_reference", "An inventory relationship references an absent identifier."
                    ))
                    snapshot["diagnostics"][-1]["source_dataset"] = source
                    break

        snapshot["complete"] = all(c["complete"] for c in capabilities.values())
        if not snapshot["complete"]:
            snapshot["publication_blockers"].append("inventory_incomplete")
        snapshot["counts"] = {name: len(rows) for name, rows in data.items()}
        snapshot["counts"]["attributes"] = sum(len(e.get("Attributes", [])) for e in data["entity_definitions"])
        snapshot["observed_end"] = _now()
        return snapshot
