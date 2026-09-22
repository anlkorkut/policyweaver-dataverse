"""Plan and publish native OneLake policies for materialized reader projections.

The adapter, not OneLake, computes Dataverse access and secured-field NULLs.
Every exposed table must contain trusted ``__pw_reader`` and
``__pw_generation`` columns. Neither helper is included in the business-column
allowlist. The public planner does not grant workspace or item permissions.

REST reference: https://learn.microsoft.com/en-us/rest/api/fabric/core/
onelake-data-access-security/create-or-update-data-access-roles

PUT replaces the complete role collection. This implementation preserves
unowned roles, requires ETags, performs dry-run validation, never retries a PUT,
and never restores an older generation following an ambiguous failure.
Publication verification checks the control plane only: it does not certify
engine propagation, SQL identity mode, cache invalidation, or a revocation SLA.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Mapping, Protocol
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import UUID

import httpx

from .role_naming import MAX_ROLE_NAME_LENGTH, ReaderRoleLabel

FABRIC_ROOT = "https://api.fabric.microsoft.com/v1"
FABRIC_SCOPE = "https://api.fabric.microsoft.com/.default"
MAX_READERS = 1000
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_PREFIX = re.compile(r"[A-Za-z][A-Za-z0-9_]{3,47}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")


class NativePolicyError(ValueError):
    """An input, boundary, or policy invariant is not satisfied."""


class FabricRequestError(RuntimeError):
    """Sanitized Fabric failure; response bodies and tokens are never exposed."""

    def __init__(self, message: str, *, status_code: int | None = None,
                 error_code: str | None = None, detail_codes: tuple[str, ...] = ()):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code if isinstance(error_code, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", error_code) else None
        self.detail_codes = tuple(c for c in detail_codes if isinstance(c, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", c))

    @property
    def code(self) -> str:
        detail = self.detail_codes[0] if self.detail_codes else self.error_code
        return "fabric_" + (str(self.status_code) if self.status_code else "request") + ("_" + detail if detail else "_failed")


class PublicationUncertain(FabricRequestError):
    """A mutation might have committed; inspect state without restoring old grants."""


class TokenCredential(Protocol):
    def get_token(self, *scopes: str, **kwargs: Any) -> Any: ...


def _guid(value: Any, label: str) -> str:
    try:
        result = str(UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise NativePolicyError(f"{label} must be a UUID") from exc
    if result == "00000000-0000-0000-0000-000000000000":
        raise NativePolicyError(f"{label} must not be the zero UUID")
    return result


def _generation(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise NativePolicyError("generation must be a positive integer")
    if not re.fullmatch(r"[1-9][0-9]{0,18}", str(value)):
        raise NativePolicyError("generation must be a positive integer")
    result = int(value)
    if result > 2**63 - 1:
        raise NativePolicyError("generation exceeds signed 64-bit range")
    return result


def _utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise NativePolicyError(f"{label} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode()).hexdigest()


def _role_namespace(prefix: str) -> str:
    """Fabric role names allow only letters/digits, even though paths allow '_'.

    Hash the configured namespace instead of stripping punctuation, which would
    collide for deployments such as pw_ab and pwa_b. Never use UPNs in names.
    """
    if not isinstance(prefix, str) or not _PREFIX.fullmatch(prefix):
        raise NativePolicyError("invalid ownership namespace")
    return "PW" + hashlib.sha256(prefix.encode("utf-8")).hexdigest()[:16]


def _reader_role_name(prefix: str, reader: str, label: ReaderRoleLabel | None = None) -> str:
    namespace = _role_namespace(prefix)
    suffix = "R" + _guid(reader, "role reader").replace("-", "")
    if label is None:
        return namespace + suffix
    name = "PW" + label.readable_token() + "N" + namespace[2:] + suffix
    if len(name) > MAX_ROLE_NAME_LENGTH or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", name):
        raise NativePolicyError("Readable role name violates the supported Fabric name limits")
    return name


def _owned_role_reader(name: Any, prefix: str) -> str | None:
    """Parse old/new identity suffixes, refusing malformed owned candidates.

    Display labels never decide ownership. The complete GUID and deployment
    namespace must match, and callers must also verify the single role member.
    Name comparisons follow Fabric's case-insensitive uniqueness contract.
    """
    if not isinstance(name, str):
        raise NativePolicyError("Malformed role name")
    namespace = _role_namespace(prefix)
    marker = "N" + namespace[2:] + "R"
    folded = name.casefold()
    if folded.startswith(prefix.casefold()):
        raise NativePolicyError("Legacy or unrecognized role occupies the configured namespace")
    legacy = re.fullmatch(re.escape(namespace) + r"R([a-f0-9]{32})", name, re.IGNORECASE)
    readable = re.fullmatch(r"PW[A-Za-z0-9]{1,72}" + re.escape(marker) + r"([a-f0-9]{32})",
                            name, re.IGNORECASE)
    match = legacy or readable
    if match:
        return match[1].lower()
    if folded.startswith(namespace.casefold()) or ("N" + namespace[2:]).casefold() in folded:
        raise NativePolicyError("Unrecognized role occupies the owned namespace; refusing replacement")
    return None


@dataclass(frozen=True)
class TableSpec:
    """One local Delta table and the exact columns readers may query.

    Paths are /Tables/name or /Tables/schema/name. Explicit identifiers prevent
    predicate injection. An empty/wildcard list or helper column is rejected.
    """

    path: str
    columns: tuple[str, ...]

    def __post_init__(self) -> None:
        parts = self.path.split("/") if isinstance(self.path, str) else []
        if len(parts) not in (3, 4) or parts[:2] != ["", "Tables"]:
            raise NativePolicyError("table path must be /Tables/[schema/]table")
        if not all(_IDENTIFIER.fullmatch(p) for p in parts[2:]):
            raise NativePolicyError("table path contains an unsupported identifier")
        if isinstance(self.columns, str):
            raise NativePolicyError("business columns must be a sequence of identifiers")
        columns = tuple(self.columns)
        if not columns or any(not isinstance(c, str) or not _IDENTIFIER.fullmatch(c)
                              or c.lower().startswith("__pw_") for c in columns):
            raise NativePolicyError("business columns must be explicit identifiers without __pw_ helpers")
        if len({c.lower() for c in columns}) != len(columns):
            raise NativePolicyError("duplicate business column")
        object.__setattr__(self, "columns", columns)

    @property
    def sql_name(self) -> str:
        # Bracket quoting also handles SQL reserved words. No user SQL is used.
        return ".".join(f"[{p}]" for p in self.path.split("/")[2:])


@dataclass(frozen=True)
class RoleShard:
    key: str
    audience_index: int
    table_index: int
    tenant_id: str
    generation: int
    reader_ids: tuple[str, ...]
    tables: tuple[TableSpec, ...]
    ownership_prefix: str
    role_limit: int
    reserve_roles: int
    reader_table_paths: tuple[tuple[str, tuple[str, ...]], ...] | None = None
    reader_role_labels: tuple[tuple[str, ReaderRoleLabel], ...] | None = None

    def __post_init__(self) -> None:
        if self.tenant_id != _guid(self.tenant_id, "shard tenant"):
            raise NativePolicyError("shard tenant must use canonical UUID format")
        if self.generation != _generation(self.generation) or isinstance(self.generation, bool):
            raise NativePolicyError("shard generation must be a positive integer")
        if not _PREFIX.fullmatch(self.ownership_prefix):
            raise NativePolicyError("invalid shard ownership prefix")
        if (not isinstance(self.role_limit, int) or not 1 <= self.role_limit <= 1000
                or not isinstance(self.reserve_roles, int) or not 0 <= self.reserve_roles < self.role_limit):
            raise NativePolicyError("invalid shard role quota")
        if (not self.reader_ids or len(self.reader_ids) > self.role_limit - self.reserve_roles
                or len(set(self.reader_ids)) != len(self.reader_ids)
                or any(r != _guid(r, "shard reader") for r in self.reader_ids)):
            raise NativePolicyError("invalid shard audience")
        if (not self.tables or len(self.tables) > 500 or any(not isinstance(t, TableSpec) for t in self.tables)
                or len({t.path.lower() for t in self.tables}) != len(self.tables)):
            raise NativePolicyError("invalid shard tables")
        if self.reader_table_paths is not None:
            mapping = dict(self.reader_table_paths)
            if len(mapping) != len(self.reader_table_paths) or set(mapping) != set(self.reader_ids):
                raise NativePolicyError("table-access map must cover exactly the shard readers")
            known_paths = {t.path for t in self.tables}
            if any(not set(paths) <= known_paths or len(paths) != len(set(paths)) for paths in mapping.values()):
                raise NativePolicyError("table-access map contains unknown or duplicate table paths")
        if self.reader_role_labels is not None:
            labels = dict(self.reader_role_labels)
            if (len(labels) != len(self.reader_role_labels) or set(labels) != set(self.reader_ids)
                    or any(not isinstance(value, ReaderRoleLabel) for value in labels.values())):
                raise NativePolicyError("role labels must cover exactly the shard readers")

    @property
    def roles(self) -> list[dict[str, Any]]:
        """Return a fresh payload so callers cannot mutate the plan."""
        access = dict(self.reader_table_paths) if self.reader_table_paths is not None else None
        labels = dict(self.reader_role_labels) if self.reader_role_labels is not None else {}
        roles = []
        for reader in self.reader_ids:
            tables = self.tables if access is None else tuple(t for t in self.tables if t.path in access[reader])
            if tables:
                roles.append(_reader_role(self.tenant_id, reader, tables, self.generation,
                                          self.ownership_prefix, labels.get(reader)))
        return roles

    @property
    def payload(self) -> dict[str, Any]:
        return {"value": self.roles}

    @property
    def role_name_map(self) -> list[dict[str, Any]]:
        access = dict(self.reader_table_paths) if self.reader_table_paths is not None else None
        return [{"entra_id": reader, "role_name": _reader_role_name(self.ownership_prefix, reader, label),
                 **label.audit()} for reader, label in self.reader_role_labels or ()
                if access is None or access[reader]]

    @property
    def plan_digest(self) -> str:
        return _hash({"key": self.key, "generation": self.generation, "tenant": self.tenant_id,
                      "reader_ids": self.reader_ids, "tables": [t.path for t in self.tables], "roles": self.roles})


@dataclass(frozen=True)
class RolePlan:
    tenant_id: str
    generation: int
    reader_count: int
    table_count: int
    audience_shards: int
    table_shards: int
    shards: tuple[RoleShard, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"tenant_id": self.tenant_id, "generation": self.generation,
                "reader_count": self.reader_count, "table_count": self.table_count,
                "audience_shards": self.audience_shards, "table_shards": self.table_shards,
                "required_lakehouses": len(self.shards), "shards": [
                    {"key": s.key, "reader_ids": list(s.reader_ids),
                     "tables": [{"path": t.path, "columns": list(t.columns)} for t in s.tables],
                     "role_count": len(s.roles), "plan_digest": s.plan_digest,
                     "payload": s.payload,
                     **({"role_name_map": s.role_name_map} if s.reader_role_labels is not None else {})
                    } for s in self.shards]}


def _reader_role(tenant: str, reader: str, tables: tuple[TableSpec, ...],
                 generation: int, prefix: str, label: ReaderRoleLabel | None = None) -> dict[str, Any]:
    # Fabric accepts exactly one decision rule per role. Each permitted path
    # retains its own row predicate and explicit business-column allowlist.
    paths, rows, columns = [], [], []
    for table in tables:
        predicate = (f"SELECT * FROM {table.sql_name} WHERE __pw_reader = '{reader}' "
                     f"AND __pw_generation = {generation}")
        if len(predicate) > 1000:
            raise NativePolicyError("OneLake predicate exceeds 1000 characters")
        paths.append(table.path)
        rows.append({"tablePath": table.path, "value": predicate})
        columns.append({"tablePath": table.path, "columnNames": list(table.columns),
                        "columnEffect": "Permit", "columnAction": ["Read"]})
    rules = [{"effect": "Permit", "permission": [
            {"attributeName": "Path", "attributeValueIncludedIn": paths},
            {"attributeName": "Action", "attributeValueIncludedIn": ["Read"]}],
            "constraints": {"rows": rows, "columns": columns}}] if tables else []
    return {"name": _reader_role_name(prefix, reader, label), "kind": "Policy",
            "decisionRules": rules, "members": {"microsoftEntraMembers": [
                {"tenantId": tenant, "objectId": reader, "objectType": "User"}]}}


def plan_roles(tenant_id: str, tables: Iterable[TableSpec | Mapping[str, Any]],
               readers: Iterable[str | Mapping[str, Any]], generation: int | str,
               *, role_limit: int = 250, reserve_roles: int = 10,
               max_table_permissions: int = 500,
               ownership_prefix: str = "PolicyWeaver_",
               reader_table_paths: Mapping[str, Iterable[str]] | None = None,
               reader_labels: Mapping[str, Mapping[str, Any]] | None = None) -> RolePlan:
    """Partition readers and tables into independently secured lakehouse items.

    The default quota was verified in the supplied demo tenant. A 1000-role
    override must be confirmed separately for each destination item. At 250
    roles with ten reserved slots, 200 readers need one audience shard and
    1000 readers need five. Each table contributes one path and paired row/column
    constraints inside the role's single decision rule.
    Sharding uses separate local Delta tables, not OneLake-to-OneLake shortcuts.
    """
    tenant = _guid(tenant_id, "tenant_id")
    gen = _generation(generation)
    if not isinstance(ownership_prefix, str) or not _PREFIX.fullmatch(ownership_prefix):
        raise NativePolicyError("ownership_prefix must contain 4-48 safe identifier characters")
    for value, label, minimum, maximum in ((role_limit, "role_limit", 1, 1000),
            (reserve_roles, "reserve_roles", 0, 999),
            (max_table_permissions, "max_table_permissions", 1, 500)):
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise NativePolicyError(f"{label} outside supported range")
    if reserve_roles >= role_limit:
        raise NativePolicyError("reserve_roles must leave capacity for at least one reader")
    normalized_tables = []
    for table in tables:
        if isinstance(table, TableSpec):
            normalized_tables.append(table)
        elif isinstance(table, Mapping):
            normalized_tables.append(TableSpec(table["path"], table["columns"]))
        else:
            raise NativePolicyError("tables must contain TableSpec objects or path/columns mappings")
    normalized_tables.sort(key=lambda t: t.path)
    if not normalized_tables or len({t.path.lower() for t in normalized_tables}) != len(normalized_tables):
        raise NativePolicyError("at least one unique table path is required")
    ids = []
    for reader in readers:
        ids.append(_guid(reader.get("entra_id") if isinstance(reader, Mapping) else reader, "reader entra_id"))
    if not 1 <= len(ids) <= MAX_READERS:
        raise NativePolicyError("reader count must be between 1 and 1000")
    if len(set(ids)) != len(ids):
        raise NativePolicyError("duplicate reader identity")
    ids.sort()
    labels = None
    if reader_labels is not None:
        if not isinstance(reader_labels, Mapping):
            raise NativePolicyError("reader labels must be a mapping")
        labels = {}
        for raw_reader, value in reader_labels.items():
            identity = _guid(raw_reader, "role-label reader")
            if identity in labels:
                raise NativePolicyError("duplicate role-label identity")
            try:
                labels[identity] = ReaderRoleLabel.from_mapping(value)
            except (ValueError, TypeError, AttributeError) as exc:
                raise NativePolicyError("Malformed reader role label provenance") from exc
        if set(labels) != set(ids):
            raise NativePolicyError("role labels must cover exactly the selected readers")
    table_access = None
    if reader_table_paths is not None:
        table_access = {}
        known_paths = {t.path for t in normalized_tables}
        for raw_reader, paths in reader_table_paths.items():
            identity = _guid(raw_reader, "table-access reader")
            if identity in table_access or isinstance(paths, str):
                raise NativePolicyError("invalid or duplicate table-access identity")
            permitted = tuple(paths)
            if any(not isinstance(p, str) for p in permitted) or not set(permitted) <= known_paths:
                raise NativePolicyError("table-access map contains an unknown table path")
            if len(set(permitted)) != len(permitted):
                raise NativePolicyError("table-access map contains duplicate paths")
            table_access[identity] = tuple(sorted(permitted))
        if set(table_access) != set(ids):
            raise NativePolicyError("table-access map must cover exactly the selected readers")
    audience_size = role_limit - reserve_roles
    audiences = [tuple(ids[i:i + audience_size]) for i in range(0, len(ids), audience_size)]
    table_groups = [tuple(normalized_tables[i:i + max_table_permissions])
                    for i in range(0, len(normalized_tables), max_table_permissions)]
    shards = tuple(RoleShard(f"a{ai:03d}_t{ti:03d}", ai, ti, tenant, gen, audience, group,
                             ownership_prefix, role_limit, reserve_roles,
                             None if table_access is None else tuple(
                                 (r, tuple(t.path for t in group if t.path in table_access[r])) for r in audience),
                             None if labels is None else tuple((r, labels[r]) for r in audience))
                   for ai, audience in enumerate(audiences) for ti, group in enumerate(table_groups))
    return RolePlan(tenant, gen, len(ids), len(normalized_tables), len(audiences), len(table_groups), shards)


@dataclass(frozen=True)
class DataReadyReceipt:
    """Local controller assertion bound to one verified materialization.

    This is not a signature or an automatic expiry policy in OneLake. The
    controller must secure its state and run a withdrawal watchdog. Publication
    must finish while valid; expiry does not itself revoke native access.
    """
    workspace_id: str
    item_id: str
    shard_key: str
    generation: int
    plan_digest: str
    content_digest: str
    source_observed_at: datetime
    completed_at: datetime
    valid_until: datetime

    def validate(self, shard: RoleShard, now: datetime) -> None:
        now = _utc(now, "now")
        observed = _utc(self.source_observed_at, "source_observed_at")
        completed = _utc(self.completed_at, "completed_at")
        deadline = _utc(self.valid_until, "valid_until")
        if (self.shard_key != shard.key or self.generation != shard.generation
                or self.plan_digest != shard.plan_digest):
            raise NativePolicyError("materialization receipt does not match the policy plan")
        if not isinstance(self.content_digest, str) or not _DIGEST.fullmatch(self.content_digest):
            raise NativePolicyError("materialization content digest must be SHA-256")
        if not observed <= completed <= now < deadline <= observed + timedelta(minutes=60):
            raise NativePolicyError("materialization receipt is expired, future-dated, or exceeds the 60-minute budget")


@dataclass(frozen=True)
class BoundaryAttestation:
    """Trusted deployment-controller review of surfaces outside role REST.

    All reader identities must be reviewed for elevated workspace roles,
    direct raw-storage access and alternate item/SQL grants. SQL must use
    UserIdentity, or be inaccessible to the audience. Operator assertions are
    not a substitute for end-user runtime and cache/revocation qualification.
    """
    workspace_id: str
    item_id: str
    reader_ids: tuple[str, ...]
    inspected_at: datetime
    no_privileged_workspace_readers: bool
    no_alternate_data_access: bool
    sql_endpoint_mode: str

    def validate(self, shard: RoleShard, now: datetime) -> None:
        inspected = _utc(self.inspected_at, "inspected_at")
        now = _utc(now, "now")
        if not timedelta(0) <= now - inspected <= timedelta(minutes=15):
            raise NativePolicyError("boundary attestation must be no more than 15 minutes old")
        if {_guid(x, "attested reader") for x in self.reader_ids} != set(shard.reader_ids):
            raise NativePolicyError("boundary attestation must cover exactly the shard audience")
        if (self.no_privileged_workspace_readers is not True or self.no_alternate_data_access is not True
                or self.sql_endpoint_mode not in ("UserIdentity", "DisabledForReaders")):
            raise NativePolicyError("reader bypass paths must be closed before publication")


@dataclass(frozen=True)
class RoleSnapshot:
    roles: tuple[dict[str, Any], ...]
    etag: str

    @property
    def digest(self) -> str:
        return _hash(sorted(self.roles, key=lambda r: r["name"]))


@dataclass(frozen=True)
class PublicationResult:
    status: str
    role_count: int
    policy_digest: str
    etag: str
    control_plane_verified: bool
    enforcement_verified: bool = False


@dataclass(frozen=True)
class WorkspaceBoundaryReview:
    """Fresh workspace check; item/SQL/other-workspace access is out of scope."""
    workspace_id: str
    inspected_at: datetime
    reader_count: int
    direct_privileged_readers: tuple[str, ...]
    unresolved_assignments: int

    @property
    def closed(self) -> bool:
        return not self.direct_privileged_readers and self.unresolved_assignments == 0


def _path_overlaps(scope: str, tables: set[str]) -> bool:
    path = scope.rstrip("/").lower()
    if not path.startswith("/"):
        path = "/" + path
    if "*" in path:
        return True  # Wildcards are intentionally not interpreted optimistically.
    return any(t == path or t.startswith(path + "/") or path.startswith(t + "/") for t in tables)


def _bypass_roles(roles: Iterable[dict[str, Any]], shard: RoleShard) -> list[str]:
    readers = set(shard.reader_ids)
    tables = {t.path.lower() for t in shard.tables}
    blocked = []
    for role in roles:
        overlaps = False
        rules = role.get("decisionRules")
        if not isinstance(rules, list) or not rules:
            overlaps = True
        else:
            for rule in rules:
                scopes = rule.get("permission", []) if isinstance(rule, dict) else []
                paths = [v for p in scopes if isinstance(p, dict) and p.get("attributeName") == "Path"
                         for v in p.get("attributeValueIncludedIn", [])]
                if not paths or any(not isinstance(p, str) or _path_overlaps(p, tables) for p in paths):
                    overlaps = True
        if not overlaps:
            continue
        members = role.get("members")
        if not isinstance(members, dict) or set(members) - {"microsoftEntraMembers", "fabricItemMembers"}:
            blocked.append(role.get("name", "<unnamed>"))
            continue
        potential_reader = bool(members.get("fabricItemMembers"))
        for member in members.get("microsoftEntraMembers", []):
            if not isinstance(member, dict) or member.get("objectType") != "User":
                potential_reader = True  # Group membership/service identities require a separate boundary.
                continue
            try:
                identity = _guid(member.get("objectId"), "existing member")
                tenant = _guid(member.get("tenantId"), "existing member tenant")
            except NativePolicyError:
                potential_reader = True
                continue
            if tenant != shard.tenant_id or identity in readers:
                potential_reader = True
        if potential_reader:
            blocked.append(role.get("name", "<unnamed>"))
    return blocked


def _semantic_roles(roles: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compare policy meaning across Fabric's documented/observed GET envelope.

    Fabric omits the User member discriminator and adds ``type: Fabric`` to
    static row constraints on persistence. These two default annotations are
    not changes to the policy. Explicit other member/constraint types remain
    in the comparison and therefore cannot masquerade as our canonical form.
    """
    cleaned = [{k: copy.deepcopy(v) for k, v in r.items() if k not in ("id", "eTag", "etag")}
               for r in roles]
    for role in cleaned:
        role.setdefault("kind", "Policy")
        for member in role.get("members", {}).get("microsoftEntraMembers", []):
            if isinstance(member, dict) and member.get("objectType") == "User":
                member.pop("objectType")
        for rule in role.get("decisionRules", []):
            if not isinstance(rule, dict):
                continue
            for row in rule.get("constraints", {}).get("rows", []):
                if isinstance(row, dict) and row.get("type") == "Fabric":
                    row.pop("type")
    return sorted(cleaned, key=lambda r: r["name"])


class FabricNativeClient:
    """Tenant-bound synchronous client for a single preprovisioned lakehouse.

    Inject an Azure TokenCredential (AzureCliCredential for development;
    managed identity or certificate credentials for service operation).
    Credentials must be scoped to this tenant. HTTP redirects are disabled.
    The client does not create items, share items, or change workspace roles.
    """

    def __init__(self, tenant_id: str, workspace_id: str, item_id: str,
                 credential: TokenCredential, *, http_client: httpx.Client | None = None,
                 clock: Callable[[], datetime] | None = None,
                 sleep: Callable[[float], None] = time.sleep, max_get_attempts: int = 4) -> None:
        self.tenant_id = _guid(tenant_id, "tenant_id")
        self.workspace_id = _guid(workspace_id, "workspace_id")
        self.item_id = _guid(item_id, "item_id")
        self.credential = credential
        self.item_url = f"{FABRIC_ROOT}/workspaces/{self.workspace_id}/items/{self.item_id}"
        self.roles_url = self.item_url + "/dataAccessRoles"
        self.workspace_roles_url = f"{FABRIC_ROOT}/workspaces/{self.workspace_id}/roleAssignments"
        self.http = http_client or httpx.Client(timeout=60, follow_redirects=False, trust_env=False)
        self._owns_http = http_client is None
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.sleep = sleep
        if not isinstance(max_get_attempts, int) or not 1 <= max_get_attempts <= 5:
            raise NativePolicyError("max_get_attempts must be between 1 and 5")
        self.max_get_attempts = max_get_attempts

    def close(self) -> None:
        if self._owns_http:
            self.http.close()

    def __enter__(self) -> FabricNativeClient:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _headers(self) -> dict[str, str]:
        try:
            token = self.credential.get_token(FABRIC_SCOPE).token
            encoded = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            if _guid(claims.get("tid"), "token tenant") != self.tenant_id:
                raise NativePolicyError("Azure credential tenant does not match configured tenant")
            if str(claims.get("aud", "")).rstrip("/") != "https://api.fabric.microsoft.com":
                raise NativePolicyError("Azure credential returned a token for an unexpected audience")
        except NativePolicyError:
            raise
        except Exception as exc:
            raise FabricRequestError("Unable to obtain a tenant-bound Fabric access token") from None
        return {"Authorization": "Bearer " + token, "Accept": "application/json"}

    def _route(self, method: str, url: str) -> None:
        parsed, expected = urlsplit(url), urlsplit(self.roles_url)
        if parsed.scheme != "https" or parsed.netloc != expected.netloc or parsed.fragment:
            raise NativePolicyError("Untrusted Fabric request URL")
        query = parse_qs(parsed.query, keep_blank_values=True)
        if method == "GET":
            if parsed.path == urlsplit(self.item_url).path and not parsed.query:
                return
            if (parsed.path in (expected.path, urlsplit(self.workspace_roles_url).path) and (not parsed.query or
                    set(query) == {"continuationToken"} and len(query["continuationToken"]) == 1)):
                return
        elif method == "PUT" and parsed.path == expected.path:
            if not parsed.query or parsed.query == "dryRun=true":
                return
        raise NativePolicyError("Request outside the exact item/role routes is forbidden")

    def _request(self, method: str, url: str, *, payload: dict[str, Any] | None = None,
                 etag: str | None = None) -> httpx.Response:
        self._route(method, url)
        headers = self._headers()
        if etag:
            if (not re.fullmatch(r'(?:"[^"\r\n]+"|[^"\r\n]+)', etag)
                    or etag in ("*", '"*"') or etag.startswith("W/")):
                raise NativePolicyError("A strong, specific ETag is required")
            headers["If-Match"] = etag if etag.startswith('"') and etag.endswith('"') else f'"{etag}"'
        if method == "PUT" and not etag:
            raise NativePolicyError("Role replacement requires If-Match")
        attempts = self.max_get_attempts if method == "GET" else 1
        for attempt in range(attempts):
            try:
                response = self.http.request(method, url, headers=headers, json=payload,
                                             follow_redirects=False)
            except httpx.TransportError:
                if method == "PUT":
                    raise PublicationUncertain("Fabric role PUT transport failed; inspect current roles before further action") from None
                if attempt + 1 == attempts:
                    raise FabricRequestError("Fabric GET transport failed after bounded retries") from None
                self.sleep(min(2**attempt, 10))
                continue
            if response.status_code in (429, 502, 503, 504) and method == "GET" and attempt + 1 < attempts:
                try:
                    delay = float(response.headers.get("Retry-After", 2**attempt))
                except ValueError:
                    delay = float(2**attempt)
                # Never retry earlier than a long service Retry-After. Stop instead.
                if delay > 30:
                    raise FabricRequestError("Fabric GET throttled beyond the bounded retry budget")
                self.sleep(max(0, delay))
                continue
            if response.status_code != 200:
                error_code, detail_codes = None, ()
                try:
                    body = response.json()
                    error = body.get("error", body) if isinstance(body, dict) else {}
                    if isinstance(error, dict):
                        error_code = error.get("errorCode") or error.get("code")
                        details = error.get("moreDetails", error.get("details", []))
                        if isinstance(details, list):
                            detail_codes = tuple(d.get("errorCode") or d.get("code") for d in details if isinstance(d, dict))
                except ValueError:
                    pass
                if method == "PUT" and response.status_code >= 500:
                    raise PublicationUncertain(f"Fabric role PUT HTTP {response.status_code}; inspect current roles before further action",
                                               status_code=response.status_code, error_code=error_code, detail_codes=detail_codes)
                raise FabricRequestError(f"Fabric {method} HTTP {response.status_code}", status_code=response.status_code,
                                         error_code=error_code, detail_codes=detail_codes)
            return response
        raise FabricRequestError("Fabric request did not complete")

    def get_item(self) -> dict[str, Any]:
        response = self._request("GET", self.item_url)
        try:
            item = response.json()
        except ValueError:
            raise FabricRequestError("Fabric item response was not JSON") from None
        if not isinstance(item, dict) or _guid(item.get("id"), "returned item") != self.item_id:
            raise NativePolicyError("Fabric returned an unexpected item")
        if item.get("type") != "Lakehouse":
            raise NativePolicyError("Native publication supports Lakehouse items only")
        return item

    def list_roles(self) -> RoleSnapshot:
        url, seen, rows, first_etag = self.roles_url, set(), [], None
        for _ in range(100):
            if url in seen:
                raise NativePolicyError("Repeated Fabric continuation URL")
            seen.add(url)
            response = self._request("GET", url)
            etag = response.headers.get("etag")
            if not etag or (first_etag is not None and etag != first_etag):
                raise NativePolicyError("Role collection lacks a consistent ETag")
            first_etag = etag
            try:
                body = response.json()
            except ValueError:
                raise FabricRequestError("Fabric role response was not JSON") from None
            if not isinstance(body, dict) or not isinstance(body.get("value"), list):
                raise NativePolicyError("Incomplete Fabric role collection")
            rows.extend(body["value"])
            if len(rows) > 1000:
                raise NativePolicyError("Role inventory exceeds supported item quota")
            next_url = body.get("continuationUri")
            if not next_url and body.get("continuationToken"):
                next_url = self.roles_url + "?" + urlencode({"continuationToken": body["continuationToken"]})
            if not next_url:
                names = [r.get("name") if isinstance(r, dict) else None for r in rows]
                if (any(not isinstance(n, str) or not n for n in names)
                        or len({n.casefold() for n in names}) != len(names)):
                    raise NativePolicyError("Malformed or duplicate role names")
                return RoleSnapshot(tuple(copy.deepcopy(rows)), first_etag)
            if not isinstance(next_url, str):
                raise NativePolicyError("Invalid role continuation URI")
            self._route("GET", next_url)
            url = next_url
        raise NativePolicyError("Role pagination bound exceeded")

    def inspect_workspace_boundary(self, reader_ids: Iterable[str]) -> WorkspaceBoundaryReview:
        """Fail closed on unresolved groups and any privileged direct reader.

        The GA workspace-role API requires Member or Admin. No Graph permissions
        are assumed and groups are not treated as empty when unresolved. Viewer
        roles do not bypass this item's OneLake rules, but can expose other
        workspace items: the separate boundary attestation must cover that.
        """
        readers = {_guid(r, "boundary reader") for r in reader_ids}
        url, seen, privileged, unresolved = self.workspace_roles_url, set(), set(), 0
        for _ in range(100):
            if url in seen:
                raise NativePolicyError("Repeated workspace-role continuation")
            seen.add(url)
            response = self._request("GET", url)
            try:
                body = response.json()
            except ValueError:
                raise FabricRequestError("Workspace-role response was not JSON") from None
            if not isinstance(body, dict) or not isinstance(body.get("value"), list):
                raise NativePolicyError("Incomplete workspace-role inventory")
            for assignment in body["value"]:
                if not isinstance(assignment, dict):
                    unresolved += 1
                    continue
                principal, role = assignment.get("principal"), assignment.get("role")
                if not isinstance(principal, dict) or role not in ("Admin", "Member", "Contributor", "Viewer"):
                    unresolved += 1
                    continue
                if principal.get("type") == "User":
                    identity = _guid(principal.get("id"), "workspace principal")
                    if identity in readers and role != "Viewer":
                        privileged.add(identity)
                elif principal.get("type") != "ServicePrincipal":
                    # Includes groups, EntireTenant, profiles and future unknown types.
                    unresolved += 1
            next_url = body.get("continuationUri")
            if not next_url and body.get("continuationToken"):
                next_url = self.workspace_roles_url + "?" + urlencode({"continuationToken": body["continuationToken"]})
            if not next_url:
                return WorkspaceBoundaryReview(self.workspace_id, self.clock(), len(readers),
                                               tuple(sorted(privileged)), unresolved)
            if not isinstance(next_url, str) or urlsplit(next_url).path != urlsplit(self.workspace_roles_url).path:
                raise NativePolicyError("Workspace-role continuation escaped its collection")
            self._route("GET", next_url)
            url = next_url
        raise NativePolicyError("Workspace-role pagination bound exceeded")

    def _owned(self, role: Mapping[str, Any], prefix: str) -> bool:
        name = role.get("name", "")
        reader_hex = _owned_role_reader(name, prefix)
        if reader_hex is None:
            return False
        members = role.get("members", {})
        if not isinstance(members, dict) or set(members) != {"microsoftEntraMembers"}:
            raise NativePolicyError("Unrecognized role occupies the owned namespace; refusing replacement")
        identities = members.get("microsoftEntraMembers")
        if not isinstance(identities, list) or len(identities) != 1:
            raise NativePolicyError("Owned role must have exactly one reader")
        member = identities[0]
        # GET currently drops objectType for our explicitly User-only PUTs.
        # Ownership remains bound to tenant and the GUID in the canonical role
        # name. This is not a directory-user assertion: publication separately
        # validates readers against Dataverse, and the watchdog only withdraws.
        if (not isinstance(member, dict) or member.get("objectType", "User") != "User"
                or _guid(member.get("tenantId"), "owned role tenant") != self.tenant_id
                or _guid(member.get("objectId"), "owned reader").replace("-", "") != reader_hex):
            raise NativePolicyError("Owned role identity does not match its namespace")
        return True

    def _merge(self, snapshot: RoleSnapshot, shard: RoleShard) -> dict[str, Any]:
        if shard.tenant_id != self.tenant_id:
            raise NativePolicyError("Plan tenant does not match Fabric client")
        unowned, previous = [], {}
        for role in snapshot.roles:
            if self._owned(role, shard.ownership_prefix):
                previous[role["name"]] = role
            else:
                unowned.append(copy.deepcopy(role))
        if _bypass_roles(unowned, shard):
            raise NativePolicyError("Unmanaged overlapping roles may bypass reader RLS/CLS; review or isolate the serving item")
        planned = shard.roles
        existing_generations = set()
        for old in previous.values():
            rules = old.get("decisionRules")
            if not isinstance(rules, list) or not rules:
                raise NativePolicyError("Owned policy has no recognizable generation; inspect before replacement")
            for rule in rules:
                rows = rule.get("constraints", {}).get("rows", [])
                if not rows:
                    raise NativePolicyError("Owned policy has no recognizable generation; inspect before replacement")
                for row in rows:
                    match = re.search(r"\b__pw_generation = ([1-9][0-9]*)\s*$", str(row.get("value", "")))
                    if not match:
                        raise NativePolicyError("Owned policy has no recognizable generation; inspect before replacement")
                    existing_generations.add(int(match[1]))
        if existing_generations:
            if len(existing_generations) != 1:
                raise NativePolicyError("Owned policies have inconsistent generations; inspect or withdraw")
            latest = max(existing_generations)
            if shard.generation < latest:
                raise NativePolicyError("Refusing to republish an older security generation")
            if shard.generation == latest and _semantic_roles(previous.values()) != _semantic_roles(planned):
                raise NativePolicyError("A security generation is immutable; changed policies require a new generation")
        for role in planned:
            old = previous.get(role["name"])
            if old and old.get("id"):
                role["id"] = old["id"]
        if len(unowned) + len(planned) > shard.role_limit:
            raise NativePolicyError("Merged role collection exceeds configured item quota")
        return {"value": unowned + planned}

    def _check_dry_run(self, snapshot: RoleSnapshot, payload: dict[str, Any]) -> None:
        self._request("PUT", self.roles_url + "?dryRun=true", payload=payload, etag=snapshot.etag)
        after = self.list_roles()
        if after.etag != snapshot.etag or after.digest != snapshot.digest:
            raise PublicationUncertain("Role collection changed during dry run; refusing publication or automatic repair")

    def dry_run(self, shard: RoleShard) -> PublicationResult:
        self.get_item()
        snapshot = self.list_roles()
        payload = self._merge(snapshot, shard)
        self._check_dry_run(snapshot, payload)
        return PublicationResult("dry_run_validated", len(payload["value"]),
                                 _hash(_semantic_roles(payload["value"])), snapshot.etag, True)

    def publish(self, shard: RoleShard, receipt: DataReadyReceipt,
                boundary: BoundaryAttestation) -> PublicationResult:
        """Replace owned roles only after data and boundary checks; no retries.

        The generation switch is one role-collection PUT per item. A multi-item
        plan is not a distributed transaction: the controller must withdraw
        affected items if its batch cannot finish before the freshness deadline.
        """
        for assertion in (receipt, boundary):
            if (_guid(assertion.workspace_id, "assertion workspace") != self.workspace_id
                    or _guid(assertion.item_id, "assertion item") != self.item_id):
                raise NativePolicyError("Publication assertions must bind this workspace and item")
        receipt.validate(shard, self.clock())
        boundary.validate(shard, self.clock())
        self.get_item()
        snapshot = self.list_roles()
        payload = self._merge(snapshot, shard)
        self._check_dry_run(snapshot, payload)
        receipt.validate(shard, self.clock())
        boundary.validate(shard, self.clock())
        if not self.inspect_workspace_boundary(shard.reader_ids).closed:
            raise NativePolicyError("Workspace roles contain privileged readers or unresolved group access")
        receipt.validate(shard, self.clock())
        self._request("PUT", self.roles_url, payload=payload, etag=snapshot.etag)
        try:
            after = self.list_roles()
        except (FabricRequestError, NativePolicyError):
            raise PublicationUncertain("Role PUT returned success but control-plane verification failed; inspect before further action") from None
        if _semantic_roles(after.roles) != _semantic_roles(payload["value"]):
            raise PublicationUncertain("Published role payload does not match the subsequent inventory; do not restore previous grants")
        if self.clock() >= _utc(receipt.valid_until, "valid_until"):
            raise PublicationUncertain("Publication completed after freshness expiry; withdraw current owned roles")
        return PublicationResult("published_control_plane_verified", len(after.roles),
                                 _hash(_semantic_roles(after.roles)), after.etag, True)

    def withdraw(self, ownership_prefix: str = "PolicyWeaver_") -> PublicationResult:
        """Remove only this deployment's reader roles, preserving unowned roles.

        Idempotent at the policy level but PUT is never retried automatically.
        This does not remove unrelated bypass permissions or invalidate caches.
        """
        if not _PREFIX.fullmatch(ownership_prefix):
            raise NativePolicyError("Invalid ownership prefix")
        snapshot = self.list_roles()
        remaining = [copy.deepcopy(r) for r in snapshot.roles if not self._owned(r, ownership_prefix)]
        if len(remaining) == len(snapshot.roles):
            return PublicationResult("already_withdrawn", len(remaining),
                                     _hash(_semantic_roles(remaining)), snapshot.etag, True)
        payload = {"value": remaining}
        self._request("PUT", self.roles_url, payload=payload, etag=snapshot.etag)
        try:
            after = self.list_roles()
        except (FabricRequestError, NativePolicyError):
            raise PublicationUncertain("Withdrawal returned success but verification failed; inspect current roles") from None
        if _semantic_roles(after.roles) != _semantic_roles(remaining):
            raise PublicationUncertain("Withdrawal inventory differs from expected roles")
        return PublicationResult("withdrawn_control_plane_verified", len(after.roles),
                                 _hash(_semantic_roles(after.roles)), after.etag, True)
