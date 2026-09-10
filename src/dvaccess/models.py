"""Core domain models shared across extract, compile, and apply stages."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum

# Sentinel scope meaning "all rows of the table" (no RLS predicate needed).
ALL_ROWS = "ALL"

# A table scope is either ALL_ROWS or a frozenset of business-unit GUIDs.
Scope = str | frozenset


class Depth(StrEnum):
    """Dataverse privilege depth. Access is cumulative: Global > Deep > Local > Basic."""

    BASIC = "Basic"
    LOCAL = "Local"
    DEEP = "Deep"
    GLOBAL = "Global"

    @property
    def rank(self) -> int:
        return _DEPTH_RANK[self]


_DEPTH_RANK = {Depth.BASIC: 1, Depth.LOCAL: 2, Depth.DEEP: 3, Depth.GLOBAL: 4}

# PrivilegeDepth enum values as returned by RetrieveRolePrivilegesRole when numeric.
_DEPTH_FROM_ENUM = {0: Depth.BASIC, 1: Depth.LOCAL, 2: Depth.DEEP, 3: Depth.GLOBAL}


def parse_depth(value: object) -> Depth:
    """Parse a PrivilegeDepth from RetrieveRolePrivilegesRole output.

    The Web API serializes the enum as a string name ("Basic"/"Local"/"Deep"/"Global");
    numeric 0-3 (the PrivilegeDepth enum) is accepted defensively. Do NOT feed
    privilegedepthmask bit values (1/2/4/8) through this function - 1 and 2 would be
    misread as Local and Deep.
    """
    if isinstance(value, Depth):
        return value
    if isinstance(value, str):
        v = value.strip()
        for d in Depth:
            if d.value.lower() == v.lower():
                return d
        if v.isdigit():
            value = int(v)
    if isinstance(value, int) and value in _DEPTH_FROM_ENUM:
        return _DEPTH_FROM_ENUM[value]
    raise ValueError(f"Unrecognized privilege depth: {value!r}")


class Ownership(StrEnum):
    """Table ownership. Determines whether depth semantics apply to reads and, when
    they do, which column carries the business unit for the RLS predicate."""

    USER = "user"  # user/team owned: rows carry owningbusinessunit
    BUSINESS = "business"  # business owned: rows carry businessunitid
    ORG = "org"  # organization owned or no ownership: any read grants all rows


def parse_ownership(value: object) -> Ownership:
    """Map EntityDefinitions.OwnershipType (string name or OwnershipTypes int) to Ownership."""
    if isinstance(value, Ownership):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if "organization" in v or v in ("none", ""):
            return Ownership.ORG
        if "business" in v:  # BusinessOwned, BusinessParentChild
            return Ownership.BUSINESS
        return Ownership.USER
    if isinstance(value, int):
        # OwnershipTypes: None=0, UserOwned=1, TeamOwned=2, BusinessOwned=4,
        # OrganizationOwned=8, BusinessParentChild=16
        if value in (0, 8):
            return Ownership.ORG
        if value in (4, 16):
            return Ownership.BUSINESS
        return Ownership.USER
    # Unknown metadata: treat as user-owned (fail closed: depth restrictions apply).
    return Ownership.USER


class TeamType:
    OWNER = 0
    ACCESS = 1
    AAD_SECURITY_GROUP = 2
    AAD_OFFICE_GROUP = 3

    AAD_TYPES = (AAD_SECURITY_GROUP, AAD_OFFICE_GROUP)


@dataclass
class BusinessUnit:
    id: str
    name: str
    parent_id: str | None


@dataclass
class DvUser:
    id: str
    name: str
    domain_name: str | None
    aad_object_id: str | None
    bu_id: str
    is_disabled: bool
    access_mode: int
    application_id: str | None


@dataclass
class DvTeam:
    id: str
    name: str
    bu_id: str
    team_type: int
    aad_object_id: str | None


@dataclass
class DvRole:
    """A security-role instance. Dataverse stamps one copy of each role per business
    unit; copies share parentrootroleid, which is the canonical (root) role identity."""

    id: str
    name: str
    bu_id: str
    root_role_id: str | None


@dataclass
class TableMeta:
    logical_name: str
    schema_name: str
    object_type_code: int | None
    ownership: Ownership


@dataclass
class RoleReadGrant:
    """A read privilege held by a role instance, resolved to a target table."""

    role_id: str
    table: str  # entity logical name
    depth: Depth
    privilege_name: str = ""


@dataclass
class FieldSecurityProfile:
    id: str
    name: str


@dataclass
class FieldPermission:
    profile_id: str
    table: str
    attribute: str
    can_read: int  # 4 = allowed


@dataclass
class Snapshot:
    """Raw, point-in-time extract of the Dataverse security model."""

    run_id: str
    observed_at: str
    environment_url: str
    business_units: list[BusinessUnit] = field(default_factory=list)
    users: list[DvUser] = field(default_factory=list)
    teams: list[DvTeam] = field(default_factory=list)
    roles: list[DvRole] = field(default_factory=list)
    tables: list[TableMeta] = field(default_factory=list)
    role_grants: list[RoleReadGrant] = field(default_factory=list)
    user_roles: list[tuple[str, str]] = field(default_factory=list)  # (user_id, role_id)
    team_roles: list[tuple[str, str]] = field(default_factory=list)  # (team_id, role_id)
    team_members: list[tuple[str, str]] = field(default_factory=list)  # (team_id, user_id)
    fsps: list[FieldSecurityProfile] = field(default_factory=list)
    field_permissions: list[FieldPermission] = field(default_factory=list)
    user_fsps: list[tuple[str, str]] = field(default_factory=list)  # (user_id, profile_id)
    team_fsps: list[tuple[str, str]] = field(default_factory=list)  # (team_id, profile_id)
    unmatched_privileges: list[str] = field(default_factory=list)

    def counts(self) -> dict:
        return {
            "business_units": len(self.business_units),
            "users": len(self.users),
            "teams": len(self.teams),
            "role_instances": len(self.roles),
            "root_roles": len({r.root_role_id or r.id for r in self.roles}),
            "tables_with_metadata": len(self.tables),
            "role_read_grants": len(self.role_grants),
            "user_role_assignments": len(self.user_roles),
            "team_role_assignments": len(self.team_roles),
            "team_memberships": len(self.team_members),
            "field_security_profiles": len(self.fsps),
            "field_permissions": len(self.field_permissions),
            "unmatched_read_privileges": len(self.unmatched_privileges),
        }


@dataclass
class SkippedUser:
    user_id: str
    name: str
    reason: str


@dataclass
class BasicExclusion:
    """A (user, table) pair where Basic-depth (own-records) access could not be
    represented in OneLake and was fail-closed excluded (or partially excluded)."""

    user_id: str
    user_name: str
    table: str
    kind: str  # "basic_only": no access granted; "basic_partial": BU grants kept, own-records part dropped


@dataclass
class CompileDiagnostics:
    skipped_users: list[SkippedUser] = field(default_factory=list)
    basic_exclusions: list[BasicExclusion] = field(default_factory=list)
    tables_without_metadata: list[str] = field(default_factory=list)
    tables_excluded_by_filter: list[str] = field(default_factory=list)
    # Granted in Dataverse but not present in the target Fabric item (not synced).
    tables_absent_from_item: list[str] = field(default_factory=list)


@dataclass
class Profile:
    """An access profile: the equivalence class of users sharing identical effective
    read access. One Entra group and one OneLake role family per profile."""

    profile_hash: str
    scopes: dict  # table -> Scope
    user_ids: list[str] = field(default_factory=list)
    fsp_signature: tuple = ()

    @property
    def short_hash(self) -> str:
        return self.profile_hash[:12]


def canonical_scope_key(scopes: dict, fsp_signature: tuple = ()) -> str:
    """Deterministic hash of an effective-access map. Sorted, JSON-canonical."""
    payload = {
        "tables": sorted(
            (t, s if s == ALL_ROWS else sorted(s)) for t, s in scopes.items()
        ),
        "fsp": sorted(fsp_signature),
    }
    blob = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class RoleDefinition:
    """A single OneLake data access role to be emitted (one chunk of a profile)."""

    name: str
    profile_hash: str
    table_paths: list[str] = field(default_factory=list)
    row_constraints: list[tuple[str, str]] = field(default_factory=list)  # (tablePath, T-SQL)
    column_constraints: list[dict] = field(default_factory=list)
    entra_group_id: str | None = None
    entra_user_ids: list[str] = field(default_factory=list)

    def to_api(self, tenant_id: str) -> dict:
        members: list[dict] = []
        if self.entra_group_id:
            members.append(
                {"objectId": self.entra_group_id, "tenantId": tenant_id, "objectType": "Group"}
            )
        members.extend(
            {"objectId": uid, "tenantId": tenant_id, "objectType": "User"}
            for uid in self.entra_user_ids
        )
        rule: dict = {
            "effect": "Permit",
            "permission": [
                {"attributeName": "Path", "attributeValueIncludedIn": list(self.table_paths)},
                {"attributeName": "Action", "attributeValueIncludedIn": ["Read"]},
            ],
        }
        constraints: dict = {}
        if self.row_constraints:
            constraints["rows"] = [
                {"tablePath": path, "value": predicate}
                for path, predicate in self.row_constraints
            ]
        if self.column_constraints:
            constraints["columns"] = list(self.column_constraints)
        if constraints:
            rule["constraints"] = constraints
        return {
            "name": self.name,
            "decisionRules": [rule],
            "members": {"microsoftEntraMembers": members},
        }
