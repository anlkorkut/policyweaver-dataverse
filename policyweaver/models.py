"""Normalized, organization-scoped read facts. Names never serve as identity keys."""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Fact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Identified(Fact):
    id: str

    @field_validator("id")
    @classmethod
    def canonical_id(cls, value: str) -> str:
        return str(UUID(value))


class BusinessUnit(Identified):
    name: str
    parent_id: str | None = None


class User(Identified):
    name: str
    entra_object_id: str | None
    bu_id: str
    enabled: bool = True
    access_mode: int = 0
    application: bool = False


class Team(Identified):
    name: str
    bu_id: str
    kind: Literal["owner", "access", "group"] = "owner"
    membership_verified: bool = True


class Column(Fact):
    name: str
    secured: bool = False
    masked: bool = False


class Table(Fact):
    name: str
    ownership: Literal["user_team", "organization"]
    columns: tuple[Column, ...] = ()


class ReadGrant(Fact):
    table: str
    depth: Literal["Basic", "Local", "Deep", "Global"]


class Role(Identified):
    name: str
    bu_id: str
    grants: tuple[ReadGrant, ...]
    member_basic: bool = False


class Assignment(Fact):
    principal_id: str
    principal_type: Literal["user", "team"]
    role_id: str


class Membership(Fact):
    user_id: str
    team_id: str


class Record(Identified):
    table: str
    owner_id: str | None = None
    owning_bu_id: str | None = None


class RecordAccess(Fact):
    """Verified effective read exception; ingestion must resolve cascade/hierarchy first."""
    principal_id: str
    principal_type: Literal["user", "team"]
    table: str
    record_id: str
    kind: Literal["share", "hierarchy"]
    evidence: str = Field(min_length=1)


class FieldPermission(Fact):
    table: str
    column: str
    can_read: bool
    read_unmasked: Literal["none", "one", "all"] = "none"


class Profile(Identified):
    name: str
    permissions: tuple[FieldPermission, ...]


class ProfileAssignment(Fact):
    profile_id: str
    principal_id: str
    principal_type: Literal["user", "team"]


class Snapshot(Fact):
    tenant_id: str
    organization_id: str
    observed_at: datetime
    valid_until: datetime
    source_kind: Literal["synthetic", "normalized"] = "normalized"
    # These are evidence assertions in a local simulation, never sufficient for publication.
    blockers: tuple[str, ...] = ()
    business_units: tuple[BusinessUnit, ...]
    users: tuple[User, ...]
    teams: tuple[Team, ...]
    tables: tuple[Table, ...]
    roles: tuple[Role, ...]
    assignments: tuple[Assignment, ...]
    memberships: tuple[Membership, ...]
    records: tuple[Record, ...]
    record_access: tuple[RecordAccess, ...] = ()
    profiles: tuple[Profile, ...] = ()
    profile_assignments: tuple[ProfileAssignment, ...] = ()

    @field_validator("tenant_id", "organization_id")
    @classmethod
    def canonical_id(cls, value: str) -> str:
        return str(UUID(value))

    @model_validator(mode="after")
    def verify_graph(self) -> "Snapshot":
        def index(items, key="id"):
            result = {}
            for item in items:
                value = getattr(item, key)
                if value in result:
                    raise ValueError(f"Duplicate {key}: {value}; reconcile source versions first")
                result[value] = item
            return result

        def require(value, values, kind):
            if value not in values:
                raise ValueError(f"Unresolved {kind}: {value}")

        if self.observed_at.tzinfo is None or self.valid_until.tzinfo is None:
            raise ValueError("Snapshot times must include a timezone")
        if self.valid_until <= self.observed_at:
            raise ValueError("Snapshot validity must end after observation")
        bus, users, teams, roles, profiles = [index(x) for x in (
            self.business_units, self.users, self.teams, self.roles, self.profiles)]
        tables = index(self.tables, "name")
        records = {(r.table, r.id): r for r in self.records}
        if len(records) != len(self.records):
            raise ValueError("Duplicate table/record key")
        if users.keys() & teams.keys():
            raise ValueError("Ambiguous user/team principal")
        if not bus or sum(b.parent_id is None for b in bus.values()) != 1:
            raise ValueError("Require exactly one business-unit root")
        for bu in bus.values():
            seen = {bu.id}
            parent = bu.parent_id
            while parent:
                require(parent, bus, "parent BU")
                if parent in seen:
                    raise ValueError("Business-unit hierarchy contains a cycle")
                seen.add(parent)
                parent = bus[parent].parent_id
        identity_ids = set()
        for user in users.values():
            if user.entra_object_id:
                oid = str(UUID(user.entra_object_id))
                if oid != user.entra_object_id or oid in identity_ids:
                    raise ValueError("Ambiguous or noncanonical Entra identity")
                identity_ids.add(oid)
        for principal in (*users.values(), *teams.values(), *roles.values()):
            require(principal.bu_id, bus, "BU")
        for table in tables.values():
            index(table.columns, "name")
        for role in roles.values():
            index(role.grants, "table")
            for grant in role.grants:
                require(grant.table, tables, "table")
                if tables[grant.table].ownership == "organization" and grant.depth != "Global":
                    raise ValueError("Organization-owned tables require Global read")
        for edge in self.assignments:
            require(edge.principal_id, users if edge.principal_type == "user" else teams, "principal")
            require(edge.role_id, roles, "role")
            if edge.principal_type == "team" and teams[edge.principal_id].kind == "access":
                raise ValueError("Access teams cannot hold security roles")
        for edge in self.memberships:
            require(edge.user_id, users, "user")
            require(edge.team_id, teams, "team")
        for record in records.values():
            require(record.table, tables, "table")
            if tables[record.table].ownership == "user_team":
                require(record.owner_id, users.keys() | teams.keys(), "owner")
                require(record.owning_bu_id, bus, "owning BU")
                if record.owner_id in teams and teams[record.owner_id].kind == "access":
                    raise ValueError("Access teams cannot own records")
        for access in self.record_access:
            require((access.table, access.record_id), records, "shared/hierarchy record")
            require(access.principal_id, users if access.principal_type == "user" else teams, "principal")
        for profile in profiles.values():
            permission_keys = set()
            for permission in profile.permissions:
                require(permission.table, tables, "table")
                require(permission.column, {c.name for c in tables[permission.table].columns}, "column")
                key = (permission.table, permission.column)
                if key in permission_keys:
                    raise ValueError("Duplicate field permission")
                permission_keys.add(key)
        for edge in self.profile_assignments:
            require(edge.profile_id, profiles, "profile")
            require(edge.principal_id, users if edge.principal_type == "user" else teams, "principal")
        return self

