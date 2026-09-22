"""Qualified, immutable READ authorization facts and a shadow compiler.

This module is deliberately not an alternative to Dataverse impersonation.  A
normalizer must qualify the source's Basic/team rules, hierarchy, security-parent
rules, membership, masking and privilege metadata before constructing these
facts.  ``complete=True`` is an assertion by that normalizer, not proof of parity.
No decision or projection from this module authorizes Fabric publication.

Identity keys and Read privilege IDs are used verbatim; display-name parsing is
never used.  In particular, an Activity Read privilege can resolve to multiple
table metadata entries with the same privilege ID.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, fields, is_dataclass
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
import math
from types import MappingProxyType
from typing import Any, Literal, Mapping, Protocol


READ_ACCESS = 1
# Dataverse AccessRights: Read, Write, Append, AppendTo, Create, Delete, Share, Assign.
KNOWN_ACCESS_MASK = 1 | 2 | 4 | 16 | 32 | 65536 | 262144 | 524288
Scalar = str | int | float | bool | None | date | datetime | Decimal


class AuthorizationFactsError(ValueError):
    """Facts are incomplete, contradictory, unsupported, or have dangling keys."""


@dataclass(frozen=True, slots=True)
class Evidence:
    id: str
    source: str
    detail: str


@dataclass(frozen=True, slots=True)
class PrincipalRef:
    kind: Literal["user", "team", "organization"]
    id: str


@dataclass(frozen=True, slots=True)
class BusinessUnitFact:
    id: str
    parent_id: str | None
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class ReaderFact:
    """Referenced source user; users without Entra identity can own records.

    Such users cannot be evaluated as eligible Fabric readers.  This permits
    records owned by system/application users outside the publication audience.
    """
    id: str
    entra_object_id: str | None
    business_unit_id: str
    evidence: Evidence
    enabled: bool = True
    application: bool = False
    access_mode: int = 0


@dataclass(frozen=True, slots=True)
class TeamFact:
    id: str
    business_unit_id: str
    kind: Literal["owner", "access", "group_owner", "group_access"]
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class TeamMembershipFact:
    reader_id: str
    team_id: str
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class ColumnFact:
    name: str
    secured: bool = False
    masked: bool = False


@dataclass(frozen=True, slots=True)
class TableFact:
    name: str
    read_privilege_id: str
    ownership: Literal["user_team", "business_unit", "organization"]
    columns: tuple[ColumnFact, ...]
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class ReadContext:
    """One qualified effective privilege; never collapse distinct BU anchors.

    ``member_basic`` records the qualified team-role inheritance setting.  It is
    explanatory evidence, not an instruction to guess ``personal_basic``.  The
    independently qualified BasicQualification supplies ownership/share scope.
    """
    id: str
    reader_id: str
    privilege_id: str
    depth: Literal["Basic", "Local", "Deep", "Global"]
    business_unit_anchor: str
    source_principal: PrincipalRef
    member_basic: bool
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class BasicQualification:
    """Source-qualified Basic closure for one effective reader/table pair.

    All sets must be supplied even when empty.  Team-only personal Basic and POA
    applicability are deliberately not inferred.  ``owner_principals`` determines
    ownership access, ``sharing_principals`` determines which POA principals are
    usable.  ``business_units`` explicitly handles qualified Basic on tables with
    BU ownership.  An enabled reader still needs a table Read context first.
    """
    reader_id: str
    table: str
    personal_basic: bool
    owner_principals: tuple[PrincipalRef, ...]
    sharing_principals: tuple[PrincipalRef, ...]
    business_units: tuple[str, ...]
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class RecordFact:
    id: str
    table: str
    owner: PrincipalRef | None
    owning_business_unit_id: str | None
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class PoaFact:
    id: str
    table: str
    record_id: str
    principal: PrincipalRef
    access_rights_mask: int
    inherited_access_rights_mask: int
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class QualifiedRecordGrant:
    """Explicit source-qualified extra scope; no hierarchy is inferred here."""
    id: str
    reader_id: str
    table: str
    record_id: str
    kind: Literal["hierarchy", "security_parent", "source_verified"]
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class FieldProfileFact:
    id: str
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class FieldProfileAssignment:
    profile_id: str
    principal: PrincipalRef
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class FieldPermissionFact:
    profile_id: str
    table: str
    column: str
    can_read: bool
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class RecordFieldGrant:
    """Normalized PrincipalObjectAttributeAccess Read, not a row grant."""
    id: str
    table: str
    record_id: str
    column: str
    principal: PrincipalRef
    can_read: bool
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class AuthorizationSnapshot:
    tenant_id: str
    organization_id: str
    observed_at: datetime
    valid_until: datetime
    complete: bool
    qualification: Evidence
    business_units: tuple[BusinessUnitFact, ...]
    readers: tuple[ReaderFact, ...]
    teams: tuple[TeamFact, ...]
    memberships: tuple[TeamMembershipFact, ...]
    tables: tuple[TableFact, ...]
    contexts: tuple[ReadContext, ...]
    basic_qualifications: tuple[BasicQualification, ...]
    records: tuple[RecordFact, ...]
    poa: tuple[PoaFact, ...] = ()
    record_grants: tuple[QualifiedRecordGrant, ...] = ()
    field_profiles: tuple[FieldProfileFact, ...] = ()
    profile_assignments: tuple[FieldProfileAssignment, ...] = ()
    field_permissions: tuple[FieldPermissionFact, ...] = ()
    record_field_grants: tuple[RecordFieldGrant, ...] = ()
    blockers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Reason:
    code: str
    detail: str
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class RowDecision:
    reader_id: str
    table: str
    record_id: str
    allowed: bool
    reasons: tuple[Reason, ...]
    snapshot_id: str
    publication_authorized: Literal[False] = False


@dataclass(frozen=True, slots=True)
class ProjectedCell:
    column: str
    value: Scalar
    state: Literal["value", "denied_null", "qualified_masked_value"]
    reasons: tuple[Reason, ...]


@dataclass(frozen=True, slots=True)
class ProjectedRow:
    decision: RowDecision
    cells: tuple[ProjectedCell, ...]

    @property
    def values(self) -> Mapping[str, Scalar]:
        return MappingProxyType({cell.column: cell.value for cell in self.cells})


@dataclass(frozen=True, slots=True)
class SafeMaskedValue:
    """Value obtained from a separately qualified source masking projection."""
    value: Scalar
    evidence: Evidence


class MaskedValueProvider(Protocol):
    def project(self, reader_id: str, table: str, record_id: str, column: str) -> SafeMaskedValue:
        """Return source-qualified visible value; raw values are never supplied."""


def _nonempty(value: Any, description: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise AuthorizationFactsError(f"{description} must be a nonempty string")


def _evidence(value: Evidence) -> None:
    if not isinstance(value, Evidence):
        raise AuthorizationFactsError("Every qualification requires Evidence")
    for name in ("id", "source", "detail"):
        _nonempty(getattr(value, name), f"Evidence.{name}")


def _scalar(value: Any) -> None:
    if value is not None and not isinstance(value, (str, int, float, bool, date, Decimal)):
        raise AuthorizationFactsError("Projection supports only normalized scalar values")
    if isinstance(value, float) and not math.isfinite(value):
        raise AuthorizationFactsError("Projection cannot contain NaN or infinity")
    if isinstance(value, Decimal) and not value.is_finite():
        raise AuthorizationFactsError("Projection cannot contain nonfinite decimals")


def _canonical(value: Any) -> Any:
    if is_dataclass(value):
        return {f.name: _canonical(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, tuple):
        return [_canonical(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


class AuthorizationCompiler:
    """Validate normalized facts, then explain row decisions and NULL projections.

    Construction rejects incomplete facts instead of returning an empty plan that
    could be mistaken for success.  Unknown requests, disabled readers and expired
    snapshots deny.  Instances support concurrent reads: indexes are built once,
    then exposed only through methods returning immutable results.
    """

    def __init__(self, snapshot: AuthorizationSnapshot, *, masked_value_provider: MaskedValueProvider | None = None):
        if not isinstance(snapshot, AuthorizationSnapshot):
            raise AuthorizationFactsError("Expected an AuthorizationSnapshot")
        self.snapshot = snapshot
        self._masked_value_provider = masked_value_provider
        self._validate()
        if any(c.masked for t in snapshot.tables for c in t.columns) and not callable(
                getattr(masked_value_provider, "project", None)):
            raise AuthorizationFactsError("Masked columns require a qualified safe-value provider")
        encoded = json.dumps(_canonical(snapshot), sort_keys=True, separators=(",", ":"))
        self.snapshot_id = hashlib.sha256(encoded.encode()).hexdigest()
        self._contexts: dict[tuple[str, str], tuple[ReadContext, ...]] = {}
        context_lists: dict[tuple[str, str], list[ReadContext]] = defaultdict(list)
        for context in snapshot.contexts:
            for table in self._privilege_tables[context.privilege_id]:
                context_lists[(context.reader_id, table)].append(context)
        self._contexts = {key: tuple(value) for key, value in context_lists.items()}
        self._poa = self._group(snapshot.poa, lambda f: (f.table, f.record_id))
        self._record_grants = self._group(snapshot.record_grants, lambda f: (f.reader_id, f.table, f.record_id))
        self._field_grants = self._group(snapshot.record_field_grants, lambda f: (f.table, f.record_id, f.column))
        self._profile_assignments = self._group(snapshot.profile_assignments, lambda f: f.principal)
        self._field_permissions = self._group(snapshot.field_permissions, lambda f: (f.table, f.column))

    @staticmethod
    def _group(items, key):
        result = defaultdict(list)
        for item in items:
            result[key(item)].append(item)
        return {k: tuple(v) for k, v in result.items()}

    def _validate(self) -> None:
        s = self.snapshot
        _nonempty(s.tenant_id, "tenant_id")
        _nonempty(s.organization_id, "organization_id")
        _evidence(s.qualification)
        if s.complete is not True or s.blockers:
            raise AuthorizationFactsError("Incomplete authorization facts cannot be compiled")
        if not all(isinstance(t, datetime) and t.tzinfo is not None and t.utcoffset() is not None
                   for t in (s.observed_at, s.valid_until)):
            raise AuthorizationFactsError("Snapshot times must be timezone-aware")
        if not timedelta(0) < s.valid_until - s.observed_at <= timedelta(minutes=60):
            raise AuthorizationFactsError("Snapshot lease must be positive and no longer than 60 minutes")
        # Frozen dataclasses containing lists would not provide an immutable fact set.
        for f in fields(s):
            value = getattr(s, f.name)
            if f.name not in {"tenant_id", "organization_id", "observed_at", "valid_until", "complete", "qualification"}:
                if not isinstance(value, tuple):
                    raise AuthorizationFactsError(f"{f.name} must be an immutable tuple")

        def index(items, expected, key=lambda x: x.id):
            result = {}
            for item in items:
                if not isinstance(item, expected):
                    raise AuthorizationFactsError(f"Expected {expected.__name__} fact")
                _evidence(item.evidence)
                k = key(item)
                for part in (k if isinstance(k, tuple) else (k,)):
                    _nonempty(part, "Fact identity")
                if k in result:
                    raise AuthorizationFactsError(f"Duplicate {expected.__name__} identity: {k}")
                result[k] = item
            return result

        def require(key, collection, description):
            if key not in collection:
                raise AuthorizationFactsError(f"Unresolved {description}: {key}")

        self._bus = index(s.business_units, BusinessUnitFact)
        self._readers = index(s.readers, ReaderFact)
        self._teams = index(s.teams, TeamFact)
        self._tables = index(s.tables, TableFact, lambda x: x.name)
        self._records = index(s.records, RecordFact, lambda x: (x.table, x.id))
        self._basic = index(s.basic_qualifications, BasicQualification, lambda x: (x.reader_id, x.table))
        profiles = index(s.field_profiles, FieldProfileFact)
        index(s.contexts, ReadContext)
        index(s.poa, PoaFact)
        index(s.record_grants, QualifiedRecordGrant)
        index(s.record_field_grants, RecordFieldGrant)
        if self._readers.keys() & self._teams.keys() or s.organization_id in self._readers or s.organization_id in self._teams:
            raise AuthorizationFactsError("User, team and organization principal IDs must be disjoint")
        if not self._bus or sum(b.parent_id is None for b in s.business_units) != 1:
            raise AuthorizationFactsError("Require exactly one BU root")
        self._ancestors = {}
        for bu in s.business_units:
            ancestors = {bu.id}
            parent = bu.parent_id
            while parent is not None:
                require(parent, self._bus, "parent BU")
                if parent in ancestors:
                    raise AuthorizationFactsError("Business-unit cycle")
                ancestors.add(parent)
                parent = self._bus[parent].parent_id
            self._ancestors[bu.id] = frozenset(ancestors)
        entra_ids = set()
        for reader in s.readers:
            require(reader.business_unit_id, self._bus, "reader BU")
            if reader.entra_object_id is not None:
                _nonempty(reader.entra_object_id, "Reader Entra identity")
                if reader.entra_object_id in entra_ids:
                    raise AuthorizationFactsError("Duplicate Entra identity")
                entra_ids.add(reader.entra_object_id)
            if type(reader.enabled) is not bool or type(reader.application) is not bool or type(reader.access_mode) is not int:
                raise AuthorizationFactsError("Reader eligibility flags require exact bool/int types")
        for team in s.teams:
            require(team.business_unit_id, self._bus, "team BU")
            if team.kind not in {"owner", "access", "group_owner", "group_access"}:
                raise AuthorizationFactsError("Unsupported team kind")
        self._memberships = defaultdict(set)
        self._membership_evidence = {}
        for edge in s.memberships:
            if not isinstance(edge, TeamMembershipFact):
                raise AuthorizationFactsError("Expected TeamMembershipFact")
            _evidence(edge.evidence)
            require(edge.reader_id, self._readers, "membership reader")
            require(edge.team_id, self._teams, "membership team")
            if (edge.reader_id, edge.team_id) in self._membership_evidence:
                raise AuthorizationFactsError("Duplicate membership")
            self._memberships[edge.reader_id].add(edge.team_id)
            self._membership_evidence[(edge.reader_id, edge.team_id)] = edge.evidence

        def principal(ref: PrincipalRef):
            if not isinstance(ref, PrincipalRef):
                raise AuthorizationFactsError("Expected typed PrincipalRef")
            if ref.kind == "user":
                require(ref.id, self._readers, "user principal")
            elif ref.kind == "team":
                require(ref.id, self._teams, "team principal")
            elif ref.kind == "organization":
                if ref.id != s.organization_id:
                    raise AuthorizationFactsError("Organization principal belongs to another organization")
            else:
                raise AuthorizationFactsError("Unsupported principal kind")

        def applicable(ref: PrincipalRef, reader_id: str):
            principal(ref)
            return (ref.kind == "user" and ref.id == reader_id) or (
                ref.kind == "team" and ref.id in self._memberships[reader_id]) or ref.kind == "organization"

        self._privilege_tables = defaultdict(list)
        self._columns = {}
        for table in s.tables:
            _nonempty(table.read_privilege_id, "Read privilege ID")
            if table.ownership not in {"user_team", "business_unit", "organization"}:
                raise AuthorizationFactsError("Unsupported table ownership")
            if not isinstance(table.columns, tuple):
                raise AuthorizationFactsError("Columns must be an immutable tuple")
            self._privilege_tables[table.read_privilege_id].append(table.name)
            columns = {}
            for col in table.columns:
                if not isinstance(col, ColumnFact):
                    raise AuthorizationFactsError("Expected ColumnFact")
                _nonempty(col.name, "Column name")
                if type(col.secured) is not bool or type(col.masked) is not bool or col.name in columns:
                    raise AuthorizationFactsError("Invalid or duplicate column metadata")
                columns[col.name] = col
            self._columns[table.name] = columns
        context_pairs = set()
        for context in s.contexts:
            require(context.reader_id, self._readers, "context reader")
            require(context.privilege_id, self._privilege_tables, "Read privilege metadata")
            require(context.business_unit_anchor, self._bus, "context BU anchor")
            if context.depth not in {"Basic", "Local", "Deep", "Global"} or type(context.member_basic) is not bool:
                raise AuthorizationFactsError("Unsupported privilege depth/member_basic")
            if not applicable(context.source_principal, context.reader_id) or context.source_principal.kind == "organization":
                raise AuthorizationFactsError("Privilege source must be the reader or an effective role-holding team")
            if context.source_principal.kind == "team" and self._teams[context.source_principal.id].kind in {"access", "group_access"}:
                raise AuthorizationFactsError("Access teams cannot supply role privileges")
            for table_name in self._privilege_tables[context.privilege_id]:
                context_pairs.add((context.reader_id, table_name))
                if self._tables[table_name].ownership == "organization" and context.depth != "Global":
                    raise AuthorizationFactsError("Normalize organization-owned privilege to qualified Global scope")
        if context_pairs != self._basic.keys():
            raise AuthorizationFactsError("Every effective reader/table pair requires exactly one Basic qualification")
        for basic in s.basic_qualifications:
            if type(basic.personal_basic) is not bool:
                raise AuthorizationFactsError("personal_basic must be explicitly qualified true or false")
            for refs in (basic.owner_principals, basic.sharing_principals):
                if not isinstance(refs, tuple) or len(set(refs)) != len(refs):
                    raise AuthorizationFactsError("Qualified principal scopes must be unique immutable tuples")
                for ref in refs:
                    if not applicable(ref, basic.reader_id):
                        raise AuthorizationFactsError("Basic qualification contains an unrelated principal")
            if any(p.kind == "organization" for p in basic.owner_principals):
                raise AuthorizationFactsError("Organization principals do not own user/team rows")
            if any(p.kind == "team" and self._teams[p.id].kind in {"access", "group_access"} for p in basic.owner_principals):
                raise AuthorizationFactsError("Access teams cannot supply row ownership")
            own_user = PrincipalRef("user", basic.reader_id) in basic.owner_principals
            if self._tables[basic.table].ownership == "user_team" and basic.personal_basic != own_user:
                raise AuthorizationFactsError("personal_basic must agree with the qualified personal ownership scope")
            if not isinstance(basic.business_units, tuple) or len(set(basic.business_units)) != len(basic.business_units):
                raise AuthorizationFactsError("Qualified Basic BU scopes must be unique immutable tuples")
            for bu in basic.business_units:
                require(bu, self._bus, "qualified Basic BU")
            if basic.business_units and self._tables[basic.table].ownership != "business_unit":
                raise AuthorizationFactsError("Explicit Basic BU scope applies only to business-unit-owned tables")
            if basic.owner_principals and self._tables[basic.table].ownership != "user_team":
                raise AuthorizationFactsError("Owner Basic scope applies only to user/team-owned tables")
        for record in s.records:
            require(record.table, self._tables, "record table")
            ownership = self._tables[record.table].ownership
            if ownership == "user_team":
                principal(record.owner)
                if record.owner.kind == "organization" or (record.owner.kind == "team" and self._teams[record.owner.id].kind in {"access", "group_access"}):
                    raise AuthorizationFactsError("Invalid record owner")
            elif record.owner is not None:
                raise AuthorizationFactsError("Non-user/team-owned record cannot have a user/team owner")
            if ownership in {"user_team", "business_unit"}:
                require(record.owning_business_unit_id, self._bus, "record owning BU")
            elif record.owning_business_unit_id is not None:
                raise AuthorizationFactsError("Organization-owned record cannot have an owning BU")
        for fact in s.poa:
            require((fact.table, fact.record_id), self._records, "POA record")
            principal(fact.principal)
            for mask in (fact.access_rights_mask, fact.inherited_access_rights_mask):
                if type(mask) is not int or mask < 0 or mask & ~KNOWN_ACCESS_MASK:
                    raise AuthorizationFactsError("POA contains an unsupported access-rights mask")
        for fact in s.record_grants:
            require(fact.reader_id, self._readers, "record-grant reader")
            require((fact.table, fact.record_id), self._records, "record-grant record")
            if fact.kind not in {"hierarchy", "security_parent", "source_verified"}:
                raise AuthorizationFactsError("Unsupported qualified record-grant kind")
        profile_edges = set()
        for edge in s.profile_assignments:
            if not isinstance(edge, FieldProfileAssignment):
                raise AuthorizationFactsError("Expected FieldProfileAssignment")
            _evidence(edge.evidence)
            require(edge.profile_id, profiles, "field profile")
            principal(edge.principal)
            if edge.principal.kind == "organization":
                raise AuthorizationFactsError("Field profiles support only user/team assignment")
            key = (edge.profile_id, edge.principal)
            if key in profile_edges:
                raise AuthorizationFactsError("Duplicate profile assignment")
            profile_edges.add(key)

        def secured_column(table, column):
            require(table, self._columns, "field table")
            require(column, self._columns[table], "field column")
            if not self._columns[table][column].secured:
                raise AuthorizationFactsError("Field permission targets a column not marked secured")

        permission_keys = set()
        for fact in s.field_permissions:
            if not isinstance(fact, FieldPermissionFact):
                raise AuthorizationFactsError("Expected FieldPermissionFact")
            _evidence(fact.evidence)
            require(fact.profile_id, profiles, "field-permission profile")
            secured_column(fact.table, fact.column)
            if type(fact.can_read) is not bool:
                raise AuthorizationFactsError("Field Read flag requires an exact boolean")
            key = (fact.profile_id, fact.table, fact.column)
            if key in permission_keys:
                raise AuthorizationFactsError("Duplicate profile/column permission")
            permission_keys.add(key)
        for fact in s.record_field_grants:
            require((fact.table, fact.record_id), self._records, "record-field record")
            principal(fact.principal)
            secured_column(fact.table, fact.column)
            if type(fact.can_read) is not bool:
                raise AuthorizationFactsError("Record field Read flag requires an exact boolean")
        self._memberships = {reader.id: frozenset(self._memberships.get(reader.id, ())) for reader in s.readers}
        self._privilege_tables = {key: tuple(value) for key, value in self._privilege_tables.items()}

    def _principal_evidence(self, reader_id: str, principal: PrincipalRef) -> tuple[Evidence, ...]:
        if principal.kind == "team":
            return (self._membership_evidence[(reader_id, principal.id)],)
        return ()

    def evaluate_row(self, reader_id: str, table: str, record_id: str, *, now: datetime | None = None,
                     tenant_id: str | None = None, organization_id: str | None = None) -> RowDecision:
        now = now or datetime.now(timezone.utc)
        base = (self.snapshot.qualification,)

        def decision(allowed, *reasons):
            return RowDecision(reader_id, table, record_id, allowed, tuple(reasons), self.snapshot_id)

        def deny(code, detail, evidence=base):
            return decision(False, Reason(code, detail, evidence))

        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            return deny("invalid_clock", "Evaluation time must include a timezone")
        if (tenant_id is not None and tenant_id != self.snapshot.tenant_id) or (
                organization_id is not None and organization_id != self.snapshot.organization_id):
            return deny("identity_boundary_mismatch", "Tenant or organization does not match the snapshot")
        if not self.snapshot.observed_at <= now < self.snapshot.valid_until:
            return deny("snapshot_expired_or_future", "The qualified source snapshot is outside its lease")
        reader = self._readers.get(reader_id)
        if reader is None:
            return deny("unknown_reader", "No qualified reader identity")
        if not reader.enabled or not reader.entra_object_id or reader.application or reader.access_mode not in (0, 2):
            return deny("ineligible_reader", "Reader is disabled, lacks Entra identity, or uses an unsupported application/access mode", (reader.evidence,))
        record = self._records.get((table, record_id))
        if record is None:
            return deny("unknown_record", "No qualified table/record identity")
        contexts = self._contexts.get((reader_id, table), ())
        if not contexts:
            return deny("no_table_read", "Ownership, POA and field grants cannot supply missing table Read")
        basic = self._basic[(reader_id, table)]
        grants = []
        for context in contexts:
            evidence = (context.evidence, self._tables[table].evidence, *self._principal_evidence(reader_id, context.source_principal))
            if context.depth == "Global":
                grants.append(Reason("global_read", f"Qualified Global scope from context {context.id}", evidence))
            elif context.depth == "Local" and record.owning_business_unit_id == context.business_unit_anchor:
                grants.append(Reason("local_read", f"Owning BU matches context {context.id} anchor {context.business_unit_anchor}", evidence))
            elif context.depth == "Deep" and context.business_unit_anchor in self._ancestors.get(record.owning_business_unit_id, ()):
                grants.append(Reason("deep_read", f"Owning BU descends from context {context.id} anchor {context.business_unit_anchor}", evidence))
        if record.owner is not None and record.owner in basic.owner_principals:
            grants.append(Reason("qualified_basic_owner", "Ownership is in the source-qualified Basic closure",
                                 (basic.evidence, record.evidence, *self._principal_evidence(reader_id, record.owner))))
        if record.owning_business_unit_id in basic.business_units:
            grants.append(Reason("qualified_basic_business_unit", "BU ownership is in the qualified Basic closure", (basic.evidence, record.evidence)))
        for fact in self._poa.get((table, record_id), ()):
            if fact.principal not in basic.sharing_principals:
                continue
            evidence = (fact.evidence, basic.evidence, *self._principal_evidence(reader_id, fact.principal))
            if fact.access_rights_mask & READ_ACCESS:
                grants.append(Reason("poa_direct_read", f"Direct Read bit in POA {fact.id}", evidence))
            if fact.inherited_access_rights_mask & READ_ACCESS:
                grants.append(Reason("poa_inherited_read", f"Inherited Read bit in POA {fact.id}", evidence))
        for fact in self._record_grants.get((reader_id, table, record_id), ()):
            grants.append(Reason(f"qualified_{fact.kind}", "Explicitly source-qualified additional row access", (fact.evidence,)))
        if not grants:
            return deny("outside_read_scope", "Read privilege exists but no qualified scope grants this record",
                        (basic.evidence, *(c.evidence for c in contexts)))
        gate = Reason("table_read_gate", "Read privilege resolved by metadata ID", tuple(c.evidence for c in contexts))
        return decision(True, gate, *grants)

    def _field_reasons(self, reader_id: str, table: str, record_id: str, column: ColumnFact) -> tuple[Reason, ...]:
        if not column.secured:
            return (Reason("unsecured_column", "Column metadata does not require field Read", (self._tables[table].evidence,)),)
        principals = {PrincipalRef("user", reader_id), PrincipalRef("organization", self.snapshot.organization_id)}
        principals.update(PrincipalRef("team", team) for team in self._memberships[reader_id])
        assignments = defaultdict(list)
        for principal in principals:
            for edge in self._profile_assignments.get(principal, ()):
                assignments[edge.profile_id].append(edge)
        reasons = []
        for fact in self._field_permissions.get((table, column.name), ()):
            if fact.can_read:
                for edge in assignments.get(fact.profile_id, ()):
                    reasons.append(Reason("field_profile_read", f"Cumulative field Read from profile {fact.profile_id}",
                                          (fact.evidence, edge.evidence, *self._principal_evidence(reader_id, edge.principal))))
        for fact in self._field_grants.get((table, record_id, column.name), ()):
            if fact.can_read and fact.principal in principals:
                reasons.append(Reason("record_field_read", f"Record-specific field Read from {fact.id}",
                                      (fact.evidence, *self._principal_evidence(reader_id, fact.principal))))
        return tuple(reasons)

    def project(self, reader_id: str, table: str, record_id: str, values: Mapping[str, Scalar], *,
                now: datetime | None = None, tenant_id: str | None = None,
                organization_id: str | None = None) -> ProjectedRow:
        """Project one qualified row. Denied rows have no cells; denied fields NULL.

        ``values`` must contain exactly the configured table columns.  OData
        annotations, expansions and unknown columns cannot accidentally bypass
        the field decision.  This function does not accept a caller's row decision.
        """
        decision = self.evaluate_row(reader_id, table, record_id, now=now, tenant_id=tenant_id,
                                     organization_id=organization_id)
        if not decision.allowed:
            return ProjectedRow(decision, ())
        if not isinstance(values, Mapping) or set(values) != self._columns[table].keys():
            raise AuthorizationFactsError("Projection values must match configured columns exactly")
        cells = []
        for column in self._tables[table].columns:
            reasons = self._field_reasons(reader_id, table, record_id, column)
            if not reasons:
                cells.append(ProjectedCell(column.name, None, "denied_null", (
                    Reason("no_field_read", "No cumulative profile or record-field Read; preserve a NULL cell",
                           (self._tables[table].evidence, self.snapshot.qualification)),)))
                continue
            if column.masked:
                safe = self._masked_value_provider.project(reader_id, table, record_id, column.name)
                if not isinstance(safe, SafeMaskedValue):
                    raise AuthorizationFactsError("Masked provider must return a qualified SafeMaskedValue")
                _evidence(safe.evidence)
                _scalar(safe.value)
                cells.append(ProjectedCell(column.name, safe.value, "qualified_masked_value", (
                    *reasons, Reason("source_masking_projection", "Value supplied by qualified masking provider", (safe.evidence,)))))
            else:
                _scalar(values[column.name])
                cells.append(ProjectedCell(column.name, values[column.name], "value", reasons))
        return ProjectedRow(decision, tuple(cells))

    def readable_record_ids(self, reader_id: str, table: str, *, now: datetime | None = None) -> frozenset[str]:
        """Bounded shadow-validation helper; not a per-row RPC publication path."""
        now = now or datetime.now(timezone.utc)
        return frozenset(record.id for record in self.snapshot.records if record.table == table
                         and self.evaluate_row(reader_id, table, record.id, now=now).allowed)
