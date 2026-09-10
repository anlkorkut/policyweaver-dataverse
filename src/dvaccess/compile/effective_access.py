"""Effective read-access computation.

Semantics ("access is cumulative, the greatest amount of access prevails"):
- A user's grants = union over all role instances assigned directly plus role
  instances assigned to teams the user belongs to.
- Role instances are BU-stamped: a role assigned to a user is that user's BU copy,
  a role assigned to a team is the team's BU copy, so the role instance's BU is the
  correct context for Local/Deep scoping in both cases.
- Per (user, table): Global depth, or any read on an org-owned table, grants all
  rows; Deep grants the role BU's subtree; Local grants the role BU; multiple
  BU-scoped grants union their BU sets; a BU set covering every BU normalizes to
  ALL_ROWS.
- Basic depth (own records) is not expressible as static OneLake RLS. It is
  subsumed when the user's own BU and their teams' BUs are already inside the
  granted scope; otherwise it is fail-closed excluded and reported.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field

from ..config import CompileConfig
from ..models import (
    ALL_ROWS,
    BasicExclusion,
    CompileDiagnostics,
    Depth,
    DvRole,
    DvUser,
    Ownership,
    SkippedUser,
    Snapshot,
)

logger = logging.getLogger(__name__)


@dataclass
class SecurityIndex:
    """Prebuilt lookups over a snapshot, filtered per compile configuration."""

    snapshot: Snapshot
    eligible_users: list[DvUser]
    role_by_id: dict[str, DvRole]
    role_tables: dict[str, dict[str, Depth]]  # role_id -> table -> max depth
    user_role_ids: dict[str, set[str]]
    team_role_ids: dict[str, set[str]]
    user_team_ids: dict[str, set[str]]
    team_bu_by_id: dict[str, str]
    table_ownership: dict[str, Ownership]
    bu_subtree: dict[str, frozenset]
    all_bus: frozenset
    user_fsp_ids: dict[str, frozenset]
    diagnostics: CompileDiagnostics = field(default_factory=CompileDiagnostics)


def _compute_bu_subtrees(snapshot: Snapshot) -> tuple[dict[str, frozenset], frozenset]:
    children: dict[str, list[str]] = defaultdict(list)
    for bu in snapshot.business_units:
        if bu.parent_id:
            children[bu.parent_id].append(bu.id)
    subtree: dict[str, frozenset] = {}

    def collect(bu_id: str) -> frozenset:
        if bu_id in subtree:
            return subtree[bu_id]
        acc = {bu_id}
        for child in children.get(bu_id, ()):
            acc |= collect(child)
        result = frozenset(acc)
        subtree[bu_id] = result
        return result

    for bu in snapshot.business_units:
        collect(bu.id)
    all_bus = frozenset(b.id for b in snapshot.business_units)
    return subtree, all_bus


def build_index(
    snapshot: Snapshot, cfg: CompileConfig, item_tables: set[str] | None = None
) -> SecurityIndex:
    """Build compile-time lookups. `item_tables`, when given, restricts compilation to
    tables that actually exist in the target Fabric item - Dataverse grants privileges
    on every table in the environment, but only the synced subset is in the lakehouse."""
    diagnostics = CompileDiagnostics()

    eligible: list[DvUser] = []
    for user in snapshot.users:
        if user.application_id:
            diagnostics.skipped_users.append(SkippedUser(user.id, user.name, "application user"))
        elif user.is_disabled:
            diagnostics.skipped_users.append(SkippedUser(user.id, user.name, "disabled"))
        elif user.access_mode not in cfg.user_access_modes:
            diagnostics.skipped_users.append(
                SkippedUser(user.id, user.name, f"access mode {user.access_mode} not eligible")
            )
        elif not user.aad_object_id:
            diagnostics.skipped_users.append(
                SkippedUser(user.id, user.name, "no Entra object id")
            )
        else:
            eligible.append(user)

    include = {t.lower() for t in cfg.include_tables}
    exclude = {t.lower() for t in cfg.exclude_tables}
    present = {t.lower() for t in item_tables} if item_tables is not None else None

    def table_allowed(table: str) -> bool:
        key = table.lower()
        if present is not None and key not in present:
            return False
        if include and key not in include:
            return False
        return key not in exclude

    role_tables: dict[str, dict[str, Depth]] = defaultdict(dict)
    filtered_out: set[str] = set()
    absent_from_item: set[str] = set()
    for grant in snapshot.role_grants:
        if not table_allowed(grant.table):
            filtered_out.add(grant.table)
            if present is not None and grant.table.lower() not in present:
                absent_from_item.add(grant.table)
            continue
        current = role_tables[grant.role_id].get(grant.table)
        if current is None or grant.depth.rank > current.rank:
            role_tables[grant.role_id][grant.table] = grant.depth
    diagnostics.tables_excluded_by_filter = sorted(filtered_out)
    diagnostics.tables_absent_from_item = sorted(absent_from_item)

    user_role_ids: dict[str, set[str]] = defaultdict(set)
    for user_id, role_id in snapshot.user_roles:
        user_role_ids[user_id].add(role_id)
    team_role_ids: dict[str, set[str]] = defaultdict(set)
    for team_id, role_id in snapshot.team_roles:
        team_role_ids[team_id].add(role_id)
    user_team_ids: dict[str, set[str]] = defaultdict(set)
    for team_id, user_id in snapshot.team_members:
        user_team_ids[user_id].add(team_id)

    table_ownership = {t.logical_name: t.ownership for t in snapshot.tables}
    known_tables = set(table_ownership)
    missing_meta = {
        grant.table for grant in snapshot.role_grants if grant.table not in known_tables
    }
    diagnostics.tables_without_metadata = sorted(missing_meta)

    subtree, all_bus = _compute_bu_subtrees(snapshot)

    team_fsp_by_team: dict[str, set[str]] = defaultdict(set)
    for team_id, profile_id in snapshot.team_fsps:
        team_fsp_by_team[team_id].add(profile_id)
    user_fsp_ids: dict[str, frozenset] = {}
    direct_fsps: dict[str, set[str]] = defaultdict(set)
    for user_id, profile_id in snapshot.user_fsps:
        direct_fsps[user_id].add(profile_id)
    for user in eligible:
        fsps = set(direct_fsps.get(user.id, ()))
        for team_id in user_team_ids.get(user.id, ()):
            fsps |= team_fsp_by_team.get(team_id, set())
        user_fsp_ids[user.id] = frozenset(fsps)

    return SecurityIndex(
        snapshot=snapshot,
        eligible_users=eligible,
        role_by_id={r.id: r for r in snapshot.roles},
        role_tables=dict(role_tables),
        user_role_ids=dict(user_role_ids),
        team_role_ids=dict(team_role_ids),
        user_team_ids=dict(user_team_ids),
        team_bu_by_id={t.id: t.bu_id for t in snapshot.teams},
        table_ownership=table_ownership,
        bu_subtree=subtree,
        all_bus=all_bus,
        user_fsp_ids=user_fsp_ids,
        diagnostics=diagnostics,
    )


def role_grants_for(index: SecurityIndex, role: DvRole) -> dict:
    """Grants for a role instance. Extraction stores privileges once per ROOT role
    (BU copies share the root's privilege set); fixtures/tests may store them under
    the instance id, so the instance id takes precedence."""
    grants = index.role_tables.get(role.id)
    if grants is not None:
        return grants
    if role.root_role_id:
        return index.role_tables.get(role.root_role_id, {})
    return {}


def iter_user_scopes(index: SecurityIndex) -> Iterator[tuple[DvUser, dict]]:
    """Yield (user, {table -> ALL_ROWS | frozenset(bu_ids)}) for each eligible user.

    Basic-depth findings are appended to index.diagnostics as they are discovered.
    """
    interned: dict[frozenset, frozenset] = {}

    def intern(s: frozenset) -> frozenset:
        return interned.setdefault(s, s)

    for user in index.eligible_users:
        role_ids = set(index.user_role_ids.get(user.id, ()))
        for team_id in index.user_team_ids.get(user.id, ()):
            role_ids |= index.team_role_ids.get(team_id, set())

        scopes: dict[str, object] = {}
        basic_tables: set[str] = set()
        for role_id in role_ids:
            role = index.role_by_id.get(role_id)
            if role is None:
                continue
            for table, depth in role_grants_for(index, role).items():
                ownership = index.table_ownership.get(table, Ownership.USER)
                if ownership is Ownership.ORG or depth is Depth.GLOBAL:
                    contribution: object = ALL_ROWS
                elif depth is Depth.DEEP:
                    sub = index.bu_subtree.get(role.bu_id, frozenset({role.bu_id}))
                    contribution = ALL_ROWS if sub == index.all_bus else sub
                elif depth is Depth.LOCAL:
                    contribution = frozenset({role.bu_id})
                elif ownership is Ownership.BUSINESS:
                    # Business-owned rows belong to a BU, not a user, so Basic depth
                    # resolves to the user's own business unit rather than to
                    # individual record ownership - fully expressible as static RLS.
                    contribution = frozenset({user.bu_id})
                else:  # Basic depth on user/team-owned rows: not expressible
                    basic_tables.add(table)
                    continue
                existing = scopes.get(table)
                if existing == ALL_ROWS or contribution == ALL_ROWS:
                    scopes[table] = ALL_ROWS
                elif existing is None:
                    scopes[table] = intern(contribution)
                else:
                    merged = existing | contribution  # type: ignore[operator]
                    scopes[table] = ALL_ROWS if merged == index.all_bus else intern(merged)

        basic_cover = {user.bu_id} | {
            index.team_bu_by_id[t]
            for t in index.user_team_ids.get(user.id, ())
            if t in index.team_bu_by_id
        }
        for table in sorted(basic_tables):
            scope = scopes.get(table)
            if scope is None:
                index.diagnostics.basic_exclusions.append(
                    BasicExclusion(user.id, user.name, table, "basic_only")
                )
            elif scope != ALL_ROWS and not basic_cover <= scope:
                index.diagnostics.basic_exclusions.append(
                    BasicExclusion(user.id, user.name, table, "basic_partial")
                )

        yield user, scopes


def explain_user(index: SecurityIndex, user: DvUser, table: str | None = None) -> list[dict]:
    """Trace which role instances contribute which access for one user (audit aid)."""
    rows: list[dict] = []
    sources: list[tuple[str, str | None]] = [(rid, None) for rid in index.user_role_ids.get(user.id, ())]
    for team_id in index.user_team_ids.get(user.id, ()):
        sources.extend((rid, team_id) for rid in index.team_role_ids.get(team_id, set()))
    team_names = {t.id: t.name for t in index.snapshot.teams}
    bu_names = {b.id: b.name for b in index.snapshot.business_units}
    for role_id, via_team in sources:
        role = index.role_by_id.get(role_id)
        if role is None:
            continue
        for tbl, depth in sorted(role_grants_for(index, role).items()):
            if table and tbl.lower() != table.lower():
                continue
            rows.append(
                {
                    "table": tbl,
                    "depth": depth.value,
                    "role": role.name,
                    "role_id": role.id,
                    "role_bu": bu_names.get(role.bu_id, role.bu_id),
                    "via_team": team_names.get(via_team) if via_team else None,
                    "ownership": index.table_ownership.get(tbl, Ownership.USER).value,
                }
            )
    return rows
