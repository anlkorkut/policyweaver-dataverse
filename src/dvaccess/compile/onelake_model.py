"""Translate access profiles into OneLake data access role definitions, enforcing
every OneLake limit by construction:

- max permissions per role: tables are bin-packed into sibling roles;
- max RLS statement length: a table's BU list is split across sibling roles
  (RLS combines with OR across roles a user belongs to, and chunks of the same
  table are never placed in the same role);
- max members per role: 'group' membership emits one Entra group per profile
  (one member per role); 'direct' membership clones the role family per member
  chunk of at most the member limit.

A table appears with its full grant in exactly the sibling roles that carry its
predicate chunks - never once with RLS and once without, which would union to
unrestricted rows.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..config import AppConfig
from ..models import ALL_ROWS, Ownership, Profile, RoleDefinition

logger = logging.getLogger(__name__)


def rls_columns_for_tables(table_ownership: dict, cfg: AppConfig) -> dict[str, str]:
    """Which column carries the business unit, per table. Business-owned rows use
    businessunitid; user/team-owned rows use owningbusinessunit. Getting this wrong
    produces a predicate that references a missing column, and OneLake then fails the
    query rather than returning rows."""
    return {
        table: (
            cfg.compile.rls_column_business_owned
            if ownership is Ownership.BUSINESS
            else cfg.compile.rls_column
        )
        for table, ownership in table_ownership.items()
    }


class CompileLimitError(RuntimeError):
    pass


class RoleBudgetExceeded(RuntimeError):
    def __init__(self, message: str, breakdown: dict):
        super().__init__(message)
        self.breakdown = breakdown


def table_path(schema_name: str | None, table: str) -> str:
    return f"/Tables/{schema_name}/{table}" if schema_name else f"/Tables/{table}"


def qualified_table(schema_name: str | None, table: str) -> str:
    return f"{schema_name}.{table}" if schema_name else table


def build_rls_predicates(
    schema_name: str | None, table: str, column: str, bu_ids: frozenset, max_chars: int
) -> list[str]:
    """Build one or more `SELECT * FROM t WHERE col IN (...)` statements, each within
    the RLS character limit. Multiple statements mean the table must be split across
    sibling roles (OneLake ORs row constraints across a user's roles)."""
    prefix = f"SELECT * FROM {qualified_table(schema_name, table)} WHERE {column} IN ("
    suffix = ")"
    values = [f"'{bu_id}'" for bu_id in sorted(bu_ids)]
    if not values:
        raise CompileLimitError(f"Empty BU scope for table {table}")
    if len(prefix) + len(values[0]) + len(suffix) > max_chars:
        raise CompileLimitError(
            f"RLS statement for table {table} cannot fit a single value within "
            f"{max_chars} characters; table/column names too long."
        )
    statements: list[str] = []
    current: list[str] = []
    current_len = len(prefix) + len(suffix)
    for value in values:
        extra = len(value) + (1 if current else 0)  # comma separator
        if current and current_len + extra > max_chars:
            statements.append(prefix + ",".join(current) + suffix)
            current = [value]
            current_len = len(prefix) + len(suffix) + len(value)
        else:
            current.append(value)
            current_len += extra
    statements.append(prefix + ",".join(current) + suffix)
    return statements


@dataclass
class _Bucket:
    tables: set = field(default_factory=set)
    units: list = field(default_factory=list)  # (table, predicate | None)


def _pack_units(units: list[tuple[str, str | None, int]], max_permissions: int) -> list[_Bucket]:
    """Bin-pack (table, predicate) units into buckets of at most max_permissions,
    never placing two chunks of the same table in one bucket. Units are sorted so
    multi-chunk tables place first."""
    buckets: list[_Bucket] = []
    for table, predicate, _ in sorted(units, key=lambda u: (-u[2], u[0])):
        placed = False
        for bucket in buckets:
            if table not in bucket.tables and len(bucket.units) < max_permissions:
                bucket.tables.add(table)
                bucket.units.append((table, predicate))
                placed = True
                break
        if not placed:
            bucket = _Bucket()
            bucket.tables.add(table)
            bucket.units.append((table, predicate))
            buckets.append(bucket)
    return buckets


def compile_profile_roles(
    profile: Profile,
    cfg: AppConfig,
    member_aad_ids: list[str],
    rls_column_by_table: dict[str, str] | None = None,
) -> list[RoleDefinition]:
    schema = cfg.fabric.schema_name
    limits = cfg.limits
    columns = rls_column_by_table or {}
    units: list[tuple[str, str | None, int]] = []
    for table, scope in sorted(profile.scopes.items()):
        if scope == ALL_ROWS:
            units.append((table, None, 1))
        else:
            predicates = build_rls_predicates(
                schema, table, columns.get(table, cfg.compile.rls_column),
                scope, limits.max_rls_chars,
            )
            units.extend((table, predicate, len(predicates)) for predicate in predicates)

    buckets = _pack_units(units, limits.max_permissions_per_role)

    if cfg.entra.membership == "direct":
        member_chunks = [
            member_aad_ids[i:i + limits.max_members_per_role]
            for i in range(0, len(member_aad_ids), limits.max_members_per_role)
        ] or [[]]
    else:
        member_chunks = [[]]  # single chunk; the Entra group is the sole member

    roles: list[RoleDefinition] = []
    for bucket_idx, bucket in enumerate(buckets):
        for chunk_idx, chunk in enumerate(member_chunks):
            # Alphanumeric only, starting with a letter: OneLake rejects anything else.
            name = f"{cfg.fabric.role_prefix}{profile.short_hash}p{bucket_idx:02d}"
            if len(member_chunks) > 1:
                name += f"m{chunk_idx:02d}"
            role = RoleDefinition(
                name=name,
                profile_hash=profile.profile_hash,
                table_paths=sorted(table_path(schema, t) for t, _ in bucket.units),
                row_constraints=sorted(
                    (table_path(schema, t), predicate)
                    for t, predicate in bucket.units
                    if predicate is not None
                ),
                entra_user_ids=list(chunk),
            )
            roles.append(role)
    return roles


def compile_all_roles(
    profiles: list[Profile],
    cfg: AppConfig,
    aad_by_user_id: dict[str, str],
    rls_column_by_table: dict[str, str] | None = None,
) -> list[RoleDefinition]:
    if cfg.compile.cls_enabled:
        raise NotImplementedError(
            "cls_enabled requires table column metadata to emit Permit column lists; "
            "planned for milestone M4. Disable compile.cls_enabled."
        )
    roles: list[RoleDefinition] = []
    per_profile: dict[str, int] = {}
    for profile in profiles:
        member_aad_ids = sorted(
            aad_by_user_id[uid] for uid in profile.user_ids if uid in aad_by_user_id
        )
        produced = compile_profile_roles(profile, cfg, member_aad_ids, rls_column_by_table)
        per_profile[profile.short_hash] = len(produced)
        roles.extend(produced)
    logger.info(
        "Compiled %d OneLake roles from %d profiles", len(roles), len(profiles)
    )
    return roles


def validate_role_budget(
    desired_count: int, unmanaged_count: int, budget: int, per_profile: dict | None = None
) -> None:
    total = desired_count + unmanaged_count
    if total > budget:
        raise RoleBudgetExceeded(
            f"Compiled {desired_count} managed roles + {unmanaged_count} existing unmanaged "
            f"roles = {total}, exceeding the item budget of {budget}. "
            "Reduce table scope, consolidate roles in Dataverse, or request a higher limit.",
            {"desired": desired_count, "unmanaged": unmanaged_count, "budget": budget,
             "per_profile": per_profile or {}},
        )
