"""Synthetic scale benchmark: does the compiled-profile model fit the role budget?

The demo environment has one interactive user, so it cannot exercise profile
compression. This generates a synthetic Dataverse security model at production
scale and compiles it, reporting profile and role counts against the budget.

The dominant variable is not user count - it is how many distinct (job archetype,
business-unit scope) combinations exist, because that is what an access profile
keys on. Global-depth grants collapse across business units; Local/Deep grants do
not. The --global-share sweep shows where the cliff is.

    python tools/scale_benchmark.py                      # bank-scale default
    python tools/scale_benchmark.py --sweep              # sweep the depth mix
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dvaccess.compile.effective_access import build_index  # noqa: E402
from dvaccess.compile.onelake_model import (  # noqa: E402
    compile_all_roles,
    rls_columns_for_tables,
)
from dvaccess.compile.profiles import build_profiles  # noqa: E402
from dvaccess.config import AppConfig  # noqa: E402
from dvaccess.models import (  # noqa: E402
    BusinessUnit,
    Depth,
    DvRole,
    DvTeam,
    DvUser,
    Ownership,
    RoleReadGrant,
    Snapshot,
    TableMeta,
)


def build_config(role_budget: int) -> AppConfig:
    return AppConfig.model_validate(
        {
            "environment": {"name": "bench", "dataverse_url": "https://bench.crm.dynamics.com"},
            "auth": {"tenant_id": "t"},
            "fabric": {
                "workspace_id": "w", "item_id": "i", "schema_name": None,
                "role_prefix": "dv_", "role_budget": role_budget,
            },
        }
    )


def generate(
    *,
    users: int,
    business_units: int,
    tables: int,
    roles: int,
    archetypes: int,
    roles_per_archetype: int,
    teams: int,
    global_share: float,
    seed: int,
) -> tuple[Snapshot, int]:
    rng = random.Random(seed)
    snap = Snapshot(run_id="bench", observed_at="", environment_url="")

    # Business unit tree: root -> divisions -> desks (custodian-bank shaped).
    bu_ids = [f"bu{i:04d}" for i in range(business_units)]
    divisions = max(1, business_units // 12)
    for i, bu in enumerate(bu_ids):
        if i == 0:
            parent = None
        elif i <= divisions:
            parent = bu_ids[0]
        else:
            parent = bu_ids[1 + (i % divisions)]
        snap.business_units.append(BusinessUnit(id=bu, name=bu.upper(), parent_id=parent))

    table_names = [f"tbl{i:05d}" for i in range(tables)]
    for i, t in enumerate(table_names):
        ownership = (
            Ownership.ORG if i % 10 == 0
            else Ownership.BUSINESS if i % 10 == 1
            else Ownership.USER
        )
        snap.tables.append(TableMeta(t, t, i, ownership))

    # Root roles, each granting read on a slice of tables at a sampled depth.
    root_role_ids = [f"role{i:04d}" for i in range(roles)]
    for r in root_role_ids:
        for t in rng.sample(table_names, rng.randint(5, 60)):
            depth = (
                Depth.GLOBAL if rng.random() < global_share
                else rng.choice([Depth.LOCAL, Depth.DEEP, Depth.BASIC])
            )
            snap.role_grants.append(RoleReadGrant(role_id=r, table=t, depth=depth))

    # Dataverse stamps one instance of each role per business unit.
    instance_by_root_bu: dict[tuple[str, str], str] = {}
    for r in root_role_ids:
        for bu in bu_ids:
            iid = f"{r}@{bu}"
            instance_by_root_bu[(r, bu)] = iid
            snap.roles.append(DvRole(id=iid, name=r, bu_id=bu, root_role_id=r))

    # Job archetypes: the real driver of profile cardinality.
    archetype_roles = [
        rng.sample(root_role_ids, roles_per_archetype) for _ in range(archetypes)
    ]

    for u in range(users):
        uid = f"user{u:06d}"
        bu = bu_ids[rng.randrange(len(bu_ids))]
        snap.users.append(
            DvUser(uid, uid, f"{uid}@bank.test", f"aad-{uid}", bu, False, 0, None)
        )
        for r in archetype_roles[rng.randrange(archetypes)]:
            snap.user_roles.append((uid, instance_by_root_bu[(r, bu)]))

    for t in range(teams):
        tid = f"team{t:03d}"
        bu = bu_ids[rng.randrange(len(bu_ids))]
        snap.teams.append(DvTeam(tid, tid, bu, 0, None))
        for r in rng.sample(root_role_ids, 2):
            snap.team_roles.append((tid, instance_by_root_bu[(r, bu)]))
        for uid in rng.sample([u.id for u in snap.users], min(400, users)):
            snap.team_members.append((tid, uid))

    assignments = len(snap.user_roles) + len(snap.team_roles) + len(snap.team_members)
    return snap, assignments


def run_case(label: str, snap: Snapshot, assignments: int, cfg: AppConfig) -> dict:
    started = time.perf_counter()
    index = build_index(snap, cfg.compile)
    result = build_profiles(index, cfg.compile)
    roles = compile_all_roles(
        result.profiles, cfg,
        {u.id: u.aad_object_id for u in index.eligible_users if u.aad_object_id},
        rls_columns_for_tables(index.table_ownership, cfg),
    )
    elapsed = time.perf_counter() - started
    stats = result.stats
    total = len(roles)
    verdict = "FITS" if total <= cfg.fabric.role_budget else "EXCEEDS BUDGET"
    print(
        f"  {label:<22} profiles={stats['profiles']:>6}  roles={total:>6}  "
        f"largest={stats['largest_profile_members']:>6}  "
        f"maxtables={stats['max_tables_per_profile']:>5}  "
        f"basic_excl={len(index.diagnostics.basic_exclusions):>7}  "
        f"{elapsed:>5.1f}s  {verdict}"
    )
    return {"profiles": stats["profiles"], "roles": total, "assignments": assignments}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--users", type=int, default=14541)
    p.add_argument("--business-units", type=int, default=93)
    p.add_argument("--tables", type=int, default=2074)
    p.add_argument("--roles", type=int, default=293)
    p.add_argument("--archetypes", type=int, default=40)
    p.add_argument("--roles-per-archetype", type=int, default=3)
    p.add_argument("--teams", type=int, default=13)
    p.add_argument("--global-share", type=float, default=0.83)
    p.add_argument("--role-budget", type=int, default=1000)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--sweep", action="store_true", help="sweep global-depth share")
    args = p.parse_args()

    cfg = build_config(args.role_budget)
    shares = [0.95, 0.83, 0.6, 0.4, 0.2] if args.sweep else [args.global_share]

    print(
        f"Scale: {args.users} users, {args.business_units} BUs, {args.tables} tables, "
        f"{args.roles} roles, {args.archetypes} archetypes x {args.roles_per_archetype} roles, "
        f"budget {args.role_budget}"
    )
    print(
        "  (global-share = fraction of privileges at Global depth; the rest are "
        "Local/Deep/Basic and therefore business-unit specific)\n"
    )
    for share in shares:
        snap, assignments = generate(
            users=args.users, business_units=args.business_units, tables=args.tables,
            roles=args.roles, archetypes=args.archetypes,
            roles_per_archetype=args.roles_per_archetype, teams=args.teams,
            global_share=share, seed=args.seed,
        )
        run_case(f"global={share:.0%}", snap, assignments, cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
