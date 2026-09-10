"""Run artifacts: every stage writes machine-readable JSON/CSV plus a human
summary under runs/<run_id>/ so each sync is auditable after the fact."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..compile.effective_access import SecurityIndex
from ..models import ALL_ROWS, Profile


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_compile_reports(
    directory: Path,
    index: SecurityIndex,
    profiles: list[Profile],
    profile_stats: dict,
    roles_by_profile: dict[str, list[str]],
) -> None:
    diag = index.diagnostics
    users_by_id = {u.id: u for u in index.snapshot.users}

    write_csv(
        directory / "skipped_users.csv",
        [{"user_id": s.user_id, "name": s.name, "reason": s.reason} for s in diag.skipped_users],
        ["user_id", "name", "reason"],
    )
    write_csv(
        directory / "basic_depth_exclusions.csv",
        [
            {"user_id": e.user_id, "user_name": e.user_name, "table": e.table, "kind": e.kind}
            for e in diag.basic_exclusions
        ],
        ["user_id", "user_name", "table", "kind"],
    )
    write_csv(
        directory / "profiles.csv",
        [
            {
                "profile": p.short_hash,
                "members": len(p.user_ids),
                "tables": len(p.scopes),
                "rls_tables": sum(1 for s in p.scopes.values() if s != ALL_ROWS),
                "roles_emitted": len(roles_by_profile.get(p.profile_hash, [])),
            }
            for p in profiles
        ],
        ["profile", "members", "tables", "rls_tables", "roles_emitted"],
    )

    manifest = []
    bu_names = {b.id: b.name for b in index.snapshot.business_units}
    for profile in profiles:
        manifest.append(
            {
                "profile": profile.short_hash,
                "roles": roles_by_profile.get(profile.profile_hash, []),
                "member_count": len(profile.user_ids),
                "members": [
                    {
                        "user_id": uid,
                        "name": users_by_id[uid].name if uid in users_by_id else uid,
                        "aad_object_id": users_by_id[uid].aad_object_id if uid in users_by_id else None,
                    }
                    for uid in profile.user_ids
                ],
                "tables": {
                    table: (
                        "ALL"
                        if scope == ALL_ROWS
                        else {"business_units": sorted(bu_names.get(b, b) for b in scope)}
                    )
                    for table, scope in sorted(profile.scopes.items())
                },
            }
        )
    write_json(directory / "manifest.json", manifest)

    summary = {
        "profile_stats": profile_stats,
        "skipped_users": len(diag.skipped_users),
        "basic_exclusions": len(diag.basic_exclusions),
        "tables_without_metadata": diag.tables_without_metadata,
        "tables_excluded_by_filter": diag.tables_excluded_by_filter,
        "tables_granted_but_absent_from_item": diag.tables_absent_from_item,
        "unmatched_read_privileges": index.snapshot.unmatched_privileges,
    }
    write_json(directory / "compile_summary.json", summary)

    lines = [
        "# Compile summary",
        "",
        f"- Snapshot: `{index.snapshot.run_id}` observed {index.snapshot.observed_at}",
        f"- Eligible users: {len(index.eligible_users)} (skipped: {len(diag.skipped_users)})",
        f"- Access profiles: {profile_stats.get('profiles')}"
        f" (largest {profile_stats.get('largest_profile_members')} members)",
        f"- Users with no read access: {profile_stats.get('users_without_access')}",
        f"- OneLake roles compiled: {sum(len(v) for v in roles_by_profile.values())}",
        f"- Basic-depth fail-closed exclusions: {len(diag.basic_exclusions)}"
        " (see basic_depth_exclusions.csv)",
        f"- Read privileges not matched to a table: {len(index.snapshot.unmatched_privileges)}",
        f"- Granted in Dataverse but not synced to the item: {len(diag.tables_absent_from_item)}"
        " tables (no OneLake permission emitted)",
        "",
        "Every exclusion above means Fabric grants LESS than Dataverse, never more.",
    ]
    (directory / "compile_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
