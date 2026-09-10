"""Snapshot persistence: each extract run is stored as a SQLite database under
runs/<run_id>/snapshot.sqlite so the raw security model is auditable and every
downstream stage is reproducible without re-querying Dataverse."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ..models import (
    BusinessUnit,
    DvRole,
    DvTeam,
    DvUser,
    FieldPermission,
    FieldSecurityProfile,
    Ownership,
    RoleReadGrant,
    Snapshot,
    TableMeta,
    parse_depth,
)

_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE business_units (id TEXT PRIMARY KEY, name TEXT, parent_id TEXT);
CREATE TABLE users (
    id TEXT PRIMARY KEY, name TEXT, domain_name TEXT, aad_object_id TEXT,
    bu_id TEXT, is_disabled INTEGER, access_mode INTEGER, application_id TEXT
);
CREATE TABLE teams (id TEXT PRIMARY KEY, name TEXT, bu_id TEXT, team_type INTEGER, aad_object_id TEXT);
CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT, bu_id TEXT, root_role_id TEXT);
CREATE TABLE tables_meta (
    logical_name TEXT PRIMARY KEY, schema_name TEXT, object_type_code INTEGER, ownership TEXT
);
CREATE TABLE role_grants (role_id TEXT, "table" TEXT, depth TEXT, privilege_name TEXT);
CREATE TABLE user_roles (user_id TEXT, role_id TEXT);
CREATE TABLE team_roles (team_id TEXT, role_id TEXT);
CREATE TABLE team_members (team_id TEXT, user_id TEXT);
CREATE TABLE fsps (id TEXT PRIMARY KEY, name TEXT);
CREATE TABLE field_permissions (profile_id TEXT, "table" TEXT, attribute TEXT, can_read INTEGER);
CREATE TABLE user_fsps (user_id TEXT, profile_id TEXT);
CREATE TABLE team_fsps (team_id TEXT, profile_id TEXT);
CREATE TABLE unmatched_privileges (name TEXT);
"""


def save_snapshot(snapshot: Snapshot, run_dir: str | Path) -> Path:
    directory = Path(run_dir) / snapshot.run_id
    directory.mkdir(parents=True, exist_ok=True)
    db_path = directory / "snapshot.sqlite"
    if db_path.exists():
        db_path.unlink()
    con = sqlite3.connect(db_path)
    try:
        con.executescript(_SCHEMA)
        con.executemany(
            "INSERT INTO meta VALUES (?, ?)",
            [
                ("run_id", snapshot.run_id),
                ("observed_at", snapshot.observed_at),
                ("environment_url", snapshot.environment_url),
                ("counts", json.dumps(snapshot.counts())),
            ],
        )
        con.executemany(
            "INSERT INTO business_units VALUES (?, ?, ?)",
            [(b.id, b.name, b.parent_id) for b in snapshot.business_units],
        )
        con.executemany(
            "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (u.id, u.name, u.domain_name, u.aad_object_id, u.bu_id,
                 int(u.is_disabled), u.access_mode, u.application_id)
                for u in snapshot.users
            ],
        )
        con.executemany(
            "INSERT INTO teams VALUES (?, ?, ?, ?, ?)",
            [(t.id, t.name, t.bu_id, t.team_type, t.aad_object_id) for t in snapshot.teams],
        )
        con.executemany(
            "INSERT INTO roles VALUES (?, ?, ?, ?)",
            [(r.id, r.name, r.bu_id, r.root_role_id) for r in snapshot.roles],
        )
        con.executemany(
            "INSERT INTO tables_meta VALUES (?, ?, ?, ?)",
            [(t.logical_name, t.schema_name, t.object_type_code, t.ownership.value)
             for t in snapshot.tables],
        )
        con.executemany(
            "INSERT INTO role_grants VALUES (?, ?, ?, ?)",
            [(g.role_id, g.table, g.depth.value, g.privilege_name) for g in snapshot.role_grants],
        )
        con.executemany("INSERT INTO user_roles VALUES (?, ?)", snapshot.user_roles)
        con.executemany("INSERT INTO team_roles VALUES (?, ?)", snapshot.team_roles)
        con.executemany("INSERT INTO team_members VALUES (?, ?)", snapshot.team_members)
        con.executemany("INSERT INTO fsps VALUES (?, ?)", [(f.id, f.name) for f in snapshot.fsps])
        con.executemany(
            "INSERT INTO field_permissions VALUES (?, ?, ?, ?)",
            [(p.profile_id, p.table, p.attribute, p.can_read) for p in snapshot.field_permissions],
        )
        con.executemany("INSERT INTO user_fsps VALUES (?, ?)", snapshot.user_fsps)
        con.executemany("INSERT INTO team_fsps VALUES (?, ?)", snapshot.team_fsps)
        con.executemany(
            "INSERT INTO unmatched_privileges VALUES (?)",
            [(n,) for n in snapshot.unmatched_privileges],
        )
        con.commit()
    finally:
        con.close()
    (directory / "counts.json").write_text(
        json.dumps(snapshot.counts(), indent=2), encoding="utf-8"
    )
    return db_path


def load_snapshot(db_path: str | Path) -> Snapshot:
    con = sqlite3.connect(db_path)
    try:
        meta = dict(con.execute("SELECT key, value FROM meta"))
        snapshot = Snapshot(
            run_id=meta["run_id"],
            observed_at=meta["observed_at"],
            environment_url=meta["environment_url"],
        )
        snapshot.business_units = [
            BusinessUnit(*row) for row in con.execute("SELECT id, name, parent_id FROM business_units")
        ]
        snapshot.users = [
            DvUser(
                id=r[0], name=r[1], domain_name=r[2], aad_object_id=r[3], bu_id=r[4],
                is_disabled=bool(r[5]), access_mode=r[6], application_id=r[7],
            )
            for r in con.execute(
                "SELECT id, name, domain_name, aad_object_id, bu_id, is_disabled,"
                " access_mode, application_id FROM users"
            )
        ]
        snapshot.teams = [
            DvTeam(id=r[0], name=r[1], bu_id=r[2], team_type=r[3], aad_object_id=r[4])
            for r in con.execute("SELECT id, name, bu_id, team_type, aad_object_id FROM teams")
        ]
        snapshot.roles = [
            DvRole(id=r[0], name=r[1], bu_id=r[2], root_role_id=r[3])
            for r in con.execute("SELECT id, name, bu_id, root_role_id FROM roles")
        ]
        snapshot.tables = [
            TableMeta(logical_name=r[0], schema_name=r[1], object_type_code=r[2],
                      ownership=Ownership(r[3]))
            for r in con.execute(
                "SELECT logical_name, schema_name, object_type_code, ownership FROM tables_meta"
            )
        ]
        snapshot.role_grants = [
            RoleReadGrant(role_id=r[0], table=r[1], depth=parse_depth(r[2]), privilege_name=r[3])
            for r in con.execute('SELECT role_id, "table", depth, privilege_name FROM role_grants')
        ]
        snapshot.user_roles = list(con.execute("SELECT user_id, role_id FROM user_roles"))
        snapshot.team_roles = list(con.execute("SELECT team_id, role_id FROM team_roles"))
        snapshot.team_members = list(con.execute("SELECT team_id, user_id FROM team_members"))
        snapshot.fsps = [
            FieldSecurityProfile(id=r[0], name=r[1]) for r in con.execute("SELECT id, name FROM fsps")
        ]
        snapshot.field_permissions = [
            FieldPermission(profile_id=r[0], table=r[1], attribute=r[2], can_read=r[3])
            for r in con.execute(
                'SELECT profile_id, "table", attribute, can_read FROM field_permissions'
            )
        ]
        snapshot.user_fsps = list(con.execute("SELECT user_id, profile_id FROM user_fsps"))
        snapshot.team_fsps = list(con.execute("SELECT team_id, profile_id FROM team_fsps"))
        snapshot.unmatched_privileges = [
            r[0] for r in con.execute("SELECT name FROM unmatched_privileges")
        ]
        return snapshot
    finally:
        con.close()


def latest_run_dir(run_dir: str | Path) -> Path | None:
    root = Path(run_dir)
    if not root.exists():
        return None
    candidates = sorted(
        (p for p in root.iterdir() if p.is_dir() and (p / "snapshot.sqlite").exists()),
        key=lambda p: p.name,
    )
    return candidates[-1] if candidates else None
