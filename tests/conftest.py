"""Synthetic-org fixtures: a small custodian-bank-like environment.

BU tree:
    root
    +-- emea
    |   +-- uk
    |   +-- de
    +-- apac
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from dvaccess.config import AppConfig
from dvaccess.models import (
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

BUS = ["root", "emea", "uk", "de", "apac"]
PARENTS = {"root": None, "emea": "root", "uk": "emea", "de": "emea", "apac": "root"}


def make_snapshot() -> Snapshot:
    snapshot = Snapshot(
        run_id="test-run", observed_at="2026-09-09T00:00:00Z",
        environment_url="https://example.crm.dynamics.com",
    )
    snapshot.business_units = [BusinessUnit(id=b, name=b.upper(), parent_id=PARENTS[b]) for b in BUS]
    snapshot.tables = [
        TableMeta("account", "Account", 1, Ownership.USER),
        TableMeta("contact", "Contact", 2, Ownership.USER),
        TableMeta("activity", "Activity", 3, Ownership.USER),
        TableMeta("product", "Product", 4, Ownership.ORG),
        TableMeta("role", "Role", 5, Ownership.BUSINESS),
    ]
    return snapshot


def add_user(snapshot: Snapshot, uid: str, bu: str, *, aad: str | None = "aad-" + "x",
             disabled: bool = False, access_mode: int = 0, app_id: str | None = None) -> DvUser:
    user = DvUser(
        id=uid, name=uid.title(), domain_name=f"{uid}@bank.test",
        aad_object_id=f"aad-{uid}" if aad is not None else None,
        bu_id=bu, is_disabled=disabled, access_mode=access_mode, application_id=app_id,
    )
    snapshot.users.append(user)
    return user


def add_role(snapshot: Snapshot, rid: str, bu: str, grants: list[tuple[str, Depth]],
             root_role_id: str | None = None, name: str | None = None) -> DvRole:
    role = DvRole(id=rid, name=name or rid, bu_id=bu, root_role_id=root_role_id or f"root-{rid}")
    snapshot.roles.append(role)
    for table, depth in grants:
        snapshot.role_grants.append(
            RoleReadGrant(role_id=rid, table=table, depth=depth, privilege_name=f"prvRead{table.title()}")
        )
    return role


def add_team(snapshot: Snapshot, tid: str, bu: str, members: list[str],
             roles: list[str], team_type: int = 0) -> DvTeam:
    team = DvTeam(id=tid, name=tid, bu_id=bu, team_type=team_type, aad_object_id=None)
    snapshot.teams.append(team)
    snapshot.team_members.extend((tid, uid) for uid in members)
    snapshot.team_roles.extend((tid, rid) for rid in roles)
    return team


def assign(snapshot: Snapshot, uid: str, rid: str) -> None:
    snapshot.user_roles.append((uid, rid))


@pytest.fixture
def app_config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "environment": {"name": "test", "dataverse_url": "https://example.crm.dynamics.com"},
            "auth": {"tenant_id": "tenant-1"},
            "fabric": {
                "workspace_id": "ws-1", "item_id": "item-1", "schema_name": "dbo",
                "role_prefix": "dv", "role_budget": 1000,
            },
        }
    )
