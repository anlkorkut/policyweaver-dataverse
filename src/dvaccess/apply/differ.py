"""Diff desired (compiled) roles against the item's current roles.

Only roles whose name starts with the managed prefix are ever created, updated,
or deleted; every other role (DefaultReader, human-authored roles) is passed
through to the PUT payload byte-for-byte, because the API replaces the full set.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field

_SERVER_MANAGED_FIELDS = frozenset({"id", "kind", "etag"})


def normalize_role(role: dict) -> str:
    """Canonical form for change detection: server-managed fields (id, kind, etag)
    dropped, unordered lists sorted, GUID-like strings lowercased. Members compare by
    objectId alone: Fabric does not round-trip objectType, and an objectId already
    identifies exactly one directory object."""

    def canon(value: object) -> object:
        if isinstance(value, dict):
            is_member = "objectId" in value
            return {
                k: canon(v)
                for k, v in sorted(value.items())
                if k not in _SERVER_MANAGED_FIELDS and not (is_member and k == "objectType")
            }
        if isinstance(value, list):
            return sorted((canon(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
        if isinstance(value, str) and _looks_like_guid(value):
            return value.lower()
        return value

    return json.dumps(canon(role), sort_keys=True)


def _looks_like_guid(value: str) -> bool:
    v = value.strip("{}")
    return len(v) == 36 and v.count("-") == 4


@dataclass
class RolePlan:
    creates: list[str] = field(default_factory=list)
    updates: list[str] = field(default_factory=list)
    deletes: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    kept_stale: list[str] = field(default_factory=list)  # would delete, but prune is off
    retires: list[str] = field(default_factory=list)  # pre-existing roles being replaced
    unmanaged: list[str] = field(default_factory=list)
    payload: list[dict] = field(default_factory=list)
    etag: str | None = None

    @property
    def has_changes(self) -> bool:
        return bool(self.creates or self.updates or self.deletes or self.retires)

    def summary(self) -> dict:
        return {
            "creates": len(self.creates),
            "updates": len(self.updates),
            "deletes": len(self.deletes),
            "retires": len(self.retires),
            "unchanged": len(self.unchanged),
            "kept_stale": len(self.kept_stale),
            "unmanaged_passthrough": len(self.unmanaged),
            "payload_roles": len(self.payload),
        }


def build_plan(
    actual_roles: list[dict],
    etag: str | None,
    desired_roles: list[dict],
    managed_prefix: str,
    prune: bool,
    retire_patterns: list[str] | None = None,
) -> RolePlan:
    patterns = retire_patterns or []
    plan = RolePlan(etag=etag)
    actual_managed: dict[str, dict] = {}
    for role in actual_roles:
        name = role.get("name", "")
        if name.startswith(managed_prefix):
            actual_managed[name] = role
        elif any(fnmatch.fnmatch(name, p) for p in patterns):
            # Retired by omission from the replacement payload.
            plan.retires.append(name)
        else:
            plan.unmanaged.append(name)
            plan.payload.append(role)

    desired_by_name = {role["name"]: role for role in desired_roles}
    duplicate = len(desired_by_name) != len(desired_roles)
    if duplicate:
        raise ValueError("Compiled role names are not unique; refusing to build a plan.")

    for name, desired in sorted(desired_by_name.items()):
        existing = actual_managed.get(name)
        if existing is None:
            plan.creates.append(name)
            plan.payload.append(desired)
        else:
            if normalize_role(existing) == normalize_role(desired):
                plan.unchanged.append(name)
                plan.payload.append(existing)
            else:
                plan.updates.append(name)
                merged = dict(desired)
                if "id" in existing:
                    merged["id"] = existing["id"]
                plan.payload.append(merged)

    for name, existing in sorted(actual_managed.items()):
        if name in desired_by_name:
            continue
        if prune:
            plan.deletes.append(name)  # deletion happens by omission from the payload
        else:
            plan.kept_stale.append(name)
            plan.payload.append(existing)

    return plan
