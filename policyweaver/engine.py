"""Conservative reference evaluator for normalized READ facts.

This is an analyst simulator, not an authorization boundary. It deliberately does
not infer sharing, hierarchy, role inheritance, or administrators from labels.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone

from .models import Snapshot


class AccessEngine:
    def __init__(self, snapshot: Snapshot):
        self.snapshot = snapshot
        self.version = hashlib.sha256(json.dumps(snapshot.model_dump(mode="json"), sort_keys=True,
                                                separators=(",", ":")).encode()).hexdigest()
        self.users = {u.id: u for u in snapshot.users}
        self.teams = {t.id: t for t in snapshot.teams}
        self.roles = {r.id: r for r in snapshot.roles}
        self.tables = {t.name: t for t in snapshot.tables}
        self.records = {(r.table, r.id): r for r in snapshot.records}
        self.profiles = {p.id: p for p in snapshot.profiles}
        self.memberships = defaultdict(set)
        self.assignments = defaultdict(set)
        self.profile_assignments = defaultdict(set)
        self.exceptions = defaultdict(list)
        self.ancestors = {}
        bus = {b.id: b for b in snapshot.business_units}
        for bu in bus.values():
            ancestors = {bu.id}
            parent = bu.parent_id
            while parent:
                ancestors.add(parent)
                parent = bus[parent].parent_id
            self.ancestors[bu.id] = ancestors
        for edge in snapshot.memberships:
            self.memberships[edge.user_id].add(edge.team_id)
        for edge in snapshot.assignments:
            self.assignments[(edge.principal_type, edge.principal_id)].add(edge.role_id)
        for edge in snapshot.profile_assignments:
            self.profile_assignments[(edge.principal_type, edge.principal_id)].add(edge.profile_id)
        for access in snapshot.record_access:
            self.exceptions[(access.table, access.record_id)].append(access)
        self.grants = defaultdict(list)
        for principal, role_ids in self.assignments.items():
            for role_id in sorted(role_ids):
                role = self.roles[role_id]
                for grant in role.grants:
                    self.grants[(principal, grant.table)].append((role, grant))

    def evaluate(self, user_id: str, table: str, record_id: str, column: str | None = None,
                 *, now: datetime | None = None, tenant_id: str | None = None,
                 organization_id: str | None = None) -> dict:
        now = now or datetime.now(timezone.utc)
        result = {"allowed": False, "reasons": [], "policy_version": self.version,
                  "simulation": True, "column_state": None}

        def deny(reason):
            result["reasons"].append(reason)
            return result

        if (tenant_id is not None and tenant_id != self.snapshot.tenant_id) or (
                organization_id is not None and organization_id != self.snapshot.organization_id):
            return deny("Tenant or organization does not match this security snapshot.")
        if now < self.snapshot.observed_at or now >= self.snapshot.valid_until:
            return deny("Security snapshot is stale or from the future; refresh before evaluating.")
        if self.snapshot.blockers:
            return deny("Incomplete security evidence: " + "; ".join(self.snapshot.blockers))
        if any(not t.membership_verified for t in self.snapshot.teams):
            return deny("Team membership evidence is incomplete; evaluation blocked.")
        user = self.users.get(user_id)
        if not user or not user.enabled or not user.entra_object_id:
            return deny("User is missing, disabled, or has no verified Entra object ID.")
        # Explicitly support interactive read-write (0) and read-only (2) users.
        if user.application or user.access_mode not in (0, 2):
            return deny("Application or special access-mode identity requires a separate approved policy.")
        record = self.records.get((table, record_id))
        if not record:
            return deny("Unknown table or record; no name-based fallback is permitted.")
        teams = self.memberships[user_id]
        principals = [("user", user_id), *[("team", t) for t in sorted(teams)]]
        effective = [(principal, role, grant) for principal in principals
                     for role, grant in self.grants[(principal, table)]]
        if not effective:
            return deny("No table Read privilege. Sharing or ownership alone cannot grant access.")
        # Never take max(depth) across different BU anchors or different team contexts.
        personal_basic = any(p[0] == "user" or role.member_basic or grant.depth != "Basic"
                             for p, role, grant in effective)
        for principal, role, grant in effective:
            reason = None
            if grant.depth == "Global":
                reason = "Global Read"
            elif grant.depth in ("Local", "Deep") and record.owning_bu_id == role.bu_id:
                reason = f"{grant.depth} Read in role business unit"
            elif grant.depth == "Deep" and role.bu_id in self.ancestors.get(record.owning_bu_id, set()):
                reason = "Deep Read in a descendant of the role business unit"
            elif principal[0] == "team" and record.owner_id == principal[1]:
                reason = "Read through the team that owns this record"
            if reason:
                result["reasons"].append(f"{reason}: role {role.name} ({role.id}), {principal[0]} {principal[1]}.")
        if personal_basic and record.owner_id in {user_id, *teams}:
            result["reasons"].append("Read privilege plus user/team ownership, including ownership across business units.")
        for access in self.exceptions[(table, record_id)]:
            if (access.principal_type, access.principal_id) in principals and personal_basic:
                result["reasons"].append(f"Verified {access.kind} Read exception: {access.evidence}.")
        if not result["reasons"]:
            return deny("Read privilege exists, but no supported ownership, BU scope, sharing, or hierarchy grant matches.")
        result["allowed"] = True
        if column is None:
            return result
        column_meta = next((c for c in self.tables[table].columns if c.name == column), None)
        if not column_meta:
            result["allowed"] = False
            return deny("Unknown column; field access denied.")
        if not column_meta.secured and not column_meta.masked:
            result["column_state"] = "readable"
            return result
        profile_ids = set().union(*(self.profile_assignments[p] for p in principals))
        permissions = [(pid, permission) for pid in sorted(profile_ids)
                       for permission in self.profiles[pid].permissions
                       if permission.table == table and permission.column == column and permission.can_read]
        if not permissions:
            result["allowed"] = False
            result["column_state"] = "hidden"
            return deny("No assigned field-security profile grants Read for this secured column.")
        result["reasons"].append("Column Read granted by profile(s): " + ", ".join(self.profiles[p].name for p, _ in permissions))
        if column_meta.masked:
            if any(p.read_unmasked == "all" for _, p in permissions):
                result["column_state"] = "unmasked_bulk_permitted"
            else:
                result["allowed"] = False
                result["column_state"] = "requires_masked_projection"
                return deny("Bulk raw value denied: masked/one-record unmask permissions require a separately validated masked projection.")
        else:
            result["column_state"] = "readable"
        return result

    def scope_rows(self) -> list[dict]:
        """Compact entitlement facts for review. No Cartesian user × record expansion."""
        rows = []
        for user in self.snapshot.users:
            if not user.enabled or not user.entra_object_id or user.application or user.access_mode not in (0, 2):
                continue
            principals = [("user", user.id), *[("team", t) for t in sorted(self.memberships[user.id])]]
            for principal in principals:
                for role_id in sorted(self.assignments[principal]):
                    role = self.roles[role_id]
                    for grant in role.grants:
                        rows.append({"tenant_id": self.snapshot.tenant_id,
                                     "organization_id": self.snapshot.organization_id,
                                     "user_id": user.id, "entra_object_id": user.entra_object_id,
                                     "table": grant.table, "depth": grant.depth,
                                     "bu_anchor": role.bu_id, "via_type": principal[0],
                                     "via_id": principal[1], "member_basic": role.member_basic,
                                     "role_id": role.id, "policy_version": self.version})
        return rows
