"""Capacity estimates are review artifacts, never security deployment payloads."""
import hashlib
import json
import math
from collections import defaultdict

from .engine import AccessEngine


def plan(engine: AccessEngine, role_limit: int = 1000) -> dict:
    if not 1 <= role_limit <= 1000:
        raise ValueError("Configure a verified role limit between 1 and 1000")
    snapshot = engine.snapshot
    signatures = defaultdict(list)
    facts = defaultdict(list)
    for row in engine.scope_rows():
        # Resolve Basic ownership per principal: omit display role labels/IDs but never owner IDs or BU anchors.
        own_scope = row["user_id"] if row["via_type"] == "user" or row["member_basic"] or row["depth"] != "Basic" else row["via_id"]
        facts[row["user_id"]].append((row["table"], row["depth"], row["bu_anchor"], own_scope))
    for user in snapshot.users:
        if user.id not in facts:
            continue
        principals = {("user", user.id)} | {("team", t) for t in engine.memberships[user.id]}
        # Include all resolved columns, ownership teams and exceptions; conservative signatures may over-split.
        profiles = [p.model_dump(mode="json") for p in snapshot.profiles if any(
            a.profile_id == p.id and (a.principal_type, a.principal_id) in principals
            for a in snapshot.profile_assignments)]
        exceptions = [a.model_dump(mode="json") for a in snapshot.record_access
                      if (a.principal_type, a.principal_id) in principals]
        canonical = {"scopes": sorted(set(facts[user.id])), "profiles": profiles,
                     "exceptions": exceptions, "owner_teams": sorted(engine.memberships[user.id])}
        digest = hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()
        signatures[digest].append(user.entra_object_id)
    candidate_roles = sum(math.ceil(len(members) / 500) for members in signatures.values())
    return {
        "status": "review_only", "publishable": False, "role_limit": role_limit,
        "role_limit_source": "User-reported Microsoft support exception; verify on target item",
        "candidate_signatures": len(signatures), "candidate_roles_after_member_splits": candidate_roles,
        "fits_role_count_only": candidate_roles <= role_limit,
        "scope_fact_count": sum(len(v) for v in facts.values()),
        "blockers": [
            "No production publisher or Fabric endpoint parity certification is implemented.",
            "Live inventory has not been normalized into verified record and column access evidence.",
            "OneLake RLS cannot join a dynamic user entitlement table; identity-dependent scopes require static materialization or SQL enforcement.",
            "Table mappings, 500 permissions/role, expression limits, CLS combinations, and existing permissions need target-specific validation.",
            *snapshot.blockers,
        ],
        "note": "Conservative candidate grouping is not a minimum-role solver or a deployable OneLake policy.",
        "recommended_plane": "Fabric Warehouse SQL RLS with entitlement tables; restricted raw OneLake",
    }
