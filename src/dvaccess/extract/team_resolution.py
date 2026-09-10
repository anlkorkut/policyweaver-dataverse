"""Resolve Entra-group-backed Dataverse teams to concrete user memberships.

Dataverse materializes group-team membership lazily, so teammembership rows can
be incomplete for teamtype 2/3 teams. This merges Microsoft Graph transitive
group membership (mapped back to Dataverse users by Entra object id) into the
snapshot before compilation.
"""

from __future__ import annotations

import logging

from ..models import Snapshot, TeamType
from .graph_client import GraphClient

logger = logging.getLogger(__name__)


def merge_aad_team_members(snapshot: Snapshot, graph: GraphClient) -> dict:
    users_by_aad = {
        u.aad_object_id.lower(): u.id for u in snapshot.users if u.aad_object_id
    }
    existing = set(snapshot.team_members)
    stats = {"aad_teams": 0, "members_added": 0, "aad_users_not_in_dataverse": 0}
    for team in snapshot.teams:
        if team.team_type not in TeamType.AAD_TYPES or not team.aad_object_id:
            continue
        stats["aad_teams"] += 1
        for aad_id in graph.transitive_user_member_ids(team.aad_object_id):
            user_id = users_by_aad.get(aad_id.lower())
            if user_id is None:
                stats["aad_users_not_in_dataverse"] += 1
                continue
            pair = (team.id, user_id)
            if pair not in existing:
                existing.add(pair)
                snapshot.team_members.append(pair)
                stats["members_added"] += 1
    if stats["aad_teams"]:
        logger.info("Entra team resolution: %s", stats)
    return stats
