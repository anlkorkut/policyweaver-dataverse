"""Per-profile Entra security-group management.

Group mode assigns exactly one Entra security group per access profile as the
sole member of that profile's OneLake role family. Group names are deterministic
(prefix + profile hash) so re-runs find and reuse existing groups.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from ..extract.graph_client import GraphClient
from ..models import Profile

logger = logging.getLogger(__name__)


def group_display_name(prefix: str, profile: Profile) -> str:
    return f"{prefix}{profile.short_hash}"


@dataclass
class GroupReconcileResult:
    profile_hash: str
    display_name: str
    group_id: str | None
    created: bool = False
    members_added: int = 0
    members_removed: int = 0
    pending_create: bool = False  # plan-only: group does not exist yet


def resolve_profile_groups(
    graph: GraphClient,
    profiles: list[Profile],
    prefix: str,
    environment_name: str,
    create_missing: bool,
) -> list[GroupReconcileResult]:
    """Look up (and in apply mode create) the Entra group for each profile."""
    results: list[GroupReconcileResult] = []
    for profile in profiles:
        name = group_display_name(prefix, profile)
        group_id = graph.find_group_id(name)
        created = False
        pending = False
        if group_id is None:
            if create_missing:
                group_id = graph.create_security_group(
                    name,
                    description=(
                        f"dvaccess managed: Dataverse access profile {profile.short_hash} "
                        f"for environment {environment_name}. Do not edit membership manually."
                    ),
                )
                created = True
            else:
                pending = True
        results.append(
            GroupReconcileResult(
                profile_hash=profile.profile_hash,
                display_name=name,
                group_id=group_id,
                created=created,
                pending_create=pending,
            )
        )
    return results


def reconcile_group_members(
    graph: GraphClient,
    result: GroupReconcileResult,
    desired_aad_ids: set[str],
    dry_run: bool,
) -> GroupReconcileResult:
    if result.group_id is None:
        return result
    current = graph.list_member_ids(result.group_id)
    to_add = sorted(desired_aad_ids - current)
    to_remove = sorted(current - desired_aad_ids)
    result.members_added = len(to_add)
    result.members_removed = len(to_remove)
    if dry_run:
        return result
    if to_add:
        graph.add_members(result.group_id, to_add)
    for member_id in to_remove:
        graph.remove_member(result.group_id, member_id)
    if to_add or to_remove:
        logger.info(
            "Group %s: +%d / -%d members", result.display_name, len(to_add), len(to_remove)
        )
    return result
