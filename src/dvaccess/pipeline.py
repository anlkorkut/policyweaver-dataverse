"""Stage orchestration shared by the CLI commands."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from .apply.differ import RolePlan, build_plan
from .apply.entra_groups import (
    GroupReconcileResult,
    reconcile_group_members,
    resolve_profile_groups,
)
from .apply.fabric_client import FabricClient
from .compile.effective_access import SecurityIndex, build_index
from .compile.onelake_model import (
    compile_all_roles,
    rls_columns_for_tables,
    validate_role_budget,
)
from .compile.profiles import ProfileBuildResult, build_profiles
from .config import AppConfig
from .extract.graph_client import GraphClient
from .models import Profile, RoleDefinition, Snapshot
from .report.reports import write_compile_reports, write_json

logger = logging.getLogger(__name__)


@dataclass
class CompiledOutput:
    index: SecurityIndex
    profiles: list[Profile]
    profile_result: ProfileBuildResult
    roles: list[RoleDefinition]
    aad_by_user_id: dict[str, str] = field(default_factory=dict)

    def roles_by_profile(self) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for role in self.roles:
            grouped.setdefault(role.profile_hash, []).append(role.name)
        return grouped


def compile_from_snapshot(
    snapshot: Snapshot,
    cfg: AppConfig,
    out_dir: Path,
    item_tables: set[str] | None = None,
) -> CompiledOutput:
    index = build_index(snapshot, cfg.compile, item_tables)
    profile_result = build_profiles(index, cfg.compile)
    aad_by_user_id = {
        u.id: u.aad_object_id for u in index.eligible_users if u.aad_object_id
    }
    roles = compile_all_roles(
        profile_result.profiles, cfg, aad_by_user_id,
        rls_columns_for_tables(index.table_ownership, cfg),
    )
    output = CompiledOutput(
        index=index,
        profiles=profile_result.profiles,
        profile_result=profile_result,
        roles=roles,
        aad_by_user_id=aad_by_user_id,
    )
    write_compile_reports(
        out_dir, index, output.profiles, profile_result.stats, output.roles_by_profile()
    )
    return output


def attach_group_membership(
    compiled: CompiledOutput,
    group_results: list[GroupReconcileResult],
) -> list[str]:
    """Set each role's Entra group member; returns profile hashes still lacking a group."""
    by_hash = {g.profile_hash: g for g in group_results}
    pending: list[str] = []
    for role in compiled.roles:
        result = by_hash.get(role.profile_hash)
        if result and result.group_id:
            role.entra_group_id = result.group_id
        else:
            pending.append(role.profile_hash)
    return sorted(set(pending))


def build_role_plan(
    compiled: CompiledOutput,
    cfg: AppConfig,
    fabric: FabricClient,
    graph: GraphClient | None,
    *,
    create_groups: bool,
    reconcile_members: bool,
    out_dir: Path,
) -> tuple[RolePlan, list[GroupReconcileResult], list[str]]:
    """Fetch current state, resolve membership, and produce the diff plan."""
    group_results: list[GroupReconcileResult] = []
    pending_groups: list[str] = []
    if cfg.entra.membership == "group":
        if graph is None:
            raise RuntimeError("Graph client required for entra.membership='group'")
        group_results = resolve_profile_groups(
            graph, compiled.profiles, cfg.entra.group_prefix, cfg.environment.name,
            create_missing=create_groups,
        )
        members_by_hash = {
            p.profile_hash: {
                compiled.aad_by_user_id[uid]
                for uid in p.user_ids
                if uid in compiled.aad_by_user_id
            }
            for p in compiled.profiles
        }
        for result in group_results:
            reconcile_group_members(
                graph, result, members_by_hash.get(result.profile_hash, set()),
                dry_run=not reconcile_members,
            )
        pending_groups = attach_group_membership(compiled, group_results)

    actual_roles, etag = fabric.get_data_access_roles(cfg.fabric.workspace_id, cfg.fabric.item_id)
    desired_api = [role.to_api(cfg.fabric_tenant_id) for role in compiled.roles]
    plan = build_plan(
        actual_roles, etag, desired_api, cfg.fabric.role_prefix, cfg.apply.prune,
        cfg.apply.retire_role_patterns,
    )
    validate_role_budget(
        desired_count=len(desired_api),
        unmanaged_count=len(plan.unmanaged) + len(plan.kept_stale),
        budget=cfg.fabric.role_budget,
    )

    write_json(
        out_dir / "plan.json",
        {
            "summary": plan.summary(),
            "creates": plan.creates,
            "updates": plan.updates,
            "deletes": plan.deletes,
            "retires": plan.retires,
            "kept_stale": plan.kept_stale,
            "unmanaged_passthrough": plan.unmanaged,
            "profiles_awaiting_group_creation": pending_groups,
            "groups": [
                {
                    "profile": g.profile_hash[:12],
                    "display_name": g.display_name,
                    "group_id": g.group_id,
                    "created": g.created,
                    "pending_create": g.pending_create,
                    "members_added": g.members_added,
                    "members_removed": g.members_removed,
                }
                for g in group_results
            ],
        },
    )
    write_json(out_dir / "desired_roles.json", desired_api)
    return plan, group_results, pending_groups
