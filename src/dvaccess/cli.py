"""dvaccess command-line interface.

Stages:
  extract  - snapshot the Dataverse security model into runs/<run_id>/
  compile  - compute effective access, build profiles, compile OneLake roles
  plan     - read-only diff against the Fabric item (no writes anywhere)
  apply    - create/reconcile Entra groups and PUT the role set (requires --yes)
  verify   - re-fetch and confirm the item matches the compiled state
  explain  - trace why one user has access to which tables
  run      - extract + compile + plan (+ apply with --yes)
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from azure.identity import CredentialUnavailableError

from .apply.fabric_client import FabricClient
from .apply.onelake_client import OneLakeClient
from .auth import TokenProvider, WrongTenantError
from .compile.effective_access import build_index, explain_user, iter_user_scopes
from .compile.onelake_model import RoleBudgetExceeded
from .config import AppConfig, load_config
from .extract.dataverse_client import DataverseClient
from .extract.graph_client import GraphClient
from .extract.snapshot import latest_run_dir, load_snapshot, save_snapshot
from .extract.team_resolution import merge_aad_team_members
from .http_util import ApiError
from .models import ALL_ROWS, TeamType
from .pipeline import build_role_plan, compile_from_snapshot

logger = logging.getLogger("dvaccess")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    logging.getLogger("azure").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def _resolve_run_dir(cfg: AppConfig, run_id: str | None) -> Path:
    root = Path(cfg.run_dir)
    if run_id:
        directory = root / run_id
        if not (directory / "snapshot.sqlite").exists():
            raise SystemExit(f"No snapshot found in {directory}")
        return directory
    directory = latest_run_dir(root)
    if directory is None:
        raise SystemExit(f"No extract runs found under {root}; run 'dvaccess extract' first.")
    return directory


def cmd_extract(cfg: AppConfig, args: argparse.Namespace) -> Path:
    tokens = TokenProvider(cfg.auth)
    client = DataverseClient(cfg.environment.dataverse_url, tokens)
    try:
        who = client.whoami()
        logger.info(
            "Connected to %s (org %s) as %s",
            cfg.environment.dataverse_url, who.get("OrganizationId"), who.get("UserId"),
        )
        snapshot = client.fetch_snapshot(progress=logger.info)
    finally:
        client.close()

    aad_teams = [
        t for t in snapshot.teams if t.team_type in TeamType.AAD_TYPES and t.aad_object_id
    ]
    if aad_teams:
        graph = GraphClient(tokens)
        try:
            merge_aad_team_members(snapshot, graph)
        except (ApiError, CredentialUnavailableError) as exc:
            logger.warning(
                "Could not resolve %d Entra-group team(s) via Graph (%s). "
                "Their membership may be incomplete in this snapshot.",
                len(aad_teams), exc,
            )
        finally:
            graph.close()

    db_path = save_snapshot(snapshot, cfg.run_dir)
    logger.info("Snapshot saved: %s", db_path)
    for key, value in snapshot.counts().items():
        logger.info("  %s: %s", key, value)
    return db_path.parent


def _fetch_item_tables(cfg: AppConfig, tokens: TokenProvider) -> set[str] | None:
    """Tables present in the target Fabric item, or None to compile unfiltered."""
    if not cfg.fabric.restrict_to_item_tables:
        return None
    client = OneLakeClient(tokens)
    try:
        return client.list_tables(
            cfg.fabric.workspace_id, cfg.fabric.item_id, cfg.fabric.schema_name
        )
    except ApiError as exc:
        logger.warning(
            "Could not list tables in the target item (%s). Compiling WITHOUT the item "
            "filter: permissions may name tables that are not synced, which grant "
            "nothing but count against the 500-permissions-per-role limit.",
            exc,
        )
        return None
    finally:
        client.close()


def cmd_compile(cfg: AppConfig, args: argparse.Namespace) -> None:
    run_dir = _resolve_run_dir(cfg, args.run)
    snapshot = load_snapshot(run_dir / "snapshot.sqlite")
    item_tables = _fetch_item_tables(cfg, TokenProvider(cfg.auth))
    compiled = compile_from_snapshot(snapshot, cfg, run_dir, item_tables)
    stats = compiled.profile_result.stats
    logger.info("Profiles: %s | OneLake roles compiled: %d", stats, len(compiled.roles))
    if len(compiled.roles) > cfg.fabric.role_budget:
        raise SystemExit(
            f"Compiled {len(compiled.roles)} roles which alone exceed the budget of "
            f"{cfg.fabric.role_budget}. See {run_dir / 'compile_summary.md'}."
        )
    logger.info("Compile reports written to %s", run_dir)


def _plan_or_apply(cfg: AppConfig, args: argparse.Namespace, *, apply_changes: bool) -> None:
    run_dir = _resolve_run_dir(cfg, args.run)
    snapshot = load_snapshot(run_dir / "snapshot.sqlite")
    tokens = TokenProvider(cfg.auth)
    compiled = compile_from_snapshot(
        snapshot, cfg, run_dir, _fetch_item_tables(cfg, tokens)
    )

    fabric = FabricClient(tokens)
    graph = GraphClient(tokens) if cfg.entra.membership == "group" else None
    try:
        plan, _groups, pending = build_role_plan(
            compiled, cfg, fabric, graph,
            create_groups=apply_changes,
            reconcile_members=apply_changes,
            out_dir=run_dir,
        )
        logger.info("Plan: %s", plan.summary())
        for name in plan.creates:
            logger.info("  + create %s", name)
        for name in plan.updates:
            logger.info("  ~ update %s", name)
        for name in plan.deletes:
            logger.info("  - delete %s", name)
        for name in plan.retires:
            logger.info("  - RETIRE (replaced by this app) %s", name)
        for name in plan.kept_stale:
            logger.info("  ! stale (prune off, kept) %s", name)
        if pending:
            logger.info(
                "Entra groups not yet created for %d profile(s)%s",
                len(pending),
                "" if apply_changes else " (created during apply)",
            )

        if not apply_changes:
            if getattr(args, "dry_run", False):
                fabric.put_data_access_roles(
                    cfg.fabric.workspace_id, cfg.fabric.item_id,
                    plan.payload, etag=plan.etag, dry_run=True,
                )
                logger.info("Server-side dryRun validation passed.")
            logger.info("Plan written to %s (no changes made).", run_dir / "plan.json")
            return

        if pending:
            raise SystemExit(f"Cannot apply: profiles without Entra groups: {pending}")
        if not plan.has_changes:
            logger.info("No role changes needed; item already matches compiled state.")
            return
        try:
            new_etag = fabric.put_data_access_roles(
                cfg.fabric.workspace_id, cfg.fabric.item_id, plan.payload, etag=plan.etag
            )
        except ApiError as exc:
            if exc.status_code == 412:
                logger.warning("ETag conflict (item changed during run); refetching and retrying once.")
                actual, etag = fabric.get_data_access_roles(cfg.fabric.workspace_id, cfg.fabric.item_id)
                from .apply.differ import build_plan as rebuild
                desired_api = [r.to_api(cfg.fabric_tenant_id) for r in compiled.roles]
                plan = rebuild(
                    actual, etag, desired_api, cfg.fabric.role_prefix, cfg.apply.prune,
                    cfg.apply.retire_role_patterns,
                )
                new_etag = fabric.put_data_access_roles(
                    cfg.fabric.workspace_id, cfg.fabric.item_id, plan.payload, etag=plan.etag
                )
            else:
                raise
        logger.info("Applied. New ETag: %s", new_etag)
        _verify(cfg, compiled, fabric, run_dir)
    finally:
        fabric.close()
        if graph:
            graph.close()


def _verify(cfg: AppConfig, compiled, fabric: FabricClient, run_dir: Path) -> None:
    from .apply.differ import build_plan as rebuild

    actual, etag = fabric.get_data_access_roles(cfg.fabric.workspace_id, cfg.fabric.item_id)
    desired_api = [r.to_api(cfg.fabric_tenant_id) for r in compiled.roles]
    check = rebuild(
        actual, etag, desired_api, cfg.fabric.role_prefix, cfg.apply.prune,
        cfg.apply.retire_role_patterns,
    )
    if check.has_changes:
        logger.error("VERIFY FAILED: item still differs from compiled state: %s", check.summary())
        raise SystemExit(1)
    logger.info(
        "Verify OK: %d managed roles match compiled state (%d unmanaged untouched). "
        "Note: role changes take ~5 min, group membership up to ~1 h to enforce.",
        len(check.unchanged), len(check.unmanaged),
    )


def cmd_verify(cfg: AppConfig, args: argparse.Namespace) -> None:
    run_dir = _resolve_run_dir(cfg, args.run)
    snapshot = load_snapshot(run_dir / "snapshot.sqlite")
    tokens = TokenProvider(cfg.auth)
    compiled = compile_from_snapshot(
        snapshot, cfg, run_dir, _fetch_item_tables(cfg, tokens)
    )
    graph = GraphClient(tokens) if cfg.entra.membership == "group" else None
    fabric = FabricClient(tokens)
    try:
        if graph is not None:
            from .apply.entra_groups import resolve_profile_groups

            groups = resolve_profile_groups(
                graph, compiled.profiles, cfg.entra.group_prefix, cfg.environment.name,
                create_missing=False,
            )
            from .pipeline import attach_group_membership

            pending = attach_group_membership(compiled, groups)
            if pending:
                logger.warning("Profiles without Entra groups yet: %s", pending)
        _verify(cfg, compiled, fabric, run_dir)
    finally:
        fabric.close()
        if graph:
            graph.close()


def cmd_explain(cfg: AppConfig, args: argparse.Namespace) -> None:
    run_dir = _resolve_run_dir(cfg, args.run)
    snapshot = load_snapshot(run_dir / "snapshot.sqlite")
    index = build_index(snapshot, cfg.compile)
    needle = args.user.lower()
    matches = [
        u for u in snapshot.users
        if needle in (u.id.lower(), (u.domain_name or "").lower(), u.name.lower())
    ]
    if not matches:
        raise SystemExit(f"No user matching {args.user!r} in snapshot {snapshot.run_id}")
    if len(matches) > 1:
        raise SystemExit(
            "Ambiguous user; candidates: " + ", ".join(f"{u.name} ({u.id})" for u in matches)
        )
    user = matches[0]
    print(f"User: {user.name} ({user.id}) BU={user.bu_id} aad={user.aad_object_id}")
    rows = explain_user(index, user, args.table)
    if not rows:
        print("No read grants found (or user is ineligible).")
    for row in rows:
        via = f" via team '{row['via_team']}'" if row["via_team"] else ""
        print(
            f"  {row['table']}: {row['depth']} read from role '{row['role']}' "
            f"[BU {row['role_bu']}]{via} (table ownership: {row['ownership']})"
        )
    index.eligible_users = [u for u in index.eligible_users if u.id == user.id]
    for _, scopes in iter_user_scopes(index):
        print("Effective OneLake scopes:")
        for table, scope in sorted(scopes.items()):
            if args.table and table.lower() != args.table.lower():
                continue
            desc = "ALL rows" if scope == ALL_ROWS else f"rows of {len(scope)} business unit(s)"
            print(f"  {table}: {desc}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dvaccess", description=__doc__)
    parser.add_argument("--config", default="config/config.yaml", help="Path to config YAML")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("extract", help="Snapshot the Dataverse security model")
    for name, help_text in [
        ("compile", "Compile profiles and OneLake roles from a snapshot"),
        ("verify", "Check the Fabric item matches the compiled state"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--run", help="Run id (default: latest)")

    p = sub.add_parser("plan", help="Read-only diff against the Fabric item")
    p.add_argument("--run", help="Run id (default: latest)")
    p.add_argument("--dry-run", action="store_true",
                   help="Also validate the payload server-side with dryRun=true")

    p = sub.add_parser("apply", help="Apply compiled roles to the Fabric item")
    p.add_argument("--run", help="Run id (default: latest)")
    p.add_argument("--yes", action="store_true", help="Confirm applying changes")

    p = sub.add_parser("explain", help="Trace one user's access")
    p.add_argument("--run", help="Run id (default: latest)")
    p.add_argument("--user", required=True, help="User id, full name, or UPN")
    p.add_argument("--table", help="Limit to one table")

    p = sub.add_parser("run", help="extract + compile + plan (+ apply with --yes)")
    p.add_argument("--yes", action="store_true", help="Also apply changes")

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    cfg = load_config(args.config)

    try:
        if args.command == "extract":
            cmd_extract(cfg, args)
        elif args.command == "compile":
            cmd_compile(cfg, args)
        elif args.command == "plan":
            _plan_or_apply(cfg, args, apply_changes=False)
        elif args.command == "apply":
            if not args.yes:
                raise SystemExit("apply changes external state; re-run with --yes to confirm.")
            _plan_or_apply(cfg, args, apply_changes=True)
        elif args.command == "verify":
            cmd_verify(cfg, args)
        elif args.command == "explain":
            cmd_explain(cfg, args)
        elif args.command == "run":
            run_dir = cmd_extract(cfg, args)
            args.run = run_dir.name
            if args.yes:
                _plan_or_apply(cfg, args, apply_changes=True)
            else:
                args.dry_run = False
                _plan_or_apply(cfg, args, apply_changes=False)
    except KeyboardInterrupt:
        if args.command in ("apply", "run") and getattr(args, "yes", False):
            logger.error(
                "Interrupted during apply. Run 'dvaccess verify' to check the item's state."
            )
        else:
            logger.error(
                "Interrupted. '%s' is read-only for Dataverse, Entra and Fabric, so "
                "nothing was changed.",
                args.command,
            )
        return 130
    except RoleBudgetExceeded as exc:
        logger.error("%s", exc)
        return 2
    except WrongTenantError as exc:
        logger.error("%s", exc)
        return 3
    except CredentialUnavailableError as exc:
        logger.error(
            "Authentication cannot proceed with the current credential: %s\n"
            "Either run the az command above to satisfy the claims challenge, or "
            "configure a service principal (auth.client_id + DVACCESS_CLIENT_SECRET), "
            "which answers claims challenges automatically.",
            exc,
        )
        return 3
    except ApiError as exc:
        logger.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
