"""Policy Weaver adapter operator commands; preparation never grants access."""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path


def output(value):
    print(json.dumps(value, indent=2, default=str), flush=True)


def progress_output(event):
    """Runtime supplies aggregate-only telemetry; stdout remains result JSON."""
    print(json.dumps(event, separators=(",", ":")), file=sys.stderr, flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("policyweaver.config.json"))
    parser.add_argument("--progress", action="store_true",
                        help="Emit sanitized live progress as timestamped JSON Lines on stderr")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("discover", "prepare", "status", "doctor", "withdraw", "watchdog", "provision"):
        commands.add_parser(name)
    for name in ("dry-run", "publish", "boundary-template"):
        command = commands.add_parser(name)
        command.add_argument("--generation", type=int, required=True)
        if name == "publish":
            command.add_argument("--boundary", type=Path, required=True)
    for name in ("run", "worker"):
        command = commands.add_parser(name)
        command.add_argument("--publish", action="store_true")
        command.add_argument("--boundary", type=Path)
    commands.add_parser("watchdog-worker")
    recovery = commands.add_parser("recover-lock")
    recovery.add_argument("--expected-owner", required=True)
    recovery.add_argument("--worker-stopped", action="store_true")
    console = commands.add_parser("console")
    console.add_argument("--port", type=int, default=8000)
    for command in commands.choices.values():
        command.add_argument("--progress", action="store_true", default=argparse.SUPPRESS,
                            help="Emit sanitized live progress on stderr")
    args = parser.parse_args(argv)
    try:
        from .config import load_config, state_path
        from .journal import Journal
        config = load_config(args.config)
        if args.command == "console":
            import uvicorn
            os.environ["POLICYWEAVER_CONFIG"] = str(args.config.resolve())
            uvicorn.run("policyweaver.app:app", host="127.0.0.1", port=args.port, proxy_headers=False)
            return 0
        if args.command == "status":
            journal = Journal(state_path(config, args.config))
            runs = journal.recent()
            output({"deployment": config.deployment_name, "runs": runs,
                    "configured_retention_mode": config.retention_mode,
                    "writer_lock": journal.lock_info(),
                    "production_certified": False, "native_expiry_self_enforcing": False})
            return 0
        if args.command == "recover-lock":
            Journal(state_path(config, args.config)).recover_lock(args.expected_owner, worker_stopped=args.worker_stopped)
            output({"status": "writer_lock_recovered", "action": "Run watchdog and inspect remote roles before restarting publication."})
            return 0
        from .runtime import AdapterRuntime
        runtime_options = {"progress": progress_output} if args.progress else {}
        with AdapterRuntime(args.config, **runtime_options) as runtime:
            if args.command == "discover":
                output(runtime.discover())
            elif args.command == "doctor":
                with runtime.source() as source:
                    org = source.verify_environment()
                    tables = [source.table_metadata(t.name, t.columns) for t in config.tables]
                    output({"organization_verified": org, "eligible_reader_count": len(source.discover_readers()),
                            "tables": [{"name": t.name, "columns": list(t.columns),
                                        "secured_columns": [a.property_name for a in t.attributes if a.is_secured],
                                        "masked_columns": [a.property_name for a in t.attributes if a.is_masked]}
                                       for t in tables],
                            "serving_item_count": len(config.serving_items), "production_certified": False})
            elif args.command == "prepare":
                output(runtime.prepare())
            elif args.command == "provision":
                from .provisioning import provision
                output(provision(runtime))
            elif args.command == "dry-run":
                output(runtime.dry_run(args.generation))
            elif args.command == "publish":
                output(runtime.publish(args.generation, args.boundary))
            elif args.command == "boundary-template":
                _, _, _, plan = runtime.prepared(args.generation)
                output({s.key: {"workspace_id": config.workspace_id, "item_id": config.serving_items[s.key],
                    "reader_ids": list(s.reader_ids), "inspected_at": "REPLACE_WITH_ACTUAL_INSPECTION_UTC",
                    "no_privileged_workspace_readers": False, "no_alternate_data_access": False,
                    "sql_endpoint_mode": "UNVERIFIED"} for s in plan.shards})
            elif args.command == "withdraw":
                output(runtime.withdraw())
            elif args.command == "watchdog":
                output(runtime.watchdog())
            elif args.command in ("run", "worker", "watchdog-worker"):
                if getattr(args, "publish", False) and not args.boundary:
                    parser.error("--publish requires a current, reviewed --boundary file")
                stopping = False
                def stop(*_):
                    nonlocal stopping
                    stopping = True
                signal.signal(signal.SIGTERM, stop)
                signal.signal(signal.SIGINT, stop)
                while not stopping:
                    started = time.monotonic()
                    try:
                        output(runtime.watchdog())
                        if args.command != "watchdog-worker":
                            run = runtime.prepare()
                            output(run)
                            if args.publish:
                                output(runtime.publish(run["generation"], args.boundary))
                        if args.command == "run":
                            return 0
                    except Exception as exc:
                        output({"status": "failed", "error_code": getattr(exc, "code", type(exc).__name__),
                                "detail": "Inspect the run journal; previous grants are never silently renewed."})
                        if args.command == "run":
                            return 1
                    interval = 30 if args.command == "watchdog-worker" else config.refresh_interval_seconds
                    while not stopping and time.monotonic() < started + interval:
                        time.sleep(min(1, max(0, started + interval - time.monotonic())))
        return 0
    except Exception as exc:
        output({"status": "failed", "error_code": getattr(exc, "code", type(exc).__name__),
                "detail": "No credential or source-value details are printed. See the local journal and runbook."})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
