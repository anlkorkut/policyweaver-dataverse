"""Stream an explicit adapter operation to the terminal and private local logs.

Default: prepare only. Withdrawal requires an explicit withdraw operation. This
launcher never invokes the mutating watchdog, provisions items, changes
configuration, or fabricates a boundary.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def command_for(python, config, operation, generation=None, boundary=None):
    if operation in {"dry-run", "publish", "boundary-template"} and not generation:
        raise ValueError("This operation requires --generation from a successful preparation.")
    if operation == "publish" and not boundary:
        raise ValueError("Publication requires --boundary from a fresh, real access inspection.")
    command = [str(python), "-u", "-m", "policyweaver.adapter_cli", "--progress",
               "--config", str(config), operation]
    if operation in {"dry-run", "publish", "boundary-template"}:
        command.extend(["--generation", str(generation)])
    if operation == "publish":
        command.extend(["--boundary", str(boundary)])
    return command


def _powershell_literal(value):
    """Quote a single literal argument, including apostrophes and dollar signs."""
    return "'" + str(value).replace("'", "''") + "'"


def preparation_guidance(result_path, config_path, publication_budget_seconds, *, now=None):
    """Describe a structured prepare result without changing it or calling the adapter.

    Invalid/missing output deliberately produces no success claim. The caller treats
    this optional display as best effort and always preserves the child's exit code.
    """
    try:
        result = json.loads(Path(result_path).read_text(encoding="utf-8"))
        if not isinstance(result, dict) or result.get("status") != "prepared":
            return None
        generation, expires = result.get("generation"), result.get("expires")
        if type(generation) is not int or generation <= 0:
            return None
        if type(expires) not in (int, float) or not math.isfinite(expires):
            return None
        summary = result.get("summary", {})
        if not isinstance(summary, dict):
            return None
        retention_mode = summary.get("retention_mode", "timed")
        if retention_mode not in {"timed", "manual"}:
            return None
        if retention_mode == "manual" and (
                summary.get("automatic_withdrawal_at", "missing") is not None or
                summary.get("publication_deadline_at") != expires - publication_budget_seconds):
            return None
        expiry = datetime.fromtimestamp(expires, timezone.utc)
        cutoff = datetime.fromtimestamp(expires - publication_budget_seconds, timezone.utc)
        current = datetime.now(timezone.utc) if now is None else now
        if current.tzinfo is None:
            return None
        def timestamp(value):
            return (value.isoformat(timespec="microseconds") + " UTC; local "
                    + value.astimezone().isoformat(timespec="microseconds"))
        launcher = "& " + _powershell_literal(ROOT / "scripts" / "Run-PolicyWeaver.ps1")
        common = (" -Config " + _powershell_literal(config_path)
                  + " -PythonPath " + _powershell_literal(sys.executable))
        scoped = common + " -Generation " + str(generation)
        lines = [
            "Prepared locally - no OneLake roles published by this operation.",
            f"Generation: {generation}",
            "Source freshness deadline: " + timestamp(expiry),
            ("Role retention: manual; no age-based automatic withdrawal after publication. "
             "Source changes will not reach these roles until a fresh generation is published."
             if retention_mode == "manual" else
             "Role retention: timed; watchdog withdrawal is due at the source freshness deadline."),
            "Publication cutoff: " + timestamp(cutoff),
            f"The {publication_budget_seconds}s reserve is checked before each upload and policy update; "
            "these checks must remain strictly before the cutoff, not just publication start.",
        ]
        if retention_mode == "manual":
            lines.extend([
                "The independently hosted watchdog must use the same manual retention setting for these serving items.",
                "Integrity failures and failed publication can still trigger protective withdrawal.",
                "Explicit withdrawal remains available after publication:",
                launcher + " -Operation Withdraw" + common,
            ])
        if current >= cutoff:
            lines.extend([
                "Publication reserve is already exhausted. Prepare a new generation; do not publish this one.",
                launcher + " -Operation Prepare" + common,
            ])
        else:
            lines.extend([
                "Next: complete a fresh inspection of real workspace/item access and SQL identity mode, "
                "and ensure the destination tables are ready. Publication requires a verified boundary JSON file.",
                "PowerShell follow-ups (each remains subject to the cutoff and publication checks):",
                launcher + " -Operation DryRun" + scoped,
                "BoundaryTemplate creates an UNVERIFIED template only; do not publish it unchanged:",
                launcher + " -Operation BoundaryTemplate" + scoped,
                "Replace the boundary placeholder below with the actual fresh, verified boundary file:",
                launcher + " -Operation Publish" + scoped
                + " -Boundary '<PATH_TO_FRESH_VERIFIED_BOUNDARY_JSON>'",
                "If the cutoff passes, prepare again. No publication or boundary inspection was performed by this launcher.",
            ])
        return "\n".join(lines)
    except (OSError, ValueError, TypeError, OverflowError):
        return None


def stream_process(command, directory, *, cwd=ROOT, heartbeat_seconds=15):
    """Drain stdout and stderr concurrently; retain the child's exact exit code."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    messages = queue.Queue()
    environment = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
    def drain(stream, label):
        try:
            for line in stream:
                messages.put((label, line))
        finally:
            stream.close()
            messages.put((label, None))

    interrupted = False
    # Establish every log sink before starting an adapter that could publish.
    with (directory / "result.json").open("w", encoding="utf-8") as result, \
         (directory / "progress.jsonl").open("w", encoding="utf-8") as progress, \
         (directory / "terminal.log").open("w", encoding="utf-8") as transcript:
        child = None
        threads = []
        code = 130
        try:
            child = subprocess.Popen(command, cwd=cwd, env=environment, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
            for stream, label in ((child.stdout, "stdout"), (child.stderr, "stderr")):
                thread = threading.Thread(target=drain, args=(stream, label), daemon=True)
                thread.start()
                threads.append(thread)
            streams = {"stdout": result, "stderr": progress}
            finished = set()
            while len(finished) < 2 or child.poll() is None:
                try:
                    timeout = min(heartbeat_seconds, 0.1) if len(finished) == 2 else heartbeat_seconds
                    label, line = messages.get(timeout=timeout)
                except queue.Empty:
                    if len(finished) == 2 and child.poll() is not None:
                        break
                    state = "Process alive" if child.poll() is None else "Process exited; draining output"
                    heartbeat = f"[{utc()}] {state}; elapsed {time.monotonic() - started:.1f}s; waiting for next progress event."
                    print(heartbeat, flush=True)
                    transcript.write(heartbeat + "\n")
                    transcript.flush()
                    continue
                if line is None:
                    finished.add(label)
                    continue
                streams[label].write(line)
                streams[label].flush()
                transcript.write(f"[{utc()}] {label}: {line}")
                transcript.flush()
                print(line, end="", flush=True)
            code = child.wait()
        except KeyboardInterrupt:
            interrupted = True
            print("Interrupted. Publication may be incomplete or quarantined. Inspect status and remote roles "
                  "before retrying; the launcher performs no automatic remote rollback.", flush=True)
        finally:
            # Cover log/terminal failures and interrupts anywhere in the loop,
            # not just queue waits. Never leave an unseen publishing child alive.
            if child is not None and child.poll() is None:
                try:
                    child.terminate()
                    child.wait(timeout=5)
                except (subprocess.TimeoutExpired, KeyboardInterrupt):
                    child.kill()
                    child.wait(timeout=5)
            if child is not None:
                code = child.returncode
            for thread in threads:
                thread.join(timeout=1)
    summary = {"finished_utc": utc(), "elapsed_seconds": round(time.monotonic() - started, 3),
               "exit_code": code, "interrupted": interrupted}
    (directory / "execution.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"[{utc()}] Finished: exit={code}; elapsed={summary['elapsed_seconds']}s; logs={directory}", flush=True)
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "policyweaver.config.json")
    parser.add_argument("--operation", choices=("prepare", "doctor", "status", "dry-run", "publish", "boundary-template", "withdraw"), default="prepare")
    parser.add_argument("--generation", type=int)
    parser.add_argument("--boundary", type=Path)
    parser.add_argument("--log-directory", type=Path)
    parser.add_argument("--preview", action="store_true", help="Show local configuration and command without running the adapter.")
    args = parser.parse_args(argv)
    sys.path.insert(0, str(ROOT))
    from policyweaver.config import load_config, state_path
    try:
        config_path = args.config.resolve(strict=True)
        config = load_config(config_path)
        boundary = args.boundary.resolve(strict=True) if args.boundary else None
        command = command_for(sys.executable, config_path, args.operation, args.generation, boundary)
    except Exception as exc:
        print(f"Launcher configuration rejected ({type(exc).__name__}). Check paths and required arguments.", file=sys.stderr)
        return 2
    print(f"[{utc()}] Policy Weaver authoritative Dataverse adapter", flush=True)
    print(f"Operation: {args.operation}; configured tables: {', '.join(t.name for t in config.tables)}", flush=True)
    print(f"Column counts: {', '.join(t.name + '=' + str(len(t.columns)) for t in config.tables)}", flush=True)
    print("Audience: discovered eligible readers excluding the operator" if config.discover_readers
          else f"Audience: {len(config.readers)} explicitly configured reader IDs", flush=True)
    print(f"Config: {config_path}; destination items: {len(config.serving_items)}", flush=True)
    print(f"Role retention: {getattr(config, 'retention_mode', 'timed')}; "
          "preparation and publication freshness checks remain finite.", flush=True)
    if getattr(config, "retention_mode", "timed") == "manual":
        print("Manual retention requires matching publisher and independently hosted watchdog configuration. "
              "Age-based withdrawal is disabled; explicit withdrawal, replacement, and protective containment remain available.", flush=True)
    print("Prepare stages fresh Dataverse results locally. Publish is a separate, explicit operation.", flush=True)
    if args.preview:
        print(json.dumps({"preview": True, "command": command}, indent=2), flush=True)
        return 0
    log_root = args.log_directory.resolve() if args.log_directory else state_path(config, config_path) / "terminal-logs"
    directory = log_root / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + args.operation + "-" + uuid4().hex[:8])
    print(f"Logs: {directory}", flush=True)
    try:
        code = stream_process(command, directory)
    except Exception as exc:
        print(f"Launcher failed ({type(exc).__name__}). Publication may be incomplete or quarantined; "
              "inspect local logs, adapter status and remote roles before retrying. "
              "The launcher performs no automatic remote rollback.", file=sys.stderr)
        return 1
    if code == 0 and args.operation == "prepare":
        # Presentation must never turn a completed child into a failed operation,
        # including when its output is malformed or the terminal/log is unavailable.
        try:
            guidance = preparation_guidance(directory / "result.json", config_path,
                                            config.publication_budget_seconds)
            if guidance:
                print(guidance, flush=True)
                with (directory / "terminal.log").open("a", encoding="utf-8") as transcript:
                    transcript.write(guidance + "\n")
        except Exception:
            pass
    return code


if __name__ == "__main__":
    raise SystemExit(main())
