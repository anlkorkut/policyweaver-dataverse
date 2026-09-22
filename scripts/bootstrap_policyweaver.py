"""Install Policy Weaver in a repository-local virtual environment.

Uses the Python interpreter running this script. No Azure command, login, resource
creation, global skill installation, or live Policy Weaver operation is performed.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def bootstrap_plan(root, environment=".venv", *, with_tests=False, with_qualification=False):
    if sys.version_info < (3, 11) or struct.calcsize("P") != 8:
        raise ValueError("Use 64-bit Python 3.11 or newer; Python 3.11 is the dependency baseline")
    root = Path(root).resolve()
    for name in ("pyproject.toml", "requirements.lock", "policyweaver/adapter_cli.py"):
        if not (root / name).is_file():
            raise ValueError(f"Required repository file is missing: {name}")
    target = root / environment
    if target.is_symlink() or not target.resolve().is_relative_to(root) or target.resolve() == root:
        raise ValueError("Virtual environment must be a non-symlink subdirectory of this repository")
    for parent in (target, *target.parents):
        if parent == root:
            break
        if parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction()):
            raise ValueError("Virtual environment cannot traverse symbolic links or junctions")
    target = target.resolve()
    executable = target / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    if target.exists() and not ((target / "pyvenv.cfg").is_file() and executable.is_file()):
        raise ValueError("Existing directory is not a complete Python virtual environment; nothing was changed")
    extras = ["adapter"]
    if with_tests:
        extras.append("test")
    if with_qualification:
        extras.append("qualification")
    commands = [] if target.exists() else [[sys.executable, "-m", "venv", str(target)]]
    commands.extend([
        [str(executable), "-m", "pip", "install", "--constraint", str(root / "requirements.lock"),
         "--editable", ".[" + ",".join(extras) + "]"],
        [str(executable), "-m", "pip", "check"],
    ])
    return {"repository": str(root), "venv": str(target), "python": str(executable), "commands": commands,
            "creates_environment": not target.exists(), "azure_operations": False, "global_skill_installation": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--venv", default=".venv", help="Repository-local environment directory (default: .venv)")
    parser.add_argument("--with-tests", action="store_true")
    parser.add_argument("--with-qualification", action="store_true", help="Install pyodbc; OS ODBC Driver 18 remains separate")
    parser.add_argument("--plan", action="store_true", help="Display exact local commands without executing them")
    args = parser.parse_args(argv)
    try:
        plan = bootstrap_plan(ROOT, args.venv, with_tests=args.with_tests, with_qualification=args.with_qualification)
        if args.plan:
            print(json.dumps(plan, indent=2))
            return 0
        for command in plan["commands"]:
            print(json.dumps({"event": "bootstrap_command", "argv": command}), flush=True)
            completed = subprocess.run(command, cwd=ROOT, check=False)
            if completed.returncode:
                print(json.dumps({"event": "bootstrap_failed", "exit_code": completed.returncode}), flush=True)
                return completed.returncode
        print(json.dumps({"event": "bootstrap_complete", "python": plan["python"],
                          "next": "Use $policyweaver-dataverse or run python -m policyweaver.onboarding --help",
                          "live_environment_changed": False}), flush=True)
        return 0
    except (OSError, ValueError) as error:
        parser.exit(2, f"Bootstrap failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
