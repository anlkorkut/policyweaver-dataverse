"""Review and install the pinned, read-only Dataverse identity-proof function.

No install occurs without the explicit install subcommand and reviewed plan hash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policyweaver.config import load_config
from policyweaver.read_context_deployment import (
    API_NAME, ASSEMBLY_NAME, TYPE_NAME, ReadContextDeploymentError,
    install_plan, plan_install, repair_plan, verify_read_context_registration,
)
from policyweaver.runtime import make_credential
from policyweaver.source_projection import SourceProjectionClient


def artifact(manifest_path):
    path = Path(manifest_path).resolve()
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    expected = {"schema_version": 1, "assembly_name": ASSEMBLY_NAME, "assembly_culture": "neutral",
                "type_name": TYPE_NAME, "custom_api_name": API_NAME, "protocol_version": "1", "target_framework": "net462"}
    if any(value.get(k) != v or type(value.get(k)) is not type(v) for k, v in expected.items()):
        raise ReadContextDeploymentError("read_context_artifact_manifest_mismatch")
    name = value.get("file")
    if not isinstance(name, str):
        raise ReadContextDeploymentError("read_context_artifact_path_invalid")
    dll = (path.parent / name).resolve()
    if dll.parent != path.parent or dll.name != "PolicyWeaver.ReadContext.dll":
        raise ReadContextDeploymentError("read_context_artifact_path_invalid")
    if hashlib.sha256(dll.read_bytes()).hexdigest() != value.get("sha256"):
        raise ReadContextDeploymentError("read_context_artifact_changed")
    identity = {"name": value["assembly_name"], "version": value.get("assembly_version"),
                "culture": value["assembly_culture"], "publickeytoken": value.get("public_key_token")}
    return dll, identity


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    sub = parser.add_subparsers(dest="operation", required=True)
    for name in ("plan", "install"):
        command = sub.add_parser(name)
        command.add_argument("--artifact-manifest", required=True)
        command.add_argument("--receipt")
        if name == "plan":
            command.add_argument("--output", required=True)
        else:
            command.add_argument("--plan", required=True)
            command.add_argument("--approved-plan-sha256", required=True)
            command.add_argument("--previous-plan", help="Original reviewed plan for the known response-description repair only")
    repair = sub.add_parser("repair-plan", help="Read-only plan for absent v1 responses with overlong descriptions")
    repair.add_argument("--plan", required=True)
    repair.add_argument("--receipt")
    repair.add_argument("--output", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--assembly-sha256", required=True)
    args = parser.parse_args(argv)
    credential = None
    try:
        config_path = Path(args.config).resolve()
        config = load_config(config_path)
        credential = make_credential(config)
        with SourceProjectionClient(config.environment_url, config.tenant_id, config.organization_id,
                                    credential=credential) as source:
            if args.operation == "verify":
                result = verify_read_context_registration(source, api_name=API_NAME,
                                                         assembly_sha256=args.assembly_sha256)
            elif args.operation == "repair-plan":
                receipt = Path(args.receipt) if args.receipt else config_path.parent / config.state_directory / "read-context-install.json"
                original = json.loads(Path(args.plan).read_text(encoding="utf-8"))
                output = Path(args.output)
                if output.exists():
                    raise ReadContextDeploymentError("read_context_plan_output_exists")
                revised = repair_plan(source, config, plan=original, receipt_path=receipt)
                output.parent.mkdir(parents=True, exist_ok=True)
                with output.open("x", encoding="utf-8") as stream:
                    json.dump(revised, stream, indent=2)
                result = {"status": "repair_planned_read_only", "plan_sha256": revised["plan_sha256"],
                          "previous_plan_sha256": revised["previous_plan_sha256"], "plan_path": str(output.resolve())}
            else:
                dll, identity = artifact(args.artifact_manifest)
                receipt = Path(args.receipt) if args.receipt else config_path.parent / config.state_directory / "read-context-install.json"
                if args.operation == "plan":
                    output = Path(args.output)
                    if output.exists():
                        raise ReadContextDeploymentError("read_context_plan_output_exists")
                    result = plan_install(source, config, assembly_path=dll, assembly_identity=identity, receipt_path=receipt)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with output.open("x", encoding="utf-8") as stream:
                        json.dump(result, stream, indent=2)
                    result = {"status": "planned_read_only", "plan_sha256": result["plan_sha256"],
                              "assembly_sha256": result["assembly_sha256"], "metadata_creates": len(result["mutations"]),
                              "plan_path": str(output.resolve())}
                else:
                    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
                    if identity != plan.get("assembly_identity"):
                        raise ReadContextDeploymentError("read_context_artifact_manifest_mismatch")
                    result = install_plan(source, config, plan=plan, assembly_path=dll,
                                          receipt_path=receipt, approved_plan_sha256=args.approved_plan_sha256,
                                          previous_plan=json.loads(Path(args.previous_plan).read_text(encoding="utf-8")) if args.previous_plan else None)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_code": getattr(exc, "code", type(exc).__name__)}))
        return 2
    finally:
        if credential is not None:
            credential.close()


if __name__ == "__main__":
    raise SystemExit(main())
