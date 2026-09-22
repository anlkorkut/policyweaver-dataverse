"""No command publishes permissions or modifies Dataverse."""
import argparse
import json
import sys
from pathlib import Path

from .demo import demo_snapshot, example_queries
from .engine import AccessEngine
from .models import Snapshot
from .planner import plan
from .storage import load_inventory, save_inventory


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="policyweaver", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Launch local loopback analyst console")
    serve.add_argument("--port", type=int, default=8000)
    collect = commands.add_parser("collect", help="GET security metadata from Dataverse; no writes")
    collect.add_argument("--environment", required=True, help="Explicit Dataverse HTTPS origin")
    collect.add_argument("--tenant", required=True, help="Expected Entra tenant GUID")
    collect.add_argument("--expected-org", required=True, help="Expected Dataverse organization GUID")
    collect.add_argument("--managed-identity", action="store_true")
    collect.add_argument("--skip-attributes", action="store_true", help="Partial inventory; explicitly blocks completeness")
    commands.add_parser("inspect", help="Summarize most recent local inventory")
    commands.add_parser("demo", help="Run synthetic read-access scenarios")
    planning = commands.add_parser("plan", help="Review compact scope facts and quota estimate; cannot publish")
    planning.add_argument("--snapshot", type=Path, help="Normalized snapshot JSON; default is synthetic")
    planning.add_argument("--role-limit", type=int, default=1000)
    arguments = parser.parse_args(argv)
    if arguments.command == "serve":
        import uvicorn
        uvicorn.run("policyweaver.app:app", host="127.0.0.1", port=arguments.port, proxy_headers=False)
        return 0
    if arguments.command == "collect":
        from .dataverse import DataverseClient
        from azure.identity import ManagedIdentityCredential
        credential = ManagedIdentityCredential() if arguments.managed_identity else None
        print("Collecting read-only metadata; all pages will be retrieved. Credentials stay in memory.", flush=True)
        try:
            with DataverseClient(environment_url=arguments.environment, tenant_id=arguments.tenant,
                                 expected_organization_id=arguments.expected_org, credential=credential) as client:
                snapshot = client.collect(include_attributes=not arguments.skip_attributes)
            path = save_inventory(snapshot)
            print(json.dumps({"saved": str(path), "organization_id": snapshot.get("organization_id"),
                              "complete": snapshot.get("complete"), "counts": snapshot.get("counts"),
                              "diagnostics": snapshot.get("diagnostics"), "publication_ready": False}, indent=2))
            return 0 if snapshot.get("complete") else 2
        except Exception as exc:
            # Azure and HTTP exception strings can contain URLs or credential-provider details.
            print(f"Collection failed ({type(exc).__name__}); no inventory was activated. Check Azure login and collector prerequisites.", file=sys.stderr)
            return 1
        finally:
            if credential:
                credential.close()
    if arguments.command == "inspect":
        from .app import inventory_summary
        print(json.dumps(inventory_summary(load_inventory()), indent=2))
        return 0
    if arguments.command == "demo":
        engine = AccessEngine(demo_snapshot())
        decisions = []
        for query in example_queries():
            result = engine.evaluate(**{k: query[k] for k in ("user_id", "table", "record_id", "column")})
            decisions.append({"scenario": query["label"], "expected": query["expected_allowed"], **result})
        print(json.dumps({"source": "synthetic", "decisions": decisions}, indent=2))
        return 0 if all(d["allowed"] == d["expected"] for d in decisions) else 1
    if arguments.command == "plan":
        snapshot = Snapshot.model_validate_json(arguments.snapshot.read_text(encoding="utf-8")) if arguments.snapshot else demo_snapshot()
        print(json.dumps(plan(AccessEngine(snapshot), arguments.role_limit), indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
