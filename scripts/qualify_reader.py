"""Run explicit actual-user Dataverse/Fabric SQL checks; never sign users in."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policyweaver.qualification import (
    BoundUserCredential, DirectReaderSource, QualificationError, ReaderSqlTarget,
    load_scenario, qualify, scenario_template,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", type=Path)
    parser.add_argument("--reader", help="Fixture reader label; never a password or token")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--write-template", type=Path)
    parser.add_argument("--prepared-manifest", type=Path,
                        help="Prepared column metadata; fill reader Entra/Dataverse ID pairs from controlled inventory")
    args = parser.parse_args(argv)
    source = target = credential = None
    try:
        if args.write_template:
            manifest = json.loads(args.prepared_manifest.read_text(encoding="utf-8-sig")) if args.prepared_manifest else None
            args.write_template.write_text(json.dumps(scenario_template(manifest), indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"status": "unpopulated_fixture_template_created", "reader_scenarios": 4}))
            return 0
        if not args.scenario or not args.reader:
            parser.error("Provide --scenario and --reader, or --write-template")
        scenario = load_scenario(args.scenario, args.reader)
        from azure.identity import AzureCliCredential
        credential = AzureCliCredential(tenant_id=scenario.tenant_id)
        bound = BoundUserCredential(credential, scenario.tenant_id, scenario.reader_entra_id, scenario.environment_url)
        source = DirectReaderSource(scenario, bound)
        # Verify source identity before attempting an SQL session under that user.
        source.verify_identity()
        target = ReaderSqlTarget(scenario, bound)
        report = qualify(scenario, source, target)
        if args.output:
            args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 0 if report["status"] == "passed_selected_sql_checks" else 1
    except Exception as exc:
        report = {"status": "incomplete", "error_code": getattr(exc, "code", type(exc).__name__),
                  "production_certified": False,
                  "detail": "No rows, tokens, connection strings, or server error bodies are printed."}
        if args.output:
            args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 2
    finally:
        for resource in (target, source, credential):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass


if __name__ == "__main__":
    raise SystemExit(main())
