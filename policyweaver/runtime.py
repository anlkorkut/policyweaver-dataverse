"""Prepare, validate, publish and withdraw bounded authorization generations."""
from __future__ import annotations

import hashlib
import json
import re
import time
from contextlib import ExitStack
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from azure.identity import AzureCliCredential, ManagedIdentityCredential

from .config import AdapterConfig, TableSelection, load_config, state_path
from .fabric_native import (BoundaryAttestation, DataReadyReceipt, FabricNativeClient,
                            TableSpec, plan_roles)
from .journal import Journal, retention_metadata
from .materialization import DeltaDestination, GenerationWriter, verify_generation
from .parallel_projection import CombinedSourceMetrics, ParallelSourceScans
from .source_projection import SourceAttribute, SourceProjectionClient, SourceReader, SourceTable


class RuntimeErrorSafe(RuntimeError):
    @property
    def code(self):
        return str(self).split(";", 1)[0]


def make_credential(config):
    from .auth import CachedCredential
    if config.authentication == "managed_identity":
        return CachedCredential(ManagedIdentityCredential(client_id=config.managed_identity_client_id))
    return CachedCredential(AzureCliCredential(tenant_id=config.tenant_id))


def _dt(value):
    return datetime.fromtimestamp(value, timezone.utc)


def restore_tables(manifest):
    return [SourceTable(**{**t, "attributes": tuple(SourceAttribute(**a) for a in t["attributes"])})
            for t in manifest["tables"]]


def role_plan(config, tables, readers, generation, table_access=None, reader_labels=None):
    allowed = None if table_access is None else {reader: [f"/Tables/dbo/{config.deployment_name}_{name}" for name in names]
                                                 for reader, names in table_access.items()}
    return plan_roles(config.tenant_id,
                      [TableSpec(f"/Tables/dbo/{config.deployment_name}_{t.name}", tuple(t.columns)) for t in tables],
                      readers, generation, role_limit=config.role_limit, reserve_roles=config.reserved_roles,
                      max_table_permissions=config.tables_per_shard, ownership_prefix=config.role_prefix,
                      reader_table_paths=allowed, reader_labels=reader_labels, role_naming=config.role_naming)


class AdapterRuntime:
    def __init__(self, config_path: Path, *, credential=None, source_factory=None, fabric_factory=None,
                 destination=None, progress=None):
        self._progress_callback = progress
        self._progress_started = time.monotonic()
        self.config_path = Path(config_path).resolve()
        self.config = load_config(self.config_path)
        self.directory = state_path(self.config, self.config_path)
        self.journal = Journal(self.directory)
        self._bind_deployment()
        self.credential = credential or make_credential(self.config)
        self._owns_credential = credential is None
        self.source_factory = source_factory or SourceProjectionClient
        self.fabric_factory = fabric_factory or FabricNativeClient
        self.destination = destination or DeltaDestination(self.config.workspace_id, self.credential)

    def _progress(self, event, *, source=None, **details):
        """Best-effort sanitized telemetry; never a security decision or journal.

        Only aggregate counters and a validated logical table name are emitted.
        A failed log sink must not interrupt expiry checks or rollback/withdrawal.
        """
        if self._progress_callback is None:
            return
        try:
            if event not in {
                "prepare_started", "source_verified", "readers_selected", "table_metadata_started",
                "table_metadata_completed", "operator_scope_verified", "projection_started",
                "projection_completed", "role_labels_started", "role_labels_completed",
                "prepare_completed", "prepare_failed", "dry_run_started",
                "dry_run_shard_completed", "dry_run_completed", "publish_started",
                "publication_boundary_verified", "upload_started", "upload_completed",
                "policy_publish_started", "policy_publish_completed", "publish_completed",
                "publication_quarantine_started", "publication_quarantine_completed",
            }:
                return
            entry = {"event": event, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                     "elapsed_seconds": round(time.monotonic() - self._progress_started, 3)}
            counters = {"reader_index", "reader_count", "table_index", "table_count", "completed",
                        "total", "rows", "total_rows", "shard_index", "shard_count", "role_count",
                        "failed_shard_count"}
            for key, value in details.items():
                if key in counters and type(value) is int and value >= 0:
                    entry[key] = value
                elif key == "table" and isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,99}", value):
                    entry[key] = value
            if source is not None:
                for name in ("requests", "retries"):
                    value = getattr(source, "metrics", {}).get(name)
                    if type(value) is int and value >= 0:
                        entry["source_" + name] = value
            self._progress_callback(entry)
        except Exception:
            # Logging is deliberately outside the authorization failure path.
            pass

    def close(self):
        if self._owns_credential:
            self.credential.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def source(self):
        c = self.config
        return self.source_factory(c.environment_url, c.tenant_id, c.organization_id,
                                   credential=self.credential, max_rows_per_scan=c.max_rows_per_reader_table,
                                   max_scan_seconds=c.generation_lifetime_seconds,
                                   identity_verification=c.identity_verification,
                                   identity_api_name=c.identity_api_name,
                                   identity_api_assembly_sha256=c.identity_api_assembly_sha256)

    def fabric(self, item):
        return self.fabric_factory(self.config.tenant_id, self.config.workspace_id, item, credential=self.credential)

    def discover(self):
        with self.source() as source:
            source.verify_environment()
            readers = source.discover_readers()
            return {"eligible_readers": readers, "count": len(readers), "max_supported": 1000}

    def select_readers(self, source):
        discovered = {r["entra_id"]: r for r in source.discover_readers()}
        c = self.config
        selected = set(discovered) if c.discover_readers else set(c.readers)
        selected -= set(c.excluded_readers)
        if c.discover_readers:
            caller_id = source.verify_environment().get("caller_user_id")
            selected -= {r["entra_id"] for r in discovered.values() if r["dataverse_id"] == caller_id}
        if not selected or len(selected) > c.max_readers:
            raise RuntimeErrorSafe("reader_selection_empty_or_over_budget")
        if not selected <= discovered.keys():
            raise RuntimeErrorSafe("configured_reader_missing_disabled_or_unhydrated")
        return [SourceReader(discovered[r]["dataverse_id"], r) for r in sorted(selected)]

    def _check_time(self, run, *, reserve=0):
        if time.time() + reserve >= run["expires"]:
            raise RuntimeErrorSafe("generation_freshness_budget_exhausted")

    def _check_config(self):
        if load_config(self.config_path).fingerprint != self.config.fingerprint:
            raise RuntimeErrorSafe("configuration_changed_restart_worker_and_prepare_new_generation")
        self._bind_deployment()

    def _deployment_scope(self):
        c = self.config
        return {"tenant_id": c.tenant_id, "workspace_id": c.workspace_id,
                "organization_id": c.organization_id, "deployment_name": c.deployment_name}

    def _bind_deployment(self):
        self.journal.bind_deployment(self._deployment_scope(), self.config.serving_items,
            [t.model_dump(mode="json") for t in self.config.tables], self.config.fingerprint)

    def _managed_item_mapping(self):
        result = dict(self.config.serving_items)
        for item in self.journal.managed_items():
            if item["item_id"] not in result.values():
                result["historical_" + item["item_id"].replace("-", "")] = item["item_id"]
        return result

    def prepare(self):
        c = self.config
        self._progress("prepare_started", table_count=len(c.tables))
        self._check_config()
        with self.journal.lock():
            generation = self.journal.create(c.fingerprint, c.generation_lifetime_seconds,
                retention_mode=c.retention_mode, publication_budget_seconds=c.publication_budget_seconds)
            run = self.journal.get(generation)
            try:
                with self.source() as source:
                    source.verify_environment()
                    self._progress("source_verified", source=source)
                    readers = self.select_readers(source)
                    self._progress("readers_selected", reader_count=len(readers), source=source)
                    tables = []
                    for table_index, selection in enumerate(c.tables, 1):
                        self._progress("table_metadata_started", table=selection.name,
                                       table_index=table_index, table_count=len(c.tables), source=source)
                        tables.append(source.table_metadata(selection.name, selection.columns))
                        self._progress("table_metadata_completed", table=selection.name,
                                       table_index=table_index, table_count=len(c.tables), source=source)
                    operator_scopes = {}
                    for table in tables:
                        evidence = source.verify_operator_read_scope(table)
                        if any(a.is_secured for a in table.attributes) and evidence.get("field_security_scope_verified") is not True:
                            raise RuntimeErrorSafe("operator_field_security_scope_unverified")
                        operator_scopes[table.name] = evidence
                        self._progress("operator_scope_verified", table=table.name, source=source)
                    writer = GenerationWriter(self.directory / "generations" / str(generation), generation,
                                              tables, c.batch_size)
                    table_access = {r.entra_id: [] for r in readers}
                    completed, total_rows = 0, 0
                    total = len(tables) * len(readers)
                    progress_source = source
                    with ExitStack() as scan_context:
                        scan_source = source
                        if c.source_workers > 1:
                            pairs = ((reader, table) for table in tables for reader in readers)
                            scan_source = scan_context.enter_context(ParallelSourceScans(
                                self.source, pairs, c.source_workers,
                                deadline_check=lambda: self._check_time(run, reserve=c.publication_budget_seconds),
                                forbidden_sources=(source,)))
                            progress_source = CombinedSourceMetrics(source, scan_source)
                        for table_index, table in enumerate(tables, 1):
                            for reader_index, reader in enumerate(readers, 1):
                                self._check_time(run, reserve=c.publication_budget_seconds)
                                self._progress("projection_started", table=table.name, table_index=table_index,
                                    table_count=len(tables), reader_index=reader_index, reader_count=len(readers),
                                    completed=completed, total=total, total_rows=total_rows, source=progress_source)
                                # Each worker uses the same fresh inclusive gate
                                # and verified source iterator as sequential mode.
                                # Only this thread writes Delta or the journal.
                                scan = scan_source.open_scan(reader, table)
                                count = writer.add_reader(table.name, reader.entra_id, scan.rows,
                                    max_rows=c.max_rows_per_reader_table,
                                    deadline_check=lambda: self._check_time(run, reserve=c.publication_budget_seconds))
                                if scan.has_read:
                                    table_access[reader.entra_id].append(table.name)
                                self.journal.event(generation, "projection_completed", {"table": table.name, "rows": count})
                                completed += 1
                                total_rows += count
                                self._progress("projection_completed", table=table.name, table_index=table_index,
                                    table_count=len(tables), reader_index=reader_index, reader_count=len(readers),
                                    completed=completed, total=total, rows=count, total_rows=total_rows, source=progress_source)
                    # All producers are closed and joined before labels or a
                    # successful manifest can be emitted.
                    reader_labels = None
                    if c.role_naming in {"readable", "user_business_role"}:
                        # Labels are collected after reader-context scans so JIT
                        # group membership observations are as recent as possible.
                        # Collection errors invalidate the whole generation;
                        # labels never supply a table permission or data row.
                        self._progress("role_labels_started", reader_count=len(readers), source=progress_source)
                        reader_labels = source.reader_role_labels(readers,
                            deadline_check=lambda: self._check_time(run, reserve=c.publication_budget_seconds))
                        self._progress("role_labels_completed", reader_count=len(readers), source=progress_source)
                    plan = role_plan(c, tables, [r.entra_id for r in readers], generation, table_access, reader_labels)
                    manifest = writer.finish({"config_hash": c.fingerprint, "source_mode": "dataverse_impersonated_reads",
                        **retention_metadata(c.retention_mode, run["expires"], c.publication_budget_seconds),
                        "source_observed_at": run["started"], "expires_at": run["expires"],
                        "completed_at": time.time(), "tables": [asdict(t) for t in tables],
                        "operator_scope": operator_scopes,
                        "readers": [asdict(r) for r in readers], "table_access": table_access, "source_metrics": progress_source.metrics,
                        **({"source_workers": c.source_workers} if c.source_workers > 1 else {}),
                        "shards": plan.as_dict(),
                        **({"role_naming": c.role_naming, "reader_labels": reader_labels} if reader_labels is not None else {})})
                    self._check_time(run, reserve=c.publication_budget_seconds)
                summary = {"reader_count": len(readers), "table_count": len(tables),
                           **retention_metadata(c.retention_mode, run["expires"], c.publication_budget_seconds),
                           "total_rows": manifest["total_rows"], "required_lakehouses": len(plan.shards),
                           "source_metrics": manifest["source_metrics"], "source_mode": manifest["source_mode"],
                           "manifest_sha256": hashlib.sha256((writer.directory / "manifest.json").read_bytes()).hexdigest(),
                           "deployment_scope": self._deployment_scope(), "managed_items": dict(c.serving_items),
                           "managed_tables": [t.model_dump(mode="json") for t in c.tables]}
                self.journal.transition(generation, "preparing", "prepared", summary=summary)
                self._progress("prepare_completed", reader_count=len(readers), table_count=len(tables),
                               total_rows=manifest["total_rows"], shard_count=len(plan.shards), source=progress_source)
                return self.journal.get(generation)
            except Exception as exc:
                self._progress("prepare_failed")
                self.journal.transition(generation, "preparing", "failed", error_code=getattr(exc, "code", type(exc).__name__))
                raise

    def prepared(self, generation):
        self._check_config()
        run = self.journal.get(generation)
        if run["status"] != "prepared" or run["config_hash"] != self.config.fingerprint:
            raise RuntimeErrorSafe("generation_not_prepared_or_configuration_changed")
        self.journal.assert_publishable_generation(generation)
        self._check_time(run, reserve=self.config.publication_budget_seconds)
        directory = self.directory / "generations" / str(generation)
        if hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest() != run["summary"].get("manifest_sha256"):
            raise RuntimeErrorSafe("generation_manifest_hash_mismatch")
        manifest = verify_generation(directory)
        if manifest["config_hash"] != self.config.fingerprint or manifest["generation"] != generation:
            raise RuntimeErrorSafe("manifest_scope_mismatch")
        expected_retention = retention_metadata(self.config.retention_mode, run["expires"],
                                               self.config.publication_budget_seconds)
        # Timed generations created before the additive retention option remain
        # valid. Partial metadata or any manual generation must match exactly.
        if (self.config.retention_mode == "manual" or any(k in manifest or k in run["summary"]
                                                        for k in expected_retention)):
            if any(manifest.get(k, object()) != v or run["summary"].get(k, object()) != v
                   for k, v in expected_retention.items()):
                raise RuntimeErrorSafe("generation_retention_metadata_mismatch")
        if self.config.role_naming in {"readable", "user_business_role"}:
            if manifest.get("role_naming") != self.config.role_naming:
                raise RuntimeErrorSafe("generation_role_naming_mismatch")
            if not isinstance(manifest.get("reader_labels"), dict):
                raise RuntimeErrorSafe("generation_role_labels_missing")
        elif "reader_labels" in manifest or manifest.get("role_naming", "legacy") != "legacy":
            raise RuntimeErrorSafe("generation_role_naming_mismatch")
        plan = role_plan(self.config, restore_tables(manifest), [r["entra_id"] for r in manifest["readers"]], generation,
                         manifest["table_access"], manifest.get("reader_labels"))
        if any(s.key not in self.config.serving_items for s in plan.shards):
            raise RuntimeErrorSafe("serving_items_missing; provision items and prepare a new generation")
        return run, directory, manifest, plan

    def dry_run(self, generation):
        self._progress("dry_run_started")
        _, _, _, plan = self.prepared(generation)
        results = {}
        for shard_index, shard in enumerate(plan.shards, 1):
            with self.fabric(self.config.serving_items[shard.key]) as fabric:
                results[shard.key] = asdict(fabric.dry_run(shard))
            self._progress("dry_run_shard_completed", shard_index=shard_index,
                           shard_count=len(plan.shards), role_count=len(shard.roles))
        self.journal.event(generation, "role_dry_run_validated", {"shards": len(results)})
        self._progress("dry_run_completed", shard_count=len(results))
        return results

    def publish(self, generation, boundary_path):
        self._progress("publish_started")
        c = self.config
        boundaries = json.loads(Path(boundary_path).read_text(encoding="utf-8"))
        with self.journal.lock():
            run, directory, manifest, plan = self.prepared(generation)
            # Validate every external boundary before uploading any business data.
            attested = {}
            for shard_index, shard in enumerate(plan.shards, 1):
                raw = boundaries[shard.key]
                boundary = BoundaryAttestation(**{**raw, "reader_ids": tuple(raw["reader_ids"]),
                    "inspected_at": datetime.fromisoformat(raw["inspected_at"])})
                boundary.validate(shard, datetime.now(timezone.utc))
                if boundary.workspace_id != c.workspace_id or boundary.item_id != c.serving_items[shard.key]:
                    raise RuntimeErrorSafe("boundary_scope_mismatch")
                attested[shard.key] = boundary
                with self.fabric(c.serving_items[shard.key]) as fabric:
                    fabric.dry_run(shard)
                self._progress("publication_boundary_verified", shard_index=shard_index,
                               shard_count=len(plan.shards))
            self.journal.begin_activation(generation, c.serving_items.values())
            try:
                receipts, outputs = {}, {}
                source_by_path = {f"/Tables/dbo/{c.deployment_name}_{t['name']}": t["name"] for t in manifest["tables"]}
                for shard_index, shard in enumerate(plan.shards, 1):
                    commits = []
                    for table in shard.tables:
                        self._check_time(run, reserve=c.publication_budget_seconds)
                        source_table = source_by_path[table.path]
                        self._progress("upload_started", table=source_table, shard_index=shard_index,
                                       shard_count=len(plan.shards))
                        commit = self.destination.append(directory, source_table, c.serving_items[shard.key],
                                                         table.path, shard.reader_ids, generation)
                        expected = sum(manifest["reader_table_counts"][source_table + ":" + r] for r in shard.reader_ids)
                        if commit["rows"] != expected:
                            raise RuntimeErrorSafe("destination_row_count_mismatch")
                        commits.append(commit)
                        self._progress("upload_completed", table=source_table, rows=expected,
                                       shard_index=shard_index, shard_count=len(plan.shards))
                    receipts[shard.key] = DataReadyReceipt(c.workspace_id, c.serving_items[shard.key], shard.key,
                        generation, shard.plan_digest, hashlib.sha256(json.dumps(commits, sort_keys=True).encode()).hexdigest(),
                        _dt(run["started"]), datetime.now(timezone.utc), _dt(run["expires"]))
                # Data for every shard exists before changing any consumer policy.
                for shard_index, shard in enumerate(plan.shards, 1):
                    self._check_time(run, reserve=c.publication_budget_seconds)
                    self._check_config()
                    self._progress("policy_publish_started", shard_index=shard_index,
                                   shard_count=len(plan.shards), role_count=len(shard.roles))
                    with self.fabric(c.serving_items[shard.key]) as fabric:
                        outputs[shard.key] = asdict(fabric.publish(shard, receipts[shard.key], attested[shard.key]))
                        self.journal.mark_item(c.serving_items[shard.key], "active")
                    self._progress("policy_publish_completed", shard_index=shard_index,
                                   shard_count=len(plan.shards), role_count=len(shard.roles))
                # Removed readers/tables must not survive in retired shards.
                for key, item in c.serving_items.items():
                    if key not in outputs:
                        with self.fabric(item) as fabric:
                            result = fabric.withdraw(c.role_prefix)
                            if result.control_plane_verified is not True:
                                raise RuntimeErrorSafe("item_withdrawal_not_verified")
                            self.journal.mark_item(item, "withdrawn")
                self.journal.transition(generation, "publishing", "published", summary={**run["summary"], "publication": outputs})
                for old in self.journal.recent(1000):
                    if old["generation"] < generation and old["status"] in {"published", "quarantined", "withdrawal_failed"}:
                        self.journal.transition(old["generation"], old["status"], "superseded")
                self._progress("publish_completed", shard_count=len(plan.shards))
                return self.journal.get(generation)
            except Exception as exc:
                # Withdrawal is attempted on ALL managed items, including ones
                # whose mutation outcome is uncertain. Never roll back to old grants.
                self._progress("publication_quarantine_started")
                failed = self._withdraw_items()
                self.journal.transition(generation, "publishing", "quarantined", error_code=getattr(exc, "code", type(exc).__name__),
                                        summary={**run["summary"], "withdrawal_failed_items": failed})
                self._progress("publication_quarantine_completed", failed_shard_count=len(failed))
                raise

    def _withdraw_items(self):
        failed = []
        for key, item in self._managed_item_mapping().items():
            try:
                with self.fabric(item) as fabric:
                    result = fabric.withdraw(self.config.role_prefix)
                    if result.control_plane_verified is not True:
                        raise RuntimeErrorSafe("item_withdrawal_not_verified")
                    self.journal.mark_item(item, "withdrawn")
            except Exception:
                failed.append(key)
        return failed

    def withdraw(self):
        with self.journal.lock():
            self.journal.withdrawal_barrier()
            failed = self._withdraw_items()
            for run in self.journal.recent(1000):
                if run["status"] in {"published", "publishing"}:
                    self.journal.transition(run["generation"], run["status"], "withdrawal_failed" if failed else "withdrawn")
            if failed:
                raise RuntimeErrorSafe("withdrawal_failed:" + ",".join(failed))
            return {"status": "withdrawn_control_plane", "engine_propagation_verified": False}

    def watchdog(self):
        # Inspect and withdraw the exact same remote role snapshot under its
        # ETag. A journal read followed by generic withdraw() could erase a newer
        # generation activated concurrently by the publisher.
        from .native_watchdog import run_watchdog
        item_mapping = self._managed_item_mapping()
        if not item_mapping:
            return {"status": "no_managed_items", "critical": False, "items": {},
                    "engine_revocation_verified": False}
        watch_config = self.config.model_copy(update={
            "serving_items": item_mapping,
            "tables": tuple(TableSelection(**t) for t in self.journal.managed_tables()),
        })
        result = run_watchdog(watch_config, credential=self.credential,
                              client_factory=self.fabric_factory, now=time.time)
        # Do not mark item state withdrawn from an asynchronous watchdog result:
        # a fresh publish can follow the assessed withdrawal before this local
        # write. Explicit withdraw() holds the writer lock and verifies that gate.
        self.journal.event(None, "native_watchdog", {"critical": result["critical"],
            "items": {key: entry["status"] for key, entry in result["items"].items()}})
        if result["critical"]:
            raise RuntimeErrorSafe("critical_stale_access_watchdog; inspect native watchdog events and remote roles")
        return result
