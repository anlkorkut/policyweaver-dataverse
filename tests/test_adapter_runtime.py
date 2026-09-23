"""End-to-end local Delta runtime tests with fake source and Fabric boundaries.

These exercise orchestration and real on-disk Delta commits.  They do not claim
Dataverse user-session parity, OneLake enforcement or a revocation SLA.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import time
from uuid import UUID

from deltalake import DeltaTable
import pyarrow as pa
import pyarrow.dataset as ds
import pytest

from policyweaver.config import AdapterConfig, TableSelection, save_config
from policyweaver.fabric_native import FabricNativeClient, PublicationResult, RoleSnapshot
from policyweaver.journal import Journal, JournalError
from policyweaver.materialization import DeltaDestination, GenerationWriter, MaterializationError, verify_generation
from policyweaver.runtime import AdapterRuntime, RuntimeErrorSafe
from policyweaver.source_projection import SourceAttribute, SourceProjectionError, SourceReader, SourceScan, SourceTable


def uid(number):
    return str(UUID(int=number))


class FakeSource:
    """Implements the source adapter interface, including empty privilege denial."""

    def __init__(self, reader_count=2):
        self.readers = tuple(SourceReader(uid(10000 + i), uid(20000 + i)) for i in range(reader_count))
        self.metrics = {"requests": 0, "completed_scans": 0, "completed_rows": 0}
        self.calls = []
        self.fail_pair = None
        self.fail_after_yield = False
        self.operator_field_scope_verified = True
        self.denied = set()
        self.rows = {}
        self.tables = {}
        for table_index, name in enumerate(("account", "contact")):
            columns = (name + "id", "name", "amount", "createdon", "secret")
            types = ("Uniqueidentifier", "String", "Money", "DateTime", "String")
            attrs = tuple(SourceAttribute(c, c, typ, c == "secret", False) for c, typ in zip(columns, types))
            self.tables[name] = SourceTable(name, name + "s", name + "id", columns, attrs, uid(30000 + table_index))
            for i, reader in enumerate(self.readers):
                self.rows[(reader.entra_id, name)] = [{
                    name + "id": uid(40000 + table_index * 10000 + i),
                    "name": "SOURCE_PII_SENTINEL_" + str(i),
                    "amount": Decimal("12345678901234567890.1234567890") if i % 2 == 0 else None,
                    "createdon": "2026-09-18T14:00:00+02:00",
                    "secret": "FIELD_PII_SENTINEL" if i % 2 == 0 else None,
                }]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def verify_environment(self):
        self.calls.append(("verify_environment",))
        return {"organization_id": uid(2), "caller_user_id": uid(3)}

    def discover_readers(self):
        return [{"dataverse_id": r.dataverse_id, "entra_id": r.entra_id} for r in self.readers]

    def table_metadata(self, name, columns):
        table = self.tables[name]
        assert tuple(columns) == table.columns
        return table

    def verify_operator_read_scope(self, table):
        self.calls.append(("operator_read_scope", table.name))
        return {"global_read_verified": True, "field_security_scope_verified": self.operator_field_scope_verified}

    def verify_identity(self, reader):
        self.calls.append(("identity", reader.entra_id))
        return {"dataverse_id": reader.dataverse_id, "entra_id": reader.entra_id}

    def verify_reader_binding(self, reader):
        self.calls.append(("reader_binding", reader.entra_id))
        assert reader in self.readers
        return {"verified": True}

    def can_read_table(self, reader, table):
        self.verify_reader_binding(reader)
        self.calls.append(("table_privilege", reader.entra_id, table.name))
        return (reader.entra_id, table.name) not in self.denied

    def open_scan(self, reader, table):
        if not self.can_read_table(reader, table):
            self.metrics["completed_scans"] += 1
            return SourceScan(False, iter(()))
        return SourceScan(True, self._iter_readable_rows(reader, table))

    def iter_rows(self, reader, table):
        yield from self.open_scan(reader, table).rows

    def _iter_readable_rows(self, reader, table):
        pair = reader.entra_id, table.name
        self.verify_identity(reader)
        if self.fail_pair == pair and not self.fail_after_yield:
            raise SourceProjectionError("synthetic_source_failure", "SOURCE_PII_SENTINEL must not be logged")
        for row in self.rows[pair]:
            yield dict(row)
            if self.fail_pair == pair and self.fail_after_yield:
                raise SourceProjectionError("synthetic_partial_source_failure", "FIELD_PII_SENTINEL must not be logged")
        self.metrics["completed_scans"] += 1
        self.metrics["completed_rows"] += len(self.rows[pair])


class RecordingDestination(DeltaDestination):
    def __init__(self, directory):
        super().__init__(local_root=directory)
        self.commits = []
        self.fail_on_table = None
        self.wrong_count = False

    def append(self, source_directory, source_table, item_id, path, reader_ids, generation):
        if source_table == self.fail_on_table:
            raise MaterializationError("synthetic_destination_failure")
        receipt = super().append(source_directory, source_table, item_id, path, reader_ids, generation)
        self.commits.append((item_id, receipt))
        return {**receipt, "rows": receipt["rows"] + 1} if self.wrong_count else receipt


class FakeFabric:
    def __init__(self, destination):
        self.destination = destination
        self.calls = []
        self.active = {}
        self.roles = {}
        self.etags = {}
        self.fail_publish_item = None
        self.fail_withdraw_items = set()
        self.expected_commit_count = None
        self.receipts = []

    def factory(self, tenant_id, workspace_id, item_id, **_):
        backend = self

        class Client:
            roles_url = "https://mock.invalid/roles"

            def __init__(self):
                self.tenant_id, self.workspace_id, self.item_id = tenant_id, workspace_id, item_id

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

            def dry_run(self, shard):
                backend.calls.append(("dry_run", item_id, shard.generation))
                return PublicationResult("dry_run", len(shard.roles), shard.plan_digest, "etag-dry", True)

            def list_roles(self):
                return RoleSnapshot(tuple(backend.roles.get(item_id, [])), str(backend.etags.get(item_id, 0)))

            def _owned(self, role, prefix):
                return FabricNativeClient._owned(self, role, prefix)

            def _request(self, method, url, *, payload, etag):
                assert method == "PUT" and url == self.roles_url
                assert etag == str(backend.etags.get(item_id, 0))
                if item_id in backend.fail_withdraw_items:
                    raise RuntimeError("synthetic_withdraw_failure")
                backend.roles[item_id] = payload["value"]
                backend.etags[item_id] = backend.etags.get(item_id, 0) + 1
                if not payload["value"]:
                    backend.active.pop(item_id, None)
                backend.calls.append(("watchdog_put", item_id, etag))

            def publish(self, shard, receipt, boundary):
                now = datetime.now(timezone.utc)
                receipt.validate(shard, now)
                boundary.validate(shard, now)
                assert receipt.workspace_id == workspace_id and receipt.item_id == item_id
                assert boundary.workspace_id == workspace_id and boundary.item_id == item_id
                if backend.expected_commit_count is not None:
                    assert len(backend.destination.commits) == backend.expected_commit_count
                backend.calls.append(("publish", item_id, shard.generation))
                backend.active[item_id] = shard.generation
                backend.roles[item_id] = shard.roles
                backend.etags[item_id] = backend.etags.get(item_id, 0) + 1
                backend.receipts.append(receipt)
                if item_id == backend.fail_publish_item:
                    # The ambiguous mutation could have committed, then lost its response.
                    raise RuntimeError("synthetic_mutation_response_lost")
                return PublicationResult("published", len(shard.roles), shard.plan_digest, "etag-live", True)

            def withdraw(self, prefix):
                backend.calls.append(("withdraw", item_id, prefix))
                if item_id in backend.fail_withdraw_items:
                    raise RuntimeError("synthetic_withdraw_failure")
                backend.active.pop(item_id, None)
                backend.roles[item_id] = []
                backend.etags[item_id] = backend.etags.get(item_id, 0) + 1
                return PublicationResult("withdrawn", 0, "0" * 64, "etag-empty", True)

        return Client()


def harness(tmp_path, count=2, *, table_shards=True, include_retired=False, batch_size=2, retention_mode="timed",
            role_naming="legacy", source_workers=1):
    source = FakeSource(count)
    items = {"a000_t000": uid(100)}
    if table_shards:
        items["a000_t001"] = uid(101)
    if include_retired:
        items["a099_t099"] = uid(199)
    config = AdapterConfig(
        environment_url="https://test.crm.dynamics.com", tenant_id=uid(1), organization_id=uid(2), workspace_id=uid(3),
        deployment_name="pw_runtime_test", readers=tuple(r.entra_id for r in source.readers),
        tables=tuple(TableSelection(name=t.name, columns=t.columns) for t in source.tables.values()),
        tables_per_shard=1 if table_shards else 100, serving_items=items, state_directory="private-state", batch_size=batch_size,
        retention_mode=retention_mode, role_naming=role_naming, source_workers=source_workers)
    path = tmp_path / "config.json"
    save_config(config, path)
    destination = RecordingDestination(tmp_path / "local-onelake")
    fabric = FakeFabric(destination)
    runtime = AdapterRuntime(path, credential=object(), source_factory=lambda *_, **__: source,
                             fabric_factory=fabric.factory, destination=destination)
    return runtime, source, destination, fabric


def boundaries(runtime, generation, tmp_path, *, mutate=None):
    _, _, _, plan = runtime.prepared(generation)
    value = {shard.key: {
        "workspace_id": runtime.config.workspace_id,
        "item_id": runtime.config.serving_items[shard.key],
        "reader_ids": list(shard.reader_ids),
        "inspected_at": datetime.now(timezone.utc).isoformat(),
        "no_privileged_workspace_readers": True,
        "no_alternate_data_access": True,
        "sql_endpoint_mode": "UserIdentity",
    } for shard in plan.shards}
    if mutate:
        mutate(value)
    path = tmp_path / "boundary.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def expire(journal, generation):
    with journal.connect() as db:
        db.execute("UPDATE runs SET expires=? WHERE generation=?", (time.time() - 1, generation))


def test_real_delta_prepare_200_readers_two_tables_and_typed_nulls(tmp_path):
    runtime, source, destination, fabric = harness(tmp_path, 200, batch_size=2000)
    for i, reader in enumerate(source.readers):
        if i % 10 == 0:
            source.denied.add((reader.entra_id, "contact"))
    run = runtime.prepare()
    assert run["status"] == "prepared"
    assert {k: v for k, v in run["summary"].items() if k not in {"manifest_sha256", "deployment_scope", "managed_items", "managed_tables",
                                                              "retention_mode", "publication_deadline_at", "automatic_withdrawal_at"}} == {
        "reader_count": 200, "table_count": 2, "total_rows": 380, "required_lakehouses": 2,
        "source_metrics": {"requests": 0, "completed_scans": 400, "completed_rows": 380},
        "source_mode": "dataverse_impersonated_reads",
    }
    assert len(run["summary"]["manifest_sha256"]) == 64
    assert run["summary"]["managed_items"] == runtime.config.serving_items
    assert not fabric.calls and not destination.commits
    _, directory, manifest, plan = runtime.prepared(run["generation"])
    assert len(plan.shards) == 2
    assert [len(shard.roles) for shard in plan.shards] == [200, 180]
    account = DeltaTable(str(directory / "account")).to_pyarrow_table()
    assert account.num_rows == 200
    assert pa.types.is_decimal(account.schema.field("amount").type)
    assert account.schema.field("createdon").type == pa.timestamp("us", tz="UTC")
    rows = {r["__pw_reader"]: r for r in account.to_pylist()}
    first, second = (rows[r.entra_id] for r in source.readers[:2])
    assert first["amount"] == Decimal("12345678901234567890.1234567890")
    assert first["createdon"] == datetime(2026, 9, 18, 12, tzinfo=timezone.utc)
    assert second["amount"] is None and second["secret"] is None
    assert {r["__pw_generation"] for r in rows.values()} == {run["generation"]}
    assert manifest["reader_table_counts"]["contact:" + source.readers[0].entra_id] == 0
    assert manifest["table_access"][source.readers[0].entra_id] == ["account"]
    assert ("table_privilege", source.readers[0].entra_id, "contact") in source.calls
    gates = Counter(call for call in source.calls if call[0] == "table_privilege")
    assert len(gates) == 400 and set(gates.values()) == {1}
    with runtime.journal.connect() as db:
        serialized = "\n".join(str(tuple(row)) for row in db.execute("SELECT * FROM events"))
    assert "SOURCE_PII_SENTINEL" not in serialized and "FIELD_PII_SENTINEL" not in serialized
    assert "SOURCE_PII_SENTINEL" not in (directory / "manifest.json").read_text()


@pytest.mark.parametrize("role_naming", ["readable", "user_business_role"])
def test_labelled_roles_are_persisted_and_replayed_without_changing_entitlements(tmp_path, role_naming):
    runtime, source, _, _ = harness(tmp_path, role_naming=role_naming)
    first, second = source.readers
    source.denied.add((second.entra_id, "contact"))
    labels = {r.entra_id: {
        "dataverse_id": r.dataverse_id, "entra_id": r.entra_id,
        "alias": f"pwtest{i:03d}", "display_name": f"Reader {i}",
        "business_unit": {"id": uid(1000), "name": "BNY Wealth"},
        "effective_roles": [{"role_id": uid(2001), "root_role_id": uid(2000),
            "name": "BNYM Contact Owner Role", "business_unit": {"id": uid(1000), "name": "BNY Wealth"},
            "origins": [{"kind": "team", "principal_id": uid(3000), "team": {"name": "Cross BU"}}]}],
        "teams": [{"id": uid(3000), "name": "Cross BU"}],
    } for i, r in enumerate(source.readers, 1)}
    calls = []
    def collect(readers, *, deadline_check):
        deadline_check()
        calls.append(tuple(readers))
        # Labels are acquired after all authoritative scans, never instead of them.
        assert source.metrics["completed_scans"] == 4
        return labels
    source.reader_role_labels = collect
    events = []
    runtime._progress_callback = events.append
    run = runtime.prepare()
    _, directory, manifest, plan = runtime.prepared(run["generation"])
    assert calls == [source.readers]
    assert manifest["role_naming"] == role_naming and manifest["reader_labels"] == labels
    assert manifest["table_access"][first.entra_id] == ["account", "contact"]
    assert manifest["table_access"][second.entra_id] == ["account"]
    assert manifest["total_rows"] == 3
    assert [len(s.roles) for s in plan.shards] == [2, 1]
    assert all("BNYMContactOwnerRole" in r["name"] for s in plan.shards for r in s.roles)
    if role_naming == "user_business_role":
        assert all(r["name"].startswith("pwtest") and not r["name"].startswith("PW")
                   for s in plan.shards for r in s.roles)
    assert verify_generation(directory)["reader_labels"] == labels
    # Replanning depends exclusively on hash-bound manifest evidence, not live labels.
    source.reader_role_labels = lambda *_args, **_kwargs: pytest.fail("Prepared replay cannot discover new labels")
    assert runtime.prepared(run["generation"])[3].as_dict() == plan.as_dict()
    assert "BNYM" not in json.dumps(events) and "pwtest" not in json.dumps(events)


@pytest.mark.parametrize("role_naming", ["readable", "user_business_role"])
def test_label_failure_never_prepares_or_publishes_partial_projection(tmp_path, role_naming):
    runtime, source, destination, fabric = harness(tmp_path, role_naming=role_naming)
    def fail(*_args, **_kwargs):
        raise SourceProjectionError("label_http_error", "A label endpoint failed.")
    source.reader_role_labels = fail
    with pytest.raises(SourceProjectionError) as failure:
        runtime.prepare()
    assert failure.value.code == "label_http_error"
    assert not destination.commits and not fabric.calls
    with runtime.journal.connect() as db:
        row = db.execute("SELECT status,error_code FROM runs").fetchone()
    assert tuple(row) == ("failed", "label_http_error")
    assert not list((runtime.directory / "generations").glob("*/manifest.json"))


@pytest.mark.parametrize("old_mode,new_mode", [
    ("legacy", "user_business_role"), ("readable", "user_business_role"),
    ("user_business_role", "readable"), ("user_business_role", "legacy"),
])
def test_naming_mode_change_requires_a_fresh_generation(tmp_path, old_mode, new_mode):
    runtime, source, destination, fabric = harness(tmp_path, role_naming=old_mode)
    source.reader_role_labels = lambda readers, **_: _simple_reader_labels(readers)
    run = runtime.prepare()
    changed = runtime.config.model_copy(update={"role_naming": new_mode})
    save_config(changed, runtime.config_path)
    with pytest.raises(RuntimeErrorSafe, match="configuration_changed_restart_worker"):
        runtime.prepared(run["generation"])
    with AdapterRuntime(runtime.config_path, credential=object(), source_factory=lambda *_, **__: source,
                        fabric_factory=fabric.factory, destination=destination) as restarted:
        with pytest.raises(RuntimeErrorSafe, match="generation_not_prepared_or_configuration_changed"):
            restarted.prepared(run["generation"])
        fresh = restarted.prepare()
        assert fresh["generation"] != run["generation"]
        assert restarted.prepared(fresh["generation"])[2].get("role_naming", "legacy") == new_mode
    assert not fabric.calls and not destination.commits


def _simple_reader_labels(readers):
    return {reader.entra_id: {
        "dataverse_id": reader.dataverse_id, "entra_id": reader.entra_id,
        "alias": f"reader{i:03d}", "display_name": f"Reader {i}",
        "business_unit": {"id": uid(1000), "name": "Client BU"},
        "effective_roles": [{"role_id": uid(2001), "root_role_id": uid(2000),
            "name": "Client Role", "business_unit": {"id": uid(1000), "name": "Client BU"},
            "origins": [{"kind": "direct", "principal_id": reader.dataverse_id}]}],
        "teams": [],
    } for i, reader in enumerate(readers, 1)}


@pytest.mark.parametrize("configured_mode,recorded_mode", [
    ("readable", "user_business_role"), ("user_business_role", "readable"),
    ("user_business_role", "legacy"), ("user_business_role", None),
])
def test_prepared_labelled_mode_mismatch_is_rejected_even_with_rebound_manifest_hash(
        tmp_path, configured_mode, recorded_mode):
    runtime, source, destination, fabric = harness(tmp_path, role_naming=configured_mode)
    source.reader_role_labels = lambda readers, **_: _simple_reader_labels(readers)
    run = runtime.prepare()
    path = runtime.directory / "generations" / str(run["generation"]) / "manifest.json"
    manifest = json.loads(path.read_text())
    if recorded_mode is None:
        manifest.pop("role_naming")
    else:
        manifest["role_naming"] = recorded_mode
    path.write_text(json.dumps(manifest), encoding="utf-8")
    summary = {**run["summary"], "manifest_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    with runtime.journal.connect() as db:
        db.execute("UPDATE runs SET summary=? WHERE generation=?", (json.dumps(summary), run["generation"]))
    with pytest.raises(RuntimeErrorSafe, match="generation_role_naming_mismatch"):
        runtime.prepared(run["generation"])
    assert not fabric.calls and not destination.commits


def test_legacy_naming_does_not_request_new_source_metadata(tmp_path):
    runtime, source, _, _ = harness(tmp_path)
    source.reader_role_labels = lambda *_a, **_kw: pytest.fail("Legacy mode cannot require new privileges or calls")
    run = runtime.prepare()
    _, _, manifest, plan = runtime.prepared(run["generation"])
    assert "reader_labels" not in manifest and "role_naming" not in manifest
    assert all("BNYM" not in r["name"] for s in plan.shards for r in s.roles)


@pytest.mark.parametrize("mode,name", [("fetchxml", "pw_ReadContext"), ("custom_api", "bank_ReadContext")])
def test_runtime_passes_explicit_identity_verification_to_source(tmp_path, mode, name):
    runtime, source, _, _ = harness(tmp_path)
    digest = "a" * 64 if mode == "custom_api" else None
    config = runtime.config.model_copy(update={"identity_verification": mode, "identity_api_name": name,
                                               "identity_api_assembly_sha256": digest})
    save_config(config, runtime.config_path)
    seen = {}
    def factory(*args, **kwargs):
        seen.update(kwargs)
        return source
    with AdapterRuntime(runtime.config_path, credential=object(), source_factory=factory) as updated:
        assert updated.source() is source
    assert seen["identity_verification"] == mode
    assert seen["identity_api_name"] == name
    assert seen["identity_api_assembly_sha256"] == digest


def test_all_data_commits_precede_any_policy_activation_and_receipts_match(tmp_path):
    runtime, source, destination, fabric = harness(tmp_path)
    run = runtime.prepare()
    fabric.expected_commit_count = 2
    result = runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
    assert result["status"] == "published"
    assert len(fabric.receipts) == 2
    assert all(r.generation == run["generation"] for r in fabric.receipts)
    assert all(len(r.content_digest) == 64 for r in fabric.receipts)
    assert set(fabric.active.values()) == {run["generation"]}
    assert all(p["enforcement_verified"] is False for p in result["summary"]["publication"].values())
    for table_index, name in enumerate(("account", "contact")):
        uri = destination.uri(runtime.config.serving_items[f"a000_t{table_index:03d}"], f"/Tables/dbo/pw_runtime_test_{name}")
        rows = DeltaTable(uri).to_pyarrow_table().to_pylist()
        assert len(rows) == 2
        assert {r["__pw_reader"] for r in rows} == {r.entra_id for r in source.readers}


@pytest.mark.parametrize("after_yield", [False, True])
def test_one_failed_reader_discards_whole_generation_and_never_activates(tmp_path, after_yield):
    runtime, source, destination, fabric = harness(tmp_path)
    source.fail_pair = source.readers[-1].entra_id, "contact"
    source.fail_after_yield = after_yield
    with pytest.raises(SourceProjectionError):
        runtime.prepare()
    run = runtime.journal.recent()[0]
    assert run["status"] == "failed"
    assert run["error_code"] in {"synthetic_source_failure", "synthetic_partial_source_failure"}
    assert not (runtime.directory / "generations" / str(run["generation"]) / "manifest.json").exists()
    assert not fabric.calls and not destination.commits
    with pytest.raises(RuntimeErrorSafe):
        runtime.prepared(run["generation"])


def test_unqualified_operator_field_scope_blocks_generation_before_source_rows(tmp_path):
    runtime, source, destination, fabric = harness(tmp_path)
    source.operator_field_scope_verified = False
    with pytest.raises((RuntimeErrorSafe, SourceProjectionError)):
        runtime.prepare()
    assert runtime.journal.recent()[0]["status"] == "failed"
    assert not destination.commits and not fabric.calls
    assert source.metrics["completed_rows"] == 0


def test_entirely_empty_denied_table_is_typed_delta_and_zero_row_receipt(tmp_path):
    runtime, source, destination, fabric = harness(tmp_path)
    source.denied = {(r.entra_id, "contact") for r in source.readers}
    run = runtime.prepare()
    _, directory, manifest, plan = runtime.prepared(run["generation"])
    empty = DeltaTable(str(directory / "contact")).to_pyarrow_table()
    assert empty.num_rows == 0
    assert empty.schema.field("amount").type == pa.decimal128(38, 10)
    assert all(manifest["reader_table_counts"]["contact:" + r.entra_id] == 0 for r in source.readers)
    assert plan.shards[1].roles == []
    result = runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
    assert result["status"] == "published"
    assert destination.commits[1][1]["rows"] == 0


def test_removing_all_reader_roles_produces_empty_projection_and_removes_native_permissions(tmp_path, monkeypatch):
    runtime, source, _, fabric = harness(tmp_path)
    previous = runtime.prepare()
    runtime.publish(previous["generation"], boundaries(runtime, previous["generation"], tmp_path))
    removed = source.readers[0].entra_id
    source.denied = {(removed, name) for name in source.tables}
    original_identity, original_rows = source.verify_identity, source._iter_readable_rows
    def identity(reader):
        if reader.entra_id == removed:
            pytest.fail("An unroled reader cannot execute the impersonated identity probe.")
        return original_identity(reader)
    def rows(reader, table):
        if reader.entra_id == removed:
            pytest.fail("Verified absence must not be re-read or become a data scan.")
        return original_rows(reader, table)
    monkeypatch.setattr(source, "verify_identity", identity)
    monkeypatch.setattr(source, "_iter_readable_rows", rows)
    run = runtime.prepare()
    _, directory, manifest, plan = runtime.prepared(run["generation"])
    assert manifest["table_access"][removed] == []
    assert all(manifest["reader_table_counts"][name + ":" + removed] == 0 for name in source.tables)
    for name in source.tables:
        dataset = DeltaTable(str(directory / name)).to_pyarrow_dataset()
        assert dataset.count_rows(filter=ds.field("__pw_reader") == removed) == 0
    assert all(member["objectId"] != removed for shard in plan.shards for role in shard.roles
               for member in role["members"]["microsoftEntraMembers"])
    runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
    assert all(member["objectId"] != removed for roles in fabric.roles.values() for role in roles
               for member in role["members"]["microsoftEntraMembers"])


def test_positive_read_execution_context_failure_still_discards_generation(tmp_path, monkeypatch):
    runtime, source, destination, fabric = harness(tmp_path)
    def wrong_context(reader):
        raise SourceProjectionError("impersonation_mismatch", "Synthetic wrong execution context.")
    monkeypatch.setattr(source, "verify_identity", wrong_context)
    with pytest.raises(SourceProjectionError) as failure:
        runtime.prepare()
    assert failure.value.code == "impersonation_mismatch"
    assert runtime.journal.recent()[0]["status"] == "failed"
    assert not destination.commits and not fabric.calls


@pytest.mark.parametrize("retention_mode", ["timed", "manual"])
def test_expired_prepared_generation_cannot_reach_fabric(tmp_path, retention_mode):
    runtime, _, destination, fabric = harness(tmp_path, retention_mode=retention_mode)
    run = runtime.prepare()
    path = boundaries(runtime, run["generation"], tmp_path)
    expire(runtime.journal, run["generation"])
    with pytest.raises(RuntimeErrorSafe):
        runtime.publish(run["generation"], path)
    assert not destination.commits and not fabric.calls


def test_changed_configuration_cannot_publish_existing_generation(tmp_path):
    runtime, source, destination, fabric = harness(tmp_path)
    run = runtime.prepare()
    path = boundaries(runtime, run["generation"], tmp_path)
    changed = runtime.config.model_copy(update={"excluded_readers": (source.readers[0].entra_id,)})
    save_config(changed, runtime.config_path)
    new_runtime = AdapterRuntime(runtime.config_path, credential=object(), source_factory=lambda *_, **__: source,
                                 fabric_factory=fabric.factory, destination=destination)
    with pytest.raises(RuntimeErrorSafe):
        new_runtime.publish(run["generation"], path)
    assert not destination.commits and not fabric.calls


def test_same_worker_rejects_configuration_edited_after_prepare(tmp_path):
    runtime, source, destination, fabric = harness(tmp_path)
    run = runtime.prepare()
    path = boundaries(runtime, run["generation"], tmp_path)
    save_config(runtime.config.model_copy(update={"excluded_readers": (source.readers[0].entra_id,)}), runtime.config_path)
    with pytest.raises(RuntimeErrorSafe):
        runtime.publish(run["generation"], path)
    assert not destination.commits and not fabric.calls


def test_delta_file_tamper_is_detected_before_upload(tmp_path):
    runtime, _, destination, fabric = harness(tmp_path)
    run = runtime.prepare()
    path = boundaries(runtime, run["generation"], tmp_path)
    directory = runtime.directory / "generations" / str(run["generation"])
    parquet = next(directory.rglob("*.parquet"))
    with parquet.open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(MaterializationError, match="hash_mismatch"):
        runtime.publish(run["generation"], path)
    assert not destination.commits and not fabric.calls


def test_manifest_tamper_is_detected_before_plan_or_upload(tmp_path):
    runtime, _, destination, fabric = harness(tmp_path)
    run = runtime.prepare()
    path = runtime.directory / "generations" / str(run["generation"]) / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["reader_table_counts"][next(iter(manifest["reader_table_counts"]))] += 1
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises((MaterializationError, RuntimeErrorSafe)):
        runtime.prepared(run["generation"])
    assert not destination.commits and not fabric.calls


@pytest.mark.parametrize("mutation", [
    lambda b: b["a000_t000"].update(no_alternate_data_access=False),
    lambda b: b["a000_t000"].update(sql_endpoint_mode="DelegatedIdentity"),
    lambda b: b["a000_t000"].update(inspected_at=(datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat()),
    lambda b: b["a000_t000"].update(item_id=uid(999)),
    lambda b: b["a000_t000"].update(reader_ids=[]),
])
@pytest.mark.parametrize("retention_mode", ["timed", "manual"])
def test_invalid_boundary_never_uploads_or_activates(tmp_path, mutation, retention_mode):
    runtime, _, destination, fabric = harness(tmp_path, retention_mode=retention_mode)
    run = runtime.prepare()
    path = boundaries(runtime, run["generation"], tmp_path, mutate=mutation)
    with pytest.raises(Exception):
        runtime.publish(run["generation"], path)
    assert not destination.commits
    assert not any(c[0] == "publish" for c in fabric.calls)
    assert runtime.journal.get(run["generation"])["status"] == "prepared"


@pytest.mark.parametrize("retention_mode", ["timed", "manual"])
def test_ambiguous_publication_withdraws_all_managed_items_without_rollback(tmp_path, retention_mode):
    runtime, _, destination, fabric = harness(tmp_path, include_retired=True, retention_mode=retention_mode)
    first = runtime.prepare()
    runtime.publish(first["generation"], boundaries(runtime, first["generation"], tmp_path))
    fabric.calls.clear()
    second = runtime.prepare()
    fabric.fail_publish_item = uid(101)
    with pytest.raises(RuntimeError, match="mutation_response_lost"):
        runtime.publish(second["generation"], boundaries(runtime, second["generation"], tmp_path))
    assert runtime.journal.get(second["generation"])["status"] == "quarantined"
    assert {c[1] for c in fabric.calls if c[0] == "withdraw"} == set(runtime.config.serving_items.values())
    assert not fabric.active
    assert all(c[2] == second["generation"] for c in fabric.calls if c[0] == "publish")


def test_destination_failure_and_count_mismatch_prevent_activation_and_withdraw_all(tmp_path):
    runtime, _, destination, fabric = harness(tmp_path, include_retired=True)
    run = runtime.prepare()
    destination.wrong_count = True
    with pytest.raises(RuntimeErrorSafe, match="row_count"):
        runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
    assert not any(c[0] == "publish" for c in fabric.calls)
    assert {c[1] for c in fabric.calls if c[0] == "withdraw"} == set(runtime.config.serving_items.values())
    assert runtime.journal.get(run["generation"])["status"] == "quarantined"


def test_watchdog_expiry_withdraws_and_does_not_claim_engine_propagation(tmp_path, monkeypatch):
    runtime, _, _, fabric = harness(tmp_path)
    run = runtime.prepare()
    runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
    assert runtime.watchdog()["status"] == "ok"
    monkeypatch.setattr("policyweaver.runtime.time.time", lambda: run["expires"] + 1)
    result = runtime.watchdog()
    assert result["status"] == "ok"
    assert all(item["status"] == "withdrawn_expired_generation" for item in result["items"].values())
    assert result["engine_revocation_verified"] is False
    assert not fabric.active
    # An asynchronous remote observation must not overwrite concurrent journal
    # activation state. Item-remap recovery requires explicit locked withdrawal.
    assert runtime.journal.get(run["generation"])["status"] == "published"


def test_watchdog_reports_failed_withdrawal_and_retries(tmp_path, monkeypatch):
    runtime, _, _, fabric = harness(tmp_path)
    run = runtime.prepare()
    runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
    monkeypatch.setattr("policyweaver.runtime.time.time", lambda: run["expires"] + 1)
    fabric.fail_withdraw_items.add(uid(100))
    with pytest.raises(RuntimeErrorSafe, match="critical_stale_access"):
        runtime.watchdog()
    assert uid(100) in fabric.active and uid(101) not in fabric.active
    fabric.fail_withdraw_items.clear()
    runtime.watchdog()
    assert not fabric.active
    assert runtime.journal.get(run["generation"])["status"] == "published"


def test_old_quarantined_generation_does_not_withdraw_new_success(tmp_path):
    runtime, _, _, fabric = harness(tmp_path)
    first = runtime.prepare()
    fabric.fail_publish_item = uid(101)
    with pytest.raises(RuntimeError):
        runtime.publish(first["generation"], boundaries(runtime, first["generation"], tmp_path))
    fabric.fail_publish_item = None
    second = runtime.prepare()
    runtime.publish(second["generation"], boundaries(runtime, second["generation"], tmp_path))
    expire(runtime.journal, first["generation"])
    fabric.calls.clear()
    runtime.watchdog()
    assert fabric.active == {item: second["generation"] for item in runtime.config.serving_items.values()}
    assert not any(c[0] == "withdraw" for c in fabric.calls)


def test_journal_lock_single_writer_exception_release_and_no_timeout_steal(tmp_path):
    journal = Journal(tmp_path)
    with journal.lock(lifetime=0):
        with pytest.raises(JournalError, match="writer_lock_held"):
            with Journal(tmp_path).lock():
                raise AssertionError("second writer acquired lock")
    with pytest.raises(RuntimeError):
        with journal.lock():
            raise RuntimeError("simulated operation failure")
    with journal.lock():
        pass
    # A process death leaves a durable lock. Timeout alone must not steal it;
    # recovery must establish that the previous writer has actually stopped.
    with journal.connect() as db:
        db.execute("INSERT INTO process_lock VALUES(1,?,?)", ("crashed-worker", time.time() - 3600))
    with pytest.raises(JournalError, match="writer_lock_held"):
        with journal.lock():
            raise AssertionError("expired lock was stolen")


def test_journal_cas_transitions_and_monotonic_generation_ids(tmp_path, monkeypatch):
    journal = Journal(tmp_path)
    monkeypatch.setattr("policyweaver.journal.time.time", lambda: 1234567890.0)
    first = journal.create("hash", 100)
    second = journal.create("hash", 100)
    assert second == first + 1
    journal.transition(first, "preparing", "prepared")
    with pytest.raises(JournalError, match="invalid_generation_transition"):
        journal.transition(first, "preparing", "published")
    assert journal.get(first)["status"] == "prepared"


def test_journal_crash_recovery_requires_exact_owner_and_stopped_worker_attestation(tmp_path):
    journal = Journal(tmp_path)
    with journal.connect() as db:
        db.execute("INSERT INTO process_lock VALUES(1,?,?)", ("99999:crashed-worker", time.time() - 3600))
    info = journal.lock_info()
    assert info["owner"] == "99999:crashed-worker"
    with pytest.raises(JournalError, match="confirmed_stopped_worker"):
        journal.recover_lock(info["owner"])
    with pytest.raises(JournalError, match="owner_changed"):
        journal.recover_lock("different-worker", worker_stopped=True)
    assert journal.lock_info() == info
    journal.recover_lock(info["owner"], worker_stopped=True)
    assert journal.lock_info() is None
    with journal.lock():
        pass
    with journal.connect() as db:
        events = db.execute("SELECT kind,details FROM events WHERE kind='operator_lock_recovery'").fetchall()
    assert len(events) == 1 and json.loads(events[0]["details"])["previous_owner"] == info["owner"]


def test_generation_writer_duplicate_record_or_reader_table_rejects(tmp_path):
    source = FakeSource(1)
    table = source.tables["account"]
    reader = source.readers[0]
    row = source.rows[(reader.entra_id, table.name)][0]
    writer = GenerationWriter(tmp_path / "g1", 1, [table], batch_size=1)
    with pytest.raises(MaterializationError, match="duplicate_record"):
        writer.add_reader(table.name, reader.entra_id, [row, row])
    writer2 = GenerationWriter(tmp_path / "g2", 2, [table])
    writer2.add_reader(table.name, reader.entra_id, [row])
    with pytest.raises(MaterializationError, match="written_twice"):
        writer2.add_reader(table.name, reader.entra_id, [])


def test_cli_status_and_failures_do_not_print_source_rows_or_credentials(tmp_path, capsys, monkeypatch):
    from policyweaver import adapter_cli

    runtime, source, _, _ = harness(tmp_path)
    assert adapter_cli.main(["--config", str(runtime.config_path), "status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["runs"] == [] and status["production_certified"] is False
    source.fail_pair = source.readers[0].entra_id, "account"
    monkeypatch.setattr("policyweaver.runtime.AdapterRuntime", lambda *_: runtime)
    assert adapter_cli.main(["--config", str(runtime.config_path), "prepare"]) == 1
    captured = capsys.readouterr().out
    failure = json.loads(captured)
    assert failure["error_code"] == "synthetic_source_failure"
    assert "SOURCE_PII_SENTINEL" not in captured and "FIELD_PII_SENTINEL" not in captured


@pytest.mark.parametrize("retention_mode", ["timed", "manual"])
def test_retention_metadata_is_durable_and_separate_from_publication_freshness(tmp_path, retention_mode):
    runtime, _, _, _ = harness(tmp_path, retention_mode=retention_mode)
    run = runtime.prepare()
    _, _, manifest, _ = runtime.prepared(run["generation"])
    assert run["expires"] - run["started"] == runtime.config.generation_lifetime_seconds
    assert manifest["expires_at"] == run["expires"]
    expected = {"retention_mode": retention_mode,
                "publication_deadline_at": run["expires"] - runtime.config.publication_budget_seconds,
                "automatic_withdrawal_at": None if retention_mode == "manual" else run["expires"]}
    reopened = Journal(runtime.directory).get(run["generation"])
    assert all(manifest[k] == run["summary"][k] == reopened["summary"][k] == v for k, v in expected.items())


def test_manual_roles_survive_age_but_explicit_withdrawal_still_removes_them(tmp_path, monkeypatch):
    runtime, _, _, fabric = harness(tmp_path, retention_mode="manual")
    run = runtime.prepare()
    published = runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
    assert published["summary"]["automatic_withdrawal_at"] is None
    monkeypatch.setattr("policyweaver.runtime.time.time", lambda: run["expires"] + 86_400)
    health = runtime.watchdog()
    assert health["status"] == "ok" and all(not entry["mutation_attempted"] for entry in health["items"].values())
    assert fabric.active == {item: run["generation"] for item in runtime.config.serving_items.values()}
    result = runtime.withdraw()
    assert result["status"] == "withdrawn_control_plane" and result["engine_propagation_verified"] is False
    assert not fabric.active
    assert runtime.journal.get(run["generation"])["status"] == "withdrawn"
    assert runtime.journal.get(run["generation"])["summary"]["retention_mode"] == "manual"


@pytest.mark.parametrize("initial,replacement", [("timed", "manual"), ("manual", "timed")])
def test_retention_change_requires_a_new_generation(tmp_path, initial, replacement):
    runtime, source, destination, fabric = harness(tmp_path, retention_mode=initial)
    run = runtime.prepare()
    boundary = boundaries(runtime, run["generation"], tmp_path)
    save_config(runtime.config.model_copy(update={"retention_mode": replacement}), runtime.config_path)
    other = AdapterRuntime(runtime.config_path, credential=object(), source_factory=lambda *_, **__: source,
                           fabric_factory=fabric.factory, destination=destination)
    with pytest.raises(RuntimeErrorSafe, match="configuration_changed"):
        other.publish(run["generation"], boundary)
    assert not fabric.calls and not destination.commits


def test_manual_scan_still_stops_when_finite_publication_reserve_is_exhausted(tmp_path, monkeypatch):
    runtime, source, destination, fabric = harness(tmp_path, retention_mode="manual")
    original = source.open_scan
    calls = 0
    def run_out_of_time(reader, table):
        nonlocal calls
        calls += 1
        scan = original(reader, table)
        if calls == 1:
            active = runtime.journal.recent()[0]
            monkeypatch.setattr("policyweaver.runtime.time.time",
                                lambda: active["expires"] - runtime.config.publication_budget_seconds)
        return scan
    monkeypatch.setattr(source, "open_scan", run_out_of_time)
    with pytest.raises(RuntimeErrorSafe, match="freshness_budget_exhausted"):
        runtime.prepare()
    assert runtime.journal.recent()[0]["status"] == "failed"
    assert not fabric.calls and not destination.commits


def test_journal_retention_cannot_change_during_transition(tmp_path):
    journal = Journal(tmp_path)
    generation = journal.create("hash", 2700, retention_mode="manual", publication_budget_seconds=600)
    summary = journal.get(generation)["summary"]
    for changed in ({}, {**summary, "retention_mode": "timed"},
                    {**summary, "automatic_withdrawal_at": journal.get(generation)["expires"]},
                    {**summary, "publication_deadline_at": summary["publication_deadline_at"] + 1}):
        with pytest.raises(JournalError, match="retention_metadata_changed"):
            journal.transition(generation, "preparing", "prepared", summary=changed)
    journal.transition(generation, "preparing", "prepared", summary={**summary, "reader_count": 2})
    assert journal.get(generation)["summary"]["retention_mode"] == "manual"


def test_manual_manifest_retention_mismatch_rejects_even_with_rebound_file_hash(tmp_path):
    runtime, _, destination, fabric = harness(tmp_path, retention_mode="manual")
    run = runtime.prepare()
    path = runtime.directory / "generations" / str(run["generation"]) / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["retention_mode"] = "timed"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    summary = {**run["summary"], "manifest_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    with runtime.journal.connect() as db:
        db.execute("UPDATE runs SET summary=? WHERE generation=?", (json.dumps(summary), run["generation"]))
    with pytest.raises(RuntimeErrorSafe, match="retention_metadata_mismatch"):
        runtime.prepared(run["generation"])
    assert not fabric.calls and not destination.commits


def test_legacy_timed_generation_with_no_retention_metadata_remains_preparable(tmp_path):
    runtime, _, _, _ = harness(tmp_path)
    run = runtime.prepare()
    path = runtime.directory / "generations" / str(run["generation"]) / "manifest.json"
    manifest, summary = json.loads(path.read_text()), dict(run["summary"])
    for key in ("retention_mode", "publication_deadline_at", "automatic_withdrawal_at"):
        manifest.pop(key)
        summary.pop(key)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    summary["manifest_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with runtime.journal.connect() as db:
        db.execute("UPDATE runs SET summary=? WHERE generation=?", (json.dumps(summary), run["generation"]))
    actual, _, _, _ = runtime.prepared(run["generation"])
    assert actual["generation"] == run["generation"]
