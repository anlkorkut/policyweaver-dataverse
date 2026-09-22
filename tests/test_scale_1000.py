"""Local 1,000-reader integration capacity smoke test, never a live-load claim."""
from collections import Counter
from decimal import Decimal
import re

from deltalake import DeltaTable
import pyarrow.dataset as ds

from policyweaver.config import AdapterConfig, TableSelection, save_config
from policyweaver.runtime import AdapterRuntime

# Reuse the existing source/Fabric boundary doubles while retaining real Delta.
from test_adapter_runtime import FakeSource, RecordingDestination, FakeFabric, boundaries, uid


def test_1000_readers_typed_delta_publish_across_five_isolated_audience_shards(tmp_path):
    source = FakeSource(1000)
    selected = source.tables["account"]
    items = {f"a{i:03d}_t000": uid(700 + i) for i in range(5)}
    config = AdapterConfig(
        environment_url="https://test.crm.dynamics.com", tenant_id=uid(1), organization_id=uid(2),
        workspace_id=uid(3), deployment_name="pw_scale_1000",
        readers=tuple(r.entra_id for r in source.readers),
        tables=(TableSelection(name=selected.name, columns=selected.columns),),
        role_limit=250, reserved_roles=10, tables_per_shard=100,
        serving_items=items, batch_size=2000, state_directory="isolated-state")
    config_path = tmp_path / "config.json"
    save_config(config, config_path)
    destination = RecordingDestination(tmp_path / "local-serving")
    fabric = FakeFabric(destination)
    runtime = AdapterRuntime(config_path, credential=object(), source_factory=lambda *_, **__: source,
                             fabric_factory=fabric.factory, destination=destination)
    try:
        run = runtime.prepare()
        assert run["status"] == "prepared"
        assert run["summary"]["reader_count"] == 1000
        assert run["summary"]["total_rows"] == 1000
        assert run["summary"]["required_lakehouses"] == 5
        assert source.metrics["completed_scans"] == 1000
        assert not fabric.calls and not destination.commits
        _, _, manifest, plan = runtime.prepared(run["generation"])
        assert [len(s.reader_ids) for s in plan.shards] == [240, 240, 240, 240, 40]
        assert len(manifest["reader_table_counts"]) == 1000
        assert all(count == 1 for count in manifest["reader_table_counts"].values())
        reader_shards = Counter(reader for shard in plan.shards for reader in shard.reader_ids)
        assert set(reader_shards.values()) == {1}
        assert set(reader_shards) == {r.entra_id for r in source.readers}

        for shard in plan.shards:
            assert len(shard.roles) + config.reserved_roles <= config.role_limit
            for role, reader in zip(shard.roles, shard.reader_ids):
                assert role["members"]["microsoftEntraMembers"] == [
                    {"tenantId": config.tenant_id, "objectId": reader, "objectType": "User"}]
                rule = role["decisionRules"][0]
                predicate = rule["constraints"]["rows"][0]["value"]
                assert len(predicate) <= 1000
                assert re.search(r"__pw_reader\s*=\s*'" + re.escape(reader) + "'", predicate)
                assert f"__pw_generation = {run['generation']}" in predicate
                assert not any(c.startswith("__pw_") for c in rule["constraints"]["columns"][0]["columnNames"])

        fabric.expected_commit_count = 5
        published = runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
        assert published["status"] == "published"
        assert len(destination.commits) == 5
        assert len(fabric.receipts) == 5
        assert set(fabric.active) == set(items.values())
        assert all(len(commit[1]["content_sha256"]) == 64 for commit in destination.commits)
        all_readers = set()
        for shard, (_, commit) in zip(plan.shards, destination.commits):
            assert commit["rows"] == len(shard.reader_ids)
            uri = destination.uri(items[shard.key], shard.tables[0].path)
            dataset = DeltaTable(uri).to_pyarrow_dataset()
            actual = dataset.to_table().to_pylist()
            assert {r["__pw_reader"] for r in actual} == set(shard.reader_ids)
            assert {r["__pw_generation"] for r in actual} == {run["generation"]}
            assert not all_readers.intersection(shard.reader_ids)
            all_readers.update(shard.reader_ids)
            # Exercise actual typed Arrow filtering for every reader, not just
            # planning count arithmetic. This does not emulate an engine identity.
            for reader in shard.reader_ids:
                visible = dataset.scanner(filter=(ds.field("__pw_reader") == reader)
                                          & (ds.field("__pw_generation") == run["generation"])).to_table().to_pylist()
                assert len(visible) == 1
                expected = source.rows[(reader, "account")][0]
                assert visible[0]["accountid"] == expected["accountid"]
                assert visible[0]["secret"] == expected["secret"]
                assert visible[0]["amount"] == expected["amount"]
                if expected["amount"] is not None:
                    assert isinstance(visible[0]["amount"], Decimal)
            foreign = next(r.entra_id for r in source.readers if r.entra_id not in shard.reader_ids)
            assert dataset.count_rows(filter=ds.field("__pw_reader") == foreign) == 0
        assert len(all_readers) == 1000
    finally:
        runtime.close()
