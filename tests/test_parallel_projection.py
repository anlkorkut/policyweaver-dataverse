"""Parallel scheduling preserves reader gates and never publishes partial scans."""
from collections import Counter
from copy import deepcopy
from pathlib import Path
from threading import Event, Lock, get_ident
import time

from deltalake import DeltaTable
import pytest

from policyweaver.parallel_projection import ParallelProjectionError, ParallelSourceScans
from policyweaver.source_projection import SourceProjectionError, SourceScan
from policyweaver.materialization import GenerationWriter
from test_adapter_runtime import FakeSource, harness, uid


def parallel_harness(tmp_path, *, count=6, failure=None, after_yield=False, readable=False):
    runtime, source, destination, fabric = harness(tmp_path, count=count, source_workers=2,
                                                  role_naming="readable" if readable else "legacy")
    clients = []
    lock = Lock()
    class IsolatedSource(FakeSource):
        def __init__(self):
            super().__init__(count)
            self.closed = False
            self.owner_thread = None
            self.denied = {(r.entra_id, "contact") for i, r in enumerate(self.readers) if i % 3 == 0}
            self.fail_pair, self.fail_after_yield = failure, after_yield
            with lock:
                self.number = len(clients)
                clients.append(self)
        def __enter__(self):
            self.owner_thread = get_ident()
            return self
        def __exit__(self, *_):
            assert get_ident() == self.owner_thread
            self.closed = True
        def open_scan(self, reader, table):
            assert self.number != 0, "Metadata client cannot execute parallel reader scans"
            assert get_ident() == self.owner_thread
            return super().open_scan(reader, table)
        def reader_role_labels(self, readers, *, deadline_check):
            assert self.number == 0 and all(s.closed for s in clients[1:])
            deadline_check()
            return {r.entra_id: {"alias": f"pwtest{i:03d}", "business_unit": {"name": "Bank"},
                                "effective_roles": []} for i, r in enumerate(readers, 1)}
    runtime.source_factory = lambda *_args, **_kwargs: IsolatedSource()
    return runtime, clients, destination, fabric


def test_parallel_real_delta_matches_sequential_and_only_main_thread_writes(tmp_path, monkeypatch):
    sequential, sequential_source, _, _ = harness(tmp_path / "sequential", count=6)
    sequential_source.denied = {(r.entra_id, "contact") for i, r in enumerate(sequential_source.readers) if i % 3 == 0}
    before = sequential.prepare()
    _, sequential_dir, sequential_manifest, _ = sequential.prepared(before["generation"])
    parallel, clients, destination, fabric = parallel_harness(tmp_path / "parallel")
    main_thread = get_ident()
    original_add = GenerationWriter.add_reader
    def main_only(writer, *args, **kwargs):
        assert get_ident() == main_thread
        return original_add(writer, *args, **kwargs)
    monkeypatch.setattr(GenerationWriter, "add_reader", main_only)
    original_event = parallel.journal.event
    def journal_main_only(*args, **kwargs):
        assert get_ident() == main_thread
        return original_event(*args, **kwargs)
    monkeypatch.setattr(parallel.journal, "event", journal_main_only)
    after = parallel.prepare()
    _, parallel_dir, manifest, _ = parallel.prepared(after["generation"])
    assert after["status"] == "prepared"
    assert manifest["source_workers"] == 2 and "source_workers" not in sequential_manifest
    assert manifest["source_metrics"]["completed_scans"] == 12
    assert manifest["source_metrics"]["completed_rows"] == 10
    assert manifest["table_access"] == sequential_manifest["table_access"]
    assert manifest["reader_table_counts"] == sequential_manifest["reader_table_counts"]
    for name in ("account", "contact"):
        def rows(directory):
            data = DeltaTable(str(directory / name)).to_pyarrow_table().to_pylist()
            return sorted(({k: v for k, v in r.items() if k != "__pw_generation"} for r in data),
                          key=lambda r: r["__pw_reader"])
        assert rows(parallel_dir) == rows(sequential_dir)
    assert len(clients) == 3 and all(s.closed for s in clients)
    assert clients[0].owner_thread == main_thread
    assert len({s.owner_thread for s in clients[1:]}) == 2
    actual = Counter(c for s in clients for c in s.calls if c[0] == "table_privilege")
    assert len(actual) == 12 and set(actual.values()) == {1}
    assert not destination.commits and not fabric.calls


def test_parallel_labels_are_collected_after_all_workers_close(tmp_path):
    runtime, clients, _, _ = parallel_harness(tmp_path, readable=True)
    run = runtime.prepare()
    manifest = runtime.prepared(run["generation"])[2]
    assert len(manifest["reader_labels"]) == 6
    assert all(s.closed for s in clients)


@pytest.mark.parametrize("after_yield", [False, True])
def test_any_parallel_reader_or_page_failure_invalidates_whole_generation(tmp_path, after_yield):
    failure = (uid(20001), "account")
    runtime, clients, destination, fabric = parallel_harness(tmp_path, failure=failure, after_yield=after_yield)
    with pytest.raises(SourceProjectionError):
        runtime.prepare()
    with runtime.journal.connect() as db:
        assert db.execute("SELECT status FROM runs").fetchone()[0] == "failed"
    assert not list((runtime.directory / "generations").glob("*/manifest.json"))
    assert all(s.closed for s in clients)
    assert not destination.commits and not fabric.calls


class StreamingSource:
    def __init__(self, clients, started, produced, *, gate_failure=False):
        self.clients, self.started, self.produced = clients, started, produced
        self.closed = False
        self.metrics = {"requests": 1, "retries": 0, "completed_scans": 0, "completed_rows": 0}
        self.gate_failure = gate_failure
        clients.append(self)
    def __enter__(self):
        return self
    def __exit__(self, *_):
        self.closed = True
    def open_scan(self, reader, table):
        self.started.append((reader, table))
        if self.gate_failure:
            raise SourceProjectionError("synthetic_gate_failure", "Failed gate is never absent Read")
        def rows():
            for number in range(100000):
                self.produced.append((reader, number))
                yield {"id": number}
            self.metrics["completed_scans"] += 1
        return SourceScan(True, rows())


def test_queues_and_inflight_pairs_stay_bounded_and_early_exit_closes_all():
    clients, started, produced = [], [], []
    factory = lambda: StreamingSource(clients, started, produced)
    began = time.monotonic()
    pool = ParallelSourceScans(factory, [(i, "t") for i in range(100)], 2,
                               deadline_check=lambda: None, queue_size=2)
    with pytest.raises(ParallelProjectionError, match="not_exhausted"):
        with pool:
            scan = pool.open_scan(0, "t")
            time.sleep(0.1)  # Allow both producers to reach their bounded queues.
            assert len(started) == 2 and len(pool._active) == 2
            assert all(t.messages.qsize() <= 2 for t in pool._active)
            assert len(produced) <= 5  # Two queues plus at most one held row per producer.
            assert scan.has_read is True
    assert time.monotonic() - began < 3
    assert len(clients) == 2 and all(s.closed for s in clients)
    assert all(not t.is_alive() for t in pool._threads)


def test_deadline_interrupts_bounded_queue_wait_and_cleans_up():
    clients, started, produced = [], [], []
    expired = Event()
    def deadline():
        if expired.is_set():
            raise RuntimeError("test_deadline_exhausted")
    pool = ParallelSourceScans(lambda: StreamingSource(clients, started, produced), [(1, "t"), (2, "t")], 2,
                               deadline_check=deadline, queue_size=1)
    began = time.monotonic()
    with pytest.raises(RuntimeError, match="test_deadline"):
        with pool:
            scan = pool.open_scan(1, "t")
            expired.set()
            next(scan.rows)
    assert time.monotonic() - began < 3
    assert all(s.closed for s in clients) and all(not t.is_alive() for t in pool._threads)


def test_shared_source_context_is_rejected_and_cannot_hang():
    clients, started, produced = [], [], []
    source = StreamingSource(clients, started, produced)
    pool = ParallelSourceScans(lambda: source, [(1, "t"), (2, "t")], 2,
                               deadline_check=lambda: None, queue_size=1)
    with pytest.raises(ParallelProjectionError, match="client_reused"):
        with pool:
            pool.open_scan(1, "t")
    assert source.closed and all(not t.is_alive() for t in pool._threads)


def test_worker_start_failure_propagates_without_waiting_for_a_scan_message():
    def factory():
        raise SourceProjectionError("synthetic_start_failure", "Client creation failed")
    pool = ParallelSourceScans(factory, [(1, "t"), (2, "t")], 2, deadline_check=lambda: None)
    with pytest.raises(SourceProjectionError) as failure:
        with pool:
            pool.open_scan(1, "t")
    assert failure.value.code == "synthetic_start_failure"
    assert all(not t.is_alive() for t in pool._threads)


def test_pair_order_cannot_cross_reader_queues():
    clients, started, produced = [], [], []
    pool = ParallelSourceScans(lambda: StreamingSource(clients, started, produced), [(1, "a"), (2, "b")], 2,
                               deadline_check=lambda: None, queue_size=1)
    with pytest.raises(ParallelProjectionError, match="pair_mismatch"):
        with pool:
            pool.open_scan(2, "a")
    assert all(s.closed for s in clients)


def test_main_metadata_source_cannot_be_adopted_by_a_worker():
    clients, started, produced = [], [], []
    main_source = StreamingSource(clients, started, produced)
    with main_source:
        pool = ParallelSourceScans(lambda: main_source, [(1, "t"), (2, "t")], 2,
                                   deadline_check=lambda: None, forbidden_sources=(main_source,))
        with pytest.raises(ParallelProjectionError, match="client_reused"):
            with pool:
                pool.open_scan(1, "t")
        assert not main_source.closed and not started
    assert main_source.closed


def test_metrics_include_every_closed_worker_and_main_metadata_counters():
    from types import SimpleNamespace
    from policyweaver.parallel_projection import CombinedSourceMetrics
    clients = []
    class FiniteSource:
        def __init__(self):
            self.metrics = {"requests": 10, "retries": 1, "completed_scans": 0, "completed_rows": 0}
            clients.append(self)
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def open_scan(self, reader, table):
            self.metrics["requests"] += 1
            def rows():
                yield {"id": reader}
                self.metrics["completed_scans"] += 1
                self.metrics["completed_rows"] += 1
            return SourceScan(True, rows())
    main = SimpleNamespace(metrics={"requests": 7, "retries": 2, "completed_scans": 0, "completed_rows": 0})
    with ParallelSourceScans(FiniteSource, [(n, "t") for n in range(20)], 2,
                             deadline_check=lambda: None) as pool:
        for n in range(20):
            assert list(pool.open_scan(n, "t").rows) == [{"id": n}]
    assert len(clients) == 2
    assert CombinedSourceMetrics(main, pool).metrics == {
        "requests": 47, "retries": 4, "completed_scans": 20, "completed_rows": 20}


def test_actual_source_clients_keep_interleaved_impersonation_requests_bound_to_their_reader():
    import re
    from threading import Barrier
    from types import SimpleNamespace
    import httpx
    from policyweaver.source_projection import SourceAttribute, SourceProjectionClient, SourceReader, SourceTable
    readers = [SourceReader(uid(11), uid(21)), SourceReader(uid(12), uid(22))]
    by_dv = {r.dataverse_id: r for r in readers}
    by_entra = {r.entra_id: r for r in readers}
    table = SourceTable("account", "accounts", "accountid", ("accountid", "name"),
                        (SourceAttribute("accountid", "accountid", "Uniqueidentifier", False),
                         SourceAttribute("name", "name", "String", False)), uid(30))
    clients, calls = [], []
    overlap = Barrier(2)
    def binding(reader):
        return {"systemuserid": reader.dataverse_id, "azureactivedirectoryobjectid": reader.entra_id,
                "isdisabled": False, "applicationid": None, "accessmode": 0}
    def endpoint(request):
        calls.append((request.url.path, request.headers.get("CallerObjectId")))
        if request.url.path.endswith("WhoAmI"):
            return httpx.Response(200, json={"OrganizationId": uid(2), "UserId": uid(3)})
        if "RetrieveUserPrivilegeByPrivilegeId" in request.url.path:
            assert "CallerObjectId" not in request.headers
            return httpx.Response(200, json={"RolePrivileges": [{"PrivilegeId": uid(30), "Depth": "Global"}]})
        if "fetchXml" in request.url.params:
            reader = by_entra[request.headers["CallerObjectId"]]
            return httpx.Response(200, json={"value": [binding(reader)]})
        identity = re.search(r"/systemusers\(([^)]+)\)$", request.url.path)
        if identity:
            assert "CallerObjectId" not in request.headers
            return httpx.Response(200, json=binding(by_dv[identity[1]]))
        if request.url.path.endswith("/accounts"):
            reader = by_entra[request.headers["CallerObjectId"]]
            overlap.wait(timeout=3)
            return httpx.Response(200, json={"value": [{"accountid": reader.dataverse_id, "name": reader.entra_id}]})
        raise AssertionError("Unexpected mock source route")
    class Credential:
        def get_token(self, *_):
            return SimpleNamespace(token="test-token")
    def factory():
        source = SourceProjectionClient("https://test.crm.dynamics.com", uid(1), uid(2),
            credential=Credential(), transport=httpx.MockTransport(endpoint), max_retries=0)
        clients.append(source)
        return source
    with ParallelSourceScans(factory, [(r, table) for r in readers], 2, deadline_check=lambda: None) as pool:
        for reader in readers:
            assert list(pool.open_scan(reader, table).rows) == [{"accountid": reader.dataverse_id,
                                                               "name": reader.entra_id}]
    assert len(clients) == 2 and all(c._client.is_closed for c in clients)
    assert pool.metrics["completed_scans"] == 2 and pool.metrics["completed_rows"] == 2
    assert {caller for path, caller in calls if path.endswith("/accounts")} == set(by_entra)
