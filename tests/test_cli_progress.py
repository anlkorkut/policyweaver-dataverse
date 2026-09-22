"""Live operator telemetry is opt-in, useful during work, and aggregate-only."""
import json
from datetime import datetime

import pytest

from policyweaver import adapter_cli
from policyweaver.runtime import AdapterRuntime
from test_adapter_runtime import boundaries, harness


def attach_cli_runtime(monkeypatch, runtime):
    def factory(*_, **kwargs):
        runtime._progress_callback = kwargs.get("progress")
        return runtime
    monkeypatch.setattr("policyweaver.runtime.AdapterRuntime", factory)


@pytest.mark.parametrize("placement", ["disabled", "before", "after"])
def test_cli_progress_preserves_stdout_and_never_logs_source_values_or_identities(
        tmp_path, monkeypatch, capsys, placement):
    runtime, source, _, _ = harness(tmp_path)
    source.metrics.update(requests=12, retries=2, token="TOKEN_SENTINEL")
    attach_cli_runtime(monkeypatch, runtime)
    argv = ["--config", str(runtime.config_path)]
    if placement == "before": argv.append("--progress")
    argv.append("prepare")
    if placement == "after": argv.append("--progress")
    assert adapter_cli.main(argv) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["status"] == "prepared"
    if placement == "disabled":
        assert captured.err == ""
        return
    events = [json.loads(line) for line in captured.err.splitlines()]
    completed = [e for e in events if e["event"] == "projection_completed"]
    assert [(e["table"], e["reader_index"], e["completed"]) for e in completed] == [
        ("account", 1, 1), ("account", 2, 2), ("contact", 1, 3), ("contact", 2, 4)]
    assert all(e["total"] == 4 and e["reader_count"] == 2 and e["rows"] == 1 for e in completed)
    assert events[0]["event"] == "prepare_started"
    assert events[-1]["event"] == "prepare_completed"
    assert events[-1]["total_rows"] == 4
    assert events[-1]["source_requests"] == 12 and events[-1]["source_retries"] == 2
    for event in events:
        assert datetime.fromisoformat(event["timestamp_utc"]).utcoffset().total_seconds() == 0
        assert event["elapsed_seconds"] >= 0
    for secret in ["SOURCE_PII_SENTINEL", "FIELD_PII_SENTINEL", "TOKEN_SENTINEL",
                   *[r.entra_id for r in source.readers], *[r.dataverse_id for r in source.readers]]:
        assert secret not in captured.err


def test_progress_is_emitted_before_reader_scan_and_denied_read_still_counts(tmp_path):
    runtime, source, _, _ = harness(tmp_path)
    events = []
    runtime._progress_callback = events.append
    source.denied.add((source.readers[0].entra_id, "contact"))
    original = source.open_scan
    def scan(reader, table):
        assert events[-1]["event"] == "projection_started"
        assert events[-1]["table"] == table.name
        return original(reader, table)
    source.open_scan = scan
    run = runtime.prepare()
    completed = [e for e in events if e["event"] == "projection_completed"]
    assert len(completed) == 4 and completed[2]["rows"] == 0
    assert run["summary"]["total_rows"] == 3


def test_cli_failure_progress_is_sanitized_and_cannot_claim_preparation_completed(tmp_path, monkeypatch, capsys):
    runtime, source, _, _ = harness(tmp_path)
    source.fail_pair = source.readers[0].entra_id, "account"
    attach_cli_runtime(monkeypatch, runtime)
    assert adapter_cli.main(["--config", str(runtime.config_path), "prepare", "--progress"]) == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out)["error_code"] == "synthetic_source_failure"
    events = [json.loads(line) for line in captured.err.splitlines()]
    assert events[-1]["event"] == "prepare_failed"
    assert not any(e["event"] == "prepare_completed" for e in events)
    assert "SOURCE_PII_SENTINEL" not in captured.err


def test_progress_sink_failure_cannot_change_preparation_or_publication(tmp_path):
    previous, source, destination, fabric = harness(tmp_path)
    def failed_sink(_):
        raise OSError("BROKEN_LOG_SINK_SENTINEL")
    runtime = AdapterRuntime(previous.config_path, credential=object(), source_factory=lambda *a, **k: source,
        fabric_factory=fabric.factory, destination=destination, progress=failed_sink)
    run = runtime.prepare()
    assert run["status"] == "prepared"
    result = runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
    assert result["status"] == "published"
    assert len(fabric.active) == 2


def test_progress_has_closed_field_allowlist_and_does_not_print_arbitrary_input(tmp_path):
    runtime, source, _, _ = harness(tmp_path)
    events = []
    runtime._progress_callback = events.append
    source.metrics.update(requests="TOKEN_SENTINEL", retries=True)
    runtime._progress("projection_completed", source=source, rows=3,
        table="person@example.com", reader_id=source.readers[0].entra_id,
        token="TOKEN_SENTINEL", reader_count=True, total=-1, total_rows="SOURCE_PII_SENTINEL")
    assert set(events[0]) == {"event", "timestamp_utc", "elapsed_seconds", "rows"}
    runtime._progress("UNKNOWN_SECRET_EVENT", token="TOKEN_SENTINEL")
    assert len(events) == 1


def test_publication_events_follow_verified_upload_and_control_plane_stages(tmp_path):
    runtime, _, _, _ = harness(tmp_path)
    events = []
    runtime._progress_callback = events.append
    run = runtime.prepare()
    events.clear()
    runtime.dry_run(run["generation"])
    assert [e["event"] for e in events] == [
        "dry_run_started", "dry_run_shard_completed", "dry_run_shard_completed", "dry_run_completed"]
    events.clear()
    runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
    names = [e["event"] for e in events]
    assert names[0] == "publish_started" and names[-1] == "publish_completed"
    assert names.count("publication_boundary_verified") == 2
    assert names.count("upload_completed") == 2
    assert names.count("policy_publish_completed") == 2
    assert max(i for i, n in enumerate(names) if n == "upload_completed") < names.index("policy_publish_started")
    assert all(e["rows"] == 2 for e in events if e["event"] == "upload_completed")


def test_publication_failure_logs_quarantine_and_retains_withdrawal(tmp_path):
    runtime, _, _, fabric = harness(tmp_path)
    events = []
    runtime._progress_callback = events.append
    run = runtime.prepare()
    fabric.fail_publish_item = runtime.config.serving_items["a000_t001"]
    with pytest.raises(RuntimeError):
        runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
    assert events[-2]["event"] == "publication_quarantine_started"
    assert events[-1]["event"] == "publication_quarantine_completed"
    assert events[-1]["failed_shard_count"] == 0
    assert not fabric.active
    assert not any(e["event"] == "publish_completed" for e in events)
