"""Independent release-review regressions for historical authorization state."""

import json

import pytest

from policyweaver.config import save_config
from policyweaver.journal import JournalError
from policyweaver.runtime import AdapterRuntime, RuntimeErrorSafe

from test_adapter_runtime import boundaries, harness, uid


def test_remapping_a_serving_item_cannot_abandon_old_reader_permissions(tmp_path):
    """A new shard mapping must withdraw, or refuse to forget, the old item."""
    runtime, source, destination, fabric = harness(tmp_path, table_shards=False)
    original = runtime.prepare()
    runtime.publish(original["generation"], boundaries(runtime, original["generation"], tmp_path))
    old_item = runtime.config.serving_items["a000_t000"]
    assert old_item in fabric.active

    replacement = runtime.config.model_copy(update={"serving_items": {"a000_t000": uid(777)}})
    save_config(replacement, runtime.config_path)
    try:
        changed = AdapterRuntime(
            runtime.config_path, credential=object(), source_factory=lambda *_, **__: source,
            fabric_factory=fabric.factory, destination=destination,
        )
        new = changed.prepare()
        changed.publish(new["generation"], boundaries(changed, new["generation"], tmp_path))
    except (RuntimeErrorSafe, JournalError):
        # Refusing a remap until explicit old-item withdrawal is also safe.
        assert not any(call[0] == "publish" and call[1] == uid(777) for call in fabric.calls)
        return
    assert old_item not in fabric.active, "Old destination retained live permissions after its mapping was superseded."


def test_withdrawal_does_not_erase_monotonic_generation_activation(tmp_path):
    """A prepared pre-revocation generation must never reactivate afterward."""
    runtime, source, destination, fabric = harness(tmp_path, table_shards=False)
    earlier = runtime.prepare()
    for pair in source.rows:
        source.rows[pair] = []  # The authoritative source has since revoked rows.
    later = runtime.prepare()
    runtime.publish(later["generation"], boundaries(runtime, later["generation"], tmp_path))
    runtime.withdraw()
    assert not fabric.active

    with pytest.raises((RuntimeErrorSafe, JournalError)):
        # Existing remote-role monotonic checks cannot help after roles are gone.
        boundary = boundaries(runtime, earlier["generation"], tmp_path)
        runtime.publish(earlier["generation"], boundary)
    assert not fabric.active


@pytest.mark.parametrize("field,value", [
    ("tenant_id", uid(88)), ("workspace_id", uid(89)),
    ("organization_id", uid(90)), ("deployment_name", "pw_different"),
])
def test_journal_scope_cannot_be_rebound_to_other_deployment(tmp_path, field, value):
    runtime, source, destination, fabric = harness(tmp_path, table_shards=False)
    save_config(runtime.config.model_copy(update={field: value}), runtime.config_path)
    with pytest.raises(JournalError, match="scope_mismatch"):
        AdapterRuntime(runtime.config_path, credential=object(), source_factory=lambda *_, **__: source,
                       fabric_factory=fabric.factory, destination=destination)
    assert not fabric.calls


def test_verified_withdrawal_allows_remap_and_retains_historical_inventory(tmp_path):
    runtime, source, destination, fabric = harness(tmp_path, table_shards=False)
    original = runtime.prepare()
    runtime.publish(original["generation"], boundaries(runtime, original["generation"], tmp_path))
    old_item = runtime.config.serving_items["a000_t000"]
    runtime.withdraw()
    replacement = runtime.config.model_copy(update={"serving_items": {"a000_t000": uid(777)}})
    save_config(replacement, runtime.config_path)
    changed = AdapterRuntime(runtime.config_path, credential=object(), source_factory=lambda *_, **__: source,
                             fabric_factory=fabric.factory, destination=destination)
    new = changed.prepare()
    changed.publish(new["generation"], boundaries(changed, new["generation"], tmp_path))
    assert old_item not in fabric.active
    assert set(changed._managed_item_mapping().values()) == {old_item, uid(777)}
    watch = changed.watchdog()
    assert {v["item_id"] for v in watch["items"].values()} == {old_item, uid(777)}


def test_failed_withdrawal_does_not_unlock_item_remap(tmp_path):
    runtime, source, destination, fabric = harness(tmp_path, table_shards=False)
    run = runtime.prepare()
    runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
    fabric.fail_withdraw_items.add(uid(100))
    with pytest.raises(RuntimeErrorSafe, match="withdrawal_failed"):
        runtime.withdraw()
    replacement = runtime.config.model_copy(update={"serving_items": {"a000_t000": uid(777)}})
    save_config(replacement, runtime.config_path)
    with pytest.raises(JournalError, match="requires_verified_withdrawal"):
        AdapterRuntime(runtime.config_path, credential=object(), source_factory=lambda *_, **__: source,
                       fabric_factory=fabric.factory, destination=destination)


def test_explicit_withdrawal_invalidates_prepared_but_never_activated_rows(tmp_path):
    runtime, _, _, fabric = harness(tmp_path, table_shards=False)
    run = runtime.prepare()
    runtime.withdraw()
    with pytest.raises(JournalError, match="activation_high_water"):
        runtime.prepared(run["generation"])
    assert not fabric.active
    fresh = runtime.prepare()
    assert fresh["generation"] > runtime.journal.activation_high_water()


def _make_legacy_journal(runtime, generation, *, keep_scope_summary=False):
    with runtime.journal.connect() as db:
        db.execute("DELETE FROM deployment_scope")
        db.execute("DELETE FROM managed_items")
        db.execute("DELETE FROM managed_tables")
        if not keep_scope_summary:
            summary = runtime.journal.get(generation)["summary"]
            for key in ("deployment_scope", "managed_items", "managed_tables"):
                summary.pop(key, None)
            db.execute("UPDATE runs SET summary=? WHERE generation=?", (json.dumps(summary), generation))


def test_legacy_publication_migrates_when_original_config_fingerprint_matches(tmp_path):
    runtime, source, destination, fabric = harness(tmp_path, table_shards=False)
    run = runtime.prepare()
    runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
    _make_legacy_journal(runtime, run["generation"])
    restored = AdapterRuntime(runtime.config_path, credential=object(), source_factory=lambda *_, **__: source,
                              fabric_factory=fabric.factory, destination=destination)
    assert restored.journal.activation_high_water() == run["generation"]
    assert {r["item_id"] for r in restored.journal.managed_items()} == {uid(100)}
    assert {t["name"] for t in restored.journal.managed_tables()} == {"account", "contact"}


def test_legacy_unknown_mapping_cannot_be_guessed_from_changed_configuration(tmp_path):
    runtime, source, destination, fabric = harness(tmp_path, table_shards=False)
    run = runtime.prepare()
    runtime.publish(run["generation"], boundaries(runtime, run["generation"], tmp_path))
    _make_legacy_journal(runtime, run["generation"])
    save_config(runtime.config.model_copy(update={"serving_items": {"a000_t000": uid(777)}}), runtime.config_path)
    with pytest.raises(JournalError, match="legacy_item_scope_unverified"):
        AdapterRuntime(runtime.config_path, credential=object(), source_factory=lambda *_, **__: source,
                       fabric_factory=fabric.factory, destination=destination)
    assert fabric.active == {uid(100): run["generation"]}
