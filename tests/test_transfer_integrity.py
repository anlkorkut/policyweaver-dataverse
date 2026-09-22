"""A serving receipt must verify values, including NULLs, not just row counts."""
from datetime import datetime, timezone
from decimal import Decimal

import pyarrow as pa
import pyarrow.dataset as ds
import pytest

from policyweaver.materialization import dataset_fingerprint


def data(rows):
    schema = pa.schema([pa.field("id", pa.string()), pa.field("secret", pa.string()),
                        pa.field("amount", pa.decimal128(38, 10)),
                        pa.field("observed", pa.timestamp("us", tz="UTC"))])
    return ds.dataset(pa.Table.from_pylist(rows, schema=schema))


def row(key, secret=None):
    return {"id": key, "secret": secret, "amount": Decimal("123456.1234567890"),
            "observed": datetime(2026, 9, 18, tzinfo=timezone.utc)}


def test_fingerprint_preserves_multiset_and_null_semantics():
    rows = [row("a"), row("b", "allowed")]
    original = dataset_fingerprint(data(rows), None)
    assert original == dataset_fingerprint(data(rows[::-1]), None)
    assert original != dataset_fingerprint(data([row("a", "leaked"), rows[1]]), None)
    assert original != dataset_fingerprint(data([rows[0], rows[0]]), None)
    assert original != dataset_fingerprint(data(rows + [rows[0]]), None)


def test_fingerprint_binds_schema_and_selected_rows():
    original = data([row("a"), row("b", "allowed")])
    assert dataset_fingerprint(original, ds.field("id") == "a") == dataset_fingerprint(data([row("a")]), None)
    renamed = original.to_table().rename_columns(["id", "another_secret", "amount", "observed"])
    assert dataset_fingerprint(original, None) != dataset_fingerprint(ds.dataset(renamed), None)


def test_committed_same_count_value_change_is_rejected(tmp_path, monkeypatch):
    from deltalake import DeltaTable, write_deltalake
    import deltalake
    from policyweaver.materialization import DeltaDestination, MaterializationError
    source = tmp_path / "source" / "account"
    schema = pa.schema([("accountid", pa.string()), ("secret", pa.string()),
                        ("__pw_reader", pa.string()), ("__pw_generation", pa.int64())])
    reader = "00000000-0000-0000-0000-000000000001"
    original = pa.Table.from_pylist([{"accountid": "one", "secret": None,
        "__pw_reader": reader, "__pw_generation": 1}], schema=schema)
    write_deltalake(str(source), original)
    real_write = deltalake.write_deltalake

    def corrupt(uri, batches, **kwargs):
        table = batches.read_all()
        rows = table.to_pylist()
        rows[0]["secret"] = "unauthorized_value"
        real_write(uri, pa.Table.from_pylist(rows, schema=table.schema), **kwargs)

    monkeypatch.setattr(deltalake, "write_deltalake", corrupt)
    destination = DeltaDestination(local_root=tmp_path / "destination")
    with pytest.raises(MaterializationError, match="destination_content_verification_failed"):
        destination.append(tmp_path / "source", "account", reader, "/Tables/dbo/account", [reader], 1)
