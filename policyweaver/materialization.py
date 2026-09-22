"""Typed, immutable local generations and append-only OneLake publication."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from uuid import UUID

from .storage import _atomic_write


class MaterializationError(RuntimeError):
    @property
    def code(self):
        return str(self).split(":", 1)[0]


def arrow_type(attribute_type):
    import pyarrow as pa
    if attribute_type in {"String", "Memo", "Uniqueidentifier", "Lookup", "Customer", "Owner", "EntityName", "MultiSelectPicklist"}:
        return pa.string()
    if attribute_type in {"Integer", "Picklist", "State", "Status", "BigInt"}:
        return pa.int64()
    if attribute_type == "Boolean":
        return pa.bool_()
    if attribute_type in {"Decimal", "Money"}:
        return pa.decimal128(38, 10)
    if attribute_type == "Double":
        return pa.float64()
    if attribute_type == "DateTime":
        return pa.timestamp("us", tz="UTC")
    raise MaterializationError("unsupported_source_type:" + str(attribute_type))


def schema_for(table):
    import pyarrow as pa
    attrs = {a.property_name: a for a in table.attributes}
    fields = []
    for column in table.columns:
        if column.startswith("__pw_") or column not in attrs:
            raise MaterializationError("untyped_or_reserved_source_column")
        fields.append(pa.field(column, arrow_type(attrs[column].attribute_type)))
    return pa.schema([*fields, pa.field("__pw_reader", pa.string(), nullable=False),
                      pa.field("__pw_generation", pa.int64(), nullable=False)])


def cast_row(row, schema):
    import pyarrow as pa
    result = {}
    for field in schema:
        value = row.get(field.name)
        if value is not None:
            if pa.types.is_decimal(field.type):
                value = Decimal(str(value))
            elif pa.types.is_timestamp(field.type):
                if isinstance(value, str):
                    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if value.tzinfo is None:
                    value = value.replace(tzinfo=timezone.utc)
            elif pa.types.is_string(field.type) and not isinstance(value, str):
                raise MaterializationError("non_scalar_string_value")
        result[field.name] = value
    return result


def tree_hashes(directory: Path):
    result = {}
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.name == "manifest.json":
            continue
        if path.is_symlink():
            raise MaterializationError("generation_contains_symlink")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        result[path.relative_to(directory).as_posix()] = digest.hexdigest()
    return result


class GenerationWriter:
    def __init__(self, directory: Path, generation: int, tables, batch_size=2000):
        import pyarrow as pa
        from deltalake import write_deltalake
        self.directory, self.generation = Path(directory), generation
        self.tables = {t.name: t for t in tables}
        self.schemas = {t.name: schema_for(t) for t in tables}
        self.batch_size, self.counts = batch_size, {}
        self.buffers = {t.name: [] for t in tables}
        if self.directory.exists():
            raise MaterializationError("generation_directory_already_exists")
        self.directory.mkdir(parents=True)
        for table, schema in self.schemas.items():
            write_deltalake(str(self.directory / table), pa.Table.from_pylist([], schema=schema), mode="error")

    def add_reader(self, table_name, entra_id, rows, *, max_rows=1_000_000, deadline_check=lambda: None):
        entra_id = str(UUID(entra_id))
        key = table_name + ":" + entra_id
        if key in self.counts:
            raise MaterializationError("reader_table_written_twice")
        table, schema = self.tables[table_name], self.schemas[table_name]
        batch, count, ids = self.buffers[table_name], 0, set()
        for source in rows:
            deadline_check()
            source_id = source.get(table.primary_key)
            if not source_id or source_id in ids:
                raise MaterializationError("missing_or_duplicate_record_key")
            ids.add(source_id)
            count += 1
            if count > max_rows:
                raise MaterializationError("reader_table_row_budget_exceeded")
            batch.append(cast_row({**source, "__pw_reader": entra_id, "__pw_generation": self.generation}, schema))
            if len(batch) >= self.batch_size:
                self._flush(table_name)
        self.counts[key] = count
        return count

    def _flush(self, table_name):
        import pyarrow as pa
        from deltalake import write_deltalake
        batch = self.buffers[table_name]
        if batch:
            write_deltalake(str(self.directory / table_name), pa.Table.from_pylist(batch, schema=self.schemas[table_name]), mode="append")
            batch.clear()

    def finish(self, metadata):
        for table in self.tables:
            self._flush(table)
        manifest = {**metadata, "generation": self.generation, "reader_table_counts": self.counts,
                    "total_rows": sum(self.counts.values()), "files": tree_hashes(self.directory)}
        _atomic_write(self.directory / "manifest.json", json.dumps(manifest, indent=2).encode())
        return manifest


def verify_generation(directory: Path):
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest["files"] != tree_hashes(directory):
        raise MaterializationError("generation_content_hash_mismatch")
    return manifest


def dataset_fingerprint(dataset, predicate):
    """Order-independent, bounded-memory fingerprint of typed row contents.

    Delta may reorder files during a write, so file hashes and row counts alone
    cannot verify a serving copy. Accumulate SHA-512 row hashes modulo 2**512,
    binding column names/types and the row count as well. This is a transfer
    integrity check, not a signature or evidence of consumer enforcement.
    """
    def value_json(value):
        if isinstance(value, datetime):
            return {"datetime": value.astimezone(timezone.utc).isoformat(timespec="microseconds")}
        if isinstance(value, Decimal):
            return {"decimal": str(value)}
        raise MaterializationError("unsupported_fingerprint_value")

    total, count, modulus = 0, 0, 1 << 512
    for batch in dataset.scanner(filter=predicate, batch_size=10000).to_batches():
        for row in batch.to_pylist():
            encoded = json.dumps(row, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False, default=value_json).encode()
            total = (total + int.from_bytes(hashlib.sha512(encoded).digest(), "big")) % modulus
            count += 1
    schema = [(f.name, str(f.type)) for f in dataset.schema]
    binding = json.dumps({"schema": schema, "rows": count, "sum": format(total, "0128x")},
                         sort_keys=True, separators=(",", ":")).encode()
    return count, hashlib.sha256(binding).hexdigest()


class DeltaDestination:
    """Single writer, atomic Delta commits; OneLake policies are activated separately.

    Always append a new generation. Retrying a partially uploaded generation is
    forbidden; create a fresh generation, leaving the failed one inaccessible.
    No automatic VACUUM or deletion is performed.
    """
    def __init__(self, workspace_id=None, credential=None, local_root=None):
        self.workspace_id = str(UUID(workspace_id)) if workspace_id else None
        self.credential = credential
        self.local_root = Path(local_root) if local_root else None

    def uri(self, item_id, path):
        if not path.startswith("/Tables/") or ".." in path or "\\" in path:
            raise MaterializationError("invalid_destination_path")
        item_id = str(UUID(item_id))
        if self.local_root:
            return str(self.local_root / item_id / path.lstrip("/"))
        return f"abfss://{self.workspace_id}@onelake.dfs.fabric.microsoft.com/{item_id}{path}"

    def options(self):
        if self.local_root:
            return None
        if not self.credential:
            raise MaterializationError("missing_destination_credential")
        token = self.credential.get_token("https://storage.azure.com/.default")
        return {"bearer_token": token.token, "use_fabric_endpoint": "true"}

    def append(self, source_directory, source_table, item_id, path, reader_ids, generation):
        import pyarrow as pa
        import pyarrow.dataset as ds
        from deltalake import DeltaTable, write_deltalake
        source = DeltaTable(str(Path(source_directory) / source_table))
        dataset = source.to_pyarrow_dataset()
        predicate = ds.field("__pw_reader").isin(list(reader_ids)) & (ds.field("__pw_generation") == generation)
        expected_count, expected_hash = dataset_fingerprint(dataset, predicate)
        scanner = dataset.scanner(filter=predicate, batch_size=10000)
        # The writer consumes batches under one atomic transaction for this table.
        reader = pa.RecordBatchReader.from_batches(dataset.schema, scanner.to_batches())
        destination = self.uri(item_id, path)
        options = self.options()
        write_deltalake(destination, reader, mode="append", storage_options=options)
        written = DeltaTable(destination, storage_options=self.options())
        # Read back complete typed contents through the privileged publisher.
        actual, content_hash = dataset_fingerprint(written.to_pyarrow_dataset(),
                                                   ds.field("__pw_generation") == generation)
        if actual != expected_count or content_hash != expected_hash:
            raise MaterializationError("destination_content_verification_failed")
        return {"path": path, "delta_version": written.version(), "generation": generation,
                "rows": actual, "content_sha256": content_hash}
