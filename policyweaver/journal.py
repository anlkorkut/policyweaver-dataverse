"""Durable local run journal and single-writer lock. Contains no business rows."""
from __future__ import annotations

import json
import math
import sqlite3
import time
import os
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4


class JournalError(RuntimeError):
    @property
    def code(self):
        return str(self).split(";", 1)[0]


def retention_metadata(mode, expires, publication_budget_seconds):
    """Explicit retention, separate from the unchanged finite freshness clock."""
    if mode not in {"timed", "manual"}:
        raise JournalError("invalid_retention_mode")
    if (type(expires) not in (int, float) or not math.isfinite(expires)
            or type(publication_budget_seconds) is not int or publication_budget_seconds < 0):
        raise JournalError("invalid_publication_deadline")
    return {"retention_mode": mode,
            "publication_deadline_at": expires - publication_budget_seconds,
            "automatic_withdrawal_at": expires if mode == "timed" else None}


class Journal:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "journal.sqlite3"
        with self.connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
              generation INTEGER PRIMARY KEY, started REAL NOT NULL, expires REAL NOT NULL,
              status TEXT NOT NULL, config_hash TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '{}',
              error_code TEXT, updated REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
              generation INTEGER, kind TEXT NOT NULL, details TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS process_lock (
              key INTEGER PRIMARY KEY CHECK(key=1), owner TEXT NOT NULL, expires REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS deployment_scope (
              key INTEGER PRIMARY KEY CHECK(key=1), scope TEXT NOT NULL,
              activation_high_water INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS managed_items (
              item_id TEXT PRIMARY KEY, shard_key TEXT NOT NULL,
              status TEXT NOT NULL, registered REAL NOT NULL, updated REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS managed_tables (
              name TEXT PRIMARY KEY, columns_json TEXT NOT NULL
            );
            """)

    def bind_deployment(self, scope, items, tables, config_hash):
        """Bind this protected journal to one deployment and retain old items.

        Removing/remapping an item is permitted only after verified withdrawal.
        The registry is append-only: a changed current config cannot make old
        reader permissions disappear from the controller's responsibility.
        """
        canonical = json.dumps(scope, sort_keys=True, separators=(",", ":"))
        now = time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT * FROM deployment_scope WHERE key=1").fetchone()
            if existing and existing["scope"] != canonical:
                raise JournalError("journal_deployment_scope_mismatch; use a separate state directory")
            if not existing:
                # Legacy runs did not persist destination IDs in their summary.
                # A matching config fingerprint proves the current mapping is
                # still the original one; otherwise explicit recorded scope is
                # required. Never guess old item IDs from shard names.
                old = db.execute("SELECT * FROM runs WHERE status IN "
                    "('publishing','published','quarantined','withdrawal_failed','withdrawn','superseded')").fetchall()
                recovered, recovered_tables = {}, {}
                for row in old:
                    summary = json.loads(row["summary"])
                    if row["config_hash"] == config_hash:
                        mapping = items
                        old_tables = tables
                    elif (summary.get("deployment_scope") == scope
                          and isinstance(summary.get("managed_items"), dict)
                          and isinstance(summary.get("managed_tables"), list)):
                        mapping = summary["managed_items"]
                        old_tables = summary["managed_tables"]
                    else:
                        raise JournalError("legacy_item_scope_unverified; restore original configuration or reconcile deployment history")
                    for key, item in mapping.items():
                        recovered[item] = key
                    for table in old_tables:
                        recovered_tables[table["name"]] = table["columns"]
                high_water = max((r["generation"] for r in old), default=0)
                db.execute("INSERT INTO deployment_scope VALUES (1,?,?)", (canonical, high_water))
                for item, key in recovered.items():
                    db.execute("INSERT OR IGNORE INTO managed_items VALUES (?,?,?,?,?)",
                               (item, key, "unverified", now, now))
                for name, columns in recovered_tables.items():
                    db.execute("INSERT OR IGNORE INTO managed_tables VALUES (?,?)", (name, json.dumps(list(columns))))
            previous = db.execute("SELECT * FROM managed_items").fetchall()
            for item in previous:
                if items.get(item["shard_key"]) != item["item_id"] and item["status"] != "withdrawn":
                    raise JournalError("managed_item_remap_requires_verified_withdrawal; restore the previous mapping and withdraw first")
            by_item = {row["item_id"]: row for row in previous}
            for key, item in items.items():
                if item in by_item:
                    old = by_item[item]
                    if old["shard_key"] != key and old["status"] != "withdrawn":
                        raise JournalError("managed_item_remap_requires_verified_withdrawal")
                    db.execute("UPDATE managed_items SET shard_key=?,updated=? WHERE item_id=?", (key, now, item))
                else:
                    db.execute("INSERT INTO managed_items VALUES (?,?,?,?,?)", (item, key, "unverified", now, now))
            for table in tables:
                db.execute("INSERT INTO managed_tables VALUES (?,?) ON CONFLICT(name) DO UPDATE SET columns_json=excluded.columns_json",
                           (table["name"], json.dumps(list(table["columns"]))))

    def managed_items(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM managed_items ORDER BY item_id")]

    def managed_tables(self):
        with self.connect() as db:
            return [{"name": row["name"], "columns": json.loads(row["columns_json"])}
                    for row in db.execute("SELECT * FROM managed_tables ORDER BY name")]

    def mark_item(self, item_id, status):
        if status not in {"active", "withdrawn"}:
            raise JournalError("invalid_item_status")
        with self.connect() as db:
            result = db.execute("UPDATE managed_items SET status=?,updated=? WHERE item_id=?", (status, time.time(), item_id))
            if result.rowcount != 1:
                raise JournalError("item_not_registered")

    def activation_high_water(self):
        with self.connect() as db:
            row = db.execute("SELECT activation_high_water FROM deployment_scope WHERE key=1").fetchone()
        if not row:
            raise JournalError("deployment_scope_not_bound")
        return row[0]

    def assert_publishable_generation(self, generation):
        if generation <= self.activation_high_water():
            raise JournalError("generation_at_or_below_activation_high_water; prepare a fresh generation")

    def begin_activation(self, generation, item_ids):
        """Atomically burn the generation before any possible remote activation."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            state = db.execute("SELECT activation_high_water FROM deployment_scope WHERE key=1").fetchone()
            run = db.execute("SELECT status FROM runs WHERE generation=?", (generation,)).fetchone()
            if not state or generation <= state[0] or not run or run[0] != "prepared":
                raise JournalError("generation_not_publishable")
            for item in item_ids:
                result = db.execute("UPDATE managed_items SET status='activation_pending',updated=? WHERE item_id=?", (time.time(), item))
                if result.rowcount != 1:
                    raise JournalError("item_not_registered")
            db.execute("UPDATE deployment_scope SET activation_high_water=? WHERE key=1", (generation,))
            db.execute("UPDATE runs SET status='publishing',updated=? WHERE generation=?", (time.time(), generation))
        self.event(generation, "publishing", {})

    def withdrawal_barrier(self):
        """Explicit containment invalidates every already-prepared generation."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT MAX(generation) FROM runs").fetchone()
            db.execute("UPDATE deployment_scope SET activation_high_water=MAX(activation_high_water,?) WHERE key=1", (row[0] or 0,))

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    @contextmanager
    def lock(self, lifetime=3600):
        owner, now = f"{os.getpid()}:{uuid4()}", time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM process_lock WHERE key=1").fetchone()
            if row:
                # Never steal a lock on timeout: an old writer may still be alive.
                raise JournalError("writer_lock_held; verify the previous worker has stopped before recovery")
            db.execute("INSERT INTO process_lock VALUES (1,?,?)", (owner, now + lifetime))
        try:
            yield owner
        finally:
            with self.connect() as db:
                db.execute("DELETE FROM process_lock WHERE key=1 AND owner=?", (owner,))

    def lock_info(self):
        with self.connect() as db:
            row = db.execute("SELECT * FROM process_lock WHERE key=1").fetchone()
        return dict(row) if row else None

    def recover_lock(self, expected_owner: str, *, worker_stopped: bool = False):
        if worker_stopped is not True:
            raise JournalError("recovery_requires_confirmed_stopped_worker")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT owner FROM process_lock WHERE key=1").fetchone()
            if not row or row["owner"] != expected_owner:
                raise JournalError("lock_owner_changed")
            db.execute("DELETE FROM process_lock WHERE key=1 AND owner=?", (expected_owner,))
        self.event(None, "operator_lock_recovery", {"previous_owner": expected_owner})

    def create(self, config_hash: str, lifetime: int, *, retention_mode="timed",
               publication_budget_seconds=0) -> int:
        if type(lifetime) is not int or lifetime <= 0 or publication_budget_seconds >= lifetime:
            raise JournalError("invalid_generation_lifetime")
        now = time.time()
        metadata = retention_metadata(retention_mode, now + lifetime, publication_budget_seconds)
        generation = int(now * 1_000_000)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT MAX(generation) FROM runs").fetchone()[0]
            generation = max(generation, (previous or 0) + 1)
            db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?)", (
                generation, now, now + lifetime, "preparing", config_hash, json.dumps(metadata), None, now))
        self.event(generation, "created", metadata)
        return generation

    def get(self, generation: int) -> dict:
        with self.connect() as db:
            row = db.execute("SELECT * FROM runs WHERE generation=?", (generation,)).fetchone()
        if not row:
            raise JournalError("generation_not_found")
        result = dict(row)
        result["summary"] = json.loads(result["summary"])
        return result

    def transition(self, generation, expected, status, *, summary=None, error_code=None):
        expected = (expected,) if isinstance(expected, str) else tuple(expected)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status,summary FROM runs WHERE generation=?", (generation,)).fetchone()
            if not row or row["status"] not in expected:
                raise JournalError("invalid_generation_transition")
            if summary is not None:
                previous = json.loads(row["summary"])
                for key in ("retention_mode", "publication_deadline_at", "automatic_withdrawal_at"):
                    if key in previous and (key not in summary or summary[key] != previous[key]):
                        raise JournalError("generation_retention_metadata_changed")
            db.execute("UPDATE runs SET status=?,summary=?,error_code=?,updated=? WHERE generation=?", (
                status, json.dumps(summary) if summary is not None else row["summary"], error_code, time.time(), generation))
        self.event(generation, status, {"error_code": error_code} if error_code else {})

    def event(self, generation, kind, details):
        with self.connect() as db:
            db.execute("INSERT INTO events(at,generation,kind,details) VALUES(?,?,?,?)", (
                time.time(), generation, kind, json.dumps(details)))

    def recent(self, limit=25):
        with self.connect() as db:
            ids = [r[0] for r in db.execute("SELECT generation FROM runs ORDER BY generation DESC LIMIT ?", (limit,))]
        return [self.get(g) for g in ids]

    def current(self):
        with self.connect() as db:
            row = db.execute("SELECT generation FROM runs WHERE status='published' ORDER BY generation DESC LIMIT 1").fetchone()
        return self.get(row[0]) if row else None
