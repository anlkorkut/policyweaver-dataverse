"""Bounded reader/table producers with one ordered materialization consumer.

Every producer owns a separate source client and uses its ordinary open_scan.
This module changes scheduling only; it cannot supply identities or privileges.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread
from typing import Any, Callable, Iterable

from .source_projection import SourceScan


class ParallelProjectionError(RuntimeError):
    @property
    def code(self):
        return str(self).split(":", 1)[0]


class _Cancelled(Exception):
    pass


def sum_metrics(*values):
    """Add counters only; no reader labels, rows or remote responses."""
    names = {name for value in values for name in value}
    return {name: sum(value.get(name, 0) for value in values) for name in names}


class CombinedSourceMetrics:
    def __init__(self, *sources):
        self.sources = sources

    @property
    def metrics(self):
        return sum_metrics(*(source.metrics for source in self.sources))


@dataclass
class _Task:
    reader: Any
    table: Any
    messages: Queue
    completed: bool = False


class ParallelSourceScans:
    """At most worker_count active pairs, each with a bounded message queue.

    The caller must request pairs in the supplied order and exhaust every scan.
    Only the caller consumes rows or writes storage/journals. Worker failures
    invalidate all pairs, including completed ones. Exit cancels and joins all
    producers before returning, so no producer can outlive preparation.
    """
    def __init__(self, source_factory: Callable, pairs: Iterable, worker_count: int, *,
                 deadline_check: Callable[[], None], queue_size: int = 32, forbidden_sources=()):
        if type(worker_count) is not int or not 2 <= worker_count <= 4:
            raise ValueError("Parallel projection requires two to four workers")
        if type(queue_size) is not int or not 1 <= queue_size <= 128:
            raise ValueError("Row queue size must be one to 128")
        self.source_factory, self.pairs = source_factory, iter(pairs)
        self.worker_count, self.queue_size = worker_count, queue_size
        self.deadline_check = deadline_check
        self._jobs = Queue(maxsize=worker_count)
        self._active = deque()
        self._stop = Event()
        self._lock = Lock()
        self._threads = []
        self._failure = None
        self._worker_metrics = {}
        # The metadata client is also forbidden: it remains owned by the main
        # thread even when it happens to be idle during producer execution.
        self._source_ids = {id(source) for source in forbidden_sources}
        self._opened = None
        self._exhausted = False
        self._entered = False

    @property
    def metrics(self):
        with self._lock:
            return sum_metrics(*self._worker_metrics.values())

    def _record_failure(self, error):
        if not isinstance(error, Exception):
            error = ParallelProjectionError("parallel_worker_terminated")
        with self._lock:
            if self._failure is None:
                self._failure = error
        self._stop.set()

    def _check(self):
        with self._lock:
            failure = self._failure
        if failure is not None:
            raise failure
        self.deadline_check()
        if self._stop.is_set():
            raise ParallelProjectionError("parallel_source_cancelled")

    def _worker_check(self):
        if self._stop.is_set():
            raise _Cancelled()
        self.deadline_check()

    def _put(self, task, kind, value=None):
        while True:
            self._worker_check()
            try:
                task.messages.put((kind, value), timeout=0.05)
                return
            except Full:
                pass

    def _worker(self, number):
        source = None
        try:
            # A factory returning the same instance to multiple workers is a
            # programming error. Refuse it instead of sharing an HTTP context.
            candidate = self.source_factory()
            with self._lock:
                if id(candidate) in self._source_ids:
                    raise ParallelProjectionError("parallel_source_client_reused")
                self._source_ids.add(id(candidate))
            with candidate as source:
                while not self._stop.is_set():
                    try:
                        task = self._jobs.get(timeout=0.05)
                    except Empty:
                        continue
                    self._worker_check()
                    scan = source.open_scan(task.reader, task.table)
                    if type(scan.has_read) is not bool:
                        raise ParallelProjectionError("parallel_scan_gate_invalid")
                    self._put(task, "gate", scan.has_read)
                    rows = iter(scan.rows)
                    try:
                        for row in rows:
                            self._put(task, "row", row)
                        self._put(task, "done")
                    finally:
                        close = getattr(rows, "close", None)
                        if close is not None:
                            close()
                    with self._lock:
                        self._worker_metrics[number] = dict(source.metrics)
        except _Cancelled:
            pass
        except BaseException as exc:
            self._record_failure(exc)
        finally:
            if source is not None:
                with self._lock:
                    self._worker_metrics[number] = dict(source.metrics)

    def _schedule_one(self):
        if self._exhausted:
            return
        self._check()
        try:
            reader, table = next(self.pairs)
        except StopIteration:
            self._exhausted = True
            return
        task = _Task(reader, table, Queue(maxsize=self.queue_size))
        self._active.append(task)
        self._jobs.put_nowait(task)

    def __enter__(self):
        if self._entered:
            raise ParallelProjectionError("parallel_source_pool_reused")
        self._entered = True
        try:
            # Schedule before threads start. There can never be more than this
            # bounded initial window; each consumed pair admits only one more.
            for _ in range(self.worker_count):
                self._schedule_one()
            for number in range(self.worker_count):
                thread = Thread(target=self._worker, args=(number,), name=f"pw-source-{number}", daemon=False)
                self._threads.append(thread)
                thread.start()
            return self
        except BaseException:
            self._stop.set()
            self._join()
            raise

    def _message(self, task):
        while True:
            self._check()
            try:
                return task.messages.get(timeout=0.05)
            except Empty:
                pass

    def open_scan(self, reader, table):
        self._check()
        if self._opened is not None or not self._active:
            raise ParallelProjectionError("parallel_scan_not_exhausted_or_unplanned")
        task = self._active[0]
        if task.reader != reader or task.table != table:
            raise ParallelProjectionError("parallel_scan_pair_mismatch")
        self._opened = task
        kind, has_read = self._message(task)
        if kind != "gate" or type(has_read) is not bool:
            raise ParallelProjectionError("parallel_scan_gate_invalid")
        return SourceScan(has_read, self._rows(task))

    def _rows(self, task):
        while True:
            kind, value = self._message(task)
            if kind == "row":
                yield value
            elif kind == "done":
                task.completed = True
                if self._active.popleft() is not task:
                    raise ParallelProjectionError("parallel_scan_order_invalid")
                self._opened = None
                self._schedule_one()
                return
            else:
                raise ParallelProjectionError("parallel_scan_message_invalid")

    def _join(self):
        for thread in self._threads:
            thread.join()

    def __exit__(self, exc_type, exc, traceback):
        incomplete = self._active or self._opened is not None or not self._exhausted
        self._stop.set()
        self._join()
        if exc_type is None:
            with self._lock:
                failure = self._failure
            if failure is not None:
                raise failure
            if incomplete:
                raise ParallelProjectionError("parallel_scan_not_exhausted")
        return False
