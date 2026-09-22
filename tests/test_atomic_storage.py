"""Windows sharing retries retain the original durable receipt until replacement."""
import errno
from pathlib import Path

import pytest

from policyweaver import storage


def windows_error(code):
    error = PermissionError(errno.EACCES, "synthetic Windows filesystem denial")
    error.winerror = code
    return error


@pytest.mark.parametrize("code", [5, 32])
def test_transient_windows_sharing_retry_preserves_atomic_receipt(tmp_path, monkeypatch, code):
    path = tmp_path / "receipt.json"
    path.write_bytes(b"old-complete")
    replace = storage.os.replace
    attempts, waits = [], []
    def race(temporary, target):
        attempts.append(temporary)
        assert target == path
        assert path.read_bytes() == b"old-complete"
        assert Path(temporary).read_bytes() == b"new-complete"
        if len(attempts) < 3:
            raise windows_error(code)
        replace(temporary, target)
    monkeypatch.setattr(storage.os, "replace", race)
    monkeypatch.setattr(storage.time, "sleep", waits.append)
    storage._atomic_write(path, b"new-complete")
    assert path.read_bytes() == b"new-complete"
    assert len(attempts) == 3 and len(set(attempts)) == 1
    assert waits == [0.05, 0.10]
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("code", [5, 32])
def test_persistent_windows_denial_is_capped_and_retains_old_receipt(tmp_path, monkeypatch, code):
    path = tmp_path / "receipt.json"
    path.write_bytes(b"old-complete")
    error = windows_error(code)
    attempts, waits = [], []
    def denied(temporary, target):
        attempts.append(temporary)
        assert path.read_bytes() == b"old-complete"
        raise error
    monkeypatch.setattr(storage.os, "replace", denied)
    monkeypatch.setattr(storage.time, "sleep", waits.append)
    with pytest.raises(PermissionError) as caught:
        storage._atomic_write(path, b"new-complete")
    assert caught.value is error
    assert len(attempts) == 4 and sum(waits) == pytest.approx(0.35)
    assert path.read_bytes() == b"old-complete"
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("error", [PermissionError(errno.EACCES, "ordinary permission denial"), windows_error(33),
                                  OSError(errno.ENOSPC, "disk full")])
def test_unrelated_filesystem_errors_are_not_retried(tmp_path, monkeypatch, error):
    path = tmp_path / "receipt.json"
    path.write_bytes(b"old-complete")
    attempts, waits = [], []
    def denied(temporary, target):
        attempts.append(temporary)
        raise error
    monkeypatch.setattr(storage.os, "replace", denied)
    monkeypatch.setattr(storage.time, "sleep", waits.append)
    with pytest.raises(OSError) as caught:
        storage._atomic_write(path, b"new-complete")
    assert caught.value is error and len(attempts) == 1 and not waits
    assert path.read_bytes() == b"old-complete"
    assert list(tmp_path.iterdir()) == [path]
