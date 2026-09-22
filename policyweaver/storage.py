"""Atomic, versioned local inventory storage; never store tokens or credentials."""
import hashlib
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


def data_directory() -> Path:
    override = os.environ.get("POLICYWEAVER_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    base = os.environ.get("LOCALAPPDATA")
    return (Path(base) / "PolicyWeaver" / "inventory") if base else (Path.home() / ".local/share/policyweaver/inventory")


def _replace_with_sharing_retry(temporary: str, path: Path):
    """Retain atomic replacement through brief Windows file-sharing contention.

    Receipt writes can race with scanners opening the old file without delete
    sharing. Retry only Windows access/sharing codes, for at most 350 ms of added
    wait. A permanent denial still raises; never delete or rewrite the old file.
    """
    delays = (0.05, 0.10, 0.20)
    for attempt in range(len(delays) + 1):
        try:
            os.replace(temporary, path)
            return
        except OSError as error:
            if getattr(error, "winerror", None) not in (5, 32) or attempt == len(delays):
                raise
            time.sleep(delays[attempt])


def _atomic_write(path: Path, content: bytes):
    descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        _replace_with_sharing_retry(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_inventory(snapshot: dict, directory: Path | None = None) -> Path:
    directory = directory or data_directory()
    directory.mkdir(parents=True, exist_ok=True)
    content = json.dumps(snapshot, ensure_ascii=False, indent=2).encode("utf-8")
    digest = hashlib.sha256(content).hexdigest()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = directory / f"inventory-{stamp}-{digest[:12]}.json"
    _atomic_write(path, content)
    _atomic_write(directory / "latest.json", json.dumps({"file": path.name, "sha256": digest}).encode())
    return path


def load_inventory(directory: Path | None = None) -> dict | None:
    directory = directory or data_directory()
    pointer = directory / "latest.json"
    if not pointer.exists():
        return None
    manifest = json.loads(pointer.read_text(encoding="utf-8"))
    path = (directory / manifest["file"]).resolve()
    if path.parent != directory.resolve():
        raise ValueError("Inventory pointer escapes the configured directory")
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != manifest["sha256"]:
        raise ValueError("Inventory hash does not match local manifest")
    return json.loads(content)
