"""Append complete JSON lines with thread/process serialization on local disks."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import threading

_WRITE_LOCK = threading.Lock()


def serialize_event(event: dict) -> str:
    """Return deterministic single-line JSON; no non-finite numbers or raw newlines."""
    return json.dumps(event, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


@contextmanager
def _process_lock(path: Path):
    descriptor = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def append_event(event: dict, destination: str | Path) -> None:
    """Append one durable event, reopening the file each time to support rotation.

    Raises OSError on a write failure. Callers must report it; the returned event
    remains available for retry using the same event_id.
    """
    payload = (serialize_event(event) + "\n").encode("utf-8")
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _WRITE_LOCK, _process_lock(path):
        descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o640)
        with os.fdopen(descriptor, "ab") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
