"""Small thread-safe TTL cache for external intelligence lookups."""

from __future__ import annotations

import copy
import threading
import time
from collections import OrderedDict
from typing import Any


class TTLCache:
    """In-memory TTL cache that returns copies to prevent caller mutation leaks."""

    def __init__(self, ttl_seconds: int, maxsize: int = 1024):
        self.ttl_seconds = max(0, ttl_seconds)
        self.maxsize = max(1, maxsize)
        self._lock = threading.Lock()
        self._items: OrderedDict[str, tuple[float, Any]] = OrderedDict()

    def get(self, key: str) -> tuple[bool, Any]:
        if self.ttl_seconds <= 0:
            return False, None

        now = time.monotonic()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return False, None

            expires_at, value = item
            if expires_at <= now:
                self._items.pop(key, None)
                return False, None

            self._items.move_to_end(key)
            return True, copy.deepcopy(value)

    def set(self, key: str, value: Any) -> None:
        if self.ttl_seconds <= 0:
            return

        with self._lock:
            self._items[key] = (
                time.monotonic() + self.ttl_seconds,
                copy.deepcopy(value),
            )
            self._items.move_to_end(key)
            while len(self._items) > self.maxsize:
                self._items.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
