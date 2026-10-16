"""Disposable historical read acceleration; never authority or an integrity check."""

import json
from collections import OrderedDict
from threading import RLock
from time import monotonic
from weakref import WeakKeyDictionary

from dtvp.storage import canonical, digest

# Bump whenever historical comparison/coverage/score synthesis semantics change.
ALGORITHM_VERSION = "dtvp.historical-comparison/2"
MAX_BYTES = 32 * 1024 * 1024
MAX_ENTRY_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 16
TTL_SECONDS = 300


class ComparisonCache:
    def __init__(
        self,
        *,
        max_bytes=MAX_BYTES,
        max_entry_bytes=MAX_ENTRY_BYTES,
        max_entries=MAX_ENTRIES,
        ttl=TTL_SECONDS,
        clock=monotonic,
    ):
        self.max_bytes, self.max_entry_bytes = max_bytes, max_entry_bytes
        self.max_entries, self.ttl, self.clock = max_entries, ttl, clock
        self._entries = OrderedDict()
        self._bytes = 0
        self._lock = RLock()

    def _expire(self, now):
        for key, (expires, raw) in list(self._entries.items()):
            if expires <= now:
                del self._entries[key]
                self._bytes -= len(raw)

    def get(self, key):
        with self._lock:
            self._expire(self.clock())
            entry = self._entries.get(key)
            if entry is None:
                return None
            self._entries.move_to_end(key)
            raw = entry[1]
        # Never return shared mutable dictionaries or lists to a caller.
        return json.loads(raw)

    def put(self, key, value):
        raw = canonical(value)
        if len(raw) > min(self.max_entry_bytes, self.max_bytes) or self.max_entries < 1:
            return
        with self._lock:
            now = self.clock()
            self._expire(now)
            prior = self._entries.pop(key, None)
            if prior:
                self._bytes -= len(prior[1])
            while self._entries and (
                len(self._entries) >= self.max_entries or self._bytes + len(raw) > self.max_bytes
            ):
                _, (_, removed) = self._entries.popitem(last=False)
                self._bytes -= len(removed)
            self._entries[key] = (now + self.ttl, raw)
            self._bytes += len(raw)


_caches = WeakKeyDictionary()
_lock = RLock()


def cache_for(journal):
    """Instances, including two stores containing identical hashes, never share data."""
    with _lock:
        cache = _caches.get(journal)
        if cache is None:
            cache = ComparisonCache()
            _caches[journal] = cache
        return cache


def cache_key(project_id, before, after):
    return digest(canonical([ALGORITHM_VERSION, "historical", project_id, before, after]))
