"""External authority high-water marks.

Every piece of consumed authority in the reference store (grant lifecycle epochs,
fence tokens behind issued permits, consumed permits, claimed risk states) lives in
one SQLite file. Restoring that file from an older backup silently resurrects all
of it: a revoked grant is ACTIVE again, a consumed single-use permit is consumable
again, a spent risk-state version authorizes a new intent.

An `AuthorityAnchor` records, outside the database file, the highest
`(runtime_epoch, fence_counter)` ever committed per grant version. The store
compares its own row against the anchor before it issues, consumes, or changes
grant authority; a row that has moved backwards means the datastore was restored
and the store fails closed (`REGRESSED`) until an operator reconciles it
explicitly. The anchor must therefore be kept on storage that is *not* restored
together with the database (a different volume, a remote KV, the venue's own
ledger); an anchor restored alongside the database detects nothing.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Protocol


class AuthorityRegression(RuntimeError):
    """The datastore's authority state is older than the externally anchored state."""


class AuthorityAnchor(Protocol):
    def high_water(self, grant_id: str, version: int) -> tuple[int, int] | None:
        """Highest (runtime_epoch, fence_counter) recorded for the grant version."""

    def record(self, grant_id: str, version: int, epoch: int, fence: int) -> None:
        """Raise the high-water mark; never lowers it."""

    def reset(self, grant_id: str, version: int, epoch: int, fence: int) -> None:
        """Operator-only: set the mark to the given values after manual reconciliation."""


def regressed(current: tuple[int, int], mark: tuple[int, int] | None) -> bool:
    return mark is not None and current < mark


class InMemoryAuthorityAnchor:
    """Process-local anchor for tests and single-process demos."""

    def __init__(self) -> None:
        self._marks: dict[tuple[str, int], tuple[int, int]] = {}
        self._lock = threading.Lock()

    def high_water(self, grant_id: str, version: int) -> tuple[int, int] | None:
        with self._lock:
            return self._marks.get((grant_id, version))

    def record(self, grant_id: str, version: int, epoch: int, fence: int) -> None:
        with self._lock:
            key = (grant_id, version)
            self._marks[key] = max(self._marks.get(key, (0, 0)), (epoch, fence))

    def reset(self, grant_id: str, version: int, epoch: int, fence: int) -> None:
        with self._lock:
            self._marks[(grant_id, version)] = (epoch, fence)


class FileAuthorityAnchor:
    """Durable anchor in a small JSON file rewritten atomically (tmp + fsync + rename).

    Place the file on storage that is not part of the database backup set.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        if not self.path.exists():
            self._write({})

    @staticmethod
    def _key(grant_id: str, version: int) -> str:
        return f"{grant_id}\x1f{version}"

    def _read(self) -> dict[str, list[int]]:
        try:
            raw = self.path.read_text()
        except FileNotFoundError:
            return {}
        return json.loads(raw) if raw.strip() else {}

    def _write(self, marks: dict[str, list[int]]) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w") as handle:
            json.dump(marks, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)
        try:
            dir_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:  # pragma: no cover - platform-specific directory fsync support
            pass

    def high_water(self, grant_id: str, version: int) -> tuple[int, int] | None:
        with self._lock:
            mark = self._read().get(self._key(grant_id, version))
        return None if mark is None else (int(mark[0]), int(mark[1]))

    def record(self, grant_id: str, version: int, epoch: int, fence: int) -> None:
        with self._lock:
            marks = self._read()
            key = self._key(grant_id, version)
            current = marks.get(key)
            proposed = [int(epoch), int(fence)]
            if current is None or [int(current[0]), int(current[1])] < proposed:
                marks[key] = proposed
                self._write(marks)

    def reset(self, grant_id: str, version: int, epoch: int, fence: int) -> None:
        with self._lock:
            marks = self._read()
            marks[self._key(grant_id, version)] = [int(epoch), int(fence)]
            self._write(marks)
