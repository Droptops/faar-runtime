"""External authority high-water marks.

Every piece of consumed authority in the reference store (grant lifecycle epochs,
fence tokens behind issued permits, consumed permits, claimed risk states) lives in
one SQLite file. Restoring that file from an older backup silently resurrects all
of it: a revoked grant is ACTIVE again, a consumed single-use permit is consumable
again, a spent risk-state version authorizes a new intent.

An `AuthorityAnchor` records, outside the database file, the highest
`(runtime_epoch, fence_counter)` ever committed per grant version. The fence
counter advances on every permit issuance *and* every permit consumption, so a
snapshot taken between the two is detected as well. The store compares its own
row against the anchor before it issues, consumes, or changes grant authority; a
row that has moved backwards means the datastore was restored and the store fails
closed (`REGRESSED`) until an operator reconciles it explicitly. The anchor must
therefore be kept on storage that is *not* restored together with the database
(a different volume, a remote KV, the venue's own ledger); an anchor restored
alongside the database detects nothing.

An anchor that cannot be read is reported as `AnchorUnavailable`; the store maps
that to the effective grant status `ANCHOR_UNAVAILABLE`, which refuses issuance and
consumption exactly like a regression.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Protocol

try:  # POSIX advisory locks make the file anchor safe across processes.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms fall back to the thread lock
    fcntl = None  # type: ignore[assignment]


class AuthorityRegression(RuntimeError):
    """The datastore's authority state is older than the externally anchored state."""


class AnchorUnavailable(RuntimeError):
    """The anchor could not be read or written; authority checks must fail closed."""


class AnchorUnavailableAfterCommit(AnchorUnavailable):
    """The stop-direction change committed to the datastore; the anchor mark could not
    be raised. The next anchored open (or a re-run of the same command) repairs it."""


class AnchorMismatch(RuntimeError):
    """The datastore is bound to a different anchor than the one presented (a fresh,
    replaced or wrong anchor file); opening with it would silently un-regress a
    restored datastore, so it is refused."""


# Reserved key under which the anchor stores the identity it was bound with.
ANCHOR_IDENTITY_KEY = "__identity__"


# Longest wait for the inter-process anchor lock before the anchor is reported
# unavailable. A stalled holder (frozen process, hung network volume) must turn
# into a machine-readable failure, never an unbounded hang inside process() or
# under the emergency halt.
ANCHOR_LOCK_TIMEOUT_SECONDS = 5.0


class AuthorityAnchor(Protocol):
    def high_water(self, grant_id: str, version: int) -> tuple[int, int] | None:
        """Highest (runtime_epoch, fence_counter) recorded for the grant version."""

    def record(self, grant_id: str, version: int, epoch: int, fence: int) -> None:
        """Raise the high-water mark; never lowers it."""

    def reset(self, grant_id: str, version: int, epoch: int, fence: int) -> None:
        """Operator-only: set the mark to the given values after manual reconciliation."""

    def identity(self) -> str | None:
        """The identity this anchor was bound with, or None for a fresh anchor."""

    def bind_identity(self, anchor_id: str) -> None:
        """Bind a fresh anchor to an identity; a different existing identity is `AnchorMismatch`."""


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

    def identity(self) -> str | None:
        with self._lock:
            return getattr(self, "_identity", None)

    def bind_identity(self, anchor_id: str) -> None:
        with self._lock:
            current = getattr(self, "_identity", None)
            if current is not None and current != anchor_id:
                raise AnchorMismatch(f"anchor is bound to {current}, not {anchor_id}")
            self._identity = str(anchor_id)


class FileAuthorityAnchor:
    """Durable anchor in a small JSON file rewritten atomically (tmp + fsync + rename).

    Every read-modify-write holds a process-wide thread lock and an inter-process
    advisory lock on `<path>.lock`, so several workers and the operator CLI can
    share one anchor file without losing marks (a lost update would let a later
    restore go undetected). Place the file on storage that is not part of the
    database backup set.
    """

    def __init__(self, path: str | Path, *, lock_timeout_seconds: float = ANCHOR_LOCK_TIMEOUT_SECONDS) -> None:
        self.path = Path(path)
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._lock = threading.Lock()
        if not lock_timeout_seconds > 0:
            raise ValueError("lock_timeout_seconds must be positive")
        self.lock_timeout_seconds = float(lock_timeout_seconds)
        if not self.path.exists():
            with self._exclusive():
                if not self.path.exists():
                    self._write({})

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        with self._lock:
            if fcntl is None:  # pragma: no cover - non-POSIX
                yield
                return
            try:
                fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            except OSError as exc:
                raise AnchorUnavailable(f"cannot open anchor lock {self._lock_path}: {exc}") from exc
            try:
                deadline = time.monotonic() + self.lock_timeout_seconds
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise AnchorUnavailable(
                                f"anchor lock {self._lock_path} not acquired within {self.lock_timeout_seconds}s"
                            ) from None
                        time.sleep(0.01)
                try:
                    yield
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    @staticmethod
    def _key(grant_id: str, version: int) -> str:
        return f"{grant_id}\x1f{version}"

    @staticmethod
    def _mark(value: object) -> tuple[int, int]:
        try:
            return int(value[0]), int(value[1])  # type: ignore[index]
        except (TypeError, ValueError, IndexError) as exc:
            raise AnchorUnavailable("anchor file contains a malformed high-water mark") from exc

    def _read(self) -> dict[str, list[int]]:
        """Caller holds the exclusive lock. A missing or unreadable file fails closed."""
        try:
            raw = self.path.read_text()
        except OSError as exc:
            raise AnchorUnavailable(f"anchor file {self.path} cannot be read: {exc}") from exc
        if not raw.strip():
            return {}
        try:
            marks = json.loads(raw)
        except ValueError as exc:
            raise AnchorUnavailable(f"anchor file {self.path} is not valid JSON") from exc
        if not isinstance(marks, dict):
            raise AnchorUnavailable(f"anchor file {self.path} does not contain a JSON object")
        return marks

    def _write(self, marks: dict[str, list[int]]) -> None:
        """Caller holds the exclusive lock. The temp name is unique per writer."""
        fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(marks, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            dir_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:  # pragma: no cover - platform-specific directory fsync support
            pass

    def high_water(self, grant_id: str, version: int) -> tuple[int, int] | None:
        with self._exclusive():
            mark = self._read().get(self._key(grant_id, version))
        return None if mark is None else self._mark(mark)

    def record(self, grant_id: str, version: int, epoch: int, fence: int) -> None:
        proposed = (int(epoch), int(fence))
        with self._exclusive():
            marks = self._read()
            key = self._key(grant_id, version)
            current = marks.get(key)
            if current is None or self._mark(current) < proposed:
                marks[key] = list(proposed)
                self._write(marks)

    def reset(self, grant_id: str, version: int, epoch: int, fence: int) -> None:
        with self._exclusive():
            marks = self._read()
            marks[self._key(grant_id, version)] = [int(epoch), int(fence)]
            self._write(marks)

    def identity(self) -> str | None:
        with self._exclusive():
            value = self._read().get(ANCHOR_IDENTITY_KEY)
        if value is None:
            return None
        if not isinstance(value, str) or not value:
            raise AnchorUnavailable("anchor file carries a malformed identity")
        return value

    def bind_identity(self, anchor_id: str) -> None:
        with self._exclusive():
            marks = self._read()
            current = marks.get(ANCHOR_IDENTITY_KEY)
            if current is not None and current != anchor_id:
                raise AnchorMismatch(f"anchor {self.path} is bound to {current}, not {anchor_id}")
            if current is None:
                marks[ANCHOR_IDENTITY_KEY] = str(anchor_id)
                self._write(marks)
