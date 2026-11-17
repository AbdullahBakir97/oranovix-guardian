"""
Reading a growing log file.

The position in each file is kept with the identity of the file (inode
on Linux, file index on Windows) in a small SQLite file, so a restart
continues where it stopped, a rotated file is read from its start and a
truncated file is read again from the top.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import threading
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int

    @classmethod
    def of(cls, stat: os.stat_result) -> "FileIdentity":
        return cls(int(stat.st_dev), int(stat.st_ino))

    @property
    def text(self) -> str:
        return f"{self.device}:{self.inode}"


@dataclass(frozen=True)
class TailPosition:
    identity: str
    offset: int


@dataclass(frozen=True)
class ReadResult:
    lines: Tuple[str, ...] = ()
    bytes_read: int = 0
    pending: int = 0                # bytes still waiting after this read
    rotated: bool = False
    truncated: bool = False
    first_run: bool = False
    missing: bool = False


class TailStateStore:
    """Offsets of the watched files, in their own SQLite file."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._path = Path(db_path) if db_path else self.default_path()
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS positions (path TEXT PRIMARY KEY, identity TEXT NOT NULL, "
                "offset INTEGER NOT NULL)"
            )

    @staticmethod
    def default_path() -> Path:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).parent / "log_sentinel_state.db"
        return Path(__file__).resolve().parents[1] / "log_sentinel_state.db"

    def get(self, path: str) -> Optional[TailPosition]:
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute("SELECT identity, offset FROM positions WHERE path = ?", (self._key(path),)).fetchone()
        return TailPosition(row[0], int(row[1])) if row else None

    def save(self, path: str, position: TailPosition) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO positions (path, identity, offset) VALUES (?, ?, ?) "
                "ON CONFLICT(path) DO UPDATE SET identity = excluded.identity, offset = excluded.offset",
                (self._key(path), position.identity, position.offset),
            )

    def forget(self, path: str) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM positions WHERE path = ?", (self._key(path),))

    @staticmethod
    def _key(path: str) -> str:
        return os.path.normcase(os.path.abspath(path))

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(self._path, timeout=10)


class LogTailer:
    """Reads the new complete lines of one file."""

    def __init__(self, path: str, store: TailStateStore, backfill_bytes: int = 0) -> None:
        self._path = os.path.abspath(path)
        self._store = store
        self._backfill = max(0, int(backfill_bytes))

    @property
    def path(self) -> str:
        return self._path

    def read(self, max_bytes: int) -> ReadResult:
        """At most *max_bytes*; a line that is still being written waits for the next read."""
        try:
            stat = os.stat(self._path)
        except OSError:
            return ReadResult(missing=True)
        identity = FileIdentity.of(stat).text
        size = int(stat.st_size)
        saved = self._store.get(self._path)
        first_run = rotated = truncated = False
        if saved is None:
            # A new file to watch: start at its end, or a little before when asked.
            first_run = True
            offset = max(0, size - self._backfill) if self._backfill else size
        elif saved.identity != identity:
            rotated, offset = True, 0
        elif size < saved.offset:
            truncated, offset = True, 0
        else:
            offset = saved.offset

        lines: List[str] = []
        consumed = 0
        if size > offset and max_bytes > 0:
            with open(self._path, "rb") as handle:
                handle.seek(offset)
                chunk = handle.read(min(max_bytes, size - offset))
            if first_run and offset > 0:
                # Backfill starts in the middle of a line: skip to the next one.
                start = chunk.find(b"\n") + 1
                chunk, consumed = chunk[start:], start
            end = chunk.rfind(b"\n") + 1
            if end == 0 and len(chunk) >= max_bytes:
                end = len(chunk)        # one giant line: take it, the parser caps it
            text = chunk[:end].decode("utf-8", errors="replace")
            lines = text.splitlines()
            consumed += end
        new_offset = offset + consumed
        self._store.save(self._path, TailPosition(identity, new_offset))
        return ReadResult(
            lines=tuple(lines), bytes_read=consumed, pending=max(0, size - new_offset),
            rotated=rotated, truncated=truncated, first_run=first_run,
        )
