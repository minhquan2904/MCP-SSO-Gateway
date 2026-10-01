"""Best-effort rotating JSONL audit log without token material."""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import IO

log = logging.getLogger("mcp_gateway.audit")


class AuditLog:
    def __init__(
        self, directory: str | Path, *, max_bytes: int, now: Callable[[], float] = time.time
    ) -> None:
        self._directory = Path(directory)
        self._max_bytes = max_bytes
        self._now = now
        self._lock = threading.Lock()
        self._handle: IO[str] | None = None
        self._size = 0
        self._epoch: int | None = None
        self._sequence = 0

    def write(
        self,
        *,
        identity_id: str | None,
        server: str | None,
        path: str | None,
        decision: str,
        status: int,
    ) -> None:
        record = {
            "ts": datetime.fromtimestamp(self._now(), UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "identity_id": identity_id,
            "server": server,
            "path": path,
            "decision": decision,
            "status": status,
        }
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n"
        try:
            with self._lock:
                handle = self._file_for(len(line.encode("utf-8")))
                handle.write(line)
                handle.flush()
                self._size += len(line.encode("utf-8"))
        except OSError as exc:
            log.warning("audit write failed (%s)", type(exc).__name__)

    def _file_for(self, incoming: int) -> IO[str]:
        if self._handle is not None and self._size and self._size + incoming > self._max_bytes:
            self._handle.close()
            self._handle = None
            self._sequence += 1
        if self._handle is None:
            self._directory.mkdir(parents=True, exist_ok=True)
            if self._epoch is None:
                self._epoch = int(self._now())
            while True:
                candidate = self._directory / f"audit-{self._epoch}-{self._sequence}.jsonl"
                try:
                    self._handle = candidate.open("x", encoding="utf-8")
                    self._size = 0
                    break
                except FileExistsError:
                    self._sequence += 1
        return self._handle
