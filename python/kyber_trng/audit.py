"""Bounded ring-buffer audit log of entropy consumption events."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import List


@dataclass
class AuditEntry:
    when: float           # seconds since epoch
    operation: str        # 'keygen' / 'encaps' / 'decaps' / etc.
    source: str           # source.name at the time of the call
    bytes_consumed: int


class AuditLog:
    """Thread-safe bounded ring buffer of audit entries."""

    def __init__(self, capacity: int = 4096):
        self._buf: deque[AuditEntry] = deque(maxlen=capacity)
        self._lock = threading.Lock()

    def record(self, operation: str, source: str, bytes_consumed: int) -> None:
        e = AuditEntry(time.time(), operation, source, int(bytes_consumed))
        with self._lock:
            self._buf.append(e)

    def entries(self) -> List[AuditEntry]:
        with self._lock:
            return list(self._buf)

    def clear(self) -> None:
        with self._lock:
            self._buf.clear()

    def __len__(self) -> int:
        return len(self._buf)
