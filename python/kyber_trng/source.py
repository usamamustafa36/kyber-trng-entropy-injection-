"""
Entropy sources for the Kyber TRNG injection.

Three implementations:
  - SerialTRNGSource: production — reads framed bytes from the SAM3X8E firmware
  - SimulatedTRNGSource: development — OS entropy + timing jitter, NOT for production keys
  - TRNGSource: abstract base
"""

from __future__ import annotations

import os
import time
import threading
from abc import ABC, abstractmethod
from collections import deque
from typing import Optional

try:
    import serial  # type: ignore
except ImportError:
    serial = None  # SerialTRNGSource will raise if used


class TRNGSourceError(RuntimeError):
    pass


class TRNGSource(ABC):
    """Abstract entropy source. Pull `n` bytes via .read(n)."""

    @abstractmethod
    def read(self, n: int) -> bytes: ...

    @abstractmethod
    def close(self) -> None: ...


class SerialTRNGSource(TRNGSource):
    """
    Reads framed bytes from the SAM3X8E TRNG firmware.

    Frame format (per byte): [0xAA 0x55] <byte> <crc8>

    On CRC mismatch or framing error, the byte is dropped.
    On firmware health-test failure (0xFF 0xFF beacon repeated), raises TRNGSourceError.
    """

    _CRC8_POLY = 0x07

    def __init__(self, port: str, baudrate: int = 115200, buffer_size: int = 8192,
                 timeout: float = 2.0):
        if serial is None:
            raise ImportError("pyserial is required for SerialTRNGSource — `pip install pyserial`")
        self._ser = serial.Serial(port, baudrate=baudrate, timeout=timeout)
        self._buf: deque = deque(maxlen=buffer_size)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._fail_streak = 0
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()
        time.sleep(0.1)  # let firmware banner settle

    @staticmethod
    def _crc8(b: int) -> int:
        c = b & 0xFF
        for _ in range(8):
            c = ((c << 1) ^ SerialTRNGSource._CRC8_POLY) & 0xFF if (c & 0x80) else (c << 1) & 0xFF
        return c

    def _pump(self) -> None:
        prev = b""
        while not self._stop.is_set():
            chunk = self._ser.read(256)
            if not chunk:
                continue
            data = prev + chunk
            i = 0
            while i + 4 <= len(data):
                if data[i] == 0xAA and data[i + 1] == 0x55:
                    byte_v, crc_v = data[i + 2], data[i + 3]
                    if self._crc8(byte_v) == crc_v:
                        with self._lock:
                            self._buf.append(byte_v)
                        i += 4
                        continue
                # Health-fail beacon (0xFF 0xFF repeated)
                if data[i] == 0xFF and data[i + 1] == 0xFF:
                    self._fail_streak += 1
                    if self._fail_streak >= 4:
                        self._stop.set()
                        return
                else:
                    self._fail_streak = 0
                i += 1
            prev = data[i:]

    def read(self, n: int) -> bytes:
        out = bytearray()
        deadline = time.monotonic() + max(5.0, n * 0.001)
        while len(out) < n:
            if self._stop.is_set():
                raise TRNGSourceError("TRNG firmware reported health-test failure")
            with self._lock:
                while self._buf and len(out) < n:
                    out.append(self._buf.popleft())
            if len(out) < n:
                if time.monotonic() > deadline:
                    raise TRNGSourceError(f"TRNG starved: got {len(out)}/{n} bytes before timeout")
                time.sleep(0.005)
        return bytes(out)

    def close(self) -> None:
        self._stop.set()
        try:
            self._ser.close()
        except Exception:
            pass


class SimulatedTRNGSource(TRNGSource):
    """
    OS-entropy + timing-jitter simulator.

    For development, CI, and reproducible benchmarking ONLY. Do NOT use this
    for production keys — it derives entropy from os.urandom which is exactly
    what we set out to replace.

    The added timing jitter does not increase security — it is only there to
    make the byte stream behaviourally distinguishable from raw os.urandom in
    the benchmark harness.
    """

    def __init__(self, seed: Optional[bytes] = None):
        self._seed = seed
        self._closed = False

    def read(self, n: int) -> bytes:
        if self._closed:
            raise TRNGSourceError("source closed")
        out = bytearray()
        for _ in range(n):
            t1 = time.perf_counter_ns()
            _ = sum(i * i for i in range(64))
            t2 = time.perf_counter_ns()
            jitter = (t2 - t1) & 0xFF
            os_byte = os.urandom(1)[0]
            out.append(jitter ^ os_byte)
        return bytes(out)

    def close(self) -> None:
        self._closed = True
