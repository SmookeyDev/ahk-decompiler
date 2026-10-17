"""Read-only memory access, cancellation and backwards-compatible convenience APIs."""

from __future__ import annotations

import threading
import time
import struct

import psutil

from .winapi import WindowsAPI


def is_readable_region(state: int, protect: int) -> bool:
    return (
        state == 0x1000
        and not (protect & 0x100)
        and (protect & 0xFF)
        in {
            0x02,
            0x04,
            0x08,
            0x20,
            0x40,
            0x80,
        }
    )


class ProcessMemory:
    def __init__(self, pid: int, *, create_time: float | None = None, api=None):
        self.pid = pid
        self.api = api if api is not None else WindowsAPI()
        process = psutil.Process(pid)
        self.created = process.create_time()
        if create_time is not None and self.created != create_time:
            raise ProcessLookupError(f"PID {pid} was reused")
        self.process = process
        self.handle = self.api.open(pid)
        try:
            if not process.is_running() or process.create_time() != self.created:
                raise ProcessLookupError(f"PID {pid} changed while opening it")
            self.architecture = self.api.architecture(self.handle)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.handle:
            self.api.close(self.handle)
            self.handle = None

    def alive(self):
        return self.process.is_running() and self.process.status() != psutil.STATUS_ZOMBIE

    def regions(self):
        return self.api.regions(self.handle)

    def read(self, address: int, size: int):
        return self.api.read(self.handle, address, size)

    def module_base(self, *, read=None, cancel=None, deadline=None):
        try:
            return self.api.module_base(self.handle)
        except OSError:
            # PSAPI can fail across architectures or while the loader is changing.
            # A mapped non-DLL PE image is an independent way to locate the main image.
            seen = set()
            for index, region in enumerate(self.api.regions(self.handle)):
                if (cancel is not None and cancel.is_set()) or (
                    deadline is not None and time.monotonic() >= deadline
                ):
                    raise InterruptedError("Module lookup cancelled or deadline expired")
                if index >= 4096:
                    break
                base = region.allocation_base
                if region.type != 0x1000000 or not base or base in seen:
                    continue
                seen.add(base)
                header = read(base, 4096) if read else self.api.read(self.handle, base, 4096).data
                if len(header) < 64 or header[:2] != b"MZ":
                    continue
                offset = struct.unpack_from("<I", header, 60)[0]
                if offset + 24 <= len(header) and header[offset : offset + 4] == b"PE\0\0":
                    characteristics = struct.unpack_from("<H", header, offset + 22)[0]
                    if not characteristics & 0x2000:
                        return base
            raise


_api = None


def _native():
    global _api
    if _api is None:
        _api = WindowsAPI()
    return _api


def open_process(pid):
    return _native().open(pid)


def close_process(handle):
    _native().close(handle)


def enum_memory(handle):
    for region in _native().regions(handle):
        yield region.base, region.size, region.state, region.protection


def read_region(handle, base, size):
    """Legacy bounded read; do not allocate a buffer the size of an entire region."""
    if size > 4 * 1024 * 1024:
        raise ValueError("Use the streaming extractor for regions larger than 4 MiB")
    return _native().read(handle, base, size).data


def wait_for_unpack(pid, timeout=60, check_interval=0.15, cancel=None):
    """Ready means a validated, complete script was found, not an unrelated string."""
    from .extractor import scan_process
    from .models import ExtractionConfig
    from pathlib import Path

    result = scan_process(
        pid,
        ExtractionConfig(Path("."), timeout=timeout, poll_interval=check_interval),
        cancel or threading.Event(),
        deadline=time.monotonic() + timeout,
    )
    return any(candidate.complete for candidate in result.candidates)
