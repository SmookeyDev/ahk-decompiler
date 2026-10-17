"""Streaming extraction with identical detection rules for every process."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import psutil

from .detection import ScriptScanner, detect_scripts
from .memory import ProcessMemory, is_readable_region
from .models import ExtractionConfig, ExtractionResult, ProcessResult, Status
from .output import OutputStore
from .resources import runtime_entries
from .winapi import UnsupportedArchitectureError, UnsupportedPlatformError, WindowsAPIError


class ReadBudget:
    """One read budget shared across all workers and retries in a session."""

    def __init__(self, maximum: int):
        self.remaining = maximum
        self._lock = threading.Lock()

    def claim(self, size: int) -> int:
        with self._lock:
            granted = min(size, self.remaining)
            self.remaining -= granted
            return granted


def scan_process(
    pid: int,
    config: ExtractionConfig,
    cancel: threading.Event,
    *,
    deadline: float | None = None,
    create_time: float | None = None,
    resource_entries=(),
    budget=None,
    reader_factory=ProcessMemory,
    once=False,
) -> ProcessResult:
    result = ProcessResult(pid, create_time=create_time)
    deadline = deadline if deadline is not None else time.monotonic() + config.timeout
    budget = budget if budget is not None else ReadBudget(config.max_scan_bytes)
    best = {}

    def diagnostic(message, **extra):
        if len(result.diagnostics) < 100:
            result.diagnostics.append({"stage": "memory", "message": message, **extra})

    def collect(candidates):
        for candidate in candidates:
            key = (candidate.source, candidate.offset, candidate.encoding)
            previous = best.get(key)
            if previous is None or (candidate.complete, len(candidate.raw)) >= (
                previous.complete,
                len(previous.raw),
            ):
                best[key] = candidate

    def stopped():
        return cancel.is_set() or time.monotonic() >= deadline or result.stats.budget_exhausted

    try:
        if cancel.is_set():
            result.status = Status.CANCELLED
            return result
        with reader_factory(pid, create_time=create_time) as reader:

            def read(address, size):
                parts = []
                remaining = size
                while remaining > 0 and not stopped():
                    requested = budget.claim(min(remaining, config.block_size))
                    if not requested:
                        result.stats.budget_exhausted = True
                        break
                    block = reader.read(address, requested)
                    if block.error:
                        result.stats.read_errors += 1
                        diagnostic("ReadProcessMemory returned an error", address=address, code=block.error)
                    if not block.data:
                        break
                    data = block.data[:requested]
                    parts.append(data)
                    result.stats.bytes_read += len(data)
                    address += len(data)
                    remaining -= len(data)
                return b"".join(parts)

            def priority():
                # Prefer exact resource ranges in the expanded image (important for MPRESS).
                try:
                    module_base = reader.module_base(read=read, cancel=cancel, deadline=deadline)
                    entries = runtime_entries(read, module_base) or resource_entries
                    for entry in entries:
                        if stopped() or entry.size > config.max_script_bytes:
                            continue
                        blob = read(module_base + entry.rva, entry.size)
                        collect(
                            detect_scripts(
                                blob,
                                source="memory_resource",
                                base_offset=module_base + entry.rva,
                                bounded=len(blob) == entry.size,
                                resource_name=entry.name,
                                codepage=entry.codepage,
                                max_script_bytes=config.max_script_bytes,
                                details={"pid": pid, "create_time": create_time, **entry.metadata()},
                            )
                        )
                except (WindowsAPIError, ValueError) as exc:
                    diagnostic(str(exc), code=getattr(exc, "winerror", None))
                authoritative = [c for c in best.values() if c.source == "memory_resource" and c.complete]
                for key, candidate in list(best.items()):
                    if candidate.source == "memory" and any(
                        candidate.text.startswith(c.text) for c in authoritative
                    ):
                        del best[key]

            while not stopped():
                if not reader.alive():
                    diagnostic("Process exited before extraction completed")
                    break
                result.stats.passes += 1
                priority()
                if any(candidate.complete for candidate in best.values()):
                    break

                scanner = ScriptScanner(config.max_script_bytes)
                for region in reader.regions():
                    if stopped():
                        break
                    result.stats.regions_seen += 1
                    if not is_readable_region(region.state, region.protection):
                        continue
                    address, end = region.base, region.base + region.size
                    region_read = False
                    while address < end and not stopped():
                        length = min(config.block_size, end - address)
                        blob = read(address, length)
                        if blob:
                            region_read = True
                            collect(
                                scanner.feed(
                                    address,
                                    blob,
                                    source="memory",
                                    details={"pid": pid, "create_time": create_time},
                                )
                            )
                            address += len(blob)
                            if not config.exhaustive_memory and any(c.complete for c in best.values()):
                                priority()
                                result.stats.stopped_after_script = True
                                break
                        else:
                            # A failed page must not discard the rest of a large region.
                            address += min(4096, end - address)
                    result.stats.regions_read += int(region_read)
                    if result.stats.stopped_after_script:
                        break
                if any(candidate.complete for candidate in best.values()) or once or stopped():
                    break
                cancel.wait(min(config.poll_interval, max(0, deadline - time.monotonic())))

        # Keep only the best version of each origin, with exact copies deduplicated later.
        result.candidates = list(best.values())
        if cancel.is_set():
            result.status = Status.CANCELLED
        elif result.candidates:
            result.status = (
                Status.SUCCESS
                if all(c.complete for c in result.candidates) and not result.stats.budget_exhausted
                else Status.PARTIAL
            )
        elif result.stats.budget_exhausted:
            result.status = Status.NOT_FOUND
            diagnostic("Session read budget exhausted; scan coverage is incomplete")
        elif time.monotonic() >= deadline:
            result.status = Status.TIMEOUT
        else:
            result.status = Status.NOT_FOUND
    except (InterruptedError, TimeoutError) as exc:
        result.status = Status.CANCELLED if cancel.is_set() else Status.TIMEOUT
        diagnostic(str(exc))
    except (UnsupportedArchitectureError, UnsupportedPlatformError) as exc:
        result.status = Status.UNSUPPORTED
        diagnostic(str(exc))
    except (psutil.AccessDenied, WindowsAPIError, PermissionError) as exc:
        code = getattr(exc, "winerror", None)
        result.status = (
            Status.ACCESS_DENIED
            if isinstance(exc, (psutil.AccessDenied, PermissionError)) or code == 5
            else Status.ERROR
        )
        diagnostic(str(exc), code=code)
    except (psutil.NoSuchProcess, ProcessLookupError) as exc:
        result.status = Status.NOT_FOUND
        diagnostic(str(exc))
    except Exception as exc:
        result.status = Status.ERROR
        diagnostic(str(exc))
    result.candidates = list(best.values())
    if result.candidates and result.status in (Status.ERROR, Status.NOT_FOUND, Status.TIMEOUT):
        result.status = Status.PARTIAL
    return result


def _save_legacy(result, target, out_dir):
    if result.candidates:
        store = OutputStore(Path(out_dir), Path(target))
        for candidate in result.candidates:
            store.save(candidate)
        store.finish(ExtractionResult(status=result.status, processes=[result.summary()]))
        return len(store.artifacts)
    return 0


def extract_scripts(pid, out_dir, progress=None, is_subprocess=False):
    """Compatibility wrapper; main and child processes intentionally share detection."""
    target = Path(psutil.Process(pid).exe())
    config = ExtractionConfig(target)
    result = scan_process(pid, config, threading.Event(), once=True)
    if progress:
        progress(result.stats.bytes_read)
    return _save_legacy(result, target, out_dir)


def process_single_pid(pid, is_main_process=False):
    try:
        target = Path(psutil.Process(pid).exe())
        config = ExtractionConfig(target)
        result = scan_process(pid, config, threading.Event())
        count = _save_legacy(result, target, "dump_scripts")
        return {
            **result.summary(),
            "scripts_count": count,
            "error": result.diagnostics[-1]["message"]
            if result.status == Status.ERROR and result.diagnostics
            else None,
        }
    except (psutil.Error, OSError) as exc:
        return {"pid": pid, "scripts_count": 0, "status": str(Status.ERROR), "error": str(exc)}
