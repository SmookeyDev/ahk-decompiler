import ctypes as ct
import threading
import time

import pytest

from core.engine import ExtractionEngine
from core.extractor import scan_process
from core.memory import is_readable_region
from core.models import ExtractionConfig, ProcessResult, Status
from core.winapi import (
    MEMORY_BASIC_INFORMATION32,
    MEMORY_BASIC_INFORMATION64,
    MemoryRegion,
    ReadResult,
    WindowsAPI,
    WindowsAPIError,
)
from tests.pe_fixture import make_pe
from tests.test_detection import SCRIPT


class Reader:
    def __init__(self, pid, *, create_time=None):
        self.blob = SCRIPT.encode("utf-16-le") + b"\0\0"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def alive(self):
        return True

    def module_base(self, **kwargs):
        raise WindowsAPIError("fixture has no module", 126)

    def regions(self):
        split = 31
        yield MemoryRegion(4097, split, 0x1000, 4)
        yield MemoryRegion(4097 + split, len(self.blob) - split, 0x1000, 4)

    def read(self, address, size):
        offset = address - 4097
        return ReadResult(self.blob[offset : offset + min(size, 17)], 299)


def test_partial_reads_and_adjacent_regions_are_recovered(tmp_path):
    result = scan_process(
        1,
        ExtractionConfig(tmp_path / "x", block_size=32),
        threading.Event(),
        reader_factory=Reader,
        once=True,
    )
    assert result.status == Status.SUCCESS
    assert result.stats.read_errors > 0
    assert result.candidates[0].text == SCRIPT
    assert result.candidates[0].complete


def test_no_script_is_never_success(tmp_path):
    class Empty(Reader):
        def __init__(self, *args, **kwargs):
            self.blob = b"AutoHotkey\0COMPILER ::\0"

    result = scan_process(
        1, ExtractionConfig(tmp_path / "x"), threading.Event(), reader_factory=Empty, once=True
    )
    assert result.status == Status.NOT_FOUND
    assert not result.candidates


def test_global_budget_is_bounded_and_reported(tmp_path):
    result = scan_process(
        1, ExtractionConfig(tmp_path / "x", max_scan_bytes=8), threading.Event(), reader_factory=Reader
    )
    assert result.stats.budget_exhausted
    assert result.stats.bytes_read <= 8
    assert result.status != Status.SUCCESS


def test_native_read_preserves_partial_bytes(monkeypatch):
    api = WindowsAPI.__new__(WindowsAPI)

    def read(handle, address, buffer, size, count):
        ct.memmove(buffer, b"hello", 5)
        ct.cast(count, ct.POINTER(ct.c_size_t)).contents.value = 5
        return 0

    api.ReadProcessMemory = read
    monkeypatch.setattr(ct, "get_last_error", lambda: 299, raising=False)
    monkeypatch.setattr(ct, "set_last_error", lambda value: None, raising=False)
    result = api.read(1, 1024, 20)
    assert result.data == b"hello"
    assert result.error == 299


def test_native_structure_layout_and_protection_flags():
    assert ct.sizeof(MEMORY_BASIC_INFORMATION32) == 28
    assert MEMORY_BASIC_INFORMATION32.RegionSize.offset == 12
    assert ct.sizeof(MEMORY_BASIC_INFORMATION64) == 48
    assert MEMORY_BASIC_INFORMATION64.RegionSize.offset == 24
    for flag in (2, 4, 8, 0x20, 0x40, 0x80):
        assert is_readable_region(0x1000, flag)
        assert not is_readable_region(0x1000, flag | 0x100)
    assert not is_readable_region(0x1000, 1)
    assert not is_readable_region(0x2000, 4)


class Identity:
    pid = 123
    create_time = 1.0
    name = "fixture.exe"

    def alive(self):
        return False


class Session:
    closed = False

    def __init__(self, config):
        self.root = Identity()
        self.known = {123: self.root}

    def discover(self):
        return [self.root]

    def close(self):
        Session.closed = True


def test_zero_artifact_result_cannot_report_success(tmp_path):
    target = tmp_path / "empty.exe"
    target.write_bytes(make_pe())

    def scanner(pid, *args, **kwargs):
        return ProcessResult(pid, Status.SUCCESS)

    result = ExtractionEngine(session_factory=Session, scanner=scanner).run(
        ExtractionConfig(target, tmp_path / "out", mode="memory", allow_execution=True)
    )
    assert result.status == Status.NOT_FOUND
    assert Session.closed


def test_cancellation_waits_for_worker_and_cleans_session(tmp_path):
    target = tmp_path / "empty.exe"
    target.write_bytes(make_pe())
    started, cancel = threading.Event(), threading.Event()
    Session.closed = False

    def scanner(pid, config, stop, **kwargs):
        started.set()
        assert stop.wait(2)
        return ProcessResult(pid, Status.CANCELLED)

    engine = ExtractionEngine(session_factory=Session, scanner=scanner)
    results = []
    worker = threading.Thread(
        target=lambda: results.append(
            engine.run(
                ExtractionConfig(target, tmp_path / "out", mode="memory", allow_execution=True), cancel
            )
        )
    )
    worker.start()
    assert started.wait(1)
    t0 = time.monotonic()
    cancel.set()
    worker.join(2)
    assert not worker.is_alive()
    assert time.monotonic() - t0 < 2
    assert results[0].status == Status.CANCELLED
    assert Session.closed


@pytest.mark.parametrize(
    "field,value",
    [("timeout", float("nan")), ("timeout", -1), ("block_size", 0), ("max_workers", 100), ("pid", -1)],
)
def test_invalid_limits_are_rejected(tmp_path, field, value):
    with pytest.raises(ValueError):
        ExtractionConfig(tmp_path / "x", **{field: value})
