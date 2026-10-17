"""Portable contracts shared by command line, GUI and extraction strategies."""

from __future__ import annotations

import hashlib
import math
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Status(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    NOT_FOUND = "not_found"
    RUNTIME_REQUIRED = "runtime_required"
    ACCESS_DENIED = "access_denied"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


@dataclass(frozen=True)
class ExtractionConfig:
    target: Path
    output_dir: Path = Path("dump_scripts")
    mode: str = "static"
    allow_execution: bool = False
    pid: int | None = None
    monitor_children: bool = True
    extract_resources: bool = True
    timeout: float = 30.0
    discovery_seconds: float = 3.0
    poll_interval: float = 0.15
    max_scan_bytes: int = 512 * 1024 * 1024
    max_script_bytes: int = 16 * 1024 * 1024
    max_file_bytes: int = 512 * 1024 * 1024
    block_size: int = 1024 * 1024
    max_workers: int = 5
    exhaustive_memory: bool = False
    upx_path: Path | None = None
    upx_sha256: str | None = None
    arguments: tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "target", Path(self.target).expanduser().resolve())
        object.__setattr__(self, "output_dir", Path(self.output_dir).expanduser().resolve())
        if self.mode not in {"static", "auto", "memory"}:
            raise ValueError("mode must be static, auto or memory")
        if self.pid is not None and self.pid <= 0:
            raise ValueError("PID must be positive")
        for name in ("timeout", "poll_interval", "discovery_seconds"):
            value = getattr(self, name)
            if not math.isfinite(value) or value < 0 or (name != "discovery_seconds" and value == 0):
                raise ValueError(f"{name} must be finite and positive")
        for name in ("max_scan_bytes", "max_script_bytes", "max_file_bytes", "block_size", "max_workers"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.block_size > 4 * 1024 * 1024 or self.max_workers > 16:
            raise ValueError("block_size is limited to 4 MiB and max_workers to 16")
        if self.max_script_bytes > 64 * 1024 * 1024:
            raise ValueError("max_script_bytes is limited to 64 MiB")


@dataclass(frozen=True)
class Candidate:
    text: str
    raw: bytes
    encoding: str
    source: str
    offset: int = 0
    complete: bool = True
    confidence: str = "high"
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        # Deduplication never changes the saved source.
        return hashlib.sha256(self.text.replace("\r\n", "\n").encode("utf-8")).hexdigest()

    def origin(self) -> dict:
        return {
            "source": self.source,
            "offset": self.offset,
            "encoding": self.encoding,
            "complete": self.complete,
            "confidence": self.confidence,
            "raw_sha256": hashlib.sha256(self.raw).hexdigest(),
            "raw_bytes": len(self.raw),
            **self.details,
        }


@dataclass
class ScanStats:
    regions_seen: int = 0
    regions_read: int = 0
    bytes_read: int = 0
    read_errors: int = 0
    passes: int = 0
    budget_exhausted: bool = False
    stopped_after_script: bool = False


@dataclass
class ProcessResult:
    pid: int
    status: Status = Status.NOT_FOUND
    candidates: list[Candidate] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    diagnostics: list[dict] = field(default_factory=list)

    create_time: float | None = None

    def summary(self) -> dict:
        status = Status.NOT_FOUND if self.status == Status.SUCCESS and not self.candidates else self.status
        return {
            "pid": self.pid,
            "create_time": self.create_time,
            "status": str(status),
            "scripts_count": len(self.candidates),
            "stats": asdict(self.stats),
            "diagnostics": self.diagnostics,
        }


@dataclass
class ExtractionResult:
    status: Status = Status.NOT_FOUND
    run_id: str = ""
    output_dir: str = ""
    artifacts: list[dict] = field(default_factory=list)
    processes: list[dict] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)
    analysis: dict = field(default_factory=dict)
    configuration: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)

    @property
    def scripts_count(self) -> int:
        return len(self.artifacts)
