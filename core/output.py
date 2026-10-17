"""Per-run, atomic output with lossless evidence and provenance-aware deduplication."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .models import Candidate, ExtractionResult
from .version import __version__


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class OutputStore:
    def __init__(self, root: Path, target: Path):
        self.run_id = uuid4().hex
        stem = re.sub(r"[^\w.-]", "_", target.stem)[:60] or "script"
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.directory = Path(root) / f"{stem}_{stamp}_{self.run_id[:8]}"
        self.directory.mkdir(parents=True, exist_ok=False)
        self._lock = threading.RLock()
        self._artifacts: dict[str, dict] = {}
        self.input = {"path": str(target), "sha256": file_sha256(target), "bytes": target.stat().st_size}

    def _atomic_write(self, path: Path, data: bytes):
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def save(self, candidate: Candidate) -> dict:
        with self._lock:
            key = candidate.digest
            origin = candidate.origin()
            raw_name = f"{key[:24]}_{origin['raw_sha256'][:24]}.bin"
            raw_path = self.directory / raw_name
            if not raw_path.exists():
                self._atomic_write(raw_path, candidate.raw)
            origin["raw_file"] = raw_name
            if key not in self._artifacts:
                if len(self._artifacts) >= 1000:
                    raise ValueError("Artifact limit (1000) exceeded")
                suffix = "" if candidate.complete else ".partial"
                name = f"script_{len(self._artifacts) + 1:03d}_{key[:12]}{suffix}.ahk"
                encoded = candidate.text.encode("utf-8")
                self._atomic_write(self.directory / name, encoded)
                self._artifacts[key] = {
                    "file": name,
                    "sha256": hashlib.sha256(encoded).hexdigest(),
                    "content_id": key,
                    "bytes": len(encoded),
                    "complete": candidate.complete,
                    "confidence": candidate.confidence,
                    "origins": [],
                }
            artifact = self._artifacts[key]
            if candidate.complete and not artifact["complete"] and ".partial.ahk" in artifact["file"]:
                old_path = self.directory / artifact["file"]
                artifact["file"] = artifact["file"].replace(".partial.ahk", ".ahk")
                os.replace(old_path, self.directory / artifact["file"])
            if origin not in artifact["origins"]:
                artifact["origins"].append(origin)
            artifact["complete"] = artifact["complete"] or candidate.complete
            return artifact

    @property
    def artifacts(self) -> list[dict]:
        with self._lock:
            return list(self._artifacts.values())

    def event(self, event: dict):
        with self._lock:
            payload = {"timestamp": datetime.now(UTC).isoformat(), **event}
            with (self.directory / "events.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def finish(self, result: ExtractionResult):
        result.run_id = self.run_id
        result.output_dir = str(self.directory)
        result.artifacts = self.artifacts
        manifest = {
            "schema_version": 1,
            "application_version": __version__,
            "input": self.input,
            **result.as_dict(),
        }
        self._atomic_write(
            self.directory / "manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"),
        )
