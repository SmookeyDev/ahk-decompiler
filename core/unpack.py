"""Optional, user-selected UPX adapter; the original input is never rewritten."""

from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from .output import file_sha256


def unpack_upx(config, directory: Path, cancel, deadline: float) -> Path:
    tool = Path(config.upx_path).expanduser().resolve()
    if not tool.is_file():
        raise ValueError("Selected UPX executable does not exist")
    if config.upx_sha256 and file_sha256(tool).lower() != config.upx_sha256.lower():
        raise ValueError("UPX executable SHA-256 does not match")
    output = directory / "unpacked.exe"
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(
            [str(tool), "-d", "-o", str(output), str(config.target)],
            stdout=log,
            stderr=subprocess.STDOUT,
            shell=False,
        )
        try:
            while process.poll() is None:
                if cancel.is_set():
                    raise InterruptedError("UPX operation cancelled")
                if time.monotonic() >= deadline:
                    raise TimeoutError("UPX operation timed out")
                if log.tell() > 1024 * 1024:
                    raise ValueError("UPX diagnostic output limit exceeded")
                if output.exists() and output.stat().st_size > config.max_file_bytes:
                    raise ValueError("UPX output exceeds the configured file size limit")
                cancel.wait(0.05)
            if process.returncode:
                log.seek(0)
                raise ValueError(
                    f"UPX failed ({process.returncode}): {log.read(4096).decode(errors='replace')}"
                )
            if not output.is_file() or output.stat().st_size > config.max_file_bytes:
                raise ValueError("UPX did not produce an output within the file size limit")
            return output
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
