"""One extraction service for GUI, CLI and programmatic callers."""

from __future__ import annotations

import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import psutil

from utils.pe_analyzer import analyze_pe_file

from .extractor import ReadBudget, scan_process
from .models import ExtractionConfig, ExtractionResult, Status
from .output import OutputStore, file_sha256
from .processes import ProcessSession
from .resources import PEResourceExtractor
from .unpack import unpack_upx
from .winapi import UnsupportedArchitectureError, UnsupportedPlatformError, WindowsAPIError


def analyze_target(path: Path, maximum=512 * 1024 * 1024) -> tuple[dict, PEResourceExtractor]:
    path = Path(path)
    if not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("Select a regular file within the configured input size limit")
    analysis = analyze_pe_file(path)
    resources = PEResourceExtractor(str(path), maximum)
    if not analysis.is_pe or not resources.load_file():
        raise ValueError(analysis.additional_info.get("error", "Invalid or truncated PE executable"))
    info = {
        "is_pe": True,
        "architecture": analysis.additional_info.get("Architecture"),
        "packer": analysis.packer.value,
        "packer_confidence_is_heuristic": True,
        "compiler": analysis.compiler.value,
        "runtime_version": analysis.compiler_version,
        "file_size": analysis.file_size,
        "sections": [vars(section) for section in analysis.sections],
        "resources": [entry.metadata() for entry in resources.entries],
        "requires_runtime": resources.requires_runtime,
    }
    return info, resources


class ExtractionEngine:
    def __init__(self, *, session_factory=ProcessSession, scanner=scan_process):
        self.session_factory = session_factory
        self.scanner = scanner

    def run(self, config: ExtractionConfig, cancel=None, callback=None) -> ExtractionResult:
        cancel = cancel if cancel is not None else threading.Event()
        result = ExtractionResult()
        result.configuration = {
            "mode": config.mode,
            "allow_execution": config.allow_execution,
            "pid": config.pid,
            "monitor_children": config.monitor_children,
            "timeout": config.timeout,
            "discovery_seconds": config.discovery_seconds,
            "max_scan_bytes": config.max_scan_bytes,
            "max_script_bytes": config.max_script_bytes,
            "block_size": config.block_size,
            "exhaustive_memory": config.exhaustive_memory,
        }
        store = None

        def emit(kind, message="", **data):
            event = {"kind": kind, "message": message, **data}
            if store:
                event["run_id"] = store.run_id
                store.event(event)
            if callback:
                try:
                    callback(event)
                except Exception:
                    # A presentation callback cannot break process cleanup or extraction.
                    pass

        try:
            if cancel.is_set():
                result.status = Status.CANCELLED
                return result
            result.analysis, resources = analyze_target(config.target, config.max_file_bytes)
            store = OutputStore(config.output_dir, config.target)
            emit("phase", "Inspecting PE resources", progress=5)
            if config.extract_resources and config.mode != "memory":
                for candidate in resources.candidates(config.max_script_bytes):
                    if cancel.is_set():
                        break
                    store.save(candidate)
            if cancel.is_set():
                result.status = Status.CANCELLED
                return result
            if (
                store.artifacts
                and all(item["complete"] for item in store.artifacts)
                and config.mode != "memory"
            ):
                result.status = Status.SUCCESS
                emit("log", "Static extraction succeeded; target execution is unnecessary")
                return result
            deadline = time.monotonic() + config.timeout
            if config.upx_path and result.analysis["packer"] == "UPX" and config.mode != "memory":
                emit("phase", "Unpacking a temporary copy with selected UPX", progress=10)
                with tempfile.TemporaryDirectory(prefix="ahk-upx-") as directory:
                    unpacked = unpack_upx(config, Path(directory), cancel, deadline)
                    _, unpacked_resources = analyze_target(unpacked, config.max_file_bytes)
                    for candidate in unpacked_resources.candidates(config.max_script_bytes):
                        store.save(candidate)
                if store.artifacts and all(item["complete"] for item in store.artifacts):
                    result.status = Status.SUCCESS
                    return result
            if cancel.is_set():
                result.status = Status.CANCELLED
                return result
            if config.mode == "static" or (config.pid is None and not config.allow_execution):
                result.status = (
                    Status.PARTIAL
                    if store.artifacts
                    else (
                        Status.RUNTIME_REQUIRED
                        if resources.requires_runtime
                        or result.analysis["packer"] != "None"
                        or config.mode == "memory"
                        else Status.NOT_FOUND
                    )
                )
                result.diagnostics.append(
                    {
                        "stage": "strategy",
                        "message": "Runtime extraction requires memory mode or auto mode with execution enabled"
                        if result.status == Status.RUNTIME_REQUIRED
                        else "No complete script found in file resources",
                    }
                )
                return result
            if file_sha256(config.target) != store.input["sha256"]:
                raise ValueError("Input changed during analysis; extraction aborted")
            emit("phase", "Reading process memory", progress=15, indeterminate=True)
            self._dynamic(config, cancel, deadline, resources, result, store, emit)
            if cancel.is_set():
                result.status = Status.CANCELLED
            elif store.artifacts:
                incomplete = any(not item["complete"] for item in store.artifacts)
                failed = any(
                    item["status"] not in (Status.SUCCESS, Status.NOT_FOUND) for item in result.processes
                )
                result.status = Status.PARTIAL if incomplete or failed else Status.SUCCESS
            else:
                precedence = (Status.ACCESS_DENIED, Status.UNSUPPORTED, Status.ERROR, Status.TIMEOUT)
                result.status = next(
                    (status for status in precedence if any(p["status"] == status for p in result.processes)),
                    Status.NOT_FOUND,
                )
        except InterruptedError as exc:
            result.status = Status.CANCELLED
            result.diagnostics.append({"stage": "cancel", "message": str(exc)})
        except TimeoutError as exc:
            result.status = Status.TIMEOUT
            result.diagnostics.append({"stage": "timeout", "message": str(exc)})
        except (UnsupportedPlatformError, UnsupportedArchitectureError) as exc:
            result.status = Status.UNSUPPORTED
            result.diagnostics.append({"stage": "platform", "message": str(exc)})
        except (psutil.AccessDenied, PermissionError, WindowsAPIError) as exc:
            code = getattr(exc, "winerror", None)
            result.status = (
                Status.ACCESS_DENIED
                if isinstance(exc, (psutil.AccessDenied, PermissionError)) or code == 5
                else Status.ERROR
            )
            result.diagnostics.append({"stage": "process", "message": str(exc), "code": code})
        except Exception as exc:
            result.status = Status.ERROR
            result.diagnostics.append({"stage": "extraction", "message": str(exc)})
        finally:
            if store:
                emit(
                    "finished",
                    str(result.status),
                    status=str(result.status),
                    scripts_count=len(store.artifacts),
                )
                store.finish(result)
        return result

    def _dynamic(self, config, cancel, deadline, resources, result, store, emit):
        session = self.session_factory(config)
        worker_stop = threading.Event()
        budget = ReadBudget(config.max_scan_bytes)
        futures = {}
        names = {}
        completed = set()
        discovery_until = time.monotonic() + (config.discovery_seconds if config.monitor_children else 0)
        executor = ThreadPoolExecutor(max_workers=config.max_workers, thread_name_prefix="ahk-memory")
        try:
            while not cancel.is_set() and time.monotonic() < deadline:
                identities = session.discover()
                for identity in identities:
                    key = (identity.pid, identity.create_time)
                    if key not in futures:
                        if len(futures) >= 128:
                            raise ValueError("Session process limit (128) exceeded")
                        discovery_until = min(
                            deadline,
                            max(
                                discovery_until,
                                time.monotonic()
                                + (config.discovery_seconds if config.monitor_children else 0),
                            ),
                        )
                        emit(
                            "process",
                            f"Analyzing {identity.name}",
                            pid=identity.pid,
                            name=identity.name,
                            create_time=identity.create_time,
                            status="scanning",
                        )
                        futures[key] = executor.submit(
                            self.scanner,
                            identity.pid,
                            config,
                            worker_stop,
                            deadline=deadline,
                            create_time=identity.create_time,
                            budget=budget,
                            resource_entries=resources.entries
                            if key == (session.root.pid, session.root.create_time)
                            else (),
                        )
                        names[key] = identity.name
                for key, future in futures.items():
                    if future.done() and key not in completed:
                        scan = future.result()
                        completed.add(key)
                        for candidate in scan.candidates:
                            store.save(candidate)
                        result.processes.append(scan.summary())
                        emit(
                            "process",
                            f"PID {scan.pid}: {scan.status}",
                            pid=scan.pid,
                            name=names[key],
                            status=str(scan.status),
                            scripts_count=len(scan.candidates),
                            stats=vars(scan.stats),
                        )
                if futures and len(completed) == len(futures):
                    if time.monotonic() >= discovery_until:
                        break
                cancel.wait(min(config.poll_interval, max(0, deadline - time.monotonic())))
        finally:
            worker_stop.set()
            executor.shutdown(wait=True, cancel_futures=True)
            try:
                for key, future in futures.items():
                    if key not in completed and not future.cancelled():
                        scan = future.result()
                        if scan.status == Status.CANCELLED and not cancel.is_set():
                            scan.status = Status.TIMEOUT
                        for candidate in scan.candidates:
                            store.save(candidate)
                        result.processes.append(scan.summary())
            finally:
                session.close()
