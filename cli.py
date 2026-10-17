"""Portable analysis and explicit, scriptable extraction."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

import psutil

from core.engine import ExtractionEngine, analyze_target
from core.models import ExtractionConfig, Status
from core.output import file_sha256
from core.version import __version__

EXIT_CODES = {
    Status.SUCCESS: 0,
    Status.NOT_FOUND: 2,
    Status.PARTIAL: 3,
    Status.RUNTIME_REQUIRED: 4,
    Status.ACCESS_DENIED: 5,
    Status.UNSUPPORTED: 6,
    Status.TIMEOUT: 7,
    Status.CANCELLED: 130,
    Status.ERROR: 1,
}


def parser():
    result = argparse.ArgumentParser(description="Recover AutoHotkey source from PE resources and memory")
    result.add_argument("--version", action="version", version=__version__)
    commands = result.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="Inspect a file without executing it")
    analyze.add_argument("target", type=Path)
    analyze.add_argument("--report", type=Path, help="Save the analysis JSON")
    extract = commands.add_parser("extract", help="Extract source; defaults to static resources only")
    extract.add_argument("target", type=Path)
    attach = commands.add_parser("attach", help="Read an existing process; never terminates it")
    attach.add_argument("pid", type=int)
    for command in (extract, attach):
        command.add_argument("--output", type=Path, default=Path("dump_scripts"))
        command.add_argument("--timeout", type=float, default=30)
        command.add_argument("--discovery-seconds", type=float, default=3)
        command.add_argument("--max-scan-mib", type=int, default=512)
        command.add_argument("--max-script-mib", type=int, default=16)
        command.add_argument("--no-children", action="store_true")
        command.add_argument(
            "--exhaustive", action="store_true", help="Continue after finding a complete script"
        )
        command.add_argument("--verbose", action="store_true", help="Write progress to stderr")
    extract.add_argument("--mode", choices=("static", "auto", "memory"), default="static")
    extract.add_argument(
        "--allow-execution", action="store_true", help="Allow starting the target for memory extraction"
    )
    extract.add_argument("--upx", type=Path, help="Optional local UPX executable; no automatic downloads")
    extract.add_argument("--upx-sha256", help="Require this SHA-256 for the selected UPX executable")
    extract.add_argument(
        "--argument", action="append", default=[], help="Argument for the target; may be repeated"
    )
    return result


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    args = parser().parse_args(argv)
    cancel = threading.Event()
    previous = signal.signal(signal.SIGINT, lambda *_: cancel.set())
    try:
        if args.command == "analyze":
            info, _ = analyze_target(args.target)
            info["sha256"] = file_sha256(args.target)
            payload = json.dumps(info, ensure_ascii=False, indent=2)
            if args.report:
                args.report.write_text(payload + "\n", encoding="utf-8")
            print(payload)
            return 0
        if args.command == "attach":
            target = Path(psutil.Process(args.pid).exe())
        else:
            target = args.target
            if args.mode == "memory" and not args.allow_execution:
                parser().error("--mode memory requires --allow-execution; use attach for an existing process")
        config = ExtractionConfig(
            target,
            args.output,
            mode="memory" if args.command == "attach" else args.mode,
            pid=args.pid if args.command == "attach" else None,
            allow_execution=getattr(args, "allow_execution", False),
            timeout=args.timeout,
            discovery_seconds=args.discovery_seconds,
            max_scan_bytes=args.max_scan_mib * 1024 * 1024,
            max_script_bytes=args.max_script_mib * 1024 * 1024,
            monitor_children=not args.no_children,
            exhaustive_memory=args.exhaustive,
            upx_path=getattr(args, "upx", None),
            upx_sha256=getattr(args, "upx_sha256", None),
            arguments=tuple(getattr(args, "argument", ())),
        )

        def progress(event):
            if args.verbose:
                print(event["message"], file=sys.stderr)

        result = ExtractionEngine().run(config, cancel, progress)
        print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
        return EXIT_CODES[result.status]
    except (OSError, ValueError, RuntimeError, psutil.Error) as exc:
        print(json.dumps({"status": "error", "diagnostics": [{"message": str(exc)}]}))
        return 1
    finally:
        signal.signal(signal.SIGINT, previous)


if __name__ == "__main__":
    raise SystemExit(main())
