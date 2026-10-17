# AHK Decompiler

Recover AutoHotkey source retained in PE resources or process memory. Python
3.13+, MIT license. Static analysis is portable; process memory extraction and
the distributed executables require Windows.

## Recovery strategies

The engine first reads RCDATA resources without executing the target. Resource
names, languages, declared lengths and directories in sections with any name are
supported. Virtual-only data is reported as `runtime_required` instead of an
absent script.

Runtime extraction prioritizes resources in the expanded process image, then
scans readable memory. All paths share UTF-8, UTF-16 LE/BE and legacy decoding,
including scripts without hotkeys. Original whitespace is preserved. Recovery
depends on source still being present; recognizing a packer does not imply that
every executable protected by it can be recovered.

## Install and run

Download `ahk-decompiler.exe` (GUI) and `ahk-decompiler-cli.exe` (console) from
[Releases](https://github.com/SmookeyDev/ahk-decompiler/releases). Updated binaries
become available only after a validated tagged release.

```sh
python -m venv .venv
# Activate .venv using your shell's activation command.
python -m pip install -r requirements.txt
python main.py
```

The GUI needs Tkinter; the CLI does not import it. Windows APIs use typed ctypes
bindings initialized only when needed, with no pywin32 dependency.

## GUI modes

| Mode | Behavior |
| --- | --- |
| Static resources | Default. Reads the file without starting the target. |
| Auto | Tries static recovery, then permits target execution if necessary. |
| Memory | Starts the target and reads its memory. |

Select a file, output directory and mode, then start extraction. Choosing Auto
or Memory authorizes target execution. The decompiler is not a sandbox; use a
disposable Windows environment for unknown executables.

Launched processes enter a private Windows Job Object before execution resumes.
Cleanup terminates that owned tree, including descendants whose parent exited.
Stop cancels workers and waits for cleanup before enabling a new run. Updates
arrive through a queue on the UI thread. Zero scripts never means successful
recovery. The output button opens the current session, including diagnostics.

## CLI

From source use `python main.py`; packaged users use `ahk-decompiler-cli.exe`
with the same arguments.

```sh
python main.py analyze program.exe --report analysis.json
python main.py extract program.exe --output recovered
python main.py extract program.exe --mode auto --allow-execution --output recovered
python main.py extract program.exe --mode memory --allow-execution --no-children
python main.py attach 1234 --timeout 15 --output recovered
python main.py extract packed.exe --upx /path/to/upx --upx-sha256 SHA256
```

Static extraction is the default. Attaching reads an existing process and never
terminates it. `--argument=value` passes an argument to a launched target and
may be repeated. File detection uses PE contents rather than the extension.
The optional UPX adapter preserves the input and writes temporary output. The
application never downloads UPX; select a trusted local binary and optionally
enforce its digest. Static success skips both the unpacker and target execution.

JSON goes to UTF-8 stdout; `--verbose` writes progress to stderr. Ctrl+C cancels
workers and performs cleanup.

| Control | Default |
| --- | --- |
| `--timeout` | 30 seconds for runtime extraction |
| `--discovery-seconds` | 3 seconds after the latest new process, bounded by the timeout |
| `--no-children` | Disable discovery and finish when the main scan ends |
| `--max-scan-mib` | 512 MiB shared read budget across processes and retries |
| `--max-script-mib` | 16 MiB per candidate, maximum 64 MiB |
| `--exhaustive` | Continue the memory fallback after finding a complete candidate |

All exact resource ranges are examined. By default, the general memory fallback
stops after a complete candidate. Discovery and extraction run concurrently;
processes that exit before discovery may still be missed. Exhaustive mode retains
the same read and time limits.

| Result | Exit code | Meaning |
| --- | --- | --- |
| `success` | 0 | At least one validated complete candidate was saved. |
| `error` | 1 | Invalid input, output failure or another reported error. |
| `not_found` | 2 | No script found within the reported scan scope. |
| `partial` | 3 | Incomplete candidates or incomplete process results. |
| `runtime_required` | 4 | A necessary runtime strategy was not enabled. |
| `access_denied` | 5 | A native permission failure was recorded. |
| `unsupported` | 6 | Unsupported platform or collector/target architecture. |
| `timeout` | 7 | Runtime deadline expired. |
| `cancelled` | 130 | Cancelled; recovered artifacts remain available. |

Argument syntax errors use argparse's exit code 2. A complete candidate means
its selected resource or string boundary was found. Heuristic memory recovery
needs inspection and does not prove equivalence to an unavailable original.

## Output and diagnosis

Each run creates a unique folder under the selected destination:

```text
recovered/program_<UTC timestamp>_<run-id>/
  script_001_<content-id>.ahk
  <content-id>_<raw-id>.bin
  manifest.json
  events.jsonl
```

Text is saved as UTF-8, preserving whitespace and line endings. Raw variants are
saved separately. Exact copies are deduplicated while retaining their origins,
encodings, addresses, resource metadata and process creation times. Truncated
candidates use `.partial.ahk` names.

The manifest includes input/artifact hashes, application version, process results,
read statistics, limits reached and native errors. Events use UTC timestamps.
Writes are atomic and previous sessions are never overwritten. Source, raw
candidates and diagnostic paths may contain sensitive target data. No telemetry
or automatic uploads are performed.

## Architecture

| Module | Responsibility |
| --- | --- |
| `core/engine.py`, `models.py` | Sessions, immutable configuration and typed results |
| `core/detection.py` | Shared lossless decoder and contiguous streaming windows |
| `core/resources.py` | PE file and mapped runtime resources |
| `core/winapi.py`, `memory.py` | Typed APIs, architecture checks and bounded reads |
| `core/processes.py` | Process identities and Windows Job Object ownership |
| `core/output.py` | Atomic artifacts, deduplication and provenance |
| `core/unpack.py` | Optional local UPX adapter |
| `cli.py`, `gui/` | Presentations over the same service |

The distribution targets an x64 collector. CI tests owned x86/x64 AHK v1.1 and
v2 runtimes. A 32-bit collector rejects wider targets. ARM64 is outside the
validated distribution matrix. MPRESS recovery uses the expanded process image;
no general offline MPRESS decompressor is included. Encrypted, virtualized and
very old AHK formats have no guaranteed recovery strategy.

Original convenience imports remain available, including `core.extract_scripts`,
`core.process_single_pid` and resource extraction. For structured results:

```python
from pathlib import Path
from core.engine import ExtractionEngine
from core.models import ExtractionConfig

result = ExtractionEngine().run(ExtractionConfig(Path('program.exe'), Path('recovered')))
print(result.status, result.artifacts)
```

## Development and verification

```sh
python -m pip install --require-hashes -r requirements-dev.lock
python -m pytest -q
python -m ruff check core cli.py main.py scripts tests utils/pe_analyzer.py gui/main_window.py gui/layout/sections.py gui/components
```

Portable tests construct their own PE files. Windows tests read a known Unicode
buffer and exercise owned process lifecycles. GUI tests withdraw their window
and skip when Tk or a display is unavailable.

Generate owned AHK v1/v2 x86/x64, UPX and MPRESS fixtures on Windows:

```powershell
python scripts/prepare_fixtures.py --with-mpress
$env:AHK_FIXTURES = "$PWD\.fixtures"
python -m pytest -q
```

The generator downloads hash-pinned AutoHotkey and UPX upstream releases.
`--with-mpress` uses the mirror referenced by the official Ahk2Exe updater and
retains its license in `.test-tools/mpress`. Alternatively pass a local binary
with `--mpress C:\tools\mpress.exe`. Tools and generated executables stay outside
Git and application builds. Public CI never executes unknown issue attachments.

Build using a full Windows Python installation with Tk:

```sh
python -m pip install --require-hashes -r requirements-build.lock
python -m PyInstaller --noconfirm ahk-decompiler.spec
python scripts/smoke_packaged.py dist/ahk-decompiler-cli.exe
```

CI runs Python 3.13/3.14 on Linux and Windows, tests the owned runtime matrix on
Windows 3.13, checks Unicode extraction through the packaged CLI and verifies
packaged GUI startup. Tagged publication is gated on those jobs and remains a
separate operation from implementing or reviewing a change.

## Reporting problems

Include the application version and exported diagnostic JSON. Useful evidence
includes the input hash, runtime version if known, collector/target architecture,
packer, mode and native errors. Review diagnostic paths and metadata before sharing.

[Issue #2](https://github.com/SmookeyDev/ahk-decompiler/issues/2) motivated the
Unicode, virtual-resource and zero-result regressions. Its attachment must be
validated separately in a disposable Windows environment before claiming that
specific executable is recovered.
