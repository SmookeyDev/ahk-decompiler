import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from core.models import ExtractionResult, Status
from tests.pe_fixture import make_pe
from tests.test_detection import SCRIPT


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "main.py", *map(str, args)], capture_output=True, encoding="utf-8", timeout=10
    )


def test_cli_extracts_and_preserves_unicode(tmp_path):
    target = tmp_path / "source.txt"
    target.write_bytes(make_pe(SCRIPT.encode("utf-16-le")))
    process = run_cli("extract", target, "--output", tmp_path / "output")
    assert process.returncode == 0, process.stderr
    result = json.loads(process.stdout)
    artifact = Path(result["output_dir"]) / result["artifacts"][0]["file"]
    assert artifact.read_bytes() == SCRIPT.encode("utf-8")


def test_cli_analysis_exit_codes_and_execution_gate(tmp_path):
    target = tmp_path / "packed.exe"
    target.write_bytes(make_pe(b"not on disk", virtual=True))
    result = run_cli("extract", target, "--output", tmp_path / "out")
    assert result.returncode == 4
    assert json.loads(result.stdout)["status"] == "runtime_required"
    assert run_cli("extract", target, "--mode", "memory").returncode == 2
    assert run_cli("extract", target, "--timeout", "nan").returncode == 1
    assert run_cli("attach", "999999999").returncode == 1
    report = tmp_path / "report.json"
    result = run_cli("analyze", target, "--report", report)
    assert result.returncode == 0 and json.loads(report.read_text())["requires_runtime"]


@pytest.fixture
def gui():
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("Tk display is unavailable")
    root.withdraw()
    from gui.main_window import DumpGUI

    app = DumpGUI(root)
    yield root, app
    if app.running:
        app.stop_extraction()
        app._worker.join(3)
    root.destroy()


def test_gui_static_result_and_current_output_folder(gui, tmp_path):
    root, app = gui
    target = tmp_path / "fixture.exe"
    target.write_bytes(make_pe(SCRIPT.encode("utf-16-le")))
    app.exe = str(target)
    app.output_path.set(str(tmp_path / "out"))
    app.start_dump()
    deadline = time.monotonic() + 3
    while (app.running or app._result is None) and time.monotonic() < deadline:
        root.update()
        time.sleep(0.02)
    assert app._result.status == Status.SUCCESS
    assert app._result.output_dir != str(tmp_path / "out")
    assert app.progress_widget.progressbar["value"] == 100


def test_gui_stop_does_not_enable_start_until_cleanup(gui, monkeypatch, tmp_path):
    root, app = gui
    release = threading.Event()
    started = threading.Event()

    class Engine:
        def run(self, config, cancel, callback):
            started.set()
            cancel.wait(2)
            release.wait(2)
            return ExtractionResult(status=Status.CANCELLED)

    monkeypatch.setattr("gui.main_window.ExtractionEngine", Engine)
    app.exe = str(tmp_path / "fixture.exe")
    app.start_dump()
    assert started.wait(1)
    app.stop_extraction()
    assert str(app.run_button["state"]) == "disabled"
    assert app._cancel.is_set()
    release.set()
    deadline = time.monotonic() + 3
    while (app.running or app._result is None) and time.monotonic() < deadline:
        root.update()
        time.sleep(0.02)
    root.update()
    app._drain()
    assert str(app.run_button["state"]) == "normal"
    assert app.progress_widget.progressbar["value"] == 0
