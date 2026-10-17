"""Native API and real AHK fixtures. Unknown issue attachments are never executed here."""

import ctypes as ct
import json
import os
import sys
from pathlib import Path

import pytest

from core.engine import ExtractionEngine
from core.memory import ProcessMemory
from core.models import ExtractionConfig, Status
from core.processes import ProcessSession
from tests.test_detection import SCRIPT

pytestmark = [
    pytest.mark.windows,
    pytest.mark.skipif(sys.platform != "win32", reason="Native Windows API test"),
]


def test_native_pointer_width_and_unicode_read():
    raw = SCRIPT.encode("utf-16-le") + b"\0\0"
    buffer = ct.create_string_buffer(raw)
    with ProcessMemory(os.getpid()) as memory:
        result = memory.read(ct.addressof(buffer), len(raw))
        assert result.data == raw
        assert result.error == 0
        assert memory.module_base() > 0
        assert memory.architecture in ("x86", "x64", "arm64")


def fixture_manifest():
    directory = os.environ.get("AHK_FIXTURES")
    if not directory:
        pytest.skip("Set AHK_FIXTURES after scripts/prepare_fixtures.py to test owned runtimes")
    directory = Path(directory)
    return directory, json.loads((directory / "fixtures.json").read_text())


@pytest.mark.ahk
def test_owned_runtime_matrix_static_and_dynamic(tmp_path):
    directory, manifest = fixture_manifest()
    for fixture in manifest["fixtures"]:
        target = directory / fixture["file"]
        expected = (directory / fixture["source"]).read_bytes().decode("utf-8")
        if fixture["packer"] == "none":
            modes = ["static", "memory"]
        else:
            modes = ["memory"]
        for mode in modes:
            result = ExtractionEngine().run(
                ExtractionConfig(
                    target,
                    tmp_path,
                    mode=mode,
                    allow_execution=mode == "memory",
                    monitor_children=False,
                    timeout=10,
                )
            )
            assert result.status == Status.SUCCESS, result.as_dict()
            recovered = [
                (Path(result.output_dir) / item["file"]).read_bytes().decode("utf-8")
                for item in result.artifacts
            ]
            assert expected in recovered, result.as_dict()
            for process in result.processes:
                import psutil

                assert not psutil.pid_exists(process["pid"]), "Owned process was not reaped"


@pytest.mark.ahk
def test_upx_offline_adapter(tmp_path):
    directory, manifest = fixture_manifest()
    packed = next(f for f in manifest["fixtures"] if f["packer"] == "UPX")
    from core.unpack import unpack_upx
    import threading
    import time
    from core.engine import analyze_target

    config = ExtractionConfig(
        directory / packed["file"],
        tmp_path,
        upx_path=Path(manifest["upx"]),
        upx_sha256=manifest["upx_sha256"],
    )
    unpacked = unpack_upx(config, tmp_path, threading.Event(), time.monotonic() + 20)
    info, _ = analyze_target(unpacked)
    assert info["packer"] == "None"
    result = ExtractionEngine().run(
        ExtractionConfig(
            directory / packed["file"],
            tmp_path,
            upx_path=Path(manifest["upx"]),
            upx_sha256=manifest["upx_sha256"],
            timeout=20,
        )
    )
    assert result.status == Status.SUCCESS, result.as_dict()
    assert not result.processes


@pytest.mark.ahk
def test_owned_child_survives_parent_exit_and_is_recovered(tmp_path):
    directory, manifest = fixture_manifest()
    child = next(
        f for f in manifest["fixtures"] if f["version"] == "v1" and f["bits"] == 64 and f["packer"] == "none"
    )
    from scripts.prepare_fixtures import embed_script

    parent = tmp_path / "parent.exe"
    child_path = directory / child["file"]
    text = (
        '; <COMPILER: parent-fixture>\r\n#NoEnv\r\n#SingleInstance Off\r\nRun, "'
        + str(child_path)
        + '"\r\nSleep, 500\r\nExitApp\r\n'
    )
    embed_script(child_path, parent, text)
    result = ExtractionEngine().run(
        ExtractionConfig(
            parent,
            tmp_path / "out",
            mode="memory",
            allow_execution=True,
            discovery_seconds=2,
            timeout=15,
            poll_interval=0.05,
        )
    )
    assert result.status == Status.SUCCESS, result.as_dict()
    assert len(result.processes) >= 2, result.as_dict()
    assert len(result.artifacts) >= 2, result.as_dict()


def test_attach_session_does_not_terminate_existing_process():
    config = ExtractionConfig(Path(sys.executable), mode="memory", pid=os.getpid(), monitor_children=False)
    session = ProcessSession(config)
    assert not session.owned
    session.close()
    assert session.root.alive()
