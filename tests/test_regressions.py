import threading

from core.detection import ScriptScanner, detect_scripts
from core.engine import ExtractionEngine
from core.models import Candidate, ExtractionConfig, ExtractionResult, Status
from core.output import OutputStore
from tests.pe_fixture import make_pe


def test_multibyte_split_after_large_preamble():
    text = '; <COMPILER: v1.1>\n#NoEnv\ntext := "' + ("a" * 8000) + '漢字"\nExitApp\n'
    raw = text.encode() + b"\0"
    split = raw.index("漢".encode()) + 1
    scanner = ScriptScanner()
    partial = scanner.feed(4096, raw[:split])
    assert partial and not partial[0].complete
    complete = scanner.feed(4096 + split, raw[split:])
    assert complete[0].complete and complete[0].text == text


def test_detection_does_not_return_every_line_as_a_separate_script():
    text = '#Requires AutoHotkey v2.0\nMsgBox "hi"\n' + ("Sleep 1\n" * 10000)
    result = detect_scripts(text.encode(), bounded=True)
    assert len(result) == 1
    assert result[0].text == text


def test_partial_output_is_upgraded_atomically(tmp_path):
    source = tmp_path / "test.exe"
    source.write_bytes(b"fixture")
    store = OutputStore(tmp_path / "out", source)
    text = "#NoEnv\nMsgBox, hello\n"
    store.save(Candidate(text, text.encode(), "utf-8", "memory", complete=False))
    store.save(Candidate(text, text.encode(), "utf-8", "memory", complete=True))
    result = ExtractionResult(status=Status.SUCCESS)
    store.finish(result)
    assert ".partial" not in result.artifacts[0]["file"]
    assert len(list(store.directory.glob("*.ahk"))) == 1


def test_cancel_during_static_phase_is_not_success(tmp_path):
    path = tmp_path / "fixture.exe"
    path.write_bytes(make_pe(b"#NoEnv\nMsgBox, hi\n"))
    cancel = threading.Event()

    def event(payload):
        if payload["kind"] == "phase":
            cancel.set()

    result = ExtractionEngine().run(ExtractionConfig(path, tmp_path / "out"), cancel, event)
    assert result.status == Status.CANCELLED
