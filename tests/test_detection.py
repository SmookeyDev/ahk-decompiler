import random

import pytest

from core.detection import ScriptScanner, detect_scripts

SCRIPT = "; <COMPILER: v1.1.37.02>\r\n#NoEnv\r\nMsgBox, Olá ação € 漢字\r\nExitApp\r\n"


@pytest.mark.parametrize(
    "encoding,bom",
    [
        ("utf-8", b""),
        ("utf-8", b"\xef\xbb\xbf"),
        ("utf-16-le", b""),
        ("utf-16-le", b"\xff\xfe"),
        ("utf-16-be", b"\xfe\xff"),
    ],
)
def test_unicode_without_hotkeys_is_lossless(encoding, bom):
    data = bom + SCRIPT.encode(encoding)
    end = b"\0\0" if encoding.startswith("utf-16") else b"\0"
    candidates = detect_scripts(b"\x01\x02\x03" + data + end + b"garbage")
    assert len(candidates) == 1
    assert candidates[0].text == SCRIPT
    assert candidates[0].raw == data
    assert candidates[0].complete


def test_resource_utf16_is_not_decoded_as_utf8():
    text = "#NoEnv\n#SingleInstance Force\nMsgBox, ação € 漢字\n"
    result = detect_scripts(text.encode("utf-16-le"), bounded=True, source="resource")
    assert len(result) == 1
    assert result[0].text == text


def test_legacy_codepage_and_continuation_whitespace_are_preserved():
    text = "; <COMPILER: v1.1>\n#NoEnv\nMsgBox, ação €\n(\n  keep spaces  \n\n)\n"
    (candidate,) = detect_scripts(text.encode("cp1252"), bounded=True, codepage=1252)
    assert candidate.text == text


def test_minimal_named_resource_and_v2_without_header():
    (candidate,) = detect_scripts(b'MsgBox "hello"\n', bounded=True, resource_name=">AUTOHOTKEY SCRIPT<")
    assert candidate.complete
    assert detect_scripts(b'#Requires AutoHotkey v2.0\nMsgBox "hello"\n', bounded=True)


def test_binary_and_incidental_strings_are_not_scripts():
    random_bytes = random.Random(42).randbytes(1024 * 100)
    for data in (random_bytes, b"AutoHotkey COMPILER Sleep ::", b"COMPILER\0#NoEnv\0MsgBox, hi\0"):
        assert not detect_scripts(data)


def test_no_terminator_is_partial_and_limits_do_not_fake_completion():
    candidates = detect_scripts(SCRIPT.encode())
    assert candidates and not candidates[0].complete
    candidates = detect_scripts(SCRIPT.encode(), bounded=True, max_script_bytes=40)
    assert not candidates or not candidates[0].complete


def test_multiple_scripts_and_adjacent_chunks():
    scanner = ScriptScanner()
    raw = SCRIPT.encode("utf-16-le") + b"\0\0"
    split = 31
    scanner.feed(0x1001, raw[:split])
    candidates = scanner.feed(0x1001 + split, raw[split:])
    assert len(candidates) == 1 and candidates[0].text == SCRIPT and candidates[0].complete
    candidates = detect_scripts(SCRIPT.encode() + b"\0" + SCRIPT.replace("ação", "outro").encode() + b"\0")
    assert len(candidates) == 2


def test_memory_holes_never_join_unrelated_data():
    scanner = ScriptScanner()
    scanner.feed(0x1000, b"; <COMPILER: v1.1>\n#NoEnv\n")
    assert not scanner.feed(0x5000, b"MsgBox, unrelated\0")
