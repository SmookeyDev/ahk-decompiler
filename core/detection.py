"""Lossless, encoding-aware script detection, independent of Windows."""

from __future__ import annotations

import re

from .models import Candidate

_HEADER = re.compile(r";[ \t]*<COMPILER:[^\r\n>]{1,160}>", re.IGNORECASE)
_DIRECTIVE = re.compile(
    r"(?im)^[ \t]*#(?:NoEnv\b|SingleInstance\b|Persistent\b|Requires[ \t]+AutoHotkey\b|"
    r"Include\b|Warn\b|IfWin\w*\b|HotIf\b|UseHook\b)"
)
_COMMAND = re.compile(
    r"(?im)^[ \t]*(?:SendInput|Send|WinActivate|Sleep|ControlClick|WinWait|IfWinExist|"
    r"Hotkey|Run|MouseClick|SetKeyDelay|MsgBox|SetTimer|FileAppend|ToolTip|ExitApp|"
    r"Return|Pause)(?:[ \t]*[,\(]|[ \t]+[^\r\n]|[ \t]*$)"
)
_HOTKEY = re.compile(r"(?m)^[ \t]*[^\r\n:;]{1,60}::")
_ASSIGNMENT = re.compile(r"(?m)^[ \t]*[A-Za-z_][\w.]*[ \t]*:=")
_ANCHOR = re.compile(
    rb"(?:\A|[\r\n\x00])([ \t]*(?:#(?:NoEnv|SingleInstance|Requires|Persistent|Include|HotIf|Warn)\b|"
    rb"(?:SendInput|WinActivate|Sleep|MsgBox|SetTimer|FileAppend|ExitApp)\b))",
    re.IGNORECASE,
)
_WIDE_ANCHORS = ("#NoEnv", "#SingleInstance", "#Requires", "#Persistent", "#HotIf", "; <COMPILER:")
_SCRIPT_NAMES = {">AUTOHOTKEY SCRIPT<", ">AHK WITH ICON<", "AHK_SCRIPT"}


def is_likely_script(text: str, *, named_resource: bool = False) -> bool:
    if not text or "\x00" in text:
        return False
    printable = sum(c.isprintable() or c in "\r\n\t" for c in text)
    if printable / len(text) < 0.985:
        return False
    signals = (_DIRECTIVE.search(text), _COMMAND.search(text), _HOTKEY.search(text), _ASSIGNMENT.search(text))
    if _HEADER.match(text.lstrip("\ufeff")):
        return bool(text.splitlines()[1:]) and any(signals)
    directive, command, hotkey, assignment = map(bool, signals)
    if named_resource:
        return directive or command or hotkey or assignment
    return (
        (directive and (command or hotkey or assignment))
        or (hotkey and command)
        or (len(_COMMAND.findall(text)) >= 2 and assignment)
    )


def _encoding_order(data: bytes, codepage: int = 0) -> list[str]:
    if data.startswith(b"\xff\xfe"):
        return ["utf-16-le"]
    if data.startswith(b"\xfe\xff"):
        return ["utf-16-be"]
    sample = data[:2048]
    if len(sample) >= 8:
        pairs = len(sample) // 2
        even = sample[: pairs * 2 : 2].count(0) / pairs
        odd = sample[1 : pairs * 2 : 2].count(0) / pairs
        if odd > 0.3 and even < 0.15:
            return ["utf-16-le"]
        if even > 0.3 and odd < 0.15:
            return ["utf-16-be"]
    legacy = f"cp{codepage}" if codepage and codepage not in (65001, 1200, 1201) else "cp1252"
    return list(dict.fromkeys(["utf-8-sig", legacy]))


def _end(data: bytes, start: int, encoding: str, limit: int) -> tuple[int, bool]:
    stop = min(len(data), start + limit)
    if encoding.startswith("utf-16"):
        for pos in range(start, stop - 1, 2):
            if data[pos : pos + 2] == b"\0\0":
                return pos, True
        return stop - ((stop - start) % 2), False
    pos = data.find(b"\0", start, stop)
    return (pos, True) if pos >= 0 else (stop, False)


def detect_scripts(
    data: bytes,
    *,
    source: str = "memory",
    base_offset: int = 0,
    bounded: bool = False,
    resource_name: str = "",
    codepage: int = 0,
    max_script_bytes: int = 16 * 1024 * 1024,
    details: dict | None = None,
) -> list[Candidate]:
    """Only bounded resources or terminated strings are classified as complete."""
    if not data:
        return []
    starts: dict[int, tuple[list[str], bool]] = {}
    for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
        for marker in ("; <COMPILER:", ";<COMPILER:"):
            needle = marker.encode(encoding)
            pos = data.find(needle)
            while pos >= 0:
                if len(starts) >= 256:
                    break
                start = pos
                bom = {"utf-8": b"\xef\xbb\xbf", "utf-16-le": b"\xff\xfe", "utf-16-be": b"\xfe\xff"}[encoding]
                if data[max(0, start - len(bom)) : start] == bom:
                    start -= len(bom)
                encodings = _encoding_order(data[start:], codepage) if encoding == "utf-8" else [encoding]
                starts[start] = (encodings, True)
                pos = data.find(needle, pos + len(needle))
    if bounded:
        starts.setdefault(0, (_encoding_order(data, codepage), False))
    else:
        for match in _ANCHOR.finditer(data):
            if len(starts) >= 256:
                break
            start = match.start(1)
            boundary = data.rfind(b"\0", max(0, start - 4096), start) + 1
            if all(c in (9, 10, 13) or 32 <= c < 127 for c in data[boundary:start]):
                start = boundary
            starts.setdefault(start, (_encoding_order(data[start:], codepage), False))
        for encoding in ("utf-16-le", "utf-16-be"):
            for marker in _WIDE_ANCHORS:
                pos = data.find(marker.encode(encoding))
                while pos >= 0:
                    if len(starts) >= 256:
                        break
                    starts.setdefault(pos, ([encoding], marker.startswith(";")))
                    pos = data.find(marker.encode(encoding), pos + 2)
    found: dict[str, Candidate] = {}
    header_ranges: list[tuple[int, int]] = []
    for start, (encodings, header) in sorted(starts.items(), key=lambda item: (not item[1][1], item[0])):
        if any(low <= start < high for low, high in header_ranges):
            continue
        for encoding in encodings:
            end, terminated = _end(data, start, encoding, max_script_bytes)
            raw = data[start:end]
            if not raw:
                continue
            try:
                text = raw.decode(encoding, errors="strict").removeprefix("\ufeff")
            except UnicodeDecodeError as exc:
                if bounded or terminated or exc.reason != "unexpected end of data" or exc.end != len(raw):
                    continue
                text = raw[: exc.start].decode(encoding, errors="strict").removeprefix("\ufeff")
            except (UnicodeError, LookupError):
                continue
            if not is_likely_script(text, named_resource=resource_name.upper() in _SCRIPT_NAMES):
                continue
            complete = terminated or (bounded and end == len(data) and len(raw) <= max_script_bytes)
            candidate = Candidate(
                text,
                raw,
                encoding,
                source,
                base_offset + start,
                complete,
                "high" if header or resource_name.upper() in _SCRIPT_NAMES else "heuristic",
                details or {},
            )
            found.setdefault(candidate.digest, candidate)
            header_ranges.append((start, end))
            break
    return list(found.values())


class ScriptScanner:
    """Bounded rolling window joining only genuinely contiguous memory reads."""

    def __init__(self, max_script_bytes=16 * 1024 * 1024):
        self.maximum = max_script_bytes
        self.data = b""
        self.base = 0

    def feed(self, address: int, data: bytes, **kwargs) -> list[Candidate]:
        if address != self.base + len(self.data):
            self.data = b""
            self.base = address
        self.data += data
        if len(self.data) > self.maximum:
            excess = len(self.data) - self.maximum
            self.data = self.data[excess:]
            self.base += excess
        candidates = detect_scripts(self.data, base_offset=self.base, max_script_bytes=self.maximum, **kwargs)
        pending = [candidate.offset for candidate in candidates if not candidate.complete]
        keep_from = min(pending) - self.base if pending else max(0, len(self.data) - 4096)
        self.data = self.data[keep_from:]
        self.base += keep_from
        return candidates
