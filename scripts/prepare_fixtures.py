"""Build only our own scripts from hash-pinned official AHK runtimes.

Run on Windows. Downloads stay in .test-tools and generated files in .fixtures.
MPRESS is fetched only with --with-mpress from the official Ahk2Exe updater's
mirror. A local MPRESS executable can also be selected with --mpress.
"""

from __future__ import annotations

import argparse
import ctypes as ct
import hashlib
import io
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.request import urlopen

TOOLS = {
    "mpress": (
        "https://github.com/TAC109/Mpress/releases/download/Mpress.219/mpress.219.zip",
        "19ffee93706dff67f83d9ef48c0c794dea761d4459b11c37f9bc65b04af736c5",
    ),
    "v1": (
        "https://github.com/AutoHotkey/AutoHotkey/releases/download/v1.1.37.02/AutoHotkey_1.1.37.02.zip",
        "6f3663f7cdd25063c8c8728f5d9b07813ced8780522fd1f124ba539e2854215f",
    ),
    "v2": (
        "https://github.com/AutoHotkey/AutoHotkey/releases/download/v2.0.30/AutoHotkey_2.0.30.zip",
        "1e0ece7ecb2d5646e55758150472677996a57f9db5c83d2996d8b47b9e2f31a4",
    ),
    "upx": (
        "https://github.com/upx/upx/releases/download/v5.2.1/upx-5.2.1-win64.zip",
        "eabc6792a347d45e945be7748423e7868fd01b0d2bcaa2f4b1031fd71ff69bda",
    ),
}


def download_tool(key, root):
    url, expected = TOOLS[key]
    directory = root / key
    archive_path = root / f"{key}.zip"
    root.mkdir(parents=True, exist_ok=True)
    if not archive_path.is_file():
        with urlopen(url, timeout=60) as response:
            data = response.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"{key}: downloaded archive hash mismatch")
        archive_path.write_bytes(data)
    data = archive_path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"{key}: cached archive hash mismatch")
    directory.mkdir(exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            target = (directory / member.filename).resolve()
            if not target.is_relative_to(directory.resolve()) or member.file_size > 64 * 1024 * 1024:
                raise ValueError("Invalid archive member")
        archive.extractall(directory)
    return directory


def embed_script(base, output, source):
    """Use the standard compiled-script resource on a COPY of a compiled AHK base."""
    from core.winapi import DWORD, HANDLE, WORD, WindowsAPIError, bind

    shutil.copyfile(base, output)
    kernel = ct.WinDLL("kernel32", use_last_error=True)
    begin = bind(kernel, "BeginUpdateResourceW", HANDLE, [ct.c_wchar_p, ct.c_int])
    update = bind(kernel, "UpdateResourceW", ct.c_int, [HANDLE, HANDLE, ct.c_wchar_p, WORD, HANDLE, DWORD])
    end = bind(kernel, "EndUpdateResourceW", ct.c_int, [HANDLE, ct.c_int])
    handle = begin(str(output), False)
    if not handle:
        raise WindowsAPIError("BeginUpdateResourceW", ct.get_last_error())
    data = b"\xef\xbb\xbf" + source.encode("utf-8")
    buffer = ct.create_string_buffer(data)
    if not update(handle, 10, ">AUTOHOTKEY SCRIPT<", 1033, buffer, len(data)):
        error = ct.get_last_error()
        end(handle, True)
        raise WindowsAPIError("UpdateResourceW", error)
    if not end(handle, False):
        raise WindowsAPIError("EndUpdateResourceW", ct.get_last_error())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path, default=Path(".test-tools"))
    parser.add_argument("--output", type=Path, default=Path(".fixtures"))
    parser.add_argument("--mpress", type=Path, help="Optional local MPRESS binary")
    parser.add_argument(
        "--with-mpress", action="store_true", help="Fetch hash-pinned MPRESS from the Ahk2Exe updater mirror"
    )
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        parser.error("Fixture generation requires Windows")
    tools = {
        key: download_tool(key, args.tools.resolve()) for key in TOOLS if key != "mpress" or args.with_mpress
    }
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    upx = next(tools["upx"].rglob("upx.exe"))
    mpress = args.mpress or (next(tools["mpress"].rglob("mpress.exe")) if args.with_mpress else None)
    fixtures = []
    for version in ("v1", "v2"):
        for bits in (32, 64):
            base = tools[version] / (
                f"Compiler/Unicode {bits}-bit.bin" if version == "v1" else f"AutoHotkey{bits}.exe"
            )
            if version == "v1":
                body = '#NoEnv\r\n#SingleInstance Off\r\n#Persistent\r\ntext := "Olá ação € 漢字"\r\nSleep, 60000\r\n'
            else:
                body = '#Requires AutoHotkey v2.0\r\n#SingleInstance Off\r\ntext := "Olá ação € 漢字"\r\nSleep 60000\r\n'
            source = f"; <COMPILER: fixture-{version}-{bits}>\r\n" + body
            source_path = output / f"{version}-{bits}.ahk"
            source_path.write_bytes(source.encode("utf-8"))
            executable = output / f"{version}-{bits}.exe"
            embed_script(base, executable, source)
            fixtures.append(
                {
                    "file": executable.name,
                    "source": source_path.name,
                    "version": version,
                    "bits": bits,
                    "packer": "none",
                }
            )
            packed = output / f"{version}-{bits}-upx.exe"
            subprocess.run([str(upx), "-q", "-o", str(packed), str(executable)], check=True, timeout=60)
            fixtures.append(
                {
                    "file": packed.name,
                    "source": source_path.name,
                    "version": version,
                    "bits": bits,
                    "packer": "UPX",
                }
            )
            if mpress:
                packed = output / f"{version}-{bits}-mpress.exe"
                shutil.copyfile(executable, packed)
                subprocess.run([str(mpress.resolve()), "-x", str(packed)], check=True, timeout=60)
                fixtures.append(
                    {
                        "file": packed.name,
                        "source": source_path.name,
                        "version": version,
                        "bits": bits,
                        "packer": "MPRESS",
                    }
                )
    manifest = {
        "tools": {key: {"url": value[0], "sha256": value[1]} for key, value in TOOLS.items()},
        "upx": str(upx),
        "upx_sha256": hashlib.sha256(upx.read_bytes()).hexdigest(),
        "fixtures": fixtures,
    }
    (output / "fixtures.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Prepared {len(fixtures)} owned fixtures in {output}")


if __name__ == "__main__":
    # Running by path must still find the project's core package.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    main()
