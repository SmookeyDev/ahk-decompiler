"""Verify a packaged CLI with our own PE resource fixture, without starting the target."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.pe_fixture import make_pe


def main():
    executable = Path(sys.argv[1]).resolve()
    source = "; <COMPILER: fixture>\r\n#NoEnv\r\nMsgBox, Olá ação € 漢字\r\nExitApp\r\n"
    version = subprocess.run(
        [str(executable), "--version"], check=True, capture_output=True, text=True, timeout=30
    ).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="ahk-packaged-smoke-") as directory:
        root = Path(directory)
        target = root / "fixture.exe"
        original = make_pe(source.encode("utf-16-le"))
        target.write_bytes(original)
        process = subprocess.run(
            [str(executable), "extract", str(target), "--output", str(root / "output")],
            check=True,
            capture_output=True,
            encoding="utf-8",
            timeout=45,
        )
        result = json.loads(process.stdout)
        assert result["status"] == "success", result
        assert not result["processes"], result
        assert len(result["artifacts"]) == 1, result
        artifact = Path(result["output_dir"]) / result["artifacts"][0]["file"]
        assert artifact.read_bytes().decode("utf-8") == source
        assert target.read_bytes() == original
        assert (Path(result["output_dir"]) / "manifest.json").is_file()
    print(f"Packaged CLI {version}: Unicode extraction, manifest and static-only behavior passed")


if __name__ == "__main__":
    main()
