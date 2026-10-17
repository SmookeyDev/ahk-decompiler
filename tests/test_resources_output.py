import json

import pytest

from core.engine import ExtractionEngine, analyze_target
from core.models import Candidate, ExtractionConfig, ExtractionResult, Status
from core.output import OutputStore
from core.resources import PEResourceExtractor, runtime_entries
from tests.pe_fixture import make_pe
from tests.test_detection import SCRIPT


@pytest.mark.parametrize("machine", [0x14C, 0x8664])
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le"])
def test_resources_use_directory_instead_of_section_name(tmp_path, machine, encoding):
    target = tmp_path / "renamed.txt"
    target.write_bytes(make_pe(SCRIPT.encode(encoding), machine=machine))
    info, extractor = analyze_target(target)
    (candidate,) = extractor.candidates()
    assert candidate.text == SCRIPT
    assert candidate.complete
    assert info["architecture"] == ("x64" if machine == 0x8664 else "x86")


def test_virtual_resource_is_not_mapped_to_unrelated_file_bytes(tmp_path):
    target = tmp_path / "packed.exe"
    target.write_bytes(make_pe(b"script", virtual=True))
    extractor = PEResourceExtractor(str(target))
    assert extractor.load_file()
    assert extractor.requires_runtime
    assert not list(extractor.candidates())
    assert extractor.entries[0].reason == "virtual_only"
    result = ExtractionEngine().run(ExtractionConfig(target, tmp_path / "out"))
    assert result.status == Status.RUNTIME_REQUIRED
    assert result.artifacts == []


def test_runtime_uses_virtual_addresses(tmp_path):
    target = tmp_path / "packed.exe"
    target.write_bytes(make_pe(SCRIPT.encode("utf-16-le"), virtual=True))
    extractor = PEResourceExtractor(str(target))
    assert extractor.load_file()
    image = bytearray(0x6000)
    image[:512] = target.read_bytes()[:512]
    image[0x1000:0x1200] = target.read_bytes()[512:1024]
    image[0x4000 : 0x4000 + len(SCRIPT.encode("utf-16-le"))] = SCRIPT.encode("utf-16-le")
    entries = runtime_entries(
        lambda address, length: bytes(image[address - 0x400000 : address - 0x400000 + length]), 0x400000
    )
    assert len(entries) == 1
    assert entries[0].rva == 0x4000
    assert entries[0].name == ">AUTOHOTKEY SCRIPT<"


def test_static_success_never_starts_target_and_preserves_input(tmp_path):
    target = tmp_path / "sample.exe"
    binary = make_pe(SCRIPT.encode())
    target.write_bytes(binary)

    def forbidden(config):
        pytest.fail("Static success must not create a process")

    config = ExtractionConfig(target, tmp_path / "out", mode="auto", allow_execution=True)
    result = ExtractionEngine(session_factory=forbidden).run(config)
    assert result.status == Status.SUCCESS
    assert len(result.artifacts) == 1
    assert target.read_bytes() == binary
    manifest = json.loads((tmp_path / result.output_dir / "manifest.json").read_text())
    assert manifest["status"] == "success"
    assert (tmp_path / result.output_dir / result.artifacts[0]["file"]).read_bytes() == SCRIPT.encode()


def test_invalid_and_oversize_inputs(tmp_path):
    target = tmp_path / "invalid.exe"
    target.write_bytes(b"MZ")
    result = ExtractionEngine().run(ExtractionConfig(target, tmp_path / "out"))
    assert result.status == Status.ERROR
    assert not result.artifacts
    target.write_bytes(make_pe(b"hi"))
    result = ExtractionEngine().run(ExtractionConfig(target, tmp_path / "out", max_file_bytes=100))
    assert result.status == Status.ERROR


def test_output_is_unique_and_deduplicates_with_raw_provenance(tmp_path):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"fixture")
    one = OutputStore(tmp_path / "out", target)
    two = OutputStore(tmp_path / "out", target)
    assert one.directory != two.directory
    one.save(Candidate(SCRIPT, SCRIPT.encode(), "utf-8", "resource"))
    one.save(Candidate(SCRIPT, SCRIPT.encode("utf-16-le"), "utf-16-le", "memory", 1024))
    result = ExtractionResult(status=Status.SUCCESS)
    one.finish(result)
    assert len(result.artifacts) == 1
    assert len(result.artifacts[0]["origins"]) == 2
    for origin in result.artifacts[0]["origins"]:
        assert (one.directory / origin["raw_file"]).is_file()
    assert not list(one.directory.glob("*.tmp"))
