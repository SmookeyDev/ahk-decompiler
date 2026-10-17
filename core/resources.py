"""Read PE resources without loading or executing the target image."""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from pathlib import Path

import pefile

from .detection import detect_scripts, is_likely_script
from .output import OutputStore

logger = logging.getLogger(__name__)
RT_RCDATA = 10
MAX_RESOURCE_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class ResourceEntry:
    name: str
    language: int
    rva: int
    size: int
    codepage: int = 0
    data: bytes | None = None
    reason: str = ""

    def metadata(self):
        return {
            "name": self.name,
            "language": self.language,
            "rva": self.rva,
            "size": self.size,
            "codepage": self.codepage,
            "availability": self.reason or "file",
        }


def file_range(pe: pefile.PE, data: bytes, rva: int, size: int) -> tuple[bytes | None, str]:
    """VirtualSize never authorizes reading past SizeOfRawData on disk."""
    if size <= 0 or size > MAX_RESOURCE_BYTES:
        return None, "invalid_size"
    if 0 <= rva < pe.OPTIONAL_HEADER.SizeOfHeaders:
        if rva + size <= min(pe.OPTIONAL_HEADER.SizeOfHeaders, len(data)):
            return data[rva : rva + size], ""
        return None, "invalid_range"
    for section in pe.sections:
        relative = rva - section.VirtualAddress
        if 0 <= relative < max(section.Misc_VirtualSize, section.SizeOfRawData):
            if relative + size > section.SizeOfRawData:
                return None, "virtual_only"
            offset = section.PointerToRawData + relative
            if offset < 0 or offset + size > len(data):
                return None, "truncated_file"
            return data[offset : offset + size], ""
    return None, "unmapped_rva"


class PEResourceExtractor:
    def __init__(self, filepath: str, max_file_bytes: int = MAX_FILE_BYTES):
        self.filepath = str(filepath)
        self.maximum = max_file_bytes
        self.file_data = b""
        self.entries: list[ResourceEntry] = []
        self.diagnostics: list[dict] = []

    def load_file(self) -> bool:
        self.entries.clear()
        self.diagnostics.clear()
        pe = None
        try:
            path = Path(self.filepath)
            if path.stat().st_size > self.maximum:
                raise ValueError("Input exceeds the configured file size limit")
            with path.open("rb") as stream:
                self.file_data = stream.read(self.maximum + 1)
            if len(self.file_data) > self.maximum:
                raise ValueError("Input exceeds the configured file size limit")
            pe = pefile.PE(data=self.file_data, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
            for resource_type in root.entries if root else []:
                if resource_type.id != RT_RCDATA or not hasattr(resource_type, "directory"):
                    continue
                for resource in resource_type.directory.entries:
                    name = str(resource.name) if resource.name is not None else str(resource.id)
                    for language in (
                        getattr(resource, "directory", ()).entries if hasattr(resource, "directory") else []
                    ):
                        if len(self.entries) >= 4096:
                            raise ValueError("Resource count limit (4096) exceeded")
                        if not hasattr(language, "data"):
                            continue
                        entry = language.data.struct
                        content, reason = file_range(pe, self.file_data, entry.OffsetToData, entry.Size)
                        self.entries.append(
                            ResourceEntry(
                                name,
                                language.id or 0,
                                entry.OffsetToData,
                                entry.Size,
                                entry.CodePage,
                                content,
                                reason,
                            )
                        )
            return True
        except (OSError, ValueError, pefile.PEFormatError) as exc:
            self.diagnostics.append({"stage": "resources", "message": str(exc)})
            logger.warning("Resource analysis failed: %s", exc)
            return False
        finally:
            if pe is not None:
                pe.close()

    @property
    def requires_runtime(self) -> bool:
        return any(entry.reason == "virtual_only" for entry in self.entries)

    def extract_rcdata_resources(self) -> list[bytes]:
        return [entry.data for entry in self.entries if entry.data is not None]

    def candidates(self, max_script_bytes=16 * 1024 * 1024):
        for entry in self.entries:
            if entry.data is not None:
                yield from detect_scripts(
                    entry.data,
                    source="resource",
                    bounded=True,
                    base_offset=entry.rva,
                    resource_name=entry.name,
                    codepage=entry.codepage,
                    max_script_bytes=max_script_bytes,
                    details=entry.metadata(),
                )


def extract_scripts_from_resources(filepath: str, output_dir: str) -> int:
    """Compatibility wrapper. Each call receives a unique output directory."""
    extractor = PEResourceExtractor(filepath)
    if not extractor.load_file():
        return 0
    candidates = list(extractor.candidates())
    if not candidates:
        return 0
    from .models import ExtractionResult, Status

    store = OutputStore(Path(output_dir), Path(filepath))
    for candidate in candidates:
        store.save(candidate)
    status = Status.SUCCESS if all(c.complete for c in candidates) else Status.PARTIAL
    store.finish(ExtractionResult(status=status))
    return len(store.artifacts)


def _extract_ahk_from_resource(resource_data: bytes) -> str | None:
    candidates = detect_scripts(resource_data, bounded=True, source="resource")
    return candidates[0].text if candidates else None


def _is_likely_ahk_script(text: str) -> bool:
    return is_likely_script(text)


def _clean_ahk_script(script: str) -> str:
    # Whitespace may be semantically significant in continuation sections.
    return script.removeprefix("\ufeff")


def runtime_entries(read, module_base: int) -> list[ResourceEntry]:
    """Walk the mapped resource directory using RVAs, never disk offsets."""
    header = read(module_base, 4096)
    if len(header) < 64 or header[:2] != b"MZ":
        return []
    pe_offset = struct.unpack_from("<I", header, 60)[0]
    if pe_offset > 64 * 1024:
        return []
    if pe_offset + 264 > len(header):
        header = read(module_base, pe_offset + 264)
    if pe_offset + 264 > len(header) or header[pe_offset : pe_offset + 4] != b"PE\0\0":
        return []
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", header, optional)[0]
    if magic not in (0x10B, 0x20B):
        return []
    directories = optional + (112 if magic == 0x20B else 96)
    rva, size = struct.unpack_from("<II", header, directories + 16)
    if not rva or not 16 <= size <= 4 * 1024 * 1024:
        return []
    blob = read(module_base + rva, size)
    entries: list[ResourceEntry] = []
    visited = set()

    def walk(offset=0, path=()):
        if offset in visited or len(path) > 3 or offset + 16 > len(blob):
            return
        visited.add(offset)
        names, ids = struct.unpack_from("<HH", blob, offset + 12)
        for index in range(min(names + ids, 4096)):
            pos = offset + 16 + index * 8
            if pos + 8 > len(blob) or len(entries) >= 4096:
                return
            identifier, pointer = struct.unpack_from("<II", blob, pos)
            name = identifier
            if identifier & 0x80000000:
                name_offset = identifier & 0x7FFFFFFF
                if name_offset + 2 > len(blob):
                    continue
                length = struct.unpack_from("<H", blob, name_offset)[0]
                if name_offset + 2 + length * 2 > len(blob):
                    continue
                try:
                    name = blob[name_offset + 2 : name_offset + 2 + length * 2].decode("utf-16-le")
                except UnicodeError:
                    continue
            chain = (*path, name)
            if chain[0] != RT_RCDATA:
                continue
            if pointer & 0x80000000:
                walk(pointer & 0x7FFFFFFF, chain)
            elif len(chain) == 3 and pointer + 16 <= len(blob):
                data_rva, data_size, codepage, _ = struct.unpack_from("<IIII", blob, pointer)
                if 0 < data_size <= MAX_RESOURCE_BYTES:
                    entries.append(
                        ResourceEntry(
                            str(chain[1]), int(chain[2]), data_rva, data_size, codepage, reason="runtime"
                        )
                    )

    walk()
    return entries
