"""
Advanced PE analyzer for detecting packers, compilers, and file formats.
Similar to Detect It Easy (DiE) functionality.

This module provides comprehensive analysis of PE files including:
- Packer detection (MPRESS, UPX, ASPack, PECompact, etc.)
- Compiler detection (MSVC, GCC, Delphi, etc.)
- File format analysis
- Entry point analysis
- Section analysis
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum


class PackerType(Enum):
    """Known packer types."""

    NONE = "None"
    MPRESS = "MPRESS"
    UPX = "UPX"
    ASPACK = "ASPack"
    PECOMPACT = "PECompact"
    PETITE = "PETite"
    NSPACK = "NSPack"
    PACKMAN = "PackMan"
    THEMIDA = "Themida"
    VMPROTECT = "VMProtect"
    ENIGMA = "Enigma"
    ARMADILLO = "Armadillo"
    ASPROTECT = "ASProtect"
    EXECRYPTOR = "ExeCryptor"
    OBSIDIUM = "Obsidium"
    UNKNOWN = "Unknown Packer"


class CompilerType(Enum):
    """Known compiler types."""

    UNKNOWN = "Unknown"
    MSVC = "Microsoft Visual C++"
    GCC = "GCC"
    DELPHI = "Delphi"
    BORLAND = "Borland C++"
    MINGW = "MinGW"
    AUTOHOTKEY = "AutoHotkey"
    DOTNET = ".NET"
    VB = "Visual Basic"
    WATCOM = "Watcom C++"


@dataclass
class SectionInfo:
    """Information about a PE section."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_address: int
    raw_size: int
    characteristics: int
    entropy: float = 0.0


@dataclass
class PEAnalysisResult:
    """Complete PE analysis result."""

    is_pe: bool = False
    is_64bit: bool = False
    packer: PackerType = PackerType.NONE
    packer_version: str = ""
    compiler: CompilerType = CompilerType.UNKNOWN
    compiler_version: str = ""
    entry_point: int = 0
    image_base: int = 0
    sections: List[SectionInfo] = None
    imports: List[str] = None
    exports: List[str] = None
    resources: List[str] = None
    overlay_size: int = 0
    file_size: int = 0
    is_packed: bool = False
    confidence: float = 0.0
    additional_info: Dict[str, str] = None

    def __post_init__(self):
        if self.sections is None:
            self.sections = []
        if self.imports is None:
            self.imports = []
        if self.exports is None:
            self.exports = []
        if self.resources is None:
            self.resources = []
        if self.additional_info is None:
            self.additional_info = {}


class PEAnalyzer:
    """Advanced PE file analyzer."""

    # Packer signatures - (signature, offset_range, packer_type, version_pattern)
    # Focused on packers commonly used with AutoHotkey executables
    PACKER_SIGNATURES = [
        # MPRESS signatures (very common for AHK)
        (b"MPRESS 2.", (0, 0x400), PackerType.MPRESS, r"MPRESS (\d+\.\d+)"),
        (b".MPRESS", (0, 0x1000), PackerType.MPRESS, ""),
        (b"MPRESS1", (0, 0x1000), PackerType.MPRESS, ""),
        (b"MPRESS2", (0, 0x1000), PackerType.MPRESS, ""),
        # UPX signatures (popular for AHK compression)
        (b"UPX!", (0, 0x1000), PackerType.UPX, r"UPX (\d+\.\d+)"),
        (b"$Info: This file is packed with the UPX", (0, 0x1000), PackerType.UPX, ""),
        (b".UPX0", (0, 0x1000), PackerType.UPX, ""),
        (b".UPX1", (0, 0x1000), PackerType.UPX, ""),
        (b"UPX0", (0, 0x1000), PackerType.UPX, ""),
        (b"UPX1", (0, 0x1000), PackerType.UPX, ""),
        (b"UPX2", (0, 0x1000), PackerType.UPX, ""),
        # ASPack signatures (sometimes used for AHK)
        (b"aPLib", (0, 0x1000), PackerType.ASPACK, ""),
        (b".aspack", (0, 0x1000), PackerType.ASPACK, ""),
        (b".adata", (0, 0x1000), PackerType.ASPACK, ""),
        (b"ASPack", (0, 0x2000), PackerType.ASPACK, r"ASPack (\d+\.\d+)"),
        # PECompact signatures (used for AHK compression)
        (b"PECompact2", (0, 0x1000), PackerType.PECOMPACT, r"PECompact(\d+)"),
        (b".pcmp", (0, 0x1000), PackerType.PECOMPACT, ""),
        (b"PEC2TO", (0, 0x1000), PackerType.PECOMPACT, ""),
        (b"PEC2", (0, 0x1000), PackerType.PECOMPACT, ""),
        # PETite signatures (lightweight packer for AHK)
        (b".petite", (0, 0x1000), PackerType.PETITE, ""),
        (b"petite", (0, 0x1000), PackerType.PETITE, ""),
        (b"PETite", (0, 0x1000), PackerType.PETITE, r"PETite (\d+\.\d+)"),
        # NSPack signatures (sometimes used)
        (b".nsp0", (0, 0x1000), PackerType.NSPACK, ""),
        (b".nsp1", (0, 0x1000), PackerType.NSPACK, ""),
        (b".nsp2", (0, 0x1000), PackerType.NSPACK, ""),
        (b"NsPacK", (0, 0x1000), PackerType.NSPACK, ""),
        # Themida signatures (advanced protection, less common for AHK)
        (b".themida", (0, 0x1000), PackerType.THEMIDA, ""),
        (b"Themida", (0, 0x2000), PackerType.THEMIDA, ""),
        # VMProtect signatures (advanced protection)
        (b".vmp0", (0, 0x1000), PackerType.VMPROTECT, ""),
        (b".vmp1", (0, 0x1000), PackerType.VMPROTECT, ""),
        (b"VMProtect", (0, 0x2000), PackerType.VMPROTECT, ""),
        # Enigma signatures (commercial protector)
        (b".enigma1", (0, 0x1000), PackerType.ENIGMA, ""),
        (b".enigma2", (0, 0x1000), PackerType.ENIGMA, ""),
        (b"Enigma", (0, 0x2000), PackerType.ENIGMA, ""),
        # ASProtect signatures
        (b".aspr", (0, 0x1000), PackerType.ASPROTECT, ""),
        (b"ASProtect", (0, 0x2000), PackerType.ASPROTECT, ""),
        # ExeCryptor signatures
        (b".ecr", (0, 0x1000), PackerType.EXECRYPTOR, ""),
        (b"ExeCryptor", (0, 0x2000), PackerType.EXECRYPTOR, ""),
        # Obsidium signatures
        (b".obsidium", (0, 0x1000), PackerType.OBSIDIUM, ""),
        (b"Obsidium", (0, 0x2000), PackerType.OBSIDIUM, ""),
    ]

    # Compiler signatures - focused on AutoHotkey and common compilers
    COMPILER_SIGNATURES = [
        # AutoHotkey signatures (primary focus)
        (b"AutoHotkey", CompilerType.AUTOHOTKEY, r"(\d+\.\d+\.\d+\.\d+)"),
        (b"ahk.exe", CompilerType.AUTOHOTKEY, ""),
        (b"AutoHotkey.exe", CompilerType.AUTOHOTKEY, ""),
        (b"AHK2Exe", CompilerType.AUTOHOTKEY, ""),
        (b"Ahk2Exe", CompilerType.AUTOHOTKEY, ""),
        (b">AUTOHOTKEY SCRIPT<", CompilerType.AUTOHOTKEY, ""),
        (b"AUTOHOTKEY SCRIPT", CompilerType.AUTOHOTKEY, ""),
        (b"AHK_SCRIPT", CompilerType.AUTOHOTKEY, ""),
        # Microsoft Visual C++ (used by AHK compiler)
        (b"Microsoft (R) 32-bit C/C++", CompilerType.MSVC, r"(\d+\.\d+)"),
        (b"Microsoft (R) C/C++", CompilerType.MSVC, r"(\d+\.\d+)"),
        (b"MSVCRT.dll", CompilerType.MSVC, ""),
        (b"MSVCR", CompilerType.MSVC, ""),
        # GCC/MinGW (alternative compilers)
        (b"GCC: (GNU)", CompilerType.GCC, r"(\d+\.\d+\.\d+)"),
        (b"libgcc", CompilerType.GCC, ""),
        (b"mingw", CompilerType.MINGW, ""),
        (b"MinGW", CompilerType.MINGW, ""),
        # Delphi (some AHK tools use Delphi)
        (b"Borland Delphi", CompilerType.DELPHI, r"(\d+\.\d+)"),
        (b"Embarcadero Delphi", CompilerType.DELPHI, r"(\d+\.\d+)"),
        # .NET (less common for AHK)
        (b"mscoree.dll", CompilerType.DOTNET, ""),
        (b".NET Framework", CompilerType.DOTNET, r"(\d+\.\d+)"),
        # Visual Basic (legacy)
        (b"VB5!", CompilerType.VB, "5.0"),
        (b"VB6!", CompilerType.VB, "6.0"),
        (b"MSVBVM", CompilerType.VB, ""),
    ]

    def __init__(self):
        self._pe_signature = b"PE\x00\x00"
        self._dos_header_size = 64
        self._section_header_size = 40

    def analyze_file(self, filepath: str | Path) -> PEAnalysisResult:
        """Analyze headers through pefile; signatures are labelled as heuristics."""
        import pefile

        path = Path(filepath)
        result = PEAnalysisResult()
        pe = None
        try:
            result.file_size = path.stat().st_size
            if result.file_size > 512 * 1024 * 1024:
                raise ValueError("Input exceeds the 512 MiB analysis limit")
            with path.open('rb') as stream:
                data = stream.read(512 * 1024 * 1024 + 1)
            if len(data) > 512 * 1024 * 1024:
                raise ValueError('Input grew beyond the 512 MiB analysis limit')
            pe = pefile.PE(data=data, fast_load=True)
            result.is_pe = True
            machine = pe.FILE_HEADER.Machine
            result.is_64bit = pe.OPTIONAL_HEADER.Magic == 0x20B
            result.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            result.image_base = pe.OPTIONAL_HEADER.ImageBase
            result.sections = [
                SectionInfo(
                    section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                    section.VirtualAddress,
                    section.Misc_VirtualSize,
                    section.PointerToRawData,
                    section.SizeOfRawData,
                    section.Characteristics,
                    section.get_entropy(),
                )
                for section in pe.sections
            ]
            result.packer, result.packer_version, result.confidence = self._detect_packer(
                data, result.sections
            )
            result.is_packed = result.packer != PackerType.NONE
            result.compiler, _ = self._detect_compiler(data)
            is_ahk = any(
                marker in data or marker.decode().encode("utf-16-le") in data
                for marker in (b"AutoHotkey", b">AUTOHOTKEY SCRIPT<", b"Ahk2Exe")
            )
            if is_ahk:
                result.compiler = CompilerType.AUTOHOTKEY
            # Version comes from version resources, not an unrelated version-like string.
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            runtime_version = ""
            for group in getattr(pe, "FileInfo", []):
                for info in group:
                    for table in getattr(info, "StringTable", []):
                        values = {
                            key.decode(errors="replace"): value.decode(errors="replace")
                            for key, value in table.entries.items()
                        }
                        if "AutoHotkey" in values.get("ProductName", ""):
                            runtime_version = values.get("ProductVersion", "")
            result.compiler_version = runtime_version if is_ahk else ""
            result.overlay_size = self._calculate_overlay_size(data, result.sections)
            result.additional_info = {
                "File Type": "AutoHotkey Executable" if is_ahk else "Standard PE Executable",
                "Architecture": {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}.get(machine, "unknown"),
                "Sections": str(len(result.sections)),
                "Entry Point": f"0x{result.entry_point:X}",
                "Packing Status": "Packed (heuristic)" if result.is_packed else "Not Packed",
                "File Size": f"{result.file_size:,} bytes",
            }
            if runtime_version:
                result.additional_info["AHK Version"] = runtime_version
        except (OSError, ValueError, pefile.PEFormatError) as exc:
            result.additional_info = {"error": str(exc)}
        finally:
            if pe is not None:
                pe.close()
        return result

    def _detect_packer(self, data: bytes, sections: List[SectionInfo]) -> Tuple[PackerType, str, float]:
        """Detect packer using signatures and heuristics."""
        best_match = (PackerType.NONE, "", 0.0)

        # Check signature-based detection
        for signature, offset_range, packer_type, version_pattern in self.PACKER_SIGNATURES:
            start, end = offset_range
            search_data = data[start : min(end, len(data))]

            if signature in search_data:
                version = ""
                confidence = 0.8

                # Try to extract version
                if version_pattern:
                    match = re.search(version_pattern.encode(), search_data)
                    if match:
                        version = match.group(1).decode("ascii", errors="ignore")
                        confidence = 0.9

                if confidence > best_match[2]:
                    best_match = (packer_type, version, confidence)

        # Check section-based detection
        section_confidence = self._detect_packer_by_sections(sections)
        if section_confidence[2] > best_match[2]:
            best_match = section_confidence

        # Heuristic detection based on entropy and section characteristics
        heuristic_confidence = self._detect_packer_heuristic(sections)
        if heuristic_confidence[2] > best_match[2]:
            best_match = heuristic_confidence

        return best_match

    def _detect_packer_by_sections(self, sections: List[SectionInfo]) -> Tuple[PackerType, str, float]:
        """Detect packer by section names and characteristics."""
        section_names = [s.name.upper() for s in sections]

        # UPX detection
        if any(name.startswith("UPX") for name in section_names):
            return (PackerType.UPX, "", 0.9)

        # MPRESS detection
        if any(name.startswith(".MPRESS") for name in section_names):
            return (PackerType.MPRESS, "", 0.9)

        # ASPack detection
        if ".aspack" in [s.name.lower() for s in sections]:
            return (PackerType.ASPACK, "", 0.9)

        # PECompact detection
        if ".pcmp" in [s.name.lower() for s in sections]:
            return (PackerType.PECOMPACT, "", 0.9)

        return (PackerType.NONE, "", 0.0)

    def _detect_packer_heuristic(self, sections: List[SectionInfo]) -> Tuple[PackerType, str, float]:
        """Heuristic packer detection based on entropy and section characteristics."""
        if not sections:
            return (PackerType.NONE, "", 0.0)

        # Check for high entropy sections (typical of packed files)
        high_entropy_sections = [s for s in sections if s.entropy > 7.5]

        # Check for unusual section characteristics
        executable_sections = [s for s in sections if s.characteristics & 0x20000000]  # IMAGE_SCN_MEM_EXECUTE

        if len(high_entropy_sections) > 0 and len(executable_sections) == 1:
            # Likely packed - single executable section with high entropy
            if len(sections) <= 3:  # Few sections is also suspicious
                return (PackerType.UNKNOWN, "", 0.6)

        return (PackerType.NONE, "", 0.0)

    def _detect_compiler(self, data: bytes) -> Tuple[CompilerType, str]:
        for signature, compiler, _ in self.COMPILER_SIGNATURES:
            if signature in data:
                return compiler, ""
        return CompilerType.UNKNOWN, ""

    def _calculate_overlay_size(self, data: bytes, sections: List[SectionInfo]) -> int:
        """Calculate overlay size (data after last section)."""
        if not sections:
            return 0

        try:
            last_section = max(sections, key=lambda s: s.raw_address + s.raw_size)
            overlay_start = last_section.raw_address + last_section.raw_size
            return max(0, len(data) - overlay_start)
        except Exception:
            return 0


# Convenience functions for backward compatibility
def is_mpress_packed(filepath: str | Path) -> bool:
    """Check if file is packed with MPRESS (backward compatibility)."""
    analyzer = PEAnalyzer()
    result = analyzer.analyze_file(filepath)
    return result.packer == PackerType.MPRESS


def analyze_pe_file(filepath: str | Path) -> PEAnalysisResult:
    """Analyze PE file and return comprehensive results."""
    analyzer = PEAnalyzer()
    return analyzer.analyze_file(filepath)


def get_packer_info(filepath: str | Path) -> Tuple[str, str]:
    """Get packer name and version (simplified interface)."""
    result = analyze_pe_file(filepath)
    return (result.packer.value, result.packer_version)


def is_packed(filepath: str | Path) -> bool:
    """Check if file is packed with any known packer."""
    result = analyze_pe_file(filepath)
    return result.is_packed
