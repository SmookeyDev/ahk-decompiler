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

import struct
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, NamedTuple
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
        """Perform comprehensive PE analysis."""
        path = Path(filepath)
        result = PEAnalysisResult()
        
        if not path.is_file():
            return result
        
        try:
            result.file_size = path.stat().st_size
            
            # Read file data
            with path.open("rb") as f:
                data = f.read()
            
            # Basic PE validation
            if not self._validate_pe(data):
                return result
            
            result.is_pe = True
            
            # Parse PE headers
            dos_header = self._parse_dos_header(data)
            pe_offset = dos_header.get('e_lfanew', 0)
            
            coff_header = self._parse_coff_header(data, pe_offset)
            result.is_64bit = coff_header.get('machine') == 0x8664
            
            optional_header = self._parse_optional_header(data, pe_offset, result.is_64bit)
            result.entry_point = optional_header.get('entry_point', 0)
            result.image_base = optional_header.get('image_base', 0)
            
            # Parse sections
            result.sections = self._parse_sections(data, pe_offset, coff_header.get('num_sections', 0))
            
            # Detect packer
            packer_info = self._detect_packer(data, result.sections)
            result.packer = packer_info[0]
            result.packer_version = packer_info[1]
            result.is_packed = result.packer != PackerType.NONE
            result.confidence = packer_info[2]
            
            # Detect compiler
            compiler_info = self._detect_compiler(data)
            result.compiler = compiler_info[0]
            result.compiler_version = compiler_info[1]
            
            # Calculate overlay size
            result.overlay_size = self._calculate_overlay_size(data, result.sections)
            
            # Additional analysis
            result.additional_info = self._get_additional_info(data, result)
            
        except Exception as e:
            result.additional_info = {"error": str(e)}
        
        return result

    def _validate_pe(self, data: bytes) -> bool:
        """Validate if file is a valid PE."""
        if len(data) < self._dos_header_size:
            return False
        
        if data[:2] != b"MZ":
            return False
        
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 4 > len(data):
                return False
            
            return data[pe_offset:pe_offset + 4] == self._pe_signature
        except:
            return False

    def _parse_dos_header(self, data: bytes) -> Dict:
        """Parse DOS header."""
        if len(data) < self._dos_header_size:
            return {}
        
        return {
            'e_magic': struct.unpack_from("<H", data, 0)[0],
            'e_lfanew': struct.unpack_from("<I", data, 0x3C)[0]
        }

    def _parse_coff_header(self, data: bytes, pe_offset: int) -> Dict:
        """Parse COFF header."""
        try:
            offset = pe_offset + 4  # Skip PE signature
            return {
                'machine': struct.unpack_from("<H", data, offset)[0],
                'num_sections': struct.unpack_from("<H", data, offset + 2)[0],
                'timestamp': struct.unpack_from("<I", data, offset + 4)[0],
                'characteristics': struct.unpack_from("<H", data, offset + 18)[0]
            }
        except:
            return {}

    def _parse_optional_header(self, data: bytes, pe_offset: int, is_64bit: bool) -> Dict:
        """Parse optional header."""
        try:
            offset = pe_offset + 24  # Skip PE signature + COFF header
            
            if is_64bit:
                # PE32+
                return {
                    'entry_point': struct.unpack_from("<I", data, offset + 16)[0],
                    'image_base': struct.unpack_from("<Q", data, offset + 24)[0]
                }
            else:
                # PE32
                return {
                    'entry_point': struct.unpack_from("<I", data, offset + 16)[0],
                    'image_base': struct.unpack_from("<I", data, offset + 28)[0]
                }
        except:
            return {}

    def _parse_sections(self, data: bytes, pe_offset: int, num_sections: int) -> List[SectionInfo]:
        """Parse section headers."""
        sections = []
        
        try:
            # Calculate section table offset
            optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            section_offset = pe_offset + 24 + optional_header_size
            
            for i in range(num_sections):
                offset = section_offset + i * self._section_header_size
                
                if offset + self._section_header_size > len(data):
                    break
                
                name_raw = data[offset:offset + 8].rstrip(b"\x00")
                name = name_raw.decode("ascii", errors="ignore")
                
                virtual_size = struct.unpack_from("<I", data, offset + 8)[0]
                virtual_address = struct.unpack_from("<I", data, offset + 12)[0]
                raw_size = struct.unpack_from("<I", data, offset + 16)[0]
                raw_address = struct.unpack_from("<I", data, offset + 20)[0]
                characteristics = struct.unpack_from("<I", data, offset + 36)[0]
                
                # Calculate entropy for packed detection
                entropy = self._calculate_entropy(data, raw_address, raw_size)
                
                sections.append(SectionInfo(
                    name=name,
                    virtual_address=virtual_address,
                    virtual_size=virtual_size,
                    raw_address=raw_address,
                    raw_size=raw_size,
                    characteristics=characteristics,
                    entropy=entropy
                ))
        except:
            pass
        
        return sections

    def _detect_packer(self, data: bytes, sections: List[SectionInfo]) -> Tuple[PackerType, str, float]:
        """Detect packer using signatures and heuristics."""
        best_match = (PackerType.NONE, "", 0.0)
        
        # Check signature-based detection
        for signature, offset_range, packer_type, version_pattern in self.PACKER_SIGNATURES:
            start, end = offset_range
            search_data = data[start:min(end, len(data))]
            
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
        """Detect compiler using signatures."""
        for signature, compiler_type, version_pattern in self.COMPILER_SIGNATURES:
            if signature in data:
                version = ""
                if version_pattern:
                    match = re.search(version_pattern.encode(), data)
                    if match:
                        version = match.group(1).decode("ascii", errors="ignore")
                return (compiler_type, version)
        
        return (CompilerType.UNKNOWN, "")

    def _calculate_entropy(self, data: bytes, offset: int, size: int) -> float:
        """Calculate Shannon entropy of a data section."""
        if size == 0 or offset >= len(data):
            return 0.0
        
        try:
            section_data = data[offset:offset + min(size, len(data) - offset)]
            if not section_data:
                return 0.0
            
            # Count byte frequencies
            frequencies = [0] * 256
            for byte in section_data:
                frequencies[byte] += 1
            
            # Calculate entropy
            import math
            entropy = 0.0
            length = len(section_data)
            
            for freq in frequencies:
                if freq > 0:
                    p = freq / length
                    entropy -= p * math.log2(p)
            
            return entropy
        except:
            return 0.0

    def _calculate_overlay_size(self, data: bytes, sections: List[SectionInfo]) -> int:
        """Calculate overlay size (data after last section)."""
        if not sections:
            return 0
        
        try:
            last_section = max(sections, key=lambda s: s.raw_address + s.raw_size)
            overlay_start = last_section.raw_address + last_section.raw_size
            return max(0, len(data) - overlay_start)
        except:
            return 0

    def _is_autohotkey_executable(self, data: bytes) -> Tuple[bool, str]:
        """Detect if this is an AutoHotkey executable and get version info."""
        ahk_signatures = [
            b"AutoHotkey",
            b"ahk.exe", 
            b"AutoHotkey.exe",
            b"AHK2Exe",
            b"Ahk2Exe",
            b">AUTOHOTKEY SCRIPT<",
            b"AUTOHOTKEY SCRIPT",
            b"AHK_SCRIPT"
        ]
        
        for signature in ahk_signatures:
            if signature in data:
                # Try to extract version
                version_patterns = [
                    rb"AutoHotkey\s+(\d+\.\d+\.\d+\.\d+)",
                    rb"AutoHotkey\s+v(\d+\.\d+\.\d+)",
                    rb"AHK\s+(\d+\.\d+\.\d+)"
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, data, re.IGNORECASE)
                    if match:
                        return True, match.group(1).decode("ascii", errors="ignore")
                
                return True, ""
        
        return False, ""

    def _get_additional_info(self, data: bytes, result: PEAnalysisResult) -> Dict[str, str]:
        """Get additional analysis information."""
        info = {}
        
        # Check if it's an AutoHotkey executable
        is_ahk, ahk_version = self._is_autohotkey_executable(data)
        if is_ahk:
            info["File Type"] = "AutoHotkey Executable"
            if ahk_version:
                info["AHK Version"] = ahk_version
        else:
            info["File Type"] = "Standard PE Executable"
        
        # Architecture
        if result.is_64bit:
            info["Architecture"] = "x64"
        else:
            info["Architecture"] = "x86"
        
        # Section count
        info["Sections"] = str(len(result.sections))
        
        # Entry point info
        if result.entry_point:
            info["Entry Point"] = f"0x{result.entry_point:08X}"
        
        # Packing status
        if result.is_packed:
            info["Packing Status"] = f"Packed ({result.confidence:.0%} confidence)"
        else:
            info["Packing Status"] = "Not Packed"
        
        # High entropy sections (indicates compression/packing)
        high_entropy = [s.name for s in result.sections if s.entropy > 7.5]
        if high_entropy:
            info["High Entropy Sections"] = ", ".join(high_entropy)
        
        # File size info
        if result.file_size:
            if result.file_size < 1024 * 1024:  # < 1MB
                info["File Size"] = f"{result.file_size // 1024} KB"
            else:
                info["File Size"] = f"{result.file_size // (1024 * 1024)} MB"
        
        # Overlay info
        if result.overlay_size > 0:
            info["Overlay Size"] = f"{result.overlay_size} bytes"
        
        return info


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