"""
Resource extraction functionality for AutoHotkey decompilation.

This module provides functionality to extract RCDATA resources from
executable files, which often contain embedded AHK scripts.
"""

import os
import re
import struct
import logging
from typing import List, Dict, Optional, Tuple

# PE file constants
PE_SIGNATURE = b'PE\x00\x00'
DOS_HEADER_SIZE = 64
IMAGE_NT_HEADERS_SIZE = 24
SECTION_HEADER_SIZE = 40

# Resource directory constants
RT_RCDATA = 10  # RCDATA resource type
IMAGE_RESOURCE_DIRECTORY_SIZE = 16
IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE = 8


class PEResourceExtractor:
    """Extract resources from PE executable files."""
    
    def __init__(self, filepath: str):
        """Initialize the PE resource extractor."""
        self.filepath = filepath
        self.file_data = None
        self.pe_offset = 0
        self.sections = []
        self.resource_section = None
        
    def load_file(self) -> bool:
        """Load the PE file into memory."""
        try:
            with open(self.filepath, 'rb') as f:
                self.file_data = f.read()
            return self._parse_pe_headers()
        except Exception as e:
            logging.error(f"Failed to load file {self.filepath}: {e}")
            return False
    
    def _parse_pe_headers(self) -> bool:
        """Parse PE headers to locate resource section."""
        try:
            # Check DOS header
            if len(self.file_data) < DOS_HEADER_SIZE:
                return False
                
            if self.file_data[:2] != b'MZ':
                return False
                
            # Get PE offset from DOS header
            self.pe_offset = struct.unpack('<I', self.file_data[60:64])[0]
            
            # Check PE signature
            if len(self.file_data) < self.pe_offset + 4:
                return False
                
            if self.file_data[self.pe_offset:self.pe_offset + 4] != PE_SIGNATURE:
                return False
                
            # Parse COFF header to get number of sections
            coff_offset = self.pe_offset + 4
            if len(self.file_data) < coff_offset + 20:
                return False
                
            num_sections = struct.unpack('<H', self.file_data[coff_offset + 2:coff_offset + 4])[0]
            optional_header_size = struct.unpack('<H', self.file_data[coff_offset + 16:coff_offset + 18])[0]
            
            # Parse sections
            sections_offset = coff_offset + 20 + optional_header_size
            for i in range(num_sections):
                section_offset = sections_offset + (i * SECTION_HEADER_SIZE)
                if len(self.file_data) < section_offset + SECTION_HEADER_SIZE:
                    break
                    
                section_data = self.file_data[section_offset:section_offset + SECTION_HEADER_SIZE]
                section_name = section_data[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                virtual_size = struct.unpack('<I', section_data[8:12])[0]
                virtual_address = struct.unpack('<I', section_data[12:16])[0]
                raw_size = struct.unpack('<I', section_data[16:20])[0]
                raw_offset = struct.unpack('<I', section_data[20:24])[0]
                
                section_info = {
                    'name': section_name,
                    'virtual_address': virtual_address,
                    'virtual_size': virtual_size,
                    'raw_offset': raw_offset,
                    'raw_size': raw_size
                }
                
                self.sections.append(section_info)
                
                # Check if this is the resource section
                if section_name == '.rsrc':
                    self.resource_section = section_info
                    
            return True
            
        except Exception as e:
            logging.error(f"Error parsing PE headers: {e}")
            return False
    
    def extract_rcdata_resources(self) -> List[bytes]:
        """Extract all RCDATA resources from the executable."""
        if not self.resource_section:
            logging.warning("No resource section found")
            return []
            
        try:
            resources = []
            rsrc_offset = self.resource_section['raw_offset']
            rsrc_size = self.resource_section['raw_size']
            
            if len(self.file_data) < rsrc_offset + rsrc_size:
                logging.error("Resource section extends beyond file")
                return []
                
            rsrc_data = self.file_data[rsrc_offset:rsrc_offset + rsrc_size]
            
            # Parse resource directory
            rcdata_resources = self._parse_resource_directory(rsrc_data, rsrc_offset)
            
            for resource_rva, size in rcdata_resources:
                # Convert RVA to file offset
                file_offset = self._rva_to_file_offset(resource_rva)
                if file_offset and file_offset + size <= len(self.file_data):
                    resource_data = self.file_data[file_offset:file_offset + size]
                    resources.append(resource_data)
                    
            return resources
            
        except Exception as e:
            logging.error(f"Error extracting RCDATA resources: {e}")
            return []
    
    def _parse_resource_directory(self, rsrc_data: bytes, rsrc_base_offset: int) -> List[Tuple[int, int]]:
        """Parse resource directory to find RCDATA entries."""
        resources = []
        
        try:
            if len(rsrc_data) < IMAGE_RESOURCE_DIRECTORY_SIZE:
                return resources
                
            # Parse root directory
            num_name_entries = struct.unpack('<H', rsrc_data[12:14])[0]
            num_id_entries = struct.unpack('<H', rsrc_data[14:16])[0]
            
            # Look for RCDATA entries (RT_RCDATA = 10)
            entry_offset = IMAGE_RESOURCE_DIRECTORY_SIZE
            
            for i in range(num_name_entries + num_id_entries):
                if entry_offset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE > len(rsrc_data):
                    break
                    
                entry_data = rsrc_data[entry_offset:entry_offset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE]
                resource_id = struct.unpack('<I', entry_data[:4])[0]
                entry_rva = struct.unpack('<I', entry_data[4:8])[0]
                
                # Check if this is RCDATA
                if resource_id == RT_RCDATA:
                    # Parse second level directory
                    if entry_rva & 0x80000000:  # High bit set means it's a directory
                        dir_offset = entry_rva & 0x7FFFFFFF
                        sub_resources = self._parse_sub_directory(rsrc_data, dir_offset, rsrc_base_offset)
                        resources.extend(sub_resources)
                
                entry_offset += IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
                
        except Exception as e:
            logging.error(f"Error parsing resource directory: {e}")
            
        return resources
    
    def _parse_sub_directory(self, rsrc_data: bytes, dir_offset: int, rsrc_base_offset: int) -> List[Tuple[int, int]]:
        """Parse subdirectory for actual resource data."""
        resources = []
        
        try:
            if dir_offset + IMAGE_RESOURCE_DIRECTORY_SIZE > len(rsrc_data):
                return resources
                
            dir_data = rsrc_data[dir_offset:dir_offset + IMAGE_RESOURCE_DIRECTORY_SIZE]
            num_name_entries = struct.unpack('<H', dir_data[12:14])[0]
            num_id_entries = struct.unpack('<H', dir_data[14:16])[0]
            
            entry_offset = dir_offset + IMAGE_RESOURCE_DIRECTORY_SIZE
            
            for i in range(num_name_entries + num_id_entries):
                if entry_offset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE > len(rsrc_data):
                    break
                    
                entry_data = rsrc_data[entry_offset:entry_offset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE]
                entry_rva = struct.unpack('<I', entry_data[4:8])[0]
                
                if entry_rva & 0x80000000:  # Another directory level
                    lang_dir_offset = entry_rva & 0x7FFFFFFF
                    lang_resources = self._parse_language_directory(rsrc_data, lang_dir_offset, rsrc_base_offset)
                    resources.extend(lang_resources)
                else:
                    # Direct data entry
                    data_entry_offset = entry_rva
                    if data_entry_offset + 16 <= len(rsrc_data):
                        data_entry = rsrc_data[data_entry_offset:data_entry_offset + 16]
                        data_rva = struct.unpack('<I', data_entry[:4])[0]
                        data_size = struct.unpack('<I', data_entry[4:8])[0]
                        resources.append((data_rva, data_size))
                
                entry_offset += IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
                
        except Exception as e:
            logging.error(f"Error parsing subdirectory: {e}")
            
        return resources
    
    def _parse_language_directory(self, rsrc_data: bytes, dir_offset: int, rsrc_base_offset: int) -> List[Tuple[int, int]]:
        """Parse language directory for resource data entries."""
        resources = []
        
        try:
            if dir_offset + IMAGE_RESOURCE_DIRECTORY_SIZE > len(rsrc_data):
                return resources
                
            dir_data = rsrc_data[dir_offset:dir_offset + IMAGE_RESOURCE_DIRECTORY_SIZE]
            num_name_entries = struct.unpack('<H', dir_data[12:14])[0]
            num_id_entries = struct.unpack('<H', dir_data[14:16])[0]
            
            entry_offset = dir_offset + IMAGE_RESOURCE_DIRECTORY_SIZE
            
            for i in range(num_name_entries + num_id_entries):
                if entry_offset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE > len(rsrc_data):
                    break
                    
                entry_data = rsrc_data[entry_offset:entry_offset + IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE]
                entry_rva = struct.unpack('<I', entry_data[4:8])[0]
                
                # This should be a data entry
                data_entry_offset = entry_rva
                if data_entry_offset + 16 <= len(rsrc_data):
                    data_entry = rsrc_data[data_entry_offset:data_entry_offset + 16]
                    data_rva = struct.unpack('<I', data_entry[:4])[0]
                    data_size = struct.unpack('<I', data_entry[4:8])[0]
                    resources.append((data_rva, data_size))
                
                entry_offset += IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE
                
        except Exception as e:
            logging.error(f"Error parsing language directory: {e}")
            
        return resources
    
    def _rva_to_file_offset(self, rva: int) -> Optional[int]:
        """Convert RVA (Relative Virtual Address) to file offset."""
        for section in self.sections:
            va_start = section['virtual_address']
            va_end = va_start + section['virtual_size']
            
            if va_start <= rva < va_end:
                offset_in_section = rva - va_start
                return section['raw_offset'] + offset_in_section
                
        return None


def extract_scripts_from_resources(filepath: str, output_dir: str) -> int:
    """
    Extract AHK scripts from RCDATA resources in an executable.
    
    Args:
        filepath (str): Path to the executable file
        output_dir (str): Output directory for extracted scripts
        
    Returns:
        int: Number of scripts extracted
    """
    os.makedirs(output_dir, exist_ok=True)
    
    extractor = PEResourceExtractor(filepath)
    if not extractor.load_file():
        logging.error("Failed to load PE file")
        return 0
    
    resources = extractor.extract_rcdata_resources()
    scripts_found = 0
    
    for i, resource_data in enumerate(resources):
        try:
            # Try to detect AHK scripts in the resource data
            script_content = _extract_ahk_from_resource(resource_data)
            
            if script_content:
                scripts_found += 1
                filename = f"{output_dir}/script_resource_{i+1}.ahk"
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(script_content)
                    
                logging.info(f"Extracted script from resource {i+1}: {len(script_content)} characters")
                
        except Exception as e:
            logging.error(f"Error processing resource {i+1}: {e}")
    
    return scripts_found


def _extract_ahk_from_resource(resource_data: bytes) -> Optional[str]:
    """
    Extract AHK script content from resource data.
    
    Args:
        resource_data (bytes): Raw resource data
        
    Returns:
        Optional[str]: AHK script content if found, None otherwise
    """
    try:
        # Method 1: Look for null-terminated string
        null_pos = resource_data.find(b'\x00\x00')
        if null_pos > 0:
            text_data = resource_data[:null_pos]
        else:
            text_data = resource_data
            
        # Try different encodings
        for encoding in ['utf-8', 'utf-16-le', 'latin-1', 'cp1252']:
            try:
                decoded_text = text_data.decode(encoding, errors='ignore')
                
                # Clean up the text
                decoded_text = decoded_text.replace('\x00', '').strip()
                
                if _is_likely_ahk_script(decoded_text):
                    return _clean_ahk_script(decoded_text)
                    
            except UnicodeDecodeError:
                continue
                
        # Method 2: Look for compressed/encoded data
        if len(resource_data) > 100:
            # Check for patterns that might indicate compressed AHK scripts
            patterns = [
                b'AutoHotkey',
                b'SendInput',
                b'WinActivate', 
                b'#NoEnv',
                b'#SingleInstance',
                b'::',
                b'Sleep,',
                b'Run,'
            ]
            
            pattern_count = sum(1 for pattern in patterns if pattern.lower() in resource_data.lower())
            
            if pattern_count >= 2:
                # Try to extract readable text
                readable_text = ""
                for byte in resource_data:
                    if 32 <= byte <= 126:  # Printable ASCII
                        readable_text += chr(byte)
                    elif byte in [9, 10, 13]:  # Tab, LF, CR
                        readable_text += chr(byte)
                    else:
                        readable_text += " "
                
                # Clean up and check again
                cleaned_text = re.sub(r'\s+', ' ', readable_text).strip()
                if len(cleaned_text) > 50 and _is_likely_ahk_script(cleaned_text):
                    return _clean_ahk_script(cleaned_text)
                    
    except Exception as e:
        logging.error(f"Error extracting AHK from resource: {e}")
        
    return None


def _is_likely_ahk_script(text: str) -> bool:
    """
    Determine if text is likely an AutoHotkey script.
    
    Args:
        text (str): Text to analyze
        
    Returns:
        bool: True if likely AHK script, False otherwise
    """
    if len(text) < 20:
        return False
        
    # Look for AHK-specific patterns
    ahk_indicators = [
        r'#NoEnv',
        r'#SingleInstance',
        r'#Include',
        r'SendInput\s*[,\(]',
        r'WinActivate\s*[,\(]',
        r'Sleep\s*[,\(]',
        r'ControlClick\s*[,\(]',
        r'WinWait\s*[,\(]',
        r'IfWinExist\s*[,\(]',
        r'Loop\s*[,\(]',
        r'Hotkey\s*[,\(]',
        r'::[^:]+::',  # Hotkey syntax
        r'^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*:=',  # Variable assignment
        r'Run\s*[,\(]',
        r'MouseClick\s*[,\(]',
        r'SetKeyDelay\s*[,\(]'
    ]
    
    matches = 0
    for pattern in ahk_indicators:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            matches += 1
            
    # Need at least 2 AHK patterns to consider it a script
    return matches >= 2


def _clean_ahk_script(script: str) -> str:
    """
    Clean up extracted AHK script.
    
    Args:
        script (str): Raw script content
        
    Returns:
        str: Cleaned script
    """
    # Split into lines and clean each line
    lines = script.split('\n')
    cleaned_lines = []
    
    for line in lines:
        # Remove null characters and excessive whitespace
        line = line.replace('\x00', '').strip()
        
        # Skip empty lines at the beginning
        if not cleaned_lines and not line:
            continue
            
        cleaned_lines.append(line)
    
    # Join lines and remove excessive blank lines
    cleaned_script = '\n'.join(cleaned_lines)
    cleaned_script = re.sub(r'\n\s*\n\s*\n', '\n\n', cleaned_script)  # Max 2 consecutive newlines
    
    return cleaned_script.strip() 