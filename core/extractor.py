"""
AutoHotkey script extraction functionality.
"""

import os
import re
import psutil
from core.memory import enum_memory, read_region, open_process, close_process, is_readable_region, wait_for_unpack
from utils.constants import (
    COMPILER_SIGNATURE, SCRIPT_END_PATTERN, SCRIPT_MINIMUM_HEURISTIC,
    DEFAULT_UNPACK_TIMEOUT, DEFAULT_CHILD_UNPACK_TIMEOUT
)


def extract_scripts(pid, out_dir, progress=None, is_subprocess=False):
    """
    Extract AutoHotkey scripts from a running process.
    
    Args:
        pid (int): Process ID
        out_dir (str): Output directory for extracted scripts
        progress (callable, optional): Progress callback function
        is_subprocess (bool): Whether this is a subprocess (affects detection logic)
        
    Returns:
        int: Number of scripts extracted
    """
    os.makedirs(out_dir, exist_ok=True)
    hproc = open_process(pid)
    if not hproc:
        print(f"Failed to open process {pid}")
        return 0

    total = scripts = 0
    try:
        print(f"Starting memory analysis for PID {pid} (subprocess: {is_subprocess})")
        memory_regions_analyzed = 0
        
        for base, size, state, prot in enum_memory(hproc):
            if not is_readable_region(state, prot):
                continue
                
            memory_regions_analyzed += 1
            blob = read_region(hproc, base, size)
            if not blob:
                total += size
                if progress:
                    progress(total)
                continue

            # For subprocesses, use more flexible script detection
            if is_subprocess:
                scripts += _extract_subprocess_scripts(blob, pid, scripts, out_dir, base, size)
            else:
                # Original extraction logic for main processes
                if COMPILER_SIGNATURE not in blob:
                    total += size
                    if progress:
                        progress(total)
                    continue

                # Find start and end of script
                for m in re.finditer(COMPILER_SIGNATURE, blob):
                    start = blob.rfind(b'\n', 0, m.start()) + 1
                    end = blob.find(SCRIPT_END_PATTERN, m.end())
                    if end == -1:
                        continue
                        
                    data = blob[start:end].decode('utf-8', 'ignore').strip()
                    if SCRIPT_MINIMUM_HEURISTIC in data:  # Minimum heuristic
                        scripts += 1
                        script_filename = f'{out_dir}/script_{pid}_{scripts}.ahk'
                        with open(script_filename, 'w', encoding='utf-8') as f:
                            f.write(data)
                        print(f"Extracted script {scripts} from PID {pid} (main process)")
                        
            total += size
            if progress:
                progress(total)
                
        print(f"Memory analysis complete for PID {pid}: {memory_regions_analyzed} regions analyzed, {scripts} scripts found")
    except Exception as e:
        print(f"Error during extraction from PID {pid}: {e}")
    finally:
        close_process(hproc)
        
    return scripts


def _extract_subprocess_scripts(blob, pid, current_scripts, out_dir, base_addr, size):
    """
    Extract scripts from subprocess memory using enhanced detection methods.
    
    Args:
        blob (bytes): Memory blob to analyze
        pid (int): Process ID
        current_scripts (int): Current script count
        out_dir (str): Output directory
        base_addr (int): Base memory address
        size (int): Memory region size
        
    Returns:
        int: Number of scripts found in this blob
    """
    scripts_found = 0
    
    try:
        # Method 1: Look for COMPILER signature (standard method)
        if COMPILER_SIGNATURE in blob:
            for m in re.finditer(COMPILER_SIGNATURE, blob):
                start = blob.rfind(b'\n', 0, m.start()) + 1
                end = blob.find(SCRIPT_END_PATTERN, m.end())
                if end == -1:
                    continue
                    
                data = blob[start:end].decode('utf-8', 'ignore').strip()
                if SCRIPT_MINIMUM_HEURISTIC in data:
                    scripts_found += 1
                    script_filename = f'{out_dir}/script_{pid}_{current_scripts + scripts_found}_subprocess.ahk'
                    with open(script_filename, 'w', encoding='utf-8') as f:
                        f.write(data)
                    print(f"Extracted subprocess script {scripts_found} from PID {pid} (Method 1: COMPILER)")
        
        # Method 2: Look for AHK script patterns without COMPILER signature
        # This handles cases where the subprocess contains raw AHK code
        ahk_patterns = [
            rb'SendInput[,\s]',
            rb'WinActivate[,\s]',
            rb'Sleep[,\s]',
            rb'ControlClick[,\s]',
            rb'WinWait[,\s]',
            rb'IfWinExist[,\s]',
            rb'Loop[,\s]',
            rb'Hotkey[,\s]',
            rb'#NoEnv',
            rb'#SingleInstance',
            rb'#Include',
            rb'::',
            rb'#IfWin'
        ]
        
        # Look for multiple AHK patterns in the same memory region
        pattern_matches = 0
        potential_start = 0
        
        for pattern in ahk_patterns:
            matches = list(re.finditer(pattern, blob, re.IGNORECASE))
            if matches:
                pattern_matches += len(matches)
                if potential_start == 0:
                    potential_start = max(0, matches[0].start() - 100)
        
        # If we found multiple AHK patterns, try to extract the script
        if pattern_matches >= 2:
            # Look for script boundaries
            script_data = blob[potential_start:].decode('utf-8', 'ignore')
            
            # Clean up the script data
            lines = script_data.split('\n')
            clean_lines = []
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('\x00'):
                    clean_lines.append(line)
                elif clean_lines:  # Stop at first empty/null line after content
                    break
            
            if len(clean_lines) >= 3:  # Minimum script length
                clean_script = '\n'.join(clean_lines)
                
                # Validate it looks like AHK script
                if any(pattern.decode('utf-8', 'ignore').replace('[,\\s]', '').replace('\\', '') in clean_script 
                       for pattern in ahk_patterns[:8]):  # Check main patterns
                    scripts_found += 1
                    script_filename = f'{out_dir}/script_{pid}_{current_scripts + scripts_found}_subprocess_raw.ahk'
                    with open(script_filename, 'w', encoding='utf-8') as f:
                        f.write(clean_script)
                    print(f"Extracted subprocess script {scripts_found} from PID {pid} (Method 2: Pattern matching)")
                    
        # Method 3: Look for embedded scripts in string format
        # Some subprocesses store AHK code as strings
        string_patterns = [
            rb'"[^"]*(?:SendInput|WinActivate|Sleep)[^"]*"',
            rb"'[^']*(?:SendInput|WinActivate|Sleep)[^']*'"
        ]
        
        for pattern in string_patterns:
            matches = list(re.finditer(pattern, blob, re.IGNORECASE | re.DOTALL))
            for match in matches:
                string_content = match.group(0).decode('utf-8', 'ignore').strip('"\'')
                if len(string_content) > 50 and '::' in string_content:
                    scripts_found += 1
                    script_filename = f'{out_dir}/script_{pid}_{current_scripts + scripts_found}_subprocess_string.ahk'
                    with open(script_filename, 'w', encoding='utf-8') as f:
                        f.write(string_content)
                    print(f"Extracted subprocess script {scripts_found} from PID {pid} (Method 3: String)")
                    break
                    
    except Exception as e:
        print(f"Error in subprocess extraction for PID {pid}: {e}")
    
    return scripts_found


def process_single_pid(pid, is_main_process=False):
    """
    Process a single PID for script extraction.
    
    Args:
        pid (int): Process ID
        is_main_process (bool): Whether this is the main process
        
    Returns:
        dict: Processing result with status and script count
    """
    result = {
        'pid': pid,
        'scripts_count': 0,
        'status': 'unknown',
        'error': None
    }
    
    try:
        # Check if process is still running
        if not psutil.pid_exists(pid):
            result['status'] = 'terminated_before_processing'
            return result
            
        # For subprocesses, use extended timeout and different approach
        if not is_main_process:
            timeout = DEFAULT_CHILD_UNPACK_TIMEOUT * 2  # Double timeout for subprocesses
            print(f"Processing subprocess PID {pid} with extended timeout ({timeout}s)")
        else:
            timeout = DEFAULT_UNPACK_TIMEOUT
            
        # Wait for unpack of each process
        process_unpacked = wait_for_unpack(pid, timeout=timeout)
        
        if not process_unpacked:
            if psutil.pid_exists(pid):
                result['status'] = 'unpack_timeout'
                print(f"Timeout waiting for unpack of PID {pid}, attempting extraction anyway...")
            else:
                result['status'] = 'terminated_during_unpack'
                print(f"PID {pid} terminated during unpack, skipping...")
                return result
        else:
            result['status'] = 'unpacked_successfully'
        
        # Extract scripts only if process still exists
        if psutil.pid_exists(pid):
            scripts_count = extract_scripts(pid, 'dump_scripts', is_subprocess=not is_main_process)
            result['scripts_count'] = scripts_count
            if result['status'] == 'unpack_timeout':
                result['status'] = 'extracted_after_timeout'
            elif result['status'] == 'unpacked_successfully':
                result['status'] = 'extracted_successfully'
                
            # For subprocesses, if no scripts found with standard method, 
            # wait a bit more and try again
            if not is_main_process and scripts_count == 0:
                print(f"No scripts found in subprocess {pid}, waiting and retrying...")
                import time
                time.sleep(2)
                if psutil.pid_exists(pid):
                    scripts_count = extract_scripts(pid, 'dump_scripts', is_subprocess=True)
                    result['scripts_count'] = scripts_count
                    if scripts_count > 0:
                        result['status'] = 'extracted_on_retry'
        else:
            result['status'] = 'terminated_before_extraction'
            print(f"PID {pid} terminated before extraction, skipping...")
            
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
        result['error'] = str(e)
        result['status'] = 'error'
        print(f"Error processing PID {pid}: {e}")
    
    return result 