"""
Memory utilities for process memory manipulation and analysis.
"""

import ctypes
import time
import psutil
import win32con
from utils.constants import (
    PAGE_READABLE, PROCESS_ALL_ACCESS, MEMORY_BASIC_INFO_SIZE,
    COMPILER_SIGNATURE, DEFAULT_UNPACK_TIMEOUT, DEFAULT_CHECK_INTERVAL
)


def enum_memory(proc):
    """
    Enumerate memory regions of a process.
    
    Args:
        proc: Process handle
        
    Yields:
        tuple: (base_address, size, state, protection) for each memory region
    """
    mbi = ctypes.create_string_buffer(MEMORY_BASIC_INFO_SIZE)
    addr = 0
    while ctypes.windll.kernel32.VirtualQueryEx(proc, ctypes.c_void_p(addr), mbi, MEMORY_BASIC_INFO_SIZE):
        base = ctypes.c_void_p.from_buffer(mbi).value
        size = int.from_bytes(mbi.raw[24:32], 'little')
        state = int.from_bytes(mbi.raw[32:36], 'little')
        protect = int.from_bytes(mbi.raw[36:40], 'little')
        yield base, size, state, protect
        addr += size


def read_region(proc, base, size):
    """
    Read a memory region from a process.
    
    Args:
        proc: Process handle
        base: Base address to read from
        size: Number of bytes to read
        
    Returns:
        bytes: The read memory data, or empty bytes if failed
    """
    buf = ctypes.create_string_buffer(size)
    br = ctypes.c_size_t(0)
    if ctypes.windll.kernel32.ReadProcessMemory(proc, ctypes.c_void_p(base),
                                               buf, size, ctypes.byref(br)):
        return buf.raw[:br.value]
    return b''


def open_process(pid):
    """
    Open a process handle with full access rights.
    
    Args:
        pid (int): Process ID
        
    Returns:
        handle: Process handle or None if failed
    """
    return ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)


def close_process(handle):
    """
    Close a process handle.
    
    Args:
        handle: Process handle to close
    """
    if handle:
        ctypes.windll.kernel32.CloseHandle(handle)


def is_readable_region(state, protect):
    """
    Check if a memory region is readable.
    
    Args:
        state: Memory state
        protect: Memory protection flags
        
    Returns:
        bool: True if region is readable, False otherwise
    """
    return state == win32con.MEM_COMMIT and (protect & PAGE_READABLE)


def wait_for_unpack(pid, timeout=DEFAULT_UNPACK_TIMEOUT, check_interval=DEFAULT_CHECK_INTERVAL):
    """
    Wait for a packed executable to unpack in memory.
    
    Args:
        pid (int): Process ID
        timeout (int): Maximum wait time in seconds
        check_interval (int): Check interval in seconds
        
    Returns:
        bool: True if unpacked successfully, False otherwise
    """
    # First check if process exists
    if not psutil.pid_exists(pid):
        print(f"Process {pid} does not exist or has terminated")
        return False
        
    hproc = open_process(pid)
    if not hproc:
        return False

    t0 = time.time()
    try:
        print(f"Waiting for unpack of PID {pid} (timeout: {timeout}s)")
        
        # Alternative signatures to look for (not just COMPILER)
        unpack_signatures = [
            COMPILER_SIGNATURE,  # Standard signature
            b'AutoHotkey',       # AutoHotkey string
            b'SendInput',        # Common AHK function
            b'WinActivate',      # Common AHK function
            b'#NoEnv',          # Common AHK directive
            b'#SingleInstance',  # Common AHK directive
            b'::'               # Hotkey syntax
        ]
        
        signature_found = False
        last_check_time = t0
        
        while time.time() - t0 < timeout:
            # Check if process is still alive
            if not psutil.pid_exists(pid):
                print(f"Process {pid} terminated during unpack wait")
                return False
                
            current_time = time.time()
            
            # Log progress every 10 seconds
            if current_time - last_check_time >= 10:
                elapsed = current_time - t0
                print(f"Still waiting for unpack of PID {pid} ({elapsed:.1f}s elapsed)")
                last_check_time = current_time
                
            for base, size, state, prot in enum_memory(hproc):
                if not is_readable_region(state, prot):
                    continue
                    
                blob = read_region(hproc, base, size)
                if not blob:
                    continue
                
                # Check for any of the signatures
                for signature in unpack_signatures:
                    if signature in blob:
                        print(f"Found signature '{signature.decode('utf-8', 'ignore')}' in PID {pid}")
                        signature_found = True
                        
                        # For COMPILER signature, we're definitely unpacked
                        if signature == COMPILER_SIGNATURE:
                            print(f"COMPILER signature found - PID {pid} is unpacked")
                            return True
                        
                        # For other signatures, continue looking but note we found something
                        break
                
                # If we found any signature and it's been at least 5 seconds, consider it unpacked
                if signature_found and (current_time - t0) >= 5:
                    print(f"Alternative signature found and waited 5s - considering PID {pid} unpacked")
                    return True
                    
            time.sleep(check_interval)
            
        # If we found signatures but didn't get COMPILER, still consider it potentially unpacked
        if signature_found:
            print(f"Alternative signatures found for PID {pid} - proceeding with extraction")
            return True
            
    except Exception as e:
        print(f"Error during unpack wait for PID {pid}: {e}")
    finally:
        close_process(hproc)
        
    print(f"Unpack timeout for PID {pid} after {timeout}s")
    return False 