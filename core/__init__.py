"""
Core functionality for the AHK Decompiler.

This package contains the core modules for memory manipulation,
script extraction, and process monitoring.
"""

from .extractor import extract_scripts, process_single_pid
from .memory import enum_memory, read_region, wait_for_unpack
from .monitor import monitor_child_processes, get_process_info, get_active_pids

__all__ = [
    'extract_scripts',
    'process_single_pid',
    'enum_memory',
    'read_region',
    'wait_for_unpack',
    'monitor_child_processes',
    'get_process_info',
    'get_active_pids'
] 