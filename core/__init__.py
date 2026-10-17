"""
Core functionality for the AHK Decompiler.

This package contains the core modules for memory manipulation,
script extraction, and process monitoring.
"""

from importlib import import_module

from .version import __version__

_COMPAT = {
    "extract_scripts": "extractor",
    "process_single_pid": "extractor",
    "enum_memory": "memory",
    "read_region": "memory",
    "wait_for_unpack": "memory",
    "monitor_child_processes": "monitor",
    "get_process_info": "monitor",
    "get_active_pids": "monitor",
    "extract_scripts_from_resources": "resources",
}


def __getattr__(name):
    if name in _COMPAT:
        return getattr(import_module(f".{_COMPAT[name]}", __name__), name)
    raise AttributeError(name)


__all__ = ["__version__", *_COMPAT]
