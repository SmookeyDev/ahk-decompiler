"""
GUI package for the AHK Decompiler.

This package contains all GUI-related components organized by context:
- main_window: Main application window (DumpGUI class)
- components/: Custom widget components (progress, analysis, logging, process)
- layout/: Layout and section setup functions (sections, containers)
- theming/: Style configurations and theming (styles, colors, fonts)
- utils/: GUI utility functions (window, scrolling, file_operations, validation, dialogs)
"""

from .main_window import DumpGUI

__all__ = ['DumpGUI'] 