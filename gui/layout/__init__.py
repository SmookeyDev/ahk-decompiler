"""
GUI Layout package.

This package contains layout and section setup functions organized by context:
- sections: Main GUI section setup functions
- containers: Container and frame setup utilities
"""

from .sections import (
    setup_header_section,
    setup_config_section, 
    setup_progress_section,
    setup_pe_analysis_section,
    setup_process_section,
    setup_log_section,
    setup_action_section
)

from .containers import (
    setup_scrollable_frame,
    setup_main_container
)

__all__ = [
    'setup_header_section',
    'setup_config_section',
    'setup_progress_section', 
    'setup_pe_analysis_section',
    'setup_process_section',
    'setup_log_section',
    'setup_action_section',
    'setup_scrollable_frame',
    'setup_main_container'
] 