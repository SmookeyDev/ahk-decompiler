"""
GUI Theming package.

This package contains theming and styling configurations:
- styles: TTK style configurations
- colors: Color scheme definitions
- fonts: Font configurations
"""

from .styles import setup_gui_styles
from .colors import get_color_scheme, ColorScheme
from .fonts import get_font_config, FontConfig

__all__ = [
    'setup_gui_styles',
    'get_color_scheme',
    'ColorScheme',
    'get_font_config', 
    'FontConfig'
] 