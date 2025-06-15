"""
Font configurations for the AHK Decompiler GUI.
"""

from dataclasses import dataclass
from typing import Dict, Tuple
import platform


@dataclass
class FontConfig:
    """Font configuration data class."""
    title: Tuple[str, int, str]
    subtitle: Tuple[str, int]
    heading: Tuple[str, int, str]
    body: Tuple[str, int]
    small: Tuple[str, int]
    monospace: Tuple[str, int]
    monospace_small: Tuple[str, int]


def get_font_config(style='default') -> Dict[str, Tuple]:
    """Get font configurations for different UI elements."""
    system = platform.system().lower()
    
    # Base fonts by system
    if system == 'windows':
        base_font = 'Segoe UI'
        mono_font = 'Consolas'
    elif system == 'darwin':  # macOS
        base_font = 'SF Pro Display'
        mono_font = 'SF Mono'
    else:  # Linux and others
        base_font = 'Ubuntu'
        mono_font = 'Ubuntu Mono'
    
    configs = {
        'default': {
            'title': (base_font, 16, 'bold'),
            'subtitle': (base_font, 10),
            'heading': (base_font, 9, 'bold'),
            'body': (base_font, 9),
            'small': (base_font, 8),
            'monospace': (mono_font, 9),
            'monospace_small': (mono_font, 8)
        },
        'large': {
            'title': (base_font, 20, 'bold'),
            'subtitle': (base_font, 12),
            'heading': (base_font, 11, 'bold'),
            'body': (base_font, 11),
            'small': (base_font, 10),
            'monospace': (mono_font, 11),
            'monospace_small': (mono_font, 10)
        },
        'small': {
            'title': (base_font, 14, 'bold'),
            'subtitle': (base_font, 9),
            'heading': (base_font, 8, 'bold'),
            'body': (base_font, 8),
            'small': (base_font, 7),
            'monospace': (mono_font, 8),
            'monospace_small': (mono_font, 7)
        },
        'compact': {
            'title': (base_font, 12, 'bold'),
            'subtitle': (base_font, 8),
            'heading': (base_font, 8, 'bold'),
            'body': (base_font, 7),
            'small': (base_font, 6),
            'monospace': (mono_font, 7),
            'monospace_small': (mono_font, 6)
        }
    }
    
    return configs.get(style, configs['default'])


def get_font_config_object(style='default') -> FontConfig:
    """Get the font configuration as a FontConfig object."""
    fonts = get_font_config(style)
    return FontConfig(**fonts)


def get_available_font_styles() -> list:
    """Get list of available font styles."""
    return ['default', 'large', 'small', 'compact']


def get_system_fonts() -> Dict[str, str]:
    """Get system-appropriate fonts."""
    system = platform.system().lower()
    
    if system == 'windows':
        return {
            'sans_serif': 'Segoe UI',
            'serif': 'Times New Roman',
            'monospace': 'Consolas',
            'ui': 'Segoe UI'
        }
    elif system == 'darwin':  # macOS
        return {
            'sans_serif': 'SF Pro Display',
            'serif': 'Times New Roman',
            'monospace': 'SF Mono',
            'ui': 'SF Pro Display'
        }
    else:  # Linux and others
        return {
            'sans_serif': 'Ubuntu',
            'serif': 'Liberation Serif',
            'monospace': 'Ubuntu Mono',
            'ui': 'Ubuntu'
        }


def get_fallback_fonts() -> Dict[str, list]:
    """Get fallback font lists for different categories."""
    return {
        'sans_serif': [
            'Segoe UI', 'SF Pro Display', 'Ubuntu', 'Arial', 'Helvetica', 'sans-serif'
        ],
        'serif': [
            'Times New Roman', 'Times', 'Liberation Serif', 'serif'
        ],
        'monospace': [
            'Consolas', 'SF Mono', 'Ubuntu Mono', 'Monaco', 'Courier New', 'monospace'
        ]
    }


def scale_font_size(base_size: int, scale_factor: float) -> int:
    """Scale font size by a factor."""
    return max(6, int(base_size * scale_factor))


def get_accessible_fonts(high_contrast=False, large_text=False) -> Dict[str, Tuple]:
    """Get accessibility-optimized font configurations."""
    base_config = get_font_config('large' if large_text else 'default')
    
    if high_contrast:
        # Use fonts that work well with high contrast
        system_fonts = get_system_fonts()
        for key in base_config:
            if 'monospace' in key:
                base_config[key] = (system_fonts['monospace'], base_config[key][1])
            else:
                base_config[key] = (system_fonts['ui'], base_config[key][1])
    
    return base_config 