"""
Color scheme definitions for the AHK Decompiler GUI.
"""

from dataclasses import dataclass
from typing import Dict


@dataclass
class ColorScheme:
    """Color scheme data class."""
    primary: str
    secondary: str
    success: str
    warning: str
    error: str
    info: str
    light_gray: str
    background: str
    text: str
    timestamp: str


def get_color_scheme(theme='default') -> Dict[str, str]:
    """Get the application color scheme."""
    schemes = {
        'default': {
            'primary': '#2c3e50',
            'secondary': '#7f8c8d',
            'success': '#28a745',
            'warning': '#ffc107',
            'error': '#dc3545',
            'info': '#0066cc',
            'light_gray': '#666666',
            'background': '#f8f9fa',
            'text': '#333333',
            'timestamp': '#6c757d'
        },
        'dark': {
            'primary': '#3498db',
            'secondary': '#95a5a6',
            'success': '#2ecc71',
            'warning': '#f39c12',
            'error': '#e74c3c',
            'info': '#3498db',
            'light_gray': '#34495e',
            'background': '#2c3e50',
            'text': '#ecf0f1',
            'timestamp': '#95a5a6'
        },
        'blue': {
            'primary': '#1e3a8a',
            'secondary': '#64748b',
            'success': '#059669',
            'warning': '#d97706',
            'error': '#dc2626',
            'info': '#2563eb',
            'light_gray': '#6b7280',
            'background': '#f1f5f9',
            'text': '#1e293b',
            'timestamp': '#64748b'
        },
        'green': {
            'primary': '#166534',
            'secondary': '#6b7280',
            'success': '#16a34a',
            'warning': '#ca8a04',
            'error': '#dc2626',
            'info': '#2563eb',
            'light_gray': '#6b7280',
            'background': '#f0fdf4',
            'text': '#14532d',
            'timestamp': '#6b7280'
        }
    }
    
    return schemes.get(theme, schemes['default'])


def get_color_scheme_object(theme='default') -> ColorScheme:
    """Get the color scheme as a ColorScheme object."""
    colors = get_color_scheme(theme)
    return ColorScheme(**colors)


def get_available_color_schemes() -> list:
    """Get list of available color schemes."""
    return ['default', 'dark', 'blue', 'green']


def get_semantic_colors() -> Dict[str, str]:
    """Get semantic color mappings."""
    return {
        'success': '#28a745',
        'info': '#17a2b8',
        'warning': '#ffc107',
        'danger': '#dc3545',
        'light': '#f8f9fa',
        'dark': '#343a40',
        'muted': '#6c757d'
    }


def get_status_colors() -> Dict[str, str]:
    """Get status-specific colors."""
    return {
        'running': '#28a745',
        'stopped': '#dc3545',
        'paused': '#ffc107',
        'pending': '#6c757d',
        'completed': '#28a745',
        'failed': '#dc3545',
        'cancelled': '#6c757d'
    }


def hex_to_rgb(hex_color: str) -> tuple:
    """Convert hex color to RGB tuple."""
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))


def rgb_to_hex(rgb_color: tuple) -> str:
    """Convert RGB tuple to hex color."""
    return f"#{rgb_color[0]:02x}{rgb_color[1]:02x}{rgb_color[2]:02x}"


def lighten_color(hex_color: str, factor: float = 0.1) -> str:
    """Lighten a hex color by a given factor."""
    rgb = hex_to_rgb(hex_color)
    lightened = tuple(min(255, int(c + (255 - c) * factor)) for c in rgb)
    return rgb_to_hex(lightened)


def darken_color(hex_color: str, factor: float = 0.1) -> str:
    """Darken a hex color by a given factor."""
    rgb = hex_to_rgb(hex_color)
    darkened = tuple(max(0, int(c * (1 - factor))) for c in rgb)
    return rgb_to_hex(darkened) 