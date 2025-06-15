"""
TTK style configurations for the AHK Decompiler GUI.
"""

from tkinter import ttk
from .colors import get_color_scheme


def setup_gui_styles():
    """Configure custom styles for the GUI."""
    style = ttk.Style()
    colors = get_color_scheme()
    
    # Try to use the best available theme
    _setup_base_theme(style)
    
    # Configure custom button styles
    _setup_button_styles(style, colors)
    
    # Configure custom progressbar style
    _setup_progressbar_styles(style, colors)
    
    # Configure custom frame styles
    _setup_frame_styles(style, colors)
    
    return style


def _setup_base_theme(style):
    """Setup the base theme."""
    try:
        style.theme_use('vista')
    except:
        try:
            style.theme_use('clam')
        except:
            pass  # Use default theme


def _setup_button_styles(style, colors):
    """Setup custom button styles."""
    # Primary button style
    style.configure(
        'Primary.TButton',
        font=('Segoe UI', 10, 'bold'),
        foreground=colors['primary']
    )
    
    style.map(
        'Primary.TButton',
        foreground=[('active', colors['info']),
                   ('pressed', colors['secondary'])]
    )
    
    # Secondary button style
    style.configure(
        'Secondary.TButton',
        font=('Segoe UI', 9),
        foreground=colors['text']
    )
    
    style.map(
        'Secondary.TButton',
        foreground=[('active', colors['secondary']),
                   ('pressed', colors['primary'])]
    )
    
    # Success button style
    style.configure(
        'Success.TButton',
        font=('Segoe UI', 9, 'bold'),
        foreground=colors['success']
    )
    
    # Warning button style
    style.configure(
        'Warning.TButton',
        font=('Segoe UI', 9, 'bold'),
        foreground=colors['warning']
    )
    
    # Error button style
    style.configure(
        'Error.TButton',
        font=('Segoe UI', 9, 'bold'),
        foreground=colors['error']
    )


def _setup_progressbar_styles(style, colors):
    """Setup custom progressbar styles."""
    style.configure(
        'Custom.Horizontal.TProgressbar',
        troughcolor='#e0e0e0',
        background=colors['success'],
        lightcolor=colors['success'],
        darkcolor=colors['success']
    )
    
    # Alternative progressbar for warnings
    style.configure(
        'Warning.Horizontal.TProgressbar',
        troughcolor='#e0e0e0',
        background=colors['warning'],
        lightcolor=colors['warning'],
        darkcolor=colors['warning']
    )
    
    # Error progressbar
    style.configure(
        'Error.Horizontal.TProgressbar',
        troughcolor='#e0e0e0',
        background=colors['error'],
        lightcolor=colors['error'],
        darkcolor=colors['error']
    )


def _setup_frame_styles(style, colors):
    """Setup custom frame styles."""
    # Highlighted frame
    style.configure(
        'Highlight.TFrame',
        background=colors['background'],
        relief='solid',
        borderwidth=1
    )
    
    # Card-like frame
    style.configure(
        'Card.TFrame',
        background=colors['background'],
        relief='raised',
        borderwidth=2
    )


def apply_dark_theme(style):
    """Apply a dark theme variant (experimental)."""
    dark_colors = {
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
    }
    
    # Reconfigure styles with dark colors
    _setup_button_styles(style, dark_colors)
    _setup_progressbar_styles(style, dark_colors)
    _setup_frame_styles(style, dark_colors)


def get_available_themes():
    """Get list of available TTK themes."""
    style = ttk.Style()
    return style.theme_names() 