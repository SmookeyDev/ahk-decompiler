"""
Window management utilities for the AHK Decompiler GUI.
"""

import tkinter as tk


def center_window(window, width, height):
    """Center a window on the screen."""
    window.update_idletasks()
    x = (window.winfo_screenwidth() // 2) - (width // 2)
    y = (window.winfo_screenheight() // 2) - (height // 2)
    window.geometry(f'{width}x{height}+{x}+{y}')


def center_window_on_parent(child_window, parent_window, width, height):
    """Center a child window on its parent window."""
    parent_window.update_idletasks()
    child_window.update_idletasks()
    
    parent_x = parent_window.winfo_x()
    parent_y = parent_window.winfo_y()
    parent_width = parent_window.winfo_width()
    parent_height = parent_window.winfo_height()
    
    x = parent_x + (parent_width // 2) - (width // 2)
    y = parent_y + (parent_height // 2) - (height // 2)
    
    child_window.geometry(f'{width}x{height}+{x}+{y}')


def get_screen_dimensions():
    """Get screen width and height."""
    root = tk.Tk()
    root.withdraw()  # Hide the window
    width = root.winfo_screenwidth()
    height = root.winfo_screenheight()
    root.destroy()
    return width, height


def set_window_icon(window, icon_path):
    """Set window icon if the file exists."""
    try:
        window.iconbitmap(icon_path)
        return True
    except Exception:
        return False


def make_window_topmost(window, topmost=True):
    """Make window stay on top of other windows."""
    window.attributes('-topmost', topmost)


def set_window_transparency(window, alpha=1.0):
    """Set window transparency (0.0 = transparent, 1.0 = opaque)."""
    alpha = max(0.0, min(1.0, alpha))  # Clamp between 0 and 1
    window.attributes('-alpha', alpha)


def minimize_window(window):
    """Minimize the window."""
    window.iconify()


def maximize_window(window):
    """Maximize the window."""
    window.state('zoomed')


def restore_window(window):
    """Restore window to normal state."""
    window.state('normal')


def get_window_position(window):
    """Get window position as (x, y) tuple."""
    window.update_idletasks()
    return window.winfo_x(), window.winfo_y()


def get_window_size(window):
    """Get window size as (width, height) tuple."""
    window.update_idletasks()
    return window.winfo_width(), window.winfo_height()


def set_window_minimum_size(window, min_width, min_height):
    """Set minimum window size."""
    window.minsize(min_width, min_height)


def set_window_maximum_size(window, max_width, max_height):
    """Set maximum window size."""
    window.maxsize(max_width, max_height)


def disable_window_resize(window):
    """Disable window resizing."""
    window.resizable(False, False)


def enable_window_resize(window):
    """Enable window resizing."""
    window.resizable(True, True) 