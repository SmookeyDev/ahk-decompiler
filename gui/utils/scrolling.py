"""
Scrolling and mouse wheel utilities for the AHK Decompiler GUI.
"""

import tkinter as tk


def setup_mousewheel_scrolling(canvas, scrollable_frame, root):
    """Setup mouse wheel scrolling for a canvas with scrollable frame."""
    def _on_mousewheel_vertical(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
    def _on_mousewheel_horizontal(event):
        canvas.xview_scroll(int(-1 * (event.delta / 120)), "units")
    
    def bind_to_mousewheel(widget):
        widget.bind("<MouseWheel>", _on_mousewheel_vertical)
        widget.bind("<Shift-MouseWheel>", _on_mousewheel_horizontal)
        
        for child in widget.winfo_children():
            bind_to_mousewheel(child)
    
    # Bind to root and canvas
    root.bind("<MouseWheel>", _on_mousewheel_vertical)
    root.bind("<Shift-MouseWheel>", _on_mousewheel_horizontal)
    canvas.bind("<MouseWheel>", _on_mousewheel_vertical)
    canvas.bind("<Shift-MouseWheel>", _on_mousewheel_horizontal)
    
    # Bind to all children after a short delay
    root.after(100, lambda: bind_to_mousewheel(scrollable_frame))


def setup_keyboard_scrolling(canvas, root):
    """Setup keyboard scrolling for a canvas."""
    def _on_key_scroll(event):
        if event.keysym == 'Up':
            canvas.yview_scroll(-1, "units")
        elif event.keysym == 'Down':
            canvas.yview_scroll(1, "units")
        elif event.keysym == 'Left':
            canvas.xview_scroll(-1, "units")
        elif event.keysym == 'Right':
            canvas.xview_scroll(1, "units")
        elif event.keysym == 'Prior':  # Page Up
            canvas.yview_scroll(-1, "pages")
        elif event.keysym == 'Next':   # Page Down
            canvas.yview_scroll(1, "pages")
        elif event.keysym == 'Home':
            canvas.yview_moveto(0)
        elif event.keysym == 'End':
            canvas.yview_moveto(1)
    
    # Bind keyboard events
    root.bind('<Key-Up>', _on_key_scroll)
    root.bind('<Key-Down>', _on_key_scroll)
    root.bind('<Key-Left>', _on_key_scroll)
    root.bind('<Key-Right>', _on_key_scroll)
    root.bind('<Key-Prior>', _on_key_scroll)
    root.bind('<Key-Next>', _on_key_scroll)
    root.bind('<Key-Home>', _on_key_scroll)
    root.bind('<Key-End>', _on_key_scroll)
    
    # Make sure the root can receive focus
    root.focus_set()


def setup_smooth_scrolling(canvas, sensitivity=1):
    """Setup smooth scrolling with adjustable sensitivity."""
    def _smooth_scroll_vertical(event):
        delta = int(-1 * (event.delta / 120) * sensitivity)
        canvas.yview_scroll(delta, "units")
    
    def _smooth_scroll_horizontal(event):
        delta = int(-1 * (event.delta / 120) * sensitivity)
        canvas.xview_scroll(delta, "units")
    
    canvas.bind("<MouseWheel>", _smooth_scroll_vertical)
    canvas.bind("<Shift-MouseWheel>", _smooth_scroll_horizontal)


def auto_scroll_to_bottom(widget):
    """Auto-scroll a widget to the bottom."""
    if hasattr(widget, 'yview_moveto'):
        widget.yview_moveto(1.0)
    elif hasattr(widget, 'see'):
        widget.see(tk.END)


def auto_scroll_to_top(widget):
    """Auto-scroll a widget to the top."""
    if hasattr(widget, 'yview_moveto'):
        widget.yview_moveto(0.0)
    elif hasattr(widget, 'see'):
        widget.see(1.0)


def get_scroll_position(widget):
    """Get current scroll position as a fraction (0.0 to 1.0)."""
    if hasattr(widget, 'yview'):
        return widget.yview()[0]
    return 0.0


def set_scroll_position(widget, position):
    """Set scroll position as a fraction (0.0 to 1.0)."""
    position = max(0.0, min(1.0, position))  # Clamp between 0 and 1
    if hasattr(widget, 'yview_moveto'):
        widget.yview_moveto(position)


def is_scrolled_to_bottom(widget, threshold=0.95):
    """Check if widget is scrolled near the bottom."""
    if hasattr(widget, 'yview'):
        top, bottom = widget.yview()
        return bottom >= threshold
    return False


def is_scrolled_to_top(widget, threshold=0.05):
    """Check if widget is scrolled near the top."""
    if hasattr(widget, 'yview'):
        top, bottom = widget.yview()
        return top <= threshold
    return True 