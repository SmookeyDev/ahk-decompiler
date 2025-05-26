"""
Container and frame setup utilities for the AHK Decompiler GUI.
"""

import tkinter as tk
from tkinter import ttk


def setup_scrollable_frame(parent):
    """Create a scrollable frame container."""
    container = tk.Frame(parent)
    container.pack(fill='both', expand=True, padx=5, pady=5)
    
    canvas = tk.Canvas(container, highlightthickness=0)
    v_scrollbar = tk.Scrollbar(container, orient='vertical', command=canvas.yview)
    
    canvas.configure(yscrollcommand=v_scrollbar.set)
    
    scrollable_frame = tk.Frame(canvas, padx=15, pady=15)
    canvas_frame_id = canvas.create_window((0, 0), window=scrollable_frame, anchor='nw')
    
    def _on_frame_configure(event):
        """Update scroll region when frame size changes."""
        canvas.configure(scrollregion=canvas.bbox('all'))
    
    def _on_canvas_configure(event):
        """Update frame width when canvas size changes."""
        canvas_width = event.width
        canvas.itemconfig(canvas_frame_id, width=canvas_width)
    
    scrollable_frame.bind('<Configure>', _on_frame_configure)
    canvas.bind('<Configure>', _on_canvas_configure)
    
    v_scrollbar.pack(side='right', fill='y')
    canvas.pack(side='left', fill='both', expand=True)
    
    return canvas, scrollable_frame


def setup_main_container(parent, title="AHK Decompiler", geometry="700x800"):
    """Setup the main application container with basic configuration."""
    parent.title(title)
    parent.geometry(geometry)
    parent.minsize(650, 700)
    
    return parent


def setup_resizable_frame(parent, min_width=None, min_height=None):
    """Create a resizable frame with optional minimum dimensions."""
    frame = ttk.Frame(parent)
    frame.pack(fill='both', expand=True)
    
    if min_width or min_height:
        frame.update_idletasks()
        if min_width:
            frame.config(width=min_width)
        if min_height:
            frame.config(height=min_height)
    
    return frame


def setup_tabbed_container(parent, tab_names):
    """Create a tabbed container with specified tab names."""
    notebook = ttk.Notebook(parent)
    notebook.pack(fill='both', expand=True, padx=5, pady=5)
    
    tabs = {}
    for tab_name in tab_names:
        tab_frame = ttk.Frame(notebook)
        notebook.add(tab_frame, text=tab_name)
        tabs[tab_name] = tab_frame
    
    return notebook, tabs


def setup_split_container(parent, orientation='horizontal', sash_position=None):
    """Create a split container (paned window)."""
    if orientation.lower() == 'horizontal':
        paned = ttk.PanedWindow(parent, orient='horizontal')
    else:
        paned = ttk.PanedWindow(parent, orient='vertical')
    
    paned.pack(fill='both', expand=True, padx=5, pady=5)
    
    left_frame = ttk.Frame(paned)
    right_frame = ttk.Frame(paned)
    
    paned.add(left_frame)
    paned.add(right_frame)
    
    if sash_position:
        paned.sashpos(0, sash_position)
    
    return paned, left_frame, right_frame 