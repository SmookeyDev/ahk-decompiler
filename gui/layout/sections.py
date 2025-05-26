"""
GUI section setup functions for the AHK Decompiler.
"""

import tkinter as tk
from tkinter import ttk

from ..components import ModernProgressBar, PEAnalysisWidget, LogWidget, ProcessListWidget
from ..theming import get_font_config
from ..utils.file_operations import open_output_folder


def setup_header_section(parent):
    """Setup header section with title and subtitle."""
    fonts = get_font_config()
    
    header_frame = ttk.Frame(parent)
    header_frame.pack(fill='x', pady=(0, 20))
    
    # Title
    title_label = ttk.Label(
        header_frame, 
        text="AutoHotkey Script Decompiler",
        font=fonts['title'],
        foreground='#2c3e50'
    )
    title_label.pack()
    
    # Subtitle
    subtitle_label = ttk.Label(
        header_frame, 
        text="Extract AHK scripts from compiled executables",
        font=fonts['subtitle'],
        foreground='#7f8c8d'
    )
    subtitle_label.pack()
    
    # Separator
    ttk.Separator(header_frame, orient='horizontal').pack(fill='x', pady=(10, 0))
    
    return header_frame


def setup_config_section(parent, file_path_var, browse_callback, monitor_children, extract_resources, auto_open):
    """Setup configuration section with file selection and options."""
    config_frame = ttk.LabelFrame(parent, text="Configuration", padding=10)
    config_frame.pack(fill='x', pady=(0, 10))
    
    # File selection
    file_frame = ttk.Frame(config_frame)
    file_frame.pack(fill='x', pady=(0, 10))
    
    ttk.Label(file_frame, text="Target Executable:").pack(anchor='w')
    
    file_select_frame = ttk.Frame(file_frame)
    file_select_frame.pack(fill='x', pady=(5, 0))
    
    file_entry = ttk.Entry(
        file_select_frame, 
        textvariable=file_path_var,
        state='readonly',
        font=('Segoe UI', 9)
    )
    file_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
    
    browse_button = ttk.Button(
        file_select_frame,
        text="Browse...",
        command=browse_callback,
        style='Secondary.TButton'
    )
    browse_button.pack(side='right')
    
    # Options
    options_frame = ttk.Frame(config_frame)
    options_frame.pack(fill='x')
    
    ttk.Checkbutton(
        options_frame,
        text="Monitor child processes (recommended)",
        variable=monitor_children
    ).pack(anchor='w')
    
    ttk.Checkbutton(
        options_frame,
        text="Extract from RCDATA resources (for some packed executables)",
        variable=extract_resources
    ).pack(anchor='w')
    
    ttk.Checkbutton(
        options_frame,
        text="Auto-open output folder when complete",
        variable=auto_open
    ).pack(anchor='w')
    
    return config_frame, file_entry, browse_button


def setup_progress_section(parent):
    """Setup progress section with modern progress bar."""
    return ModernProgressBar(parent)


def setup_pe_analysis_section(parent):
    """Setup PE analysis section."""
    return PEAnalysisWidget(parent)


def setup_process_section(parent):
    """Setup process monitoring section."""
    return ProcessListWidget(parent)


def setup_log_section(parent):
    """Setup log section."""
    return LogWidget(parent)


def setup_action_section(parent, start_callback, stop_callback, clear_log_callback):
    """Setup action buttons section."""
    action_frame = ttk.Frame(parent)
    action_frame.pack(fill='x', pady=(10, 0))
    
    # Left side buttons
    left_frame = ttk.Frame(action_frame)
    left_frame.pack(side='left')
    
    run_button = ttk.Button(
        left_frame,
        text="🚀 Start Extraction",
        command=start_callback,
        state='disabled',
        style='Primary.TButton'
    )
    run_button.pack(side='left', padx=(0, 10))
    
    stop_button = ttk.Button(
        left_frame,
        text="⏹ Stop",
        command=stop_callback,
        state='disabled',
        style='Secondary.TButton'
    )
    stop_button.pack(side='left', padx=(0, 10))
    
    # Right side buttons
    right_frame = ttk.Frame(action_frame)
    right_frame.pack(side='right')
    
    clear_log_button = ttk.Button(
        right_frame,
        text="Clear Log",
        command=clear_log_callback,
        style='Secondary.TButton'
    )
    clear_log_button.pack(side='left', padx=(0, 10))
    
    open_folder_button = ttk.Button(
        right_frame,
        text="📁 Open Output Folder",
        command=open_output_folder,
        state='disabled',
        style='Secondary.TButton'
    )
    open_folder_button.pack(side='left')
    
    return action_frame, run_button, stop_button, clear_log_button, open_folder_button 