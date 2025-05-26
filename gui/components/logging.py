"""
Logging and activity display components for the AHK Decompiler GUI.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import logging
from datetime import datetime


class LogWidget:
    """Enhanced log widget with timestamps and colored messages."""
    
    def __init__(self, parent):
        self.frame = ttk.LabelFrame(parent, text="Activity Log", padding=5)
        self.frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Text widget with scrollbar
        self.text = scrolledtext.ScrolledText(
            self.frame, 
            height=6,
            wrap=tk.WORD,
            font=('Consolas', 9),
            bg='#f8f9fa',
            fg='#333333'
        )
        self.text.pack(fill='both', expand=True)
        
        self._setup_text_tags()
    
    def _setup_text_tags(self):
        """Setup text tags for different log levels."""
        self.text.tag_configure('info', foreground='#0066cc')
        self.text.tag_configure('success', foreground='#28a745')
        self.text.tag_configure('warning', foreground='#ffc107')
        self.text.tag_configure('error', foreground='#dc3545')
        self.text.tag_configure('timestamp', foreground='#6c757d', font=('Consolas', 8))
    
    def log(self, message, level='info'):
        """Add a log message with timestamp."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        self.text.insert(tk.END, f"[{timestamp}] ", 'timestamp')
        self.text.insert(tk.END, f"{message}\n", level)
        
        self.text.see(tk.END)
        self.text.update_idletasks()
    
    def clear(self):
        """Clear the log."""
        self.text.delete(1.0, tk.END)
    
    def get_content(self):
        """Get all log content."""
        return self.text.get(1.0, tk.END)
    
    def save_to_file(self, filepath):
        """Save log content to a file."""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(self.get_content())
            return True
        except Exception:
            return False


class GUILogHandler(logging.Handler):
    """Custom logging handler that redirects logs to the GUI log widget."""
    
    def __init__(self, log_widget, root):
        super().__init__()
        self.log_widget = log_widget
        self.root = root
        self._setup_level_mapping()
    
    def _setup_level_mapping(self):
        """Setup mapping from logging levels to GUI levels."""
        self.level_map = {
            'DEBUG': 'info',
            'INFO': 'info', 
            'WARNING': 'warning',
            'ERROR': 'error',
            'CRITICAL': 'error'
        }
    
    def emit(self, record):
        """Emit a log record to the GUI."""
        try:
            msg = self.format(record)
            gui_level = self.level_map.get(record.levelname, 'info')
            
            # Use thread-safe method to update GUI
            self.root.after(0, lambda: self.log_widget.log(msg, gui_level))
        except Exception:
            # Silently ignore errors to prevent logging loops
            pass 