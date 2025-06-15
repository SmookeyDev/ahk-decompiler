"""
Progress tracking components for the AHK Decompiler GUI.
"""

import tkinter as tk
from tkinter import ttk


class ModernProgressBar:
    """Custom progress bar with phases and better visual feedback."""
    
    def __init__(self, parent, width=400):
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill='x', padx=10, pady=5)
        
        self.phase_label = ttk.Label(self.frame, text="Ready", font=('Segoe UI', 9, 'bold'))
        self.phase_label.pack(anchor='w')
        
        self.progressbar = ttk.Progressbar(
            self.frame, 
            length=width, 
            mode='determinate',
            style='Custom.Horizontal.TProgressbar'
        )
        self.progressbar.pack(fill='x', pady=(2, 0))
        
        self.status_label = ttk.Label(self.frame, text="", font=('Segoe UI', 8))
        self.status_label.pack(anchor='w')
        
        self.setup_style()
    
    def setup_style(self):
        """Setup custom progressbar style."""
        style = ttk.Style()
        style.configure(
            'Custom.Horizontal.TProgressbar',
            troughcolor='#e0e0e0',
            background='#4CAF50',
            lightcolor='#4CAF50',
            darkcolor='#4CAF50'
        )
    
    def set_phase(self, phase, status=""):
        """Set the current phase and status."""
        self.phase_label.config(text=phase)
        self.status_label.config(text=status)
    
    def set_progress(self, value, maximum=100):
        """Set progress value."""
        self.progressbar.config(maximum=maximum)
        self.progressbar.config(value=value)
    
    def reset(self):
        """Reset progress bar."""
        self.progressbar.config(value=0)
        self.phase_label.config(text="Ready")
        self.status_label.config(text="") 