"""
PE file analysis components for the AHK Decompiler GUI.
"""

import tkinter as tk
from tkinter import ttk

from utils.pe_analyzer import analyze_pe_file, PackerType


class PEAnalysisWidget:
    """Widget to display PE analysis information."""
    
    def __init__(self, parent):
        self.frame = ttk.LabelFrame(parent, text="PE Analysis", padding=5)
        self.frame.pack(fill='x', padx=10, pady=5)
        
        self.info_frame = ttk.Frame(self.frame)
        self.info_frame.pack(fill='x')
        
        self.analysis_labels = {}
        self._create_analysis_display()
    
    def _create_analysis_display(self):
        """Create the analysis display layout."""
        left_frame = ttk.Frame(self.info_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        right_frame = ttk.Frame(self.info_frame)
        right_frame.pack(side='right', fill='both', expand=True)
        
        # Left column
        ttk.Label(left_frame, text="File Type:", font=('Segoe UI', 9, 'bold')).grid(row=0, column=0, sticky='w', pady=2)
        self.analysis_labels['file_type'] = ttk.Label(left_frame, text="Not analyzed", foreground='#666666')
        self.analysis_labels['file_type'].grid(row=0, column=1, sticky='w', padx=(10, 0), pady=2)
        
        ttk.Label(left_frame, text="Architecture:", font=('Segoe UI', 9, 'bold')).grid(row=1, column=0, sticky='w', pady=2)
        self.analysis_labels['architecture'] = ttk.Label(left_frame, text="-", foreground='#666666')
        self.analysis_labels['architecture'].grid(row=1, column=1, sticky='w', padx=(10, 0), pady=2)
        
        ttk.Label(left_frame, text="Compiler:", font=('Segoe UI', 9, 'bold')).grid(row=2, column=0, sticky='w', pady=2)
        self.analysis_labels['compiler'] = ttk.Label(left_frame, text="-", foreground='#666666')
        self.analysis_labels['compiler'].grid(row=2, column=1, sticky='w', padx=(10, 0), pady=2)
        
        # Right column
        ttk.Label(right_frame, text="Packer:", font=('Segoe UI', 9, 'bold')).grid(row=0, column=0, sticky='w', pady=2)
        self.analysis_labels['packer'] = ttk.Label(right_frame, text="Not analyzed", foreground='#666666')
        self.analysis_labels['packer'].grid(row=0, column=1, sticky='w', padx=(10, 0), pady=2)
        
        ttk.Label(right_frame, text="Status:", font=('Segoe UI', 9, 'bold')).grid(row=1, column=0, sticky='w', pady=2)
        self.analysis_labels['status'] = ttk.Label(right_frame, text="-", foreground='#666666')
        self.analysis_labels['status'].grid(row=1, column=1, sticky='w', padx=(10, 0), pady=2)
        
        ttk.Label(right_frame, text="File Size:", font=('Segoe UI', 9, 'bold')).grid(row=2, column=0, sticky='w', pady=2)
        self.analysis_labels['file_size'] = ttk.Label(right_frame, text="-", foreground='#666666')
        self.analysis_labels['file_size'].grid(row=2, column=1, sticky='w', padx=(10, 0), pady=2)
    
    def update_analysis(self, filepath):
        """Update the analysis display with file information."""
        try:
            result = analyze_pe_file(filepath)
            
            if not result.is_pe:
                self._show_not_pe()
                return
            
            # File type with AHK version
            file_type = result.additional_info.get('File Type', 'PE Executable')
            ahk_version = result.additional_info.get('AHK Version', '')
            if ahk_version:
                file_type += f" (v{ahk_version})"
            self.analysis_labels['file_type'].config(text=file_type, foreground='#2c3e50')
            
            # Architecture
            arch = result.additional_info.get('Architecture', 'Unknown')
            self.analysis_labels['architecture'].config(text=arch, foreground='#2c3e50')
            
            # Compiler
            compiler_text = result.compiler.value
            if result.compiler_version:
                compiler_text += f" {result.compiler_version}"
            self.analysis_labels['compiler'].config(text=compiler_text, foreground='#2c3e50')
            
            # Packer with color coding
            packer_text = result.packer.value
            if result.packer_version:
                packer_text += f" {result.packer_version}"
            
            if result.packer == PackerType.NONE:
                packer_color = '#28a745'  # Green
            elif result.packer in [PackerType.MPRESS, PackerType.UPX]:
                packer_color = '#ffc107'  # Yellow
            else:
                packer_color = '#dc3545'  # Red
            
            self.analysis_labels['packer'].config(text=packer_text, foreground=packer_color)
            
            # Status
            status = result.additional_info.get('Packing Status', 'Unknown')
            status_color = '#28a745' if 'Not Packed' in status else '#ffc107'
            self.analysis_labels['status'].config(text=status, foreground=status_color)
            
            # File size
            file_size = result.additional_info.get('File Size', 'Unknown')
            self.analysis_labels['file_size'].config(text=file_size, foreground='#2c3e50')
            
        except Exception as e:
            self._show_error(str(e))
    
    def _show_not_pe(self):
        """Show that file is not a valid PE."""
        self.analysis_labels['file_type'].config(text="Not a valid PE file", foreground='#dc3545')
        for key in ['architecture', 'compiler', 'packer', 'status', 'file_size']:
            self.analysis_labels[key].config(text="-", foreground='#666666')
    
    def _show_error(self, error):
        """Show analysis error."""
        self.analysis_labels['file_type'].config(text=f"Analysis error: {error}", foreground='#dc3545')
        for key in ['architecture', 'compiler', 'packer', 'status', 'file_size']:
            self.analysis_labels[key].config(text="-", foreground='#666666')
    
    def clear(self):
        """Clear the analysis display."""
        self.analysis_labels['file_type'].config(text="Not analyzed", foreground='#666666')
        for key in ['architecture', 'compiler', 'packer', 'status', 'file_size']:
            self.analysis_labels[key].config(text="-", foreground='#666666') 