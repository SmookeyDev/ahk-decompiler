"""
Process monitoring components for the AHK Decompiler GUI.
"""

import tkinter as tk
from tkinter import ttk

from core.monitor import get_process_info


class ProcessListWidget:
    """Enhanced process list with status indicators."""
    
    def __init__(self, parent):
        self.frame = ttk.LabelFrame(parent, text="Monitored Processes", padding=5)
        self.frame.pack(fill='x', padx=10, pady=5)
        
        self.process_status = {}
        self._setup_treeview()
    
    def _setup_treeview(self):
        """Setup the treeview widget for process display."""
        columns = ('PID', 'Name', 'Status')
        self.tree = ttk.Treeview(self.frame, columns=columns, show='headings', height=6)
        
        # Configure column headings
        self.tree.heading('PID', text='PID')
        self.tree.heading('Name', text='Process Name')
        self.tree.heading('Status', text='Status')
        
        # Configure column widths
        self.tree.column('PID', width=80)
        self.tree.column('Name', width=200)
        self.tree.column('Status', width=120)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
    
    def update_processes(self, monitored_pids):
        """Update the process list with current PIDs."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add current processes
        for pid in monitored_pids:
            process_info = get_process_info(pid)
            status = "Running" if process_info['exists'] else "Terminated"
            
            self.tree.insert('', tk.END, values=(
                pid,
                process_info['name'],
                status
            ))
    
    def set_process_status(self, pid, status):
        """Update specific process status."""
        self.process_status[pid] = status
        
        # Find and update the process in the tree
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if values and int(values[0]) == pid:
                self.tree.item(item, values=(values[0], values[1], status))
                break
    
    def get_process_count(self):
        """Get the number of processes currently displayed."""
        return len(self.tree.get_children())
    
    def clear(self):
        """Clear all processes from the display."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.process_status.clear()
    
    def get_process_list(self):
        """Get list of all processes with their information."""
        processes = []
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if values:
                processes.append({
                    'pid': int(values[0]),
                    'name': values[1],
                    'status': values[2]
                })
        return processes 