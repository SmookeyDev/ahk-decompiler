"""
Graphical user interface for the AHK Decompiler.
"""

import tkinter as tk
from tkinter import filedialog, ttk, messagebox, scrolledtext
import threading
import webbrowser
import subprocess
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from utils.constants import (
    DEFAULT_OUTPUT_DIR, MAX_WORKER_THREADS, PROGRESS_BAR_LENGTH,
    PROCESS_LIST_HEIGHT, PROCESS_LIST_WIDTH
)
from core.monitor import (
    monitor_child_processes, get_process_info, get_active_pids, terminate_process_safely
)
from core.extractor import process_single_pid
from core.memory import wait_for_unpack


class ModernProgressBar:
    """Custom progress bar with phases and better visual feedback."""
    
    def __init__(self, parent, width=400):
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill='x', padx=10, pady=5)
        
        # Phase label
        self.phase_label = ttk.Label(self.frame, text="Ready", font=('Segoe UI', 9, 'bold'))
        self.phase_label.pack(anchor='w')
        
        # Progress bar
        self.progressbar = ttk.Progressbar(
            self.frame, 
            length=width, 
            mode='determinate',
            style='Custom.Horizontal.TProgressbar'
        )
        self.progressbar.pack(fill='x', pady=(2, 0))
        
        # Status label
        self.status_label = ttk.Label(self.frame, text="", font=('Segoe UI', 8))
        self.status_label.pack(anchor='w')
        
        # Configure custom style
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


class LogWidget:
    """Enhanced log widget with timestamps and colored messages."""
    
    def __init__(self, parent):
        self.frame = ttk.LabelFrame(parent, text="Activity Log", padding=5)
        self.frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Text widget with scrollbar
        self.text = scrolledtext.ScrolledText(
            self.frame, 
            height=8, 
            wrap=tk.WORD,
            font=('Consolas', 9),
            bg='#f8f9fa',
            fg='#333333'
        )
        self.text.pack(fill='both', expand=True)
        
        # Configure text tags for colored output
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
        
        # Auto-scroll to bottom
        self.text.see(tk.END)
        
        # Update the GUI
        self.text.update_idletasks()
    
    def clear(self):
        """Clear the log."""
        self.text.delete(1.0, tk.END)


class ProcessListWidget:
    """Enhanced process list with status indicators."""
    
    def __init__(self, parent):
        self.frame = ttk.LabelFrame(parent, text="Monitored Processes", padding=5)
        self.frame.pack(fill='x', padx=10, pady=5)
        
        # Treeview for better process display
        columns = ('PID', 'Name', 'Status')
        self.tree = ttk.Treeview(self.frame, columns=columns, show='headings', height=6)
        
        # Configure columns
        self.tree.heading('PID', text='PID')
        self.tree.heading('Name', text='Process Name')
        self.tree.heading('Status', text='Status')
        
        self.tree.column('PID', width=80)
        self.tree.column('Name', width=200)
        self.tree.column('Status', width=120)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Status tracking
        self.process_status = {}
    
    def update_processes(self, monitored_pids):
        """Update the process list."""
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
        
        # Find and update the item
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if values and int(values[0]) == pid:
                self.tree.item(item, values=(values[0], values[1], status))
                break


class DumpGUI:
    """Modern GUI class for the AHK Decompiler application."""
    
    def __init__(self, root):
        """Initialize the enhanced GUI."""
        self.root = root
        self.exe = None
        self.monitored_pids = set()
        self.stop_monitoring = threading.Event()
        self.current_phase = "Ready"
        
        self._setup_window()
        self._setup_styles()
        self._setup_gui()
        
    def _setup_window(self):
        """Configure the main window."""
        self.root.title('AHK Decompiler - Multi-Process Script Extractor')
        self.root.geometry('700x800')
        self.root.minsize(650, 700)
        
        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (700 // 2)
        y = (self.root.winfo_screenheight() // 2) - (800 // 2)
        self.root.geometry(f'700x800+{x}+{y}')
    
    def _setup_styles(self):
        """Configure custom styles."""
        style = ttk.Style()
        
        # Use modern theme
        try:
            style.theme_use('vista')  # Windows modern theme
        except:
            style.theme_use('clam')   # Fallback
        
        # Configure custom button styles
        style.configure(
            'Primary.TButton',
            font=('Segoe UI', 10, 'bold')
        )
        
        style.configure(
            'Secondary.TButton',
            font=('Segoe UI', 9)
        )
    
    def _setup_gui(self):
        """Set up the enhanced GUI components."""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(fill='both', expand=True)
        
        # Header section
        self._setup_header(main_frame)
        
        # Configuration section
        self._setup_config_section(main_frame)
        
        # Progress section
        self._setup_progress_section(main_frame)
        
        # Process monitoring section
        self._setup_process_section(main_frame)
        
        # Log section
        self._setup_log_section(main_frame)
        
        # Action buttons section
        self._setup_action_section(main_frame)
    
    def _setup_header(self, parent):
        """Setup header section."""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill='x', pady=(0, 20))
        
        # Title
        title_label = ttk.Label(
            header_frame, 
            text="AutoHotkey Script Decompiler",
            font=('Segoe UI', 16, 'bold'),
            foreground='#2c3e50'
        )
        title_label.pack()
        
        # Subtitle
        subtitle_label = ttk.Label(
            header_frame, 
            text="Extract AHK scripts from compiled executables",
            font=('Segoe UI', 10),
            foreground='#7f8c8d'
        )
        subtitle_label.pack()
        
        # Separator
        ttk.Separator(header_frame, orient='horizontal').pack(fill='x', pady=(10, 0))
    
    def _setup_config_section(self, parent):
        """Setup configuration section."""
        config_frame = ttk.LabelFrame(parent, text="Configuration", padding=10)
        config_frame.pack(fill='x', pady=(0, 10))
        
        # File selection
        file_frame = ttk.Frame(config_frame)
        file_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(file_frame, text="Target Executable:").pack(anchor='w')
        
        file_select_frame = ttk.Frame(file_frame)
        file_select_frame.pack(fill='x', pady=(5, 0))
        
        self.file_path_var = tk.StringVar(value="No file selected")
        self.file_entry = ttk.Entry(
            file_select_frame, 
            textvariable=self.file_path_var,
            state='readonly',
            font=('Segoe UI', 9)
        )
        self.file_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        self.browse_button = ttk.Button(
            file_select_frame,
            text="Browse...",
            command=self.pick_file,
            style='Secondary.TButton'
        )
        self.browse_button.pack(side='right')
        
        # Options
        options_frame = ttk.Frame(config_frame)
        options_frame.pack(fill='x')
        
        self.monitor_children = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame,
            text="Monitor child processes (recommended)",
            variable=self.monitor_children
        ).pack(anchor='w')
        
        self.auto_open = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame,
            text="Auto-open output folder when complete",
            variable=self.auto_open
        ).pack(anchor='w')
    
    def _setup_progress_section(self, parent):
        """Setup progress section."""
        self.progress_widget = ModernProgressBar(parent)
    
    def _setup_process_section(self, parent):
        """Setup process monitoring section."""
        self.process_widget = ProcessListWidget(parent)
    
    def _setup_log_section(self, parent):
        """Setup log section."""
        self.log_widget = LogWidget(parent)
    
    def _setup_action_section(self, parent):
        """Setup action buttons section."""
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill='x', pady=(10, 0))
        
        # Left side buttons
        left_frame = ttk.Frame(action_frame)
        left_frame.pack(side='left')
        
        self.run_button = ttk.Button(
            left_frame,
            text="🚀 Start Extraction",
            command=self.start_dump,
            state='disabled',
            style='Primary.TButton'
        )
        self.run_button.pack(side='left', padx=(0, 10))
        
        self.stop_button = ttk.Button(
            left_frame,
            text="⏹ Stop",
            command=self.stop_extraction,
            state='disabled',
            style='Secondary.TButton'
        )
        self.stop_button.pack(side='left', padx=(0, 10))
        
        # Right side buttons
        right_frame = ttk.Frame(action_frame)
        right_frame.pack(side='right')
        
        self.clear_log_button = ttk.Button(
            right_frame,
            text="Clear Log",
            command=self.clear_log,
            style='Secondary.TButton'
        )
        self.clear_log_button.pack(side='left', padx=(0, 10))
        
        self.open_folder_button = ttk.Button(
            right_frame,
            text="📁 Open Output Folder",
            command=self.open_output_folder,
            state='disabled',
            style='Secondary.TButton'
        )
        self.open_folder_button.pack(side='left')
    
    def pick_file(self):
        """Handle file selection dialog."""
        filepath = filedialog.askopenfilename(
            title="Select AutoHotkey Executable",
            filetypes=[
                ('Executable files', '*.exe'),
                ('All files', '*.*')
            ]
        )
        
        if filepath:
            self.exe = filepath
            self.file_path_var.set(filepath)
            self.run_button.config(state='normal')
            self.log_widget.log(f"Selected file: {os.path.basename(filepath)}", 'info')
    
    def clear_log(self):
        """Clear the log widget."""
        self.log_widget.clear()
    
    def open_output_folder(self):
        """Open the output folder."""
        if os.path.exists(DEFAULT_OUTPUT_DIR):
            webbrowser.open(DEFAULT_OUTPUT_DIR)
        else:
            messagebox.showwarning("Folder Not Found", f"Output folder '{DEFAULT_OUTPUT_DIR}' does not exist yet.")
    
    def stop_extraction(self):
        """Stop the extraction process."""
        self.stop_monitoring.set()
        self.log_widget.log("Stopping extraction process...", 'warning')
    
    def update_process_list(self):
        """Update the process list display - thread safe version."""
        self.root.after(0, self._update_process_list_gui)
    
    def _update_process_list_gui(self):
        """Update the process list display in the main thread."""
        self.process_widget.update_processes(self.monitored_pids)
    
    def start_dump(self):
        """Start the dump process in a separate thread."""
        if not self.exe:
            messagebox.showerror("No File Selected", "Please select an executable file first.")
            return
        
        # Reset UI state
        self.run_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.progress_widget.reset()
        self.stop_monitoring.clear()
        self.monitored_pids.clear()
        self.open_folder_button.config(state='disabled')
        
        # Clear and start logging
        self.log_widget.clear()
        self.log_widget.log("Starting AHK script extraction process...", 'info')
        self.log_widget.log(f"Target: {os.path.basename(self.exe)}", 'info')
        
        # Start extraction in separate thread
        threading.Thread(target=self.dump_process, daemon=True).start()
    
    def dump_process(self):
        """Enhanced dump process with detailed progress tracking."""
        monitor_thread = None
        main_process_unpacked = False
        main_process_terminated = False
        total_scripts = 0
        
        try:
            # Phase 1: Initialize process
            self.progress_widget.set_phase("🚀 Initializing", "Starting target process...")
            self.progress_widget.set_progress(5)
            
            proc = subprocess.Popen(self.exe)
            main_pid = proc.pid
            self.monitored_pids.add(main_pid)
            
            self.log_widget.log(f"Started main process (PID: {main_pid})", 'success')
            
            # Phase 2: Setup monitoring
            if self.monitor_children.get():
                self.progress_widget.set_phase("👁 Setting up monitoring", "Starting child process monitor...")
                self.progress_widget.set_progress(10)
                
                monitor_thread = threading.Thread(
                    target=monitor_child_processes,
                    args=(main_pid, self.monitored_pids, self.stop_monitoring, self.update_process_list)
                )
                monitor_thread.start()
                self.log_widget.log("Child process monitoring enabled", 'info')
            
            self.update_process_list()
            
            # Phase 3: Wait for unpacking
            self.progress_widget.set_phase("⏳ Waiting for unpacking", "Analyzing main process...")
            self.progress_widget.set_progress(20)
            
            main_process_unpacked, main_process_terminated = self._handle_main_process_unpack(main_pid)
            
            # Phase 4: Child process detection
            if self.monitor_children.get() and not self.stop_monitoring.is_set():
                self.progress_widget.set_phase("🔍 Detecting child processes", "Waiting for spawned processes...")
                self.progress_widget.set_progress(40)
                
                self._wait_for_child_processes()
            
            # Phase 5: Script extraction
            if not self.stop_monitoring.is_set():
                self.progress_widget.set_phase("📜 Extracting scripts", "Processing all detected processes...")
                self.progress_widget.set_progress(60)
                
                total_scripts = self._extract_from_all_processes(main_pid)
            
            # Phase 6: Cleanup
            self.progress_widget.set_phase("🧹 Cleanup", "Terminating processes...")
            self.progress_widget.set_progress(90)
            
            terminate_process_safely(main_pid)
            
            # Phase 7: Complete
            self.progress_widget.set_phase("✅ Complete", f"Extracted {total_scripts} script(s)")
            self.progress_widget.set_progress(100)
            
            self._show_final_results(total_scripts, main_process_terminated, main_process_unpacked)
            
        except Exception as e:
            self.log_widget.log(f"Error during extraction: {str(e)}", 'error')
            self.progress_widget.set_phase("❌ Error", str(e))
            messagebox.showerror("Extraction Error", f"An error occurred during extraction:\n{str(e)}")
            
        finally:
            self.stop_monitoring.set()
            if monitor_thread:
                monitor_thread.join(timeout=5)
            
            # Reset UI state
            self.root.after(0, lambda: self.run_button.config(state='normal'))
            self.root.after(0, lambda: self.stop_button.config(state='disabled'))
    
    def _handle_main_process_unpack(self, main_pid):
        """Handle main process unpacking with progress updates."""
        main_process_unpacked = False
        main_process_terminated = False
        
        if get_process_info(main_pid)['exists']:
            self.log_widget.log("Waiting for main process to unpack...", 'info')
            main_process_unpacked = wait_for_unpack(main_pid)
            
            if not main_process_unpacked:
                if get_process_info(main_pid)['exists']:
                    self.log_widget.log("Main process unpack timeout, continuing...", 'warning')
                else:
                    main_process_terminated = True
                    self.log_widget.log("Main process terminated during unpack", 'warning')
            else:
                self.log_widget.log("Main process unpacked successfully", 'success')
        else:
            main_process_terminated = True
            self.log_widget.log("Main process terminated early", 'warning')
            
        return main_process_unpacked, main_process_terminated
    
    def _wait_for_child_processes(self):
        """Wait for child processes with progress updates."""
        self.log_widget.log("Monitoring for child processes...", 'info')
        
        # Wait longer for subprocesses to appear and stabilize
        wait_cycles = 15  # Increased from 5 to 15 (30 seconds total)
        
        for i in range(wait_cycles):
            if self.stop_monitoring.is_set():
                break
                
            current_count = len(self.monitored_pids)
            
            # Log progress every few cycles
            if i % 3 == 0:
                elapsed = (i + 1) * 2
                self.log_widget.log(f"Waiting for child processes... ({elapsed}s elapsed, {current_count-1} processes detected)", 'info')
            
            time.sleep(2)  # Check every 2 seconds
            self.update_process_list()
            
            # If we detected new processes in the last few cycles, wait a bit more
            if i >= 10:  # After 20 seconds
                recent_count = len(self.monitored_pids)
                if recent_count > current_count:
                    self.log_widget.log("New processes detected, extending monitoring time...", 'info')
                    wait_cycles = min(wait_cycles + 3, 25)  # Extend but cap at 50 seconds total
        
        final_count = len(self.monitored_pids)
        if final_count > 1:  # More than just the main process
            self.log_widget.log(f"Child process detection complete. Found {final_count-1} child process(es)", 'success')
        else:
            self.log_widget.log("No child processes detected", 'info')
    
    def _extract_from_all_processes(self, main_pid):
        """Extract scripts with detailed progress tracking."""
        active_pids = get_active_pids(self.monitored_pids)
        
        if not active_pids:
            self.log_widget.log("No active processes found to analyze", 'warning')
            return 0
        
        self.log_widget.log(f"Processing {len(active_pids)} processes simultaneously...", 'info')
        
        total_scripts = 0
        
        # Use ThreadPoolExecutor with progress tracking
        max_workers = min(len(active_pids), MAX_WORKER_THREADS)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_pid = {
                executor.submit(process_single_pid, pid, pid == main_pid): pid 
                for pid in active_pids
            }
            
            # Track progress
            completed = 0
            for future in as_completed(future_to_pid):
                if self.stop_monitoring.is_set():
                    break
                    
                result = future.result()
                pid = result['pid']
                total_scripts += result['scripts_count']
                
                completed += 1
                progress = 60 + (completed / len(active_pids)) * 25  # 60-85% range
                self.progress_widget.set_progress(progress)
                
                # Log result
                if result['scripts_count'] > 0:
                    self.log_widget.log(f"PID {pid}: Extracted {result['scripts_count']} script(s)", 'success')
                else:
                    status_msg = result['status'].replace('_', ' ').title()
                    self.log_widget.log(f"PID {pid}: {status_msg}", 'warning')
                
                # Update process status
                self.process_widget.set_process_status(pid, result['status'])
        
        return total_scripts
    
    def _show_final_results(self, total_scripts, main_process_terminated, main_process_unpacked):
        """Show final results with detailed logging."""
        active_processes = len(get_active_pids(self.monitored_pids))
        
        self.log_widget.log("=" * 50, 'info')
        self.log_widget.log("EXTRACTION COMPLETE", 'success')
        self.log_widget.log("=" * 50, 'info')
        self.log_widget.log(f"Total scripts extracted: {total_scripts}", 'success')
        self.log_widget.log(f"Processes analyzed: {active_processes}", 'info')
        
        if main_process_terminated:
            self.log_widget.log("Note: Main process terminated early", 'warning')
        elif not main_process_unpacked:
            self.log_widget.log("Warning: Main process unpack timeout", 'warning')
        
        if total_scripts > 0:
            self.open_folder_button.config(state='normal')
            self.log_widget.log(f"Scripts saved to: {DEFAULT_OUTPUT_DIR}/", 'success')
            
            if self.auto_open.get():
                self.open_output_folder()
        else:
            self.log_widget.log("No scripts found. Try running as administrator or verify the executable contains AHK scripts.", 'warning')
        
        # Show completion message
        if total_scripts > 0:
            messagebox.showinfo(
                "Extraction Complete", 
                f"Successfully extracted {total_scripts} script(s)!\n\nScripts saved to '{DEFAULT_OUTPUT_DIR}' folder."
            )
        else:
            messagebox.showwarning(
                "No Scripts Found",
                "No AHK scripts were found in the target executable.\n\nTry:\n• Running as administrator\n• Verifying the file contains AHK scripts\n• Checking the log for details"
            ) 