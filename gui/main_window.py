"""
Main window for the AHK Decompiler GUI.
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import subprocess
import time
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.constants import (
    DEFAULT_OUTPUT_DIR, MAX_WORKER_THREADS
)
from core.monitor import (
    monitor_child_processes, get_process_info, get_active_pids, terminate_process_safely
)
from core.extractor import process_single_pid
from core.memory import wait_for_unpack
from core.resources import extract_scripts_from_resources
from utils.pe_analyzer import analyze_pe_file, PackerType

from .components import GUILogHandler
from .theming import setup_gui_styles
from .utils import center_window, setup_mousewheel_scrolling, show_completion_message, validate_file_selection
from .layout import (
    setup_header_section, setup_config_section, setup_progress_section,
    setup_pe_analysis_section, setup_process_section, setup_log_section, setup_action_section,
    setup_scrollable_frame
)


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
        self._setup_logging()
        
    def _setup_window(self):
        """Configure the main window."""
        self.root.title('AHK Decompiler - Multi-Process Script Extractor')
        self.root.geometry('700x800')
        self.root.minsize(650, 700)
        
        center_window(self.root, 700, 800)
    
    def _setup_styles(self):
        """Configure custom styles."""
        self.style = setup_gui_styles()
    
    def _setup_gui(self):
        """Set up the enhanced GUI components with vertical scrolling."""
        # Setup scrollable container
        self.canvas, self.scrollable_frame = setup_scrollable_frame(self.root)
        setup_mousewheel_scrolling(self.canvas, self.scrollable_frame, self.root)
        
        # Setup GUI sections
        self._setup_variables()
        self._setup_sections()
    
    def _setup_variables(self):
        """Setup tkinter variables."""
        self.file_path_var = tk.StringVar(value="No file selected")
        self.monitor_children = tk.BooleanVar(value=True)
        self.extract_resources = tk.BooleanVar(value=True)
        self.auto_open = tk.BooleanVar(value=True)
    
    def _setup_sections(self):
        """Setup all GUI sections."""
        # Header
        self.header_frame = setup_header_section(self.scrollable_frame)
        
        # Configuration
        self.config_frame, self.file_entry, self.browse_button = setup_config_section(
            self.scrollable_frame, self.file_path_var, self.pick_file,
            self.monitor_children, self.extract_resources, self.auto_open
        )
        
        # Progress
        self.progress_widget = setup_progress_section(self.scrollable_frame)
        
        # PE Analysis
        self.pe_analysis_widget = setup_pe_analysis_section(self.scrollable_frame)
        
        # Process monitoring
        self.process_widget = setup_process_section(self.scrollable_frame)
        
        # Log
        self.log_widget = setup_log_section(self.scrollable_frame)
        
        # Action buttons
        self.action_frame, self.run_button, self.stop_button, self.clear_log_button, self.open_folder_button = setup_action_section(
            self.scrollable_frame, self.start_dump, self.stop_extraction, self.clear_log
        )
    
    def _setup_logging(self):
        """Setup logging to redirect to GUI log widget."""
        logging.basicConfig(level=logging.INFO)
        
        gui_handler = GUILogHandler(self.log_widget, self.root)
        gui_handler.setFormatter(logging.Formatter('%(message)s'))
        
        resources_logger = logging.getLogger('core.resources')
        resources_logger.addHandler(gui_handler)
        resources_logger.setLevel(logging.INFO)
    
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
            self._reset_ui_state()

            base_name = os.path.basename(filepath)
            self.log_widget.log(f"Selected file: {base_name}", 'info')

            try:
                self.pe_analysis_widget.update_analysis(filepath)
                result = analyze_pe_file(filepath)
                
                if result.is_pe:
                    if result.additional_info.get('File Type', '').startswith('AutoHotkey'):
                        self.log_widget.log("✓ AutoHotkey executable detected", 'success')
                        ahk_version = result.additional_info.get('AHK Version', '')
                        if ahk_version:
                            self.log_widget.log(f"  AHK Version: {ahk_version}", 'info')
                    else:
                        self.log_widget.log("⚠ Not an AutoHotkey executable", 'warning')
                    
                    if result.is_packed:
                        packer_name = result.packer.value
                        if result.packer_version:
                            packer_name += f" {result.packer_version}"
                        confidence = f"{result.confidence:.0%}"
                        self.log_widget.log(f"📦 Packer detected: {packer_name} ({confidence} confidence)", 'warning')
                        
                        if result.packer == PackerType.MPRESS:
                            self.log_widget.log("  MPRESS is commonly used with AHK executables", 'info')
                        elif result.packer == PackerType.UPX:
                            self.log_widget.log("  UPX packer detected - may require special handling", 'info')
                        elif result.packer == PackerType.UNKNOWN:
                            self.log_widget.log("  Unknown packer - extraction may be challenging", 'warning')
                    else:
                        self.log_widget.log("✓ No packer detected", 'success')
                    
                    arch = result.additional_info.get('Architecture', 'Unknown')
                    self.log_widget.log(f"Architecture: {arch}", 'info')
                    
                else:
                    self.log_widget.log("❌ Not a valid PE executable", 'error')
                    
            except Exception as exc:
                self.log_widget.log(f"PE analysis failed: {exc}", 'warning')
                self.pe_analysis_widget._show_error(str(exc))
    
    def clear_log(self):
        """Clear the log widget."""
        self.log_widget.clear()
        self.pe_analysis_widget.clear()
    
    def _reset_ui_state(self):
        """Reset UI state to ready state - centralized button control."""
        try:
            self.run_button.config(state='normal' if self.exe else 'disabled')
            self.stop_button.config(state='disabled')
        except Exception:
            pass
    
    def stop_extraction(self):
        """Stop the extraction process."""
        self.stop_monitoring.set()
        self.log_widget.log("Stopping extraction process...", 'warning')
        
        try:
            self._terminate_all_monitored_processes()
        except Exception as e:
            self.log_widget.log(f"Error during process termination: {str(e)}", 'warning')
        
        self._reset_ui_state()
    
    def update_process_list(self):
        """Update the process list display - thread safe version."""
        self.root.after(0, self._update_process_list_gui)
    
    def _update_process_list_gui(self):
        """Update the process list display in the main thread."""
        self.process_widget.update_processes(self.monitored_pids)
    
    def start_dump(self):
        """Start the dump process in a separate thread."""
        if not validate_file_selection(self.exe):
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
            # Phase 0: Extract from resources first (if enabled)
            if self.extract_resources.get():
                self.progress_widget.set_phase("📦 Extracting resources", "Analyzing RCDATA resources...")
                self.progress_widget.set_progress(2)
                
                try:
                    resource_scripts = extract_scripts_from_resources(self.exe, DEFAULT_OUTPUT_DIR)
                    if resource_scripts > 0:
                        self.log_widget.log(f"Found {resource_scripts} script(s) in RCDATA resources", 'success')
                        total_scripts += resource_scripts
                    else:
                        self.log_widget.log("No scripts found in RCDATA resources", 'info')
                except Exception as e:
                    self.log_widget.log(f"Resource extraction failed: {str(e)}", 'warning')
            
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
                
                self._wait_for_child_processes(main_pid)
            
            # Phase 5: Script extraction
            if not self.stop_monitoring.is_set():
                self.progress_widget.set_phase("📜 Extracting scripts", "Processing all detected processes...")
                self.progress_widget.set_progress(60)
                
                # Check if we have any active processes to analyze
                active_pids = get_active_pids(self.monitored_pids)
                if not active_pids:
                    error_msg = "No active processes available for analysis"
                    self.log_widget.log(error_msg, 'error')
                    if total_scripts == 0:  # Only raise error if no scripts found via resources
                        raise Exception(error_msg)
                else:
                    memory_scripts = self._extract_from_all_processes(main_pid)
                    total_scripts += memory_scripts
                    self.log_widget.log(f"Memory extraction: {memory_scripts} script(s) found", 'info')
            
            # Phase 6: Cleanup
            self.progress_widget.set_phase("🧹 Cleanup", "Terminating processes...")
            self.progress_widget.set_progress(90)
            
            self._terminate_all_monitored_processes()
            
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
            
            # Ensure all processes are terminated even if there was an error
            try:
                self._terminate_all_monitored_processes()
            except Exception as e:
                self.log_widget.log(f"Error during final cleanup: {str(e)}", 'warning')
            
            # Reset UI state - ensure buttons are properly reset regardless of how process ended
            self.root.after(0, self._reset_ui_state)
    
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
    
    def _wait_for_child_processes(self, main_pid):
        """Wait for child processes with progress updates."""
        self.log_widget.log("Monitoring for child processes...", 'info')
        
        # Wait longer for subprocesses to appear and stabilize
        wait_cycles = 15  # Increased from 5 to 15 (30 seconds total)
        main_process_died_at_cycle = None
        
        for i in range(wait_cycles):
            if self.stop_monitoring.is_set():
                break
            
            # Check if main process is still alive
            main_process_info = get_process_info(main_pid)
            if not main_process_info['exists']:
                if main_process_died_at_cycle is None:
                    main_process_died_at_cycle = i
                    self.log_widget.log("Main process terminated - continuing to monitor for child processes...", 'warning')
                
                # Check how long since main process died
                cycles_since_death = i - main_process_died_at_cycle
                
                # Give more time for child processes to appear after main process death
                if cycles_since_death >= 5:  # 10 seconds after main process death
                    active_children = [pid for pid in self.monitored_pids if pid != main_pid and get_process_info(pid)['exists']]
                    
                    if not active_children:
                        # Check if we ever had child processes
                        total_detected = len(self.monitored_pids) - 1  # Subtract main process
                        if total_detected == 0:
                            self.log_widget.log("Main process terminated and no child processes found after waiting - stopping monitoring", 'error')
                            self.stop_monitoring.set()
                            raise Exception("Main process terminated without spawning child processes")
                        else:
                            # Had child processes but they all died
                            self.log_widget.log("Main process and all child processes terminated - stopping monitoring", 'warning')
                            break
                    else:
                        self.log_widget.log(f"Main process terminated but {len(active_children)} child process(es) still running - continuing...", 'info')
                
            current_count = len(self.monitored_pids)
            
            # Log progress every few cycles
            if i % 3 == 0:
                elapsed = (i + 1) * 2
                main_status = "terminated" if main_process_died_at_cycle is not None else "running"
                self.log_widget.log(f"Waiting for child processes... ({elapsed}s elapsed, {current_count-1} processes detected, main: {main_status})", 'info')
            
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
            active_children = [pid for pid in self.monitored_pids if pid != main_pid and get_process_info(pid)['exists']]
            self.log_widget.log(f"Child process detection complete. Found {len(active_children)} active child process(es)", 'success')
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
    
    def _terminate_all_monitored_processes(self):
        """Terminate all monitored processes (main + children)."""
        active_pids = get_active_pids(self.monitored_pids)
        
        if not active_pids:
            self.log_widget.log("No active processes to terminate", 'info')
            return
        
        self.log_widget.log(f"Terminating {len(active_pids)} process(es)...", 'info')
        
        terminated_count = 0
        for pid in active_pids:
            try:
                process_info = get_process_info(pid)
                if process_info['exists']:
                    success = terminate_process_safely(pid)
                    if success:
                        terminated_count += 1
                        self.log_widget.log(f"Terminated process {pid} ({process_info['name']})", 'success')
                    else:
                        self.log_widget.log(f"Failed to terminate process {pid} ({process_info['name']})", 'warning')
                else:
                    self.log_widget.log(f"Process {pid} already terminated", 'info')
            except Exception as e:
                self.log_widget.log(f"Error terminating process {pid}: {str(e)}", 'warning')
        
        self.log_widget.log(f"Process cleanup complete: {terminated_count}/{len(active_pids)} processes terminated", 'info')
    
    def _show_final_results(self, total_scripts, main_process_terminated, main_process_unpacked):
        """Show final results with detailed logging."""
        active_processes = len(get_active_pids(self.monitored_pids))
        
        self.log_widget.log("=" * 50, 'info')
        self.log_widget.log("EXTRACTION COMPLETE", 'success')
        self.log_widget.log("=" * 50, 'info')
        self.log_widget.log(f"Total scripts extracted: {total_scripts}", 'success')
        self.log_widget.log(f"Processes analyzed: {active_processes}", 'info')
        
        # Show breakdown if resources were also extracted
        if self.extract_resources.get():
            self.log_widget.log("Scripts found from: RCDATA resources + process memory", 'info')
        
        if main_process_terminated:
            self.log_widget.log("Note: Main process terminated early", 'warning')
        elif not main_process_unpacked:
            self.log_widget.log("Warning: Main process unpack timeout", 'warning')
        
        if total_scripts > 0:
            self.open_folder_button.config(state='normal')
            self.log_widget.log(f"Scripts saved to: {DEFAULT_OUTPUT_DIR}/", 'success')
            
            if self.auto_open.get():
                from .utils import open_output_folder
                open_output_folder()
        else:
            self.log_widget.log("No scripts found. Try running as administrator or verify the executable contains AHK scripts.", 'warning')
        
        # Show completion message
        show_completion_message(total_scripts) 