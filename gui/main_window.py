"""Tkinter presentation; all workers communicate through a queue."""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

from core.engine import ExtractionEngine, analyze_target
from core.models import ExtractionConfig, Status
from core.version import __version__

from .layout import (
    setup_action_section,
    setup_config_section,
    setup_header_section,
    setup_log_section,
    setup_pe_analysis_section,
    setup_process_section,
    setup_progress_section,
    setup_scrollable_frame,
)
from .theming import setup_gui_styles
from .utils import center_window, setup_mousewheel_scrolling
from .utils.file_operations import open_file_in_default_app


class DumpGUI:
    def __init__(self, root):
        self.root = root
        self.exe = None
        self._events = queue.Queue()
        self._worker = None
        self._cancel = None
        self._generation = 0
        self._closing = False
        self._result = None
        self._processes = {}
        self._analysis_generation = 0
        root.title(f"AHK Decompiler {__version__}")
        root.geometry("780x880")
        root.minsize(700, 720)
        center_window(root, 780, 880)
        self.style = setup_gui_styles()
        self.canvas, self.scrollable_frame = setup_scrollable_frame(root)
        setup_mousewheel_scrolling(self.canvas, self.scrollable_frame, root)
        self.file_path_var = tk.StringVar(value="No file selected")
        self.monitor_children = tk.BooleanVar(value=True)
        self.extract_resources = tk.BooleanVar(value=True)
        self.auto_open = tk.BooleanVar(value=False)
        self.mode = tk.StringVar(value="Static resources (does not run target)")
        self.timeout = tk.StringVar(value="30")
        self.output_path = tk.StringVar(value=str(Path("dump_scripts").resolve()))
        setup_header_section(self.scrollable_frame)
        self.config_frame, self.file_entry, self.browse_button = setup_config_section(
            self.scrollable_frame,
            self.file_path_var,
            self.pick_file,
            self.monitor_children,
            self.extract_resources,
            self.auto_open,
            self.mode,
            self.output_path,
            self.pick_output,
            self.timeout,
        )
        self.progress_widget = setup_progress_section(self.scrollable_frame)
        self.pe_analysis_widget = setup_pe_analysis_section(self.scrollable_frame)
        self.process_widget = setup_process_section(self.scrollable_frame)
        self.log_widget = setup_log_section(self.scrollable_frame)
        _, self.run_button, self.stop_button, self.clear_log_button, self.open_folder_button = (
            setup_action_section(self.scrollable_frame, self.start_dump, self.stop_extraction, self.clear_log)
        )
        self.open_folder_button.config(command=self.open_output)
        from tkinter import ttk

        ttk.Button(
            self.scrollable_frame, text="Export diagnostic JSON...", command=self.export_diagnostics
        ).pack(anchor="e", pady=4)
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(50, self._drain)

    @property
    def running(self):
        return self._worker is not None and self._worker.is_alive()

    def pick_output(self):
        destination = filedialog.askdirectory(title="Output directory")
        if destination:
            self.output_path.set(destination)

    def pick_file(self):
        if self.running:
            return
        path = filedialog.askopenfilename(
            title="Select compiled AutoHotkey file",
            filetypes=[("Executables", "*.exe"), ("All files", "*.*")],
        )
        if not path:
            return
        self.exe = path
        self.file_path_var.set(path)
        self.run_button.config(state="normal")
        self._analysis_generation += 1
        generation = self._analysis_generation
        self.log_widget.log(f"Selected {Path(path).name}; analyzing headers", "info")

        def analyze():
            try:
                info, _ = analyze_target(Path(path))
                self._events.put(("analysis", generation, info))
            except Exception as exc:
                self._events.put(("analysis", generation, {"error": str(exc)}))

        threading.Thread(target=analyze, daemon=True).start()

    def start_dump(self):
        if self.running or not self.exe:
            return
        try:
            mode = (
                "static"
                if self.mode.get().startswith("Static")
                else "auto"
                if self.mode.get().startswith("Auto")
                else "memory"
            )
            config = ExtractionConfig(
                Path(self.exe),
                Path(self.output_path.get()),
                mode=mode,
                allow_execution=mode != "static",
                timeout=float(self.timeout.get()),
                monitor_children=self.monitor_children.get(),
                extract_resources=self.extract_resources.get(),
            )
        except ValueError as exc:
            messagebox.showerror("Invalid configuration", str(exc))
            return
        # Snapshot every Tk variable before launching the worker.
        self._auto_open = self.auto_open.get()
        self._generation += 1
        generation = self._generation
        self._cancel = threading.Event()
        self._result = None
        self._processes.clear()
        self.process_widget.clear()
        self.log_widget.clear()
        self.progress_widget.reset()
        self.run_button.config(state="disabled")
        self.browse_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.open_folder_button.config(state="disabled")

        def work():
            try:
                result = ExtractionEngine().run(
                    config, self._cancel, lambda event: self._events.put(("event", generation, event))
                )
                self._events.put(("result", generation, result))
            except Exception as exc:
                self._events.put(("failure", generation, str(exc)))

        self._worker = threading.Thread(target=work, daemon=False, name=f"ahk-session-{generation}")
        self._worker.start()

    def stop_extraction(self):
        if self.running and self._cancel:
            self._cancel.set()
            self.stop_button.config(state="disabled")
            self.progress_widget.set_phase("Cancelling", "Waiting for workers and process cleanup...")

    def _drain(self):
        for _ in range(200):
            try:
                kind, generation, payload = self._events.get_nowait()
            except queue.Empty:
                break
            if kind == "analysis":
                if generation == self._analysis_generation:
                    self.pe_analysis_widget.show_analysis(payload)
                continue
            if generation != self._generation:
                continue
            if kind == "event":
                self._show_event(payload)
            elif kind == "result":
                self._result = payload
                self._show_result(payload)
            elif kind == "failure":
                self.log_widget.log(payload, "error")
                self.progress_widget.set_phase("Error", payload)
        if self._worker is not None and not self._worker.is_alive():
            self._worker.join()
            self._worker = None
            self.run_button.config(state="normal" if self.exe else "disabled")
            self.browse_button.config(state="normal")
            self.stop_button.config(state="disabled")
        if self._closing and not self.running:
            self.root.destroy()
            return
        self.root.after(50, self._drain)

    def _show_event(self, event):
        kind = event["kind"]
        if kind == "phase":
            self.progress_widget.set_phase(event["message"])
            self.progress_widget.set_progress(event.get("progress", 0))
            if event.get("indeterminate"):
                self.progress_widget.set_indeterminate()
        elif kind == "process":
            pid = event["pid"]
            self._processes[pid] = (event.get("name", ""), event["status"])
            self.process_widget.show_snapshots(self._processes)
        if kind != "finished":
            self.log_widget.log(event["message"], "info")

    def _show_result(self, result):
        success = result.status == Status.SUCCESS
        label = str(result.status).replace("_", " ").title()
        self.progress_widget.set_phase(
            label, f"{len(result.artifacts)} script(s); {len(result.processes)} process(es) analyzed"
        )
        self.progress_widget.set_progress(100 if success else 0)
        self.log_widget.log(
            f"{label}: {len(result.artifacts)} artifact(s)", "success" if success else "warning"
        )
        for diagnostic in result.diagnostics:
            self.log_widget.log(
                diagnostic["message"], "error" if result.status == Status.ERROR else "warning"
            )
        for process in result.processes:
            for diagnostic in process["diagnostics"]:
                self.log_widget.log(f"PID {process['pid']}: {diagnostic['message']}", "warning")
        if result.output_dir:
            self.open_folder_button.config(state="normal")
            self.log_widget.log(f"Diagnostics and source: {result.output_dir}", "info")
            if self._auto_open and result.artifacts:
                self.open_output()

    def open_output(self):
        if self._result and self._result.output_dir:
            open_file_in_default_app(self._result.output_dir)

    def export_diagnostics(self):
        if self.running:
            return
        if not self._result:
            messagebox.showinfo("Diagnostic export", "Complete an extraction first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            try:
                manifest = Path(self._result.output_dir) / "manifest.json"
                content = (
                    manifest.read_bytes()
                    if manifest.is_file()
                    else json.dumps(self._result.as_dict(), indent=2).encode()
                )
                Path(path).write_bytes(content)
            except OSError as exc:
                messagebox.showerror("Export failed", str(exc))

    def clear_log(self):
        self.log_widget.clear()

    def close(self):
        self._closing = True
        self.stop_extraction()
        if not self.running:
            self.root.destroy()
