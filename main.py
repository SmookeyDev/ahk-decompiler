"""
AHK Decompiler - Multi-Process
Main entry point for the AutoHotkey decompiler application.

This tool extracts AutoHotkey scripts from compiled executables by analyzing
process memory and identifying script patterns.
"""

import tkinter as tk
from gui.main_window import DumpGUI


def main():
    """Main entry point for the application."""
    try:
        root = tk.Tk()
        app = DumpGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"Failed to start application: {e}")
        input("Press Enter to exit...")


if __name__ == '__main__':
    main()