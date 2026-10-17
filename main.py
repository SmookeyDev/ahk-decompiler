"""
AHK Decompiler - Multi-Process
Main entry point for the AutoHotkey decompiler application.

This tool extracts AutoHotkey scripts from compiled executables by analyzing
process memory and identifying script patterns.
"""

import sys


def main():
    """Main entry point for the application."""
    smoke = sys.argv[1:] == ["--gui-smoke"]
    if len(sys.argv) > 1 and not smoke:
        from cli import main as cli_main

        return cli_main()
    import tkinter as tk
    from gui.main_window import DumpGUI

    try:
        root = tk.Tk()
        if smoke:
            root.withdraw()
        DumpGUI(root)
        if smoke:
            root.after(150, root.destroy)
        root.mainloop()
    except Exception as e:
        print(f"Failed to start application: {e}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
