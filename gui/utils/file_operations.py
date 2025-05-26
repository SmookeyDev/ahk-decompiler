"""
File and folder operations utilities for the AHK Decompiler GUI.
"""

import os
import webbrowser
import subprocess
import platform
from tkinter import messagebox, filedialog

from utils.constants import DEFAULT_OUTPUT_DIR


def open_output_folder():
    """Open the output folder in the default file manager."""
    if os.path.exists(DEFAULT_OUTPUT_DIR):
        try:
            system = platform.system().lower()
            
            if system == 'windows':
                os.startfile(DEFAULT_OUTPUT_DIR)
            elif system == 'darwin':  # macOS
                subprocess.run(['open', DEFAULT_OUTPUT_DIR])
            else:  # Linux and others
                subprocess.run(['xdg-open', DEFAULT_OUTPUT_DIR])
                
        except Exception:
            # Fallback to webbrowser
            webbrowser.open(DEFAULT_OUTPUT_DIR)
    else:
        messagebox.showwarning(
            "Folder Not Found", 
            f"Output folder '{DEFAULT_OUTPUT_DIR}' does not exist yet."
        )


def open_file_in_default_app(filepath):
    """Open a file in the default application."""
    if not os.path.exists(filepath):
        messagebox.showerror("File Not Found", f"File does not exist:\n{filepath}")
        return False
    
    try:
        system = platform.system().lower()
        
        if system == 'windows':
            os.startfile(filepath)
        elif system == 'darwin':  # macOS
            subprocess.run(['open', filepath])
        else:  # Linux and others
            subprocess.run(['xdg-open', filepath])
            
        return True
    except Exception as e:
        messagebox.showerror("Error Opening File", f"Could not open file:\n{str(e)}")
        return False


def browse_for_file(title="Select File", filetypes=None, initial_dir=None):
    """Show file browser dialog and return selected file path."""
    if filetypes is None:
        filetypes = [('All files', '*.*')]
    
    filepath = filedialog.askopenfilename(
        title=title,
        filetypes=filetypes,
        initialdir=initial_dir
    )
    
    return filepath if filepath else None


def browse_for_folder(title="Select Folder", initial_dir=None):
    """Show folder browser dialog and return selected folder path."""
    folderpath = filedialog.askdirectory(
        title=title,
        initialdir=initial_dir
    )
    
    return folderpath if folderpath else None


def browse_for_save_file(title="Save File", filetypes=None, default_extension=None, initial_dir=None):
    """Show save file dialog and return selected file path."""
    if filetypes is None:
        filetypes = [('All files', '*.*')]
    
    filepath = filedialog.asksaveasfilename(
        title=title,
        filetypes=filetypes,
        defaultextension=default_extension,
        initialdir=initial_dir
    )
    
    return filepath if filepath else None


def get_file_size_formatted(filepath):
    """Get file size in human-readable format."""
    if not os.path.exists(filepath):
        return "File not found"
    
    try:
        size = os.path.getsize(filepath)
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        
        return f"{size:.1f} PB"
    except Exception:
        return "Unknown size"


def create_directory_if_not_exists(directory):
    """Create directory if it doesn't exist."""
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception:
        return False


def get_file_extension(filepath):
    """Get file extension from filepath."""
    return os.path.splitext(filepath)[1].lower()


def get_filename_without_extension(filepath):
    """Get filename without extension."""
    return os.path.splitext(os.path.basename(filepath))[0]


def is_valid_file_path(filepath):
    """Check if filepath is valid and file exists."""
    return filepath and os.path.isfile(filepath)


def is_valid_directory_path(dirpath):
    """Check if directory path is valid and exists."""
    return dirpath and os.path.isdir(dirpath)


def get_recent_files(max_files=10):
    """Get list of recently accessed files (placeholder implementation)."""
    # This would typically read from a config file or registry
    # For now, return empty list
    return []


def add_to_recent_files(filepath):
    """Add file to recent files list (placeholder implementation)."""
    # This would typically save to a config file or registry
    pass


def get_file_info(filepath):
    """Get comprehensive file information."""
    if not os.path.exists(filepath):
        return None
    
    try:
        stat = os.stat(filepath)
        return {
            'path': filepath,
            'name': os.path.basename(filepath),
            'size': stat.st_size,
            'size_formatted': get_file_size_formatted(filepath),
            'modified': stat.st_mtime,
            'created': stat.st_ctime,
            'extension': get_file_extension(filepath),
            'is_file': os.path.isfile(filepath),
            'is_directory': os.path.isdir(filepath)
        }
    except Exception:
        return None 