"""
Input validation utilities for the AHK Decompiler GUI.
"""

import os
import re
from tkinter import messagebox


def validate_file_selection(filepath):
    """Validate that a file is selected and exists."""
    if not filepath:
        messagebox.showerror("No File Selected", "Please select an executable file first.")
        return False
    
    if not os.path.exists(filepath):
        messagebox.showerror("File Not Found", f"The selected file does not exist:\n{filepath}")
        return False
    
    return True


def validate_executable_file(filepath):
    """Validate that the selected file is an executable."""
    if not validate_file_selection(filepath):
        return False
    
    if not filepath.lower().endswith('.exe'):
        result = messagebox.askyesno(
            "Non-executable File",
            "The selected file does not have a .exe extension.\n"
            "Do you want to continue anyway?"
        )
        return result
    
    return True


def validate_output_directory(dirpath):
    """Validate output directory path."""
    if not dirpath:
        messagebox.showerror("No Directory Selected", "Please select an output directory.")
        return False
    
    if not os.path.exists(dirpath):
        result = messagebox.askyesno(
            "Directory Not Found",
            f"The directory '{dirpath}' does not exist.\n"
            "Do you want to create it?"
        )
        if result:
            try:
                os.makedirs(dirpath, exist_ok=True)
                return True
            except Exception as e:
                messagebox.showerror("Error Creating Directory", f"Could not create directory:\n{str(e)}")
                return False
        return False
    
    if not os.access(dirpath, os.W_OK):
        messagebox.showerror("Permission Denied", f"No write permission for directory:\n{dirpath}")
        return False
    
    return True


def validate_file_size(filepath, max_size_mb=500):
    """Validate file size is within reasonable limits."""
    if not os.path.exists(filepath):
        return False
    
    try:
        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if size_mb > max_size_mb:
            result = messagebox.askyesno(
                "Large File Warning",
                f"The selected file is {size_mb:.1f} MB, which is quite large.\n"
                f"Processing may take a long time. Continue anyway?"
            )
            return result
        return True
    except Exception:
        return True  # If we can't get size, assume it's OK


def validate_filename(filename):
    """Validate filename for illegal characters."""
    if not filename:
        return False, "Filename cannot be empty"
    
    # Windows illegal characters
    illegal_chars = r'[<>:"/\\|?*]'
    if re.search(illegal_chars, filename):
        return False, "Filename contains illegal characters: < > : \" / \\ | ? *"
    
    # Reserved names on Windows
    reserved_names = [
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    ]
    
    name_without_ext = os.path.splitext(filename)[0].upper()
    if name_without_ext in reserved_names:
        return False, f"'{filename}' is a reserved filename"
    
    # Check length
    if len(filename) > 255:
        return False, "Filename is too long (max 255 characters)"
    
    return True, "Valid filename"


def validate_path_length(filepath):
    """Validate path length is within system limits."""
    if len(filepath) > 260:  # Windows MAX_PATH limitation
        messagebox.showwarning(
            "Path Too Long",
            "The file path is very long and may cause issues on Windows.\n"
            "Consider moving the file to a shorter path."
        )
        return False
    return True


def validate_disk_space(directory, required_mb=100):
    """Validate available disk space."""
    try:
        import shutil
        free_bytes = shutil.disk_usage(directory).free
        free_mb = free_bytes / (1024 * 1024)
        
        if free_mb < required_mb:
            messagebox.showwarning(
                "Low Disk Space",
                f"Only {free_mb:.1f} MB available in output directory.\n"
                f"At least {required_mb} MB recommended."
            )
            return False
        return True
    except Exception:
        return True  # If we can't check, assume it's OK


def validate_permissions(filepath):
    """Validate file permissions."""
    if not os.path.exists(filepath):
        return False, "File does not exist"
    
    if not os.access(filepath, os.R_OK):
        return False, "No read permission for file"
    
    directory = os.path.dirname(filepath)
    if not os.access(directory, os.W_OK):
        return False, "No write permission for directory"
    
    return True, "Permissions OK"


def validate_process_name(process_name):
    """Validate process name format."""
    if not process_name:
        return False, "Process name cannot be empty"
    
    # Basic validation for process name
    if not re.match(r'^[a-zA-Z0-9_.-]+$', process_name):
        return False, "Process name contains invalid characters"
    
    if len(process_name) > 100:
        return False, "Process name is too long"
    
    return True, "Valid process name"


def validate_numeric_input(value, min_val=None, max_val=None):
    """Validate numeric input within optional range."""
    try:
        num_val = float(value)
        
        if min_val is not None and num_val < min_val:
            return False, f"Value must be at least {min_val}"
        
        if max_val is not None and num_val > max_val:
            return False, f"Value must be at most {max_val}"
        
        return True, "Valid number"
    except ValueError:
        return False, "Invalid number format" 