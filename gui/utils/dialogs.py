"""
Dialog and message utilities for the AHK Decompiler GUI.
"""

from tkinter import messagebox, simpledialog
import tkinter as tk


def show_completion_message(total_scripts):
    """Show appropriate completion message based on results."""
    if total_scripts > 0:
        messagebox.showinfo(
            "Extraction Complete", 
            f"Successfully extracted {total_scripts} script(s)!\n\n"
            f"Scripts saved to output folder."
        )
    else:
        messagebox.showwarning(
            "No Scripts Found",
            "No AHK scripts were found in the target executable.\n\n"
            "Try:\n"
            "• Running as administrator\n"
            "• Verifying the file contains AHK scripts\n"
            "• Checking the log for details"
        )


def show_error_dialog(title, message, details=None):
    """Show error dialog with optional details."""
    if details:
        full_message = f"{message}\n\nDetails:\n{details}"
    else:
        full_message = message
    
    messagebox.showerror(title, full_message)


def show_warning_dialog(title, message):
    """Show warning dialog."""
    messagebox.showwarning(title, message)


def show_info_dialog(title, message):
    """Show information dialog."""
    messagebox.showinfo(title, message)


def show_question_dialog(title, message):
    """Show yes/no question dialog."""
    return messagebox.askyesno(title, message)


def show_confirmation_dialog(title, message):
    """Show OK/Cancel confirmation dialog."""
    return messagebox.askokcancel(title, message)


def show_retry_dialog(title, message):
    """Show retry/cancel dialog."""
    return messagebox.askretrycancel(title, message)


def show_input_dialog(title, prompt, initial_value=""):
    """Show input dialog and return entered text."""
    return simpledialog.askstring(title, prompt, initialvalue=initial_value)


def show_password_dialog(title, prompt):
    """Show password input dialog."""
    return simpledialog.askstring(title, prompt, show='*')


def show_integer_dialog(title, prompt, initial_value=0, min_value=None, max_value=None):
    """Show integer input dialog."""
    return simpledialog.askinteger(
        title, prompt, 
        initialvalue=initial_value,
        minvalue=min_value,
        maxvalue=max_value
    )


def show_float_dialog(title, prompt, initial_value=0.0, min_value=None, max_value=None):
    """Show float input dialog."""
    return simpledialog.askfloat(
        title, prompt,
        initialvalue=initial_value,
        minvalue=min_value,
        maxvalue=max_value
    )


def show_about_dialog(parent, app_name, version, description, author=None):
    """Show about dialog with application information."""
    about_text = f"{app_name}\nVersion {version}\n\n{description}"
    
    if author:
        about_text += f"\n\nDeveloped by: {author}"
    
    messagebox.showinfo("About", about_text, parent=parent)


def show_progress_dialog(parent, title, message, progress_callback=None):
    """Show a simple progress dialog (basic implementation)."""
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.geometry("300x100")
    dialog.resizable(False, False)
    
    # Center on parent
    dialog.transient(parent)
    dialog.grab_set()
    
    # Message label
    label = tk.Label(dialog, text=message, wraplength=280)
    label.pack(pady=20)
    
    # Progress bar (if tkinter.ttk is available)
    try:
        from tkinter import ttk
        progress = ttk.Progressbar(dialog, mode='indeterminate')
        progress.pack(pady=10, padx=20, fill='x')
        progress.start()
    except ImportError:
        progress = None
    
    dialog.update()
    
    return dialog, progress


def close_progress_dialog(dialog, progress=None):
    """Close progress dialog."""
    if progress:
        progress.stop()
    dialog.destroy()


def show_custom_dialog(parent, title, content_callback):
    """Show custom dialog with user-defined content."""
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.transient(parent)
    dialog.grab_set()
    
    # Let the callback populate the dialog
    result = content_callback(dialog)
    
    return result


def show_multiline_message(title, message, width=80, height=20):
    """Show message in a scrollable text widget."""
    root = tk.Tk()
    root.withdraw()  # Hide main window
    
    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.geometry(f"{width*8}x{height*20}")
    
    # Text widget with scrollbar
    frame = tk.Frame(dialog)
    frame.pack(fill='both', expand=True, padx=10, pady=10)
    
    text_widget = tk.Text(frame, wrap='word', width=width, height=height)
    scrollbar = tk.Scrollbar(frame, orient='vertical', command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar.set)
    
    text_widget.pack(side='left', fill='both', expand=True)
    scrollbar.pack(side='right', fill='y')
    
    text_widget.insert('1.0', message)
    text_widget.config(state='disabled')
    
    # OK button
    ok_button = tk.Button(dialog, text="OK", command=dialog.destroy)
    ok_button.pack(pady=10)
    
    dialog.focus_set()
    dialog.wait_window()
    root.destroy()


def show_choice_dialog(title, message, choices):
    """Show dialog with multiple choice buttons."""
    root = tk.Tk()
    root.withdraw()
    
    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.resizable(False, False)
    
    result = [None]  # Use list to allow modification in nested function
    
    # Message
    label = tk.Label(dialog, text=message, wraplength=300, justify='left')
    label.pack(pady=20, padx=20)
    
    # Buttons frame
    button_frame = tk.Frame(dialog)
    button_frame.pack(pady=10)
    
    def on_choice(choice):
        result[0] = choice
        dialog.destroy()
    
    # Create buttons for each choice
    for i, choice in enumerate(choices):
        btn = tk.Button(
            button_frame, 
            text=choice, 
            command=lambda c=choice: on_choice(c),
            width=15
        )
        btn.pack(side='left', padx=5)
    
    # Center dialog
    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
    y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
    dialog.geometry(f"+{x}+{y}")
    
    dialog.focus_set()
    dialog.wait_window()
    root.destroy()
    
    return result[0] 