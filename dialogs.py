# dialogs.py
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import atexit
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Clipboard Helpers ---

# Dictionary to track clipboard operations, allows multiple independent operations
_clipboard_operations = {}

def center_dialog(dialog, parent=None):
    """Centers a dialog window on screen or relative to parent."""
    dialog.update_idletasks()  # Ensure dimensions are calculated
    
    # Get dialog dimensions
    dialog_w = dialog.winfo_width()
    dialog_h = dialog.winfo_height()
    
    # Calculate position
    if parent and parent.winfo_exists():
        # Center relative to parent
        x = parent.winfo_rootx() + (parent.winfo_width() - dialog_w) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - dialog_h) // 2
    else:
        # Center on screen
        ws = dialog.winfo_screenwidth()
        hs = dialog.winfo_screenheight()
        x = (ws - dialog_w) // 2
        y = (hs - dialog_h) // 2
    
    # Apply the geometry
    dialog.geometry(f'{dialog_w}x{dialog_h}+{max(0, x)}+{max(0, y)}')
    logger.debug(f"Centered dialog '{dialog.title()}' at +{x}+{y}")

def copy_to_clipboard(parent, text_to_copy, timeout_seconds=30):
    """
    Copies text to the clipboard and clears it after timeout.
    Uses a unique identifier for each clipboard operation.
    """
    if not parent or not parent.winfo_exists():
        logger.error("Invalid parent widget for clipboard operation")
        return False
        
    try:
        # Generate a unique ID for this operation
        import uuid
        operation_id = str(uuid.uuid4())
        
        # Cancel any previously scheduled clear for this parent
        for old_id in list(_clipboard_operations.keys()):
            if _clipboard_operations[old_id]['parent'] == parent:
                parent.after_cancel(_clipboard_operations[old_id]['after_id'])
                del _clipboard_operations[old_id]
                logger.debug("Cancelled previous clipboard clear")
        
        # Copy to clipboard
        parent.clipboard_clear()
        parent.clipboard_append(text_to_copy)
        parent.update()  # Required on some systems
        
        # Show notification
        messagebox.showinfo(
            "Copied", 
            f"Password copied to clipboard.\nIt will be cleared automatically after {timeout_seconds} seconds.", 
            parent=parent
        )
        
        # Schedule clearing
        after_id = parent.after(
            timeout_seconds * 1000,  # Convert to milliseconds
            lambda p=parent, op_id=operation_id: _clear_clipboard_callback(p, op_id)
        )
        
        # Store operation data
        _clipboard_operations[operation_id] = {
            'parent': parent,
            'after_id': after_id,
            'text': text_to_copy  # Store for verification when clearing
        }
        
        logger.info("Password copied to clipboard with auto-clear timer set")
        return True
        
    except tk.TclError as e:
        messagebox.showerror("Clipboard Error", f"Could not access clipboard: {e}", parent=parent)
        logger.error(f"Clipboard access error: {e}")
        return False
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected clipboard error occurred: {e}", parent=parent)
        logger.error(f"Unexpected clipboard error: {e}")
        return False

def _clear_clipboard_callback(parent, operation_id):
    """Callback to clear clipboard after timeout."""
    try:
        if operation_id not in _clipboard_operations:
            logger.warning(f"Clipboard operation {operation_id} not found")
            return
            
        if not parent or not parent.winfo_exists():
            logger.info("Parent widget no longer exists, skipping clipboard clear")
            return
        
        # Verify clipboard still contains our password before clearing
        try:
            current_clipboard = parent.clipboard_get()
            if current_clipboard == _clipboard_operations[operation_id]['text']:
                parent.clipboard_clear()
                logger.info("Clipboard cleared automatically after timeout")
            else:
                logger.info("Clipboard content changed, not clearing")
        except tk.TclError:
            logger.warning("Could not verify clipboard content")
            
    except Exception as e:
        logger.error(f"Error in clipboard clear callback: {e}")
    finally:
        # Remove the operation from tracking
        if operation_id in _clipboard_operations:
            del _clipboard_operations[operation_id]

def clear_all_clipboards():
    """Clear all pending clipboard operations, called on application exit."""
    for operation_id in list(_clipboard_operations.keys()):
        try:
            parent = _clipboard_operations[operation_id]['parent']
            if parent and parent.winfo_exists():
                parent.clipboard_clear()
        except Exception as e:
            logger.error(f"Error clearing clipboard on exit: {e}")
        finally:
            if operation_id in _clipboard_operations:
                del _clipboard_operations[operation_id]
    logger.info("All clipboard operations cleared on exit")

# Register clear_all_clipboards to run at program exit
atexit.register(clear_all_clipboards)

# --- Dialog Functions ---

def prompt_master_password(parent):
    """Prompts the user for the master password using a secure dialog."""
    dialog = tk.Toplevel(parent)
    dialog.title("Enter Master Password")
    dialog.transient(parent)
    dialog.grab_set()
    dialog.geometry("300x100")
    dialog.resizable(False, False)
    
    # Set dialog icon and properties
    try:
        dialog.iconbitmap(parent.iconbitmap())  # Copy parent icon if available
    except:
        pass  # Ignore if no icon available
    
    # Ensure dialog appears on top
    dialog.attributes('-topmost', True)
    dialog.update()
    dialog.attributes('-topmost', False)

    password_var = tk.StringVar()

    ttk.Label(dialog, text="Master Password:").pack(pady=(10, 0))
    pwd_entry = ttk.Entry(dialog, show="*", textvariable=password_var, width=30)
    pwd_entry.pack(pady=5)
    pwd_entry.focus_set()

    result = {"password": None}

    def on_ok():
        result["password"] = password_var.get()
        dialog.destroy()

    def on_cancel():
        dialog.destroy()

    button_frame = ttk.Frame(dialog)
    button_frame.pack(pady=10)
    ok_button = ttk.Button(button_frame, text="OK", command=on_ok)
    ok_button.pack(side=tk.LEFT, padx=5)
    cancel_button = ttk.Button(button_frame, text="Cancel", command=on_cancel)
    cancel_button.pack(side=tk.LEFT, padx=5)

    dialog.bind('<Return>', lambda event=None: ok_button.invoke())
    dialog.bind('<Escape>', lambda event=None: cancel_button.invoke())

    # Center dialog on screen
    center_dialog(dialog, parent)
    
    # Make sure dialog captures focus
    dialog.wait_visibility()
    dialog.focus_force()
    pwd_entry.focus_set()
    
    dialog.wait_window()
    return result["password"]

def prompt_initial_master_password(parent):
    """Prompts the user to set and confirm the initial master password."""
    dialog = tk.Toplevel(parent)
    dialog.title("Set Initial Master Password")
    dialog.transient(parent)
    dialog.grab_set()
    dialog.geometry("350x200")
    dialog.resizable(False, False)
    
    # Ensure dialog appears on top
    dialog.attributes('-topmost', True)
    dialog.update()
    dialog.attributes('-topmost', False)

    password_var = tk.StringVar()
    confirm_var = tk.StringVar()
    
    # Main frame with padding
    main_frame = ttk.Frame(dialog, padding=10)
    main_frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(main_frame, text="Create a strong Master Password:", 
              font=('TkDefaultFont', 10, 'bold')).pack(anchor=tk.W)
    ttk.Label(main_frame, text="This password unlocks all your data and cannot be recovered if lost.",
              wraplength=330).pack(pady=(0, 10), anchor=tk.W)

    f1 = ttk.Frame(main_frame)
    f1.pack(fill=tk.X)
    ttk.Label(f1, text="New Password:", width=15, anchor=tk.W).pack(side=tk.LEFT, pady=2)
    pwd_entry = ttk.Entry(f1, show="*", textvariable=password_var, width=25)
    pwd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=2)
    pwd_entry.focus_set()

    f2 = ttk.Frame(main_frame)
    f2.pack(fill=tk.X)
    ttk.Label(f2, text="Confirm Password:", width=15, anchor=tk.W).pack(side=tk.LEFT, pady=2)
    confirm_entry = ttk.Entry(f2, show="*", textvariable=confirm_var, width=25)
    confirm_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=2)

    result = {"password": None}

    def on_ok():
        password = password_var.get()
        confirm = confirm_var.get()
        if not password:
            messagebox.showwarning("Input Error", "Password cannot be empty.", parent=dialog)
            pwd_entry.focus_set()
            return
        if len(password) < 8:
            messagebox.showwarning("Security Warning", 
                                  "Please use a stronger password (at least 8 characters).", 
                                  parent=dialog)
            pwd_entry.focus_set()
            return
        if password != confirm:
            messagebox.showwarning("Input Error", "Passwords do not match.", parent=dialog)
            confirm_entry.focus_set()
            return
            
        result["password"] = password
        dialog.destroy()

    def on_cancel():
        if messagebox.askyesno("Cancel Setup", 
                              "Are you sure you want to cancel password manager setup?", 
                              parent=dialog):
            dialog.destroy()

    button_frame = ttk.Frame(main_frame)
    button_frame.pack(pady=(15, 0), anchor=tk.CENTER)
    ok_button = ttk.Button(button_frame, text="Set Password", command=on_ok, width=15)
    ok_button.pack(side=tk.LEFT, padx=5)
    cancel_button = ttk.Button(button_frame, text="Cancel Setup", command=on_cancel, width=15)
    cancel_button.pack(side=tk.LEFT, padx=5)

    # Keyboard shortcuts
    pwd_entry.bind('<Return>', lambda event=None: confirm_entry.focus_set())
    confirm_entry.bind('<Return>', lambda event=None: ok_button.invoke())
    dialog.bind('<Escape>', lambda event=None: cancel_button.invoke())
    
    # Center dialog on screen
    center_dialog(dialog, parent)
    
    # Make sure dialog captures focus
    dialog.wait_visibility()
    dialog.focus_force()
    pwd_entry.focus_set()
    
    dialog.wait_window()
    return result["password"]

def show_password_dialog(parent, website, username, password):
    """
    Shows the decrypted password in a secure dialog with improved security features
    and masked password display with toggle option.
    """
    dialog = tk.Toplevel(parent)
    dialog.title("Decrypted Password")
    dialog.geometry("400x210")
    dialog.transient(parent)
    dialog.grab_set()
    dialog.resizable(False, False)
    
    # Ensure dialog appears on top
    dialog.attributes('-topmost', True)
    dialog.update()
    dialog.attributes('-topmost', False)
    
    # Main frame with padding
    main_frame = ttk.Frame(dialog, padding=10)
    main_frame.pack(fill=tk.BOTH, expand=True)

    # Information area
    ttk.Label(main_frame, text=f"Website:", anchor=tk.W).grid(row=0, column=0, sticky=tk.W, pady=5)
    ttk.Label(main_frame, text=website, font=('TkDefaultFont', 10, 'bold')).grid(row=0, column=1, sticky=tk.W, pady=5)
    
    ttk.Label(main_frame, text=f"Username:", anchor=tk.W).grid(row=1, column=0, sticky=tk.W, pady=5)
    ttk.Label(main_frame, text=username).grid(row=1, column=1, sticky=tk.W, pady=5)

    # Password display with toggle option
    ttk.Label(main_frame, text="Password:", anchor=tk.W).grid(row=2, column=0, sticky=tk.W, pady=5)
    
    pwd_frame = ttk.Frame(main_frame)
    pwd_frame.grid(row=2, column=1, sticky=tk.W, pady=5)
    
    pwd_var = tk.StringVar(value=password)
    show_password = tk.BooleanVar(value=False)
    
    pwd_entry = ttk.Entry(pwd_frame, textvariable=pwd_var, show="•", width=25, state="readonly")
    pwd_entry.pack(side=tk.LEFT)
    
    def toggle_password_visibility():
        current = show_password.get()
        if current:
            pwd_entry.config(show="")
        else:
            pwd_entry.config(show="•")
    
    show_pwd_check = ttk.Checkbutton(pwd_frame, text="Show", 
                                     variable=show_password, 
                                     command=toggle_password_visibility)
    show_pwd_check.pack(side=tk.LEFT, padx=5)

    # Buttons frame
    button_frame = ttk.Frame(main_frame)
    button_frame.grid(row=3, column=0, columnspan=2, pady=15)
    
    copy_btn = ttk.Button(
        button_frame, 
        text="Copy to Clipboard", 
        command=lambda: copy_to_clipboard(dialog, password),
        width=20
    )
    copy_btn.pack(side=tk.LEFT, padx=5)
    
    ok_btn = ttk.Button(button_frame, text="Close", command=dialog.destroy, width=10)
    ok_btn.pack(side=tk.LEFT, padx=5)

    # Auto-focus on close button to prevent accidental selection of password
    ok_btn.focus_set()

    # Keyboard shortcuts
    dialog.bind('<Return>', lambda event=None: ok_btn.invoke())
    dialog.bind('<Escape>', lambda event=None: dialog.destroy())
    
    # Center dialog on screen
    center_dialog(dialog, parent)
    
    dialog.wait_window()
