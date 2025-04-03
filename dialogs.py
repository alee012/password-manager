# dialogs.py
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

# --- Clipboard Helpers (Moved from gui.py) ---

_clipboard_clear_id = None # Variable to store the .after id for clipboard clearing

def copy_to_clipboard(parent, text_to_copy):
    """Copies text to the clipboard and shows confirmation relative to the parent. Clears after delay."""
    global _clipboard_clear_id
    try:
        # Cancel any previously scheduled clear
        if _clipboard_clear_id:
            parent.after_cancel(_clipboard_clear_id)
            _clipboard_clear_id = None

        parent.clipboard_clear()
        parent.clipboard_append(text_to_copy)
        parent.update() # Required on some systems
        print("Password copied to clipboard.")
        # Show message relative to the window where copy was clicked
        messagebox.showinfo("Copied", "Password copied to clipboard.\nIt will be cleared automatically after 30 seconds.", parent=parent)
        # Schedule clearing using the main app window's Tcl interpreter (usually via parent.after)
        _clipboard_clear_id = parent.after(30000, lambda p=parent: clear_clipboard(p)) # 30000 ms = 30 s
    except tk.TclError:
        messagebox.showerror("Clipboard Error", "Could not access clipboard.", parent=parent)
        print("Clipboard access error.")
    except Exception as e:
         messagebox.showerror("Error", f"An unexpected clipboard error occurred: {e}", parent=parent)
         print(f"Unexpected clipboard error: {e}")

def clear_clipboard(parent):
    """Clears the system clipboard if the parent window still exists."""
    global _clipboard_clear_id
    try:
        # Check if parent window still exists before accessing clipboard
        if parent.winfo_exists():
            parent.clipboard_clear()
            print("Clipboard cleared automatically after delay.")
        else:
             print("Parent window destroyed, skipping clipboard clear.")
    except tk.TclError:
        # Ignore error if clipboard couldn't be accessed (e.g., during shutdown)
        print("Clipboard could not be cleared (TclError, possibly during shutdown).")
    except Exception as e:
        # Log unexpected errors if needed
        print(f"Unexpected error clearing clipboard: {e}")
    finally:
         _clipboard_clear_id = None # Reset id after execution or error


# --- Dialog Functions (Moved from gui.py) ---

def prompt_master_password(parent):
    """Prompts the user for the master password using a secure dialog."""
    dialog = tk.Toplevel(parent) # Use parent argument
    dialog.title("Enter Master Password")
    dialog.transient(parent) # Use parent argument
    dialog.grab_set()
    dialog.geometry("300x100")

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

    # Center dialog relative to parent
    # Center dialog directly on the screen
    dialog.update_idletasks() # Ensure dimensions are calculated

    # Get screen size
    ws = dialog.winfo_screenwidth()
    hs = dialog.winfo_screenheight()

    # Get window size
    dialog_w = dialog.winfo_width()
    dialog_h = dialog.winfo_height()

    # Calculate position x, y
    x = (ws/2) - (dialog_w/2)
    y = (hs/2) - (dialog_h/2)

    # Apply the geometry for size (optional, already set) and position
    # Using f-string for clarity, ensuring integers for position
    dialog.geometry(f'{dialog_w}x{dialog_h}+{int(x)}+{int(y)}')
    print(f"DEBUG: Centering dialog {dialog.title()} to screen at +{int(x)}+{int(y)}") # Optional debug

    dialog.wait_window()
    return result["password"]

def prompt_initial_master_password(parent):
    """Prompts the user to set and confirm the initial master password."""
    dialog = tk.Toplevel(parent) # Use parent argument
    dialog.title("Set Initial Master Password")
    dialog.transient(parent) # Use parent argument
    dialog.grab_set()
    dialog.geometry("350x180")

    password_var = tk.StringVar()
    confirm_var = tk.StringVar()

    ttk.Label(dialog, text="Create a strong Master Password:").pack(pady=(10, 0))
    ttk.Label(dialog, text="This password unlocks all your data.").pack(pady=(0, 5), anchor=tk.W, padx=10)

    f1 = ttk.Frame(dialog)
    f1.pack(fill=tk.X, padx=10)
    ttk.Label(f1, text="New Password:", width=15, anchor=tk.W).pack(side=tk.LEFT, pady=2)
    pwd_entry = ttk.Entry(f1, show="*", textvariable=password_var, width=25)
    pwd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=2)
    pwd_entry.focus_set()

    f2 = ttk.Frame(dialog)
    f2.pack(fill=tk.X, padx=10)
    ttk.Label(f2, text="Confirm Password:", width=15, anchor=tk.W).pack(side=tk.LEFT, pady=2)
    confirm_entry = ttk.Entry(f2, show="*", textvariable=confirm_var, width=25)
    confirm_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=2)

    result = {"password": None}

    def on_ok():
        password = password_var.get()
        confirm = confirm_var.get()
        if not password or not confirm:
             messagebox.showwarning("Input Error", "Password fields cannot be empty.", parent=dialog)
             return
        if password != confirm:
             messagebox.showwarning("Input Error", "Passwords do not match.", parent=dialog)
             return
        result["password"] = password
        dialog.destroy()

    def on_cancel():
        dialog.destroy()

    button_frame = ttk.Frame(dialog)
    button_frame.pack(pady=15)
    ok_button = ttk.Button(button_frame, text="Set Password", command=on_ok)
    ok_button.pack(side=tk.LEFT, padx=5)
    cancel_button = ttk.Button(button_frame, text="Cancel Setup", command=on_cancel)
    cancel_button.pack(side=tk.LEFT, padx=5)

    confirm_entry.bind('<Return>', lambda event=None: ok_button.invoke())
    dialog.bind('<Escape>', lambda event=None: cancel_button.invoke())

    
    # Center dialog directly on the screen
    dialog.update_idletasks() # Ensure dimensions are calculated

    # Get screen size
    ws = dialog.winfo_screenwidth()
    hs = dialog.winfo_screenheight()

    # Get window size
    dialog_w = dialog.winfo_width()
    dialog_h = dialog.winfo_height()

    # Calculate position x, y
    x = (ws/2) - (dialog_w/2)
    y = (hs/2) - (dialog_h/2)

    # Apply the geometry for size (optional, already set) and position
    # Using f-string for clarity, ensuring integers for position
    dialog.geometry(f'{dialog_w}x{dialog_h}+{int(x)}+{int(y)}')
    print(f"DEBUG: Centering dialog {dialog.title()} to screen at +{int(x)}+{int(y)}") # Optional debug

    dialog.wait_window()
    return result["password"]

def show_password_dialog(parent, website, username, password):
    """Shows the decrypted password in a simple temporary modal dialog."""
    dialog = tk.Toplevel(parent) # Use parent argument
    dialog.title("Decrypted Password")
    dialog.geometry("400x180")
    dialog.transient(parent) # Use parent argument
    dialog.grab_set()

    ttk.Label(dialog, text=f"Website: {website}", font=('TkDefaultFont', 10, 'bold')).pack(pady=5)
    ttk.Label(dialog, text=f"Username: {username}").pack(pady=5)

    pwd_frame = ttk.Frame(dialog)
    pwd_frame.pack(pady=10)
    ttk.Label(pwd_frame, text="Password:").pack(side=tk.LEFT, padx=5)
    pwd_entry = ttk.Entry(pwd_frame, width=35)
    pwd_entry.insert(0, password)
    pwd_entry.config(state="readonly")
    pwd_entry.pack(side=tk.LEFT)

    # Call the standalone copy_to_clipboard function
    copy_btn = ttk.Button(dialog, text="Copy to Clipboard", command=lambda p=password: copy_to_clipboard(dialog, p))
    copy_btn.pack(pady=5)

    ok_btn = ttk.Button(dialog, text="Close", command=dialog.destroy)
    ok_btn.pack(pady=10)
    ok_btn.focus_set()

    dialog.bind('<Escape>', lambda event=None: dialog.destroy())

    # Center dialog relative to parent
    
    # Center dialog directly on the screen
    dialog.update_idletasks() # Ensure dimensions are calculated

    # Get screen size
    ws = dialog.winfo_screenwidth()
    hs = dialog.winfo_screenheight()

    # Get window size
    dialog_w = dialog.winfo_width()
    dialog_h = dialog.winfo_height()

    # Calculate position x, y
    x = (ws/2) - (dialog_w/2)
    y = (hs/2) - (dialog_h/2)

    # Apply the geometry for size (optional, already set) and position
    # Using f-string for clarity, ensuring integers for position
    dialog.geometry(f'{dialog_w}x{dialog_h}+{int(x)}+{int(y)}')
    print(f"DEBUG: Centering dialog {dialog.title()} to screen at +{int(x)}+{int(y)}") # Optional debug

    dialog.wait_window()