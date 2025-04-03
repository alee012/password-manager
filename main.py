# main.py
import tkinter as tk
from tkinter import messagebox # Import directly for setup phase message boxes
import gui
import database
import encryption
import sys
import time # For potential brief pauses
import dialogs

def main():
    # --- Root window creation moved earlier for dialog parenting ---
    # I need the root window to exist so dialogs have a parent,
    # but I still want to hide it until login/setup is successful.
    print("DEBUG: Creating tk.Tk() root window...")
    try:
        root = tk.Tk()
        print("DEBUG: tk.Tk() root window created.")
        root.update_idletasks()
        w = 650 # Desired width
        h = 450 # Desired height
        ws = root.winfo_screenwidth()
        hs = root.winfo_screenheight()
        x = (ws/2) - (w/2)
        y = (hs/2) - (h/2)
        root.geometry('%dx%d+%d+%d' % (w, h, x, y))

        # Keep root hidden for now using withdraw()
        # I will use root as parent for prompts, then deiconify later if successful.
        #root.withdraw() <-- This is commented out. For some reason this breaks the program
        print("DEBUG: Root window hidden (will be used as parent).")
    except Exception as e:
        print(f"FATAL: Error during Tkinter root window creation/hiding: {e}")
        messagebox.showerror("Startup Error", f"Failed to initialize GUI:\n{e}") # Show error even without full app
        sys.exit(1)


    # --- Initialize Database (can happen before or after Tk root) ---
    try:
        print("DEBUG: Initializing database...")
        database.initialize_database()
        print("DEBUG: Database initialization complete.")
    except SystemExit as e:
        print(f"Failed to initialize database: {e}. Exiting.")
        messagebox.showerror("Startup Error", f"Failed to initialize database:\n{e}", parent=root)
        root.destroy()
        sys.exit(1)
    except Exception as e:
         print(f"An unexpected error occurred during DB initialization: {e}. Exiting.")
         messagebox.showerror("Startup Error", f"Unexpected database error:\n{e}", parent=root)
         root.destroy()
         sys.exit(1)

    # --- Create App instance (needed for prompts) ---
    # I need the app instance to call the prompt methods
    print("DEBUG: Creating PasswordManagerApp instance...")
    try:
        app = gui.PasswordManagerApp(root) # Create the app instance
        print("DEBUG: PasswordManagerApp instance created.")
    except Exception as e:
        print(f"FATAL: Error creating PasswordManagerApp instance: {e}")
        messagebox.showerror("Startup Error", f"Failed to create application components:\n{e}", parent=root)
        root.destroy()
        sys.exit(1)

    # --- Load Salt and Check Verifier ---
    master_key = None
    master_salt = None
    try:
        print("DEBUG: Loading/creating master salt...")
        master_salt = encryption.load_or_create_master_salt()
        print(f"DEBUG: Master salt loaded/created successfully.")
    except SystemExit as e:
        print("Exiting due to master salt error.")
        messagebox.showerror("Startup Error", "Fatal error handling master salt file.", parent=root)
        root.destroy()
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred loading/creating master salt: {e}. Exiting.")
        messagebox.showerror("Startup Error", f"Unexpected error loading master salt:\n{e}", parent=root)
        root.destroy()
        sys.exit(1)

    # Load verifier data (returns None if file doesn't exist)
    verifier_data = encryption.load_verifier_data()

    if verifier_data is None:
        # --- First Run / Setup Phase ---
        print("INFO: Verifier data not found. Starting initial master password setup...")
        messagebox.showinfo("First Time Setup Required", "Set your master password for your vault.", parent=root)
        print("DEBUG: showinfo dialog closed.") 
        
        initial_password = None
        print("DEBUG: About to enter initial password setup loop.") 
        while initial_password is None:
            print("DEBUG: Inside initial password setup loop. Calling prompt...") 
            initial_password = dialogs.prompt_initial_master_password(root) # Pass root
            print(f"DEBUG: prompt_initial_master_password returned: {initial_password}") 

            if initial_password is None:
                # User cancelled the setup prompt
                print("Setup cancelled by user. Exiting.")
                messagebox.showinfo("Setup Cancelled", "Application setup cancelled. Exiting.", parent=root)
                database.close_db_connection()
                root.destroy()
                sys.exit(0)

            # If loop continues, it means passwords didn't match or were empty (handled in prompt)
            # Technically, prompt_initial_master_password now only returns valid password or None

        print("DEBUG: Exited initial password setup loop.") # <-- ADD THIS
       

        
        # I have a confirmed initial password
        print("DEBUG: Initial password confirmed.")
        try:
            # Derive key
            print("DEBUG: Deriving initial master key...")
            master_key = encryption.derive_key(initial_password, master_salt)
            print("DEBUG: Initial master key derived.")

            # Encrypt verifier string
            print("DEBUG: Encrypting verifier string...")
            verify_nonce, verify_ciphertext = encryption.encrypt(encryption.VERIFIER_STRING, master_key)
            print("DEBUG: Verifier string encrypted.")

            # Save verifier data
            encryption.save_verifier_data(verify_nonce, verify_ciphertext)
            print("INFO: Initial setup complete. Verifier data saved.")
            messagebox.showinfo("Setup Complete", "Master password set successfully!", parent=root)

        except Exception as e:
            print(f"FATAL: Error during initial setup encryption/save: {e}")
            messagebox.showerror("Setup Error", f"Failed to complete setup:\n{e}", parent=root)
            # Optionally: Clean up potentially created files? (e.g., delete salt/verifier)
            database.close_db_connection()
            root.destroy()
            sys.exit(1)

    else:
        # --- Normal Login / Verification Phase ---
        print("INFO: Verifier data found. Proceeding with login.")
        verify_nonce, verify_ciphertext = verifier_data

        login_attempts = 0
        max_attempts = 5 # Allow a few attempts

        print("DEBUG: Entering master password prompt loop...")
        while login_attempts < max_attempts:
            # Prompt for password using the standard prompt
            entered_password = dialogs.prompt_master_password(root) # Pass root

            if entered_password is None: # User cancelled login
                print("Login cancelled by user. Exiting.")
                database.close_db_connection()
                root.destroy() # Destroy the hidden root window
                sys.exit(0)

            if not entered_password:
                print("Password cannot be empty.")
                login_attempts += 1
                if login_attempts < max_attempts:
                    messagebox.showwarning("Login Error", f"Password cannot be empty.\n{max_attempts - login_attempts} attempts remaining.", parent=root)
                continue # Prompt again

            # Derive potential key
            print("DEBUG: Deriving potential master key...")
            try:
                potential_master_key = encryption.derive_key(entered_password, master_salt)
                print("DEBUG: Potential master key derived.")
            except Exception as e:
                 print(f"Error deriving key during login: {e}")
                 # Treat derivation error as a failed attempt maybe? Or show specific error?
                 login_attempts += 1
                 if login_attempts < max_attempts:
                      messagebox.showerror("Login Error", f"Failed to process password.\n{max_attempts - login_attempts} attempts remaining.", parent=root)
                 continue # Prompt again


            # --- !!! Verification Step !!! ---
            print("DEBUG: Attempting to decrypt verifier...")
            try:
                decrypted_verifier = encryption.decrypt(verify_nonce, verify_ciphertext, potential_master_key)
                print("DEBUG: Verifier decrypted.")

                # Check if decrypted data matches the known string
                if decrypted_verifier == encryption.VERIFIER_STRING:
                    print("INFO: Master password verification successful!")
                    master_key = potential_master_key # Set the confirmed key
                    break # Exit the while loop - Login successful!
                else:
                    # Decrypted successfully but data doesn't match (shouldn't happen with AES-GCM if tag matches)
                    # This case is unlikely, usually decrypt would fail with InvalidTag
                    print("WARNING: Master password verification failed (decrypted data mismatch).")
                    login_attempts += 1
                    if login_attempts < max_attempts:
                         messagebox.showerror("Login Failed", f"Incorrect Master Password.\n{max_attempts - login_attempts} attempts remaining.", parent=root)

            except ValueError as e: # Catches InvalidTag or other issues from decrypt
                print(f"WARNING: Master password verification failed (decryption error): {e}")
                login_attempts += 1
                if login_attempts < max_attempts:
                     messagebox.showerror("Login Failed", f"Incorrect Master Password.\n{max_attempts - login_attempts} attempts remaining.", parent=root)
            except Exception as e:
                 print(f"Unexpected error during verifier decryption: {e}")
                 login_attempts += 1
                 if login_attempts < max_attempts:
                      messagebox.showerror("Login Error", f"An unexpected error occurred during login.\n{max_attempts - login_attempts} attempts remaining.", parent=root)

            # If loop continues, login attempt failed

        # --- After the loop ---
        if master_key is None:
            # Login failed after max attempts
            print("Maximum login attempts reached. Exiting.")
            messagebox.showerror("Login Failed", "Maximum login attempts reached. Exiting.", parent=root)
            database.close_db_connection()
            root.destroy() # Destroy the hidden root window
            sys.exit(1)

    # --- Login/Setup Successful - Proceed with application ---
    print("DEBUG: Login/Setup successful. Setting master key in app.")
    app.master_key = master_key

    # Now that I have the key and login is verified, show the main window
    print("DEBUG: Showing main application window...")
    # root.deiconify() # Make the main window visible
    # Optional: Center the main window before showing
    
    root.deiconify() # Now show it, centered and sized

    root.title(f"{root.title()} - Logged In") # Update title optionally
    app.refresh_password_list() # Load data now that I have the key

    # Setup cleanup action when window is closed
    def on_closing():
        print("Closing application...")
        database.close_db_connection()
        # app.clear_clipboard() # Ensure clipboard is cleared on exit
        # ^^^ This might fail if called during destroy, maybe clear earlier or ignore errors
        try:
            if root.winfo_exists(): # Check if window exists before clearing clipboard
                app.clear_clipboard()
        except Exception as e:
            print(f"Ignoring error during exit clipboard clear: {e}")
        finally:
            root.destroy() # Destroy the Tkinter window


    root.protocol("WM_DELETE_WINDOW", on_closing)

    # Start the Tkinter event loop
    print("DEBUG: Starting main loop...")
    root.mainloop()

if __name__ == "__main__":
    main()