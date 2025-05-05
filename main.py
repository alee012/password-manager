# main.py
import tkinter as tk
from tkinter import messagebox
import gui
import database
import encryption
import sys
import time
import dialogs
import logging
from typing import Optional, Tuple, Any

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("password_manager.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AppError(Exception):
    """Base exception class for application-specific errors."""
    pass

class DatabaseError(AppError):
    """Exception raised for database-related errors."""
    pass

class EncryptionError(AppError):
    """Exception raised for encryption-related errors."""
    pass

class AuthenticationError(AppError):
    """Exception raised for authentication-related errors."""
    pass

class SetupError(AppError):
    """Exception raised for errors during initial setup."""
    pass

def handle_critical_error(error: Exception, root: tk.Tk, message: str = None) -> None:
    """Handle critical errors that require application exit."""
    error_msg = str(error)
    error_type = type(error).__name__
    
    if not message:
        message = f"A critical error occurred: {error_msg}"
    
    logger.critical(f"{error_type}: {error_msg}")
    
    try:
        messagebox.showerror("Critical Error", message, parent=root)
        database.close_db_connection()
        root.destroy()
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
    finally:
        sys.exit(1)

def handle_authentication_error(error: Exception, root: tk.Tk, attempts_left: int) -> None:
    """Handle authentication errors during login."""
    error_msg = str(error)
    error_type = type(error).__name__
    
    logger.warning(f"Authentication error: {error_type}: {error_msg}")
    
    if attempts_left > 0:
        messagebox.showerror(
            "Authentication Failed", 
            f"Login failed: {error_msg}\n{attempts_left} attempts remaining.", 
            parent=root
        )
    else:
        messagebox.showerror(
            "Authentication Failed", 
            "Maximum login attempts reached. Exiting.", 
            parent=root
        )
        database.close_db_connection()
        root.destroy()
        sys.exit(1)

def main():
    # --- Root window creation ---
    root = None
    try:
        logger.info("Creating main application window")
        root = tk.Tk()
        w, h = 650, 450
        ws, hs = root.winfo_screenwidth(), root.winfo_screenheight()
        x, y = (ws/2) - (w/2), (hs/2) - (h/2)
        root.geometry('%dx%d+%d+%d' % (w, h, x, y))
        # root.withdraw() - commented out to avoid breaking the program
        logger.debug("Root window created and configured")
    except Exception as e:
        # Can't use handle_critical_error here as root might not exist
        logger.critical(f"Failed to initialize GUI: {e}")
        messagebox.showerror("Startup Error", f"Failed to initialize GUI:\n{e}")
        sys.exit(1)

    # --- Initialize Database ---
    try:
        logger.info("Initializing database")
        database.initialize_database()
        logger.debug("Database initialization complete")
    except Exception as e:
        handle_critical_error(
            e, root, f"Failed to initialize database: {e}"
        )

    # --- Create App instance ---
    app = None
    try:
        logger.info("Creating PasswordManagerApp instance")
        app = gui.PasswordManagerApp(root)
        logger.debug("PasswordManagerApp instance created")
    except Exception as e:
        handle_critical_error(
            e, root, f"Failed to create application components: {e}"
        )

    # --- Load Salt and Check Verifier ---
    master_key = None
    master_salt = None
    try:
        logger.info("Loading/creating master salt")
        master_salt = encryption.load_or_create_master_salt()
        logger.debug("Master salt loaded/created successfully")
    except Exception as e:
        handle_critical_error(
            e, root, f"Fatal error handling master salt: {e}"
        )

    # Load verifier data (returns None if file doesn't exist)
    try:
        verifier_data = encryption.load_verifier_data()
    except Exception as e:
        handle_critical_error(
            EncryptionError(f"Failed to load verifier data: {e}"), 
            root, 
            f"Failed to load security verification data: {e}"
        )

    if verifier_data is None:
        # --- First Run / Setup Phase ---
        logger.info("Verifier data not found. Starting initial master password setup")
        messagebox.showinfo("First Time Setup Required", "Set your master password for your vault.", parent=root)
        
        initial_password = None
        try:
            while initial_password is None:
                logger.debug("Prompting for initial master password") 
                initial_password = dialogs.prompt_initial_master_password(root)
                
                if initial_password is None:
                    # User cancelled the setup prompt
                    logger.info("Setup cancelled by user")
                    messagebox.showinfo("Setup Cancelled", "Application setup cancelled. Exiting.", parent=root)
                    database.close_db_connection()
                    root.destroy()
                    sys.exit(0)
                    
            logger.debug("Initial password confirmed")
            
            # Derive key
            logger.debug("Deriving initial master key")
            try:
                master_key = encryption.derive_key(initial_password, master_salt)
            except Exception as e:
                raise SetupError(f"Failed to generate encryption key: {e}")
            
            # Encrypt verifier string
            logger.debug("Encrypting verifier string")
            try:
                verify_nonce, verify_ciphertext = encryption.encrypt(encryption.VERIFIER_STRING, master_key)
            except Exception as e:
                raise SetupError(f"Failed to encrypt verification data: {e}")
            
            # Save verifier data
            try:
                encryption.save_verifier_data(verify_nonce, verify_ciphertext)
                logger.info("Initial setup complete. Verifier data saved")
                messagebox.showinfo("Setup Complete", "Master password set successfully!", parent=root)
            except Exception as e:
                raise SetupError(f"Failed to save verification data: {e}")
            
        except SetupError as e:
            handle_critical_error(e, root, f"Setup failed: {e}")
        except Exception as e:
            handle_critical_error(
                SetupError(f"Unexpected error during setup: {e}"), 
                root, 
                f"An unexpected error occurred during setup: {e}"
            )

    else:
        # --- Normal Login / Verification Phase ---
        logger.info("Verifier data found. Proceeding with login")
        verify_nonce, verify_ciphertext = verifier_data

        login_attempts = 0
        max_attempts = 5

        logger.debug("Entering master password prompt loop")
        while login_attempts < max_attempts:
            try:
                # Prompt for password using the standard prompt
                entered_password = dialogs.prompt_master_password(root)

                if entered_password is None:  # User cancelled login
                    logger.info("Login cancelled by user")
                    database.close_db_connection()
                    root.destroy()
                    sys.exit(0)

                if not entered_password:
                    login_attempts += 1
                    handle_authentication_error(
                        AuthenticationError("Password cannot be empty"), 
                        root, 
                        max_attempts - login_attempts
                    )
                    continue

                # Add a short delay after failed attempts to deter brute force attacks
                if login_attempts > 0:
                    time.sleep(0.5 * login_attempts)  # Increasing delay with more failures

                # Derive potential key
                logger.debug("Deriving potential master key")
                potential_master_key = encryption.derive_key(entered_password, master_salt)

                # Verification Step
                logger.debug("Attempting to decrypt verifier")
                decrypted_verifier = encryption.decrypt(verify_nonce, verify_ciphertext, potential_master_key)
                
                # Check if decrypted data matches the known string
                if decrypted_verifier == encryption.VERIFIER_STRING:
                    logger.info("Master password verification successful")
                    master_key = potential_master_key  # Set the confirmed key
                    break  # Exit the while loop - Login successful!
                else:
                    # This case is unlikely with AES-GCM if tag matches
                    login_attempts += 1
                    handle_authentication_error(
                        AuthenticationError("Invalid master password (verification mismatch)"),
                        root,
                        max_attempts - login_attempts
                    )
                    
            except ValueError as e:  # Catches InvalidTag or other issues from decrypt
                login_attempts += 1
                handle_authentication_error(
                    AuthenticationError("Incorrect master password"),
                    root,
                    max_attempts - login_attempts
                )
            except Exception as e:
                login_attempts += 1
                handle_authentication_error(
                    AuthenticationError(f"Authentication failed: {e}"),
                    root,
                    max_attempts - login_attempts
                )

        # --- After the loop ---
        if master_key is None:
            # Login failed after max attempts
            logger.warning("Maximum login attempts reached")
            handle_authentication_error(
                AuthenticationError("Maximum login attempts reached"),
                root,
                0
            )

    # --- Login/Setup Successful - Proceed with application ---
    logger.info("Login/Setup successful")
    
    # Securely store the master key in app
    app.master_key = master_key
    
    # Make sure to clear the variables that held the password
    initial_password = None
    entered_password = None
    
    # Now that we have the key and login is verified, show the main window
    logger.debug("Showing main application window")
    root.deiconify()
    root.title(f"{root.title()} - Logged In")
    
    try:
        app.refresh_password_list()  # Load data now that we have the key
    except Exception as e:
        logger.error(f"Failed to load password list: {e}")
        messagebox.showwarning(
            "Data Loading Error", 
            f"There was an error loading your passwords: {e}\n\nYou may need to restart the application.",
            parent=root
        )

    # Setup cleanup action when window is closed
    def on_closing():
        logger.info("Closing application")
        try:
            database.close_db_connection()
            if root.winfo_exists():
                app.clear_clipboard()
                
            # Clear sensitive data
            if 'master_key' in locals() and master_key is not None:
                # Overwrite with random data then None
                import os
                master_key_size = len(master_key)
                locals()['master_key'] = os.urandom(master_key_size)
                locals()['master_key'] = None
                
        except Exception as e:
            logger.error(f"Error during application shutdown: {e}")
        finally:
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    # Start the Tkinter event loop
    logger.info("Starting main application loop")
    root.mainloop()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Last resort exception handler for uncaught exceptions
        logger.critical(f"Unhandled exception in main thread: {e}", exc_info=True)
        try:
            messagebox.showerror(
                "Fatal Error", 
                f"An unhandled error occurred: {e}\n\nThe application will now exit."
            )
        except:
            pass  # If tkinter is already dead, just exit
        sys.exit(1)
