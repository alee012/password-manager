
import os
import sys # Import sys module

# --- Determine Base Path ---
# Check if the application is running as a bundled executable (PyInstaller)
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    # If running in a PyInstaller bundle (esp. --onefile mode),
    # _MEIPASS is the temporary folder. Base path should be executable's dir.
    application_path = os.path.dirname(sys.executable)
elif getattr(sys, 'frozen', False):
     # If bundled (e.g. --onedir mode), base path is directory containing executable
     application_path = os.path.dirname(sys.executable)
else:
    # If running as a normal script, base path is the script's directory
    # Use os.path.abspath to handle running from different working directories
    application_path = os.path.dirname(os.path.abspath(__file__))

print(f"DEBUG: Application Base Path: {application_path}") # Good for debugging builds

# --- Define Data Directory ---
# Define the data directory relative to the determined application path
DATA_DIR = os.path.join(application_path, "data")
print(f"DEBUG: Data Directory Path: {DATA_DIR}")

# Define the database file name
DB_FILENAME = "passwords.db"
# Construct the full path to the database file
DATABASE_PATH = os.path.join(DATA_DIR, DB_FILENAME)

# Make sure data directory exists 
# Use a try-except block for better error handling during directory creation
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except OSError as e:
     print(f"FATAL: Could not create data directory '{DATA_DIR}': {e}")
     # Might show a GUI error here before exiting in app setting
     sys.exit(f"Failed to create data directory: {e}")


# --- Encryption Parameters (remain the same) ---
PBKDF2_ITERATIONS = 600000
SALT_SIZE_BYTES = 16
KEY_SIZE_BYTES = 32

