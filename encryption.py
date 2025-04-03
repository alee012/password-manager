
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# Import InvalidTag exception for specific error handling during decryption
from cryptography.exceptions import InvalidTag
import base64 # Keep this just in case

# Import config and the constants
from config import PBKDF2_ITERATIONS, SALT_SIZE_BYTES, KEY_SIZE_BYTES
import config # Needed for get_master_salt_path

# --- Constants ---
VERIFIER_STRING = "PASSWORD_MANAGER_OK_V1" # Added version just in case format changes
NONCE_SIZE_BYTES = 12 # AES-GCM standard nonce size

# --- Key Derivation and Salt Handling (Should already be implemented) ---

def generate_salt(size: int = SALT_SIZE_BYTES) -> bytes:
    """Generates a cryptographically secure random salt."""
    
    return os.urandom(size)

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a secure encryption key from the master password and salt."""
    
    if not master_password:
        raise ValueError("Master password cannot be empty.")
    if not salt or len(salt) != SALT_SIZE_BYTES:
         raise ValueError(f"Salt must be {SALT_SIZE_BYTES} bytes.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE_BYTES, # e.g., 32 bytes for AES-256
        salt=salt,
        iterations=PBKDF2_ITERATIONS, # Use high iteration count
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode('utf-8'))
    return key

def get_master_salt_path() -> str:
    """Returns the path where the master salt file should be stored."""
    
    return os.path.join(config.DATA_DIR, "master.salt")

def load_or_create_master_salt() -> bytes:
    """Loads the master salt from its file, or creates it if it doesn't exist."""
    
    salt_path = get_master_salt_path()
    if os.path.exists(salt_path):
        with open(salt_path, "rb") as f:
            salt = f.read()
            if len(salt) == SALT_SIZE_BYTES:
                
                return salt
                
            else:
                print(f"Warning: Existing salt file '{salt_path}' has incorrect size. Regenerating.")
                # Make this into error instead if I decide size mismatch is critical
                pass # Fall through to generate
    print(f"Generating new master salt at '{salt_path}'...")
    new_salt = generate_salt()
    try:
        os.makedirs(os.path.dirname(salt_path), exist_ok=True)
        with open(salt_path, "wb") as f:
            print(f"DEBUG: File '{salt_path}' opened. Writing salt...")
            f.write(new_salt)
            print(f"DEBUG: Salt written to '{salt_path}'.")
        return new_salt
    except IOError as e:
        print(f"Error: Could not write master salt file to '{salt_path}'. Check permissions.")
        raise SystemExit(f"Salt file error: {e}")
    except Exception as e: # Catch any other potential error during file write
        print(f"Unexpected error writing salt file: {e}")
        raise SystemExit(f"Unexpected salt file error: {e}")

# --- Core Encryption/Decryption Implementation ---

def encrypt(data: str, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts string data using AES-GCM with the provided key.
    Generates a unique nonce for each encryption.

    Args:
        data (str): The plaintext string to encrypt.
        key (bytes): The encryption key (must be KEY_SIZE_BYTES long, e.g., 32 bytes for AES-256).

    Returns:
        tuple[bytes, bytes]: A tuple containing (nonce, ciphertext).
                             The nonce MUST be stored alongside the ciphertext.

    Raises:
        ValueError: If data is empty or key is invalid size.
    """
    if not data:
        raise ValueError("Data to encrypt cannot be empty.")
    if not key or len(key) != KEY_SIZE_BYTES:
         raise ValueError(f"Encryption key must be exactly {KEY_SIZE_BYTES} bytes long.")

    # 1. Initialize AES-GCM with the key
    aesgcm = AESGCM(key)

    # 2. Generate a unique, random 12-byte nonce for each encryption operation
    # Nonce does not need to be secret, but MUST be unique per key/encryption pair.
    nonce = os.urandom(12)

    # 3. Encode the string data to bytes (UTF-8 is standard)
    data_bytes = data.encode('utf-8')

    # 4. Encrypt the data bytes
    # The 'None' argument is for optional Additional Authenticated Data (AAD), not used here.
    ciphertext = aesgcm.encrypt(nonce, data_bytes, None)

    # 5. Return the nonce and the resulting ciphertext
    # Both MUST be stored together to allow for decryption.
    return nonce, ciphertext

def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    """
    Decrypts AES-GCM encrypted ciphertext using the provided nonce and key.

    Args:
        nonce (bytes): The unique nonce that was used during encryption (must be 12 bytes).
        ciphertext (bytes): The encrypted data.
        key (bytes): The encryption key used during encryption (must be KEY_SIZE_BYTES long).

    Returns:
        str: The original decrypted plaintext string.

    Raises:
        ValueError: If nonce/ciphertext/key are invalid, empty, or decryption fails
                    (e.g., wrong key, wrong nonce, or data tampered with - InvalidTag).
    """
    if not nonce or len(nonce) != 12:
        raise ValueError("Decryption requires a 12-byte nonce.")
    if not ciphertext:
         raise ValueError("Ciphertext to decrypt cannot be empty.")
    if not key or len(key) != KEY_SIZE_BYTES:
         raise ValueError(f"Decryption key must be exactly {KEY_SIZE_BYTES} bytes long.")

    # 1. Initialize AES-GCM with the key
    aesgcm = AESGCM(key)

    try:
        # 2. Decrypt the ciphertext using the same nonce and key
        # This will raise an InvalidTag exception if the key is wrong,
        # the nonce is wrong, or the ciphertext/AAD has been tampered with.
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None) # None for AAD

        # 3. Decode the decrypted bytes back into a string (using UTF-8)
        return decrypted_bytes.decode('utf-8')

    except InvalidTag:
        # This is the specific exception raised by cryptography library on AEAD decryption failure
        print("Decryption failed: InvalidTag - Data authenticity or integrity check failed (wrong key, wrong nonce, or tampered data).")
        raise ValueError("Decryption failed: Data corrupted or wrong key/nonce.") from None # Chain explicitly suppressed
    except Exception as e:
        # Catch any other potential unexpected errors during decryption
        print(f"An unexpected error occurred during decryption: {e}")
        raise ValueError(f"Decryption failed due to an unexpected error: {e}") from e
    
# --- New Verifier Data Handling ---

def get_verifier_path() -> str:
    """Returns the path where the master password verifier file should be stored."""
    return os.path.join(config.DATA_DIR, "verifier.bin")

def save_verifier_data(nonce: bytes, ciphertext: bytes):
    """Saves the verifier nonce and ciphertext to a file."""
    if len(nonce) != NONCE_SIZE_BYTES:
        raise ValueError(f"Verifier nonce must be {NONCE_SIZE_BYTES} bytes.")

    verifier_path = get_verifier_path()
    print(f"DEBUG: Saving verifier data to '{verifier_path}'...")
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(verifier_path), exist_ok=True)
        # Write nonce then ciphertext
        with open(verifier_path, "wb") as f:
            f.write(nonce)
            f.write(ciphertext)
        print("DEBUG: Verifier data saved successfully.")
    except IOError as e:
        print(f"Error: Could not write verifier file to '{verifier_path}'. Check permissions.")
        # Decide if this should be fatal - probably yes during setup.
        raise IOError(f"Verifier file write error: {e}") from e # Re-raise for main to catch

def load_verifier_data() -> tuple[bytes, bytes] | None:
    """
    Loads the verifier nonce and ciphertext from its file.
    Returns (nonce, ciphertext) tuple if successful, None otherwise (e.g., file not found).
    """
    verifier_path = get_verifier_path()
    print(f"DEBUG: Attempting to load verifier data from '{verifier_path}'...")
    if not os.path.exists(verifier_path):
        print("DEBUG: Verifier file not found.")
        return None

    try:
        with open(verifier_path, "rb") as f:
            # Read the nonce (fixed size)
            nonce = f.read(NONCE_SIZE_BYTES)
            if len(nonce) < NONCE_SIZE_BYTES:
                print(f"Error: Verifier file '{verifier_path}' is corrupted (too short for nonce).")
                return None # File exists but is too small

            # Read the rest as ciphertext
            ciphertext = f.read()
            if not ciphertext:
                print(f"Error: Verifier file '{verifier_path}' is corrupted (missing ciphertext).")
                return None # File exists but no ciphertext after nonce

            print("DEBUG: Verifier data loaded successfully.")
            return nonce, ciphertext
    except IOError as e:
        print(f"Error: Could not read verifier file from '{verifier_path}': {e}")
        return None # Treat read errors as file not being valid/available
    except Exception as e:
        print(f"Unexpected error loading verifier file: {e}")
        return None
