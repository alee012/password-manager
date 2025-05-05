# database.py
import sqlite3
import os
import re
import logging
from typing import Optional, Union, List, Dict, Any, Tuple
from config import DATABASE_PATH  # Import the database path configuration

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

# Custom exceptions for better error handling
class DatabaseError(Exception):
    """Base exception for database errors"""
    pass

class ConnectionError(DatabaseError):
    """Exception raised for connection errors"""
    pass

class QueryError(DatabaseError):
    """Exception raised for query execution errors"""
    pass

class ValidationError(DatabaseError):
    """Exception raised for input validation errors"""
    pass

# Global connection object
_connection = None

# Input validation regex patterns
WEBSITE_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?)+$')
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-@]{1,255}$')  # Basic pattern for common username formats

def validate_website(website: str) -> bool:
    """
    Validates website format.
    Returns True if valid, raises ValidationError if invalid.
    
    Args:
        website: A string representing the website (e.g., "example.com")
        
    Returns:
        bool: True if the website format is valid
        
    Raises:
        ValidationError: If the website format is invalid
    """
    if not website or not isinstance(website, str):
        raise ValidationError("Website cannot be empty and must be a string")
    
    if len(website) > 255:
        raise ValidationError("Website name is too long (maximum 255 characters)")
    
    # Remove protocol prefix if present
    website_clean = website.lower()
    if website_clean.startswith(('http://', 'https://')):
        website_clean = re.sub(r'^https?://', '', website_clean)
    
    # Remove path, query string and fragment if present
    website_clean = website_clean.split('/', 1)[0]
    
    # Basic domain validation
    if not WEBSITE_PATTERN.match(website_clean):
        raise ValidationError(f"Invalid website format: {website}")
    
    return True

def validate_username(username: str) -> bool:
    """
    Validates username format.
    Returns True if valid, raises ValidationError if invalid.
    
    Args:
        username: A string representing the username
        
    Returns:
        bool: True if the username format is valid
        
    Raises:
        ValidationError: If the username format is invalid
    """
    if not username or not isinstance(username, str):
        raise ValidationError("Username cannot be empty and must be a string")
    
    if len(username) > 255:
        raise ValidationError("Username is too long (maximum 255 characters)")
    
    if not USERNAME_PATTERN.match(username):
        raise ValidationError(f"Invalid username format: {username}")
    
    return True

def validate_entry_id(entry_id: int) -> bool:
    """
    Validates entry ID.
    Returns True if valid, raises ValidationError if invalid.
    
    Args:
        entry_id: An integer representing the database entry ID
        
    Returns:
        bool: True if the entry ID is valid
        
    Raises:
        ValidationError: If the entry ID is invalid
    """
    if not isinstance(entry_id, int):
        raise ValidationError("Entry ID must be an integer")
    
    if entry_id <= 0:
        raise ValidationError("Entry ID must be a positive integer")
    
    return True

def validate_encryption_data(data: bytes, data_name: str) -> bool:
    """
    Validates encryption data (nonce or encrypted password).
    Returns True if valid, raises ValidationError if invalid.
    
    Args:
        data: Bytes representing encryption data
        data_name: Name of the data for error messages
        
    Returns:
        bool: True if the encryption data is valid
        
    Raises:
        ValidationError: If the encryption data is invalid
    """
    if not isinstance(data, bytes):
        raise ValidationError(f"{data_name} must be bytes")
    
    if not data:
        raise ValidationError(f"{data_name} cannot be empty")
    
    # Add size limits if appropriate for your encryption method
    # For example, if using AES-GCM with a 96-bit nonce:
    if data_name == "nonce" and len(data) != 12:  # 12 bytes = 96 bits
        raise ValidationError(f"{data_name} has invalid length: {len(data)} bytes")
    
    return True

def get_db_connection() -> sqlite3.Connection:
    """
    Establishes or retrieves the SQLite database connection with proper settings.
    
    Returns:
        sqlite3.Connection: Database connection object
        
    Raises:
        ConnectionError: If the database connection fails
    """
    global _connection
    if _connection is None:
        try:
            # Make sure the directory exists before trying to connect
            db_dir = os.path.dirname(DATABASE_PATH)
            if not os.path.exists(db_dir):
                logger.info(f"Database directory '{db_dir}' not found, creating it.")
                os.makedirs(db_dir, exist_ok=True)

            # Connect with improved settings
            _connection = sqlite3.connect(
                DATABASE_PATH,
                detect_types=sqlite3.PARSE_DECLTYPES,
                timeout=10.0,  # Wait up to 10 seconds for locks
                isolation_level="EXCLUSIVE"  # Strong isolation for security
            )
            
            # Set connection properties
            _connection.row_factory = sqlite3.Row  # Access columns by name
            
            # Set pragmas for better security and performance
            cursor = _connection.cursor()
            cursor.execute("PRAGMA foreign_keys = ON")  # Enforce foreign key constraints
            cursor.execute("PRAGMA synchronous = NORMAL")  # Balance between safety and speed
            cursor.execute("PRAGMA journal_mode = WAL")  # Write-Ahead Logging for better concurrency
            
            logger.info(f"Database connection established to {DATABASE_PATH}")
            
        except sqlite3.Error as e:
            error_msg = f"Error connecting to database at '{DATABASE_PATH}': {e}"
            logger.critical(error_msg)
            raise ConnectionError(error_msg) from e
            
    return _connection

def close_db_connection() -> None:
    """
    Closes the database connection if it's open.
    """
    global _connection
    if _connection:
        _connection.close()
        _connection = None
        logger.info("Database connection closed.")

def initialize_database() -> None:
    """
    Creates the necessary table if it doesn't exist.
    
    Raises:
        QueryError: If table creation fails
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Use BLOB type for nonce and encrypted_password to store raw bytes
        # UNIQUE constraint prevents duplicate website/username pairs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL COLLATE NOCASE, -- Store case-insensitively for lookups
                username TEXT NOT NULL,
                nonce BLOB NOT NULL,
                encrypted_password BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(website, username)
            )
        """)
        
        # Create index for faster lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_website_username 
            ON passwords(website, username)
        """)
        
        conn.commit()
        logger.info("Database initialized successfully (table 'passwords' ensured).")
    except sqlite3.Error as e:
        error_msg = f"Error initializing database table: {e}"
        logger.error(error_msg)
        raise QueryError(error_msg) from e

def add_password_entry(website: str, username: str, nonce: bytes, encrypted_password: bytes) -> Optional[int]:
    """
    Adds a new encrypted password entry to the database.
    
    Args:
        website: The website domain (e.g., "example.com")
        username: The username for the website
        nonce: The encryption nonce (as bytes)
        encrypted_password: The encrypted password (as bytes)
        
    Returns:
        Optional[int]: The ID of the newly inserted row, or None if an error occurs
        
    Raises:
        ValidationError: If any input validation fails
        QueryError: If the database operation fails
    """
    # Validate inputs
    validate_website(website)
    validate_username(username)
    validate_encryption_data(nonce, "nonce")
    validate_encryption_data(encrypted_password, "encrypted password")
    
    sql = """
        INSERT INTO passwords (website, username, nonce, encrypted_password, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    """
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(sql, (website, username, nonce, encrypted_password))
        conn.commit()
        new_id = cursor.lastrowid
        logger.info(f"Entry added successfully for {website}/{username} with ID: {new_id}")
        return new_id  # Return the ID of the new row
    except sqlite3.IntegrityError as e:
        # This specifically handles the UNIQUE constraint violation
        error_msg = f"Entry for {website}/{username} already exists"
        logger.warning(error_msg)
        conn.rollback()  # Rollback the transaction
        raise ValidationError(error_msg) from e
    except sqlite3.Error as e:
        error_msg = f"Error adding password entry for {website}/{username}: {e}"
        logger.error(error_msg)
        conn.rollback()  # Rollback changes on any other database error
        raise QueryError(error_msg) from e

def get_password_entry(entry_id: int) -> Optional[sqlite3.Row]:
    """
    Retrieves a specific password entry (including nonce and encrypted pwd) by ID.
    
    Args:
        entry_id: The ID of the password entry to retrieve
        
    Returns:
        Optional[sqlite3.Row]: Row object if found, otherwise None
        
    Raises:
        ValidationError: If entry_id validation fails
        QueryError: If the database operation fails
    """
    # Validate input
    validate_entry_id(entry_id)
    
    sql = """
        SELECT id, website, username, nonce, encrypted_password, 
               created_at, updated_at 
        FROM passwords 
        WHERE id = ?
    """
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(sql, (entry_id,))
        row = cursor.fetchone()  # Fetch the first matching row
        if not row:
            logger.debug(f"No entry found with ID: {entry_id}")
        return row
    except sqlite3.Error as e:
        error_msg = f"Error fetching entry with ID {entry_id}: {e}"
        logger.error(error_msg)
        raise QueryError(error_msg) from e

def get_all_password_entries() -> List[sqlite3.Row]:
    """
    Retrieves all password entries (id, website, username only) for listing.
    
    Returns:
        List[sqlite3.Row]: List of row objects, empty list if none found
        
    Raises:
        QueryError: If the database operation fails
    """
    # Note: We only select columns needed for the list display for efficiency.
    sql = """
        SELECT id, website, username, created_at, updated_at 
        FROM passwords 
        ORDER BY website COLLATE NOCASE, username COLLATE NOCASE
    """
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(sql)
        rows = cursor.fetchall()  # Fetch all matching rows
        return rows if rows else []
    except sqlite3.Error as e:
        error_msg = f"Error fetching all entries: {e}"
        logger.error(error_msg)
        raise QueryError(error_msg) from e

def update_password_entry(entry_id: int, nonce: bytes, encrypted_password: bytes) -> bool:
    """
    Updates the nonce and encrypted password for a given entry ID.
    
    Args:
        entry_id: The ID of the password entry to update
        nonce: The new encryption nonce (as bytes)
        encrypted_password: The new encrypted password (as bytes)
        
    Returns:
        bool: True if update was successful, False if entry not found
        
    Raises:
        ValidationError: If input validation fails
        QueryError: If the database operation fails
    """
    # Validate inputs
    validate_entry_id(entry_id)
    validate_encryption_data(nonce, "nonce")
    validate_encryption_data(encrypted_password, "encrypted password")
    
    sql = """
        UPDATE passwords
        SET nonce = ?, encrypted_password = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(sql, (nonce, encrypted_password, entry_id))
        conn.commit()
        
        # Check if a row was actually updated
        if cursor.rowcount == 1:
            logger.info(f"Entry ID {entry_id} updated successfully.")
            return True
        elif cursor.rowcount == 0:
            logger.warning(f"No entry found with ID {entry_id} to update.")
            return False
        else:
            # Should not happen with PRIMARY KEY lookup
            logger.warning(f"Update affected {cursor.rowcount} rows for ID {entry_id}. Expected 1.")
            return False  # Treat unexpected row counts as failure
    except sqlite3.Error as e:
        error_msg = f"Error updating entry ID {entry_id}: {e}"
        logger.error(error_msg)
        conn.rollback()  # Rollback changes on error
        raise QueryError(error_msg) from e

def delete_password_entry(entry_id: int) -> bool:
    """
    Deletes a password entry by its ID.
    
    Args:
        entry_id: The ID of the password entry to delete
        
    Returns:
        bool: True if deletion was successful, False if entry not found
        
    Raises:
        ValidationError: If entry_id validation fails
        QueryError: If the database operation fails
    """
    # Validate input
    validate_entry_id(entry_id)
    
    sql = "DELETE FROM passwords WHERE id = ?"
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(sql, (entry_id,))
        conn.commit()
        
        # Check if a row was actually deleted
        if cursor.rowcount == 1:
            logger.info(f"Entry ID {entry_id} deleted successfully.")
            return True
        elif cursor.rowcount == 0:
            logger.warning(f"No entry found with ID {entry_id} to delete.")
            return False
        else:
            # Should not happen with PRIMARY KEY lookup
            logger.warning(f"Delete affected {cursor.rowcount} rows for ID {entry_id}. Expected 1.")
            return False  # Treat unexpected row counts as failure
    except sqlite3.Error as e:
        error_msg = f"Error deleting entry ID {entry_id}: {e}"
        logger.error(error_msg)
        conn.rollback()  # Rollback changes on error
        raise QueryError(error_msg) from e

def search_password_entries(search_term: str) -> List[sqlite3.Row]:
    """
    Searches for password entries matching the given search term in website or username.
    
    Args:
        search_term: The search term to look for
        
    Returns:
        List[sqlite3.Row]: List of matching entries
        
    Raises:
        ValidationError: If search_term validation fails
        QueryError: If the database operation fails
    """
    # Validate input
    if not isinstance(search_term, str):
        raise ValidationError("Search term must be a string")
    
    # Sanitize search term to prevent SQL injection even though we use parameters
    search_term = search_term.strip()
    if not search_term:
        raise ValidationError("Search term cannot be empty")
    
    # Use LIKE with wildcards for partial matching
    search_pattern = f"%{search_term}%"
    
    sql = """
        SELECT id, website, username, created_at, updated_at
        FROM passwords
        WHERE website LIKE ? COLLATE NOCASE OR username LIKE ? COLLATE NOCASE
        ORDER BY website COLLATE NOCASE, username COLLATE NOCASE
    """
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(sql, (search_pattern, search_pattern))
        rows = cursor.fetchall()
        return rows if rows else []
    except sqlite3.Error as e:
        error_msg = f"Error searching for entries with term '{search_term}': {e}"
        logger.error(error_msg)
        raise QueryError(error_msg) from e

# Context manager for database transactions
class DatabaseTransaction:
    """
    Context manager for database transactions.
    Ensures proper commit/rollback handling.
    
    Example usage:
    ```
    with DatabaseTransaction() as cursor:
        cursor.execute("INSERT INTO passwords VALUES (?, ?, ?)", (website, username, password))
        # More operations...
    # Transaction is automatically committed if no exceptions occur,
    # or rolled back if an exception is raised
    ```
    """
    def __init__(self):
        self.conn = None
        self.cursor = None
    
    def __enter__(self):
        self.conn = get_db_connection()
        self.cursor = self.conn.cursor()
        return self.cursor
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            # An exception occurred, rollback
            logger.warning(f"Transaction rolled back due to: {exc_val}")
            self.conn.rollback()
        else:
            # No exception, commit
            self.conn.commit()
            logger.debug("Transaction committed successfully")
        return False  # Propagate exceptions

# Example of how you might use these functions (for testing within this file)
if __name__ == '__main__':
    print("Running database module tests...")
    try:
        initialize_database()

        # Test adding (use dummy byte data for nonce/pwd)
        print("\nTesting Add:")
        id1 = add_password_entry("example.com", "user1", b'nonce1' * 4, b'encrypted1' * 8)
        id2 = add_password_entry("test.org", "admin", b'nonce2' * 4, b'encrypted2' * 8)
        id3 = add_password_entry("example.com", "user2", b'nonce3' * 4, b'encrypted3' * 8)
        
        # Test duplicate add - should raise ValidationError
        try:
            add_password_entry("test.org", "admin", b'nonce_dup' * 4, b'encrypted_dup' * 8)
            print("  Error: Duplicate entry should have raised an exception")
        except ValidationError as e:
            print(f"  Successfully caught duplicate entry: {e}")

        # Test invalid inputs
        try:
            add_password_entry("", "user", b'nonce' * 4, b'encrypted' * 8)
            print("  Error: Empty website should have raised an exception")
        except ValidationError as e:
            print(f"  Successfully caught validation error: {e}")
            
        try:
            add_password_entry("example.com", "", b'nonce' * 4, b'encrypted' * 8)
            print("  Error: Empty username should have raised an exception")
        except ValidationError as e:
            print(f"  Successfully caught validation error: {e}")
            
        try:
            add_password_entry("example.com", "user", b'', b'encrypted' * 8)
            print("  Error: Empty nonce should have raised an exception")
        except ValidationError as e:
            print(f"  Successfully caught validation error: {e}")

        # Test getting all
        print("\nTesting Get All:")
        all_entries = get_all_password_entries()
        if all_entries:
            for entry in all_entries:
                print(f"  ID: {entry['id']}, Website: {entry['website']}, User: {entry['username']}")
        else:
            print("  No entries found.")

        # Test getting one
        print("\nTesting Get One:")
        if id2:
            entry2 = get_password_entry(id2)
            if entry2:
                print(f"  Found entry ID {id2}: Website={entry2['website']}, User={entry2['username']}")
                print(f"  Nonce={entry2['nonce']}, EncryptedPwd={entry2['encrypted_password']}")
                print(f"  Created: {entry2['created_at']}, Updated: {entry2['updated_at']}")
            else:
                print(f"  Could not retrieve entry ID {id2}")
        
        # Test invalid ID
        try:
            get_password_entry(0)  # Invalid ID
            print("  Error: Invalid ID should have raised an exception")
        except ValidationError as e:
            print(f"  Successfully caught validation error: {e}")

        # Test updating
        print("\nTesting Update:")
        if id1:
            update_success = update_password_entry(id1, b'new_nonce1' * 4, b'new_encrypted1' * 8)
            print(f"  Update result for ID {id1}: {update_success}")
            # Verify update
            entry1_updated = get_password_entry(id1)
            if entry1_updated:
                print(f"  Updated entry ID {id1}: Nonce={entry1_updated['nonce']}, EncryptedPwd={entry1_updated['encrypted_password']}")
                print(f"  Updated timestamp: {entry1_updated['updated_at']}")
        
        # Test search
        print("\nTesting Search:")
        search_results = search_password_entries("example")
        if search_results:
            print(f"  Found {len(search_results)} entries for 'example':")
            for entry in search_results:
                print(f"  ID: {entry['id']}, Website: {entry['website']}, User: {entry['username']}")
        else:
            print("  No entries found for 'example'.")

        # Test deleting
        print("\nTesting Delete:")
        if id3:
            delete_success = delete_password_entry(id3)
            print(f"  Delete result for ID {id3}: {delete_success}")
            # Verify delete
            try:
                entry3_deleted = get_password_entry(id3)
                if not entry3_deleted:
                    print(f"  Entry ID {id3} confirmed deleted.")
            except Exception as e:
                print(f"  Error verifying deletion: {e}")
        
        # Test transaction context manager
        print("\nTesting Transaction Context Manager:")
        try:
            with DatabaseTransaction() as cursor:
                cursor.execute("INSERT INTO passwords (website, username, nonce, encrypted_password) VALUES (?, ?, ?, ?)",
                               ("transaction-test.com", "user-tx", b'nonce-tx' * 4, b'encrypted-tx' * 8))
                print("  Inserted in transaction")
                # Simulate a decision to commit or rollback
                do_commit = True
                if not do_commit:
                    raise Exception("Simulated error to trigger rollback")
            print("  Transaction committed successfully")
        except Exception as e:
            print(f"  Transaction test error (expected if do_commit=False): {e}")

        print("\nFinal state:")
        all_entries_final = get_all_password_entries()
        if all_entries_final:
            for entry in all_entries_final:
                print(f"  ID: {entry['id']}, Website: {entry['website']}, User: {entry['username']}")
        else:
            print("  No entries remaining.")

    except Exception as e:
        print(f"An error occurred during testing: {e}")
    finally:
        # Close the connection when testing is done or if an error occurs
        close_db_connection()
    print("\nDatabase module tests finished.")
