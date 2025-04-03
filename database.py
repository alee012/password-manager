# database.py
import sqlite3
import os # Needed for path operations if config isn't used directly everywhere
from config import DATABASE_PATH # Import the database path configuration

_connection = None # Global variable reminder 

def get_db_connection():
    """Establishes or retrieves the SQLite database connection."""
    global _connection
    if _connection is None:
        try:
            # Make sure the directory exists before trying to connect
            db_dir = os.path.dirname(DATABASE_PATH)
            if not os.path.exists(db_dir):
                 print(f"Database directory '{db_dir}' not found, creating it.")
                 os.makedirs(db_dir, exist_ok=True)

            # Use detect_types to handle BLOB data correctly if needed later
            
            _connection = sqlite3.connect(DATABASE_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
            _connection.row_factory = sqlite3.Row # Access columns by name (e.g., row['website'])
            print(f"Database connection established to {DATABASE_PATH}")
        except sqlite3.Error as e:
            print(f"FATAL: Error connecting to database at '{DATABASE_PATH}': {e}")
            # I could consider raising the exception or using sys.exit() if connection fails
            raise SystemExit(f"Database connection failed: {e}")
    return _connection

def close_db_connection():
    """Closes the database connection if it's open."""
    global _connection
    if _connection:
        _connection.close()
        _connection = None
        print("Database connection closed.")

def initialize_database():
    """Creates the necessary table if it doesn't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Use BLOB type for nonce and encrypted_password to store raw bytes
        # UNIQUE constraint prevents duplicate website/username pairs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL COLLATE NOCASE, -- Store case-insensitively for lookups
                username TEXT NOT NULL,
                nonce BLOB NOT NULL,
                encrypted_password BLOB NOT NULL,
                UNIQUE(website, username)
            )
        """)
        conn.commit()
        print("Database initialized successfully (table 'passwords' ensured).")
    except sqlite3.Error as e:
        print(f"Error initializing database table: {e}")
        # Depending on the error, you might want to raise it or handle it
        # For now, just print the error. A critical error might need sys.exit()

# --- Implemented Functions ---

def add_password_entry(website: str, username: str, nonce: bytes, encrypted_password: bytes) -> int | None:
    """
    Adds a new encrypted password entry to the database.
    Returns the ID of the newly inserted row, or None if an error occurs (e.g., duplicate).
    """
    sql = """
        INSERT INTO passwords (website, username, nonce, encrypted_password)
        VALUES (?, ?, ?, ?)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql, (website, username, nonce, encrypted_password))
        conn.commit()
        new_id = cursor.lastrowid
        print(f"Entry added successfully for {website}/{username} with ID: {new_id}")
        return new_id # Return the ID of the new row
    except sqlite3.IntegrityError:
        # This specifically handles the UNIQUE constraint violation
        print(f"Error: An entry for {website}/{username} already exists.")
        conn.rollback() # Rollback the transaction
        return None
    except sqlite3.Error as e:
        print(f"Error adding password entry for {website}/{username}: {e}")
        conn.rollback() # Rollback changes on any other database error
        return None

def get_password_entry(entry_id: int) -> sqlite3.Row | None:
    """
    Retrieves a specific password entry (including nonce and encrypted pwd) by ID.
    Returns a sqlite3.Row object if found, otherwise None.
    """
    sql = "SELECT id, website, username, nonce, encrypted_password FROM passwords WHERE id = ?"
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql, (entry_id,))
        row = cursor.fetchone() # Fetch the first matching row
        if row:
            return row
        else:
            print(f"No entry found with ID: {entry_id}")
            return None
    except sqlite3.Error as e:
        print(f"Error fetching entry with ID {entry_id}: {e}")
        return None

def get_all_password_entries() -> list[sqlite3.Row]:
    """
    Retrieves all password entries (id, website, username only) for listing.
    Returns a list of sqlite3.Row objects, or an empty list if none found or error occurs.
    """
    # Note: We only select columns needed for the list display for efficiency.
    sql = "SELECT id, website, username FROM passwords ORDER BY website, username"
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        rows = cursor.fetchall() # Fetch all matching rows
        return rows if rows else []
    except sqlite3.Error as e:
        print(f"Error fetching all entries: {e}")
        return [] # Return empty list on error

def update_password_entry(entry_id: int, nonce: bytes, encrypted_password: bytes) -> bool:
    """
    Updates the nonce and encrypted password for a given entry ID.
    Returns True if the update was successful (exactly one row affected), False otherwise.
    """
    # Note: This function assumes I only want to update the password/nonce.
    # I could extend it to update website/username too if needed.
    sql = """
        UPDATE passwords
        SET nonce = ?, encrypted_password = ?
        WHERE id = ?
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql, (nonce, encrypted_password, entry_id))
        conn.commit()
        # cursor.rowcount gives the number of rows affected by the last execute.
        if cursor.rowcount == 1:
            print(f"Entry ID {entry_id} updated successfully.")
            return True
        elif cursor.rowcount == 0:
            print(f"Error: No entry found with ID {entry_id} to update.")
            return False
        else:
            # Should not happen with PRIMARY KEY lookup, but good practice to consider
            print(f"Warning: Update affected {cursor.rowcount} rows for ID {entry_id}. Expected 1.")
            # Depending on desired behavior, maybe return True or False, or log more details
            return False # Treat unexpected row counts as failure
    except sqlite3.Error as e:
        print(f"Error updating entry ID {entry_id}: {e}")
        conn.rollback() # Rollback changes on error
        return False

def delete_password_entry(entry_id: int) -> bool:
    """
    Deletes a password entry by its ID.
    Returns True if the deletion was successful (exactly one row affected), False otherwise.
    """
    sql = "DELETE FROM passwords WHERE id = ?"
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(sql, (entry_id,))
        conn.commit()
        # Check if a row was actually deleted
        if cursor.rowcount == 1:
            print(f"Entry ID {entry_id} deleted successfully.")
            return True
        elif cursor.rowcount == 0:
            print(f"Error: No entry found with ID {entry_id} to delete.")
            return False
        else:
            # Should not happen with PRIMARY KEY lookup
            print(f"Warning: Delete affected {cursor.rowcount} rows for ID {entry_id}. Expected 1.")
            return False # Treat unexpected row counts as failure
    except sqlite3.Error as e:
        print(f"Error deleting entry ID {entry_id}: {e}")
        conn.rollback() # Rollback changes on error
        return False

# Example of how you might use these functions (for testing within this file)
if __name__ == '__main__':
    print("Running database module tests...")
    try:
        initialize_database()

        # Test adding (use dummy byte data for nonce/pwd)
        print("\nTesting Add:")
        id1 = add_password_entry("Example.com", "user1", b'nonce1', b'encrypted1')
        id2 = add_password_entry("test.org", "admin", b'nonce2', b'encrypted2')
        id3 = add_password_entry("Example.com", "user2", b'nonce3', b'encrypted3')
        # Test duplicate add
        add_password_entry("test.org", "admin", b'nonce_dup', b'encrypted_dup')

        # Test getting all
        print("\nTesting Get All:")
        all_entries = get_all_password_entries()
        if all_entries:
            for entry in all_entries:
                print(f"  ID: {entry['id']}, Website: {entry['website']}, User: {entry['username']}")
        else:
            print("  No entries found.")

        # Test getting one (if id2 was created)
        print("\nTesting Get One:")
        if id2:
            entry2 = get_password_entry(id2)
            if entry2:
                print(f"  Found entry ID {id2}: Website={entry2['website']}, User={entry2['username']}, Nonce={entry2['nonce']}, EncryptedPwd={entry2['encrypted_password']}")
            else:
                print(f"  Could not retrieve entry ID {id2}")
        get_password_entry(999) # Test non-existent ID

        # Test updating (if id1 was created)
        print("\nTesting Update:")
        if id1:
            update_success = update_password_entry(id1, b'new_nonce1', b'new_encrypted1')
            print(f"  Update result for ID {id1}: {update_success}")
            # Verify update
            entry1_updated = get_password_entry(id1)
            if entry1_updated:
                 print(f"  Updated entry ID {id1}: Nonce={entry1_updated['nonce']}, EncryptedPwd={entry1_updated['encrypted_password']}")
        update_password_entry(999, b'x', b'y') # Test non-existent ID

        # Test deleting (if id3 was created)
        print("\nTesting Delete:")
        if id3:
             delete_success = delete_password_entry(id3)
             print(f"  Delete result for ID {id3}: {delete_success}")
             # Verify delete
             entry3_deleted = get_password_entry(id3)
             if not entry3_deleted:
                  print(f"  Entry ID {id3} confirmed deleted.")
        delete_password_entry(999) # Test non-existent ID

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