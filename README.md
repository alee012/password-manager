# Password Manager

Desktop password manager built with Python, Tkinter, and SQLite as a personal learning project. It stores website login credentials using encryption protected by a single master password.


## Technology used

* **Language:** Python 3
* **GUI:** Tkinter (Python's standard GUI toolkit)
* **Database:** SQLite 3 (via Python's `sqlite3` module)
* **Cryptography:** `cryptography` library (provides AES-GCM, PBKDF2HMAC, SHA256)


## Encryption stuff (`encryption.py`)

* **Algorithm:** Passwords are encrypted using AES-GCM (Advanced Encryption Standard in Galois/Counter Mode) with a 256-bit key (derived via PBKDF2). AES-GCM is an **Authenticated Encryption with Associated Data (AEAD)** mode. This means it provides both:
    * **Confidentiality:** The password is unreadable without the correct key.
    * **Integrity & Authenticity:** It detects if the encrypted data or the associated nonce has been tampered with after encryption. If decryption fails (`InvalidTag`), the data is considered invalid/corrupted/decrypted with the wrong key.
* **Nonce:** A **N**umber used **once**. For AES-GCM, a unique, random 12-byte nonce is generated using `os.urandom()` *every time* a password is encrypted. This nonce does not need to be secret but must be unique for each encryption operation performed with the *same key*. It is stored alongside the ciphertext in the database. During decryption, the exact same nonce and key must be provided to AES-GCM.
* **Process:**
    1.  User enters password in GUI.
    2.  Password string is encoded to bytes (UTF-8).
    3.  A unique 12-byte nonce is generated.
    4.  AES-GCM encrypts the password bytes using the derived `master_key` and the generated nonce.
    5.  The nonce (bytes) and ciphertext (bytes) are stored in the SQLite database as `BLOB`s.
    6.  For viewing, the nonce and ciphertext are retrieved.
    7.  AES-GCM decrypts the ciphertext using the derived `master_key` and the retrieved nonce.
    8.  The resulting bytes are decoded back to a string (UTF-8) for display.


]



