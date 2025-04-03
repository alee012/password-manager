# gui.py
import tkinter as tk
from tkinter import ttk # Themed widgets
from tkinter import messagebox # For showing messages
import dialogs

# Import other modules ONLY when needed for callbacks to avoid circular imports,
# OR import them at the top if I'm sure no circular dependencies exist.
# For simplicity and safety, we'll import them inside the methods that use them.
# import database # Example: import database locally inside methods
# import encryption # Example: import encryption locally inside methods

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Secure Password Manager")
        # self.root.geometry("600x400") # Optional: set initial size

        # --- Master Password Handling ---
        # This will be set by main.py after successful login
        self.master_key = None

        # --- Main Window Layout ---
        self.setup_main_window()

    def setup_main_window(self):
        """Sets up the widgets in the main application window."""
        # Frame for password list
        list_frame = ttk.Frame(self.root, padding="10")
        list_frame.grid(row=0, column=0, sticky="nsew")

        # Frame for entry fields and buttons
        entry_frame = ttk.Frame(self.root, padding="10")
        entry_frame.grid(row=0, column=1, sticky="nsew")

        # Configure grid weighting so frames resize
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1) # List area takes more space
        self.root.grid_columnconfigure(1, weight=0) # Entry area fixed/smaller

        # --- Widgets for Listing Passwords ---
        ttk.Label(list_frame, text="Stored Passwords:").grid(row=0, column=0, sticky="w", pady=(0, 5))

        # Use a Treeview for a nice list display
        self.tree = ttk.Treeview(list_frame, columns=("Website", "Username"), show="headings")
        self.tree.heading("Website", text="Website")
        self.tree.heading("Username", text="Username")
        # Set column widths (optional, adjust as needed)
        self.tree.column("Website", width=200, anchor=tk.W)
        self.tree.column("Username", width=150, anchor=tk.W)
        self.tree.grid(row=1, column=0, sticky="nsew")

        # Scrollbar for the Treeview
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=1, column=1, sticky="ns")

        list_frame.grid_rowconfigure(1, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        # --- Widgets for Adding/Editing Entries ---
        ttk.Label(entry_frame, text="Website:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.website_entry = ttk.Entry(entry_frame, width=30)
        self.website_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        ttk.Label(entry_frame, text="Username:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.username_entry = ttk.Entry(entry_frame, width=30)
        self.username_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=2)

        ttk.Label(entry_frame, text="Password:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.password_entry = ttk.Entry(entry_frame, width=30, show="*") # Show '*' for password
        self.password_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=2)

        # --- Buttons ---
        button_frame = ttk.Frame(entry_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)

        self.add_button = ttk.Button(button_frame, text="Add Entry", command=self.add_entry)
        self.add_button.grid(row=0, column=0, padx=5)

        self.view_button = ttk.Button(button_frame, text="View/Copy", command=self.view_entry)
        self.view_button.grid(row=0, column=1, padx=5)

        self.delete_button = ttk.Button(button_frame, text="Delete Entry", command=self.delete_entry)
        self.delete_button.grid(row=0, column=2, padx=5)

        # --- Populate Treeview on startup ---
        # Note: This will be called again in main.py AFTER master key is set
        # self.refresh_password_list() # Initial call might be empty if key not ready

        # --- Event Bindings ---
        # When an item in the tree is selected, call self.on_tree_select
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)

    # --- Implemented/Refined Methods ---

    def refresh_password_list(self):
        """Clears and reloads the password list (id, website, username) from the database."""
        # Import locally or ensure it's imported globally without circular issues
        import database
        print("Refreshing password list...") # Debug print

        # Clear existing items in the tree
        for item in self.tree.get_children():
            try:
                self.tree.delete(item)
            except tk.TclError as e:
                print(f"Minor error clearing tree item {item}: {e}") # Ignore if item already gone

        # Fetch entries from database (only id, website, username)
        try:
            entries = database.get_all_password_entries()
            if entries:
                for entry in entries:
                    # Insert using the database ID as the Treeview item ID (iid)
                    # Ensure values are strings for display
                    self.tree.insert("", tk.END, iid=entry['id'], values=(str(entry['website']), str(entry['username'])))
                print(f"Loaded {len(entries)} entries into list.")
            else:
                print("No entries found in database.")
        except Exception as e:
             messagebox.showerror("Database Error", f"Failed to load password list: {e}", parent=self.root)
             print(f"Error in refresh_password_list: {e}")

    def get_selected_entry_id(self) -> int | None:
        """Gets the database ID of the currently selected item in the Treeview."""
        selected_items = self.tree.selection() # This returns a tuple of selected item IDs (iids)
        if selected_items:
            try:
                # The iid we stored during insert is the database ID
                return int(selected_items[0])
            except (ValueError, IndexError):
                return None # Should not happen if selection is valid
        return None # No item selected

    def on_tree_select(self, event=None):
        """Handles selection changes in the Treeview. Populates fields for context."""
        # Import locally or ensure it's imported globally without circular issues
        import database
        print("Tree selection changed.") # Debug print

        entry_id = self.get_selected_entry_id()
        self.clear_fields(clear_selection=False) # Clear fields but keep selection

        if entry_id:
            # Fetch website/username to populate fields for context (optional)
            # Avoids fetching encrypted data just for selection change
            try:
                # I could potentially get website/username directly from the tree item
                # values = self.tree.item(entry_id, 'values')
                # if values and len(values) >= 2:
                #    self.website_entry.insert(0, values[0])
                #    self.username_entry.insert(0, values[1])
                # OR fetch from DB to be absolutely sure it's current (though less efficient)
                entry_data = database.get_password_entry(entry_id) # Fetches full row needed for context anyway maybe? Let's optimize later.
                # For now, let's just clear fields on selection, user can press View/Copy
                # If I want to populate:
                if entry_data:
                    self.website_entry.insert(0, entry_data['website'])
                    self.username_entry.insert(0, entry_data['username'])
                    print(f"Selected entry ID: {entry_id} ({entry_data['website']}/{entry_data['username']})")
                else:
                    # Entry might have been deleted between refresh and select
                    print(f"Selected entry ID {entry_id} not found in DB (might be deleted).")
                    self.refresh_password_list() # Refresh list if selected item vanished

            except Exception as e:
                print(f"Error during on_tree_select for ID {entry_id}: {e}")
                messagebox.showerror("Error", f"Could not load details for selected item: {e}", parent=self.root)


    def clear_fields(self, clear_selection=True):
        """Clears the website, username, and password entry fields."""
        self.website_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        if clear_selection:
             # Deselect item in tree if requested
             selected = self.tree.selection()
             if selected:
                 self.tree.selection_remove(selected)

    def add_entry(self):
        """Handles adding a new password entry after encryption."""
        # Import locally or ensure it's imported globally without circular issues
        import database
        import encryption
        print("Attempting to add entry...") # Debug print

        website = self.website_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get() # Don't strip password

        # --- Validation ---
        if not website or not username or not password:
            messagebox.showwarning("Input Error", "Website, Username, and Password cannot be empty.", parent=self.root)
            return

        if self.master_key is None:
            messagebox.showerror("Error", "Master key is not available. Cannot add entry.", parent=self.root)
            # In a real app, might try to re-prompt for master password here
            return

        # --- Encryption and Database Add ---
        try:
            # 1. Encrypt the password
            print("Encrypting password...")
            nonce, encrypted_pwd = encryption.encrypt(password, self.master_key)
            print("Encryption successful.")

            # 2. Add to database
            print("Adding entry to database...")
            entry_id = database.add_password_entry(website, username, nonce, encrypted_pwd)

            # 3. Handle result
            if entry_id is not None:
                messagebox.showinfo("Success", f"Password entry for '{website}' added successfully.", parent=self.root)
                self.clear_fields()
                self.refresh_password_list() # Update the list display
                print(f"Entry added with ID: {entry_id}")
            else:
                # Error message likely printed by database function (e.g., duplicate)
                messagebox.showerror("Database Error", f"Failed to add password entry for '{website}'.\nIt might already exist.", parent=self.root)
                print("Failed to add entry (likely duplicate).")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to add entry: {e}", parent=self.root)
            print(f"Exception during add_entry: {e}")


    def view_entry(self):
        """Retrieves, decrypts, and displays/copies the selected password."""
        # Import locally or ensure it's imported globally without circular issues
        import database
        import encryption
        print("Attempting to view entry...") # Debug print

        entry_id = self.get_selected_entry_id()
        if not entry_id:
            messagebox.showwarning("Selection Error", "Please select an entry to view.", parent=self.root)
            return

        if self.master_key is None:
            messagebox.showerror("Error", "Master key is not available. Cannot view entry.", parent=self.root)
            return

        # --- Database Get and Decryption ---
        try:
            # 1. Get encrypted data from DB
            print(f"Fetching entry ID {entry_id} from database...")
            entry_data = database.get_password_entry(entry_id)
            if not entry_data:
                messagebox.showerror("Error", "Selected entry not found in database (it may have been deleted). Refreshing list.", parent=self.root)
                print(f"Entry ID {entry_id} not found in DB for viewing.")
                self.refresh_password_list() # Refresh list if item vanished
                return

            nonce = entry_data['nonce']
            encrypted_pwd = entry_data['encrypted_password']
            website = entry_data['website'] # Get website/user for dialog
            username = entry_data['username']

            # 2. Decrypt
            print("Decrypting password...")
            decrypted_password = encryption.decrypt(nonce, encrypted_pwd, self.master_key)
            print("Decryption successful.")

            
            # Call the function from the dialogs module, passing self.root as the parent
            dialogs.show_password_dialog(self.root, website, username, decrypted_password)
            

        except ValueError as e: # Catch decryption errors specifically
             messagebox.showerror("Decryption Failed", f"Could not decrypt password for '{website}'.\nWrong master key or data corrupted?\n\n({e})", parent=self.root)
             print(f"Decryption failed for ID {entry_id}: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to view entry: {e}", parent=self.root)
            print(f"Exception during view_entry for ID {entry_id}: {e}")






    def delete_entry(self):
        """Handles deleting the selected password entry after confirmation."""
        # Import locally or ensure it's imported globally without circular issues
        import database
        print("Attempting to delete entry...") # Debug print

        entry_id = self.get_selected_entry_id()
        if not entry_id:
            messagebox.showwarning("Selection Error", "Please select an entry to delete.", parent=self.root)
            return

        # --- Confirmation ---
        # Get website/username for confirmation message
        website = ""
        username = ""
        # tree_item = self.tree.item(entry_id) # Get item details from tree
        # if tree_item and tree_item.get('values'):
        #     website, username = tree_item['values'][:2]
        # OR fetch from DB:
        try:
             temp_entry = database.get_password_entry(entry_id)
             if temp_entry:
                  website = temp_entry['website']
                  username = temp_entry['username']
        except Exception:
            pass # Ignore error, just use ID in message
        confirm_msg = f"Are you sure you want to permanently delete the entry for:\n\nWebsite: {website}\nUsername: {username}\n(ID: {entry_id})?"
        if not website: # Fallback message if lookup failed
             confirm_msg = f"Are you sure you want to permanently delete the selected entry (ID: {entry_id})?"

        if not messagebox.askyesno("Confirm Delete", confirm_msg, parent=self.root):
            print("Deletion cancelled by user.")
            return # User chose not to delete

        # --- Database Delete ---
        try:
            print(f"Deleting entry ID {entry_id} from database...")
            success = database.delete_password_entry(entry_id)
            if success:
                messagebox.showinfo("Success", f"Password entry for '{website}' deleted successfully.", parent=self.root)
                self.clear_fields()
                self.refresh_password_list() # Update the list display
                print(f"Entry ID {entry_id} deleted.")
            else:
                # Error message likely printed by database function (e.g., not found)
                messagebox.showerror("Database Error", f"Failed to delete entry ID {entry_id}.\nIt might have already been deleted.", parent=self.root)
                print(f"Failed to delete entry ID {entry_id} (likely not found).")
                self.refresh_password_list() # Refresh list in case it was deleted elsewhere

        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete entry: {e}", parent=self.root)
            print(f"Exception during delete_entry for ID {entry_id}: {e}")


    
    


    



# Placeholder for the main execution logic (usually in main.py)
# if __name__ == '__main__':
#     root = tk.Tk()
#     app = PasswordManagerApp(root)
#     # Need to handle master password input and key derivation here before mainloop
#     # For testing GUI layout ONLY:
#     # app.master_key = b'dummy_key_for_layout_test_only' # DANGER: only for layout!!
#     # app.refresh_password_list() # Might show empty list from DB
#     root.mainloop()
#     # Need proper cleanup (DB connection close) if running standalone