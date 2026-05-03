import tkinter as tk
from tkinter import ttk, messagebox
import os
from modules.elgamal_keygen import initialize_user, load_public_key
from modules.vault_manager import create_vault, _decrypt_vault
from modules.signatures import verify_vault

class InitView(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(2, weight=1)
        
        title_label = ttk.Label(self, text="Secure Password Manager", font=("Helvetica", 16, "bold"))
        title_label.grid(row=0, column=1, pady=20)
        
        ttk.Label(self, text="Username").grid(row=1, column=1, pady=(10, 0))
        self.username_entry = ttk.Entry(self, width=40)
        self.username_entry.grid(row=2, column=1)
        self.username_entry.focus()
        
        ttk.Label(self, text="Master Password").grid(row=3, column=1, pady=(10, 0))
        self.master_password_entry = ttk.Entry(self, width=40, show="*")
        self.master_password_entry.grid(row=4, column=1)
        
        ttk.Frame(self).grid(row=5, column=1, pady=10)
        
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=6, column=1)
        
        ttk.Button(btn_frame, text="Initialize", command=self.initialize).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Login", command=self.login).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Go to Export / Import", command=self.go_to_export).pack(side=tk.LEFT, padx=10)

    def on_show(self, **kwargs):
        self.master_password_entry.delete(0, tk.END)

    def _validate_existing_user(self):
        """Validate username/password for an existing user. Returns (username, mp) or None."""
        username = self.username_entry.get().strip()
        mp = self.master_password_entry.get()

        if not username:
            messagebox.showerror("Error", "Username cannot be empty.")
            return None
        if not mp:
            messagebox.showerror("Error", "Master password cannot be empty.")
            return None

        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        key_path = os.path.join(base_dir, 'keys', username, 'private_key.json')

        if not os.path.exists(key_path):
            messagebox.showerror("Error", "User not found. Please initialize first.")
            self.master_password_entry.delete(0, tk.END)
            return None

        try:
            pub = load_public_key(username)
            if not verify_vault(username, pub):
                messagebox.showerror("Error", "Vault integrity check failed. Cannot proceed.")
                self.master_password_entry.delete(0, tk.END)
                return None
        except Exception as e:
            messagebox.showerror("Error", f"Error during verification: {e}")
            self.master_password_entry.delete(0, tk.END)
            return None

        # Verify master password is correct by attempting decryption
        try:
            _decrypt_vault(username, mp)
        except ValueError:
            messagebox.showerror("Error", "Wrong master password.")
            self.master_password_entry.delete(0, tk.END)
            return None

        return username, mp

    def initialize(self):
        username = self.username_entry.get().strip()
        mp = self.master_password_entry.get()
        
        if not username:
            messagebox.showerror("Error", "Username cannot be empty.")
            return
        if not mp:
            messagebox.showerror("Error", "Master password cannot be empty.")
            return
            
        try:
            initialize_user(username)
            create_vault(username, mp)
            messagebox.showinfo("Success", "User initialized successfully.")
            self.master_password_entry.delete(0, tk.END)
            self.controller.show_frame("VaultView", username=username, master_password=mp)
        except Exception as e:
            self.master_password_entry.delete(0, tk.END)
            messagebox.showerror("Error", str(e))

    def login(self):
        result = self._validate_existing_user()
        if result is None:
            return
        username, mp = result
        self.master_password_entry.delete(0, tk.END)
        self.controller.show_frame("VaultView", username=username, master_password=mp)

    def go_to_export(self):
        result = self._validate_existing_user()
        if result is None:
            return
        username, mp = result
        self.master_password_entry.delete(0, tk.END)
        self.controller.show_frame("ExportView", username=username, master_password=mp)