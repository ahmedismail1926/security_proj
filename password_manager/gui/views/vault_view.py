import tkinter as tk
from tkinter import ttk, messagebox
import logging
from modules.vault_manager import add_credential, get_credential, update_credential, delete_credential
from modules.signatures import verify_vault
from modules.elgamal_keygen import load_public_key

class VaultView(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.username = None
        self._master_password = None
        
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(7, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(4, weight=1)
        
        top_frame = ttk.Frame(self)
        top_frame.grid(row=1, column=1, columnspan=3, sticky="ew", pady=20)
        top_frame.grid_columnconfigure(0, weight=1)
        
        self.title_label = ttk.Label(top_frame, text="Password Vault", font=("Helvetica", 16))
        self.title_label.grid(row=0, column=0)
        
        ttk.Button(top_frame, text="Lock", command=self.lock).grid(row=0, column=1, sticky="e")
        
        ttk.Label(self, text="Website:").grid(row=2, column=1, padx=10, pady=5, sticky="e")
        self.website_entry = ttk.Entry(self, width=30)
        self.website_entry.grid(row=2, column=2, padx=10, pady=5, sticky="w")
        
        ttk.Label(self, text="Credential Username:").grid(row=3, column=1, padx=10, pady=5, sticky="e")
        self.cred_user_entry = ttk.Entry(self, width=30)
        self.cred_user_entry.grid(row=3, column=2, padx=10, pady=5, sticky="w")
        
        ttk.Label(self, text="Credential Password:").grid(row=4, column=1, padx=10, pady=5, sticky="e")
        self.cred_pass_entry = ttk.Entry(self, width=30, show="*")
        self.cred_pass_entry.grid(row=4, column=2, padx=10, pady=5, sticky="w")
        
        self.show_pass_btn = ttk.Button(self, text="Show", command=self.toggle_password)
        self.show_pass_btn.grid(row=4, column=3, padx=5, pady=5, sticky="w")
        
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=5, column=1, columnspan=3, pady=10)
        
        ttk.Button(btn_frame, text="Add", command=self.add_cred).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Get", command=self.get_cred).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Update", command=self.update_cred).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete", command=self.delete_cred).pack(side=tk.LEFT, padx=5)
        
        self.result_text = tk.Text(self, height=5, width=50, state="disabled")
        self.result_text.grid(row=6, column=1, columnspan=3, padx=10, pady=10)
        
        self.integrity_label = ttk.Label(self, text="Vault integrity: Checking...", font=("Helvetica", 10, "bold"))
        self.integrity_label.grid(row=7, column=1, columnspan=3, pady=20)

    def on_show(self, username="", master_password=""):
        self.username = username
        self._master_password = master_password
        if username:
            self.title_label.config(text=f"Password Vault - {self.username}")
            self.check_integrity()
            
    def lock(self):
        self._master_password = None
        self.username = None
        self.website_entry.delete(0, tk.END)
        self.cred_user_entry.delete(0, tk.END)
        self.cred_pass_entry.delete(0, tk.END)
        self.set_result("")
        self.controller.show_frame("InitView")

    def check_integrity(self):
        try:
            public_key = load_public_key(self.username)
            if verify_vault(self.username, public_key):
                self.integrity_label.config(text="Vault integrity: OK", foreground="green")
            else:
                self.integrity_label.config(text="Vault integrity: COMPROMISED - Do not use", foreground="red")
        except Exception as e:
             self.integrity_label.config(text=f"Vault verification error: {str(e)}", foreground="red")

    def toggle_password(self):
        if self.cred_pass_entry.cget('show') == '*':
            self.cred_pass_entry.config(show='')
            self.show_pass_btn.config(text='Hide')
        else:
            self.cred_pass_entry.config(show='*')
            self.show_pass_btn.config(text='Show')

    def set_result(self, text):
        self.result_text.config(state="normal")
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, text)
        self.result_text.config(state="disabled")

    def _execute_operation(self, func, *args):
        if not self._master_password:
            messagebox.showerror("Error", "Master password is required. Please log in.")
            return False
            
        try:
            result = func(self.username, self._master_password, *args)
            self.check_integrity()
            return result
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.set_result(f"Error: {e}")
            return False

    def add_cred(self):
        website = self.website_entry.get()
        user = self.cred_user_entry.get()
        password = self.cred_pass_entry.get()
        
        if not website or not user or not password:
            messagebox.showerror("Error", "All credential fields are required.")
            return
            
        if self._execute_operation(add_credential, website, user, password) is not False:
            self.set_result("Credential added successfully.")
            self.website_entry.delete(0, tk.END)
            self.cred_user_entry.delete(0, tk.END)
            self.cred_pass_entry.delete(0, tk.END)

    def get_cred(self):
        website = self.website_entry.get()
        if not website:
            messagebox.showerror("Error", "Website field is required.")
            return
            
        entry = self._execute_operation(get_credential, website)
        if entry:
            self.cred_user_entry.delete(0, tk.END)
            self.cred_pass_entry.delete(0, tk.END)
            self.cred_user_entry.insert(0, entry.get("username", ""))
            self.cred_pass_entry.insert(0, entry.get("password", ""))
            self.set_result(f"Credential loaded for {website}.")
        elif entry is None:
            messagebox.showinfo("Result", "Website not found.")
            self.set_result("Website not found.")

    def update_cred(self):
        website = self.website_entry.get()
        user = self.cred_user_entry.get()
        password = self.cred_pass_entry.get()
        
        if not website or not user or not password:
            messagebox.showerror("Error", "All credential fields are required.")
            return
            
        if self._execute_operation(update_credential, website, user, password) is not False:
            self.set_result("Credential updated successfully.")

    def delete_cred(self):
        website = self.website_entry.get()
        if not website:
            messagebox.showerror("Error", "Website field is required.")
            return
            
        if self._execute_operation(delete_credential, website) is not False:
            self.set_result("Credential deleted successfully.")