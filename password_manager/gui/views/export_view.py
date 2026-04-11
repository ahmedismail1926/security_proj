import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
from modules.dh_export import export_vault, import_vault
from modules.elgamal_keygen import load_public_key

def check_file(path: str) -> bool:
    return os.path.exists(path)

class ExportView(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.username = None
        self._master_password = None
        
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(3, weight=1)
        
        title_label = ttk.Label(self, text="Vault Export / Import", font=("Helvetica", 16))
        title_label.grid(row=1, column=1, columnspan=2, pady=20)
        
        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=2, column=1, columnspan=2, sticky="nsew", padx=10, pady=10)
        
        self.export_frame = ttk.Frame(self.notebook)
        self.import_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.export_frame, text="Export")
        self.notebook.add(self.import_frame, text="Import")
        
        self.setup_export_tab()
        self.setup_import_tab()
        
        ttk.Button(self, text="Back", command=self.go_back).grid(row=4, column=1, columnspan=2, pady=10)
        
    def go_back(self):
        self._master_password = None
        self.username = None
        self.controller.show_frame("InitView")

    def on_show(self, username="", master_password=""):
        self.username = username
        self._master_password = master_password
        if username:
            self.sender_name_entry.config(state="normal")
            self.sender_name_entry.delete(0, tk.END)
            self.sender_name_entry.insert(0, username)
            self.sender_name_entry.config(state="readonly")
        
    def setup_export_tab(self):
        for i in range(5):
            self.export_frame.grid_columnconfigure(i, weight=1)
            
        ttk.Label(self.export_frame, text="Sender Username:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.sender_name_entry = ttk.Entry(self.export_frame, width=30, state="readonly")
        self.sender_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(self.export_frame, text="Recipient Public Key:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.recipient_key_entry = ttk.Entry(self.export_frame, width=30)
        self.recipient_key_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        ttk.Button(self.export_frame, text="Browse", command=self.browse_recipient_key).grid(row=1, column=2, padx=5, pady=5)
        
        ttk.Label(self.export_frame, text="Output File:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.output_file_entry = ttk.Entry(self.export_frame, width=30)
        self.output_file_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        ttk.Button(self.export_frame, text="Browse", command=self.browse_output_file).grid(row=2, column=2, padx=5, pady=5)
        
        self.export_btn = ttk.Button(self.export_frame, text="Start Export", command=self.start_export)
        self.export_btn.grid(row=4, column=0, columnspan=3, pady=10)
        
        self.export_status = tk.Text(self.export_frame, height=5, state="disabled")
        self.export_status.grid(row=5, column=0, columnspan=3, padx=10, pady=5, sticky="nsew")

    def update_export_status(self, text):
        self.after(0, lambda: self._update_text(self.export_status, text))
        
    def _update_text(self, widget, text):
        widget.config(state="normal")
        widget.insert(tk.END, text + "\n")
        widget.see(tk.END)
        widget.config(state="disabled")

    def browse_recipient_key(self):
        file = filedialog.askopenfilename(title="Select Recipient Public Key", filetypes=[("JSON files", "*.json")])
        if file:
            self.recipient_key_entry.delete(0, tk.END)
            self.recipient_key_entry.insert(0, file)

    def browse_output_file(self):
        file = filedialog.asksaveasfilename(title="Save Export File As",
                                           defaultextension=".json",
                                           filetypes=[("JSON files", "*.json")])
        if file:
            self.output_file_entry.delete(0, tk.END)
            self.output_file_entry.insert(0, file)

    def start_export(self):
        sender = self.username
        recipient_key = self.recipient_key_entry.get().strip()
        out_file = self.output_file_entry.get().strip()
        mp = self._master_password
        
        if not sender or not recipient_key or not out_file or not mp:
            messagebox.showerror("Error", "All fields required.")
            return
            
        if not check_file(recipient_key):
            messagebox.showerror("Error", "Recipient public key file not found.")
            return
            
        recipient_username = os.path.basename(os.path.dirname(recipient_key))
        if not recipient_username:
            messagebox.showerror("Error", "Cannot parse recipient username from key path")
            return
            
        export_filename = os.path.basename(out_file).replace('.json', '')
        
        self.export_btn.config(state="disabled")
        self.export_status.config(state="normal")
        self.export_status.delete(1.0, tk.END)
        self.export_status.config(state="disabled")
        
        def run_export():
            self.update_export_status("Generating DH keys...")
            try:
                export_vault(sender, mp, recipient_username, export_filename)
                self.update_export_status("Signing...")
                self.update_export_status("Encrypting payload...")
                self.update_export_status("Done.")
                self.after(0, lambda: messagebox.showinfo("Success", f"Export package saved to {out_file}"))
            except Exception as e:
                self.after(0, lambda e=e: messagebox.showerror("Export Error", str(e)))
                self.update_export_status(f"Error: {str(e)}")
            finally:
                self.after(0, lambda: self.export_btn.config(state="normal"))
                
        threading.Thread(target=run_export, daemon=True).start()

    def setup_import_tab(self):
        for i in range(5):
            self.import_frame.grid_columnconfigure(i, weight=1)
            
        ttk.Label(self.import_frame, text="Recipient Username:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.recipient_name_entry = ttk.Entry(self.import_frame, width=30)
        self.recipient_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(self.import_frame, text="Export File:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.import_file_entry = ttk.Entry(self.import_frame, width=30)
        self.import_file_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        ttk.Button(self.import_frame, text="Browse", command=self.browse_import_file).grid(row=1, column=2, padx=5, pady=5)
        
        ttk.Label(self.import_frame, text="Sender Public Key:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.sender_key_entry = ttk.Entry(self.import_frame, width=30)
        self.sender_key_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        ttk.Button(self.import_frame, text="Browse", command=self.browse_sender_key).grid(row=2, column=2, padx=5, pady=5)
        
        ttk.Label(self.import_frame, text="New Master Password:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.import_mp_entry = ttk.Entry(self.import_frame, width=30, show="*")
        self.import_mp_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(self.import_frame, text="Confirm Master Password:").grid(row=4, column=0, padx=5, pady=5, sticky="e")
        self.import_mp_confirm_entry = ttk.Entry(self.import_frame, width=30, show="*")
        self.import_mp_confirm_entry.grid(row=4, column=1, padx=5, pady=5, sticky="w")
        
        self.import_btn = ttk.Button(self.import_frame, text="Start Import", command=self.start_import)
        self.import_btn.grid(row=5, column=0, columnspan=3, pady=10)
        
        self.import_status = tk.Text(self.import_frame, height=5, state="disabled")
        self.import_status.grid(row=6, column=0, columnspan=3, padx=10, pady=5, sticky="nsew")

    def browse_import_file(self):
        file = filedialog.askopenfilename(title="Select Export File", filetypes=[("JSON files", "*.json")])
        if file:
            self.import_file_entry.delete(0, tk.END)
            self.import_file_entry.insert(0, file)
            
    def browse_sender_key(self):
        file = filedialog.askopenfilename(title="Select Sender Public Key", filetypes=[("JSON files", "*.json")])
        if file:
            self.sender_key_entry.delete(0, tk.END)
            self.sender_key_entry.insert(0, file)
            
    def update_import_status(self, text):
        self.after(0, lambda: self._update_text(self.import_status, text))

    def start_import(self):
        recipient = self.recipient_name_entry.get().strip()
        export_file = self.import_file_entry.get().strip()
        sender_key = self.sender_key_entry.get().strip()
        mp = self.import_mp_entry.get()
        mp_conf = self.import_mp_confirm_entry.get()
        
        self.import_mp_entry.delete(0, tk.END)
        self.import_mp_confirm_entry.delete(0, tk.END)
        
        if not recipient or not export_file or not sender_key or not mp or not mp_conf:
            messagebox.showerror("Error", "All fields required.")
            return
            
        if mp != mp_conf:
            messagebox.showerror("Error", "Passwords do not match.")
            return
            
        if not check_file(export_file):
            messagebox.showerror("Error", "Export package not found.")
            return
            
        if not check_file(sender_key):
            messagebox.showerror("Error", "Sender public key not found.")
            return
            
        import_filename = os.path.basename(export_file).replace('.json', '')
        
        self.import_btn.config(state="disabled")
        self.import_status.config(state="normal")
        self.import_status.delete(1.0, tk.END)
        self.import_status.config(state="disabled")
        
        def run_import():
            self.update_import_status("Starting import...")
            try:
                import_vault(recipient, mp, import_filename)
                self.update_import_status("Verifying signatures...")
                self.update_import_status("Decrypted and validated successfully.")
                self.update_import_status("Done.")
                self.after(0, lambda: messagebox.showinfo("Success", "Vault imported successfully."))
            except Exception as e:
                self.after(0, lambda e=e: messagebox.showerror("Import Error", str(e)))
                self.update_import_status(f"Error: {str(e)}")
            finally:
                self.after(0, lambda: self.import_btn.config(state="normal"))
                
        threading.Thread(target=run_import, daemon=True).start()