import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import shutil
from modules.dh_export import (
    export_step1,
    export_step2,
    export_finalize,
    import_finalize
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXPORTS_DIR = os.path.join(BASE_DIR, 'exports')


def check_file(path: str) -> bool:
    return os.path.exists(path)


class ExportView(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.username = None
        self._master_password = None

        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(3, weight=0)
        self.grid_columnconfigure(0, weight=1)

        title_label = ttk.Label(self, text="Vault Export / Import", font=("Helvetica", 16))
        title_label.grid(row=0, column=0, pady=(15, 5))

        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=5, rowspan=2)

        self.export_frame = ttk.Frame(self.notebook)
        self.import_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.export_frame, text="Export (Sender)")
        self.notebook.add(self.import_frame, text="Import (Receiver)")

        self.setup_export_tab()
        self.setup_import_tab()

        ttk.Button(self, text="Back", command=self.go_back).grid(row=3, column=0, pady=10)

    def go_back(self):
        self._master_password = None
        self.username = None
        self.controller.show_frame("InitView")

    def on_show(self, username="", master_password=""):
        self.username = username
        self._master_password = master_password
        if username:
            self.export_sender_entry.config(state="normal")
            self.export_sender_entry.delete(0, tk.END)
            self.export_sender_entry.insert(0, username)
            self.export_sender_entry.config(state="readonly")

    # ──────────────────────────────────────────────────────────────────────────
    #  EXPORT TAB  (Sender / Device 1)
    # ──────────────────────────────────────────────────────────────────────────

    def setup_export_tab(self):
        # Use a single scrollable frame with two clearly labelled sections
        self.export_frame.grid_columnconfigure(1, weight=1)

        row = 0

        # ── Common fields ────────────────────────────────────────────────────
        ttk.Label(self.export_frame, text="Sender Username:").grid(
            row=row, column=0, padx=5, pady=5, sticky="e")
        self.export_sender_entry = ttk.Entry(self.export_frame, width=30, state="readonly")
        self.export_sender_entry.grid(row=row, column=1, padx=5, pady=5, sticky="w")
        row += 1

        # ── STEP 1: Initiate DH Exchange ─────────────────────────────────────
        step1_sep = ttk.Separator(self.export_frame, orient="horizontal")
        step1_sep.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(10, 5))
        row += 1

        ttk.Label(self.export_frame, text="── Step 1: Initiate DH Exchange ──",
                  font=("Helvetica", 10, "bold")).grid(
            row=row, column=0, columnspan=3, pady=(0, 5))
        row += 1

        ttk.Label(self.export_frame, text="Receiver Username:").grid(
            row=row, column=0, padx=5, pady=3, sticky="e")
        self.export_receiver_entry = ttk.Entry(self.export_frame, width=30)
        self.export_receiver_entry.grid(row=row, column=1, padx=5, pady=3, sticky="w")
        row += 1

        ttk.Label(self.export_frame, text="Session Name:").grid(
            row=row, column=0, padx=5, pady=3, sticky="e")
        self.export_session_entry = ttk.Entry(self.export_frame, width=30)
        self.export_session_entry.grid(row=row, column=1, padx=5, pady=3, sticky="w")
        row += 1

        self.step1_btn = ttk.Button(self.export_frame, text="Start DH Exchange (Step 1)",
                                    command=self.do_export_step1)
        self.step1_btn.grid(row=row, column=0, columnspan=3, pady=5)
        row += 1

        # ── STEP 2: Finalize Export ──────────────────────────────────────────
        step2_sep = ttk.Separator(self.export_frame, orient="horizontal")
        step2_sep.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(10, 5))
        row += 1

        ttk.Label(self.export_frame, text="── Step 2: Finalize Export ──",
                  font=("Helvetica", 10, "bold")).grid(
            row=row, column=0, columnspan=3, pady=(0, 5))
        row += 1

        ttk.Label(self.export_frame,
                  text="After the receiver processes Step 1 and sends back the\n"
                       "step2 response file, browse to it and finalize the export.",
                  justify="left").grid(
            row=row, column=0, columnspan=3, padx=10, pady=3)
        row += 1

        ttk.Label(self.export_frame, text="Step 2 File:").grid(
            row=row, column=0, padx=5, pady=3, sticky="e")
        self.step2_file_entry = ttk.Entry(self.export_frame, width=30)
        self.step2_file_entry.grid(row=row, column=1, padx=5, pady=3, sticky="w")
        ttk.Button(self.export_frame, text="Browse",
                   command=self.browse_step2_file).grid(row=row, column=2, padx=5, pady=3)
        row += 1

        self.finalize_btn = ttk.Button(self.export_frame, text="Finalize Export (Step 2)",
                                       command=self.do_export_finalize)
        self.finalize_btn.grid(row=row, column=0, columnspan=3, pady=5)
        row += 1

        # ── Status area ─────────────────────────────────────────────────────
        self.export_status = tk.Text(self.export_frame, height=5, state="disabled")
        self.export_status.grid(row=row, column=0, columnspan=3, padx=10, pady=5, sticky="nsew")

    def browse_step2_file(self):
        file = filedialog.askopenfilename(
            title="Select Step 2 Response File",
            initialdir=EXPORTS_DIR,
            filetypes=[("JSON files", "*.json")])
        if file:
            self.step2_file_entry.delete(0, tk.END)
            self.step2_file_entry.insert(0, file)

    def update_export_status(self, text):
        self.after(0, lambda: self._update_text(self.export_status, text))

    def _update_text(self, widget, text):
        widget.config(state="normal")
        widget.insert(tk.END, text + "\n")
        widget.see(tk.END)
        widget.config(state="disabled")

    def _clear_text(self, widget):
        widget.config(state="normal")
        widget.delete(1.0, tk.END)
        widget.config(state="disabled")

    # ── Export Step 1 ─────────────────────────────────────────────────────────
    def do_export_step1(self):
        sender = self.username
        receiver = self.export_receiver_entry.get().strip()
        session = self.export_session_entry.get().strip()

        if not sender:
            messagebox.showerror("Error", "Sender username is required.")
            return
        if not receiver:
            messagebox.showerror("Error", "Receiver username is required.")
            return
        if not session:
            messagebox.showerror("Error", "Session name is required.")
            return

        self.step1_btn.config(state="disabled")
        self._clear_text(self.export_status)

        def run():
            self.update_export_status("Generating ephemeral DH key pair...")
            try:
                export_step1(sender, receiver, session)
                step1_path = os.path.join(EXPORTS_DIR, session + "_step1.json")
                self.update_export_status(f"DH public key signed and saved.")
                self.update_export_status(f"Output: {step1_path}")
                self.update_export_status("")
                self.update_export_status("Send the _step1.json file to the receiver.")
                self.update_export_status("Wait for the receiver's _step2.json response,")
                self.update_export_status("then proceed to Step 2 above.")
                self.after(0, lambda: messagebox.showinfo(
                    "Step 1 Complete",
                    f"DH exchange file created:\n{step1_path}\n\n"
                    "Send this file to the receiver, then wait for their Step 2 response."))
            except Exception as e:
                self.after(0, lambda e=e: messagebox.showerror("Step 1 Error", str(e)))
                self.update_export_status(f"Error: {str(e)}")
            finally:
                self.after(0, lambda: self.step1_btn.config(state="normal"))

        threading.Thread(target=run, daemon=True).start()

    # ── Export Finalize ───────────────────────────────────────────────────────
    def do_export_finalize(self):
        sender = self.username
        mp = self._master_password
        step2_file = self.step2_file_entry.get().strip()
        session = self.export_session_entry.get().strip()

        if not sender or not mp:
            messagebox.showerror("Error", "Sender and master password are required.")
            return
        if not session:
            messagebox.showerror("Error", "Session name is required (same as Step 1).")
            return
        if not step2_file:
            messagebox.showerror("Error", "Please browse to the receiver's Step 2 response file.")
            return
        if not check_file(step2_file):
            messagebox.showerror("Error", "Step 2 response file not found.")
            return

        # Copy the step2 file into exports dir if it isn't already there
        expected_name = session + "_step2.json"
        expected_path = os.path.join(EXPORTS_DIR, expected_name)
        if os.path.abspath(step2_file) != os.path.abspath(expected_path):
            os.makedirs(EXPORTS_DIR, exist_ok=True)
            shutil.copy2(step2_file, expected_path)

        self.finalize_btn.config(state="disabled")
        self._clear_text(self.export_status)

        def run():
            self.update_export_status("Verifying receiver's DH public key signature...")
            try:
                export_finalize(sender, mp, session)
                final_path = os.path.join(EXPORTS_DIR, session + "_final.json")
                self.update_export_status("Receiver's DH key verified.")
                self.update_export_status("Shared secret computed.")
                self.update_export_status("Vault decrypted, re-encrypted with session key.")
                self.update_export_status("Payload signed.")
                self.update_export_status(f"Output: {final_path}")
                self.update_export_status("")
                self.update_export_status("Send the _final.json file to the receiver.")
                self.after(0, lambda: messagebox.showinfo(
                    "Export Complete",
                    f"Encrypted vault package created:\n{final_path}\n\n"
                    "Send this file to the receiver to complete the import."))
            except Exception as e:
                self.after(0, lambda e=e: messagebox.showerror("Finalize Error", str(e)))
                self.update_export_status(f"Error: {str(e)}")
            finally:
                self.after(0, lambda: self.finalize_btn.config(state="normal"))

        threading.Thread(target=run, daemon=True).start()

    # ──────────────────────────────────────────────────────────────────────────
    #  IMPORT TAB  (Receiver / Device 2)
    # ──────────────────────────────────────────────────────────────────────────

    def setup_import_tab(self):
        self.import_frame.grid_columnconfigure(1, weight=1)

        row = 0

        # ── Common field ─────────────────────────────────────────────────────
        ttk.Label(self.import_frame, text="Receiver Username:").grid(
            row=row, column=0, padx=5, pady=5, sticky="e")
        self.import_receiver_entry = ttk.Entry(self.import_frame, width=30)
        self.import_receiver_entry.grid(row=row, column=1, padx=5, pady=5, sticky="w")
        row += 1

        # ── STEP 1: Respond to DH Exchange ────────────────────────────────────
        step1_sep = ttk.Separator(self.import_frame, orient="horizontal")
        step1_sep.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(10, 5))
        row += 1

        ttk.Label(self.import_frame, text="── Step 1: Respond to DH Exchange ──",
                  font=("Helvetica", 10, "bold")).grid(
            row=row, column=0, columnspan=3, pady=(0, 5))
        row += 1

        ttk.Label(self.import_frame,
                  text="Browse to the _step1.json file received from the sender.",
                  justify="left").grid(
            row=row, column=0, columnspan=3, padx=10, pady=3)
        row += 1

        ttk.Label(self.import_frame, text="Step 1 File:").grid(
            row=row, column=0, padx=5, pady=3, sticky="e")
        self.import_step1_file_entry = ttk.Entry(self.import_frame, width=30)
        self.import_step1_file_entry.grid(row=row, column=1, padx=5, pady=3, sticky="w")
        ttk.Button(self.import_frame, text="Browse",
                   command=self.browse_import_step1_file).grid(row=row, column=2, padx=5, pady=3)
        row += 1

        ttk.Label(self.import_frame, text="Session Name:").grid(
            row=row, column=0, padx=5, pady=3, sticky="e")
        self.import_session_entry = ttk.Entry(self.import_frame, width=30)
        self.import_session_entry.grid(row=row, column=1, padx=5, pady=3, sticky="w")
        row += 1

        self.import_step1_btn = ttk.Button(self.import_frame,
                                           text="Process & Respond (Step 1)",
                                           command=self.do_import_step1)
        self.import_step1_btn.grid(row=row, column=0, columnspan=3, pady=5)
        row += 1

        # ── STEP 2: Import Vault ─────────────────────────────────────────────
        step2_sep = ttk.Separator(self.import_frame, orient="horizontal")
        step2_sep.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(10, 5))
        row += 1

        ttk.Label(self.import_frame, text="── Step 2: Decrypt & Import Vault ──",
                  font=("Helvetica", 10, "bold")).grid(
            row=row, column=0, columnspan=3, pady=(0, 5))
        row += 1

        ttk.Label(self.import_frame,
                  text="After the sender finalizes, browse to the _final.json file\n"
                       "and enter a master password for your new vault.",
                  justify="left").grid(
            row=row, column=0, columnspan=3, padx=10, pady=3)
        row += 1

        ttk.Label(self.import_frame, text="Final File:").grid(
            row=row, column=0, padx=5, pady=3, sticky="e")
        self.import_final_file_entry = ttk.Entry(self.import_frame, width=30)
        self.import_final_file_entry.grid(row=row, column=1, padx=5, pady=3, sticky="w")
        ttk.Button(self.import_frame, text="Browse",
                   command=self.browse_import_final_file).grid(row=row, column=2, padx=5, pady=3)
        row += 1

        ttk.Label(self.import_frame, text="New Master Password:").grid(
            row=row, column=0, padx=5, pady=3, sticky="e")
        self.import_mp_entry = ttk.Entry(self.import_frame, width=30, show="*")
        self.import_mp_entry.grid(row=row, column=1, padx=5, pady=3, sticky="w")
        row += 1

        ttk.Label(self.import_frame, text="Confirm Password:").grid(
            row=row, column=0, padx=5, pady=3, sticky="e")
        self.import_mp_confirm_entry = ttk.Entry(self.import_frame, width=30, show="*")
        self.import_mp_confirm_entry.grid(row=row, column=1, padx=5, pady=3, sticky="w")
        row += 1

        self.import_step2_btn = ttk.Button(self.import_frame,
                                           text="Import Vault (Step 2)",
                                           command=self.do_import_step2)
        self.import_step2_btn.grid(row=row, column=0, columnspan=3, pady=5)
        row += 1

        # ── Status area ─────────────────────────────────────────────────────
        self.import_status = tk.Text(self.import_frame, height=5, state="disabled")
        self.import_status.grid(row=row, column=0, columnspan=3, padx=10, pady=5, sticky="nsew")

    def browse_import_step1_file(self):
        file = filedialog.askopenfilename(
            title="Select Step 1 File from Sender",
            initialdir=EXPORTS_DIR,
            filetypes=[("JSON files", "*.json")])
        if file:
            self.import_step1_file_entry.delete(0, tk.END)
            self.import_step1_file_entry.insert(0, file)
            # Auto-fill session name from filename
            basename = os.path.basename(file)
            if basename.endswith("_step1.json"):
                session = basename.replace("_step1.json", "")
                self.import_session_entry.delete(0, tk.END)
                self.import_session_entry.insert(0, session)

    def browse_import_final_file(self):
        file = filedialog.askopenfilename(
            title="Select Final Export File",
            initialdir=EXPORTS_DIR,
            filetypes=[("JSON files", "*.json")])
        if file:
            self.import_final_file_entry.delete(0, tk.END)
            self.import_final_file_entry.insert(0, file)

    def update_import_status(self, text):
        self.after(0, lambda: self._update_text(self.import_status, text))

    # ── Import Step 1: Respond to DH Exchange ─────────────────────────────────
    def do_import_step1(self):
        receiver = self.import_receiver_entry.get().strip()
        step1_file = self.import_step1_file_entry.get().strip()
        session = self.import_session_entry.get().strip()

        if not receiver:
            messagebox.showerror("Error", "Receiver username is required.")
            return
        if not step1_file:
            messagebox.showerror("Error", "Please browse to the Step 1 file from the sender.")
            return
        if not session:
            messagebox.showerror("Error", "Session name is required.")
            return
        if not check_file(step1_file):
            messagebox.showerror("Error", "Step 1 file not found.")
            return

        # Copy step1 file into exports dir if needed
        expected_name = session + "_step1.json"
        expected_path = os.path.join(EXPORTS_DIR, expected_name)
        if os.path.abspath(step1_file) != os.path.abspath(expected_path):
            os.makedirs(EXPORTS_DIR, exist_ok=True)
            shutil.copy2(step1_file, expected_path)

        self.import_step1_btn.config(state="disabled")
        self._clear_text(self.import_status)

        def run():
            self.update_import_status("Verifying sender's DH public key signature...")
            try:
                export_step2(receiver, session)
                step2_path = os.path.join(EXPORTS_DIR, session + "_step2.json")
                self.update_import_status("Sender's DH key verified.")
                self.update_import_status("Generated ephemeral DH key pair.")
                self.update_import_status("Shared secret computed and saved.")
                self.update_import_status("DH response signed.")
                self.update_import_status(f"Output: {step2_path}")
                self.update_import_status("")
                self.update_import_status("Send the _step2.json file back to the sender.")
                self.update_import_status("Wait for the sender's _final.json, then proceed to Step 2.")
                self.after(0, lambda: messagebox.showinfo(
                    "Step 1 Complete",
                    f"DH response file created:\n{step2_path}\n\n"
                    "Send this file back to the sender and wait for the final export file."))
            except Exception as e:
                self.after(0, lambda e=e: messagebox.showerror("Import Step 1 Error", str(e)))
                self.update_import_status(f"Error: {str(e)}")
            finally:
                self.after(0, lambda: self.import_step1_btn.config(state="normal"))

        threading.Thread(target=run, daemon=True).start()

    # ── Import Step 2: Decrypt & Import ───────────────────────────────────────
    def do_import_step2(self):
        receiver = self.import_receiver_entry.get().strip()
        final_file = self.import_final_file_entry.get().strip()
        session = self.import_session_entry.get().strip()
        mp = self.import_mp_entry.get()
        mp_conf = self.import_mp_confirm_entry.get()

        # Clear password fields immediately
        self.import_mp_entry.delete(0, tk.END)
        self.import_mp_confirm_entry.delete(0, tk.END)

        if not receiver:
            messagebox.showerror("Error", "Receiver username is required.")
            return
        if not final_file:
            messagebox.showerror("Error", "Please browse to the final export file.")
            return
        if not session:
            messagebox.showerror("Error", "Session name is required (same as Step 1).")
            return
        if not mp or not mp_conf:
            messagebox.showerror("Error", "Master password and confirmation are required.")
            return
        if mp != mp_conf:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        if not check_file(final_file):
            messagebox.showerror("Error", "Final export file not found.")
            return

        # Copy the final file into exports dir if needed
        expected_name = session + "_final.json"
        expected_path = os.path.join(EXPORTS_DIR, expected_name)
        if os.path.abspath(final_file) != os.path.abspath(expected_path):
            os.makedirs(EXPORTS_DIR, exist_ok=True)
            shutil.copy2(final_file, expected_path)

        self.import_step2_btn.config(state="disabled")
        self._clear_text(self.import_status)

        def run():
            self.update_import_status("Loading shared secret...")
            try:
                import_finalize(receiver, mp, session)
                self.update_import_status("Sender's payload signature verified.")
                self.update_import_status("Payload decrypted with session key.")
                self.update_import_status("Vault re-encrypted with new master password.")
                self.update_import_status("Vault re-signed with receiver's private key.")
                self.update_import_status("Import complete!")
                self.after(0, lambda: messagebox.showinfo(
                    "Import Complete",
                    "Vault imported and re-encrypted successfully.\n\n"
                    "You can now access the vault with your new master password."))
            except Exception as e:
                self.after(0, lambda e=e: messagebox.showerror("Import Error", str(e)))
                self.update_import_status(f"Error: {str(e)}")
            finally:
                self.after(0, lambda: self.import_step2_btn.config(state="normal"))

        threading.Thread(target=run, daemon=True).start()