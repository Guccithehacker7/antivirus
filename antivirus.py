import os
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog

# Constants
QUARANTINE_FOLDER = os.path.expanduser("~/AayushAntivirusQuarantine")
SIGNATURE_FILE = "signatures.txt"

class AayushAntivirusAlerter(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Aayush Antivirus Alerter")

        # Load malware signatures or use default
        self.malware_signatures = self.load_signatures()

        # Setup notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill='both')

        # Tabs
        self.scan_tab = ttk.Frame(self.notebook)
        self.quarantine_tab = ttk.Frame(self.notebook)
        self.sig_manager_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.scan_tab, text="Scan")
        self.notebook.add(self.quarantine_tab, text="Quarantine")
        self.notebook.add(self.sig_manager_tab, text="Signature Manager")

        self.create_scan_tab()
        self.create_quarantine_tab()
        self.create_sig_manager_tab()

        # Scan variables
        self.current_files = []
        self.current_index = 0
        self.infected_files = []
        self.anim_chars = ['|', '/', '-', '\\']
        self.anim_index = 0

        # Create quarantine folder if missing
        if not os.path.exists(QUARANTINE_FOLDER):
            os.makedirs(QUARANTINE_FOLDER)

    # ---------- Scan Tab ----------
    def create_scan_tab(self):
        frame = self.scan_tab

        folder_frame = ttk.Frame(frame)
        folder_frame.pack(padx=10, pady=10, fill='x')

        ttk.Label(folder_frame, text="Folder to scan:").pack(side='left')
        self.folder_path_var = tk.StringVar()
        self.folder_entry = ttk.Entry(folder_frame, textvariable=self.folder_path_var, width=40)
        self.folder_entry.pack(side='left', padx=5)
        ttk.Button(folder_frame, text="Browse", command=self.browse_folder).pack(side='left')

        self.scan_button = ttk.Button(frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=5)

        self.progress = ttk.Progressbar(frame, length=500, mode='determinate')
        self.progress.pack(padx=10, pady=5)

        self.status_label = ttk.Label(frame, text="Idle")
        self.status_label.pack()

        self.output_text = scrolledtext.ScrolledText(frame, width=70, height=20)
        self.output_text.pack(padx=10, pady=10)

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path_var.set(folder)

    # ---------- Quarantine Tab ----------
    def create_quarantine_tab(self):
        frame = self.quarantine_tab

        ttk.Label(frame, text="Quarantined Files:").pack(anchor='w', padx=10, pady=5)

        self.quarantine_listbox = tk.Listbox(frame, width=80, height=20)
        self.quarantine_listbox.pack(padx=10, pady=5)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="Restore Selected", command=self.restore_selected).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Delete Selected", command=self.delete_selected).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Refresh List", command=self.refresh_quarantine_list).pack(side='left', padx=5)

        self.refresh_quarantine_list()

    def refresh_quarantine_list(self):
        self.quarantine_listbox.delete(0, tk.END)
        if not os.path.exists(QUARANTINE_FOLDER):
            os.makedirs(QUARANTINE_FOLDER)
        files = os.listdir(QUARANTINE_FOLDER)
        for file in files:
            self.quarantine_listbox.insert(tk.END, file)

    def restore_selected(self):
        selected_indices = self.quarantine_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Warning", "No file selected!")
            return
        for index in reversed(selected_indices):
            filename = self.quarantine_listbox.get(index)
            src = os.path.join(QUARANTINE_FOLDER, filename)
            dest = filedialog.askdirectory(title=f"Select folder to restore {filename} to")
            if dest:
                try:
                    shutil.move(src, os.path.join(dest, filename))
                    self.quarantine_listbox.delete(index)
                    messagebox.showinfo("Restored", f"Restored {filename} to {dest}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to restore {filename}: {e}")
        self.refresh_quarantine_list()

    def delete_selected(self):
        selected_indices = self.quarantine_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Warning", "No file selected!")
            return
        confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to permanently delete the selected files?")
        if not confirm:
            return
        for index in reversed(selected_indices):
            filename = self.quarantine_listbox.get(index)
            path = os.path.join(QUARANTINE_FOLDER, filename)
            try:
                os.remove(path)
                self.quarantine_listbox.delete(index)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete {filename}: {e}")
        self.refresh_quarantine_list()

    # ---------- Signature Manager Tab ----------
    def create_sig_manager_tab(self):
        frame = self.sig_manager_tab

        ttk.Label(frame, text="Malware Signatures:").pack(anchor='w', padx=10, pady=5)

        self.sig_listbox = tk.Listbox(frame, width=80, height=20)
        self.sig_listbox.pack(padx=10, pady=5)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="Add Signature", command=self.add_signature).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Remove Selected", command=self.remove_signature).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Save Signatures", command=self.save_signatures).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Refresh List", command=self.load_signatures_to_listbox).pack(side='left', padx=5)

        self.load_signatures_to_listbox()

    def load_signatures(self):
        if not os.path.isfile(SIGNATURE_FILE):
            return [
                "evil_code_pattern",
                "malicious_function()",
                "bad_command.exe"
            ]
        with open(SIGNATURE_FILE, 'r') as f:
            return [line.strip() for line in f if line.strip()]

    def save_signatures(self):
        with open(SIGNATURE_FILE, 'w') as f:
            for sig in self.malware_signatures:
                f.write(sig + "\n")
        messagebox.showinfo("Saved", "Signatures saved successfully!")

    def load_signatures_to_listbox(self):
        self.sig_listbox.delete(0, tk.END)
        for sig in self.malware_signatures:
            self.sig_listbox.insert(tk.END, sig)

    def add_signature(self):
        new_sig = simpledialog.askstring("Add Signature", "Enter new malware signature:")
        if new_sig:
            if new_sig in self.malware_signatures:
                messagebox.showwarning("Warning", "Signature already exists!")
            else:
                self.malware_signatures.append(new_sig)
                self.load_signatures_to_listbox()

    def remove_signature(self):
        selected_indices = self.sig_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Warning", "No signature selected!")
            return
        for index in reversed(selected_indices):
            sig = self.sig_listbox.get(index)
            self.malware_signatures.remove(sig)
            self.sig_listbox.delete(index)

    # ---------- Scanning logic ----------
    def scan_file(self, filepath):
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                for signature in self.malware_signatures:
                    if signature in content:
                        return signature
            return None
        except Exception:
            return None

    def quarantine_file(self, filepath):
        try:
            if not os.path.exists(QUARANTINE_FOLDER):
                os.makedirs(QUARANTINE_FOLDER)
            filename = os.path.basename(filepath)
            dest = os.path.join(QUARANTINE_FOLDER, filename)
            shutil.move(filepath, dest)
            return True
        except Exception as e:
            self.output_text.insert(tk.END, f"Failed to quarantine {filepath}: {e}\n")
            return False

    def start_scan(self):
        folder = self.folder_path_var.get()
        if not folder:
            messagebox.showwarning("Warning", "Please select a folder to scan.")
            return

        self.scan_button.config(state='disabled')
        self.output_text.delete(1.0, tk.END)
        self.status_label.config(text="Starting scan...")

        self.current_files = []
        self.infected_files = []
        self.current_index = 0
        self.anim_index = 0

        for root_dir, _, files in os.walk(folder):
            for file in files:
                self.current_files.append(os.path.join(root_dir, file))

        if not self.current_files:
            self.status_label.config(text="No files found in the selected folder.")
            self.scan_button.config(state='normal')
            return

        self.progress['maximum'] = len(self.current_files)
        self.progress['value'] = 0

        self.after(100, self.scan_next_file)

    def scan_next_file(self):
        if self.current_index >= len(self.current_files):
            self.status_label.config(text="Scan complete.")
            self.scan_button.config(state='normal')

            if self.infected_files:
                self.output_text.insert(tk.END, "\nSummary: Infected files quarantined:\n")
                for path, sig in self.infected_files:
                    self.output_text.insert(tk.END, f" - {path}: '{sig}'\n")
            else:
                self.output_text.insert(tk.END, "No infected files found.\n")
            return

        filepath = self.current_files[self.current_index]
        anim_char = self.anim_chars[self.anim_index]
        self.anim_index = (self.anim_index + 1) % len(self.anim_chars)

        self.status_label.config(text=f"Scanning {anim_char} {filepath}")
        self.update_idletasks()

        sig = self.scan_file(filepath)
        if sig:
            self.infected_files.append((filepath, sig))
            self.output_text.insert(tk.END, f"[!] Malware found and quarantining: {filepath}: '{sig}'\n")
            self.output_text.see(tk.END)
            self.quarantine_file(filepath)

        self.current_index += 1
        self.progress['value'] = self.current_index

        self.after(100, self.scan_next_file)

if __name__ == "__main__":
    app = AayushAntivirusAlerter()
    app.mainloop()
