import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, BOTH, YES, X, LEFT, RIGHT
import ttkbootstrap as ttk
from ttkbootstrap.constants import SUCCESS, PRIMARY, SECONDARY
from tkinterdnd2 import TkinterDnD, DND_FILES
import threading
from circus_mes import Script

class CircusToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CIRCUS Script Tool (Python Edition)")
        self.root.geometry("800x600")
        
        # Initialize variables before UI
        self.path_var = tk.StringVar()
        self.enc_var = tk.StringVar(value="cp932")
        self.all_text_var = tk.BooleanVar(value=False)
        self.path_entry = None
        self.export_btn = None
        self.build_btn = None
        self.log_area = None

        # Style
        self.style = ttk.Style(theme="superhero")
        
        self.setup_ui()
        self.log("Ready.")

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=BOTH, expand=YES)
        
        # --- File Selection ---
        file_frame = ttk.LabelFrame(main_frame, text="File / Folder Selection", padding=10)
        file_frame.pack(fill=X, pady=10)
        
        self.path_entry = ttk.Entry(file_frame, textvariable=self.path_var)
        self.path_entry.pack(side=LEFT, fill=X, expand=YES, padx=5)
        
        # Register Drag and Drop
        self.path_entry.drop_target_register(DND_FILES)
        self.path_entry.dnd_bind('<<Drop>>', self.on_drop)
        
        btn_browse_file = ttk.Button(file_frame, text="Browse File", command=self.browse_file, bootstyle=SECONDARY)
        btn_browse_file.pack(side=LEFT, padx=5)
        
        btn_browse_folder = ttk.Button(file_frame, text="Browse Folder", command=self.browse_folder, bootstyle=SECONDARY)
        btn_browse_folder.pack(side=LEFT, padx=5)
        
        # --- Encoding Selection ---
        enc_frame = ttk.LabelFrame(main_frame, text="Encoding Settings", padding=10)
        enc_frame.pack(fill=X, pady=10)
        
        ttk.Label(enc_frame, text="Encoding:").pack(side=LEFT, padx=5)
        enc_combo = ttk.Combobox(enc_frame, textvariable=self.enc_var, values=["cp932", "cp936", "shift_jis", "gbk", "utf-8"])
        enc_combo.pack(side=LEFT, padx=5)
        
        ttk.Separator(enc_frame, orient='vertical').pack(side=LEFT, fill='y', padx=10)
        
        all_text_cb = ttk.Checkbutton(enc_frame, text="All Strings (for encoding conversion)", variable=self.all_text_var)
        all_text_cb.pack(side=LEFT, padx=5)
        
        # --- Operation Buttons ---
        btn_frame = ttk.Frame(main_frame, padding=10)
        btn_frame.pack(fill=X, pady=20)
        
        self.export_btn = ttk.Button(btn_frame, text="Export Text (-e)", command=self.start_export, bootstyle=SUCCESS)
        self.export_btn.pack(side=LEFT, fill=X, expand=YES, padx=10)
        
        self.build_btn = ttk.Button(btn_frame, text="Rebuild Script (-b)", command=self.start_rebuild, bootstyle=PRIMARY)
        self.build_btn.pack(side=LEFT, fill=X, expand=YES, padx=10)
        
        # --- Log Output ---
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding=10)
        log_frame.pack(fill=BOTH, expand=YES)
        
        self.log_area = scrolledtext.ScrolledText(log_frame, height=10, state='disabled', font=("Consolas", 10))
        self.log_area.pack(fill=BOTH, expand=YES)

    def log(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, f"{message}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("CIRCUS MES files", "*.mes"), ("All files", "*.*")])
        if file_path:
            self.path_var.set(file_path)

    def browse_folder(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.path_var.set(dir_path)

    def on_drop(self, event):
        path = event.data
        if path.startswith('{') and path.endswith('}'):
            path = path[1:-1]
        # In some cases multiple files are dropped, we just take the first one
        if ' ' in path and not os.path.exists(path):
            # Try to handle multiple files in {} or space separated
            paths = self.root.tk.splitlist(path)
            if paths:
                path = paths[0]
        
        self.path_var.set(path)
        self.log(f"Dropped: {path}")

    def start_operation(self, func):
        self.export_btn.config(state='disabled')
        self.build_btn.config(state='disabled')
        
        thread = threading.Thread(target=func)
        thread.daemon = True
        thread.start()

    def end_operation(self):
        self.export_btn.config(state='normal')
        self.build_btn.config(state='normal')

    def start_export(self):
        path = self.path_var.get()
        if not path:
            messagebox.showwarning("Warning", "Please select a file or folder first.")
            return
        encoding = self.enc_var.get()
        all_text = self.all_text_var.get()
        self.start_operation(lambda: self.run_export(path, encoding, all_text))

    def run_export(self, path, encoding, all_text=False):
        try:
            if os.path.isfile(path):
                files = [path]
            elif os.path.isdir(path):
                files = [os.path.join(path, f) for f in os.listdir(path) if f.lower().endswith(".mes")]
            else:
                self.log(f"Error: Invalid path {path}")
                return

            mode_str = "all strings" if all_text else "dialog only"
            self.log(f"Mode: {mode_str}")

            for f in files:
                self.log(f"Exporting: {os.path.basename(f)}")
                script = Script()
                script.load(f)
                txt_name = os.path.splitext(f)[0] + ".txt"
                script.export_text(txt_name, encoding, all_text=all_text)
            
            self.log("Export Finished.")
        except Exception as e:
            self.log(f"Error: {str(e)}")
        finally:
            self.root.after(0, self.end_operation)

    def start_rebuild(self):
        path = self.path_var.get()
        if not path:
            messagebox.showwarning("Warning", "Please select a file or folder first.")
            return
        encoding = self.enc_var.get()
        all_text = self.all_text_var.get()
        self.start_operation(lambda: self.run_rebuild(path, encoding, all_text))

    def run_rebuild(self, path, encoding, all_text=False):
        try:
            if os.path.isfile(path):
                files = [path]
            elif os.path.isdir(path):
                files = [os.path.join(path, f) for f in os.listdir(path) if f.lower().endswith(".mes")]
            else:
                self.log(f"Error: Invalid path {path}")
                return

            rebuild_dir = os.path.join(os.path.dirname(files[0]) if os.path.isfile(path) else path, "rebuild")
            os.makedirs(rebuild_dir, exist_ok=True)

            mode_str = "all strings" if all_text else "dialog only"
            self.log(f"Mode: {mode_str}")

            for f in files:
                txt_name = os.path.splitext(f)[0] + ".txt"
                if not os.path.exists(txt_name):
                    self.log(f"Skipping {os.path.basename(f)}: Text file not found.")
                    continue
                
                self.log(f"Rebuilding: {os.path.basename(f)}")
                script = Script()
                script.load(f)
                script.import_text(txt_name, encoding, all_text=all_text)
                
                new_path = os.path.join(rebuild_dir, os.path.basename(f))
                script.save(new_path)
            
            self.log(f"Rebuild Finished. Results are in '{rebuild_dir}' folder.")
        except Exception as e:
            self.log(f"Error: {str(e)}")
        finally:
            self.root.after(0, self.end_operation)

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    # Apply ttkbootstrap theme manually to the TkinterDnD window
    app = CircusToolGUI(root)
    root.mainloop()
