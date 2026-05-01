import os
import sys
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD

    HAS_DND = True
except ImportError:
    HAS_DND = False
    DND_FILES = None
    TkinterDnD = None

from exhibit_crypto import decrypt_rld_folder, encrypt_rld_folder
from exhibit_text import process_dump, process_full_disasm, process_inject
from exhibit_keyfinder import KeyFinderManager


class ExHIBITAllInOneGUI(TkinterDnD.Tk if HAS_DND else tk.Tk):
    PREFIX_NORMAL_WITH_DISPLAY = "[CWD]"
    PREFIX_DISPLAY = "[DSP]"
    PREFIX_NORMAL_NO_DISPLAY = "[CND]"

    def __init__(self):
        super().__init__()
        self.title("ExHIBIT All-In-One Tool")
        self.geometry("980x760")
        self.minsize(920, 700)

        # 获取程序运行目录（兼容打包后的环境）
        if getattr(sys, 'frozen', False):
            self.base_dir = Path(sys.executable).parent
        else:
            self.base_dir = Path(__file__).resolve().parent
        self.loader_path = self.base_dir / "Loader.exe"
        self.dll_path = self.base_dir / "KeyFinder.dll"

        self.status_var = tk.StringVar(value="就绪")
        self.log_queue = queue.Queue()
        self.process = None

        # XOR 密钥配置（从内置改为变量控制）
        self.xor_key_var = tk.StringVar(value="")
        self.def_xor_key_var = tk.StringVar(value="")

        self.kf_manager = KeyFinderManager(
            self.base_dir,
            self.log_queue,
            self.set_status,
            self.log,
            self._set_process
        )

        self._build_ui()
        self._poll_log_queue()

        if not HAS_DND:
            self.log("警告：未检测到 tkinterdnd2，拖拽功能不可用。")
            self.log("可执行：pip install tkinterdnd2")
        self.log("已加载单文件整合版：KeyFinder + RLD解密 + 文本提取/回封 + RLD加密")

    def _set_process(self, process):
        self.process = process

    def _get_process(self):
        return self.process

    def _build_ui(self):
        main = ttk.Frame(self, padding=10)
        main.pack(fill="both", expand=True)

        title = ttk.Label(
            main,
            text="ExHIBIT 四合一工具",
            font=("Microsoft YaHei UI", 15, "bold"),
        )
        title.pack(anchor="w", pady=(0, 8))

        desc = ttk.Label(
            main,
            text="推荐流程：1. 提取密钥 → 2. 解密RLD → 3. 提取/修改/回封BIN文本 → 4. 重新加密RLD",
        )
        desc.pack(anchor="w", pady=(0, 10))

        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill="both", expand=True)

        self._build_keyfinder_tab()
        self._build_rld_crypto_tab()
        self._build_dump_inject_tab()

        log_frame = ttk.LabelFrame(main, text="日志", padding=8)
        log_frame.pack(fill="both", expand=True, pady=(10, 0))

        self.log_text = tk.Text(log_frame, height=12, wrap="word", bg="#f7f7f7")
        self.log_text.pack(side="left", fill="both", expand=True)

        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scroll.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=log_scroll.set)

        status_bar = ttk.Label(
            main,
            textvariable=self.status_var,
            relief="sunken",
            anchor="w",
            padding=(8, 4),
        )
        status_bar.pack(fill="x", pady=(10, 0))

    def _build_keyfinder_tab(self):
        frame = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(frame, text="步骤1：KeyFinder")

        self.game_exe_var = tk.StringVar()
        self.game_exe_var.trace_add("write", lambda *args: self.manual_detect_keys())

        self._add_path_row(
            frame,
            "游戏 EXE：",
            self.game_exe_var,
            0,
            choose="file",
            filetypes=[("Executable", "*.exe"), ("All Files", "*.*")],
        )

        env_box = ttk.LabelFrame(frame, text="环境检查", padding=8)
        env_box.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=10)

        self.env_text = tk.Text(env_box, height=5, wrap="word")
        self.env_text.pack(fill="x")
        self.refresh_env_text()

        btn_row = ttk.Frame(frame)
        btn_row.grid(row=2, column=0, columnspan=3, sticky="ew", pady=8)

        ttk.Button(btn_row, text="刷新检查", command=self.refresh_env_text).pack(side="left")
        ttk.Button(btn_row, text="启动 KeyFinder", command=self.start_loader).pack(side="left", padx=8)
        ttk.Button(btn_row, text="普通启动游戏", command=self.start_game_normal).pack(side="left")
        ttk.Button(btn_row, text="清理游戏目录Key", command=self.clean_game_key_files).pack(side="left", padx=8)
        ttk.Button(btn_row, text="打开游戏目录", command=self.open_work_dir).pack(side="left", padx=8)

        frame.columnconfigure(1, weight=1)

    def _build_rld_crypto_tab(self):
        frame = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(frame, text="步骤2/4：RLD加解密")

        self.dec_rld_dir_var = tk.StringVar(value=str(self.base_dir / "rld"))
        self.dec_out_dir_var = tk.StringVar(value=str(self.base_dir / "bin_dec"))
        self.dec_key_var = tk.StringVar(value=str(self.base_dir / "key.bin"))
        self.dec_key_def_var = tk.StringVar(value=str(self.base_dir / "key_def.bin"))

        self.enc_rld_dir_var = tk.StringVar(value=str(self.base_dir / "rld_chs"))
        self.enc_out_dir_var = tk.StringVar(value=str(self.base_dir / "rld_enc"))
        self.enc_key_var = tk.StringVar(value=str(self.base_dir / "key.bin"))
        self.enc_key_def_var = tk.StringVar(value=str(self.base_dir / "key_def.bin"))

        dec_box = ttk.LabelFrame(frame, text="解密 RLD -> BIN", padding=10)
        dec_box.pack(fill="x", pady=(0, 10))

        self._add_path_row(dec_box, "RLD 文件夹：", self.dec_rld_dir_var, 0, choose="dir")
        self._add_path_row(dec_box, "输出 BIN 文件夹：", self.dec_out_dir_var, 1, choose="dir")
        self._add_path_row(dec_box, "key.bin：", self.dec_key_var, 2, choose="file", filetypes=[("BIN", "*.bin"), ("All Files", "*.*")])
        self._add_path_row(dec_box, "key_def.bin：", self.dec_key_def_var, 3, choose="file", filetypes=[("BIN", "*.bin"), ("All Files", "*.*")])

        xor_row = ttk.Frame(dec_box)
        xor_row.grid(row=4, column=0, columnspan=3, sticky="ew", pady=5)
        ttk.Label(xor_row, text="XOR Key (Hex): ").pack(side="left")
        ttk.Entry(xor_row, textvariable=self.xor_key_var, width=12).pack(side="left", padx=5)
        ttk.Label(xor_row, text="Def XOR Key (Hex): ").pack(side="left", padx=(10, 0))
        ttk.Entry(xor_row, textvariable=self.def_xor_key_var, width=12).pack(side="left", padx=5)

        dec_btns = ttk.Frame(dec_box)
        dec_btns.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Button(dec_btns, text="开始解密", command=self.start_decrypt).pack(side="left")
        ttk.Button(dec_btns, text="自动识别密钥", command=self.manual_detect_keys).pack(side="left", padx=8)

        enc_box = ttk.LabelFrame(frame, text="加密 BIN -> RLD", padding=10)
        enc_box.pack(fill="x")

        self._add_path_row(enc_box, "BIN 文件夹：", self.enc_rld_dir_var, 0, choose="dir")
        self._add_path_row(enc_box, "输出 RLD 文件夹：", self.enc_out_dir_var, 1, choose="dir")
        self._add_path_row(enc_box, "key.bin：", self.enc_key_var, 2, choose="file", filetypes=[("BIN", "*.bin"), ("All Files", "*.*")])
        self._add_path_row(enc_box, "key_def.bin：", self.enc_key_def_var, 3, choose="file", filetypes=[("BIN", "*.bin"), ("All Files", "*.*")])

        enc_btns = ttk.Frame(enc_box)
        enc_btns.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Button(enc_btns, text="开始加密", command=self.start_encrypt).pack(side="left")

        for box in (dec_box, enc_box):
            box.columnconfigure(1, weight=1)

    def _build_dump_inject_tab(self):
        frame = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(frame, text="步骤3：文本提取/回封")

        top_hint = ttk.Label(
            frame,
            text="文本流程：提取支持普通/全量反汇编两种格式；回封也同时兼容这两种 txt 格式",
        )
        top_hint.pack(anchor="w", pady=(0, 8))

        notebook = ttk.Notebook(frame)
        notebook.pack(fill="both", expand=True)

        dump_frame = ttk.Frame(notebook, padding=10)
        inject_frame = ttk.Frame(notebook, padding=10)
        notebook.add(dump_frame, text="提取 Dump")
        notebook.add(inject_frame, text="回封 Inject")

        self.dump_in_var = tk.StringVar()
        self.dump_out_var = tk.StringVar()
        self.dump_enc_var = tk.StringVar(value="cp932")

        self.inj_bin_var = tk.StringVar()
        self.inj_txt_var = tk.StringVar()
        self.inj_out_var = tk.StringVar()
        self.inj_enc_var = tk.StringVar(value="gbk")

        self._add_path_row(dump_frame, "输入 BIN 文件夹：", self.dump_in_var, 0, choose="dir")
        self._add_path_row(dump_frame, "输出 TXT 文件夹：", self.dump_out_var, 1, choose="dir")

        ttk.Label(dump_frame, text="原Bin编码：").grid(row=2, column=0, sticky="e", padx=5, pady=8)
        ttk.Combobox(dump_frame, textvariable=self.dump_enc_var, values=["cp932", "utf-8", "gbk"], width=12).grid(
            row=2, column=1, sticky="w", pady=8
        )

        dump_btns = ttk.Frame(dump_frame)
        dump_btns.grid(row=3, column=0, columnspan=3, sticky="ew", pady=10)
        ttk.Button(dump_btns, text="开始提取", command=self.start_dump).pack(side="left")
        ttk.Button(dump_btns, text="全量反汇编", command=self.start_full_disasm).pack(side="left", padx=8)

        self._add_path_row(inject_frame, "原 BIN 文件夹：", self.inj_bin_var, 0, choose="dir")
        self._add_path_row(inject_frame, "翻译 TXT 文件夹：", self.inj_txt_var, 1, choose="dir")
        self._add_path_row(inject_frame, "输出 BIN 文件夹：", self.inj_out_var, 2, choose="dir")

        ttk.Label(inject_frame, text="目标Bin编码：").grid(row=3, column=0, sticky="e", padx=5, pady=8)
        ttk.Combobox(inject_frame, textvariable=self.inj_enc_var, values=["gbk", "utf-8", "cp932"], width=12).grid(
            row=3, column=1, sticky="w", pady=8
        )

        inject_btns = ttk.Frame(inject_frame)
        inject_btns.grid(row=4, column=0, columnspan=3, sticky="ew", pady=10)
        ttk.Button(inject_btns, text="普通回封", command=self.start_inject).pack(side="left")
        ttk.Button(inject_btns, text="全量反汇编回封", command=self.start_inject).pack(side="left", padx=8)

        dump_frame.columnconfigure(1, weight=1)
        inject_frame.columnconfigure(1, weight=1)

    def _add_path_row(self, parent, label_text, variable, row, choose="dir", filetypes=None):
        ttk.Label(parent, text=label_text).grid(row=row, column=0, sticky="e", padx=5, pady=6)
        entry = ttk.Entry(parent, textvariable=variable)
        entry.grid(row=row, column=1, sticky="ew", padx=5, pady=6)

        if choose == "file":
            ttk.Button(
                parent,
                text="浏览",
                command=lambda: self._browse_file(variable, filetypes),
            ).grid(row=row, column=2, padx=5, pady=6)
        else:
            ttk.Button(
                parent,
                text="浏览",
                command=lambda: self._browse_dir(variable),
            ).grid(row=row, column=2, padx=5, pady=6)

        if HAS_DND:
            entry.drop_target_register(DND_FILES)
            entry.dnd_bind("<<Drop>>", lambda e, var=variable: self._on_drop_to_var(e, var))

    def _browse_file(self, variable, filetypes=None):
        path = filedialog.askopenfilename(filetypes=filetypes or [("All Files", "*.*")])
        if path:
            variable.set(path)

    def _browse_dir(self, variable):
        path = filedialog.askdirectory()
        if path:
            variable.set(path)

    def _on_drop_to_var(self, event, variable):
        try:
            paths = self.tk.splitlist(event.data)
            if paths:
                variable.set(paths[0].strip("{}"))
        except Exception:
            variable.set(event.data.strip("{}"))

    def log(self, message):
        self.after(0, self._append_log, message)

    def _append_log(self, message):
        self.log_text.insert("end", str(message).rstrip() + "\n")
        self.log_text.see("end")

    def _poll_log_queue(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self._append_log(msg)
        except queue.Empty:
            pass
        self.after(120, self._poll_log_queue)

    def set_status(self, text):
        self.after(0, lambda: self.status_var.set(text))

    def refresh_env_text(self):
        loader_state = "存在" if self.loader_path.exists() else "缺失"
        dll_state = "存在" if self.dll_path.exists() else "缺失"
        text = (
            f"项目目录: {self.base_dir}\n"
            f"Loader.exe: {self.loader_path} [{loader_state}]\n"
            f"KeyFinder.dll: {self.dll_path} [{dll_state}]\n"
            "说明：此页用于启动原 KeyFinder 逻辑提取 key.bin / key_def.bin"
        )
        self.env_text.config(state="normal")
        self.env_text.delete("1.0", "end")
        self.env_text.insert("1.0", text)
        self.env_text.config(state="disabled")
        self.status_var.set("环境检查已刷新")

    def open_work_dir(self):
        exe_path = self.game_exe_var.get().strip()
        if not exe_path:
            messagebox.showwarning("提示", "请先选择游戏 EXE。")
            return
        target = Path(exe_path).parent
        if not target.exists():
            messagebox.showerror("错误", "游戏目录不存在。")
            return
        os.startfile(str(target))

    def start_game_normal(self):
        game_exe = self.game_exe_var.get().strip()
        ok, msg = self.kf_manager.start_game_normal(game_exe)
        if not ok:
            if "请先选择" in msg:
                messagebox.showwarning("提示", msg)
            else:
                messagebox.showerror("错误", msg)

    def clean_game_key_files(self):
        game_exe = self.game_exe_var.get().strip()
        ok, msg = self.kf_manager.clean_game_key_files(game_exe)
        if not ok:
            messagebox.showwarning("提示", msg)

    def start_loader(self):
        game_exe = self.game_exe_var.get().strip()

        if not self.loader_path.exists():
            messagebox.showerror("错误", "未找到 Loader.exe")
            return
        if not self.dll_path.exists():
            messagebox.showerror("错误", "未找到 KeyFinder.dll")
            return
        if not game_exe:
            messagebox.showwarning("提示", "请选择游戏 EXE")
            return
        exe_p = Path(game_exe)
        if not exe_p.exists():
            messagebox.showerror("错误", "游戏 EXE 不存在")
            return
        
        work_dir = str(exe_p.parent)

        command = [str(self.loader_path), "-exe", game_exe]
        self.log("=" * 60)
        self.log(f"启动命令: {' '.join(command)}")
        self.log(f"自动识别工作目录: {work_dir}")
        self.set_status("正在启动 KeyFinder...")

        threading.Thread(
            target=self.kf_manager.watch_key_files,
            args=(Path(work_dir), self._get_process, self._set_main_xor, self._set_def_xor, self._auto_fill_paths_cb),
            daemon=True,
        ).start()

        threading.Thread(
            target=self.kf_manager.run_loader_process,
            args=(command, work_dir, Path(work_dir), self._set_main_xor, self._set_def_xor, self._auto_fill_paths_cb),
            daemon=True,
        ).start()

    def manual_detect_keys(self):
        game_exe = self.game_exe_var.get().strip()
        game_dir = Path(game_exe).parent if game_exe else self.base_dir
        self.kf_manager.post_process_keys(game_dir, self._set_main_xor, self._set_def_xor, self._auto_fill_paths_cb)

    def _set_main_xor(self, main_xor):
        def update():
            if self.xor_key_var.get() != main_xor:
                self.xor_key_var.set(main_xor)
                self.log(f"已从 key.txt 读取 XOR Key: 0x{main_xor}")
        self.after(0, update)

    def _set_def_xor(self, def_xor):
        def update():
            if self.def_xor_key_var.get() != def_xor:
                self.def_xor_key_var.set(def_xor)
                self.log(f"已从 key_def.txt 读取 Def XOR Key: 0x{def_xor}")
        self.after(0, update)

    def _auto_fill_paths_cb(self, game_dir):
        self.after(0, lambda: self._auto_fill_paths(game_dir))

    def _auto_fill_paths(self, game_dir):
        rld_dir = self.base_dir / "rld"
        bin_dec_dir = self.base_dir / "bin_dec"
        txt_dir = self.base_dir / "txt"
        rld_chs_dir = self.base_dir / "rld_chs"
        rld_enc_dir = self.base_dir / "rld_enc"

        self.dec_rld_dir_var.set(str(rld_dir))
        self.dec_out_dir_var.set(str(bin_dec_dir))
        self.dec_key_var.set(str(self.base_dir / "key.bin"))
        self.dec_key_def_var.set(str(self.base_dir / "key_def.bin"))

        self.dump_in_var.set(str(bin_dec_dir))
        self.dump_out_var.set(str(txt_dir))

        self.inj_bin_var.set(str(bin_dec_dir))
        self.inj_txt_var.set(str(txt_dir))
        self.inj_out_var.set(str(rld_chs_dir))

        self.enc_rld_dir_var.set(str(rld_chs_dir))
        self.enc_out_dir_var.set(str(rld_enc_dir))
        self.enc_key_var.set(str(self.base_dir / "key.bin"))
        self.enc_key_def_var.set(str(self.base_dir / "key_def.bin"))

        self.log("已自动填充步骤2/3/4路径（使用工具目录）。")

    def start_decrypt(self):
        rld_dir = self.dec_rld_dir_var.get().strip()
        out_dir = self.dec_out_dir_var.get().strip()
        key_bin = self.dec_key_var.get().strip()
        key_def_bin = self.dec_key_def_var.get().strip()

        try:
            xor_key = int(self.xor_key_var.get(), 16)
            def_xor_key = int(self.def_xor_key_var.get(), 16)
        except ValueError:
            messagebox.showerror("错误", "XOR Key 格式错误（需为16进制字符串）")
            return

        if not rld_dir or not out_dir or not key_bin or not key_def_bin:
            messagebox.showerror("错误", "请填写完整的解密路径")
            return

        threading.Thread(
            target=decrypt_rld_folder,
            args=(Path(rld_dir), Path(out_dir), Path(key_bin), Path(key_def_bin), xor_key, def_xor_key, self.log, self.set_status),
            daemon=True,
        ).start()

    def start_encrypt(self):
        bin_dir = self.enc_rld_dir_var.get().strip()
        out_dir = self.enc_out_dir_var.get().strip()
        key_bin = self.enc_key_var.get().strip()
        key_def_bin = self.enc_key_def_var.get().strip()

        try:
            xor_key = int(self.xor_key_var.get(), 16)
            def_xor_key = int(self.def_xor_key_var.get(), 16)
        except ValueError:
            messagebox.showerror("错误", "XOR Key 格式错误（需为16进制字符串）")
            return

        if not bin_dir or not out_dir or not key_bin or not key_def_bin:
            messagebox.showerror("错误", "请填写完整的加密路径")
            return

        threading.Thread(
            target=encrypt_rld_folder,
            args=(Path(bin_dir), Path(out_dir), Path(key_bin), Path(key_def_bin), xor_key, def_xor_key, self.log, self.set_status),
            daemon=True,
        ).start()

    def start_dump(self):
        in_dir = self.dump_in_var.get().strip()
        out_dir = self.dump_out_var.get().strip()
        encoding = self.dump_enc_var.get().strip()

        if not in_dir or not out_dir:
            messagebox.showerror("错误", "请填写完整的提取路径")
            return

        threading.Thread(
            target=process_dump,
            args=(Path(in_dir), Path(out_dir), encoding, self.log, self.set_status),
            daemon=True,
        ).start()

    def start_full_disasm(self):
        in_dir = self.dump_in_var.get().strip()
        out_dir = self.dump_out_var.get().strip()
        encoding = self.dump_enc_var.get().strip()

        if not in_dir or not out_dir:
            messagebox.showerror("错误", "请填写完整的反汇编路径")
            return

        threading.Thread(
            target=process_full_disasm,
            args=(Path(in_dir), Path(out_dir), encoding, self.log, self.set_status),
            daemon=True,
        ).start()

    def start_inject(self):
        bin_dir = self.inj_bin_var.get().strip()
        txt_dir = self.inj_txt_var.get().strip()
        out_dir = self.inj_out_var.get().strip()
        encoding = self.inj_enc_var.get().strip()

        if not bin_dir or not txt_dir or not out_dir:
            messagebox.showerror("错误", "请填写完整的回封路径")
            return

        threading.Thread(
            target=process_inject,
            args=(Path(bin_dir), Path(txt_dir), Path(out_dir), encoding, self.log, self.set_status),
            daemon=True,
        ).start()

    def run(self):
        self.mainloop()


if __name__ == "__main__":
    app = ExHIBITAllInOneGUI()
    app.run()