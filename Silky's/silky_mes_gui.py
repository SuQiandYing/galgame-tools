import os
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from silky_mes import SilkyMesScript

# Attempt to import drag and drop support
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False

# Global Styling
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class CTkDnD(ctk.CTk, TkinterDnD.DnDWrapper):
    """CTk with tkinterdnd2 support."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.TkdndVersion = TkinterDnD._require(self)

if not HAS_DND:
    CTkDnD = ctk.CTk  # fallback

class SilkyMesGUI(CTkDnD):
    def __init__(self):
        super().__init__()

        # --- DnD Engine Initialization ---
        self.dnd_enabled = False
        if HAS_DND:
            try:
                self.drop_target_register(DND_FILES)
                self.dnd_bind('<<Drop>>', self.on_drop)
                self.dnd_enabled = True
            except Exception as e:
                print(f"DnD Initialization failed: {e}")

        # --- Professional UI Configuration ---
        self.title("Silky Mes 汉化工具箱 Pro")
        self.geometry("1120x840")
        
        # Color Palette (Fluent / iOS Inspiration)
        self.accent = "#007AFF" 
        self.success = "#28CD41"
        self.sidebar_color = ("#F2F2F7", "#1C1C1E")
        self.card_color = ("#FFFFFF", "#2C2C2E")
        self.border_color = ("#D1D1D6", "#3A3A3C")
        self.text_main = ("#000000", "#FFFFFF")
        self.text_sub = ("#8E8E93", "#98989D")

        # Application State
        self.mes_path = tk.StringVar()
        self.txt_path = tk.StringVar()
        self.batch_mes_dir = tk.StringVar()
        self.batch_txt_dir = tk.StringVar()
        self.diss_enc = tk.StringVar(value="cp932")
        self.asm_enc = tk.StringVar(value="GBK")
        self.current_tab = "single"

        self._init_layout()
        self.log("🚀 系统核心已就绪。")
        if self.dnd_enabled:
            self.log("✨ 智能拖拽引擎已启动。")
        else:
            self.log("💡 提示: 未检测到 tkinterdnd2，请手动选择文件。")

    def _init_layout(self):
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- 1. Sidebar Navigation ---
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color=self.sidebar_bg_logic(), border_width=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(10, weight=1)

        # Header
        ctk.CTkLabel(self.sidebar, text="SILKY", font=ctk.CTkFont(size=28, weight="bold"), text_color=self.accent).grid(row=0, column=0, pady=(40, 5))
        ctk.CTkLabel(self.sidebar, text="汉化流水线 Pro", font=ctk.CTkFont(size=12), text_color=self.text_sub).grid(row=1, column=0, pady=(0, 40))

        # Navigation
        self.nav_btns = {}
        self.nav_btns["single"] = self._create_nav_btn("📄 单文件处理", "single", 2)
        self.nav_btns["batch"] = self._create_nav_btn("📂 批量任务模式", "batch", 3)

        # Settings Section
        ctk.CTkLabel(self.sidebar, text="参数配置", font=ctk.CTkFont(size=11, weight="bold"), text_color=self.text_sub).grid(row=4, column=0, padx=30, pady=(40, 10), sticky="w")
        self._add_sidebar_opt("解包编码", self.diss_enc, ["cp932", "GBK", "utf-8"], 5)
        self._add_sidebar_opt("回封编码", self.asm_enc, ["GBK", "cp932", "utf-8"], 7)

        # Theme
        ctk.CTkOptionMenu(self.sidebar, values=["System", "Dark", "Light"], command=ctk.set_appearance_mode, 
                          height=32, fg_color=self.card_color, text_color=self.text_main, button_color=self.accent).grid(row=11, column=0, padx=20, pady=30)

        # --- 2. Main Content Area ---
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.grid(row=0, column=1, sticky="nsew", padx=40, pady=40)
        self.container.grid_columnconfigure(0, weight=1)

        # Card: Path Selection
        self.path_card = self._create_card("资源路径管理", 0)
        self.path_inner = ctk.CTkFrame(self.path_card, fg_color="transparent")
        self.path_inner.pack(fill="x", padx=20, pady=10)
        self._render_path_inputs()

        # Card: Operations
        self.op_card = self._create_card("流程化操作", 1)
        self._setup_action_grid(self.op_card)

        # Card: Console
        self.log_card = self._create_card("实时处理状态", 2)
        self.log_box = ctk.CTkTextbox(self.log_card, font=ctk.CTkFont(family="Consolas", size=13),
                                     fg_color=("#F9F9F9", "#151515"), border_width=1, border_color=self.border_color,
                                     text_color=("#333", "#00FF66"))
        self.log_box.pack(padx=20, pady=(5, 20), fill="both", expand=True)
        self.log_box.configure(state="disabled")

        self.select_tab("single")

    def sidebar_bg_logic(self):
        return self.sidebar_color

    def _create_card(self, title, row):
        f = ctk.CTkFrame(self.container, fg_color=self.card_color, corner_radius=16, border_width=1, border_color=self.border_color)
        f.grid(row=row, column=0, sticky="nsew", pady=(0, 25))
        ctk.CTkLabel(f, text=title, font=ctk.CTkFont(size=14, weight="bold"), text_color=self.accent).pack(anchor="w", padx=20, pady=(15, 5))
        return f

    def _create_nav_btn(self, text, tid, row):
        b = ctk.CTkButton(self.sidebar, text=text, anchor="w", height=48, corner_radius=12,
                          fg_color="transparent", text_color=self.text_main,
                          hover_color=("gray85", "gray25"), command=lambda: self.select_tab(tid))
        b.grid(row=row, column=0, padx=15, pady=4, sticky="ew")
        return b

    def _add_sidebar_opt(self, label, var, opts, row):
        ctk.CTkLabel(self.sidebar, text=label, font=ctk.CTkFont(size=11)).grid(row=row, column=0, padx=30, sticky="w")
        ctk.CTkOptionMenu(self.sidebar, values=opts, variable=var, height=34, corner_radius=8,
                          fg_color=self.card_color, text_color=self.text_main, button_color=self.accent).grid(row=row+1, column=0, padx=20, pady=(2, 12), sticky="ew")

    def select_tab(self, tid):
        self.current_tab = tid
        for k, b in self.nav_btns.items():
            b.configure(fg_color=self.accent if k == tid else "transparent",
                        text_color="#FFFFFF" if k == tid else self.text_main)
        self._render_path_inputs()

    def _render_path_inputs(self):
        for w in self.path_inner.winfo_children(): w.destroy()
        self.path_inner.grid_columnconfigure(1, weight=1)
        if self.current_tab == "single":
            self._add_path_row("MES 脚本", self.mes_path, self.browse_mes_file, 0)
            self._add_path_row("TXT 导出", self.txt_path, self.browse_txt_file, 1)
        else:
            self._add_path_row("MES 目录", self.batch_mes_dir, self.browse_mes_dir, 0)
            self._add_path_row("TXT 目录", self.batch_txt_dir, self.browse_txt_dir, 1)

    def _add_path_row(self, label, var, cmd, row):
        ctk.CTkLabel(self.path_inner, text=label, font=ctk.CTkFont(size=12, weight="bold")).grid(row=row, column=0, padx=(0, 15), pady=12, sticky="e")
        entry = ctk.CTkEntry(self.path_inner, textvariable=var, height=40, corner_radius=10, border_width=1,
                             placeholder_text="拖拽文件到此处或点击[选择]")
        entry.grid(row=row, column=1, sticky="ew")
        ctk.CTkButton(self.path_inner, text="选择", width=85, height=36, corner_radius=8, fg_color=self.accent, command=cmd).grid(row=row, column=2, padx=(15, 0))
        # Per-entry drag and drop
        if self.dnd_enabled:
            inner_entry = entry._entry  # access underlying tk.Entry
            inner_entry.drop_target_register(DND_FILES)
            inner_entry.dnd_bind('<<Drop>>', lambda e, v=var, lbl=label: self._on_entry_drop(e, v, lbl))

    def _on_entry_drop(self, event, var, label):
        path = event.data.strip('{}').strip('"')
        var.set(os.path.normpath(path))
        self.log(f"📥 [{label}] 已拖入: {os.path.basename(path)}")
        # Auto-fill TXT path when dropping MES file
        if path.lower().endswith(".mes") and "MES" in label:
            self.txt_path.set(os.path.splitext(path)[0] + ".txt")

    def _setup_action_grid(self, parent):
        grid = ctk.CTkFrame(parent, fg_color="transparent")
        grid.pack(fill="x", padx=20, pady=10)
        grid.grid_columnconfigure((0,1,2,3), weight=1)
        
        ops = [("解包脚本", "Unpack", self.run_disassemble, 0),
               ("提取文本", "Extract", self.run_extract, 1),
               ("导入翻译", "Import", self.run_import, 2),
               ("回封脚本", "Repack", self.run_assemble, 3)]
        
        for t, s, c, col in ops:
            ctk.CTkButton(grid, text=f"{t}\n{s}", font=ctk.CTkFont(size=13, weight="bold"), height=90, corner_radius=14,
                          fg_color=("#F2F2F7", "#3A3A3C"), text_color=self.text_main, hover_color=("#E5E5EA", "#48484A"),
                          command=c).grid(row=0, column=col, padx=8, pady=10, sticky="nsew")

        ctk.CTkButton(parent, text="✦ 一键智能导入并回封 ✦", font=ctk.CTkFont(size=16, weight="bold"), height=64, corner_radius=16,
                      fg_color=self.success, hover_color="#24B53A", command=self.run_full_repack).pack(fill="x", padx=30, pady=(15, 25))

    # --- Core Handlers ---
    def log(self, msg):
        now = time.strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{now}] {msg}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def on_drop(self, event):
        path = event.data.strip('{}').strip('"')
        if os.path.isdir(path):
            self.select_tab("batch")
            self.batch_mes_dir.set(os.path.normpath(path))
            self.log(f"📥 自动载入目录: {os.path.basename(path)}")
        elif os.path.isfile(path):
            self.select_tab("single")
            if path.lower().endswith(".mes"):
                self.mes_path.set(os.path.normpath(path))
                self.txt_path.set(os.path.splitext(path)[0] + ".txt")
                self.log(f"📥 自动识别脚本: {os.path.basename(path)}")
            elif path.lower().endswith(".txt"):
                self.txt_path.set(os.path.normpath(path))
                self.log(f"📥 自动识别文本: {os.path.basename(path)}")

    # --- Worker Launchers ---
    def browse_mes_file(self):
        p = filedialog.askopenfilename(filetypes=[("MES", "*.mes")])
        if p: self.mes_path.set(os.path.normpath(p)); self.txt_path.set(os.path.splitext(p)[0] + ".txt")

    def browse_txt_file(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt")
        if p: self.txt_path.set(os.path.normpath(p))

    def browse_mes_dir(self):
        p = filedialog.askdirectory()
        if p: self.batch_mes_dir.set(os.path.normpath(p))

    def browse_txt_dir(self):
        p = filedialog.askdirectory()
        if p: self.batch_txt_dir.set(os.path.normpath(p))

    def get_ctx(self):
        if self.current_tab == "single":
            m, t = self.mes_path.get(), self.txt_path.get()
            if not m or not t: return None
            return os.path.abspath(m), os.path.abspath(t), True
        m, t = self.batch_mes_dir.get(), self.batch_txt_dir.get()
        if not m: return None
        return os.path.abspath(m), os.path.abspath(t or m), False

    def run_disassemble(self):
        ctx = self.get_ctx()
        if ctx: threading.Thread(target=self._do_diss, args=ctx, daemon=True).start()
    def run_extract(self):
        ctx = self.get_ctx()
        if ctx: threading.Thread(target=self._do_ext, args=(ctx[1], ctx[2]), daemon=True).start()
    def run_import(self):
        ctx = self.get_ctx()
        if ctx: threading.Thread(target=self._do_imp, args=(ctx[1], ctx[2]), daemon=True).start()
    def run_assemble(self):
        ctx = self.get_ctx()
        if ctx: threading.Thread(target=self._do_asm, args=ctx, daemon=True).start()
    def run_full_repack(self):
        ctx = self.get_ctx()
        if ctx: threading.Thread(target=self._do_auto, args=ctx, daemon=True).start()

    # --- Actual Workers ---
    def _do_diss(self, m, t, s):
        try:
            self.log("▶ 开始解包任务...")
            if s: SilkyMesScript(m, t, self.diss_enc.get()).disassemble(); self.log(f"✅ 完成: {os.path.basename(m)}")
            else:
                os.makedirs(t, exist_ok=True)
                for f in [x for x in os.listdir(m) if x.lower().endswith(".mes")]:
                    SilkyMesScript(os.path.join(m, f), os.path.join(t, f[:-4]+".txt"), self.diss_enc.get()).disassemble()
                    self.log(f"  - {f} [OK]")
        except Exception as e: self.log(f"❌ 失败: {e}")

    def _do_ext(self, t, s):
        try:
            self.log("▶ 正在提取原文...")
            if s: n = SilkyMesScript.extract_text(t, t[:-4]+"_text.txt"); self.log(f"✅ 提取 {n} 条 -> {os.path.basename(t)[:-4]}_text.txt")
            else:
                tot = 0
                for f in [x for x in os.listdir(t) if x.lower().endswith(".txt") and not x.endswith("_text.txt")]:
                    tot += SilkyMesScript.extract_text(os.path.join(t, f), os.path.join(t, f[:-4]+"_text.txt"))
                self.log(f"✅ 批量提取完成: {tot} 条")
        except Exception as e: self.log(f"❌ 失败: {e}")

    def _do_imp(self, t, s):
        try:
            self.log("▶ 正在导入翻译...")
            if s:
                tf = t[:-4]+"_text.txt"
                if os.path.exists(tf): n = SilkyMesScript.import_text(t, tf, t); self.log(f"✅ 导入 {n} 条")
                else: self.log("⚠️ 错误: 找不到翻译文本文件")
            else:
                for f in [x for x in os.listdir(t) if x.lower().endswith("_text.txt")]:
                    orig = os.path.join(t, f.replace("_text.txt", ".txt"))
                    if os.path.exists(orig): SilkyMesScript.import_text(orig, os.path.join(t, f), orig)
                self.log("✅ 批量导入完成")
        except Exception as e: self.log(f"❌ 失败: {e}")

    def _do_asm(self, m, t, s):
        try:
            self.log("▶ 开始汇编封包...")
            if s: SilkyMesScript(m, t, self.asm_enc.get()).assemble(); self.log(f"✅ 完成: {os.path.basename(m)}")
            else:
                for f in [x for x in os.listdir(t) if x.lower().endswith(".txt") and not x.endswith("_text.txt") and not x.endswith("_opcode.txt")]:
                    SilkyMesScript(os.path.join(m, f[:-4]+".MES"), os.path.join(t, f), self.asm_enc.get()).assemble()
                    self.log(f"  - {f} [OK]")
        except Exception as e: self.log(f"❌ 失败: {e}")

    def _do_auto(self, m, t, s):
        try: self._do_imp(t, s); time.sleep(0.5); self._do_asm(m, t, s); self.log("✨ 全自动流程顺利结束！")
        except Exception as e: self.log(f"❌ 中断: {e}")

if __name__ == "__main__":
    app = SilkyMesGUI()
    app.mainloop()
