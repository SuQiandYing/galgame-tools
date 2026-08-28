#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import queue
import sys
import threading
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from daclocalizer.dpk import unpack_dpk, repack_dpk
from daclocalizer.pipeline import (
    disasm_project,
    export_asm_project,
    export_text_project,
    import_and_repack,
    smoke_roundtrip,
    verify_project,
)

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD  # optional
    TK_BASE = TkinterDnD.Tk
    HAS_DND = True
except Exception:
    import tkinter as tk
    TK_BASE = tk.Tk
    DND_FILES = None
    HAS_DND = False

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

ENCODINGS = ["cp932", "shift_jis", "utf-8", "utf-8-sig", "gbk", "gb18030", "big5", "latin1"]


class App(TK_BASE):
    def __init__(self):
        super().__init__()
        self.title("DacDpkLocalizer")
        self.geometry("1040x720")
        self.q: queue.Queue[str] = queue.Queue()
        self.input_dpk = tk.StringVar()
        self.workspace = tk.StringVar(value=str(ROOT / "workspace"))
        self.dsat = tk.StringVar()
        self.output_dpk = tk.StringVar()
        self.encoding = tk.StringVar(value="cp932")
        self.allow_lengthen = tk.BooleanVar(value=True)
        self._build_ui()
        self.after(100, self._pump)
        if len(sys.argv) > 1:
            self._accept_path(Path(sys.argv[1]))

    def _build_ui(self):
        pad = {"padx": 8, "pady": 5}
        settings = ttk.LabelFrame(self, text="路径设置")
        settings.pack(fill="x", **pad)
        self._row(settings, "输入DPK", self.input_dpk, self.choose_dpk)
        self._row(settings, "工作区", self.workspace, self.choose_workspace_dir)
        self._row(settings, "文本目录/文件", self.dsat, self.choose_dsat)
        self._row(settings, "输出DPK", self.output_dpk, self.choose_output_dpk)
        r = ttk.Frame(settings); r.pack(fill="x", padx=8, pady=4)
        ttk.Label(r, text="脚本编码", width=14).pack(side="left")
        ttk.Combobox(r, textvariable=self.encoding, values=ENCODINGS, width=16).pack(side="left")
        ttk.Checkbutton(r, text="允许加长回封", variable=self.allow_lengthen).pack(side="left", padx=16)

        stages = ttk.LabelFrame(self, text="操作")
        stages.pack(fill="x", **pad)
        grid = ttk.Frame(stages); grid.pack(fill="x", padx=8, pady=8)
        buttons = [
            ("解包DPK", self.do_unpack_dpk),
            ("回封解包目录", self.do_repack_unpacked),
            ("生成IR", self.do_disasm),
            ("生成ASM", self.do_export_asm),
            ("导出文本", self.do_export_text),
            ("导入文本并回封", self.do_import_repack),
            ("验证", self.do_verify),
            ("零编辑测试", self.do_smoke),
        ]
        for i, (text, cmd) in enumerate(buttons):
            ttk.Button(grid, text=text, command=cmd).grid(row=i//4, column=i%4, padx=6, pady=6, sticky="ew")
        for c in range(4):
            grid.columnconfigure(c, weight=1)

        tools = ttk.Frame(self); tools.pack(fill="x", **pad)
        ttk.Button(tools, text="打开解包目录", command=lambda: self.open_path(Path(self.workspace.get()) / "unpack")).pack(side="left", padx=4)
        ttk.Button(tools, text="打开文本目录", command=lambda: self.open_path(Path(self.workspace.get()) / "texts" / "by_source")).pack(side="left", padx=4)
        ttk.Button(tools, text="打开ASM目录", command=lambda: self.open_path(Path(self.workspace.get()) / "asm" / "by_source")).pack(side="left", padx=4)
        ttk.Button(tools, text="打开报告目录", command=lambda: self.open_path(Path(self.workspace.get()) / "reports")).pack(side="left", padx=4)

        hint = "可拖入DPK或工作区" if HAS_DND else "可拖到 run_gui.py，或用选择按钮"
        ttk.Label(self, text=hint + "。普通素材包用“解包DPK/回封解包目录”；脚本包用“生成IR→导出文本→导入文本并回封”。").pack(fill="x", padx=10)

        self.log = tk.Text(self, height=24, wrap="word")
        self.log.pack(fill="both", expand=True, padx=8, pady=8)
        if HAS_DND:
            self.drop_target_register(DND_FILES)
            self.dnd_bind("<<Drop>>", self.on_drop)

    def _row(self, parent, label, var, chooser):
        row = ttk.Frame(parent); row.pack(fill="x", padx=8, pady=4)
        ttk.Label(row, text=label, width=14).pack(side="left")
        ttk.Entry(row, textvariable=var).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="选择", command=chooser).pack(side="left", padx=4)

    def _accept_path(self, p: Path):
        if p.suffix.lower() == ".dpk":
            self.input_dpk.set(str(p))
            ws = p.with_name(p.stem + "_workspace")
            self.workspace.set(str(ws))
            self.dsat.set(str(ws / "texts" / "by_source"))
            self.output_dpk.set(str(ws / "rebuilt" / f"{p.stem}_patched.dpk"))
        elif p.suffix.lower() == ".txt":
            self.dsat.set(str(p))
        elif p.is_dir():
            self.workspace.set(str(p))
            maybe = p / "texts" / "by_source"
            if maybe.exists():
                self.dsat.set(str(maybe))
            if not self.output_dpk.get():
                self.output_dpk.set(str(p / "rebuilt" / "patched.dpk"))

    def on_drop(self, event):
        raw = event.data.strip()
        if raw.startswith("{") and raw.endswith("}"):
            raw = raw[1:-1]
        self._accept_path(Path(raw))

    def choose_dpk(self):
        p = filedialog.askopenfilename(filetypes=[("DPK archive", "*.dpk"), ("All", "*.*")])
        if p:
            self._accept_path(Path(p))

    def choose_workspace_dir(self):
        p = filedialog.askdirectory()
        if p:
            self._accept_path(Path(p))

    def choose_dsat(self):
        p = filedialog.askdirectory(title="选择文本目录")
        if not p:
            p = filedialog.askopenfilename(filetypes=[("DSAT text", "*.txt"), ("All", "*.*")])
        if p:
            self.dsat.set(p)

    def choose_output_dpk(self):
        p = filedialog.asksaveasfilename(defaultextension=".dpk", filetypes=[("DPK archive", "*.dpk"), ("All", "*.*")])
        if p:
            self.output_dpk.set(p)

    def open_path(self, path: Path):
        path.mkdir(parents=True, exist_ok=True)
        import os, subprocess, platform
        if platform.system() == "Windows":
            os.startfile(path)  # type: ignore[attr-defined]
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])

    def _run(self, name, fn):
        def worker():
            try:
                self.q.put(f"\n[RUN] {name}\n")
                msg = fn()
                self.q.put(f"[OK] {name}\n{msg}\n")
            except Exception:
                self.q.put("[FAIL]\n" + traceback.format_exc() + "\n")
        threading.Thread(target=worker, daemon=True).start()

    def _need(self, *items: tuple[str, str]) -> bool:
        missing = [name for name, value in items if not value]
        if missing:
            messagebox.showerror("缺少参数", "、".join(missing))
            return False
        return True

    def do_unpack_dpk(self):
        if not self._need(("输入DPK", self.input_dpk.get()), ("工作区", self.workspace.get())):
            return
        def task():
            out = Path(self.workspace.get()) / "unpack"
            res = unpack_dpk(Path(self.input_dpk.get()), out)
            return f"文件数: {len(res['files'])}\n输出: {out}"
        self._run("解包DPK", task)

    def do_repack_unpacked(self):
        if not self._need(("工作区", self.workspace.get()), ("输出DPK", self.output_dpk.get())):
            return
        def task():
            extract = Path(self.workspace.get()) / "unpack"
            res = repack_dpk(extract, Path(self.output_dpk.get()))
            return f"文件数: {res['file_count']}\n输出: {res['output']}\nSHA256: {res['checksums']['sha256']}"
        self._run("回封解包目录", task)

    def do_disasm(self):
        if not self._need(("输入DPK", self.input_dpk.get()), ("工作区", self.workspace.get())):
            return
        def task():
            res = disasm_project(Path(self.input_dpk.get()), Path(self.workspace.get()), self.encoding.get(), clean=True)
            scripts = len(res.get("scripts", []))
            text_entries = res.get("total_text_entries", 0)
            msg = f"文件数: {res['dpk']['file_count']}\n脚本数: {scripts}\n文本条目: {text_entries}\n输出: {self.workspace.get()}"
            if scripts == 0:
                msg += "\n提示: 这个DPK没有可识别脚本。素材包请用“解包DPK”。"
            return msg
        self._run("生成IR", task)
        self.dsat.set(str(Path(self.workspace.get()) / "texts" / "by_source"))
        if not self.output_dpk.get():
            stem = Path(self.input_dpk.get()).stem if self.input_dpk.get() else "patched"
            self.output_dpk.set(str(Path(self.workspace.get()) / "rebuilt" / f"{stem}_patched.dpk"))

    def do_export_asm(self):
        self._run("生成ASM", lambda: self._fmt(export_asm_project(Path(self.workspace.get())), {"asm_files": "ASM文件", "out": "输出"}))

    def do_export_text(self):
        def task():
            res = export_text_project(Path(self.workspace.get()))
            self.dsat.set(str(Path(self.workspace.get()) / "texts" / "by_source"))
            return f"文本条目: {res['text_entries']}\n文本文件: {res['dsat_files']}\n输出: {res['out']}"
        self._run("导出文本", task)

    def do_import_repack(self):
        if not self._need(("工作区", self.workspace.get()), ("文本目录/文件", self.dsat.get()), ("输出DPK", self.output_dpk.get())):
            return
        def task():
            res = import_and_repack(Path(self.workspace.get()), Path(self.dsat.get()), Path(self.output_dpk.get()), self.encoding.get(), self.allow_lengthen.get())
            changed = res["patch_report"].get("entries_changed", 0)
            out = res["output_dpk"]
            sha = res["repack_report"]["checksums"]["sha256"]
            return f"改动条目: {changed}\n输出: {out}\nSHA256: {sha}"
        self._run("导入文本并回封", task)

    def do_verify(self):
        if not self._need(("输入DPK", self.input_dpk.get()), ("输出DPK", self.output_dpk.get())):
            return
        def task():
            ok = verify_project(Path(self.input_dpk.get()), Path(self.output_dpk.get()), Path(self.workspace.get()))
            return f"结果: {'一致' if ok else '不一致'}\n报告: {Path(self.workspace.get()) / 'reports' / 'verify_report.txt'}"
        self._run("验证", task)

    def do_smoke(self):
        if not self._need(("输入DPK", self.input_dpk.get())):
            return
        out = Path(self.workspace.get() or Path(self.input_dpk.get()).with_name("smoke")) / "_smoke"
        def task():
            res = smoke_roundtrip(Path(self.input_dpk.get()), out, self.encoding.get())
            return f"结果: {'一致' if res['ok'] else '不一致'}\n输出: {out}"
        self._run("零编辑测试", task)

    @staticmethod
    def _fmt(res: dict, labels: dict[str, str]) -> str:
        lines = []
        for k, name in labels.items():
            if k in res:
                lines.append(f"{name}: {res[k]}")
        return "\n".join(lines)

    def _pump(self):
        try:
            while True:
                msg = self.q.get_nowait()
                self.log.insert("end", msg)
                self.log.see("end")
        except queue.Empty:
            pass
        self.after(100, self._pump)


if __name__ == "__main__":
    App().mainloop()
