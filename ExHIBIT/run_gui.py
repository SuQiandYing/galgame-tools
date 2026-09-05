"""Two-button GUI for the ExHIBIT RLD text pipeline.

Built for someone who wants to translate a game, not inspect a VM. Decryption,
key recovery, IR construction, the coverage certificate and the zero-edit
self-check all run inside the two buttons; none of them gets a button of its
own, because none of them produces a file a translator can use.

Layout and wording only -- all binary work is delegated to disassembler.py /
assembler.py so the GUI and the CLI cannot diverge.
"""
from __future__ import annotations

import queue
import threading
import traceback
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    _BASE = TkinterDnD.Tk
    _HAS_DND = True
except Exception:            # dropping is a convenience, never a requirement
    _BASE = tk.Tk
    _HAS_DND = False
    DND_FILES = None

from opcodelist import DIALECT, TOOL_VERSION
import rldcore as core
import disassembler as dis
import assembler as asm

# gb18030 listed before gbk on purpose: the original Japanese text contains
# characters gbk cannot represent, so gbk rejects untouched lines.
ENCODINGS = ["cp932", "gb18030", "gbk", "big5", "cp949", "utf-8"]
FONT = ("Microsoft YaHei UI", 9)


class App(_BASE):
    def __init__(self):
        super().__init__()
        self.title(f"ExHIBIT RLD 翻译工具 {TOOL_VERSION}")
        self.geometry("760x660")
        self.minsize(720, 620)

        self.input_var = tk.StringVar()
        self.text_var = tk.StringVar()
        self.rebuild_var = tk.StringVar()
        self.from_var = tk.StringVar()
        self.src_enc = tk.StringVar(value=DIALECT["encodings"]["source"])
        self.dst_enc = tk.StringVar(value=DIALECT["encodings"]["target"])
        self.want_texts = tk.BooleanVar(value=True)
        self.want_asm = tk.BooleanVar(value=False)
        self.with_ir = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="把游戏的 rld 文件夹拖进来，或点「浏览」选择")
        self.found = tk.StringVar(value="")

        self._q = queue.Queue()
        self._busy = False
        self._cancel = threading.Event()
        self._from_touched = False
        self._detail_lines = []

        self._build()
        self.input_var.trace_add("write", lambda *a: self._on_input_change())
        self.text_var.trace_add("write", lambda *a: self._on_text_change())
        self.from_var.trace_add("write", lambda *a: None)
        self.after(120, self._drain)
        if not _HAS_DND:
            self._log("提示：未安装 tkinterdnd2，拖放不可用，请用「浏览」按钮"
                      "（pip install tkinterdnd2 可启用拖放）")

    # -- layout ----------------------------------------------------------
    def _build(self):
        root = ttk.Frame(self, padding=12)
        root.pack(fill="both", expand=True)

        box = ttk.LabelFrame(root, text=" 游戏脚本文件夹 ", padding=10)
        box.pack(fill="x")
        row = ttk.Frame(box)
        row.pack(fill="x")
        entry = ttk.Entry(row, textvariable=self.input_var, font=FONT)
        entry.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="浏览…", width=8,
                   command=self._pick_input).pack(side="left", padx=(6, 0))
        ttk.Label(box, textvariable=self.found, foreground="#0a6",
                  font=FONT).pack(anchor="w", pady=(4, 0))
        self._dnd(entry)
        self._dnd(box)

        enc = ttk.Frame(root)
        enc.pack(fill="x", pady=(10, 0))
        ttk.Label(enc, text="原文编码", font=FONT).pack(side="left")
        ttk.Combobox(enc, textvariable=self.src_enc, values=ENCODINGS,
                     width=10, font=FONT).pack(side="left", padx=(4, 16))
        ttk.Label(enc, text="译文编码", font=FONT).pack(side="left")
        ttk.Combobox(enc, textvariable=self.dst_enc, values=ENCODINGS,
                     width=10, font=FONT).pack(side="left", padx=4)

        out = ttk.LabelFrame(root, text=" 输 出 文 本 ", padding=10)
        out.pack(fill="x", pady=(12, 0))
        self._path_row(out, "到", self.text_var)
        opts = ttk.Frame(out)
        opts.pack(fill="x", pady=(6, 0))
        ttk.Checkbutton(opts, text="双行文本（翻译用）",
                        variable=self.want_texts,
                        command=self._sync_buttons).pack(side="left")
        ttk.Checkbutton(opts, text="ASM 清单（改逻辑用）",
                        variable=self.want_asm,
                        command=self._sync_buttons).pack(side="left", padx=16)
        self.btn_export = ttk.Button(out, text="输 出 文 本",
                                     command=self._do_export)
        self.btn_export.pack(fill="x", pady=(8, 0))

        rep = ttk.LabelFrame(root, text=" 回 封 文 本 ", padding=10)
        rep.pack(fill="x", pady=(12, 0))
        self._path_row(rep, "从", self.from_var, touched=True)
        self._path_row(rep, "到", self.rebuild_var)
        self.btn_repack = ttk.Button(rep, text="回 封 文 本",
                                     command=self._do_repack)
        self.btn_repack.pack(fill="x", pady=(8, 0))

        self.bar = ttk.Progressbar(root, mode="determinate")
        self.bar.pack(fill="x", pady=(12, 4))
        ttk.Label(root, textvariable=self.status, font=FONT,
                  wraplength=700, justify="left").pack(anchor="w")

        self.detail_btn = ttk.Button(root, text="▸ 详情",
                                     command=self._toggle_detail, width=10)
        self.detail_btn.pack(anchor="w", pady=(8, 0))
        self.detail = tk.Text(root, height=11, wrap="word", font=("Consolas", 9),
                              background="#f7f7f7", relief="flat")
        self._detail_open = False

    def _path_row(self, parent, label, var, touched=False):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text=label, width=3, font=FONT).pack(side="left")
        e = ttk.Entry(row, textvariable=var, font=FONT)
        e.pack(side="left", fill="x", expand=True)
        if touched:
            e.bind("<Key>", lambda ev: setattr(self, "_from_touched", True))
        ttk.Button(row, text="浏览…", width=8,
                   command=lambda: self._pick_dir(var)).pack(side="left",
                                                             padx=(6, 0))
        self._dnd(e)

    def _dnd(self, widget):
        if not _HAS_DND:
            return
        try:
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind("<<Drop>>", self._on_drop)
        except Exception:
            pass

    def _on_drop(self, event):
        paths = self.tk.splitlist(event.data)
        if paths:
            self.input_var.set(paths[0].strip("{}"))

    # -- path derivation -------------------------------------------------
    def _on_input_change(self):
        raw = self.input_var.get().strip()
        if not raw:
            self.found.set("")
            return
        p = Path(raw)
        base = p if p.is_dir() else p.parent
        # Defaults sit BESIDE the input, never inside it, so a second run
        # cannot mistake the previous run's output for new input.
        self.text_var.set(str(base.parent / (base.name + "_text")))
        self.rebuild_var.set(str(base.parent / (base.name + "_rebuilt")))
        self._from_touched = False
        self.from_var.set(self.text_var.get())
        try:
            n = len(dis.collect_sources([raw]))
        except Exception:
            n = 0
        self.found.set(f"已找到 {n} 个脚本文件" if n else "没有找到 .rld 文件")
        self._sync_buttons()

    def _on_text_change(self):
        if not self._from_touched:
            self.from_var.set(self.text_var.get())
        self._sync_buttons()

    def _sync_buttons(self):
        has_in = bool(self.input_var.get().strip())
        any_out = self.want_texts.get() or self.want_asm.get()
        self.btn_export.state(
            ["!disabled"] if (has_in and any_out and not self._busy)
            else ["disabled"])
        src = Path(self.from_var.get().strip() or ".")
        ready = (src / "texts").is_dir() or (src / "asm").is_dir() \
            or any(src.glob("*.txt")) if src.is_dir() else False
        self.btn_repack.state(
            ["!disabled"] if (has_in and ready and not self._busy)
            else ["disabled"])
        if has_in and not any_out:
            self.status.set("请至少选择一种输出")

    def _pick_input(self):
        d = filedialog.askdirectory(title="选择 rld 文件夹")
        if d:
            self.input_var.set(d)

    def _pick_dir(self, var):
        d = filedialog.askdirectory()
        if d:
            var.set(d)

    # -- logging ---------------------------------------------------------
    def _log(self, msg):
        self._q.put(("log", str(msg)))

    def _drain(self):
        try:
            while True:
                kind, payload = self._q.get_nowait()
                if kind == "log":
                    self._detail_lines.append(payload)
                    if self._detail_open:
                        self.detail.insert("end", payload + "\n")
                        self.detail.see("end")
                    self.status.set(payload)
                elif kind == "status":
                    self.status.set(payload)
                elif kind == "progress":
                    done, total = payload
                    self.bar.configure(maximum=max(total, 1), value=done)
                elif kind == "done":
                    self._busy = False
                    self._sync_buttons()
                elif kind == "error":
                    self._busy = False
                    self._sync_buttons()
                    messagebox.showerror("出错了", payload)
        except queue.Empty:
            pass
        self.after(120, self._drain)

    def _toggle_detail(self):
        self._detail_open = not self._detail_open
        if self._detail_open:
            self.detail.pack(fill="both", expand=True, pady=(6, 0))
            self.detail.delete("1.0", "end")
            self.detail.insert("1.0", "\n".join(self._detail_lines) + "\n")
            self.detail.see("end")
            self.detail_btn.configure(text="▾ 详情")
        else:
            self.detail.pack_forget()
            self.detail_btn.configure(text="▸ 详情")

    def _run(self, fn):
        if self._busy:
            return
        self._busy = True
        self._cancel.clear()
        self._sync_buttons()
        self.bar.configure(value=0)

        def worker():
            try:
                fn()
            except core.RldError as exc:
                self._q.put(("error", str(exc)))
                return
            except Exception:
                self._q.put(("error", traceback.format_exc(limit=3)))
                return
            self._q.put(("done", None))

        threading.Thread(target=worker, daemon=True).start()

    # -- actions ---------------------------------------------------------
    def _do_export(self):
        inputs = [self.input_var.get().strip()]
        out = Path(self.text_var.get().strip())
        want_t, want_a = self.want_texts.get(), self.want_asm.get()
        src, dst = self.src_enc.get().strip(), self.dst_enc.get().strip()
        with_ir = self.with_ir.get()
        if out.exists() and any(out.iterdir()):
            if not messagebox.askyesno(
                    "目录已有内容",
                    f"{out}\n\n已经存在内容，继续会覆盖同名文件。要继续吗？"):
                return

        def job():
            def progress(done, total, path):
                self._q.put(("progress", (done, total)))
                self._q.put(("status", f"正在处理 {path.name}  {done}/{total}"))
            rep = dis.export(inputs, out, want_texts=want_t, want_asm=want_a,
                             source_encoding=src, target_encoding=dst,
                             log=self._log, progress=progress,
                             with_ir=with_ir)
            self._summarise_export(rep, out)

        self._run(job)

    def _summarise_export(self, rep, out):
        tags = rep["tags"]
        kinds = rep["name_kinds"]
        self._q.put(("status",
                     f"✓ 已导出 {rep['entries']} 条到 {out}"))
        self._log("")
        self._log(f"样本      {rep['files_decoded']}/{rep['files_total']} 个文件")
        self._log(f"理解深度  T2（按调用结构定位文本，逐字节可还原）")
        self._log(f"覆盖      byte {rep['min_byte_coverage'] * 100:.2f}%"
                  f"   往返 逐字节一致")
        self._log(f"文本      {rep['entries']} 条："
                  + "  ".join(f"{k} {v}" for k, v in sorted(tags.items())))
        self._log(f"可翻译    " + "  ".join(
            f"{k} {v}" for k, v in sorted(rep["policies"].items())))
        self._log(f"说话者    人名表 {kinds.get('table', 0)}"
                  f" / 行内覆盖 {kinds.get('override', 0)}"
                  f" / 无名 {kinds.get('virtual', 0)}")
        self._log(f"来源      " + "  ".join(
            f"{k} {v}" for k, v in sorted(rep["tag_sources"].items())))
        if rep["unresolved_files"]:
            self._log(f"无法解密  {len(rep['unresolved_files'])} 个文件"
                      f"（已原样保留，未导出）")
        if rep["selfcheck_failed"]:
            self._log(f"自检失败  {len(rep['selfcheck_failed'])} 个文件")
        self._log(f"内部产物  {out / dis.WORKDIR / 'reports'}")

    def _do_repack(self):
        inputs = [self.input_var.get().strip()]
        frm = self.from_var.get().strip()
        out = Path(self.rebuild_var.get().strip())
        src, dst = self.src_enc.get().strip(), self.dst_enc.get().strip()

        def preview():
            rep, _plans = asm.repack(inputs, frm, out, source_encoding=src,
                                     target_encoding=dst, log=self._log,
                                     dry_run=True)
            self._pending = (rep, inputs, frm, out, src, dst)
            # Hand the dialog back to the UI thread; the worker only computes.
            self.after(0, lambda: self._show_preview(rep))

        self._run(preview)

    def _show_preview(self, rep):
        grew = sum(1 for _, d in rep["size_changes"] if d > 0)
        lines = [
            f"将回封 {rep['files_total']} 个文件",
            f"  改动    {rep['entries_changed']} 条译文"
            f"（其中 {grew} 个文件变长，共 {rep['bytes_delta']:+d} 字节）",
            f"  方式    {'不改动，原样重建' if rep['strategy'] == 'identity' else '重排文本区（自动选择）'}",
            f"  跳过    {rep['files_skipped']} 个（没有对应译文）",
            f"  输出到  {self._pending[3]}",
        ]
        if rep["rejected"]:
            lines.append("")
            lines.append(f"以下 {len(rep['rejected'])} 处必须先处理，"
                         f"回封已停止：")
            lines.extend("  " + r for r in rep["rejected"][:12])
            if len(rep["rejected"]) > 12:
                lines.append(f"  …… 还有 {len(rep['rejected']) - 12} 处")
            self._log("\n".join(lines))
            messagebox.showerror("译文有问题，未执行", "\n".join(lines))
            return
        self._log("\n".join(lines))
        if not messagebox.askokcancel("确认回封", "\n".join(lines)):
            self._q.put(("status", "已取消，未写出任何文件"))
            return

        rep0, inputs, frm, out, src, dst = self._pending

        def job():
            rep2, _ = asm.repack(inputs, frm, out, source_encoding=src,
                                 target_encoding=dst, log=self._log)
            self._q.put(("status",
                         f"✓ 已回封 {rep2['files_written']} 个文件到 {out}"))
            self._log("")
            self._log(f"改动      {rep2['entries_changed']} 条，"
                      f"长度变化 {rep2['bytes_delta']:+d} 字节")
            self._log(f"回封方式  {rep2['strategy']}")
            for line in rep2["verify_failed"][:10]:
                self._log(f"校验失败  {line}")
            if not rep2["verify_failed"]:
                self._log("校验      输出可重新解析，覆盖完整，"
                          "改动内容已确认写入")
            self._log("把输出目录里的 .rld 复制回游戏的 rld 文件夹即可生效。")

        self._run(job)


def main():
    app = App()
    # advanced toggle lives in the detail area, off by default
    ttk.Checkbutton(app, text="同时导出 IR（排查用）",
                    variable=app.with_ir).pack(anchor="w", padx=12)
    app.mainloop()


if __name__ == "__main__":
    main()
