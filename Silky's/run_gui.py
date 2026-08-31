"""Two-button GUI for extracting and reinserting .MES text.

Layout only: this file never parses a binary itself, it calls disassembler.py
and assembler.py so that GUI and CLI produce identical output.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import disassembler as A
import assembler as B
import opcodelist as D

# Drag and drop backend.
#
# windnd is deliberately NOT used: it corrupts the window procedure pointer on
# 64-bit Python.
#
# It subclasses the Win32 window proc with a ctypes callback and saves the
# previous proc via GetWindowLongPtrA, leaving restype at the default *signed*
# c_long. Measured on this machine: the real pointer 0xFFFF0571 comes back as
# -64143, and windnd then re-widens it with c_uint64 to 0xFFFFFFFFFFFF0571 --
# a different, invalid address, which it hands to CallWindowProcW on every
# message. It also mixes the ANSI Get/SetWindowLongPtrA with the wide
# CallWindowProcW and keeps per-hook state in module globals.
#
# The observed symptom is:
#     Fatal Python error: PyEval_RestoreThread: the function must be called
#     with the GIL held, but the GIL is released
# That is a native fault inside the window proc, so NO amount of Python-level
# try/except can contain it -- the interpreter is already gone. Wrapping the
# callback (the previous attempt here) cannot help.
#
# tkdnd via tkinterdnd2 is a genuine Tcl/Tk extension: drops arrive as ordinary
# Tk virtual events dispatched by Tk itself with the GIL correctly held.
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    _DND = "tkinterdnd2"
except Exception:
    DND_FILES = None
    TkinterDnD = None
    _DND = None


def make_root():
    """Root window with drag-and-drop support when available.

    tkdnd has to be initialised by the root window itself, so this cannot be
    retrofitted onto a plain tk.Tk() afterwards.
    """
    if TkinterDnD is not None:
        try:
            return TkinterDnD.Tk(), True
        except Exception:
            pass
    return tk.Tk(), False

ENCODINGS = ["cp932", "gbk", "big5", "cp949", "utf-8"]


class App:
    def __init__(self, root: tk.Tk, dnd_ready: bool = False):
        self.root = root
        self.dnd_ready = dnd_ready
        root.title("SILKY'S .MES 文本工具")
        root.geometry("720x560")
        self.q = queue.Queue()
        self.busy = False
        self.text_dir_edited = False
        self.repack_from_edited = False

        pad = {"padx": 10, "pady": 4}
        frm = ttk.Frame(root, padding=10)
        frm.pack(fill="both", expand=True)

        # --- input -------------------------------------------------------
        box = ttk.LabelFrame(frm, text="游戏脚本文件夹", padding=8)
        box.pack(fill="x", **pad)
        row = ttk.Frame(box)
        row.pack(fill="x")
        self.v_in = tk.StringVar()
        ttk.Entry(row, textvariable=self.v_in).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="浏览…", command=self.pick_input).pack(side="left", padx=4)
        self.lbl_found = ttk.Label(box, text="把文件夹拖进来，或点此选择")
        self.lbl_found.pack(anchor="w", pady=(4, 0))
        self.v_in.trace_add("write", lambda *_: self.on_input_change())

        # --- encodings ---------------------------------------------------
        enc = ttk.Frame(frm)
        enc.pack(fill="x", **pad)
        ttk.Label(enc, text="原文编码").pack(side="left")
        self.v_senc = tk.StringVar(value=D.ENCODINGS["source_encoding"])
        ttk.Combobox(enc, textvariable=self.v_senc, values=ENCODINGS,
                     width=10).pack(side="left", padx=(4, 16))
        ttk.Label(enc, text="译文编码").pack(side="left")
        self.v_tenc = tk.StringVar(value=D.ENCODINGS["target_encoding"])
        ttk.Combobox(enc, textvariable=self.v_tenc, values=ENCODINGS,
                     width=10).pack(side="left", padx=4)

        # --- extract -----------------------------------------------------
        box = ttk.LabelFrame(frm, text="输 出 文 本", padding=8)
        box.pack(fill="x", **pad)
        row = ttk.Frame(box)
        row.pack(fill="x")
        ttk.Label(row, text="到").pack(side="left")
        self.v_text = tk.StringVar()
        ttk.Entry(row, textvariable=self.v_text).pack(side="left", fill="x",
                                                      expand=True, padx=4)
        ttk.Button(row, text="浏览…", command=self.pick_text).pack(side="left")
        self.v_text.trace_add("write", lambda *_: self.on_text_change())
        opt = ttk.Frame(box)
        opt.pack(fill="x", pady=(6, 0))
        self.v_dual = tk.BooleanVar(value=True)
        self.v_asm = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="双行文本（翻译用）", variable=self.v_dual,
                        command=self.sync_buttons).pack(side="left")
        ttk.Checkbutton(opt, text="ASM 清单（改逻辑用）", variable=self.v_asm,
                        command=self.sync_buttons).pack(side="left", padx=16)
        self.btn_extract = ttk.Button(box, text="输出文本", command=self.do_extract)
        self.btn_extract.pack(anchor="e", pady=(6, 0))

        # --- repack ------------------------------------------------------
        box = ttk.LabelFrame(frm, text="回 封 文 本", padding=8)
        box.pack(fill="x", **pad)
        row = ttk.Frame(box)
        row.pack(fill="x")
        ttk.Label(row, text="从").pack(side="left")
        self.v_from = tk.StringVar()
        ttk.Entry(row, textvariable=self.v_from).pack(side="left", fill="x",
                                                     expand=True, padx=4)
        ttk.Button(row, text="浏览…", command=self.pick_from).pack(side="left")
        self.v_from.trace_add("write", lambda *_: setattr(self, "repack_from_edited", True))
        row = ttk.Frame(box)
        row.pack(fill="x", pady=(4, 0))
        ttk.Label(row, text="到").pack(side="left")
        self.v_out = tk.StringVar()
        ttk.Entry(row, textvariable=self.v_out).pack(side="left", fill="x",
                                                    expand=True, padx=4)
        ttk.Button(row, text="浏览…", command=self.pick_out).pack(side="left")
        self.btn_repack = ttk.Button(box, text="回封文本", command=self.do_repack)
        self.btn_repack.pack(anchor="e", pady=(6, 0))

        # --- progress ----------------------------------------------------
        self.bar = ttk.Progressbar(frm, mode="determinate")
        self.bar.pack(fill="x", **pad)
        self.lbl_status = ttk.Label(frm, text="")
        self.lbl_status.pack(anchor="w", padx=10)

        # --- details -----------------------------------------------------
        self.details = tk.Text(frm, height=9, wrap="word", state="disabled")
        self.details.pack(fill="both", expand=True, padx=10, pady=(6, 0))

        self.setup_dnd()
        self.sync_buttons()
        self.root.after(100, self.drain)

    # ------------------------------------------------------------------
    @staticmethod
    def _decode_dropped(item) -> str:
        if isinstance(item, str):
            return item
        if isinstance(item, (bytes, bytearray)):
            for codec in ("mbcs", "utf-8", "cp932", "gbk"):
                try:
                    return bytes(item).decode(codec)
                except (UnicodeDecodeError, LookupError):
                    continue
            return bytes(item).decode("mbcs", errors="replace")
        return str(item)

    def _split_drop_data(self, data) -> list:
        """tkdnd hands over one Tcl list string. Splitting it needs care.

        tk.splitlist treats backslashes as Tcl escapes, so an unbraced Windows
        path is corrupted: 'E:\\fuyukuru_dl\\SILKYSIMAGE\\1' comes back as
        'E:\\x0cuyukuru_dlSILKYSIMAGE\\x01'. tkdnd braces paths containing
        spaces, so the safe order is: use splitlist only when the payload is
        braced, otherwise take the string as a single literal path.
        """
        if not isinstance(data, str):
            data = self._decode_dropped(data)
        data = data.strip()
        if not data:
            return []
        if "{" in data:
            try:
                return [str(p) for p in self.root.tk.splitlist(data)]
            except Exception:
                pass
        # Multiple unbraced paths are newline- or space-separated only when none
        # contain spaces; a lone path is taken verbatim so backslashes survive.
        if "\n" in data:
            return [ln.strip() for ln in data.splitlines() if ln.strip()]
        return [data]

    def _on_drop(self, event) -> None:
        """Handle a <<Drop>> virtual event. Runs on the Tk thread."""
        try:
            paths = [p for p in self._split_drop_data(getattr(event, "data", ""))
                     if p.strip()]
            if not paths:
                self.lbl_found.config(text="没能读出拖入的路径，请用「浏览…」选择")
                return
            self._accept_input(paths)
        except Exception as exc:
            self.lbl_found.config(
                text="拖放失败（%s），请用「浏览…」选择" % type(exc).__name__)

    def _accept_input(self, paths):
        """Apply a dropped/selected path list. Multiple items share a parent."""
        try:
            if len(paths) == 1:
                self.v_in.set(paths[0])
            else:
                import os
                common = os.path.commonpath([str(Path(p)) for p in paths])
                self.v_in.set(common)
                self.lbl_found.config(text="已拖入 %d 项，使用共同目录 %s"
                                           % (len(paths), common))
        except Exception as exc:
            self.lbl_found.config(text="路径无法处理：%s" % exc)

    def setup_dnd(self):
        """Register the whole window as a drop target, or say so if unavailable.

        Only tkdnd is used; see the module header for why windnd is not.
        """
        if not self.dnd_ready or DND_FILES is None:
            self.lbl_found.config(
                text="把文件夹拖进来，或点「浏览…」选择"
                     "（未装 tkinterdnd2，拖放不可用，用浏览即可）")
            return
        try:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind("<<Drop>>", self._on_drop)
        except Exception:
            self.dnd_ready = False
            self.lbl_found.config(
                text="把文件夹拖进来，或点「浏览…」选择（拖放注册失败，用浏览即可）")

    def on_input_change(self):
        p = self.v_in.get().strip().strip('"')
        if not p:
            return
        try:
            path = Path(p)
        except (OSError, ValueError):
            self.lbl_found.config(text="路径格式无效")
            return
        if not path.exists():
            self.lbl_found.config(text="路径不存在")
            return
        try:
            srcs, base = A.find_sources([p])
            self.lbl_found.config(text="已找到 %d 个脚本文件" % len(srcs))
        except A.MesParseError as exc:
            self.lbl_found.config(text=str(exc))
            return
        except OSError as exc:
            self.lbl_found.config(text="无法读取目录：%s" % exc)
            return
        # Defaults live beside the input, never inside it.
        if not self.text_dir_edited:
            self.v_text.set(str(base.parent / (base.name + "_text")))
            self.text_dir_edited = False
        if not self.repack_from_edited:
            self.v_from.set(self.v_text.get())
            self.repack_from_edited = False
        self.v_out.set(str(base.parent / (base.name + "_rebuilt")))
        self.sync_buttons()

    def on_text_change(self):
        self.text_dir_edited = True
        if not self.repack_from_edited:
            self.v_from.set(self.v_text.get())
            self.repack_from_edited = False

    def pick_input(self):
        p = filedialog.askdirectory(title="选择脚本文件夹")
        if p:
            self.v_in.set(p)

    def pick_text(self):
        p = filedialog.askdirectory(title="文本输出位置")
        if p:
            self.v_text.set(p)

    def pick_from(self):
        p = filedialog.askdirectory(title="译文所在位置")
        if p:
            self.v_from.set(p)

    def pick_out(self):
        p = filedialog.askdirectory(title="回封输出位置")
        if p:
            self.v_out.set(p)

    def sync_buttons(self):
        has_in = bool(self.v_in.get().strip())
        want = self.v_dual.get() or self.v_asm.get()
        self.btn_extract.config(
            state="normal" if (has_in and want and not self.busy) else "disabled")
        ready = False
        src = self.v_from.get().strip()
        if src:
            d = Path(src)
            ready = (d / "texts").is_dir() or (d / "asm").is_dir()
        self.btn_repack.config(
            state="normal" if (has_in and ready and not self.busy) else "disabled")
        if has_in and not want:
            self.lbl_status.config(text="请至少选择一种输出")

    def log(self, text):
        self.details.config(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.config(state="disabled")

    def drain(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "progress":
                    i, n, label = payload
                    self.bar.config(maximum=n, value=i)
                    self.lbl_status.config(text="正在处理 %s  %d%%"
                                                % (label, int(100 * i / n)))
                elif kind == "done":
                    self.busy = False
                    self.lbl_status.config(text=payload[0])
                    self.log(payload[1])
                    self.sync_buttons()
                elif kind == "error":
                    self.busy = False
                    self.lbl_status.config(text="出错了，详见下方")
                    self.log(payload)
                    self.sync_buttons()
                elif kind == "confirm":
                    self.busy = False
                    self.sync_buttons()
                    summary, proceed = payload
                    if messagebox.askokcancel("确认回封", summary):
                        proceed()
        except queue.Empty:
            pass
        self.root.after(100, self.drain)

    def start(self, fn):
        if self.busy:
            return
        self.busy = True
        self.sync_buttons()
        self.bar.config(value=0)
        threading.Thread(target=fn, daemon=True).start()

    # ------------------------------------------------------------------
    def apply_encodings(self):
        D.ENCODINGS["source_encoding"] = self.v_senc.get().strip() or "cp932"
        D.ENCODINGS["target_encoding"] = self.v_tenc.get().strip() or "cp932"

    def do_extract(self):
        src = self.v_in.get().strip()
        out = self.v_text.get().strip() or None
        dual, asm = self.v_dual.get(), self.v_asm.get()
        self.apply_encodings()

        def work():
            try:
                def prog(i, n, r):
                    self.q.put(("progress", (i, n, Path(r["rel"]).name)))
                rep = A.run_extract([src], out, want_texts=dual, want_asm=asm,
                                    jobs=None, progress=prog)
                tags = rep["tag_counts"]
                lines = [
                    "样本      %d 个文件, %d 字节" % (rep["files_total"], rep["bytes_total"]),
                    "理解深度  T3（指令流完整，%d 条指令）" % rep["instructions_total"],
                    "覆盖      byte %.2f%%   往返 %s" % (
                        100 * rep["min_byte_coverage"],
                        "逐字节一致" if rep["roundtrip_all_identical"] else "不一致"),
                    "文本      %d 条：正文 %d / 人名 %d / 锁定 %d" % (
                        rep["entries_total"], tags.get("msg", 0),
                        tags.get("name", 0), tags.get("label", 0)),
                    "来源      %s" % ", ".join("%s=%d" % kv for kv in
                                               sorted(rep["tag_source_counts"].items())),
                    "内部产物  %s" % (Path(rep["output_dir"]) / "_work" / "reports"),
                ]
                if rep["failures"]:
                    lines.append("失败 %d 个：" % len(rep["failures"]))
                    lines += ["  %s: %s" % (f["rel"], f["error"])
                              for f in rep["failures"][:10]]
                msg = "✓ 已导出 %d 条到 %s" % (rep["entries_total"], rep["output_dir"])
                self.q.put(("done", (msg, "\n".join(lines))))
            except Exception as exc:
                self.q.put(("error", "%s: %s" % (type(exc).__name__, exc)))

        self.start(work)

    def do_repack(self):
        src = self.v_in.get().strip()
        tdir = self.v_from.get().strip()
        out = self.v_out.get().strip() or None
        self.apply_encodings()

        def preview():
            try:
                rep = B.run_repack([src], tdir, out, dry_run=True)
                if rep["conflicts"]:
                    lines = ["两个编辑面对同一条给出不同内容，已停止：", ""]
                    for c in rep["conflicts"][:20]:
                        lines.append("%s idx=%08d" % (c["rel"], c["idx"]))
                        lines.append("   双行文本: %s" % c["texts"])
                        lines.append("   ASM:      %s" % c["asm"])
                    self.q.put(("error", "\n".join(lines)))
                    return
                if rep["failures"]:
                    lines = ["以下文件无法回封，已停止：", ""]
                    lines += ["%s\n   %s" % (f["rel"], f["error"])
                              for f in rep["failures"][:10]]
                    self.q.put(("error", "\n".join(lines)))
                    return
                summary = (
                    "将回封 %d 个文件\n\n"
                    "  改动    %d 条译文（其中 %d 条变长）\n"
                    "  冲突    0\n"
                    "  输出到  %s"
                    % (rep["files_total"], rep["entries_edited"],
                       rep["entries_longer"], rep["output_dir"]))
                self.q.put(("confirm", (summary, lambda: self.start(execute))))
            except Exception as exc:
                self.q.put(("error", "%s: %s" % (type(exc).__name__, exc)))

        def execute():
            try:
                def prog(i, n, rel, strat, info):
                    self.q.put(("progress", (i, n, Path(rel).name)))
                rep = B.run_repack([src], tdir, out, progress=prog)
                strat = ", ".join("%s=%d" % kv for kv in
                                  sorted(rep.get("strategies_used", {}).items()))
                lines = [
                    "回封方式  %s" % strat,
                    "改动      %d 条（%d 条变长）" % (rep["entries_edited"],
                                                     rep["entries_longer"]),
                    "输出      %s" % rep["output_dir"],
                    "",
                    "把输出目录里的文件复制回游戏即可。原始文件未被修改。",
                ]
                self.q.put(("done", ("✓ 已回封 %d 个文件" % rep["written"],
                                     "\n".join(lines))))
            except Exception as exc:
                self.q.put(("error", "%s: %s" % (type(exc).__name__, exc)))

        self.start(preview)


def main():
    root, dnd_ready = make_root()
    App(root, dnd_ready)
    root.mainloop()


if __name__ == "__main__":
    main()
