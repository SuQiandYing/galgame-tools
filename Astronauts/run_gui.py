# -*- coding: utf-8 -*-
"""run_gui.py — 两按钮图形界面：输出文本 / 回封文本。

界面只调用 disassembler.py 与 assembler.py 暴露的函数，不自行解析二进制。
同一操作经界面与命令行产出相同的 IR、产物与证书。

双击运行即可。拖放需要 tkinterdnd2 或 windnd，缺失时降级为「浏览…」按钮。
"""

from __future__ import annotations

import queue
import threading
import traceback
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import assembler as asm
import disassembler as dis

TITLE = "憑夜ノ村 脚本文本工具"
ENCODINGS = ["utf-8", "cp932", "gbk", "big5", "cp949"]


def _try_dnd(widget, callback):
    """尽力启用拖放；失败返回 False，不阻止启动。"""
    try:
        import tkinterdnd2  # noqa: F401
        widget.drop_target_register("DND_Files")
        widget.dnd_bind("<<Drop>>", lambda e: callback(e.data))
        return True
    except Exception:
        pass
    try:
        import windnd
        windnd.hook_dropfiles(widget, func=lambda files: callback(
            files[0].decode("mbcs", "replace") if files else ""))
        return True
    except Exception:
        return False


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title(TITLE)
        root.geometry("720x560")
        root.minsize(660, 520)

        self.q: queue.Queue = queue.Queue()
        self.busy = False
        self.detail_text = ""

        self.var_in = tk.StringVar()
        self.var_text_out = tk.StringVar()
        self.var_rebuild_out = tk.StringVar()
        self.var_from = tk.StringVar()
        self.var_gxp_name = tk.StringVar()
        self.var_src_enc = tk.StringVar(value="utf-8")
        self.var_tgt_enc = tk.StringVar(value="utf-8")
        self.var_dsat = tk.BooleanVar(value=True)
        self.var_asm = tk.BooleanVar(value=False)
        self.var_with_ir = tk.BooleanVar(value=False)
        self.var_all = tk.BooleanVar(value=False)
        self.var_by_chapter = tk.BooleanVar(value=True)
        self.var_status = tk.StringVar(value="把 bincode.gxp 拖进来，或点「浏览…」选择")

        self._from_touched = False
        self.var_text_out.trace_add("write", self._on_text_out_changed)
        self.var_from.trace_add("write", lambda *_: None)

        self._build()
        self.root.after(120, self._pump)

    # ---------------- 布局 ----------------
    def _build(self):
        pad = dict(padx=10, pady=6)

        # 输入
        f0 = ttk.LabelFrame(self.root, text="游戏脚本文件")
        f0.pack(fill="x", **pad)
        row = ttk.Frame(f0)
        row.pack(fill="x", padx=8, pady=(8, 2))
        e = ttk.Entry(row, textvariable=self.var_in)
        e.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="浏览…", command=self._pick_input).pack(side="left", padx=(6, 0))
        self.lbl_in = ttk.Label(f0, text="支持 bincode.gxp 或 bincode/moacode.mwb",
                                foreground="#666")
        self.lbl_in.pack(anchor="w", padx=8, pady=(0, 8))
        ok = _try_dnd(self.root, self._on_drop)
        if not ok:
            self.lbl_in.config(text="支持 bincode.gxp 或 bincode/moacode.mwb"
                                    "（未装拖放库，请用「浏览…」）")

        # 编码
        f1 = ttk.Frame(self.root)
        f1.pack(fill="x", **pad)
        ttk.Label(f1, text="原文编码").pack(side="left")
        ttk.Combobox(f1, textvariable=self.var_src_enc, values=ENCODINGS,
                     width=10).pack(side="left", padx=(4, 16))
        ttk.Label(f1, text="译文编码").pack(side="left")
        ttk.Combobox(f1, textvariable=self.var_tgt_enc, values=ENCODINGS,
                     width=10).pack(side="left", padx=4)
        ttk.Label(f1, text="（本引擎脚本为 UTF-8，通常无需改动）",
                  foreground="#666").pack(side="left", padx=8)

        # 输出文本
        f2 = ttk.LabelFrame(self.root, text="输 出 文 本")
        f2.pack(fill="x", **pad)
        r = ttk.Frame(f2)
        r.pack(fill="x", padx=8, pady=(8, 2))
        ttk.Label(r, text="到").pack(side="left")
        ttk.Entry(r, textvariable=self.var_text_out).pack(side="left", fill="x",
                                                          expand=True, padx=4)
        ttk.Button(r, text="浏览…",
                   command=lambda: self._pick_dir(self.var_text_out)).pack(side="left")
        r2 = ttk.Frame(f2)
        r2.pack(fill="x", padx=8, pady=(0, 4))
        ttk.Checkbutton(r2, text="双行文本（翻译用）", variable=self.var_dsat,
                        command=self._sync).pack(side="left")
        ttk.Checkbutton(r2, text="ASM 清单（改逻辑用）", variable=self.var_asm,
                        command=self._sync).pack(side="left", padx=16)
        r3 = ttk.Frame(f2)
        r3.pack(fill="x", padx=8, pady=(0, 2))
        ttk.Checkbutton(r3, text="按剧情分段（一段一个 txt）",
                        variable=self.var_by_chapter).pack(side="left")
        ttk.Label(r3, text="取消则输出一个大文件", foreground="#666").pack(side="left", padx=8)
        self.btn_out = ttk.Button(f2, text="输 出 文 本", command=self._do_export)
        self.btn_out.pack(fill="x", padx=8, pady=(2, 8))

        # 回封
        f3 = ttk.LabelFrame(self.root, text="回 封 文 本")
        f3.pack(fill="x", **pad)
        r = ttk.Frame(f3)
        r.pack(fill="x", padx=8, pady=(8, 2))
        ttk.Label(r, text="从").pack(side="left")
        ttk.Entry(r, textvariable=self.var_from).pack(side="left", fill="x",
                                                      expand=True, padx=4)
        ttk.Button(r, text="浏览…",
                   command=self._pick_from).pack(side="left")
        r = ttk.Frame(f3)
        r.pack(fill="x", padx=8, pady=2)
        ttk.Label(r, text="到").pack(side="left")
        ttk.Entry(r, textvariable=self.var_rebuild_out).pack(side="left", fill="x",
                                                             expand=True, padx=4)
        ttk.Button(r, text="浏览…",
                   command=lambda: self._pick_dir(self.var_rebuild_out)).pack(side="left")
        r = ttk.Frame(f3)
        r.pack(fill="x", padx=8, pady=2)
        ttk.Label(r, text="封包名").pack(side="left")
        ttk.Entry(r, textvariable=self.var_gxp_name, width=28).pack(side="left", padx=4)
        ttk.Label(r, text="（可自定义，留空则用原名）", foreground="#666").pack(side="left")
        self.btn_rb = ttk.Button(f3, text="回 封 文 本", command=self._do_repack)
        self.btn_rb.pack(fill="x", padx=8, pady=(2, 8))

        # 进度
        f4 = ttk.Frame(self.root)
        f4.pack(fill="x", **pad)
        self.bar = ttk.Progressbar(f4, mode="determinate", maximum=100)
        self.bar.pack(fill="x")
        r = ttk.Frame(f4)
        r.pack(fill="x", pady=(4, 0))
        ttk.Label(r, textvariable=self.var_status).pack(side="left")
        self.btn_open = ttk.Button(r, text="打开", command=self._open_out,
                                   state="disabled")
        self.btn_open.pack(side="right")

        # 详情
        self.detail_frame = ttk.LabelFrame(self.root, text="详情")
        r = ttk.Frame(self.detail_frame)
        r.pack(fill="x", padx=8, pady=4)
        ttk.Checkbutton(r, text="同时导出 IR（排查用）",
                        variable=self.var_with_ir).pack(side="left")
        ttk.Checkbutton(r, text="双行文本包含不可翻译条目",
                        variable=self.var_all).pack(side="left", padx=12)
        self.txt = tk.Text(self.detail_frame, height=9, wrap="none")
        self.txt.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.btn_detail = ttk.Button(self.root, text="▸ 详情", command=self._toggle)
        self.btn_detail.pack(anchor="w", padx=10, pady=(0, 8))
        self._detail_open = False
        self._sync()

    # ---------------- 路径推导 ----------------
    def _on_drop(self, data: str):
        p = data.strip().strip("{}").split("} {")[0]
        if p:
            self._set_input(p)

    def _pick_input(self):
        p = filedialog.askopenfilename(
            title="选择 bincode.gxp 或 moacode.mwb",
            filetypes=[("GXP 归档 / MWB 脚本", "*.gxp *.mwb"), ("所有文件", "*.*")])
        if p:
            self._set_input(p)

    def _set_input(self, p: str):
        path = Path(p)
        self.var_in.set(str(path))
        base = path.parent / path.stem
        self.var_text_out.set(str(base) + "_text")
        self.var_rebuild_out.set(str(base) + "_rebuilt")
        self.var_gxp_name.set(path.name if path.suffix.lower() == ".gxp" else "")
        self._from_touched = False
        self.var_from.set(self.var_text_out.get())
        try:
            size = path.stat().st_size
            self.lbl_in.config(text=f"{path.name}  {size:,} 字节")
        except OSError:
            pass
        self.var_status.set("准备就绪，点「输出文本」开始")
        self._sync()

    def _on_text_out_changed(self, *_):
        if not self._from_touched:
            self.var_from.set(self.var_text_out.get())

    def _pick_from(self):
        p = filedialog.askdirectory(title="选择文本目录")
        if p:
            self._from_touched = True
            self.var_from.set(p)

    def _pick_dir(self, var: tk.StringVar):
        p = filedialog.askdirectory(title="选择输出目录")
        if p:
            var.set(p)

    def _sync(self):
        has_in = bool(self.var_in.get())
        any_out = self.var_dsat.get() or self.var_asm.get()
        self.btn_out.config(state="normal" if (has_in and any_out and not self.busy)
                            else "disabled")
        if not any_out:
            self.var_status.set("请至少选择一种输出")
        src = Path(self.var_from.get()) if self.var_from.get() else None
        ready = bool(src and src.is_dir()
                     and (any(src.rglob("*.txt")) or any(src.rglob("*.asm.txt"))))
        self.btn_rb.config(state="normal" if (has_in and ready and not self.busy)
                           else "disabled")

    def _toggle(self):
        self._detail_open = not self._detail_open
        if self._detail_open:
            self.detail_frame.pack(fill="both", expand=True, padx=10, pady=(0, 4),
                                   before=self.btn_detail)
            self.btn_detail.config(text="▾ 详情")
        else:
            self.detail_frame.pack_forget()
            self.btn_detail.config(text="▸ 详情")

    def _open_out(self):
        import os
        p = self._last_out
        if p and Path(p).exists():
            os.startfile(p)

    _last_out = None

    # ---------------- 执行 ----------------
    def _start(self, fn):
        self.busy = True
        self._sync()
        self.btn_open.config(state="disabled")
        self.bar.config(mode="indeterminate")
        self.bar.start(12)

        def worker():
            try:
                self.q.put(("done", fn()))
            except Exception as exc:
                self.q.put(("error", (exc, traceback.format_exc())))
        threading.Thread(target=worker, daemon=True).start()

    def _say(self, msg: str):
        self.q.put(("progress", msg))

    def _do_export(self):
        inp = self.var_in.get()
        out = self.var_text_out.get()
        if not inp:
            messagebox.showwarning(TITLE, "请先选择输入文件")
            return
        if Path(out).is_dir() and any(Path(out).iterdir()):
            if not messagebox.askyesno(TITLE, f"{out}\n已存在内容，覆盖？"):
                return
        self._start(lambda: ("export", dis.run(
            inp, out, want_texts=self.var_dsat.get(), want_asm=self.var_asm.get(),
            with_ir=self.var_with_ir.get(), all_texts=self.var_all.get(),
            by_chapter=self.var_by_chapter.get(), progress=self._say)))

    def _do_repack(self):
        inp = self.var_in.get()
        src = self.var_from.get()
        out = self.var_rebuild_out.get()
        name = self.var_gxp_name.get().strip() or None

        # 预览（只读 probe，不写出）
        try:
            prev = asm.run(inp, src, out, name, dry_run=True, progress=self._say)
        except asm.ImportError_ as exc:
            messagebox.showerror(TITLE, str(exc))
            return
        except Exception as exc:
            messagebox.showerror(TITLE, f"{exc}")
            return

        st = prev.get("text_stats") or {}
        strat_cn = {"identity": "原样重建", "in_place": "原地替换",
                    "pointer-rewrite": "引用回填", "full-layout": "整体重排"}
        lines = [
            f"将回封 {Path(inp).name}",
            f"  改动    {st.get('changed', 0)} 条译文（共 {st.get('entries', 0)} 条）",
            f"  方式    {strat_cn.get(prev['selected_strategy'], prev['selected_strategy'])}（自动选择）",
            f"  冲突    {prev['conflicts']}",
            f"  输出到  {out}",
        ]
        if prev["conflicts"]:
            messagebox.showerror(TITLE, "\n".join(lines))
            return
        if not messagebox.askokcancel(TITLE, "\n".join(lines)):
            return

        self._start(lambda: ("repack", asm.run(
            inp, src, out, name, dry_run=False, progress=self._say)))

    # ---------------- 事件泵 ----------------
    def _pump(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "progress":
                    self.var_status.set(payload)
                elif kind == "done":
                    self._finish(*payload)
                elif kind == "error":
                    exc, tb = payload
                    self.busy = False
                    self.bar.stop()
                    self.bar.config(mode="determinate", value=0)
                    self.var_status.set(f"失败：{exc}")
                    self._append(tb)
                    self._sync()
        except queue.Empty:
            pass
        self.root.after(120, self._pump)

    def _finish(self, what: str, r: dict):
        self.busy = False
        self.bar.stop()
        self.bar.config(mode="determinate", value=100)
        self._sync()
        if what == "export":
            self._last_out = r["out_dir"]
            n = r.get("text_files", 1)
            extra = f"，分 {n} 个剧情文件" if n > 1 else ""
            self.var_status.set(
                f"已导出 {r['translatable']} 条可翻译文本{extra} → {r['out_dir']}")
            self._append(self._export_detail(r))
        else:
            self._last_out = r["out_dir"]
            p = r.get("repack", {})
            self.var_status.set(
                f"已回封 {r['edits']} 条 → {r.get('gxp') or r.get('mwb')}")
            self._append(self._repack_detail(r, p))
        self.btn_open.config(state="normal")
        self._sync()

    def _export_detail(self, r: dict) -> str:
        import json
        cert = json.loads(Path(r["certificate"]).read_text("utf-8"))
        tags = cert["text_tag_counts"]
        return "\n".join([
            f"样本      {Path(r['source']).name}",
            f"          sha256 {cert['source']['sha256'][:16]}…  "
            f"{cert['source']['size']:,} 字节",
            f"理解深度  {cert['min_tier']}（{cert['statements']:,} 条语句，"
            f"{cert['functions']} 个内建函数）",
            f"覆盖      byte {cert['byte_coverage']*100:.2f}%   "
            f"往返 {'逐字节一致' if cert['roundtrip']['zero_edit_identical'] else '不一致'}",
            f"文本      {sum(tags.values()):,} 条："
            f"可翻译 {cert['translatable']:,} / 锁定 {cert['frozen']:,}",
            f"分类      正文 {tags.get('msg',0):,} / 人名 {tags.get('name',0):,} / "
            f"选项 {tags.get('choice',0)} / 界面 {tags.get('ui',0)} / "
            f"标签 {tags.get('label',0)} / 其他 {tags.get('misc',0):,}",
            f"来源      结构 {cert['tag_source_counts'].get('structural',0):,} / "
            f"外观推断 {cert['tag_source_counts'].get('heuristic',0)} / "
            f"未判定 {cert['tag_source_counts'].get('unresolved',0)}",
            f"内部产物  {r['certificate']}",
        ])

    def _repack_detail(self, r: dict, p: dict) -> str:
        rows = [
            f"策略      {r['selected_strategy']}（{r['selection_rule']}）",
            f"改动      {r['edits']} 条",
        ]
        if p:
            rows += [
                f"载荷      {p['payload_size_before']:,} → "
                f"{p['payload_size_after']:,}（{p['payload_delta']:+,} 字节）",
                f"页数变化  {p['page_delta']:+d}",
                f"语句      {p['statements']:,}（重解析通过，覆盖 100%）",
            ]
        rows.append("裁决：")
        for v in r["verdicts"]:
            rows.append(f"  {v['strategy_id']:<16} "
                        f"{'可用' if v['applicable'] else '不可用'}  {v['reason_code']}")
        if r.get("mwb"):
            rows.append(f"mwb       {r['mwb']}")
        if r.get("gxp"):
            rows.append(f"gxp       {r['gxp']}")
        return "\n".join(rows)

    def _append(self, text: str):
        self.txt.delete("1.0", "end")
        self.txt.insert("1.0", text)


def main():
    try:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
    except Exception:
        root = tk.Tk()
    try:
        root.call("tk", "scaling", 1.2)
    except tk.TclError:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
