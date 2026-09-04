"""EntisGLS 脚本与封包工具 — 图形界面。

界面只暴露产物，不暴露内部阶段：解析、覆盖证书、零编辑往返自检都在按钮内部
执行。每个路径框都是独立的拖放目标，拖到哪一栏就只改那一栏；没有隐藏的路径
推导，也没有需要点「确定」的弹窗——提示与错误都显示在状态栏和「详情」里。
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

import assembler
import disassembler
import noa

ENCODINGS = ("cp932", "gbk", "big5", "cp949", "utf-8")
SCRIPT_SUFFIXES = (".csx",)


def find_scripts(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    return sorted(p for p in path.rglob("*")
                  if p.is_file() and p.suffix.lower() in SCRIPT_SUFFIXES)


class PathRow(ttk.Frame):
    """一个标签 + 路径框 + 浏览按钮，自己就是拖放目标。

    ``kind`` 决定「浏览…」打开文件还是目录，也决定拖入的路径如何取用：拖入文件
    时若本栏需要目录，则取其所在目录，这样拖任何一个成员文件都能落到正确的栏。
    """

    def __init__(self, master, label: str, variable: tk.StringVar,
                 kind: str = "dir", filetypes=None, on_change=None, width: int = 12):
        super().__init__(master)
        self.variable = variable
        self.kind = kind
        self.filetypes = filetypes or [("所有文件", "*.*")]
        self.on_change = on_change
        ttk.Label(self, text=label, width=width, anchor="w").pack(side="left")
        self.entry = ttk.Entry(self, textvariable=variable)
        self.entry.pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(self, text="浏览…", command=self.browse, width=8).pack(side="left")

    def browse(self) -> None:
        if self.kind == "file":
            chosen = filedialog.askopenfilename(filetypes=self.filetypes)
        else:
            chosen = filedialog.askdirectory()
        if chosen:
            self.set(Path(chosen))

    def set(self, path: Path) -> None:
        path = Path(path)
        if self.kind == "dir" and path.is_file():
            path = path.parent
        self.variable.set(str(path))
        if self.on_change:
            self.on_change()

    def drop_targets(self) -> tuple:
        return (self, self.entry)


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("EntisGLS")
        self.minsize(760, 600)

        self.script_input = tk.StringVar()
        self.text_out = tk.StringVar()
        self.repack_from = tk.StringVar()
        self.repack_out = tk.StringVar()
        self.archive = tk.StringVar()
        self.archive_dir = tk.StringVar()
        self.pack_out = tk.StringVar()
        self.password = tk.StringVar()
        self.source_encoding = tk.StringVar(value="cp932")
        self.target_encoding = tk.StringVar(value="gbk")
        self.want_texts = tk.BooleanVar(value=True)
        self.want_asm = tk.BooleanVar(value=False)
        self.want_ir = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="每个路径框都可以单独拖入文件或文件夹。")
        self.details = tk.StringVar(value="尚未运行。")
        self.key_hint = tk.StringVar(value="")

        self._queue: queue.Queue = queue.Queue()
        self._busy = False
        self._rows: list[PathRow] = []

        self._build()
        self._install_dnd()
        self.after(120, self._drain)

    # ---------------------------------------------------------------- 布局
    def _build(self) -> None:
        pad = {"padx": 10, "pady": 5}

        box = ttk.LabelFrame(self, text="脚本文本")
        box.pack(fill="x", **pad)
        self._row(box, "脚本或目录", self.script_input, "file",
                  [("EntisGLS 脚本", "*.csx"), ("所有文件", "*.*")], self._on_script)
        self._row(box, "文本输出到", self.text_out, "dir")
        enc = ttk.Frame(box)
        enc.pack(fill="x", padx=8, pady=4)
        ttk.Label(enc, text="原文编码", width=12, anchor="w").pack(side="left")
        ttk.Combobox(enc, textvariable=self.source_encoding, values=ENCODINGS,
                     width=10).pack(side="left", padx=(6, 16))
        ttk.Label(enc, text="译文编码").pack(side="left")
        ttk.Combobox(enc, textvariable=self.target_encoding, values=ENCODINGS,
                     width=10).pack(side="left", padx=6)
        checks = ttk.Frame(box)
        checks.pack(fill="x", padx=8, pady=(0, 4))
        ttk.Label(checks, text="", width=12).pack(side="left")
        ttk.Checkbutton(checks, text="双行文本（翻译用）", variable=self.want_texts,
                        command=self._sync).pack(side="left")
        ttk.Checkbutton(checks, text="ASM 清单（改逻辑用）", variable=self.want_asm,
                        command=self._sync).pack(side="left", padx=14)
        ttk.Checkbutton(checks, text="导出 IR（排查用）",
                        variable=self.want_ir).pack(side="left")
        self.export_button = ttk.Button(box, text="输 出 文 本", command=self._do_export)
        self.export_button.pack(anchor="e", padx=8, pady=(0, 8))

        box = ttk.LabelFrame(self, text="回封脚本")
        box.pack(fill="x", **pad)
        self._row(box, "译文目录", self.repack_from, "dir")
        self._row(box, "脚本输出到", self.repack_out, "dir")
        self.repack_button = ttk.Button(box, text="回 封 脚 本", command=self._do_repack)
        self.repack_button.pack(anchor="e", padx=8, pady=(0, 8))

        box = ttk.LabelFrame(self, text="封包（.noa）")
        box.pack(fill="x", **pad)
        self._row(box, "封包文件", self.archive, "file",
                  [("EntisGLS 封包", "*.noa"), ("所有文件", "*.*")], self._on_archive)
        self._row(box, "内容目录", self.archive_dir, "dir")
        self._row(box, "封包输出到", self.pack_out, "file",
                  [("EntisGLS 封包", "*.noa")])
        row = ttk.Frame(box)
        row.pack(fill="x", padx=8, pady=4)
        ttk.Label(row, text="密码", width=12, anchor="w").pack(side="left")
        ttk.Entry(row, textvariable=self.password, width=24).pack(side="left", padx=6)
        ttk.Label(row, textvariable=self.key_hint, foreground="#555").pack(side="left")
        buttons = ttk.Frame(box)
        buttons.pack(anchor="e", padx=8, pady=(0, 8))
        self.unpack_button = ttk.Button(buttons, text="解 包", command=self._do_unpack)
        self.unpack_button.pack(side="left", padx=(0, 6))
        self.pack_button = ttk.Button(buttons, text="封 包", command=self._do_pack)
        self.pack_button.pack(side="left")

        self.bar = ttk.Progressbar(self, mode="determinate")
        self.bar.pack(fill="x", padx=10)
        ttk.Label(self, textvariable=self.status, anchor="w",
                  wraplength=720, justify="left").pack(fill="x", padx=10, pady=(4, 0))

        self.detail_box = ttk.LabelFrame(self, text="详情")
        tk.Message(self.detail_box, textvariable=self.details, width=700,
                   justify="left", anchor="w").pack(fill="x", padx=8, pady=6)
        self.detail_open = False
        self.detail_toggle = ttk.Button(self, text="▸ 详情", command=self._toggle_details)
        self.detail_toggle.pack(anchor="w", padx=10, pady=6)

        for var in (self.script_input, self.text_out, self.repack_from,
                    self.repack_out, self.archive, self.archive_dir, self.pack_out):
            var.trace_add("write", lambda *_: self._sync())
        self._sync()

    def _row(self, parent, label, variable, kind="dir", filetypes=None, on_change=None):
        row = PathRow(parent, label, variable, kind, filetypes, on_change)
        row.pack(fill="x", padx=8, pady=4)
        self._rows.append(row)
        return row

    # ------------------------------------------------------------ 拖放
    def _install_dnd(self) -> None:
        """把每个路径框注册为独立的拖放目标。

        windnd 只能按窗口句柄挂钩，所以这里对每一栏各挂一次；拖到哪个控件上，
        就只有那一栏被改写，其余路径保持不动。
        """
        try:
            import windnd
        except ImportError:
            self.status.set("未安装 windnd，拖放不可用；请用「浏览…」选择路径。")
            return
        for row in self._rows:
            for widget in row.drop_targets():
                windnd.hook_dropfiles(
                    widget, func=lambda files, r=row: self._on_drop(r, files))

    def _on_drop(self, row: PathRow, files) -> None:
        if not files:
            return
        path = Path(files[0].decode("mbcs", errors="replace"))
        row.set(path)
        self.status.set(f"已设置 {row.variable.get()}")

    # --------------------------------------------------- 联动（只在留空时填写）
    def _on_script(self) -> None:
        path = Path(self.script_input.get())
        if not path.exists():
            return
        base = path.parent if path.is_file() else path
        stem = path.stem if path.is_file() else path.name
        if not self.text_out.get():
            self.text_out.set(str(base / f"{stem}_text"))
        if not self.repack_from.get():
            self.repack_from.set(self.text_out.get())
        if not self.repack_out.get():
            self.repack_out.set(str(base / f"{stem}_rebuilt"))

    def _on_archive(self) -> None:
        path = Path(self.archive.get())
        if not path.is_file():
            return
        known = noa.known_password(path)
        self.key_hint.set("已内置此封包的密钥" if known else "未加密或密钥未知")
        if not self.archive_dir.get():
            self.archive_dir.set(str(path.parent / f"{path.stem}_files"))
        if not self.pack_out.get():
            self.pack_out.set(str(path.parent / f"{path.stem}_rebuilt{path.suffix}"))

    def _toggle_details(self) -> None:
        self.detail_open = not self.detail_open
        if self.detail_open:
            self.detail_box.pack(fill="x", padx=10, pady=(0, 8))
            self.detail_toggle.configure(text="▾ 详情")
        else:
            self.detail_box.pack_forget()
            self.detail_toggle.configure(text="▸ 详情")

    def _sync(self) -> None:
        def has_dir(var):
            return bool(var.get()) and Path(var.get()).is_dir()

        scripts = find_scripts(Path(self.script_input.get())) if self.script_input.get() else []
        ready = bool(scripts) and not self._busy
        chosen = self.want_texts.get() or self.want_asm.get()
        self.export_button.state(["!disabled"] if ready and chosen and self.text_out.get()
                                 else ["disabled"])
        self.repack_button.state(
            ["!disabled"] if ready and has_dir(self.repack_from) and self.repack_out.get()
            and not self._busy else ["disabled"])

        archive = Path(self.archive.get()) if self.archive.get() else None
        has_archive = bool(archive and archive.is_file()) and not self._busy
        self.unpack_button.state(["!disabled"] if has_archive and self.archive_dir.get()
                                 else ["disabled"])
        self.pack_button.state(["!disabled"] if has_dir(self.archive_dir)
                               and self.pack_out.get() and not self._busy else ["disabled"])

    # ------------------------------------------------------------- 执行
    def _start(self, worker, total: int = 1) -> None:
        self._busy = True
        self._sync()
        self.bar.configure(value=0, maximum=max(total, 1))
        threading.Thread(target=worker, daemon=True).start()

    def _post(self, kind: str, payload) -> None:
        self._queue.put((kind, payload))

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "progress":
                    done, label = payload
                    self.bar.configure(value=done)
                    self.status.set(label)
                elif kind == "details":
                    self.details.set(payload)
                elif kind == "done":
                    self.status.set(payload)
                    self._busy = False
                    self._sync()
                elif kind == "error":
                    self.status.set("✗ " + payload)
                    self.details.set(payload)
                    self._busy = False
                    self._sync()
                    if not self.detail_open:
                        self._toggle_details()
        except queue.Empty:
            pass
        self.after(120, self._drain)

    def _do_export(self) -> None:
        scripts = find_scripts(Path(self.script_input.get()))
        out_root = Path(self.text_out.get())
        want_texts, want_asm = self.want_texts.get(), self.want_asm.get()
        want_ir = self.want_ir.get()

        def worker() -> None:
            entries = 0
            tags: dict[str, int] = {}
            failures: list[str] = []
            lines: list[str] = []
            for index, script in enumerate(scripts, start=1):
                self._post("progress", (index - 1, f"正在读取 {script.name}"))
                try:
                    report = disassembler.export(script, out_root, want_texts=want_texts,
                                                 want_asm=want_asm, with_ir=want_ir)
                    verify = assembler.rebuild(script, None,
                                               out_root / "_selfcheck" / script.name)
                    if not verify["identity"]:
                        failures.append(f"{script.name}：往返自检未通过，此脚本不支持回封")
                        continue
                    entries += report["exported_entries"]
                    for tag, count in report["tag_counts"].items():
                        tags[tag] = tags.get(tag, 0) + count
                    policy = report["translate_policy_counts"]
                    source = report["tag_source_counts"]
                    lines.append(
                        f"{script.name}  {report['source_size']:,} 字节\n"
                        f"  文本 {report['exported_entries']:,} 条："
                        f"可翻译 {policy.get('translatable', 0):,} / "
                        f"需确认 {policy.get('review-required', 0):,} / "
                        f"锁定 {policy.get('frozen', 0):,}\n"
                        f"  来源：锚点 {source.get('anchor', 0):,} / "
                        f"结构 {source.get('structural', 0):,} / "
                        f"未判定 {source.get('unresolved', 0):,}\n"
                        f"  说话者绑定 {report['name_bindings']:,}\n"
                        f"  覆盖 逐字节一致，往返自检通过")
                except Exception as exc:
                    failures.append(f"{script.name}：{exc}")
                self._post("progress", (index, f"已处理 {script.name}"))
            self._post("details", "\n\n".join(lines) if lines else "本次没有成功的产物。")
            summary = f"✓ 已导出 {entries:,} 条到 {out_root}"
            if tags:
                summary += "（" + " / ".join(f"{k} {v:,}" for k, v in sorted(tags.items())) + "）"
            if failures:
                summary += f"；{len(failures)} 个失败：" + "；".join(failures[:2])
            self._post("done", summary)

        self._start(worker, len(scripts))

    def _do_repack(self) -> None:
        scripts = find_scripts(Path(self.script_input.get()))
        from_root = Path(self.repack_from.get())
        out_root = Path(self.repack_out.get())

        def worker() -> None:
            written = 0
            changed = 0
            failures: list[str] = []
            for index, script in enumerate(scripts, start=1):
                self._post("progress", (index - 1, f"正在回封 {script.name}"))
                candidate = from_root / "texts" / f"{script.name}.txt"
                texts = candidate if candidate.is_file() else None
                try:
                    result = assembler.rebuild(script, texts, out_root / script.name)
                    changed += result["changed_entries"]
                    written += 1
                except Exception as exc:
                    failures.append(f"{script.name}：{exc}")
                self._post("progress", (index, f"已回封 {script.name}"))
            summary = f"✓ 已回封 {written} 个脚本到 {out_root}，改动 {changed:,} 条译文"
            if failures:
                summary += f"；{len(failures)} 个失败：" + "；".join(failures[:2])
            self._post("done", summary)

        self._start(worker, len(scripts))

    def _do_unpack(self) -> None:
        archive = Path(self.archive.get())
        target = Path(self.archive_dir.get())
        password = self.password.get() or None

        def worker() -> None:
            self._post("progress", (0, f"正在解包 {archive.name}"))
            try:
                result = noa.extract(archive, target, password,
                                     self.source_encoding.get())
            except Exception as exc:
                self._post("error", f"解包失败：{exc}")
                return
            self._post("details",
                       f"封包 {archive}\n"
                       f"  条目 {result['entries']:,}   已解出 {result['extracted']:,}\n"
                       f"  存储方式 {', '.join(result['encryption_kinds'])}\n"
                       + (f"  未解出 {len(result['failed']):,} 个："
                          + "；".join(f"{f['name']}（{f['encryption']}）"
                                     for f in result["failed"][:5])
                          if result["failed"] else "  全部解出"))
            summary = f"✓ 已解出 {result['extracted']:,}/{result['entries']:,} 个文件到 {target}"
            if result["failed"]:
                summary += f"；{len(result['failed'])} 个未能解出，详情里有原因"
            self._post("progress", (1, ""))
            self._post("done", summary)

        self._start(worker)

    def _do_pack(self) -> None:
        source = Path(self.archive_dir.get())
        output = Path(self.pack_out.get())
        password = self.password.get() or None
        if password is None and self.archive.get():
            password = noa.known_password(Path(self.archive.get()))

        def worker() -> None:
            count = len([p for p in source.iterdir() if p.is_file()])
            self._post("progress", (0, f"正在封包 {count:,} 个文件…"))
            try:
                result = noa.pack_with_engine(source, output, password)
            except Exception as exc:
                self._post("error", f"封包失败：{exc}")
                return
            self._post("details",
                       f"封包输出 {output}\n"
                       f"  条目 {result['entries']:,}\n"
                       f"  大小 {result['output_size']:,} 字节\n"
                       f"  存储方式 {result['encryption']}\n"
                       f"  打包器 {result['packer']}\n"
                       "原封包未被修改，请自行复制回游戏目录。")
            self._post("progress", (1, ""))
            self._post("done", f"✓ 已封包 {result['entries']:,} 个文件到 {output.name}"
                               f"（{result['output_size']:,} 字节）")

        self._start(worker)


if __name__ == "__main__":
    App().mainloop()
