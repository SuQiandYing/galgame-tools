from __future__ import annotations

import json
import os
import queue
import threading
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from hcb_tool.services.disassemble_service import DisassembleService
from hcb_tool.services.export_service import ExportDoubleLineService
from hcb_tool.services.import_service import ImportDoubleLineService
from hcb_tool.services.chapter_service import ExportChapterTextService, ImportChapterTextService
from hcb_tool.services.hcb_source import PROJECT_IR_NAME

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD  # type: ignore
    HAS_DND = True
except Exception:  # pragma: no cover
    DND_FILES = None
    TkinterDnD = None
    HAS_DND = False


def _split_drop_files(data: str) -> list[str]:
    root = tk.Tcl()
    try:
        return list(root.splitlist(data))
    finally:
        try:
            root.destroy()
        except Exception:
            pass


class MainWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("HCB Tool v0.3.2 - 反汇编提取工作流")
        self.root.geometry("1040x720")
        self.queue: queue.Queue[str] = queue.Queue()
        self.hcb_path = tk.StringVar()
        self.work_dir = tk.StringVar(value=str(Path.cwd() / "hcb_work"))
        self.encoding = tk.StringVar(value="cp932")
        self._build()
        self._poll()

    def opts(self) -> dict:
        return {"encoding": self.encoding.get().strip() or "cp932"}

    def path_hcb(self) -> Path:
        p = Path(self.hcb_path.get())
        if not p.is_file():
            raise ValueError("请先选择原始 .hcb 文件")
        return p

    def path_work(self) -> Path:
        p = Path(self.work_dir.get())
        p.mkdir(parents=True, exist_ok=True)
        return p

    def suggest_from_hcb(self, hcb: str | Path) -> None:
        p = Path(hcb)
        if p.suffix.lower() == ".hcb":
            self.hcb_path.set(str(p))
            self.work_dir.set(str(p.parent / f"{p.stem}_工程"))
            self._refresh_preview()
            self.log_line(f"[AUTO] 已选择 HCB：{p}")
            self.log_line(f"[AUTO] 工程目录：{self.work_dir.get()}")

    def _build(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(4, weight=1)
        outer = ttk.Frame(self.root, padding=12)
        outer.grid(sticky="nsew")
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(4, weight=1)

        title = ttk.Label(outer, text="HCB 工具：先全量反汇编/建立工程，再从反汇编结果提取文本/章节/人名/选项", font=("Segoe UI", 14, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 8))

        form = ttk.LabelFrame(outer, text="工程设置：所有过程都放在同一个工程目录里", padding=8)
        form.grid(row=1, column=0, sticky="ew", pady=4)
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text="原始 HCB").grid(row=0, column=0, sticky="w", pady=3)
        hcb_ent = ttk.Entry(form, textvariable=self.hcb_path)
        hcb_ent.grid(row=0, column=1, sticky="ew", padx=6, pady=3)
        ttk.Button(form, text="选择/自动填充", command=self.pick_hcb).grid(row=0, column=2, pady=3)
        ttk.Label(form, text="工程目录").grid(row=1, column=0, sticky="w", pady=3)
        work_ent = ttk.Entry(form, textvariable=self.work_dir)
        work_ent.grid(row=1, column=1, sticky="ew", padx=6, pady=3)
        ttk.Button(form, text="选择", command=self.pick_work).grid(row=1, column=2, pady=3)
        ttk.Button(form, text="打开", command=self.open_work).grid(row=1, column=3, padx=(6, 0), pady=3)
        ttk.Label(form, text="自定义编码").grid(row=2, column=0, sticky="w", pady=3)
        enc = ttk.Combobox(form, textvariable=self.encoding, values=["cp932", "shift_jis", "utf-8", "utf-16le", "gbk"], width=16)
        enc.grid(row=2, column=1, sticky="w", padx=6, pady=3)
        ttk.Label(form, text="默认 cp932；改编码会影响提取显示和回封编码").grid(row=2, column=2, columnspan=2, sticky="w")
        if HAS_DND:
            hcb_ent.drop_target_register(DND_FILES)  # type: ignore[arg-type]
            hcb_ent.dnd_bind("<<Drop>>", self.on_drop_hcb)  # type: ignore[attr-defined]
            work_ent.drop_target_register(DND_FILES)  # type: ignore[arg-type]
            work_ent.dnd_bind("<<Drop>>", self.on_drop_work)  # type: ignore[attr-defined]

        preview = ttk.LabelFrame(outer, text="自动输出位置", padding=8)
        preview.grid(row=2, column=0, sticky="ew", pady=4)
        preview.columnconfigure(1, weight=1)
        self.preview_vars = {k: tk.StringVar() for k in ["disasm", "project_ir", "text", "chapters", "patch_text", "patch_chapters"]}
        labels = [("反汇编目录", "disasm"), ("反汇编IR", "project_ir"), ("提取文本", "text"), ("章节文本", "chapters"), ("按文本回封", "patch_text"), ("按章节回封", "patch_chapters")]
        for i, (lab, key) in enumerate(labels):
            ttk.Label(preview, text=lab).grid(row=i, column=0, sticky="w")
            ttk.Label(preview, textvariable=self.preview_vars[key]).grid(row=i, column=1, sticky="w")

        actions = ttk.LabelFrame(outer, text="操作", padding=8)
        actions.grid(row=3, column=0, sticky="ew", pady=4)
        for c in range(5):
            actions.columnconfigure(c, weight=1)
        ttk.Button(actions, text="全量反汇编/建立工程", command=self.run_disasm).grid(row=0, column=0, sticky="ew", padx=3)
        ttk.Button(actions, text="提取文本", command=self.run_export_text).grid(row=0, column=1, sticky="ew", padx=3)
        ttk.Button(actions, text="提取章节文本", command=self.run_export_chapters).grid(row=0, column=2, sticky="ew", padx=3)
        ttk.Button(actions, text="按文本回封", command=self.run_import_text).grid(row=0, column=3, sticky="ew", padx=3)
        ttk.Button(actions, text="按章节回封", command=self.run_import_chapters).grid(row=0, column=4, sticky="ew", padx=3)
        ttk.Label(actions, text="提取来源固定为反汇编工程 project_ir.json：不再绕过反汇编直接读 HCB。", foreground="#444").grid(row=1, column=0, columnspan=5, sticky="w", pady=(8, 0))

        logframe = ttk.LabelFrame(outer, text="日志 / hash 校验", padding=8)
        logframe.grid(row=4, column=0, sticky="nsew", pady=4)
        logframe.columnconfigure(0, weight=1)
        logframe.rowconfigure(0, weight=1)
        self.log = tk.Text(logframe, wrap="word")
        self.log.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(logframe, command=self.log.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scroll.set)

        bottom = ttk.Frame(outer)
        bottom.grid(row=5, column=0, sticky="ew")
        ttk.Button(bottom, text="保存日志", command=self.save_log).pack(side="left")
        ttk.Button(bottom, text="清空日志", command=lambda: self.log.delete("1.0", "end")).pack(side="left", padx=6)
        ttk.Label(bottom, text=("拖拽 ON" if HAS_DND else "拖拽组件未安装：用选择按钮"), foreground=("green" if HAS_DND else "#885500")).pack(side="right")
        self._refresh_preview()

    def _project_dir(self) -> Path:
        h = Path(self.hcb_path.get()) if self.hcb_path.get() else Path("<hcb>")
        w = Path(self.work_dir.get()) if self.work_dir.get() else Path("<工程目录>")
        return w / "disasm" / h.stem

    def _project_ir_path(self) -> Path:
        return self._project_dir() / PROJECT_IR_NAME

    def _require_project_ir(self) -> Path:
        p = self._project_ir_path()
        if not p.is_file():
            raise FileNotFoundError(f"找不到反汇编工程IR：{p}。请先点『全量反汇编/建立工程』，再提取文本/章节。")
        return p

    def _refresh_preview(self) -> None:
        h = Path(self.hcb_path.get()) if self.hcb_path.get() else Path("<hcb>")
        w = Path(self.work_dir.get()) if self.work_dir.get() else Path("<工程目录>")
        self.preview_vars["disasm"].set(str(self._project_dir()))
        self.preview_vars["project_ir"].set(str(self._project_ir_path()))
        self.preview_vars["text"].set(str(w / "doubleline.txt"))
        self.preview_vars["chapters"].set(str(w / "chapters"))
        self.preview_vars["patch_text"].set(str(w / "patched_by_text" / h.name))
        self.preview_vars["patch_chapters"].set(str(w / "patched_by_chapters" / h.name))

    def pick_hcb(self) -> None:
        f = filedialog.askopenfilename(filetypes=[("HCB", "*.hcb"), ("All", "*.*")])
        if f:
            self.suggest_from_hcb(f)

    def pick_work(self) -> None:
        folder = filedialog.askdirectory(initialdir=self.work_dir.get() or str(Path.cwd()))
        if folder:
            self.work_dir.set(folder)
            self._refresh_preview()

    def open_work(self) -> None:
        p = self.path_work()
        try:
            os.startfile(str(p))  # type: ignore[attr-defined]
        except Exception:
            messagebox.showinfo("工程目录", str(p))

    def on_drop_hcb(self, event) -> None:  # pragma: no cover
        items = _split_drop_files(event.data)
        if items:
            self.suggest_from_hcb(items[0])

    def on_drop_work(self, event) -> None:  # pragma: no cover
        items = _split_drop_files(event.data)
        if items:
            self.work_dir.set(items[0])
            self._refresh_preview()

    def _run_worker(self, title: str, fn) -> None:
        def worker():
            self.queue.put(f"[START] {title}")
            try:
                result = fn()
                self.queue.put(f"[DONE] {title}\n{self._summary(result)}")
            except Exception:
                self.queue.put("[ERROR]\n" + traceback.format_exc())
        threading.Thread(target=worker, daemon=True).start()

    def _summary(self, result) -> str:
        try:
            verify = None
            if isinstance(result, dict):
                verify = result.get("verify") or result.get("repack", {}).get("verify")
                if verify:
                    r = verify.get("result", {})
                    status = r.get("status")
                    same = r.get("bytes_equal") and r.get("sha256_equal")
                    line = "原地回封校验：与原文件哈希值一模一样" if same else "原地回封校验：与原文件不一致"
                    return json.dumps(result, ensure_ascii=False, indent=2) + f"\n{line}\nstatus={status} bytes_equal={r.get('bytes_equal')} sha256_equal={r.get('sha256_equal')}"
            return json.dumps(result, ensure_ascii=False, indent=2, default=str)
        except Exception:
            return str(result)

    def run_disasm(self) -> None:
        def task():
            h = self.path_hcb()
            w = self.path_work()
            self._refresh_preview()
            return DisassembleService().run([h], w / "disasm", {**self.opts(), "mode": "lean"})
        self._run_worker("全量反汇编/建立工程", task)

    def run_export_text(self) -> None:
        def task():
            h = self.path_hcb()
            w = self.path_work()
            self._refresh_preview()
            project_ir = self._require_project_ir()
            return ExportDoubleLineService().run(project_ir, w / "doubleline.txt", {**self.opts(), "require_project_ir": True})
        self._run_worker("提取文本 all -> doubleline.txt", task)

    def run_export_chapters(self) -> None:
        def task():
            h = self.path_hcb()
            w = self.path_work()
            self._refresh_preview()
            project_ir = self._require_project_ir()
            return ExportChapterTextService().run(project_ir, w / "chapters", {**self.opts(), "require_project_ir": True})
        self._run_worker("按章节 opcode 提取章节文本", task)

    def run_import_text(self) -> None:
        def task():
            h = self.path_hcb()
            w = self.path_work()
            self._refresh_preview()
            txt = w / "doubleline.txt"
            if not txt.is_file():
                raise FileNotFoundError(f"找不到 {txt}，请先点 提取文本")
            project_ir = self._require_project_ir()
            return ImportDoubleLineService().run(project_ir, txt, w / "patched_by_text", {**self.opts(), "require_project_ir": True})
        self._run_worker("按文本回封", task)

    def run_import_chapters(self) -> None:
        def task():
            h = self.path_hcb()
            w = self.path_work()
            self._refresh_preview()
            chapters = w / "chapters"
            if not chapters.is_dir():
                raise FileNotFoundError(f"找不到 {chapters}，请先点 提取章节文本")
            project_ir = self._require_project_ir()
            return ImportChapterTextService().run(project_ir, chapters, w / "patched_by_chapters", {**self.opts(), "require_project_ir": True})
        self._run_worker("按章节回封", task)

    def save_log(self) -> None:
        f = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if f:
            Path(f).write_text(self.log.get("1.0", "end"), encoding="utf-8")

    def log_line(self, msg: str) -> None:
        try:
            self.log.insert("end", msg + "\n")
            self.log.see("end")
        except Exception:
            pass

    def _poll(self) -> None:
        try:
            while True:
                self.log_line(self.queue.get_nowait())
        except queue.Empty:
            pass
        self.root.after(150, self._poll)


def main() -> None:
    root = TkinterDnD.Tk() if HAS_DND else tk.Tk()  # type: ignore[union-attr]
    MainWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()
