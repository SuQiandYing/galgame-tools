"""无 PySide6 环境下的 Tkinter 回退界面。

与 PySide6 窗口完全同构：拖入根目录，三个按钮，UI 线程不解析二进制。系统级拖放
需要 `tkinterdnd2`；缺失时拖放区仍可点击浏览，并会明确提示。
"""
from __future__ import annotations

from pathlib import Path
from tkinter import (BOTH, END, LEFT, X, BooleanVar, StringVar, Tk,
                     filedialog, messagebox, ttk)
from tkinter.scrolledtext import ScrolledText

from ..services import encodings
from ..services.jobs import JobRunner
from ..services.stages import StageService
from ..services.toolchain import TOOL_VERSION
from ..services.workspace import Workspace, find_scenario_files
from .worker import StageWorker


class TkApp:
    """三按钮阶段前端。"""

    def __init__(self, root: Tk) -> None:
        self.root = root
        self.inputs: list[str] = []
        self.files: list[Path] = []
        self.worker = StageWorker()
        root.title(f"PSB/SCN 反汇编与回封工具 {TOOL_VERSION}（tk）")
        root.geometry("820x600")
        self._build()
        self._pump()

    def _build(self) -> None:
        self.drop = ttk.Label(
            self.root, relief="ridge", anchor="center", padding=24,
            text="将存放 .scn 的文件夹拖到这里\n（也可以点击此处浏览）")
        self.drop.pack(fill=X, padx=10, pady=10)
        self.drop.bind("<Button-1>", lambda _e: self._browse())

        self.status_var = StringVar(value="尚未选择输入")
        ttk.Label(self.root, textvariable=self.status_var,
                  wraplength=780, justify="left").pack(fill=X, padx=10)

        enc = ttk.Frame(self.root)
        enc.pack(fill=X, padx=10, pady=(8, 0))
        ttk.Label(enc, text="源编码：").pack(side=LEFT)
        self.src_var = StringVar(value=encodings.DEFAULT_SOURCE)
        ttk.Combobox(enc, textvariable=self.src_var, width=12,
                     values=list(encodings.SOURCE_ENCODINGS)).pack(side=LEFT)
        ttk.Label(enc, text="    目标编码：").pack(side=LEFT)
        self.dst_var = StringVar(value=encodings.DEFAULT_TARGET)
        ttk.Combobox(enc, textvariable=self.dst_var, width=12,
                     values=list(encodings.TARGET_ENCODINGS)).pack(side=LEFT)

        # 两个可选项，只影响①。默认与不勾时行为完全一致。
        opts = ttk.Frame(self.root)
        opts.pack(fill=X, padx=10, pady=(6, 0))
        self.no_asm_var = BooleanVar(value=False)
        ttk.Checkbutton(opts, text="跳过 ASM 清单（更快、省几百 MB）",
                        variable=self.no_asm_var).pack(side=LEFT)
        self.with_ir_var = BooleanVar(value=False)
        ttk.Checkbutton(opts, text="同时导出 IR",
                        variable=self.with_ir_var).pack(side=LEFT, padx=(12, 0))

        row = ttk.Frame(self.root)
        row.pack(fill=X, padx=10, pady=8)
        for text, method in (("① 反汇编", "disassemble"),
                             ("② 提取文本", "extract_text"),
                             ("③ 回封", "repack_text")):
            ttk.Button(row, text=text,
                       command=lambda m=method, t=text: self._start(t, m)
                       ).pack(side=LEFT, expand=True, fill=X, padx=3)

        row2 = ttk.Frame(self.root)
        row2.pack(fill=X, padx=10)
        ttk.Button(row2, text="打开输出目录",
                   command=self._open_output).pack(side=LEFT)
        self.cancel_btn = ttk.Button(row2, text="取消", state="disabled",
                                     command=self.worker.cancel)
        self.cancel_btn.pack(side=LEFT, padx=4)

        self.progress = ttk.Progressbar(self.root, maximum=100)
        self.progress.pack(fill=X, padx=10, pady=6)
        self.log = ScrolledText(self.root, height=18, font=("Consolas", 9))
        self.log.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))

        # 日志控件建好之后才启用拖放：缺少 tkdnd 时这里会往日志里写提示。
        self._enable_dnd()

    def _enable_dnd(self) -> None:
        try:
            self.root.tk.call("package", "require", "tkdnd")
            self.drop.drop_target_register("DND_Files")  # type: ignore[attr-defined]
            self.drop.dnd_bind("<<Drop>>", self._on_dnd)  # type: ignore[attr-defined]
        except Exception:
            self._log("系统级拖放不可用（缺少 tkinterdnd2）；请点击拖放区浏览")

    def _on_dnd(self, event) -> None:
        paths = [p for p in self.root.tk.splitlist(event.data) if p]
        if paths:
            self._set_inputs(paths)

    # -- 输入 -----------------------------------------------------------
    def _browse(self) -> None:
        folder = filedialog.askdirectory(title="选择存放 .scn 的文件夹")
        if folder:
            self._set_inputs([folder])

    def _set_inputs(self, paths: list[str]) -> None:
        self.inputs = paths
        self.files = find_scenario_files(paths)
        if not self.files:
            self.status_var.set("在所选位置未找到 PSB 剧本文件"
                                "（已按 PSB\\0 签名递归检查）")
            self._log("未找到任何 PSB 文件")
            return
        ws = Workspace.beside(paths[0])
        self.status_var.set(f"已找到 {len(self.files)} 个 .scn 文件\n"
                            f"输入：{paths[0]}\n输出：{ws.root}")
        self._log(f"已找到 {len(self.files)} 个文件，输出目录 {ws.root}")

    def _open_output(self) -> None:
        if not self.inputs:
            messagebox.showinfo("提示", "请先选择输入。")
            return
        out = Workspace.beside(self.inputs[0]).root
        if not out.exists():
            messagebox.showinfo("提示", f"输出目录还不存在：\n{out}\n"
                                        "请先运行任意一个操作。")
            return
        import webbrowser
        webbrowser.open(out.as_uri())

    # -- 操作 -----------------------------------------------------------
    def _start(self, label: str, method: str) -> None:
        if self.worker.busy:
            messagebox.showinfo("忙碌中", "已有任务正在运行。")
            return
        if not self.files:
            messagebox.showwarning("没有输入", "请先拖入存放 .scn 的文件夹。")
            return
        try:
            src = encodings.check(self.src_var.get().strip())
            dst = encodings.check(self.dst_var.get().strip())
        except ValueError as exc:
            messagebox.showwarning("编码无效", str(exc))
            return
        inputs = list(self.inputs)

        extra: dict[str, bool] = {}
        if method == "disassemble":
            extra = {"write_asm": not self.no_asm_var.get(),
                     "write_ir": self.with_ir_var.get()}

        def job(svc: StageService, cancelled):
            runner = JobRunner(svc)
            return getattr(runner, method)(
                inputs, encoding=src, target_encoding=dst,
                cancel=cancelled, **extra).as_stage_result()

        if self.worker.submit(label, job):
            self.cancel_btn.config(state="normal")
            self._log(f"开始{label}：{len(self.files)} 个文件"
                      f"（源编码 {src} → 目标编码 {dst}）")

    # -- 事件泵 ---------------------------------------------------------
    def _pump(self) -> None:
        for event in self.worker.drain():
            if event.kind == "progress":
                self.progress["value"] = event.fraction * 100
            elif event.kind == "failed":
                self._log(f"任务出错：{event.message}")
                messagebox.showerror("任务失败", event.message)
            elif event.kind in ("finished", "cancelled"):
                self.progress["value"] = 100
                self._report(event)
        if not self.worker.busy:
            self.cancel_btn.config(state="disabled")
        self.root.after(120, self._pump)

    def _report(self, event) -> None:
        data = event.payload.get("data", {})
        rows = data.get("rows", [])          # 只含失败/跳过行
        total = data.get("row_count", data.get("total", 0))
        ok = data.get("succeeded", 0)
        failed = data.get("failed", 0)
        skipped = data.get("skipped", 0) or sum(
            1 for r in rows if r.get("status") == "skipped")
        self._log(f"{event.stage}完成：{total} 个文件，成功 {ok}"
                  f"，跳过 {skipped}，失败 {failed}"
                  + ("（已取消）" if data.get("cancelled") else ""))
        if event.stage == "反汇编" and ok:
            self._log(
                f"零编辑往返："
                f"{'全部逐字节一致' if data.get('all_zero_edit_identical') else '存在不一致'}"
                f"；最低覆盖率 {data.get('min_byte_coverage', 0):.4f}")
        elif event.stage == "提取文本" and ok:
            self._log(f"共 {data.get('units', 0):,} 条文本，"
                      f"目标编码 {data.get('target_encoding', '?')}")
        elif event.stage == "回封":
            if data.get("error"):
                self._log(data["error"])
            elif ok:
                self._log(f"应用译文 {data.get('changed_entries', 0):,} 条，"
                          f"合计长度变化 {data.get('total_delta_bytes', 0):+,} 字节")
        for r in rows:
            if r.get("status") == "failed":
                self._log(f"  失败 {r['sample']}：{r['error']}")
            elif r.get("status") == "skipped":
                self._log(f"  跳过 {r['sample']}：{r['skipped']}")
        if failed + skipped > len(rows):
            self._log("  （还有更多，详见报告文件）")
        for name, path in event.payload.get("artifacts", {}).items():
            self._log(f"{name}：{path}")

    def _log(self, message: str) -> None:
        self.log.insert(END, message + "\n")
        self.log.see(END)


def run() -> int:
    try:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
    except Exception:
        root = Tk()
    TkApp(root)
    root.mainloop()
    return 0
