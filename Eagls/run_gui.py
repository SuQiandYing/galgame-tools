"""三按钮图形界面：反汇编 → 提取文本 → 回封（§11）。

    python run_gui.py

界面服务于「拿到游戏文件 → 翻译 → 装回去」的使用者，不是给逆向工程师的控制台：
不暴露 tier / unpack_mode / repack_strategy 等内部概念，策略由 probe 自动协商，
错误用自然语言呈现，技术细节收进「详情」与 logs/。
"""

from __future__ import annotations

import json
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

import assembler as A
import disassembler as D
import profile_scpack as P

try:                                    # 拖放是可选依赖：缺失时降级为「选择文件」
    from tkinterdnd2 import DND_FILES, TkinterDnD
    _DND = True
except ImportError:                     # pragma: no cover - 取决于环境
    _DND = False

_ENCODINGS = ("cp932", "gbk", "big5", "cp949", "utf-8")
_CONFIG = Path.home() / ".eagls_ulru_gui.json"

# 界面尺寸与轮询间隔属于视图参数，不是引擎方言（§8.4 advisory 需人工判断）。
_WINDOW = "760x560"
_MIN_SIZE = (680, 520)          # dialect-literal-ok 窗口最小尺寸，非引擎常量
_POLL_MS = 80                   # dialect-literal-ok 队列轮询间隔，非扫描窗口
_WRAP_PX = 700                  # dialect-literal-ok 状态文字折行宽度
_DETAIL_CHARS = 4000            # dialect-literal-ok 详情区每份报告的截断长度


def _load_config() -> dict[str, Any]:
    try:
        return json.loads(_CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_config(data: dict[str, Any]) -> None:
    try:
        _CONFIG.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                           encoding="utf-8")
    except OSError:
        pass                            # 配置写不进去不该阻断工作流


# ---------------------------------------------------------------------------
# 自然语言错误信息（§11.1）：报「第 N 条译文超长 X 字节」，不报 reason_code
# ---------------------------------------------------------------------------
_FRIENDLY = {
    "ARCHIVE_MISSING": "这个目录里没找到 SCPACK.idx 和 SCPACK.pak，"
                       "请把游戏的 Script 文件夹拖进来。",
    "IDX_KEY_UNRESOLVED": "无法解开这个归档的索引加密，可能不是 EAGLS 引擎的文件。",
    "PAK_KEY_UNRESOLVED": "无法解开脚本正文的加密，可能不是 EAGLS 引擎的文件。",
    "BODY_UNDECODABLE": "脚本文字用当前的原文编码读不出来，换一个原文编码试试。",
    "TEXT_OFFSET_DISAGREEMENT": "各脚本文件的正文起点不一致，这个版本暂不支持。",
    "SOURCE_CHANGED": "游戏文件和上次反汇编时不一样了，请重新点第 ① 步。",
    "IR_MISSING": "还没有反汇编结果，请先点第 ① 步。",
    "SRC_HASH_MISMATCH": "译文文件对应的是另一份反汇编结果，请重新点 ① 再导出译文。",
    "SOURCE_ANCHOR": "有译文文件的原文行被改动了。原文行是对照用的，只能改下面那行。",
    "EMPTY_TRANSLATION": "有一条译文被清空了。留空会把空白写进游戏；"
                         "不翻译就保留原文即可。",
    "FROZEN_MODIFIED": "有一条被锁定的内容被改动了 —— 它是脚本内部名称，改了游戏会出错。",
    "PLACEHOLDER_BROKEN": "译文里的 {{XX}} 标记被改坏了，请保持原样。",
    "EDIT_BREAKS_STRUCTURE": "译文里有引号或换行，会让脚本断行。请去掉。",
    "LABEL_LOST": "有一处脚本内部名称在译文里找不到了，请勿改动被锁定的内容。",
    "UNRESOLVED_JOIN_SITE": "这个作品的引用结构未完全解析，暂不支持改变文本长度。",
    "NO_APPLICABLE_STRATEGY": "没有可用的回封方式，详情里有每种方式被排除的原因。",
    "REPACK_VERIFY_FAILED": "回封后的自检没通过，已保留失败产物供诊断，"
                            "没有生成可放回游戏的文件。",
}


def friendly(exc: Exception) -> str:
    code = getattr(exc, "code", "")
    detail = getattr(exc, "detail", str(exc))
    if code == "ENCODING_UNREPRESENTABLE":
        return detail                   # 这条本身已经写成了自然语言并给出候选编码
    base = _FRIENDLY.get(code)
    if base is None:
        return detail
    return base


class Worker(threading.Thread):
    """解析在后台线程跑，UI 线程不读大文件、不解码、不等同步 I/O（§11.6）。"""

    def __init__(self, job: Callable[[Callable[[float, str], None]], Any],
                 sink: queue.Queue) -> None:
        super().__init__(daemon=True)
        self._job = job
        self._sink = sink

    def run(self) -> None:
        def progress(frac: float, note: str) -> None:
            self._sink.put(("progress", (frac, note)))
        try:
            self._sink.put(("done", self._job(progress)))
        except (A.ImportReject, P.ParseError) as exc:
            self._sink.put(("error", exc))
        except Exception as exc:        # 兜底：线程里的异常必须传回 UI，不能静默死掉
            self._sink.put(("error", exc))


_BASE = TkinterDnD.Tk if _DND else tk.Tk


class App(_BASE):                       # type: ignore[misc,valid-type]
    def __init__(self) -> None:
        super().__init__()
        self.title("EAGLS 脚本汉化工具")
        self.geometry(_WINDOW)
        self.minsize(*_MIN_SIZE)

        config = _load_config()
        self.script_dir: Path | None = None
        self.out_dir: Path | None = None
        self.queue: queue.Queue = queue.Queue()
        self.worker: Worker | None = None
        self.detail_text = ""

        self.var_source = tk.StringVar(value=config.get("source", "cp932"))
        self.var_target = tk.StringVar(value=config.get("target", "gbk"))
        self.var_out = tk.StringVar(value="")
        self.var_status = tk.StringVar(value="把游戏的 Script 文件夹拖进来，或点击选择")

        self._build()
        self.after(_POLL_MS, self._drain)

    # -- 布局（§11.2 单窗口，不用标签页、不用向导） -------------------------
    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        pad = {"padx": 14, "pady": 6}

        drop = tk.Label(self, height=5, relief="ridge", bd=2, justify="center",
                        text=("把文件或文件夹拖进来" if _DND else "点击下面的按钮选择文件夹")
                             + "\n\n需要 SCPACK.idx 与 SCPACK.pak")
        drop.grid(row=0, column=0, sticky="ew", **pad)
        if _DND:
            drop.drop_target_register(DND_FILES)
            drop.dnd_bind("<<Drop>>", self._on_drop)
        drop.bind("<Button-1>", lambda _event: self._choose())
        self.drop = drop

        picker = ttk.Frame(self)
        picker.grid(row=1, column=0, sticky="ew", **pad)
        ttk.Button(picker, text="选择游戏 Script 文件夹…",
                   command=self._choose).pack(side="left")
        self.lbl_path = ttk.Label(picker, text="未选择", foreground="#555")
        self.lbl_path.pack(side="left", padx=10)

        options = ttk.LabelFrame(self, text="编码")
        options.grid(row=2, column=0, sticky="ew", **pad)
        ttk.Label(options, text="原文编码").grid(row=0, column=0, padx=8, pady=6)
        ttk.Combobox(options, values=_ENCODINGS, textvariable=self.var_source,
                     width=10).grid(row=0, column=1)
        ttk.Label(options, text="译文编码").grid(row=0, column=2, padx=8)
        ttk.Combobox(options, values=_ENCODINGS, textvariable=self.var_target,
                     width=10).grid(row=0, column=3)
        ttk.Label(options, text="输出目录").grid(row=1, column=0, padx=8, pady=6)
        ttk.Entry(options, textvariable=self.var_out, width=52).grid(
            row=1, column=1, columnspan=3, sticky="ew")
        ttk.Button(options, text="浏览…", command=self._choose_out).grid(row=1, column=4,
                                                                       padx=6)
        options.columnconfigure(3, weight=1)

        steps = ttk.Frame(self)
        steps.grid(row=3, column=0, sticky="ew", **pad)
        steps.columnconfigure(0, weight=1)
        self.btn1 = ttk.Button(steps, text="①  全 量 反 汇 编",
                               command=self._run_disasm, state="disabled")
        self.btn2 = ttk.Button(steps, text="②  提 取 双 行 文 本",
                               command=self._open_texts, state="disabled")
        self.btn3 = ttk.Button(steps, text="③  回 封 文 本",
                               command=self._run_repack, state="disabled")
        for row, button in enumerate((self.btn1, self.btn2, self.btn3)):
            button.grid(row=row, column=0, sticky="ew", pady=3)

        self.bar = ttk.Progressbar(self, maximum=1.0)
        self.bar.grid(row=4, column=0, sticky="ew", **pad)
        ttk.Label(self, textvariable=self.var_status, wraplength=_WRAP_PX,
                  justify="left").grid(row=5, column=0, sticky="w", padx=14)

        actions = ttk.Frame(self)
        actions.grid(row=6, column=0, sticky="w", **pad)
        self.btn_open = ttk.Button(actions, text="打开输出目录",
                                   command=self._open_out, state="disabled")
        self.btn_open.pack(side="left")
        ttk.Button(actions, text="▸ 详情", command=self._show_detail).pack(side="left",
                                                                          padx=8)
        self.rowconfigure(7, weight=1)

    # -- 路径推导（§11.4 拖入后立刻确定全部路径） ---------------------------
    def _on_drop(self, event: Any) -> None:
        raw = event.data
        first = raw.split("} {")[0].strip("{} ") if raw.startswith("{") else raw.split()[0]
        self._accept(Path(first))

    def _choose(self) -> None:
        chosen = filedialog.askdirectory(title="选择游戏的 Script 文件夹")
        if chosen:
            self._accept(Path(chosen))

    def _choose_out(self) -> None:
        chosen = filedialog.askdirectory(title="选择输出目录")
        if chosen:
            self.var_out.set(chosen)

    def _accept(self, path: Path) -> None:
        path = path.resolve()
        folder = path if path.is_dir() else path.parent
        names = P.DIALECT["archive"]
        if not (folder / names["idx_name"]).is_file():
            self._fail(f"{folder} 里没找到 {names['idx_name']}，"
                       f"请选择游戏的 Script 文件夹。")
            return
        self.script_dir = folder
        self.out_dir = folder.parent / "output"
        self.var_out.set(str(self.out_dir))
        self.lbl_path.config(text=str(folder))
        size = (folder / names["pak_name"]).stat().st_size / 1024 / 1024
        self.drop.config(text=f"{folder.name}\n\n{names['idx_name']}   "
                              f"{names['pak_name']}  {size:.1f} MB")
        self.btn1.config(state="normal")
        # ② 必须由 ① 的往返自检点亮，不能因为目录里已有旧产物就放行（§11.3）。
        self.btn2.config(state="disabled")
        self.btn3.config(state="disabled")
        self.var_status.set("准备就绪，点 ① 开始。")

    # -- 三个按钮（§11.3） -------------------------------------------------
    def _run_disasm(self) -> None:
        if self.script_dir is None:
            return
        self.out_dir = Path(self.var_out.get() or (self.script_dir.parent / "output"))
        if (self.out_dir / "ir").exists() and not messagebox.askyesno(
                "输出目录已有内容",
                f"{self.out_dir} 下已有反汇编结果。\n\n"
                f"继续会覆盖它（原始游戏文件不会被改）。要继续吗？"):
            return
        self._busy()
        script_dir, out_dir = self.script_dir, self.out_dir
        source, target = self.var_source.get(), self.var_target.get()
        self._start(lambda progress: ("disasm", D.disassemble(
            script_dir, out_dir, source_encoding=source, target_encoding=target,
            progress=progress)))

    def _open_texts(self) -> None:
        """② 提取双行文本：从 ① 固化的 IR 投影出 texts/，然后打开目录。

        ① 只出 IR、asm 与证书，不出译文。分离的理由是：往返自检没通过时不该产出
        一份翻了两千条才发现装不回去的译文；译者也需要能在不重跑解析的情况下
        重新导出一份干净的译文（§11.3）。
        """
        if self.out_dir is None:
            return
        self._busy()
        out_dir = self.out_dir
        self._start(lambda progress: ("export", D.export_texts(out_dir, progress)))

    def _run_repack(self) -> None:
        if self.out_dir is None:
            return
        self._busy()
        out_dir, script_dir = self.out_dir, self.script_dir
        target = self.var_target.get()
        self._start(lambda progress: ("repack", A.repack(
            out_dir, script_dir, target_encoding=target, progress=progress)))

    def _start(self, job: Callable[[Callable[[float, str], None]], Any]) -> None:
        self.worker = Worker(job, self.queue)
        self.worker.start()

    def _busy(self) -> None:
        for button in (self.btn1, self.btn2, self.btn3):
            button.config(state="disabled")
        self.bar["value"] = 0
        self.var_status.set("正在处理…")

    # -- 结果处理 ----------------------------------------------------------
    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "progress":
                    frac, note = payload
                    self.bar["value"] = frac
                    self.var_status.set(note)
                elif kind == "error":
                    self._fail(friendly(payload))
                    self.detail_text = f"{type(payload).__name__}\n{payload}"
                else:
                    stage, summary = payload
                    {"disasm": self._after_disasm,
                     "export": self._after_export,
                     "repack": self._after_repack}[stage](summary)
        except queue.Empty:
            pass
        self.after(_POLL_MS, self._drain)

    def _after_disasm(self, summary: dict[str, Any]) -> None:
        self.btn1.config(state="normal")
        self.btn_open.config(state="normal")
        self.detail_text = self._detail(summary)
        _save_config({"source": self.var_source.get(), "target": self.var_target.get()})
        if summary["sanity_problems"]:
            self._fail("提取结果不合理，已停止：\n  "
                       + "\n  ".join(summary["sanity_problems"]))
            return
        if not summary["zero_edit_identical"]:
            # 最重要的一条：让使用者在还没开始翻译时就知道工具对这个游戏是否可靠。
            self._fail("这个游戏暂不支持回封 —— 未做任何修改的重建结果与原文件不一致，"
                       "说明解析还有缺陷。已停止，不会产出损坏的文件。")
            return
        translatable = summary["policy_counts"].get("translatable", 0)
        locked = summary["text_entries"] - translatable
        self.var_status.set(
            f"已完成，逐字节校验通过。解析出 {summary['text_entries']:,} 条文本："
            f"可翻译 {translatable:,} / 锁定 {locked:,}。\n"
            f"点 ② 导出可编辑的译文文件。")
        self.btn2.config(state="normal")
        # ③ 必须等 ② 导出译文之后才亮：texts/ 还不存在时点 ③ 只会撞上 NO_TEXTS。
        self.btn3.config(state="disabled")

    def _after_export(self, summary: dict[str, Any]) -> None:
        self.btn1.config(state="normal")
        self.btn2.config(state="normal")
        self.btn_open.config(state="normal")
        self.detail_text = self._detail(summary)
        if not summary["ok"]:
            self._fail("导出的条目数与 IR 不一致，已停止。详情里有具体数字。")
            return
        self.btn3.config(state="normal")
        self.var_status.set(
            f"已导出 {summary['text_entries']:,} 条到 texts/（{summary['files']} 个文件）："
            f"可翻译 {summary['translatable']:,} / 锁定 {summary['locked']:,}。\n"
            f"用任何编辑器改 ● 开头那行（○ 行是对照用的原文，不要改），改完回来点 ③。")
        self._reveal(Path(summary["texts_dir"]))

    def _after_repack(self, summary: dict[str, Any]) -> None:
        self.btn1.config(state="normal")
        self.btn2.config(state="normal")
        self.btn3.config(state="normal")
        self.btn_open.config(state="normal")
        self.detail_text = self._detail(summary)
        if not summary["ok"]:
            self._fail("回封自检未通过，没有生成可放回游戏的文件。详情里有失败项。")
            return
        delta = (summary.get("length_delta") or {}).get("actual", 0)
        changed = summary["changed_entries"]
        if changed == 0:
            self.var_status.set(
                "已生成，可放回游戏。（这次没有改动任何译文，"
                "输出与原文件完全相同。）")
        else:
            self.var_status.set(
                f"已生成，可放回游戏。改动 {changed:,} 条，"
                f"文件大小变化 {delta:+,} 字节。\n"
                f"把 rebuilt/ 里的两个文件复制回游戏目录即可。")

    def _fail(self, message: str) -> None:
        self.bar["value"] = 0
        self.var_status.set("× " + message)
        for button in (self.btn1,):
            button.config(state="normal" if self.script_dir else "disabled")

    # -- 详情折叠区（§11.7 只读信息，出问题时贴给开发者） -------------------
    def _detail(self, summary: dict[str, Any]) -> str:
        lines = [json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True)]
        if self.out_dir is not None:
            for name in ("coverage_certificate_pak.json", "repack_verdicts.json"):
                path = self.out_dir / "reports" / name
                if path.exists():
                    lines.append(f"\n--- reports/{name} ---")
                    lines.append(path.read_text(encoding="utf-8")[:_DETAIL_CHARS])
        return "\n".join(lines)

    def _show_detail(self) -> None:
        window = tk.Toplevel(self)
        window.title("详情")
        window.geometry("820x560")
        box = tk.Text(window, wrap="none", font=("Consolas", 9))
        box.pack(fill="both", expand=True, side="left")
        scroll = ttk.Scrollbar(window, command=box.yview)
        scroll.pack(fill="y", side="right")
        box.config(yscrollcommand=scroll.set)
        box.insert("1.0", self.detail_text or "还没有可显示的信息。")
        box.config(state="disabled")

    def _open_out(self) -> None:
        if self.out_dir is not None:
            self._reveal(self.out_dir)

    @staticmethod
    def _reveal(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        if sys.platform == "win32":
            import os
            os.startfile(path)          # type: ignore[attr-defined]
        else:
            import subprocess
            subprocess.Popen(["xdg-open" if sys.platform.startswith("linux")
                              else "open", str(path)])


def main() -> int:
    app = App()
    if not _DND:
        app.var_status.set("未安装 tkinterdnd2，拖放不可用；请用「选择游戏 Script "
                           "文件夹…」按钮。")
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
