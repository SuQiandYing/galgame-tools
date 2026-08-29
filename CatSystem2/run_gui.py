# -*- coding: utf-8 -*-
"""三按钮图形界面：拿到游戏文件 → 翻译 → 装回去。

面向不懂逆向的使用者，不暴露 decode_tier / unpack_mode / repack_strategy 等内部概念。
只调用 disassembler.py 与 assembler.py 暴露的函数，自己绝不解析二进制（§11.8）。
"""
from __future__ import annotations

import json
import queue
import sys
import threading
import traceback
import webbrowser
from typing import Sequence
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent))
import opcodelist as D  # noqa: E402
import disassembler as DIS  # noqa: E402
import assembler as ASM  # noqa: E402

CONFIG = Path(__file__).resolve().parent / ".gui_config.json"
ENCODINGS = list(D.TEXT_FORMAT["encoding_candidates"])
POLL_MS = 80                # dialect-literal-ok 界面轮询间隔，非方言常量
LIST_PREVIEW = 200          # dialect-literal-ok 文件列表最多显示几行，非方言常量
ERR_TAIL = 1200             # dialect-literal-ok 错误弹窗里显示多少字符，非方言常量


class _WinDrop:
    """Windows 拖放钩子。

    为什么不用 windnd：它在 64 位下用默认 restype（c_int）调 GetWindowLongPtrA，
    把原窗口过程指针从 0xFFFF1239 截断并符号扩展成 0xFFFFFFFFFFFF1239，
    再把这个野指针交给 CallWindowProcW。消息经**队列**派发时（真实拖放就是这样，
    此时 Tk 的 mainloop 已释放 GIL）直接触发

        Fatal Python error: PyEval_RestoreThread: the function must be called
        with the GIL held, but the GIL is released

    进程无 traceback 地消失——这就是「拖文件夹进去闪退」的真正原因。
    用 SendMessage 同步派发反而不崩，所以很容易误判为已修复。

    本实现的三条要点：
      1. 所有 Win32 原型显式声明 restype/argtypes，指针一律 c_void_p / c_ssize_t。
      2. 保留 WINFUNCTYPE 实例的强引用，否则回调被 GC 后同样是野指针。
      3. 回调体只做「取路径 + 交给上层」，异常一律吞掉——ctypes 回调里的异常
         无法向上传播，逃出去就是访问违例。
    """

    WM_DROPFILES = 0x0233            # dialect-literal-ok Win32 消息号
    GWLP_WNDPROC = -4                # dialect-literal-ok Win32 索引常量
    MAX_PATH = 260                   # dialect-literal-ok Win32 路径上限

    def __init__(self) -> None:
        self.reason = "未初始化"
        self._keep: list = []

    def install(self, root: tk.Misc, sink) -> bool:
        if sys.platform != "win32":
            self.reason = "非 Windows 平台"
            return False
        try:
            import ctypes
            from ctypes import wintypes as wt
        except ImportError as exc:
            self.reason = f"ctypes 不可用：{exc}"
            return False
        try:
            root.update_idletasks()
            hwnd = root.winfo_id()
            u32 = ctypes.WinDLL("user32", use_last_error=True)
            shell = ctypes.WinDLL("shell32", use_last_error=True)

            LONG_PTR = ctypes.c_ssize_t
            get_lp = getattr(u32, "GetWindowLongPtrW", None) or u32.GetWindowLongW
            set_lp = getattr(u32, "SetWindowLongPtrW", None) or u32.SetWindowLongW
            get_lp.restype = LONG_PTR
            get_lp.argtypes = [wt.HWND, ctypes.c_int]
            set_lp.restype = LONG_PTR
            set_lp.argtypes = [wt.HWND, ctypes.c_int, LONG_PTR]

            u32.CallWindowProcW.restype = LONG_PTR
            u32.CallWindowProcW.argtypes = [LONG_PTR, wt.HWND, ctypes.c_uint,
                                            ctypes.c_void_p, LONG_PTR]
            shell.DragQueryFileW.restype = ctypes.c_uint
            shell.DragQueryFileW.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                             ctypes.c_wchar_p, ctypes.c_uint]
            shell.DragFinish.restype = None
            shell.DragFinish.argtypes = [ctypes.c_void_p]
            shell.DragAcceptFiles.restype = None
            shell.DragAcceptFiles.argtypes = [wt.HWND, wt.BOOL]

            WNDPROC = ctypes.WINFUNCTYPE(LONG_PTR, wt.HWND, ctypes.c_uint,
                                         ctypes.c_void_p, LONG_PTR)
            old_proc = get_lp(hwnd, self.GWLP_WNDPROC)
            if not old_proc:
                self.reason = "取不到原窗口过程"
                return False

            def proc(h, msg, wp, lp):
                if msg == self.WM_DROPFILES:
                    try:
                        n = shell.DragQueryFileW(wp, 0xFFFFFFFF, None, 0)
                        buf = ctypes.create_unicode_buffer(self.MAX_PATH + 1)
                        out = []
                        for i in range(n):
                            if shell.DragQueryFileW(wp, i, buf, len(buf)):
                                out.append(buf.value)
                        sink(out)
                    except BaseException:
                        pass          # 绝不让异常逃出 ctypes 回调
                    finally:
                        try:
                            shell.DragFinish(wp)
                        except BaseException:
                            pass
                    return 0
                return u32.CallWindowProcW(old_proc, h, msg, wp, lp)

            cb = WNDPROC(proc)
            if not set_lp(hwnd, self.GWLP_WNDPROC,
                          ctypes.cast(cb, ctypes.c_void_p).value):
                if ctypes.get_last_error():
                    self.reason = f"替换窗口过程失败：{ctypes.get_last_error()}"
                    return False
            shell.DragAcceptFiles(hwnd, True)
            # 强引用：回调与原过程指针都不能被回收，否则又是野指针
            self._keep += [cb, old_proc, u32, shell, WNDPROC]
            self.reason = "ok"
            return True
        except Exception as exc:
            self.reason = f"{type(exc).__name__}: {exc}"
            return False


_dnd = _WinDrop()


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.inputs: list[Path] = []
        self.outdir: Path | None = None
        self.q: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.cancel = threading.Event()
        self.detail_text = ""
        # 拖放在 Win32 窗口过程里回调，只往这两个字段写，主循环再取（见 _setup_dnd）
        self.dropped: list[str] = []
        self.drop_error = ""
        self._dnd_note = ""
        root.title("CatScene 脚本翻译工具（.cst）")
        root.geometry("760x620")
        root.minsize(700, 560)          # dialect-literal-ok 窗口像素，非方言常量
        self._build()
        self._load_config()
        self.root.after(POLL_MS, self._pump)

    # ------------------------------------------------------------ 布局
    def _build(self) -> None:
        pad = {"padx": 12, "pady": 6}
        top = ttk.LabelFrame(self.root, text="① 把游戏脚本拖进来")
        top.pack(fill="x", **pad)
        self.drop = tk.Listbox(top, height=7, activestyle="none")
        self.drop.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        self.drop.insert(tk.END, "把 .cst 文件或文件夹拖到这里，或点下面的按钮选择…")
        bar = ttk.Frame(top)
        bar.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(bar, text="选择文件…", command=self._pick_files).pack(side="left")
        ttk.Button(bar, text="选择文件夹…", command=self._pick_dir).pack(
            side="left", padx=6)
        ttk.Button(bar, text="清空", command=self._clear).pack(side="left")

        opt = ttk.Frame(self.root)
        opt.pack(fill="x", **pad)
        ttk.Label(opt, text="原文编码").grid(row=0, column=0, sticky="w")
        self.senc = ttk.Combobox(opt, values=ENCODINGS, width=10)
        self.senc.set(D.ENCODING["source"])
        self.senc.grid(row=0, column=1, padx=(4, 16))
        ttk.Label(opt, text="译文编码").grid(row=0, column=2, sticky="w")
        self.tenc = ttk.Combobox(opt, values=ENCODINGS, width=10)
        self.tenc.set(D.ENCODING["target"])
        self.tenc.grid(row=0, column=3, padx=(4, 16))
        ttk.Label(opt, text="输出目录").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.out_var = tk.StringVar()
        ttk.Entry(opt, textvariable=self.out_var, width=52).grid(
            row=1, column=1, columnspan=3, sticky="we", padx=(4, 6), pady=(6, 0))
        ttk.Button(opt, text="浏览…", command=self._pick_out).grid(
            row=1, column=4, pady=(6, 0))
        opt.columnconfigure(3, weight=1)

        btns = ttk.Frame(self.root)
        btns.pack(fill="x", **pad)
        self.b1 = ttk.Button(btns, text="①  全 量 反 汇 编", command=self._go_disasm)
        self.b2 = ttk.Button(btns, text="②  提 取 双 行 文 本", command=self._go_texts,
                             state="disabled")
        self.b3 = ttk.Button(btns, text="③  回 封 文 本", command=self._go_repack,
                             state="disabled")
        for b in (self.b1, self.b2, self.b3):
            b.pack(fill="x", pady=3, ipady=6)

        prog = ttk.Frame(self.root)
        prog.pack(fill="x", **pad)
        self.bar = ttk.Progressbar(prog, mode="determinate")
        self.bar.pack(fill="x")
        self.status = ttk.Label(prog, text="等待输入", anchor="w")
        self.status.pack(fill="x", pady=(4, 0))
        row = ttk.Frame(prog)
        row.pack(fill="x", pady=(4, 0))
        self.b_open = ttk.Button(row, text="打开输出目录", command=self._open_out,
                                 state="disabled")
        self.b_open.pack(side="left")
        self.b_cancel = ttk.Button(row, text="取消", command=self._do_cancel,
                                   state="disabled")
        self.b_cancel.pack(side="left", padx=6)

        self.det_btn = ttk.Button(self.root, text="▸ 详情", command=self._toggle)
        self.det_btn.pack(anchor="w", padx=12)
        self.det = tk.Text(self.root, height=10, wrap="none", state="disabled")
        self.det_open = False
        self._setup_dnd()
        # ② ③ 必须一开始就是禁用的：①「零编辑往返自检」通过之前，
        # 使用者不该有任何路径走到回封（§11.3）。
        self._set_buttons(disasm=True, texts=False, repack=False)

    def _setup_dnd(self) -> None:
        """拖放依赖缺失时降级为「选择文件」，不阻止启动（§11.8）。

        windnd 用 SetWindowLong 换掉 Tk 的窗口过程，回调在 WM_DROPFILES 里**同步**
        执行。那个上下文有两条硬约束：
          - 不能抛异常：ctypes 回调无法向上传播，异常会变成访问违例，进程直接消失。
          - 不能弹模态框、不能做耗时工作：会在消息处理中重入消息循环。
        所以回调只做一件事——把路径丢进队列，剩下的全部交给 Tk 主循环（_on_drop）。

        force_unicode=True 是必须的：默认走 ANSI 版 DragQueryFile，路径要经过一次
        当前代码页转换，代码页表示不了的字符会变成 '?'，路径随即失效。
        """
        if _dnd.install(self.root, self._drop_raw):
            return
        try:
            self.root.tk.eval("package require tkdnd")
            self.root.tk.call("tkdnd::drop_target", "register", self.root,
                              ("DND_Files",))
            self.root.bind("<<Drop>>", lambda e: self._drop_raw(
                self.root.tk.splitlist(e.data)))
            return
        except tk.TclError:
            pass
        self.drop.delete(0, tk.END)
        self.drop.insert(tk.END, "（这个环境不支持拖放，请用下面的按钮选择文件）")
        self.drop.insert(tk.END, f"   原因：{_dnd.reason}")

    def _drop_raw(self, files) -> None:
        """在 Win32 窗口过程里执行。**绝对不能碰任何 Tk API。**

        这是「拖文件夹进去闪退」的真正原因：消息经队列派发时（真实拖放就是这样），
        Tk 的 C 层正在 Tcl_DoOneEvent 里、已经释放了 GIL。此时从窗口过程回调中
        调 root.after_idle（或任何 Tk 调用）会触发

            Fatal Python error: PyEval_RestoreThread: the function must be
            called with the GIL held

        进程无 traceback 地消失。实测：不碰 Tk 的回调能活；只要加一行 after_idle
        就必死。用 SendMessage 同步派发反而不崩，所以很容易误判为已修复。

        因此这里只往普通 list 里追加——已经在跑的 _pump 定时器（POLL_MS）会取走。
        list.append 是原子的，不需要额外加锁。
        """
        try:
            for f in files:
                p = self._decode_path(f)
                if p:
                    self.dropped.append(p)
        except BaseException:
            try:
                self.drop_error = traceback.format_exc()
            except BaseException:
                pass

    @staticmethod
    def _decode_path(f) -> str | None:
        """windnd 在 force_unicode=True 下给 str；旧版本或 bytes 情形做兜底解码。"""
        if isinstance(f, str):
            return f
        if isinstance(f, bytes):
            for enc in ("utf-8", sys.getfilesystemencoding() or "utf-8", "mbcs"):
                try:
                    return f.decode(enc)
                except (UnicodeDecodeError, LookupError):
                    continue
            return f.decode("mbcs", "replace")
        return None

    def _on_drop(self) -> None:
        """在 Tk 主循环里执行。到这里才允许弹窗、扫目录、更新界面。"""
        if self.drop_error:
            err, self.drop_error = self.drop_error, ""
            # 拖放本身出错只写状态栏与详情区：用户下一步就是再拖一次，
            # 弹窗除了挡住窗口没有别的作用。
            self.status.config(text="这次拖放没读到文件，再试一次（详情里有原因）")
            self._set_detail(err)
        paths, self.dropped = self.dropped, []
        if not paths:
            return
        if self.worker and self.worker.is_alive():
            self.status.config(text="正在处理中，请等这一步跑完再拖新文件")
            return
        self._add([Path(p) for p in paths])

    # ------------------------------------------------------------ 输入
    def _pick_files(self) -> None:
        fs = filedialog.askopenfilenames(
            title="选择 .cst 脚本", filetypes=[("CatScene 脚本", "*.cst"),
                                            ("全部文件", "*.*")])
        if fs:
            self._add([Path(f) for f in fs])

    def _pick_dir(self) -> None:
        d = filedialog.askdirectory(title="选择包含 .cst 的文件夹")
        if d:
            self._add([Path(d)])

    def _pick_out(self) -> None:
        d = filedialog.askdirectory(title="选择输出目录")
        if d:
            self.out_var.set(d)

    def _clear(self) -> None:
        self.inputs = []
        self.drop.delete(0, tk.END)
        self.drop.insert(tk.END, "把 .cst 文件或文件夹拖到这里…")
        self._set_buttons(disasm=True, texts=False, repack=False)

    def _add(self, paths: Sequence[Path]) -> None:
        """扫描并登记输入。扫大目录可能很慢也可能报权限错，两种都不该让界面死掉。"""
        self.status.config(text="正在查找 .cst 文件…")
        self.root.update_idletasks()
        try:
            found = DIS.collect_inputs(paths)
        except DIS.CstError as exc:
            # 拖错了东西是常事，写状态栏就够——用户下一步是再拖一次。
            self.status.config(text=f"这里没有 .cst / .cstl 文件（{exc}）")
            return
        except OSError as exc:
            self.status.config(text=f"读不到这个位置：{exc}")
            return
        seen = {p.resolve() for p in self.inputs}
        added = 0
        for p in found:
            try:
                rp = p.resolve()
            except OSError:
                continue
            if rp not in seen:
                seen.add(rp)
                self.inputs.append(p)
                added += 1
        if not self.inputs:
            self.status.config(text="没有找到可处理的文件")
            return
        self._refresh_list()
        if not self.out_var.get():
            try:
                self.out_var.set(str(DIS.common_parent(self.inputs) / "output"))
            except (OSError, ValueError):
                pass
        if added == 0:
            self.status.config(
                text=f"这些文件已经在列表里了（共 {len(self.inputs)} 个）")

    def _refresh_list(self) -> None:
        self.drop.delete(0, tk.END)
        for p in self.inputs[:LIST_PREVIEW]:
            try:
                size = f"{p.stat().st_size / 1024:>8.1f} KB"
            except OSError:
                size = "     读不到"
            self.drop.insert(tk.END, f"   {p.name:<28} {size}   脚本")
        if len(self.inputs) > LIST_PREVIEW:
            self.drop.insert(tk.END, f"   …另有 {len(self.inputs) - LIST_PREVIEW} 个文件")
        self.status.config(text=f"已选 {len(self.inputs)} 个文件")

    # ------------------------------------------------------------ 三个按钮
    def _go_disasm(self) -> None:
        # 没选文件、要覆盖旧产物 —— 都写状态栏就够了，不弹窗。
        # 弹窗只留给「真的出了问题、不说会导致误用」的情形。
        if not self.inputs:
            self.status.config(text="先拖入 .cst / .cstl 文件，或点上面的按钮选择")
            return
        out = Path(self.out_var.get() or
                   DIS.common_parent(self.inputs) / "output")
        if (out / "ir" / "manifest.jsonl").exists():
            # 覆盖自己生成的产物无所谓——重跑得到同样的东西。
            # 但如果 texts/ 里已经有译文，重跑会**毁掉别人的劳动**，这才值得拦一下。
            n = self._count_translated(out / "texts")
            if n and not messagebox.askyesno(
                    "会覆盖已有译文",
                    f"{out / 'texts'}\n\n里面已经有 {n} 条翻译过的内容，"
                    f"重新反汇编会全部还原成原文。\n\n继续吗？"):
                self.status.config(text="已取消，译文未被改动")
                return
            self.status.config(text=f"覆盖上一次的结果：{out}")
        self.outdir = out
        self._save_config()
        self._start("disasm", self._task_disasm, out)

    @staticmethod
    def _count_translated(texts: Path) -> int:
        """数一下有多少条译文行与原文行不同（即真的翻译过的条数）。
        只读、失败就返回 0——这个统计只用来决定要不要提醒，不该自己变成故障源。"""
        n = 0
        try:
            for tp in texts.rglob("*.txt"):
                prev = None
                for line in tp.read_text(encoding="utf-8-sig").splitlines():
                    mo = ASM._ORIG_RE.match(line)
                    if mo:
                        prev = mo.group("text")
                        continue
                    mt = ASM._TRAN_RE.match(line)
                    if mt and prev is not None:
                        if mt.group("text") and mt.group("text") != prev:
                            n += 1
                        prev = None
        except (OSError, UnicodeDecodeError):
            return 0
        return n

    def _go_texts(self) -> None:
        """② 的产物在 ① 里已经生成——这里只做定位与统计，不重算（§12.8）。"""
        out = self.outdir
        if out is None or not (out / "texts").exists():
            self.status.config(text="请先点 ① 全量反汇编")
            return
        rep = json.loads((out / "reports" / "disasm.json")
                         .read_text(encoding="utf-8"))
        n = rep["text_entries"]
        pol = rep["translate_policies"]
        tr = pol.get("translatable", 0)
        rv = pol.get("review-required", 0)
        fz = pol.get("frozen", 0)
        files = len(list((out / "texts").rglob("*.txt")))
        self.status.config(
            text=f"✓ 已导出 {files} 个译文文件、{n} 条："
                 f"可翻译 {tr} / 需确认 {rv} / 锁定 {fz}"
                 f"　→ 编辑 texts 目录里的 ● 行，改完点 ③")
        self.bar["value"] = 100
        self._set_buttons(disasm=True, texts=True, repack=True)
        self.b_open.config(state="normal")
        # 成功不弹窗：状态栏已经说清楚了，「打开输出目录」按钮就在旁边。

    def _go_repack(self) -> None:
        out = self.outdir
        if out is None:
            self.status.config(text="请先点 ① 全量反汇编")
            return
        self._start("repack", self._task_repack, out)

    # ------------------------------------------------------------ 线程
    def _start(self, kind: str, fn, arg) -> None:
        if self.worker and self.worker.is_alive():
            return
        self.cancel.clear()
        self.bar["value"] = 0
        self.b_cancel.config(state="normal")
        self._set_buttons(disasm=False, texts=False, repack=False)
        self.worker = threading.Thread(target=self._wrap, args=(kind, fn, arg),
                                       daemon=True)
        self.worker.start()

    def _wrap(self, kind, fn, arg) -> None:
        try:
            fn(arg)
        except Exception as exc:
            self.q.put(("error", kind, self._human(exc), traceback.format_exc()))

    def _task_disasm(self, out: Path) -> None:
        def prog(i, n, name):
            if self.cancel.is_set():
                raise DIS.CstError("已取消")
            self.q.put(("prog", i * 100.0 / n, f"正在反汇编 {name}（{i}/{n}）"))
        rep = DIS.run_disasm(self.inputs, out, self.senc.get(), self.tenc.get(),
                             want_asm=True, jobs=None, progress=prog)
        self.q.put(("disasm_done", rep))

    def _task_repack(self, out: Path) -> None:
        def prog(phase, i, n, name):
            if self.cancel.is_set():
                raise DIS.CstError("已取消")
            label = "正在检查译文" if phase == "verify" else "正在生成"
            self.q.put(("prog", i * 100.0 / n, f"{label} {name}（{i}/{n}）"))
        rep = ASM.run_repack([out / "texts"], out, None, None, progress=prog)
        self.q.put(("repack_done", rep))

    def _do_cancel(self) -> None:
        self.cancel.set()
        self.status.config(text="正在停止…")

    def _pump(self) -> None:
        """唯一的 Tk 侧驱动：既取后台线程的消息，也取拖放攒下的路径。

        拖放走轮询而不是 after_idle，因为回调所在的上下文不允许调用任何 Tk API
        （见 _drop_raw）。
        """
        try:
            while True:
                self._handle(self.q.get_nowait())
        except queue.Empty:
            pass
        if self.dropped or self.drop_error:
            self._on_drop()
        self.root.after(POLL_MS, self._pump)

    def _handle(self, msg) -> None:
        kind = msg[0]
        if kind == "prog":
            self.bar["value"] = msg[1]
            self.status.config(text=msg[2])
            return
        self.b_cancel.config(state="disabled")
        if kind == "disasm_done":
            self._after_disasm(msg[1])
        elif kind == "repack_done":
            self._after_repack(msg[1])
        elif kind == "error":
            self.bar["value"] = 0
            self.status.config(text=f"✗ {msg[2]}")
            self._set_detail(msg[3])
            self._set_buttons(disasm=True, texts=False, repack=False)
            messagebox.showerror("没能完成", msg[2])

    def _after_disasm(self, rep: dict) -> None:
        self.bar["value"] = 100
        self._set_detail(self._detail(rep))
        self.b_open.config(state="normal")
        if not rep["roundtrip_identity"]:
            self.status.config(text="✗ 逐字节校验没通过，此游戏暂不支持回封")
            self._set_buttons(disasm=True, texts=False, repack=False)
            messagebox.showerror(
                "此游戏暂不支持回封",
                "反汇编能读，但重建出的文件与原文不完全一致，"
                "说明还有没弄清的地方。\n\n"
                "现在装回游戏有风险，所以后面两步先不开放。\n"
                f"详情见：{self.outdir / 'reports' / 'disasm.json'}")
            return
        if not rep["sanity_gate"]["ok"]:
            self.status.config(text="✗ 提取结果不合理，已停止")
            self._set_buttons(disasm=True, texts=False, repack=False)
            messagebox.showerror("提取结果不合理",
                                 "\n".join(rep["sanity_gate"]["failures"]))
            return
        if rep["files_failed"]:
            # 这一类保留弹窗：有文件没解析成功意味着后面两步不开放，
            # 用户必须知道，否则会以为流程走通了。逐条原因同时进详情区。
            first = rep["failures"][0]
            self.status.config(
                text=f"✗ {rep['files_failed']} 个文件没能解析，"
                     f"例如 {first['rel']}（详情里有全部原因）")
            self._set_detail(
                "以下文件没能解析，所以后面两步不开放：\n\n"
                + "\n".join(f"  {f['rel']}\n    {f['error']}"
                            for f in rep["failures"][:12])
                + f"\n\n完整报告：{self.outdir / 'reports' / 'disasm.json'}")
            self._set_buttons(disasm=True, texts=False, repack=False)
            messagebox.showerror(
                "有文件没能解析",
                "\n".join(f"{f['rel']}：{f['error']}"
                          for f in rep["failures"][:6]))
            return
        self.status.config(
            text=f"✓ 已完成，逐字节校验通过（{rep['files_ok']} 个文件、"
                 f"{rep['text_entries']} 条文本）　→ 接着点 ②")
        self._set_buttons(disasm=True, texts=True, repack=False)
        # 成功不弹窗。② 已经亮起来了，下一步做什么一目了然。

    def _after_repack(self, rep: dict) -> None:
        self.bar["value"] = 100
        self._set_buttons(disasm=True, texts=True, repack=True)
        self.b_open.config(state="normal")
        if rep["failures"]:
            self.status.config(text=f"✗ {len(rep['failures'])} 个文件回封失败")
            messagebox.showerror("回封失败",
                                 "\n".join(f"{f['path']}：{f['error']}"
                                           for f in rep["failures"][:6]))
            return
        if not rep["sources_rebuilt"]:
            self.status.config(
                text=f"译文全部通过检查，但没有一条 ● 行被改过"
                     f"（共 {rep['text_files']} 个文件）——先翻译几条再回来")
            return
        self.status.config(
            text=f"✓ 已生成 {rep['sources_rebuilt']} 个文件、改动 "
                 f"{rep['changed_entries']} 条　→ 复制 rebuilt 里的文件回游戏目录即可")

    # ------------------------------------------------------------ 杂项
    def _human(self, exc: Exception) -> str:
        s = str(exc)
        if isinstance(exc, ASM.ImportError_):
            return s
        if isinstance(exc, DIS.CstError):
            return s
        return f"{type(exc).__name__}: {s}"

    def _detail(self, rep: dict) -> str:
        pol = rep["translate_policies"]
        return "\n".join([
            f"样本      {rep['files_ok']} 个文件，共 {rep['source_bytes']:,} 字节",
            f"理解深度  {rep['min_tier']}（已定位 {rep['records']:,} 条记录、"
            f"{rep['blocks']:,} 个对话块）",
            f"覆盖      byte {rep['min_byte_coverage']:.2%}   "
            f"往返 {'逐字节一致' if rep['roundtrip_identity'] else '不一致'}",
            f"文本      {rep['text_entries']:,} 条："
            f"可翻译 {pol.get('translatable', 0):,} / "
            f"需确认 {pol.get('review-required', 0):,} / "
            f"锁定 {pol.get('frozen', 0):,}",
            f"分类      {rep['tags']}",
            f"人名绑定  {rep['name_bindings']:,} 处"
            f"（其中歧义 {rep['ambiguous_bindings']} 处，已保留全部候选）",
            f"判定来源  {rep['tag_source_counts']}",
            f"窗口命中  {rep['window_hits']}   规则命中 {rep['rule_hits']}",
            f"编码      原文 {rep['source_encoding']} → 译文 "
            f"{rep['target_encoding']}",
            f"报告      {self.outdir / 'reports' / 'disasm.json'}",
        ])

    def _set_detail(self, text: str) -> None:
        self.detail_text = text
        self.det.config(state="normal")
        self.det.delete("1.0", tk.END)
        self.det.insert("1.0", text)
        self.det.config(state="disabled")

    def _toggle(self) -> None:
        self.det_open = not self.det_open
        if self.det_open:
            self.det.pack(fill="both", expand=True, padx=12, pady=(0, 10))
            self.det_btn.config(text="▾ 详情")
        else:
            self.det.pack_forget()
            self.det_btn.config(text="▸ 详情")

    def _set_buttons(self, disasm: bool, texts: bool, repack: bool) -> None:
        self.b1.config(state="normal" if disasm else "disabled")
        self.b2.config(state="normal" if texts else "disabled")
        self.b3.config(state="normal" if repack else "disabled")

    def _open_out(self) -> None:
        if self.outdir and self.outdir.exists():
            webbrowser.open(self.outdir.as_uri())

    def _load_config(self) -> None:
        """恢复上次的设置。**不恢复原文编码**——那一项记住反而危险。

        实测踩过：上一轮把原文编码改成 gbk 后，下次启动静默沿用，
        日文脚本被按 gbk 解成一整片乱码（「ふあぁ…」→「乽傆偁…」），
        而且往返自检照样通过（读错编码不影响字节层面的可逆性），
        译文文件全是垃圾却没有任何告警。

        原文编码是**样本属性**，由方言声明给出默认值；译文编码是**用户偏好**，
        记住它才有意义。两者性质不同，不该一起持久化。
        """
        try:
            c = json.loads(CONFIG.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if c.get("outdir"):
            self.out_var.set(c["outdir"])
        if c.get("target_encoding"):
            self.tenc.set(c["target_encoding"])
        self.senc.set(D.ENCODING["source"])

    def _save_config(self) -> None:
        # 不存 source_encoding：见 _load_config 的说明。
        try:
            CONFIG.write_text(json.dumps(
                {"outdir": self.out_var.get(),
                 "target_encoding": self.tenc.get()},
                ensure_ascii=False, indent=1), encoding="utf-8")
        except OSError:
            pass


def main() -> int:
    DIS._utf8_console()
    root = tk.Tk()

    def on_tk_error(exc, val, tb):
        """Tk 回调里的异常默认只打到 stderr——双击启动时没有控制台，
        看起来就是「什么也没发生」。这里强制弹窗，让问题可见。"""
        text = "".join(traceback.format_exception(exc, val, tb))
        sys.stderr.write(text)
        try:
            messagebox.showerror("出错了",
                                 f"{val}\n\n详细信息：\n{text[-ERR_TAIL:]}")
        except Exception:
            pass

    root.report_callback_exception = on_tk_error
    app = App(root)
    if len(sys.argv) > 1:
        # 拖到图标上启动时，路径由命令行传入
        app.root.after_idle(lambda: app._add([Path(a) for a in sys.argv[1:]]))
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
