#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import codecs
import ctypes
import json
import queue
import shutil
import threading
import traceback
from ctypes import wintypes
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Callable

import scr_dat_tool
import scr_text_export_tool
import scr_text_ir_tool


def safe_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def ensure_codec(name: str) -> str:
    value = name.strip()
    if not value:
        raise ValueError("编码不能为空")
    try:
        codecs.lookup(value)
    except LookupError as exc:
        raise ValueError(f"无效编码: {value}") from exc
    return value


def normalize_dat_input(value: str) -> str:
    raw = value.strip()
    if not raw:
        return raw
    path = Path(raw)
    if path.is_dir():
        candidate = path / "scr.dat"
        if candidate.exists():
            return str(candidate)
    return str(path)


def discover_scr_root(extract_dir: Path) -> Path:
    files_dir = extract_dir / "files"
    if files_dir.is_dir() and scr_text_export_tool.discover_script_files(files_dir):
        return files_dir
    if scr_text_export_tool.discover_script_files(extract_dir):
        return extract_dir
    raise FileNotFoundError(f"在 {extract_dir} 下未找到 .scr 文件")


def reset_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


class WindowsDropManager:
    WM_DROPFILES = 0x0233
    GWL_WNDPROC = -4

    def __init__(self, root: tk.Tk, on_drop: Callable[[list[str], tk.Widget | None], None]) -> None:
        self._root = root
        self._on_drop = on_drop
        self._hwnd = wintypes.HWND(root.winfo_id())
        self._user32 = ctypes.windll.user32
        self._shell32 = ctypes.windll.shell32
        self._wnd_proc = None
        self._old_wnd_proc = None
        self._install()

    def _install(self) -> None:
        long_ptr = ctypes.c_longlong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_long
        wndproc_type = ctypes.WINFUNCTYPE(
            long_ptr,
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        )
        set_window_long_ptr = getattr(self._user32, "SetWindowLongPtrW", self._user32.SetWindowLongW)
        call_window_proc = self._user32.CallWindowProcW

        set_window_long_ptr.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
        set_window_long_ptr.restype = ctypes.c_void_p
        call_window_proc.argtypes = [
            ctypes.c_void_p,
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        ]
        call_window_proc.restype = long_ptr

        self._shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
        self._shell32.DragAcceptFiles.restype = None
        self._shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
        self._shell32.DragQueryFileW.restype = wintypes.UINT
        self._shell32.DragQueryPoint.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.POINT)]
        self._shell32.DragQueryPoint.restype = wintypes.BOOL
        self._shell32.DragFinish.argtypes = [wintypes.HANDLE]
        self._shell32.DragFinish.restype = None
        self._user32.ClientToScreen.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
        self._user32.ClientToScreen.restype = wintypes.BOOL

        def wnd_proc(hwnd: Any, msg: int, wparam: int, lparam: int) -> int:
            if msg == self.WM_DROPFILES:
                self._handle_drop(wparam)
                return 0
            return call_window_proc(self._old_wnd_proc, hwnd, msg, wparam, lparam)

        self._wnd_proc = wndproc_type(wnd_proc)
        self._old_wnd_proc = set_window_long_ptr(
            self._hwnd,
            self.GWL_WNDPROC,
            ctypes.cast(self._wnd_proc, ctypes.c_void_p).value,
        )
        self._shell32.DragAcceptFiles(self._hwnd, True)
        self._root.bind("<Destroy>", self._on_destroy, add="+")

    def _on_destroy(self, event: tk.Event[Any]) -> None:
        if event.widget is not self._root or not self._old_wnd_proc:
            return
        set_window_long_ptr = getattr(self._user32, "SetWindowLongPtrW", self._user32.SetWindowLongW)
        set_window_long_ptr.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
        set_window_long_ptr.restype = ctypes.c_void_p
        set_window_long_ptr(self._hwnd, self.GWL_WNDPROC, self._old_wnd_proc)
        self._old_wnd_proc = None

    def _handle_drop(self, hdrop: int) -> None:
        count = self._shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0)
        paths: list[str] = []
        for index in range(count):
            size = self._shell32.DragQueryFileW(hdrop, index, None, 0)
            buf = ctypes.create_unicode_buffer(size + 1)
            self._shell32.DragQueryFileW(hdrop, index, buf, size + 1)
            paths.append(buf.value)

        point = wintypes.POINT()
        self._shell32.DragQueryPoint(hdrop, ctypes.byref(point))
        self._user32.ClientToScreen(self._hwnd, ctypes.byref(point))
        widget = self._root.winfo_containing(point.x, point.y)
        self._shell32.DragFinish(hdrop)
        self._on_drop(paths, widget)


class PathField(ttk.Frame):
    def __init__(
        self,
        master: tk.Widget,
        app: "SimpleWorkflowApp",
        *,
        label: str,
        variable: tk.StringVar,
        browse_mode: str,
        normalizer: Callable[[str], str] | None = None,
        filetypes: tuple[tuple[str, str], ...] | None = None,
        on_change: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(master)
        self._app = app
        self._var = variable
        self._browse_mode = browse_mode
        self._normalizer = normalizer
        self._filetypes = filetypes or (("All Files", "*.*"),)
        self._on_change = on_change
        self._suspend_change = False

        self.columnconfigure(1, weight=1)
        ttk.Label(self, text=label, width=14).grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.entry = ttk.Entry(self, textvariable=self._var)
        self.entry.grid(row=0, column=1, sticky="ew")
        ttk.Button(self, text="浏览", width=8, command=self._browse).grid(row=0, column=2, padx=(8, 0))
        self._var.trace_add("write", self._handle_var_write)

        self._app.register_drop_target(self, self._drop)
        self._app.register_drop_target(self.entry, self._drop)

    def _handle_var_write(self, *_args: object) -> None:
        if not self._suspend_change and self._on_change is not None:
            self._on_change()

    def _drop(self, paths: list[str]) -> None:
        if paths:
            self.set_value(paths[0])

    def set_value(self, raw_value: str) -> None:
        value = raw_value.strip()
        if self._normalizer is not None and value:
            value = self._normalizer(value)
        self._suspend_change = True
        try:
            self._var.set(value)
        finally:
            self._suspend_change = False
        if self._on_change is not None:
            self._on_change()

    def _browse(self) -> None:
        current = self._var.get().strip()
        current_path = Path(current) if current else None
        initial_dir = str(current_path.parent if current_path and current_path.suffix else current_path) if current_path else str(Path.cwd())

        if self._browse_mode == "open_file":
            path = filedialog.askopenfilename(parent=self, initialdir=initial_dir, filetypes=self._filetypes)
        elif self._browse_mode == "open_dir":
            path = filedialog.askdirectory(parent=self, initialdir=initial_dir, mustexist=False)
        elif self._browse_mode == "save_file":
            path = filedialog.asksaveasfilename(parent=self, initialdir=initial_dir, filetypes=self._filetypes)
        else:
            raise ValueError(f"unsupported browse mode: {self._browse_mode}")

        if path:
            self.set_value(path)


class SimpleWorkflowApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("SCR 懒人流程 GUI")
        self.root.geometry("1040x780")
        self.root.minsize(960, 720)

        self._drop_handlers: dict[str, Callable[[list[str]], None]] = {}
        self._event_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._worker: threading.Thread | None = None

        self.dat_path_var = tk.StringVar()
        self.workdir_var = tk.StringVar()
        self.encoding_var = tk.StringVar(value="cp932")
        self.status_var = tk.StringVar(value="就绪")

        self.unpacked_var = tk.StringVar()
        self.texts_var = tk.StringVar()
        self.rebuilt_scr_var = tk.StringVar()
        self.output_dat_var = tk.StringVar()
        self._applying_defaults = False
        self._path_manual = {
            "unpacked": False,
            "texts": False,
            "rebuilt_scripts": False,
            "output_dat": False,
        }

        self._build_ui()
        self.root.update_idletasks()
        if self.root.tk.call("tk", "windowingsystem") == "win32":
            self._drop_manager = WindowsDropManager(self.root, self._dispatch_drop)
        else:
            self._drop_manager = None
        self.root.after(120, self._poll_events)

    def register_drop_target(self, widget: tk.Widget, handler: Callable[[list[str]], None]) -> None:
        self._drop_handlers[str(widget)] = handler

    def _dispatch_drop(self, paths: list[str], widget: tk.Widget | None) -> None:
        current = widget
        while current is not None:
            handler = self._drop_handlers.get(str(current))
            if handler is not None:
                handler(paths)
                self._append_log(f"收到拖拽路径: {paths[0]}")
                return
            parent_name = current.winfo_parent()
            if not parent_name:
                break
            current = current.nametowidget(parent_name)
        self._append_log("拖拽未命中输入框，请把文件或目录拖到对应路径框。")

    def _build_ui(self) -> None:
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")

        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(4, weight=1)

        intro = ttk.LabelFrame(outer, text="流程")
        intro.grid(row=0, column=0, sticky="ew")
        intro.columnconfigure(0, weight=1)
        ttk.Label(
            intro,
            text="现在拆成 3 步：1. 解包并导出文本  2. 翻译后回编 SCR  3. 可选回封 DAT。",
        ).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 4))
        ttk.Label(
            intro,
            text="如果游戏支持免封包，你做到第 2 步就够了。只有需要整包时再点第 3 步。",
        ).grid(row=1, column=0, sticky="w", padx=10, pady=(0, 8))

        form = ttk.LabelFrame(outer, text="输入")
        form.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        form.columnconfigure(0, weight=1)

        PathField(
            form,
            self,
            label="scr.dat",
            variable=self.dat_path_var,
            browse_mode="open_file",
            normalizer=normalize_dat_input,
            filetypes=(("DAT Files", "*.dat"), ("All Files", "*.*")),
            on_change=self._on_dat_changed,
        ).grid(row=0, column=0, sticky="ew", pady=4, padx=8)

        PathField(
            form,
            self,
            label="工作目录",
            variable=self.workdir_var,
            browse_mode="open_dir",
            on_change=self._on_workdir_changed,
        ).grid(row=1, column=0, sticky="ew", pady=4, padx=8)

        options = ttk.Frame(form)
        options.grid(row=2, column=0, sticky="ew", pady=(4, 8), padx=8)
        options.columnconfigure(5, weight=1)
        ttk.Label(options, text="编码").grid(row=0, column=0, sticky="w")
        ttk.Entry(options, textvariable=self.encoding_var, width=16).grid(row=0, column=1, sticky="w", padx=(8, 16))
        ttk.Label(options, text="支持任意 Python codec").grid(row=0, column=2, sticky="w")
        ttk.Button(options, text="重填默认路径", command=self._autofill_workdir, width=22).grid(
            row=0, column=4, sticky="e"
        )

        derived = ttk.LabelFrame(outer, text="输出路径（可手改）")
        derived.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        derived.columnconfigure(0, weight=1)

        PathField(
            derived,
            self,
            label="解包目录",
            variable=self.unpacked_var,
            browse_mode="open_dir",
            on_change=self._on_unpacked_changed,
        ).grid(row=0, column=0, sticky="ew", pady=4, padx=8)
        PathField(
            derived,
            self,
            label="文本目录",
            variable=self.texts_var,
            browse_mode="open_dir",
            on_change=self._on_texts_changed,
        ).grid(row=1, column=0, sticky="ew", pady=4, padx=8)
        PathField(
            derived,
            self,
            label="回编 SCR",
            variable=self.rebuilt_scr_var,
            browse_mode="open_dir",
            on_change=self._on_rebuilt_changed,
        ).grid(row=2, column=0, sticky="ew", pady=4, padx=8)
        PathField(
            derived,
            self,
            label="新 DAT",
            variable=self.output_dat_var,
            browse_mode="save_file",
            filetypes=(("DAT Files", "*.dat"), ("All Files", "*.*")),
            on_change=self._on_output_dat_changed,
        ).grid(row=3, column=0, sticky="ew", pady=4, padx=8)

        actions_wrap = ttk.LabelFrame(outer, text="操作")
        actions_wrap.grid(row=3, column=0, sticky="ew", pady=(12, 0))
        actions_wrap.columnconfigure(0, weight=1)

        actions = ttk.Frame(actions_wrap)
        actions.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        for idx in range(3):
            actions.columnconfigure(idx, weight=1)

        ttk.Button(actions, text="1. 解包并导出文本", command=self._on_export_workflow).grid(row=0, column=0, sticky="ew", padx=4)
        ttk.Button(actions, text="2. 翻译后回编 SCR", command=self._on_build_scr_workflow).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(actions, text="3. 可选回封 DAT", command=self._on_repack_dat_workflow).grid(row=0, column=2, sticky="ew", padx=4)

        log_frame = ttk.LabelFrame(outer, text="日志")
        log_frame.grid(row=4, column=0, sticky="nsew", pady=(12, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=14, wrap="word", font=("Consolas", 10))
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=(8, 6))
        self.log_text.configure(state="disabled")

        bottom = ttk.Frame(log_frame)
        bottom.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 8))
        bottom.columnconfigure(0, weight=1)
        ttk.Label(bottom, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        ttk.Button(bottom, text="清空日志", command=self._clear_log).grid(row=0, column=1, sticky="e")

        self._apply_default_paths(force=False, include_workdir=True)

    def _append_log(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text.rstrip() + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _poll_events(self) -> None:
        try:
            while True:
                kind, payload = self._event_queue.get_nowait()
                if kind == "done":
                    title, result = payload
                    self.status_var.set(f"{title} 完成")
                    self._append_log(f"[完成] {title}")
                    if result is not None:
                        self._append_log(safe_json(result))
                    self._worker = None
                elif kind == "error":
                    title, error_text = payload
                    self.status_var.set(f"{title} 失败")
                    self._append_log(f"[失败] {title}")
                    self._append_log(error_text)
                    self._worker = None
                    messagebox.showerror("执行失败", f"{title} 失败。\n\n{error_text.splitlines()[-1]}", parent=self.root)
        except queue.Empty:
            pass
        self.root.after(120, self._poll_events)

    def _start_task(self, title: str, func: Callable[[], Any]) -> None:
        if self._worker is not None and self._worker.is_alive():
            messagebox.showwarning("忙碌中", "当前已有任务在运行，请先等待它完成。", parent=self.root)
            return

        self.status_var.set(f"{title} 运行中...")
        self._append_log(f"[开始] {title}")

        def worker() -> None:
            try:
                result = func()
                self._event_queue.put(("done", (title, result)))
            except Exception:
                self._event_queue.put(("error", (title, traceback.format_exc())))

        self._worker = threading.Thread(target=worker, daemon=True)
        self._worker.start()

    def _default_paths(self, workdir: Path, dat_path: Path | None) -> dict[str, Path]:
        stem = dat_path.stem if dat_path is not None and dat_path.name else "scr"
        return {
            "unpacked": workdir / "unpacked",
            "texts": workdir / "dsat",
            "rebuilt_scripts": workdir / "rebuilt_scripts",
            "output_dat": workdir / f"{stem}_translated.dat",
        }

    def _apply_default_paths(self, *, force: bool, include_workdir: bool) -> None:
        dat_raw = self.dat_path_var.get().strip()
        dat_path = Path(normalize_dat_input(dat_raw)) if dat_raw else None

        self._applying_defaults = True
        try:
            if include_workdir and dat_path is not None and dat_path.name:
                default_workdir = dat_path.parent / f"{dat_path.stem}_workflow"
                if force or not self.workdir_var.get().strip():
                    self.workdir_var.set(str(default_workdir))

            workdir_raw = self.workdir_var.get().strip()
            if not workdir_raw:
                return

            defaults = self._default_paths(Path(workdir_raw), dat_path)
            mapping = [
                ("unpacked", self.unpacked_var),
                ("texts", self.texts_var),
                ("rebuilt_scripts", self.rebuilt_scr_var),
                ("output_dat", self.output_dat_var),
            ]
            for key, var in mapping:
                if force or not var.get().strip() or not self._path_manual[key]:
                    var.set(str(defaults[key]))
                    self._path_manual[key] = False
        finally:
            self._applying_defaults = False

    def _derived_paths(self) -> dict[str, Path]:
        dat_raw = self.dat_path_var.get().strip()
        workdir_raw = self.workdir_var.get().strip()
        dat_path = Path(dat_raw) if dat_raw else None
        workdir = Path(workdir_raw) if workdir_raw else None
        dat_path = Path(normalize_dat_input(str(dat_path))) if dat_path is not None else None

        if workdir is None:
            return {
                "workdir": None,
                "unpacked": Path(self.unpacked_var.get().strip()) if self.unpacked_var.get().strip() else Path("-"),
                "ir": Path("-"),
                "texts": Path(self.texts_var.get().strip()) if self.texts_var.get().strip() else Path("-"),
                "rebuilt_scripts": Path(self.rebuilt_scr_var.get().strip()) if self.rebuilt_scr_var.get().strip() else Path("-"),
                "dat_input": Path("-"),
                "output_dat": Path(self.output_dat_var.get().strip()) if self.output_dat_var.get().strip() else Path("-"),
            }

        defaults = self._default_paths(workdir, dat_path)
        return {
            "workdir": workdir,
            "unpacked": Path(self.unpacked_var.get().strip()) if self.unpacked_var.get().strip() else defaults["unpacked"],
            "ir": workdir / "ir",
            "texts": Path(self.texts_var.get().strip()) if self.texts_var.get().strip() else defaults["texts"],
            "rebuilt_scripts": Path(self.rebuilt_scr_var.get().strip()) if self.rebuilt_scr_var.get().strip() else defaults["rebuilt_scripts"],
            "dat_input": workdir / "dat_input",
            "output_dat": Path(self.output_dat_var.get().strip()) if self.output_dat_var.get().strip() else defaults["output_dat"],
        }

    def _on_dat_changed(self) -> None:
        if self._applying_defaults:
            return
        self._apply_default_paths(force=False, include_workdir=True)

    def _on_workdir_changed(self) -> None:
        if self._applying_defaults:
            return
        self._apply_default_paths(force=False, include_workdir=False)

    def _mark_manual(self, key: str) -> None:
        if not self._applying_defaults:
            self._path_manual[key] = True

    def _on_unpacked_changed(self) -> None:
        self._mark_manual("unpacked")

    def _on_texts_changed(self) -> None:
        self._mark_manual("texts")

    def _on_rebuilt_changed(self) -> None:
        self._mark_manual("rebuilt_scripts")

    def _on_output_dat_changed(self) -> None:
        self._mark_manual("output_dat")

    def _autofill_workdir(self) -> None:
        self._apply_default_paths(force=True, include_workdir=True)

    def _require_inputs(self) -> tuple[Path, Path, str]:
        dat_raw = self.dat_path_var.get().strip()
        workdir_raw = self.workdir_var.get().strip()
        if not dat_raw:
            raise ValueError("请先选择 scr.dat")
        if not workdir_raw:
            raise ValueError("请先设置工作目录")
        dat_path = Path(normalize_dat_input(dat_raw))
        if not dat_path.is_file():
            raise FileNotFoundError(f"找不到文件: {dat_path}")
        return dat_path, Path(workdir_raw), ensure_codec(self.encoding_var.get())

    def _export_pipeline(self) -> dict[str, Any]:
        dat_path, workdir, encoding = self._require_inputs()
        paths = self._derived_paths()

        workdir.mkdir(parents=True, exist_ok=True)
        reset_dir(paths["unpacked"])
        reset_dir(paths["ir"])
        reset_dir(paths["texts"])
        reset_dir(paths["rebuilt_scripts"])
        reset_dir(paths["dat_input"])
        if paths["output_dat"].exists():
            paths["output_dat"].unlink()

        unpack_report = scr_dat_tool.unpack_archive(dat_path, paths["unpacked"])
        scripts_dir = discover_scr_root(paths["unpacked"])
        ir_report = scr_text_export_tool.disasm(scripts_dir, paths["ir"], encoding)
        text_report = scr_text_export_tool.export_text(paths["ir"], paths["texts"], relocate=True)

        return {
            "status": "ok",
            "step": "export",
            "scripts_dir": str(scripts_dir),
            "texts_dir": str(paths["texts"]),
            "unpack_files": unpack_report["archive_metadata"]["file_count"],
            "ir_totals": ir_report["totals"],
            "text_totals": text_report["totals"],
            "policy": text_report["policy"],
        }

    def _build_scr_pipeline(self) -> dict[str, Any]:
        _dat_path, _workdir, encoding = self._require_inputs()
        paths = self._derived_paths()

        if not (paths["ir"] / "project_manifest.json").exists():
            raise FileNotFoundError("还没有导出文本。请先执行“解包并导出文本”。")
        dsat_files = sorted(paths["texts"].glob("*.dsat.txt"))
        if not dsat_files:
            raise FileNotFoundError("文本目录下没有 .dsat.txt。请先执行导出文本。")

        reset_dir(paths["rebuilt_scripts"])
        compile_report = scr_text_ir_tool.compile_dynamic(
            paths["ir"],
            paths["texts"],
            paths["rebuilt_scripts"],
            target_encoding=encoding,
            strict=True,
        )
        return {
            "status": "ok",
            "step": "build_scr",
            "rebuilt_scripts": str(paths["rebuilt_scripts"]),
            "totals": compile_report["totals"],
            "changed_files": [x for x in compile_report["sources"] if not x["byte_exact"]][:10],
        }

    def _repack_dat_pipeline(self) -> dict[str, Any]:
        dat_path, _workdir, _encoding = self._require_inputs()
        paths = self._derived_paths()

        if not paths["unpacked"].exists():
            raise FileNotFoundError("解包目录不存在。请先执行“解包并导出文本”。")
        if not paths["rebuilt_scripts"].exists():
            raise FileNotFoundError("还没有回编 SCR。请先执行“翻译后回编 SCR”。")

        reset_dir(paths["dat_input"])
        make_report = scr_text_ir_tool.make_extract_dir_for_dat(paths["unpacked"], paths["rebuilt_scripts"], paths["dat_input"])
        if paths["output_dat"].exists():
            paths["output_dat"].unlink()
        dat_report = scr_dat_tool.repack_archive(paths["dat_input"], paths["output_dat"])

        return {
            "status": "ok",
            "step": "repack_dat",
            "original_dat": str(dat_path),
            "translated_dat": str(paths["output_dat"]),
            "files_replaced": make_report["files_replaced"],
            "dat_file_count": dat_report["file_count"],
            "dat_size": dat_report["byte_size"],
            "dat_sha256": dat_report["sha256"],
        }

    def _on_export_workflow(self) -> None:
        try:
            self._require_inputs()
        except Exception as exc:
            messagebox.showerror("参数错误", str(exc), parent=self.root)
            return
        self._start_task("解包并导出文本", self._export_pipeline)

    def _on_build_scr_workflow(self) -> None:
        try:
            self._require_inputs()
        except Exception as exc:
            messagebox.showerror("参数错误", str(exc), parent=self.root)
            return
        self._start_task("翻译后回编 SCR", self._build_scr_pipeline)

    def _on_repack_dat_workflow(self) -> None:
        try:
            self._require_inputs()
        except Exception as exc:
            messagebox.showerror("参数错误", str(exc), parent=self.root)
            return
        self._start_task("可选回封 DAT", self._repack_dat_pipeline)


def main() -> int:
    root = tk.Tk()
    app = SimpleWorkflowApp(root)
    app._append_log("GUI 已启动。先拖入 scr.dat，再点“解包并导出文本”。")
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
