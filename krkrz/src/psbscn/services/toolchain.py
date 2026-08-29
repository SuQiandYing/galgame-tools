"""工具链探测。

可选组件一律先探测再报告，绝不假设存在。核心解析只使用标准库，因此缺少某个可选
依赖只会影响 GUI 表现，绝不改变解析结果。
"""
from __future__ import annotations

import importlib.util
import platform
import shutil
import sys
from typing import Any

TOOL_VERSION = "1.0.0"
OPTIONAL_MODULES = ("PySide6", "tkinter", "tkinterdnd2", "pytest")
OPTIONAL_BINARIES = ("git",)


def probe_toolchain() -> dict[str, Any]:
    """报告解释器、平台与可选组件的可用性。"""
    modules: dict[str, Any] = {}
    for name in OPTIONAL_MODULES:
        try:
            spec = importlib.util.find_spec(name)
        except (ImportError, ValueError):
            spec = None
        modules[name] = {
            "available": spec is not None,
            "origin": getattr(spec, "origin", None) if spec else None,
        }
    binaries = {name: shutil.which(name) for name in OPTIONAL_BINARIES}
    return {
        "tool": "psbscn",
        "tool_version": TOOL_VERSION,
        "python": sys.version.split()[0],
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "core_dependencies": ["python-stdlib-only"],
        "optional_modules": modules,
        "optional_binaries": binaries,
        "gui_backend": _gui_backend(modules),
        "notes": [
            "核心的解析、回封与验证只使用标准库。",
            "二进制解码过程不调用任何外部命令。",
        ],
    }


def _gui_backend(modules: dict[str, Any]) -> str:
    if modules.get("PySide6", {}).get("available"):
        return "PySide6"
    if modules.get("tkinter", {}).get("available"):
        dnd = modules.get("tkinterdnd2", {}).get("available")
        return "tkinter+tkinterdnd2" if dnd else "tkinter"
    return "none"


def fingerprint() -> str:
    return f"psbscn/{TOOL_VERSION} python/{sys.version.split()[0]}"
