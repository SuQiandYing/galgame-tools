#!/usr/bin/env python3
"""图形界面入口。优先 PySide6，缺失时回退到 Tkinter。

两种后端都调用同一个 StageService；UI 线程都不解析二进制。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))


def main() -> int:
    try:
        from psbscn.gui.app import run
    except ImportError as exc:
        print(f"PySide6 不可用（{exc}），回退到 Tkinter。", file=sys.stderr)
        try:
            from psbscn.gui.tk_app import run  # type: ignore[assignment]
        except ImportError as tk_exc:
            print("没有可用的图形界面工具包。请安装 PySide6"
                  f"（pip install PySide6）或启用 tkinter：{tk_exc}",
                  file=sys.stderr)
            print("没有图形界面也可以使用命令行：python run_cli.py --help",
                  file=sys.stderr)
            return 3
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
