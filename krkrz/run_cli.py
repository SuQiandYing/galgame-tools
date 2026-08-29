#!/usr/bin/env python3
"""无界面命令行入口（与图形界面共用同一个 StageService）。"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from psbscn.cli.main import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
