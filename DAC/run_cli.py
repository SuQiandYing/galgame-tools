#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from daclocalizer.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
