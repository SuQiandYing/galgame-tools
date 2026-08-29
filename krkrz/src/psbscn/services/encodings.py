"""编码选项。

源编码用于解码原文，目标编码用于写回译文。语料实测全部是 UTF-8，但其他作品可能
是 CP932，所以两者都可选而不是写死。
"""
from __future__ import annotations

import codecs

# 顺序即下拉框顺序，第一项是默认值。
SOURCE_ENCODINGS = ("utf-8", "cp932", "shift_jis", "gbk", "big5",
                    "utf-16-le", "euc-jp", "latin-1")
TARGET_ENCODINGS = ("utf-8", "gbk", "gb18030", "cp932", "shift_jis", "big5",
                    "utf-16-le")

DEFAULT_SOURCE = SOURCE_ENCODINGS[0]
DEFAULT_TARGET = TARGET_ENCODINGS[0]


def check(name: str) -> str:
    """校验编码名可用，返回 Python 的规范名。"""
    try:
        return codecs.lookup(name).name
    except LookupError as exc:
        raise ValueError(f"未知编码 {name!r}") from exc
