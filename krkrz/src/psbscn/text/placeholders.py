"""剧本字符串中控制字节的占位符编码。

0x20 以下的任何字节以及 0x7F 都会被转义为大写 `{{XX}}`（连续段合并为
`{{XX:YY}}`），使译者既无法删除、也无法静默改写控制码。语料中的字符串不含裸控制
字节，所以实际只有在源文件被编辑过、或载入其他作品时才会出现占位符；机制本身
始终严格执行。
"""
from __future__ import annotations

import hashlib
import re

PLACEHOLDER_RE = re.compile(r"\{\{([0-9A-F]{2}(?::[0-9A-F]{2})*)\}\}")
LOOSE_RE = re.compile(r"\{\{[^{}]*\}\}")


def _is_control(byte: int) -> bool:
    return byte < 0x20 or byte == 0x7F


def encode(raw: bytes, encoding: str = "utf-8") -> str:
    """把原始字符串字节渲染为带 `{{XX}}` 控制占位符的文本。"""
    out: list[str] = []
    run: list[int] = []
    plain = bytearray()

    def flush_plain() -> None:
        if plain:
            out.append(plain.decode(encoding, "surrogateescape"))
            plain.clear()

    def flush_run() -> None:
        if run:
            out.append("{{" + ":".join(f"{b:02X}" for b in run) + "}}")
            run.clear()

    for byte in raw:
        if _is_control(byte):
            flush_plain()
            run.append(byte)
        else:
            flush_run()
            plain.append(byte)
    flush_run()
    flush_plain()
    return "".join(out)


def decode(text: str, encoding: str = "utf-8") -> bytes:
    """`encode` 的逆运算；拒绝格式错误或小写的占位符。"""
    from ..core.errors import PlaceholderError

    out = bytearray()
    pos = 0
    for loose in LOOSE_RE.finditer(text):
        strict = PLACEHOLDER_RE.fullmatch(loose.group(0))
        if strict is None:
            raise PlaceholderError(
                f"占位符格式错误 {loose.group(0)!r}；应为大写的 "
                "{{XX}} 或 {{XX:YY:...}}")
        out += text[pos:loose.start()].encode(encoding, "surrogateescape")
        out += bytes(int(h, 16) for h in strict.group(1).split(":"))
        pos = loose.end()
    out += text[pos:].encode(encoding, "surrogateescape")
    return bytes(out)


def extract(text: str) -> list[str]:
    """按出现顺序列出 `text` 中的占位符记号。"""
    return [m.group(0) for m in LOOSE_RE.finditer(text)]


def signature(text: str) -> tuple[int, int, str]:
    """对有序占位符记号列表返回 `(数量, 字节数, sha256)`。"""
    tokens = extract(text)
    byte_count = 0
    for token in tokens:
        strict = PLACEHOLDER_RE.fullmatch(token)
        if strict is not None:
            byte_count += len(strict.group(1).split(":"))
    digest = hashlib.sha256("\x1f".join(tokens).encode("utf-8")).hexdigest()
    return len(tokens), byte_count, digest
