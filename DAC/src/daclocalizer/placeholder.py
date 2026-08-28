# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import re

BRACE_PLACEHOLDER_RE = re.compile(r"\{\{([0-9A-F]{2}(?::[0-9A-F]{2})*)\}\}")
BAD_BRACE_START_RE = re.compile(r"\{\{")
LEGACY_HEX_RE = re.compile(r"\\x[0-9A-Fa-f]{1,2}")


class PlaceholderError(ValueError):
    pass


def bytes_to_placeholder(raw: bytes) -> str:
    return "{{" + ":".join(f"{b:02X}" for b in raw) + "}}"


def _validate_no_bad_placeholder(text: str) -> None:
    r"""Reject malformed {{XX:YY}} placeholders and legacy \xNN in human files."""
    if LEGACY_HEX_RE.search(text):
        raise PlaceholderError("legacy \\xNN placeholder is forbidden; use {{XX}} or {{XX:YY}}")
    pos = 0
    while True:
        start = text.find("{{", pos)
        if start < 0:
            break
        end = text.find("}}", start + 2)
        if end < 0:
            raise PlaceholderError(f"unterminated placeholder at char {start}; expected {{XX}} or {{XX:YY}}")
        token = text[start:end + 2]
        if not BRACE_PLACEHOLDER_RE.fullmatch(token):
            raise PlaceholderError(f"invalid placeholder {token!r}; expected uppercase {{XX}} or {{XX:YY}}")
        pos = end + 2


def visible_escape_from_bytes(raw: bytes, encoding: str = "cp932") -> str:
    """Render arbitrary bytes as editable text with {{XX}} placeholders for unsafe bytes.

    This is intentionally conservative: printable text is decoded through the selected
    script encoding; NUL/control bytes and bytes that cannot decode are emitted as
    {{XX}} tokens so editors cannot destroy them.
    """
    out: list[str] = []
    i = 0
    while i < len(raw):
        b = raw[i]
        if b < 0x20 and b not in (0x09,):
            out.append(bytes_to_placeholder(bytes([b])))
            i += 1
            continue
        try:
            # Try one byte first for ASCII/control-safe text.
            if b < 0x80:
                out.append(bytes([b]).decode(encoding))
                i += 1
            else:
                # Try two-byte CP932/SJIS style code unit, then fall back to placeholder.
                if i + 1 < len(raw):
                    out.append(raw[i:i+2].decode(encoding))
                    i += 2
                else:
                    out.append(bytes_to_placeholder(bytes([b])))
                    i += 1
        except UnicodeDecodeError:
            out.append(bytes_to_placeholder(bytes([b])))
            i += 1
    return "".join(out)


def decode_dsat_text(text: str, encoding: str = "cp932") -> bytes:
    """Encode DSAT/ASM visible text to bytes, restoring {{XX:YY}} placeholders."""
    _validate_no_bad_placeholder(text)
    out = bytearray()
    i = 0
    while i < len(text):
        m = BRACE_PLACEHOLDER_RE.match(text, i)
        if m:
            out.extend(int(x, 16) for x in m.group(1).split(":"))
            i = m.end()
            continue
        # Other literal braces are normal text.
        out.extend(text[i].encode(encoding, errors="strict"))
        i += 1
    return bytes(out)


def dsat_text_to_plain_string(text: str, encoding: str = "cp932") -> str:
    """Return a Python str suitable for source-line rewriting.

    The bytes must be decodable with the target encoding. If a future script uses
    non-decodable binary controls inside source lines, the importer will stop rather
    than silently corrupt data.
    """
    return decode_dsat_text(text, encoding).decode(encoding, errors="strict")


def extract_placeholder_hex(text: str) -> list[str]:
    _validate_no_bad_placeholder(text)
    return [m.group(1).replace(":", "") for m in BRACE_PLACEHOLDER_RE.finditer(text)]


def extract_placeholder_display(text: str) -> list[str]:
    _validate_no_bad_placeholder(text)
    return [m.group(0) for m in BRACE_PLACEHOLDER_RE.finditer(text)]


def placeholder_hash(hex_list: list[str]) -> str:
    joined = "|".join(hex_list)
    return hashlib.sha256(joined.encode("ascii")).hexdigest() if hex_list else ""


def validate_placeholder_preserve(src: str, dst: str, strict_order: bool = True) -> None:
    a = extract_placeholder_hex(src)
    b = extract_placeholder_hex(dst)
    if strict_order:
        if a != b:
            raise PlaceholderError(f"placeholder mismatch: expected {a}, actual {b}")
    else:
        if sorted(a) != sorted(b):
            raise PlaceholderError(f"placeholder mismatch: expected {a}, actual {b}")
