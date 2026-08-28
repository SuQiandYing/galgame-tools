from __future__ import annotations

def decode_text(raw: bytes, encoding: str = "cp932") -> str:
    if not raw:
        return ""
    candidates = []
    if encoding:
        candidates.append(encoding)
    for enc in ("cp932", "shift_jis", "utf-8", "utf-16le", "gbk"):
        if enc not in candidates:
            candidates.append(enc)
    for enc in candidates:
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            pass
        except LookupError:
            continue
    fallback = encoding or "cp932"
    try:
        return raw.decode(fallback, errors="replace")
    except LookupError:
        return raw.decode("cp932", errors="replace")


def encode_text(text: str, encoding: str = "cp932") -> bytes:
    return text.encode(encoding or "cp932")


def escape_text(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t").replace('"', '\\"')

