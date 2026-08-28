from __future__ import annotations

# Compatibility wrapper.  The implementation was split into hcb_parts/* so old
# imports such as `from hcb_tool.formats.hcb import HCBPlugin` keep working.
from .hcb_parts import (
    HCBPlugin,
    Instruction,
    OPDEFS,
    _HCBParser,
    decode_text,
    encode_text,
    escape_text,
)

__all__ = [
    "HCBPlugin",
    "Instruction",
    "OPDEFS",
    "_HCBParser",
    "decode_text",
    "encode_text",
    "escape_text",
]
