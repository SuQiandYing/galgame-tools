from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass
class HexDiff:
    equal: bool
    size_equal: bool
    first_diff_offset: int | None
    original_size: int
    rebuilt_size: int
    original_bytes: str = ""
    rebuilt_bytes: str = ""
    possible_causes: list[str] | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def first_diff(a: bytes, b: bytes, context: int = 16) -> HexDiff:
    min_len = min(len(a), len(b))
    first = None
    for i in range(min_len):
        if a[i] != b[i]:
            first = i
            break
    if first is None and len(a) != len(b):
        first = min_len
    if first is None:
        return HexDiff(True, True, None, len(a), len(b), possible_causes=[])
    lo = max(0, first - context)
    hi = min(max(len(a), len(b)), first + context)
    causes = [
        "patch wrote wrong offset or length",
        "padding changed",
        "string was re-encoded when it should have been kept raw",
        "unknown field was serialized instead of preserved",
        "header/table size or pointer changed",
    ]
    return HexDiff(
        equal=False,
        size_equal=(len(a) == len(b)),
        first_diff_offset=first,
        original_size=len(a),
        rebuilt_size=len(b),
        original_bytes=a[lo:min(len(a), hi)].hex(" ").upper(),
        rebuilt_bytes=b[lo:min(len(b), hi)].hex(" ").upper(),
        possible_causes=causes,
    )
