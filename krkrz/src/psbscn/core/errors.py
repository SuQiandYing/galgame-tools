"""专用异常体系。

每个失败都必须能定位到文件、偏移以及期望值/实际值。
"""
from __future__ import annotations


class PsbError(Exception):
    """所有工具错误的基类。"""


class ProbeRejected(PsbError):
    """输入不满足 PSB v3 假设，或评分不足。"""


class ParseError(PsbError):
    """解码某个区域时发现结构违规。"""

    def __init__(self, message: str, *, offset: int | None = None,
                 expected: object = None, actual: object = None) -> None:
        parts = [message]
        if offset is not None:
            parts.append(f"偏移=0x{offset:X}")
        if expected is not None:
            parts.append(f"期望={expected!r}")
        if actual is not None:
            parts.append(f"实际={actual!r}")
        super().__init__(" ".join(parts))
        self.offset = offset
        self.expected = expected
        self.actual = actual


class AddressSpaceCollisionError(ParseError):
    """两个区间对同一字节声明了不同归属。"""


class AddressSpaceGapError(ParseError):
    """[0, source_size) 内存在没有归属的字节。"""


class UnknownOpcodeError(ParseError):
    """值区中出现未定义的 PSB 类型字节。"""


class TextImportError(PsbError):
    """DSAT 内容未通过严格校验门禁。"""


class PlaceholderError(TextImportError):
    """占位符集合、顺序或取值被译者改动。"""


class InPlaceOverflowError(PsbError):
    """in_place 模式下编辑后的字节超出原槽位。"""


class RepackError(PsbError):
    """重序列化无法满足布局计划。"""


class VerifyError(PsbError):
    """零编辑往返同一性或证书门禁失败。"""
