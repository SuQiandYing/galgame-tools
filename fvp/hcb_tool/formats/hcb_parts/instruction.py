from __future__ import annotations

from dataclasses import asdict, dataclass

@dataclass
class Instruction:
    file: str
    offset: int
    opcode: int
    mnemonic: str
    args: list[dict]
    size: int
    raw_hex: str
    function_index: int | None = None
    label: str | None = None
    valid: bool = True
    comment: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["offset_hex"] = f"0x{self.offset:08X}"
        d["opcode_hex"] = f"0x{self.opcode:02X}" if self.opcode >= 0 else None
        return d

