from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class InstructionSet:
    param_set_opcode: int = 0x00010001
    push_immediate_opcode: int = 0x0001001F
    call_opcode: int = 0x00010017


@dataclass(frozen=True, slots=True)
class TextEntry:
    order: int
    idx: int
    entry_offset: int
    raw_text: bytes
    original_text: str

    @property
    def entry_bytes(self) -> bytes:
        return struct.pack("<I", self.idx) + self.raw_text + b"\x00"


@dataclass(frozen=True, slots=True)
class MessageEvent:
    call_offset: int
    call_id: int
    line_id: int
    flags: tuple[int, ...]
    text_offset: int
    text_idx: int
    text: str
    name_offset: int | None
    name_idx: int | None
    name: str | None
    kind: str


@dataclass(frozen=True, slots=True)
class ScriptWord:
    offset: int
    value: int


@dataclass(frozen=True, slots=True)
class NameTextContext:
    candidate_entry: TextEntry
    message_entry: TextEntry
    candidate_text: str
    message_text: str


@dataclass(frozen=True, slots=True)
class TextClassificationContext:
    entry: TextEntry
    roles: tuple[str, ...]
    reference_offsets: tuple[int, ...]
    direct_call_ids: tuple[int, ...]
    message_text_count: int = 0
    speaker_name_count: int = 0
    paired_texts: tuple[str, ...] = ()
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def call_id_set(self) -> set[int]:
        return set(self.direct_call_ids)

    @property
    def primary_role(self) -> str:
        role_set = set(self.roles)
        for preferred in (
            "speaker_name",
            "choice_text",
            "message_text",
            "script_label",
            "other_reference",
            "unreferenced",
        ):
            if preferred in role_set:
                return preferred
        return self.roles[0] if self.roles else "unreferenced"


@dataclass(frozen=True, slots=True)
class ScenarioBoundary:
    anchor_idx: int
    name: str
    kind: str
    reason: str


@dataclass(frozen=True, slots=True)
class TextDatArchive:
    header: bytes
    entries: tuple[TextEntry, ...]
    trailer: bytes
    normalized_data: bytes
    was_encrypted: bool
    input_mode: str


@dataclass(frozen=True, slots=True)
class DumpArtifacts:
    manifest: dict[str, Any]
    text_rows: list[dict[str, Any]]
    message_rows: list[dict[str, Any]]
    script_rows: list[dict[str, Any]]
