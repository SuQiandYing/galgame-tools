from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from ..binary.primitives import read_u32
from ..core.models import InstructionSet, ScriptWord, TextEntry


@dataclass(frozen=True, slots=True)
class ParsedScript:
    raw_data: bytes
    words: tuple[int, ...]
    instruction_set: InstructionSet

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        instruction_set: InstructionSet | None = None,
    ) -> "ParsedScript":
        instruction_set = instruction_set or InstructionSet()
        if len(data) % 4 != 0:
            raise ValueError("SCRIPT.SRC is not 4-byte aligned")
        words = tuple(read_u32(data, offset) for offset in range(0, len(data), 4))
        return cls(raw_data=data, words=words, instruction_set=instruction_set)

    def iter_words(self) -> Iterable[ScriptWord]:
        for index, value in enumerate(self.words):
            yield ScriptWord(offset=index * 4, value=value)

    def build_reference_map(self, text_map: Mapping[int, TextEntry]) -> dict[int, list[int]]:
        refs: dict[int, list[int]] = {offset: [] for offset in text_map}
        for word in self.iter_words():
            if word.value in refs:
                refs[word.value].append(word.offset)
        return refs

    def find_call_word_indexes(self, call_id: int | None = None) -> list[int]:
        hits: list[int] = []
        call_opcode = self.instruction_set.call_opcode
        for i in range(len(self.words) - 2):
            if self.words[i] != call_opcode:
                continue
            if self.words[i + 2] != 0:
                continue
            if call_id is not None and self.words[i + 1] != call_id:
                continue
            hits.append(i)
        return hits

    def build_direct_call_id_map(
        self,
        refs: Mapping[int, list[int]],
        *,
        lookahead_words: int = 16,
    ) -> dict[int, list[int]]:
        direct_call_ids: dict[int, list[int]] = {}
        instructions = self.instruction_set
        words = self.words
        for entry_offset, word_offsets in refs.items():
            call_ids: set[int] = set()
            for word_offset in word_offsets:
                i = word_offset // 4
                if i + 2 < len(words) and words[i + 1] == instructions.call_opcode:
                    call_ids.add(words[i + 2])
                if i > 0 and words[i - 1] == instructions.push_immediate_opcode:
                    end = min(len(words) - 1, i + lookahead_words + 1)
                    for j in range(i + 1, end):
                        if words[j] == instructions.call_opcode:
                            call_ids.add(words[j + 1])
                            break
                if (
                    i >= 2
                    and words[i - 2] == instructions.param_set_opcode
                    and (words[i - 1] & 0xFFFF0000) == 0x30000000
                ):
                    end = min(len(words) - 1, i + lookahead_words + 1)
                    for j in range(i + 1, end):
                        if words[j] == instructions.call_opcode:
                            call_ids.add(words[j + 1])
                            break
            direct_call_ids[entry_offset] = sorted(call_ids)
        return direct_call_ids

    def to_rows(self, text_map: Mapping[int, TextEntry]) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for word in self.iter_words():
            entry = text_map.get(word.value)
            row: dict[str, object] = {
                "offset": word.offset,
                "offset_hex": f"0x{word.offset:08X}",
                "u32": word.value,
                "u32_hex": f"0x{word.value:08X}",
            }
            if entry is not None:
                row["text_idx"] = entry.idx
                row["text_preview"] = entry.original_text[:80]
            rows.append(row)
        return rows
