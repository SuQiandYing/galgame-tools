from __future__ import annotations

import bisect
import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from hcb_tool import __version__
from hcb_tool.core.binary_io import u32le, i32le, u16le, i16le, i8
from hcb_tool.core.hashcheck import hash_bytes
from hcb_tool.core.region_map import Region, normalize_regions, coverage_report

from .constants import PLUGIN_ID, PLUGIN_VERSION
from .instruction import Instruction
from .opcodes import OPDEFS
from .text_codec import decode_text, encode_text, escape_text


class ChoiceDetectorMixin:
    def _choice_append_pattern_after_call(self, call_idx: int) -> dict | None:
        """Detect the common FVP choice-option append pattern.

        Observed form after the option-render call:
          pushstack <count_slot>
          copystack <option_slot>
          pushstack <count_slot>
          pushint 1
          add
          copystack <count_slot>

        This is much more reliable than judging by text shape, so labels such as
        夏目鈴 / 新人さん / 開かずの間 become tag=choice instead of unknown_string.
        """
        if call_idx + 6 >= len(self.instructions):
            return None
        seq = self.instructions[call_idx + 1: call_idx + 7]
        if len(seq) != 6 or not all(x.valid for x in seq):
            return None
        if not (seq[0].opcode == 0x10 and seq[1].opcode == 0x16 and seq[2].opcode == 0x10 and
                seq[3].opcode in (0x0A, 0x0B, 0x0C) and seq[4].opcode == 0x1A and seq[5].opcode == 0x16):
            return None
        count_slot_a = int(seq[0].args[0]["value"])
        count_slot_b = int(seq[2].args[0]["value"])
        count_slot_c = int(seq[5].args[0]["value"])
        inc = self._literal_int(seq[3])
        if count_slot_a != count_slot_b or count_slot_a != count_slot_c or inc != 1:
            return None
        return {
            "count_slot": count_slot_a,
            "option_slot": int(seq[1].args[0]["value"]),
            "pattern_start_offset": seq[0].offset,
            "pattern_end_offset": seq[-1].offset + seq[-1].size,
        }

    def _find_choice_commit_call_after(self, start_idx: int, same_func: int | None, max_scan: int = 80) -> dict | None:
        """Find the menu-finalize call that usually appears after a group of options."""
        argc_map = self._function_arg_counts()
        for j in range(start_idx + 1, min(len(self.instructions), start_idx + 1 + max_scan)):
            ins = self.instructions[j]
            if ins.function_index != same_func:
                break
            if ins.valid and ins.opcode == 0x01:
                break
            if ins.valid and ins.opcode == 0x02 and ins.args:
                target = int(ins.args[0]["value"])
                argc = argc_map.get(target)
                # The choice-open/finalize function is usually argc=0.  Stop on the
                # first such call after option append patterns.
                if argc == 0:
                    return {
                        "choice_commit_offset": ins.offset,
                        "choice_commit_offset_hex": f"0x{ins.offset:08X}",
                        "choice_commit_target": target,
                        "choice_commit_target_hex": f"0x{target:08X}",
                    }
        return None

    def _find_choice_jump_after_commit(self, commit_idx: int, option_slot: int, same_func: int | None, max_scan: int = 80) -> dict | None:
        """Best-effort jump target for the selected option.

        Typical route table code checks pushstack <option_slot> against a global
        selected-value and then jumps.  This is optional metadata; missing it must
        not stop choice tagging.
        """
        for j in range(commit_idx + 1, min(len(self.instructions), commit_idx + 1 + max_scan)):
            ins = self.instructions[j]
            if ins.function_index != same_func:
                break
            seq = self.instructions[j:j + 5]
            if len(seq) < 5 or not all(x.valid for x in seq):
                continue
            if seq[0].opcode == 0x10 and int(seq[0].args[0]["value"]) == option_slot and seq[1].opcode == 0x0F and seq[2].opcode == 0x22 and seq[3].opcode == 0x07:
                # The not-selected branch jumps over a following jmp; that following
                # jmp is usually the route for this option.
                if seq[4].opcode == 0x06 and seq[4].args:
                    target = int(seq[4].args[0]["value"])
                    return {
                        "jump_offset": seq[4].offset,
                        "jump_offset_hex": f"0x{seq[4].offset:08X}",
                        "jump_target": target,
                        "jump_target_hex": f"0x{target:08X}",
                    }
        return None

    def _infer_choice_events(self, argc_map: dict[int, int], text_target: int | None, name_target: int | None) -> list[dict]:
        choice_events: list[dict] = []
        current_group_key: tuple[int | None, int] | None = None
        group_counter = 0
        last_choice_idx = -999999
        # Cache commit call lookup per group tail so we do not rescan too much.
        for i, ins in enumerate(self.instructions):
            if not ins.valid or ins.opcode != 0x02 or not ins.args:
                continue
            target = int(ins.args[0]["value"])
            if target in (text_target, name_target):
                continue
            _target, args = self._call_args_at_index(i, argc_map)
            if not args:
                continue
            strings = [a for a in args if a.get("kind") == "string"]
            if len(strings) != 1:
                continue
            pattern = self._choice_append_pattern_after_call(i)
            if not pattern:
                continue
            # Group nearby options in the same function and rendered by the same target.
            key = (ins.function_index, target)
            if current_group_key != key or i - last_choice_idx > 120:
                group_counter += 1
                current_group_key = key
            last_choice_idx = i
            commit = self._find_choice_commit_call_after(i + 6, ins.function_index) or {}
            commit_idx = None
            if commit.get("choice_commit_offset") is not None:
                # Convert offset to instruction index for optional jump lookup.
                for jj in range(i + 1, min(len(self.instructions), i + 120)):
                    if self.instructions[jj].offset == commit["choice_commit_offset"]:
                        commit_idx = jj
                        break
            jump = self._find_choice_jump_after_commit(commit_idx, pattern["option_slot"], ins.function_index) if commit_idx is not None else None
            text_arg = strings[0]
            row = {
                "file": self.file,
                "event_id": len(choice_events) + 1,
                "event_type": "choice_option",
                "tag": "choice",
                "function_index": ins.function_index,
                "choice_group": f"choice_{group_counter:05d}",
                "choice_index": len([e for e in choice_events if e.get("choice_group") == f"choice_{group_counter:05d}"]) + 1,
                "choice_render_target": target,
                "choice_render_target_hex": f"0x{target:08X}",
                "choice_call_offset": ins.offset,
                "choice_call_offset_hex": f"0x{ins.offset:08X}",
                "instruction_offset": text_arg.get("instruction_offset"),
                "instruction_offset_hex": text_arg.get("instruction_offset_hex"),
                "text": text_arg.get("text", ""),
                "text_string_data_offset": text_arg.get("data_offset"),
                "text_string_data_offset_hex": text_arg.get("data_offset_hex"),
                "text_len": text_arg.get("len"),
                "count_slot": pattern.get("count_slot"),
                "option_slot": pattern.get("option_slot"),
                "confidence": "high",
            }
            row.update(commit)
            if jump:
                row.update(jump)
            choice_events.append(row)
        return choice_events


