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


class SemanticHelpersMixin:
    def _looks_like_speaker_name(self, text: str) -> bool:
        """Return True only for plausible speaker-name slots.

        v0.2.5 treated every argc=2 string-render call as a name definition.
        Some HCBs use the same call shape for route/chapter labels or choice text,
        so full sentence strings were wrongly emitted as names.
        This filter keeps short speaker-like labels and rejects chapter/menu/choice
        sentences before building speaker maps.
        """
        t = self._clean_speaker(text)
        if not t:
            return False
        if any(k in t for k in ("選択", "イベント", "テスト", "タイトル", "アルバム", "マップ", "画面", "開始", "初めから")):
            return False
        # Real names are normally short.  Allow things like 瑠々＠？？？ but reject
        # full choice/dialogue sentences.
        if len(t) > 18:
            return False
        if any(ch in t for ch in "。！？!?,，、「」『』（）()[]【】/\\"):
            # Keep pure mystery-name patterns like ？？？.
            if set(t) <= {"？", "?", "＠", "@"}:
                return True
            return False
        return True

    def _looks_like_choice_label(self, text: str) -> bool:
        t = (text or "").strip()
        if not t:
            return False
        if self._looks_like_speaker_name(t):
            return False
        lower = t.lower()
        if "/" in t or "\\" in t:
            # Debug/menu labels with slashes are still selectable UI, not speaker names.
            return True
        if re.fullmatch(r"[A-Za-z0-9_./:-]+", t):
            return False
        return True

    def _literal_int(self, ins: Instruction) -> int | None:
        if not ins.valid:
            return None
        if ins.opcode in (0x08, 0x09):
            return 1 if ins.opcode == 0x08 else 0
        if ins.opcode in (0x0A, 0x0B, 0x0C) and ins.args:
            return int(ins.args[0]["value"])
        return None

    def _last_pushstring_before_call(self, call_idx: int, max_scan: int = 10) -> dict | None:
        """Return the nearest pushstring that is part of a call's stack args.

        `_call_args_at_index` is intentionally strict and fails when an argument is
        built as `pushint 1; neg`.  Chapter title calls in several HCBs use exactly
        that pattern, so chapter detection needs a small opcode-level scanner that
        looks for the string argument before the call without judging by the text.
        """
        for j in range(call_idx - 1, max(-1, call_idx - max_scan - 1), -1):
            ins = self.instructions[j]
            if ins.valid and ins.opcode == 0x0E and ins.args:
                a = ins.args[0]
                return {
                    "kind": "string",
                    "text": a.get("text", ""),
                    "instruction_offset": ins.offset,
                    "instruction_offset_hex": f"0x{ins.offset:08X}",
                    "data_offset": a.get("data_offset"),
                    "data_offset_hex": a.get("data_offset_hex"),
                    "len": a.get("len"),
                    "raw_hex": a.get("raw_hex", ""),
                    "call_arg_scan_index": j,
                }
            # A previous call/jump/return/initstack starts a new expression block.
            if ins.opcode in (0x01, 0x02, 0x04, 0x05, 0x06, 0x07):
                break
        return None

    def _is_internal_string_arg(self, text: str) -> bool:
        t = (text or "").strip()
        if not t:
            return False
        if "/" in t or "\\" in t:
            return True
        # ASCII-ish identifiers such as BG001_080, SHINKU_e01a, sel_bunner1.
        if re.fullmatch(r"[A-Za-z0-9_./:-]+", t):
            return True
        return False

    def _target_has_adjacent_menu_runs(self, call_indices: list[int], target: int) -> bool:
        if len(call_indices) < 3:
            return False
        adjacent = 0
        for a, b in zip(call_indices, call_indices[1:]):
            ia = self.instructions[a]
            ib = self.instructions[b]
            if ia.function_index == ib.function_index and 0 < (b - a) <= 8:
                adjacent += 1
        # Menu/choice renderers often appear as runs of option calls:
        #   pushstring A; call T; pushstring B; call T; ...
        return adjacent >= max(2, int(len(call_indices) * 0.35))


