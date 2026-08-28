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


class SemanticsMixin:
    def _infer_semantics(self) -> dict:
        if self._semantic_cache is not None:
            return self._semantic_cache
        argc_map = self._function_arg_counts()
        text_target, preferred_name_target = self._infer_call_targets(argc_map)

        # Speaker/name mapping is handled by a dedicated module.  It supports both
        # normal text-name resolver functions and hime-style name_* resource
        # resolver functions, then exposes speaker_maps for direct/alias calls.
        name_info = self._infer_name_mapping(argc_map, preferred_name_target)
        name_target = name_info.get("name_render_target")
        choice_argc2_target: int | None = name_info.get("choice_argc2_target")
        name_defs: list[dict] = list(name_info.get("name_definitions", []))
        rejected_name_defs: list[dict] = list(name_info.get("rejected_name_definitions", []))
        name_maps: dict[int, list[dict]] = name_info.get("name_maps", defaultdict(list))
        speaker_maps: dict[int, list[dict]] = name_info.get("speaker_maps", name_maps)

        dialogue_events: list[dict] = []
        current_speaker: dict | None = None
        current_speaker_call: Instruction | None = None
        cur_func: int | None = None
        for i, ins in enumerate(self.instructions):
            if ins.valid and ins.opcode == 0x01:
                cur_func = ins.function_index
                current_speaker = None
                current_speaker_call = None
                continue
            if not ins.valid or ins.opcode != 0x02 or not ins.args:
                continue
            target = int(ins.args[0]["value"])
            _, args = self._call_args_at_index(i, argc_map)
            if target in speaker_maps:
                first_arg = None
                if args and args[0].get("kind") == "literal":
                    first_arg = int(args[0]["value"])
                current_speaker = self._resolve_speaker_name(speaker_maps, target, first_arg)
                current_speaker_call = ins
                continue
            if text_target is not None and target == text_target and args:
                strings = [a for a in args if a.get("kind") == "string"]
                if not strings:
                    continue
                text_arg = strings[0]
                sp = current_speaker or {}
                ev = {
                    "file": self.file,
                    "event_id": len(dialogue_events) + 1,
                    "event_type": "dialogue_text",
                    "tag": "text",
                    "function_index": cur_func,
                    "instruction_offset": text_arg.get("instruction_offset"),
                    "instruction_offset_hex": text_arg.get("instruction_offset_hex"),
                    "text_call_offset": ins.offset,
                    "text_call_offset_hex": f"0x{ins.offset:08X}",
                    "text_render_target": text_target,
                    "text": text_arg.get("text", ""),
                    "text_string_data_offset": text_arg.get("data_offset"),
                    "text_string_data_offset_hex": text_arg.get("data_offset_hex"),
                    "text_len": text_arg.get("len"),
                    "speaker_call_offset": current_speaker_call.offset if current_speaker_call else None,
                    "speaker_call_offset_hex": f"0x{current_speaker_call.offset:08X}" if current_speaker_call else "",
                    "speaker_resolver_function_offset": sp.get("resolver_function_offset"),
                    "speaker_resolver_function_offset_hex": sp.get("resolver_function_offset_hex", ""),
                    "speaker_condition_key": sp.get("condition_key"),
                    "speaker_display": sp.get("display_clean", ""),
                    "speaker_real": sp.get("real_clean", ""),
                    "speaker_display_raw": sp.get("display_text", ""),
                    "speaker_real_raw": sp.get("real_text", ""),
                    "speaker_name_data_offset": sp.get("real_string_data_offset") or sp.get("display_string_data_offset"),
                    "speaker_name_data_offset_hex": sp.get("real_string_data_offset_hex") or sp.get("display_string_data_offset_hex", ""),
                    "speaker_name_instruction_offset": sp.get("real_string_instruction_offset") or sp.get("display_string_instruction_offset"),
                    "speaker_name_instruction_offset_hex": sp.get("real_string_instruction_offset_hex") or sp.get("display_string_instruction_offset_hex", ""),
                    "speaker_name_len": sp.get("real_len") or sp.get("display_len"),
                    "confidence": "medium" if sp else "low",
                }
                dialogue_events.append(ev)
        choice_events = self._infer_choice_events(argc_map, text_target, name_target)

        # Detect chapter/title calls before compatibility choice retagging, so an
        # argc=2 title renderer is not swallowed as a false choice target.  This is
        # still pure structure: function scope + call target + opcode arguments.
        chapter_events = self._infer_chapter_events(argc_map, text_target, name_target, choice_events, dialogue_events)
        chapter_instr_offsets = {e.get("instruction_offset") for e in chapter_events if e.get("instruction_offset") is not None}

        # Extra compatibility: option text in hime-like scripts may use the same
        # renderer shape that older builds mistook for a name definition.  Retag
        # rejected argc=2 rows, or all calls to a globally rejected argc=2 target,
        # as choices using structural/asset checks only.
        seen_choice_instr = {e.get("instruction_offset") for e in choice_events}
        choice_counts_by_func: dict[int, int] = defaultdict(int)
        for e in choice_events:
            if e.get("function_index") is not None:
                choice_counts_by_func[int(e["function_index"])] += 1

        def add_compat_choice(func_i: int, call_off: int, target: int | None, text_arg: dict, note: str, force: bool = False) -> None:
            instr_off = text_arg.get("instruction_offset")
            txt = str(text_arg.get("text", ""))
            if instr_off in seen_choice_instr or instr_off is None or instr_off in chapter_instr_offsets:
                return
            if force:
                if not txt.strip() or re.fullmatch(r"[A-Za-z0-9_./:-]+", txt.strip()):
                    return
            elif not self._looks_like_choice_label(txt):
                return
            choice_counts_by_func[func_i] += 1
            row = {
                "file": self.file,
                "event_id": len(choice_events) + 1,
                "event_type": "choice_option",
                "tag": "choice",
                "function_index": func_i,
                "choice_group": f"choice_func{func_i:05d}",
                "choice_index": choice_counts_by_func[func_i],
                "choice_render_target": target,
                "choice_render_target_hex": f"0x{int(target):08X}" if target is not None else "",
                "choice_call_offset": call_off,
                "choice_call_offset_hex": f"0x{call_off:08X}",
                "instruction_offset": instr_off,
                "instruction_offset_hex": text_arg.get("instruction_offset_hex", ""),
                "text": txt,
                "text_string_data_offset": text_arg.get("data_offset"),
                "text_string_data_offset_hex": text_arg.get("data_offset_hex", ""),
                "text_len": text_arg.get("len"),
                "confidence": "medium",
                "compat_note": note,
            }
            choice_events.append(row)
            seen_choice_instr.add(instr_off)

        for nd in rejected_name_defs:
            txt_arg = {
                "instruction_offset": nd.get("real_string_instruction_offset") or nd.get("display_string_instruction_offset"),
                "instruction_offset_hex": nd.get("real_string_instruction_offset_hex") or nd.get("display_string_instruction_offset_hex", ""),
                "text": nd.get("real_clean", "") or nd.get("display_clean", ""),
                "data_offset": nd.get("real_string_data_offset") or nd.get("display_string_data_offset"),
                "data_offset_hex": nd.get("real_string_data_offset_hex") or nd.get("display_string_data_offset_hex", ""),
                "len": nd.get("real_len") or nd.get("display_len"),
            }
            add_compat_choice(int(nd.get("resolver_function_index")), int(nd.get("name_call_offset")), nd.get("name_render_target"), txt_arg, "argc2_string_call_retagged_from_false_name")

        if choice_argc2_target is not None:
            for ci, cin in enumerate(self.instructions):
                if not cin.valid or cin.opcode != 0x02 or not cin.args or int(cin.args[0]["value"]) != choice_argc2_target:
                    continue
                _t, cargs = self._call_args_at_index(ci, argc_map)
                cstrings = [a for a in cargs if a.get("kind") == "string"]
                if not cstrings:
                    continue
                # The visible option text is normally the last/only string argument.
                add_compat_choice(int(cin.function_index or 0), int(cin.offset), choice_argc2_target, cstrings[-1], "argc2_target_profile_retagged_as_choice", force=True)

        # Annotation maps for strings.csv and fallback exporter.
        roles: dict[int, dict] = {}
        for nd in name_defs:
            for which in ("display", "real"):
                off = nd.get(f"{which}_string_instruction_offset")
                if off is None:
                    continue
                roles[int(off)] = {
                    "role": nd.get("role", "name"),
                    "name_kind": which,
                    "name_real": nd.get("real_clean", ""),
                    "name_display": nd.get("display_clean", ""),
                    "speaker_resolver_function_offset_hex": nd.get("resolver_function_offset_hex", ""),
                    "speaker_condition_key": nd.get("condition_key_text", ""),
                }
        for ev in dialogue_events:
            off = ev.get("instruction_offset")
            if off is None:
                continue
            roles[int(off)] = {
                "role": "text",
                "event_type": "dialogue_text",
                "event_id": ev.get("event_id"),
                "speaker_real": ev.get("speaker_real", ""),
                "speaker_display": ev.get("speaker_display", ""),
                "speaker_name_data_offset_hex": ev.get("speaker_name_data_offset_hex", ""),
                "speaker_name_instruction_offset_hex": ev.get("speaker_name_instruction_offset_hex", ""),
                "speaker_call_offset_hex": ev.get("speaker_call_offset_hex", ""),
                "text_call_offset_hex": ev.get("text_call_offset_hex", ""),
            }
        for ev in choice_events:
            off = ev.get("instruction_offset")
            if off is None:
                continue
            # Do not overwrite a confirmed dialogue text, but route-menu/options
            # should beat the generic unknown_string fallback.
            roles.setdefault(int(off), {
                "role": "choice",
                "event_type": "choice_option",
                "event_id": ev.get("event_id"),
                "choice_group": ev.get("choice_group", ""),
                "choice_index": ev.get("choice_index", ""),
                "choice_call_offset_hex": ev.get("choice_call_offset_hex", ""),
                "choice_commit_offset_hex": ev.get("choice_commit_offset_hex", ""),
                "jump_target_hex": ev.get("jump_target_hex", ""),
            })
        for ev in chapter_events:
            off = ev.get("instruction_offset")
            if off is None:
                continue
            # Opcode-confirmed chapter/title rows must beat earlier provisional
            # name/choice/fallback classifications.
            roles[int(off)] = {
                "role": "chapter",
                "event_type": "chapter_title",
                "event_id": ev.get("event_id"),
                "chapter_id": ev.get("chapter_id", ""),
                "chapter_title": ev.get("title", ""),
                "chapter_call_offset_hex": ev.get("chapter_call_offset_hex", ""),
                "chapter_target_hex": ev.get("chapter_target_hex", ""),
            }
        self._semantic_cache = {
            "text_render_target": text_target,
            "name_render_target": name_target,
            "name_definitions": name_defs,
            "name_maps": name_maps,
            "dialogue_events": dialogue_events,
            "choice_events": choice_events,
            "chapter_events": chapter_events,
            "chapter_diagnosis": getattr(self, "_chapter_diagnosis_cache", {
                "status": "FAIL" if not chapter_events else "PASS",
                "chapters": len(chapter_events),
                "reason": "chapter detector did not publish diagnostics",
            }),
            "string_roles": roles,
        }
        return self._semantic_cache


