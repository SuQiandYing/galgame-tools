from __future__ import annotations

import bisect
import re
from collections import Counter, defaultdict
from typing import Any


class NameMappingMixin:
    """Infer speaker/name mappings from function scope + opcode call patterns.

    Supported layouts:
    1) Text-name resolver functions: pushstring display/real -> call argc=2 name renderer.
       This is used by iroseka/irohika/akaseka/Sakura-like files.
    2) Resource-name resolver functions: pushint slot -> pushstring name_* -> call argc=3
       name resource renderer.  This is used by hime-like files.  The resource id
       is converted to a visible speaker label for double-line reference rows, but
       the resource string itself is not treated as an editable physical name slot.
    """

    def _looks_like_name_slot_text(self, text: str) -> bool:
        t = self._clean_speaker(text)
        if not t:
            return False
        if len(t) > 24:
            return False
        if "/" in t or "\\" in t:
            return False
        # Reject obvious resource keys / numeric labels; allow mixed mystery markers
        # such as ？小? or 瑠々＠？？？ because Sakura-style HCBs use them for names.
        if re.fullmatch(r"[A-Za-z0-9_./:-]+", t):
            return False
        hard_sentence_marks = set("。、，,「」『』（）()[]【】…‥♪\n\r")
        if any(ch in hard_sentence_marks for ch in t):
            return False
        return True

    def _strip_name_resource_prefix(self, text: str) -> str:
        t = self._clean_speaker(text)
        if t.lower().startswith("name_"):
            t = t[5:]
        # Keep variant suffixes such as -少年; they are useful context in the
        # reference-only speaker line.
        return t.strip()

    def _call_target_string_profile(self, argc_map: dict[int, int]) -> dict[int, dict[str, Any]]:
        stats: dict[int, dict[str, Any]] = defaultdict(lambda: {
            "calls": 0,
            "string_calls": 0,
            "argc": None,
            "nstr": Counter(),
            "name_like": 0,
            "two_string_calls": 0,
            "name_resource_calls": 0,
            "call_indices": [],
            "samples": [],
        })
        for i, ins in enumerate(self.instructions):
            if not ins.valid or ins.opcode != 0x02 or not ins.args:
                continue
            target, args = self._call_args_at_index(i, argc_map)
            if target is None:
                continue
            st = stats[target]
            st["calls"] += 1
            st["argc"] = argc_map.get(target)
            st["call_indices"].append(i)
            strings = [a for a in args if a.get("kind") == "string"]
            if not strings:
                continue
            st["string_calls"] += 1
            st["nstr"][len(strings)] += 1
            if len(strings) >= 2:
                st["two_string_calls"] += 1
            if all(self._looks_like_name_slot_text(str(a.get("text", ""))) for a in strings):
                st["name_like"] += 1
            if any(str(a.get("text", "")).strip().lower().startswith("name_") for a in strings):
                st["name_resource_calls"] += 1
            if len(st["samples"]) < 12:
                st["samples"].extend(str(a.get("text", "")) for a in strings[:2])
        return stats

    def _select_text_name_target(self, argc_map: dict[int, int], preferred_target: int | None) -> tuple[int | None, int | None]:
        """Return (name_target, rejected_argc2_target_for_choice_compat)."""
        stats = self._call_target_string_profile(argc_map)
        candidates: list[tuple[int, int, int, int]] = []
        rejected_choice_target: int | None = None
        for target, st in stats.items():
            sc = int(st.get("string_calls") or 0)
            argc = st.get("argc")
            if argc != 2 or sc < 5:
                continue
            two = int(st.get("two_string_calls") or 0)
            name_like = int(st.get("name_like") or 0)
            # Real text-name resolvers either pass display+real strings often, or
            # use a short one-string fallback.  Menu/choice renderers generally
            # have no two-string calls and/or adjacent option-call runs.
            has_two_string_backbone = two >= max(1, int(sc * 0.30))
            good_name_shape = name_like >= max(5, int(sc * 0.55))
            # Do not reject two-string name resolver tables just because calls are
            # adjacent: Sakura-style resolver functions are exactly compact runs
            # of display/real name calls.  Choice/menu targets are filtered by the
            # missing two-string backbone instead.
            if good_name_shape and has_two_string_backbone:
                score = name_like * 4 + two * 3 + sc
                # Keep previous target preference when it is structurally valid.
                if preferred_target == target:
                    score += sc * 2
                candidates.append((score, sc, two, target))
            elif preferred_target == target:
                rejected_choice_target = target
        if candidates:
            return max(candidates)[3], rejected_choice_target
        return None, rejected_choice_target

    def _select_resource_name_target(self, argc_map: dict[int, int]) -> int | None:
        stats = self._call_target_string_profile(argc_map)
        candidates: list[tuple[int, int, int]] = []
        for target, st in stats.items():
            resource_calls = int(st.get("name_resource_calls") or 0)
            sc = int(st.get("string_calls") or 0)
            argc = st.get("argc") or 0
            if argc >= 2 and resource_calls >= 10:
                # The same renderer can also draw non-name UI assets, so use the
                # absolute number of name_* calls instead of requiring a high ratio.
                candidates.append((resource_calls, sc, target))
        return max(candidates)[2] if candidates else None


    def _function_instructions_by_index(self, function_index: int):
        if function_index is None or function_index < 0 or function_index >= len(self.func_offsets):
            return []
        offsets = getattr(self, "_name_mapping_instruction_offsets", None)
        if offsets is None:
            offsets = [ins.offset for ins in self.instructions]
            setattr(self, "_name_mapping_instruction_offsets", offsets)
        start = self.func_offsets[function_index]
        end = self.func_offsets[function_index + 1] if function_index + 1 < len(self.func_offsets) else self.code_end
        si = bisect.bisect_left(offsets, start)
        ei = bisect.bisect_left(offsets, end)
        return self.instructions[si:ei]

    def _globals_in_function_index(self, function_index: int) -> set[int]:
        vals: set[int] = set()
        for ins in self._function_instructions_by_index(function_index):
            if ins.valid and ins.opcode == 0x0F and ins.args:
                vals.add(int(ins.args[0]["value"]))
        return vals

    def _function_instruction_stats(self, function_index: int) -> tuple[int, int, list[int]]:
        total = 0
        strings = 0
        calls: list[int] = []
        for ins in self._function_instructions_by_index(function_index):
            total += 1
            if ins.valid and ins.opcode == 0x0E:
                strings += 1
            if ins.valid and ins.opcode == 0x02 and ins.args:
                calls.append(int(ins.args[0]["value"]))
        return total, strings, calls

    def _build_resource_speaker_aliases(self, name_defs: list[dict], name_maps: dict[int, list[dict]]) -> dict[int, list[dict]]:
        """Map hime-like face/window helper functions back to name resolver defs."""
        resource_resolver_offsets = {
            int(d["resolver_function_offset"])
            for d in name_defs
            if d.get("definition_kind") == "name_resource"
        }
        if not resource_resolver_offsets:
            return {}

        global_to_resolvers: dict[int, set[int]] = defaultdict(set)
        for resolver_off in resource_resolver_offsets:
            fi = self.function_id_for_offset(resolver_off, exact=True)
            if fi is None:
                continue
            for g in self._globals_in_function_index(fi):
                global_to_resolvers[g].add(resolver_off)
        unique_global_to_defs = {
            g: name_maps[next(iter(resolvers))]
            for g, resolvers in global_to_resolvers.items()
            if len(resolvers) == 1 and next(iter(resolvers)) in name_maps
        }
        aliases: dict[int, list[dict]] = {}
        # Base actor/window functions: small, no embedded strings, and share the
        # same character-state global as one resolver function.
        for fi, off in enumerate(self.func_offsets):
            if off in name_maps:
                continue
            total, nstrings, _calls = self._function_instruction_stats(fi)
            if total <= 0 or total > 90 or nstrings:
                continue
            matching = [unique_global_to_defs[g] for g in self._globals_in_function_index(fi) if g in unique_global_to_defs]
            if len(matching) == 1:
                aliases[off] = matching[0]

        # Wrapper functions often just forward stack args to one actor/window
        # function.  Propagate aliases through these tiny wrappers until stable.
        changed = True
        while changed:
            changed = False
            for fi, off in enumerate(self.func_offsets):
                if off in name_maps or off in aliases:
                    continue
                total, nstrings, calls = self._function_instruction_stats(fi)
                if total <= 0 or total > 24 or nstrings:
                    continue
                called_aliases = [aliases[c] for c in calls if c in aliases]
                if len(called_aliases) == 1:
                    aliases[off] = called_aliases[0]
                    changed = True
        return aliases

    def _infer_name_mapping(self, argc_map: dict[int, int], preferred_name_target: int | None) -> dict[str, Any]:
        text_name_target, rejected_choice_target = self._select_text_name_target(argc_map, preferred_name_target)
        resource_name_target = self._select_resource_name_target(argc_map)
        name_defs: list[dict] = []
        rejected_name_defs: list[dict] = []
        name_maps: dict[int, list[dict]] = defaultdict(list)
        ins_index_by_offset = {ins.offset: i for i, ins in enumerate(self.instructions)}

        for fi, start, end in self._func_ranges():
            defs_in_func: list[dict] = []
            si = ins_index_by_offset.get(start, 0)
            ei = ins_index_by_offset.get(end, len(self.instructions)) if end in ins_index_by_offset else len(self.instructions)
            for i in range(si, ei):
                ins = self.instructions[i]
                if not ins.valid or ins.opcode != 0x02 or not ins.args:
                    continue
                target = int(ins.args[0]["value"])
                _, args = self._call_args_at_index(i, argc_map)
                strings = [a for a in args if a.get("kind") == "string"]
                if not strings:
                    continue
                if text_name_target is not None and target == text_name_target:
                    display = strings[0]
                    real = strings[1] if len(strings) >= 2 else strings[0]
                    display_clean = self._clean_speaker(display.get("text", ""))
                    real_clean = self._clean_speaker(real.get("text", ""))
                    if not self._looks_like_name_slot_text(real_clean):
                        accept = False
                    else:
                        accept = True
                    row = self._make_name_definition_row(
                        fi, start, i, ins, text_name_target, display, real,
                        display_clean, real_clean, definition_kind="text_name", role="name",
                    )
                    if accept:
                        defs_in_func.append(row)
                        name_defs.append(row)
                    else:
                        rejected_name_defs.append(row)
                elif resource_name_target is not None and target == resource_name_target:
                    resource_strings = [s for s in strings if str(s.get("text", "")).strip().lower().startswith("name_")]
                    if not resource_strings:
                        continue
                    resource = resource_strings[-1]
                    clean = self._strip_name_resource_prefix(resource.get("text", ""))
                    if not clean:
                        continue
                    row = self._make_name_definition_row(
                        fi, start, i, ins, resource_name_target, resource, resource,
                        clean, clean, definition_kind="name_resource", role="name_resource",
                    )
                    defs_in_func.append(row)
                    name_defs.append(row)
            if defs_in_func:
                name_maps[start].extend(defs_in_func)

        aliases = self._build_resource_speaker_aliases(name_defs, name_maps)
        speaker_maps: dict[int, list[dict]] = defaultdict(list)
        for k, v in name_maps.items():
            speaker_maps[k].extend(v)
        for k, v in aliases.items():
            speaker_maps[k].extend(v)

        return {
            "text_name_target": text_name_target,
            "resource_name_target": resource_name_target,
            "name_render_target": text_name_target if text_name_target is not None else resource_name_target,
            "choice_argc2_target": rejected_choice_target,
            "name_definitions": name_defs,
            "rejected_name_definitions": rejected_name_defs,
            "name_maps": name_maps,
            "speaker_maps": speaker_maps,
            "speaker_aliases": aliases,
        }

    def _make_name_definition_row(self, fi: int, start: int, call_idx: int, ins, name_target: int,
                                  display: dict, real: dict, display_clean: str, real_clean: str,
                                  definition_kind: str, role: str) -> dict:
        key = self._branch_key_before_call(call_idx)
        return {
            "file": self.file,
            "resolver_function_index": fi,
            "resolver_function_offset": start,
            "resolver_function_offset_hex": f"0x{start:08X}",
            "condition_key": key,
            "condition_key_text": "default" if key is None else str(key),
            "name_call_offset": ins.offset,
            "name_call_offset_hex": f"0x{ins.offset:08X}",
            "name_render_target": name_target,
            "definition_kind": definition_kind,
            "role": role,
            "display_text": display.get("text", ""),
            "display_clean": display_clean,
            "display_string_instruction_offset": display.get("instruction_offset"),
            "display_string_instruction_offset_hex": display.get("instruction_offset_hex"),
            "display_string_data_offset": display.get("data_offset"),
            "display_string_data_offset_hex": display.get("data_offset_hex"),
            "display_len": display.get("len"),
            "display_raw_hex": display.get("raw_hex", ""),
            "real_text": real.get("text", ""),
            "real_clean": real_clean,
            "real_string_instruction_offset": real.get("instruction_offset"),
            "real_string_instruction_offset_hex": real.get("instruction_offset_hex"),
            "real_string_data_offset": real.get("data_offset"),
            "real_string_data_offset_hex": real.get("data_offset_hex"),
            "real_len": real.get("len"),
            "real_raw_hex": real.get("raw_hex", ""),
            "confidence": "medium",
        }

    def _resolve_speaker_name(self, speaker_maps: dict[int, list[dict]], func_off: int, first_arg: int | None) -> dict | None:
        defs = speaker_maps.get(func_off)
        if not defs:
            return None
        if first_arg is not None:
            for d in defs:
                if d.get("condition_key") == first_arg:
                    return d
        for d in reversed(defs):
            if d.get("condition_key") is None:
                return d
        return defs[0]
