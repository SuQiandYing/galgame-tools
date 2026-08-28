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


class ViewsMixin:
    def strings(self) -> list[dict]:
        if self._strings_cache is not None:
            return self._strings_cache
        rows: list[dict] = []
        instruction_index = -1
        for ins in self.instructions:
            instruction_index += 1
            if not ins.valid or ins.opcode != 0x0E or not ins.args:
                continue
            arg = ins.args[0]
            raw = bytes.fromhex(arg["raw_hex"])
            sem = self._infer_semantics()
            ann = sem.get("string_roles", {}).get(ins.offset, {})
            row = {
                "file": self.file,
                "string_index": len(rows) + 1,
                "instruction_index": instruction_index,
                "instruction_offset": ins.offset,
                "instruction_offset_hex": f"0x{ins.offset:08X}",
                "string_data_offset": arg["data_offset"],
                "string_data_offset_hex": f"0x{arg['data_offset']:08X}",
                "function_index": ins.function_index,
                "length_including_nul": arg["len"],
                "available_text_bytes": max(0, arg["len"] - 1 if raw.endswith(b"\0") else arg["len"]),
                "raw_hex": arg["raw_hex"],
                "payload_raw_hex": arg["payload_raw_hex"],
                "encoding": arg["encoding"],
                "text": arg["text"],
                "role": ann.get("role", "unknown_string"),
                "repack_policy": "in_place_same_or_padded",
                "refs_from": [f"0x{ins.offset:08X}"],
            }
            for k, v in ann.items():
                if k != "role":
                    row[k] = v
            rows.append(row)
        self._strings_cache = rows
        return rows

    def xrefs(self) -> list[dict]:
        if self._xrefs_cache is not None:
            return self._xrefs_cache
        rows: list[dict] = []
        for ins in self.instructions:
            if not ins.valid or ins.opcode not in (0x02, 0x03, 0x06, 0x07):
                continue
            row = {
                "file": self.file,
                "source_offset": ins.offset,
                "source_offset_hex": f"0x{ins.offset:08X}",
                "function_index": ins.function_index,
                "kind": ins.mnemonic,
                "confidence": "high",
            }
            if ins.opcode in (0x02, 0x06, 0x07):
                target = ins.args[0]["value"]
                row.update({
                    "target_offset": target,
                    "target_offset_hex": f"0x{target:08X}",
                    "target_type": "function" if ins.opcode == 0x02 else "code",
                    "target_function_index": self.function_id_for_offset(target, exact=(ins.opcode == 0x02)),
                    "ref_kind": "absolute_offset",
                })
            else:
                idx = ins.args[0]["uvalue"]
                row.update({
                    "target_type": "import",
                    "import_index": idx,
                    "import_name": self.imports[idx]["name"] if 0 <= idx < len(self.imports) else "",
                    "ref_kind": "import_index",
                })
            rows.append(row)
        self._xrefs_cache = rows
        return rows

    def events(self) -> list[dict]:
        if self._events_cache is not None:
            return self._events_cache
        sem = self._infer_semantics()
        events = list(sem.get("dialogue_events", []))
        if not events:
            # Conservative fallback: every pushstring is at least an auditable event.
            for s in self.strings():
                events.append({
                    "file": self.file,
                    "event_id": len(events) + 1,
                    "event_type": "pushstring_text",
                    "tag": s["role"],
                    "instruction_offset": s["instruction_offset"],
                    "instruction_offset_hex": s["instruction_offset_hex"],
                    "function_index": s["function_index"],
                    "text": s["text"],
                    "string_index": s["string_index"],
                    "confidence": "medium",
                    "note": "semantic role not inferred beyond pushstring",
                })
        self._events_cache = events
        return events

    def unknowns(self) -> list[dict]:
        rows = list(self.invalids)
        for r in self.regions:
            if "unknown" in r.type or "opaque" in r.type:
                rows.append({
                    "file": self.file,
                    "offset": r.start,
                    "offset_hex": f"0x{r.start:08X}",
                    "size": r.size,
                    "type": r.type,
                    "note": r.note,
                })
        return rows

    def build_ir(self, include_instructions: bool = True, include_events: bool = True, include_disasm: bool = True) -> dict:
        regions = normalize_regions(self.regions, self.size)
        cov = coverage_report(regions, self.size)
        sem = self._infer_semantics()
        manifest = {
            "schema_version": "hcb-ir-v1",
            "tool_version": __version__,
            "plugin_id": PLUGIN_ID,
            "plugin_version": PLUGIN_VERSION,
            "file": self.file,
            "source_path": str(self.path),
            **hash_bytes(self.data),
            "code_end": self.code_end,
            "code_end_hex": f"0x{self.code_end:08X}",
            "entry_offset": self.entry_offset,
            "entry_offset_hex": f"0x{self.entry_offset:08X}" if self.entry_offset is not None else None,
            "entry_function_index": self.function_id_for_offset(self.entry_offset or 0, exact=True),
            "title": self.title,
            "bin6_hex": self.bin6.hex(),
            "functions": len(self.func_offsets),
            "instructions": len(self.instructions),
            "strings": len(self.strings()),
            "choices": len(sem.get("choice_events", [])),
            "chapters": len(sem.get("chapter_events", [])),
            "imports": len(self.imports),
            "parse_errors": len(self.invalids),
            "extra_parse_ok": self.extra_parse_ok,
            "extra_error": self.extra_error,
            "coverage": cov,
            "text_encoding": self.text_encoding,
        }
        ir = {
            "schema_version": "hcb-ir-v1",
            "file": self.file,
            "source_path": str(self.path),
            "manifest": manifest,
            "regions": [r.to_dict() for r in regions],
            "imports": self.imports,
            "function_offsets": [{"function_index": i, "offset": off, "offset_hex": f"0x{off:08X}"} for i, off in enumerate(self.func_offsets)],
            "strings": self.strings(),
            "xrefs": self.xrefs(),
            "unknowns": self.unknowns(),
            "name_definitions": sem.get("name_definitions", []),
            "dialogue_events": sem.get("dialogue_events", []),
            "choice_events": sem.get("choice_events", []),
            "chapter_events": sem.get("chapter_events", []),
            "chapter_diagnosis": sem.get("chapter_diagnosis", {}),
            "semantic_targets": {
                "text_render_target": sem.get("text_render_target"),
                "text_render_target_hex": f"0x{sem.get('text_render_target'):08X}" if sem.get("text_render_target") is not None else "",
                "name_render_target": sem.get("name_render_target"),
                "name_render_target_hex": f"0x{sem.get('name_render_target'):08X}" if sem.get("name_render_target") is not None else "",
            },
            "opcode_frequency": [{"opcode": op, "opcode_hex": f"0x{op:02X}", "mnemonic": OPDEFS.get(op, (f"op_{op:02X}", []))[0], "count": count} for op, count in sorted(self.op_counter.items())],
        }
        if include_instructions:
            ir["instructions"] = [ins.to_dict() for ins in self.instructions]
        if include_events:
            ir["events"] = self.events()
        else:
            ir["events"] = []
        if include_disasm:
            ir["disasm_text"] = self.disasm_text()
        return ir


