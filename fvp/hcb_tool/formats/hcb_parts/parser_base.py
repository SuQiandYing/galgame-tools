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


class HCBParserBase:
    def __init__(self, path: Path, data: bytes, text_encoding: str = "cp932"):
        self.path = path
        self.file = path.name
        self.data = data
        self.text_encoding = text_encoding or "cp932"
        self.size = len(data)
        if self.size < 8:
            raise ValueError("file too small for HCB")
        self.code_end = u32le(data, 0)
        if not (4 <= self.code_end <= self.size):
            raise ValueError(f"bad code_end=0x{self.code_end:X}, file_size=0x{self.size:X}")
        self.entry_offset: int | None = None
        self.bin6 = b""
        self.title = ""
        self.title_bytes = b""
        self.imports: list[dict] = []
        self.extra_parse_ok = False
        self.extra_error = ""
        self.regions: list[Region] = []
        self.instructions: list[Instruction] = []
        self.func_offsets: list[int] = []
        self.func_by_offset: dict[int, int] = {}
        self.jump_targets_by_func: dict[int, set[int]] = defaultdict(set)
        self.invalids: list[dict] = []
        self.op_counter: Counter[int] = Counter()
        self._strings_cache: list[dict] | None = None
        self._xrefs_cache: list[dict] | None = None
        self._events_cache: list[dict] | None = None
        self._semantic_cache: dict | None = None
        self._parse_trailer()
        self._parse_code()
        self._index_functions_and_labels()

    def _add_region(self, start: int, end: int, typ: str, conf: str = "high", note: str = "") -> None:
        self.regions.append(Region(start, end, typ, conf, note))

    def _parse_trailer(self) -> None:
        self._add_region(0, 4, "header.code_end")
        self._add_region(4, self.code_end, "instruction_stream")
        p = self.code_end
        d = self.data
        try:
            if p + 4 > self.size:
                raise ValueError("missing entry offset")
            self.entry_offset = u32le(d, p)
            self._add_region(p, p + 4, "trailer.entry_offset")
            p += 4
            if p + 6 > self.size:
                raise ValueError("missing BIN6 bytes")
            self.bin6 = d[p:p + 6]
            self._add_region(p, p + 6, "trailer.bin6")
            p += 6
            if p >= self.size:
                raise ValueError("missing title length")
            title_len = d[p]
            self._add_region(p, p + 1, "trailer.title_length")
            p += 1
            if p + title_len > self.size:
                raise ValueError("title overruns file")
            self.title_bytes = d[p:p + title_len]
            title_payload = self.title_bytes[:-1] if self.title_bytes.endswith(b"\0") else self.title_bytes
            self.title = decode_text(title_payload, self.text_encoding)
            self._add_region(p, p + title_len, "trailer.title")
            p += title_len
            if p + 2 > self.size:
                raise ValueError("missing import count")
            import_count = u16le(d, p)
            self._add_region(p, p + 2, "trailer.import_count")
            p += 2
            for idx in range(import_count):
                rec_start = p
                if p + 2 > self.size:
                    raise ValueError(f"import {idx} header overrun")
                unk = d[p]
                ln = d[p + 1]
                p += 2
                if p + ln > self.size:
                    raise ValueError(f"import {idx} string overrun")
                raw = d[p:p + ln]
                payload = raw[:-1] if raw.endswith(b"\0") else raw
                name = decode_text(payload, self.text_encoding)
                p += ln
                self.imports.append({
                    "index": idx,
                    "unk": unk,
                    "len": ln,
                    "name": name,
                    "raw_hex": raw.hex(),
                    "record_start": rec_start,
                    "record_start_hex": f"0x{rec_start:08X}",
                    "record_size": p - rec_start,
                })
                self._add_region(rec_start, p, "trailer.import_record")
            if p < self.size:
                self._add_region(p, self.size, "trailer.unknown_tail", "low")
            self.extra_parse_ok = True
        except Exception as exc:
            self.extra_parse_ok = False
            self.extra_error = str(exc)
            if p < self.size:
                self._add_region(p, self.size, "trailer.opaque_unparsed", "low", str(exc))

    def _decode_one(self, off: int) -> Instruction:
        d = self.data
        opcode = d[off]
        if opcode not in OPDEFS:
            return Instruction(self.file, off, opcode, f"op_{opcode:02X}", [], 1, d[off:off + 1].hex(), valid=False, comment="unknown opcode")
        mnemonic, arg_types = OPDEFS[opcode]
        p = off + 1
        args: list[dict] = []
        try:
            for typ in arg_types:
                if typ == "i8":
                    if p + 1 > self.code_end:
                        raise EOFError("i8 overrun")
                    args.append({"type": typ, "value": i8(d, p), "uvalue": d[p], "hex": f"0x{d[p]:02X}", "offset": p})
                    p += 1
                elif typ == "i16":
                    if p + 2 > self.code_end:
                        raise EOFError("i16 overrun")
                    val = i16le(d, p)
                    uval = u16le(d, p)
                    args.append({"type": typ, "value": val, "uvalue": uval, "hex": f"0x{uval:04X}", "offset": p})
                    p += 2
                elif typ == "i32":
                    if p + 4 > self.code_end:
                        raise EOFError("i32 overrun")
                    val = i32le(d, p)
                    uval = u32le(d, p)
                    args.append({"type": typ, "value": val, "uvalue": uval, "hex": f"0x{uval:08X}", "offset": p})
                    p += 4
                elif typ == "x32":
                    if p + 4 > self.code_end:
                        raise EOFError("x32 overrun")
                    val = u32le(d, p)
                    args.append({"type": typ, "value": val, "hex": f"0x{val:08X}", "offset": p})
                    p += 4
                elif typ == "string":
                    if p + 1 > self.code_end:
                        raise EOFError("string length overrun")
                    length_offset = p
                    ln = d[p]
                    p += 1
                    if p + ln > self.code_end:
                        raise EOFError(f"string payload overrun len={ln}")
                    raw = d[p:p + ln]
                    payload = raw[:-1] if raw.endswith(b"\0") else raw
                    text = decode_text(payload, self.text_encoding)
                    args.append({
                        "type": typ,
                        "len": ln,
                        "length_offset": length_offset,
                        "data_offset": p,
                        "data_offset_hex": f"0x{p:08X}",
                        "raw_hex": raw.hex(),
                        "payload_raw_hex": payload.hex(),
                        "encoding": self.text_encoding,
                        "text": text,
                    })
                    p += ln
                else:
                    raise ValueError(f"unsupported arg type {typ}")
            return Instruction(self.file, off, opcode, mnemonic, args, p - off, d[off:p].hex())
        except Exception as exc:
            raw = d[off:min(self.code_end, max(off + 1, p))]
            return Instruction(self.file, off, opcode, mnemonic, args, max(1, len(raw)), raw.hex(), valid=False, comment=str(exc))

    def _parse_code(self) -> None:
        off = 4
        idx = 0
        while off < self.code_end:
            ins = self._decode_one(off)
            self.instructions.append(ins)
            self.op_counter[ins.opcode] += 1
            if not ins.valid:
                self.invalids.append({
                    "file": self.file,
                    "offset": off,
                    "offset_hex": f"0x{off:08X}",
                    "opcode": ins.opcode,
                    "mnemonic": ins.mnemonic,
                    "comment": ins.comment,
                    "raw_hex": ins.raw_hex,
                })
            off += max(ins.size, 1)
            idx += 1
        if off != self.code_end:
            self.invalids.append({"file": self.file, "offset": off, "offset_hex": f"0x{off:08X}", "comment": f"ended at 0x{off:X}, expected code_end 0x{self.code_end:X}"})

    def _index_functions_and_labels(self) -> None:
        self.func_offsets = [ins.offset for ins in self.instructions if ins.valid and ins.opcode == 0x01]
        self.func_by_offset = {off: i for i, off in enumerate(self.func_offsets)}
        next_func = 0
        cur: int | None = None
        for ins in self.instructions:
            if next_func < len(self.func_offsets) and ins.offset == self.func_offsets[next_func]:
                cur = next_func
                next_func += 1
            ins.function_index = cur
            if ins.valid and ins.opcode in (0x06, 0x07) and ins.args:
                self.jump_targets_by_func[cur or 0].add(ins.args[0]["value"])
        by_offset = {ins.offset: ins for ins in self.instructions}
        for fi, targets in self.jump_targets_by_func.items():
            if fi >= len(self.func_offsets):
                continue
            base = self.func_offsets[fi]
            for target in targets:
                ins = by_offset.get(target)
                if ins is not None and ins.function_index == fi:
                    ins.label = f"_F{fi}_x{ins.offset - base:X}_"

    def function_id_for_offset(self, target: int, exact: bool = False) -> int | None:
        if exact:
            return self.func_by_offset.get(target)
        if not self.func_offsets:
            return None
        i = bisect.bisect_right(self.func_offsets, target) - 1
        return i if i >= 0 else None

    def _fmt_arg(self, ins: Instruction, arg: dict) -> str:
        typ = arg.get("type")
        if typ == "string":
            return '"' + escape_text(arg.get("text", "")) + '"'
        if ins.opcode == 0x02 and typ == "x32":
            fid = self.function_id_for_offset(arg["value"], exact=True)
            return f"function_{fid}_ /*0x{arg['value']:X}*/" if fid is not None else f"0x{arg['value']:X} /*bad_call_target*/"
        if ins.opcode in (0x06, 0x07) and typ == "x32":
            fid = self.function_id_for_offset(arg["value"], exact=False)
            if fid is not None:
                base = self.func_offsets[fid]
                return f"_F{fid}_x{arg['value'] - base:X}_ /*0x{arg['value']:X}*/"
            return f"0x{arg['value']:X} /*bad_jmp_target*/"
        if ins.opcode == 0x03 and typ == "i16":
            idx = arg["uvalue"]
            name = self.imports[idx]["name"] if 0 <= idx < len(self.imports) else None
            return f"{idx}" + (f" /*{name}*/" if name else " /*bad_import*/")
        if typ in ("i8", "i16", "i32"):
            return str(arg["value"])
        if typ == "x32":
            return f"0x{arg['value']:X}"
        return str(arg.get("value", ""))

    def disasm_text(self) -> str:
        lines = [
            f"# HCB full disassembly: {self.file}",
            f"# tool_version={__version__} plugin={PLUGIN_ID}/{PLUGIN_VERSION}",
            f"# size=0x{self.size:X} ({self.size}) sha256={hash_bytes(self.data)['sha256']}",
            f"# code_end=0x{self.code_end:X} entry_offset={f'0x{self.entry_offset:X}' if self.entry_offset is not None else '<parse failed>'}",
            f"# functions={len(self.func_offsets)} instructions={len(self.instructions)} strings={len(self.strings())} imports={len(self.imports)}",
            f"# title={self.title!r} bin6={self.bin6.hex(' ').upper()}",
            "",
        ]
        for ins in self.instructions:
            if ins.opcode == 0x01 and ins.function_index is not None:
                if lines[-1] != "":
                    lines.append("")
                entry = " #ENTRYPOINT" if ins.offset == self.entry_offset else ""
                lines.append("# =================================================")
                lines.append(f"function_{ins.function_index}_:    # offset=0x{ins.offset:06X}{entry}")
            elif ins.label:
                lines.append(f"{ins.label}:")
            if not ins.valid:
                lines.append(f"  0x{ins.offset:06X}: .db 0x{ins.opcode:02X}    # INVALID {ins.mnemonic}: {ins.comment} raw={ins.raw_hex}")
                continue
            args = " ".join(self._fmt_arg(ins, a) for a in ins.args)
            op_s = ins.mnemonic + ((" " + args) if args else "")
            comment = f" # raw={bytes.fromhex(ins.raw_hex).hex(' ')}"
            if ins.opcode == 0x0E and ins.args:
                comment += f" ; cp932_len={ins.args[0]['len']}"
            lines.append(f"  0x{ins.offset:06X}: {op_s}{comment}")
        lines += ["", f"ENTRYPOINT = function_{self.function_id_for_offset(self.entry_offset or 0, exact=True)}_  # 0x{(self.entry_offset or 0):X}", "BIN = " + self.bin6.hex(" ").upper(), "TITLE = " + self.title, f"NUM_IMPORTS = {len(self.imports)}"]
        for imp in self.imports:
            lines.append(f"{imp['index']} | {imp['name']} [unk={imp['unk']} len={imp['len']}]")
        return "\n".join(lines) + "\n"

    def _func_ranges(self) -> list[tuple[int, int, int]]:
        starts = self.func_offsets
        ranges: list[tuple[int, int, int]] = []
        for i, start in enumerate(starts):
            end = starts[i + 1] if i + 1 < len(starts) else self.code_end
            ranges.append((i, start, end))
        return ranges

    def _function_arg_counts(self) -> dict[int, int]:
        counts: dict[int, int] = {}
        for ins in self.instructions:
            if ins.valid and ins.opcode == 0x01 and ins.args:
                counts[ins.offset] = int(ins.args[0]["value"])
        return counts

    def _push_value(self, ins: Instruction) -> dict | None:
        if not ins.valid:
            return None
        if ins.opcode == 0x0E and ins.args:
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
            }
        if ins.opcode == 0x08:
            return {"kind": "literal", "value": 1, "text": "true", "instruction_offset": ins.offset}
        if ins.opcode == 0x09:
            return {"kind": "literal", "value": 0, "text": "false", "instruction_offset": ins.offset}
        if ins.opcode in (0x0A, 0x0B, 0x0C) and ins.args:
            return {"kind": "literal", "value": int(ins.args[0]["value"]), "text": str(ins.args[0]["value"]), "instruction_offset": ins.offset}
        if ins.opcode == 0x0F and ins.args:
            return {"kind": "dynamic", "source": "global", "value": int(ins.args[0]["value"]), "instruction_offset": ins.offset}
        if ins.opcode == 0x10 and ins.args:
            return {"kind": "dynamic", "source": "stack", "value": int(ins.args[0]["value"]), "instruction_offset": ins.offset}
        if ins.opcode in (0x13, 0x14):
            return {"kind": "dynamic", "source": ins.mnemonic, "instruction_offset": ins.offset}
        return None

    def _call_args_at_index(self, idx: int, argc_map: dict[int, int]) -> tuple[int | None, list[dict]]:
        ins = self.instructions[idx]
        if not ins.valid or ins.opcode != 0x02 or not ins.args:
            return None, []
        target = int(ins.args[0]["value"])
        argc = argc_map.get(target)
        if argc is None or argc < 0 or idx - argc < 0:
            return target, []
        prev = self.instructions[idx - argc:idx]
        vals: list[dict] = []
        for p in prev:
            v = self._push_value(p)
            if v is None:
                return target, []
            vals.append(v)
        return target, vals

    def _infer_call_targets(self, argc_map: dict[int, int]) -> tuple[int | None, int | None]:
        # text renderer: overwhelmingly called with one pushstring + 3 flags in HCB scripts.
        # name renderer: usually argc=2 and is called by speaker resolver functions with one/two name strings.
        stats: dict[int, dict] = defaultdict(lambda: {"calls": 0, "string_calls": 0, "argc": None, "nstr": Counter(), "samples": []})
        for i, ins in enumerate(self.instructions):
            if not ins.valid or ins.opcode != 0x02:
                continue
            target, args = self._call_args_at_index(i, argc_map)
            if target is None or not args:
                continue
            texts = [a for a in args if a.get("kind") == "string"]
            st = stats[target]
            st["calls"] += 1
            st["argc"] = argc_map.get(target)
            if texts:
                st["string_calls"] += 1
                st["nstr"][len(texts)] += 1
                if len(st["samples"]) < 8:
                    st["samples"].extend([t.get("text", "") for t in texts[:2]])
        text_candidates = []
        name_candidates = []
        for target, st in stats.items():
            argc = st.get("argc")
            sc = int(st.get("string_calls") or 0)
            if sc <= 0:
                continue
            one_string = int(st["nstr"].get(1, 0))
            if argc and argc >= 3 and one_string >= max(10, sc * 0.75):
                text_candidates.append((one_string, sc, target))
            if argc == 2 and sc >= 5:
                # Prefer the real name wrapper: it is the most frequent argc=2 call with string args.
                name_candidates.append((sc, target))
        text_target = max(text_candidates)[2] if text_candidates else None
        name_target = max(name_candidates)[1] if name_candidates else None
        if text_target == name_target:
            name_target = None
        return text_target, name_target

    def _branch_key_before_call(self, call_idx: int) -> int | None:
        # Look within the current basic block for: pushstack/pushglobal, pushint, eq, jmpcond.
        # Stop at previous jmp/ret/initstack so the final default branch does not inherit the previous key.
        start = max(0, call_idx - 40)
        stop = start
        for j in range(call_idx - 1, start - 1, -1):
            op = self.instructions[j].opcode
            if op in (0x01, 0x04, 0x05, 0x06):
                stop = j + 1
                break
        for j in range(call_idx - 4, stop - 1, -1):
            seq = self.instructions[j:j + 4]
            if len(seq) != 4:
                continue
            if not all(x.valid for x in seq):
                continue
            if seq[0].opcode in (0x10, 0x0F) and seq[1].opcode in (0x0A, 0x0B, 0x0C) and seq[2].opcode == 0x22 and seq[3].opcode == 0x07:
                return int(seq[1].args[0]["value"])
            if seq[0].opcode in (0x10, 0x0F) and seq[1].opcode == 0x0C and seq[1].args[0].get("value") == -1 and seq[2].opcode == 0x22 and seq[3].opcode == 0x07:
                return -1
        return None

    def _clean_speaker(self, s: str) -> str:
        # Keep semantic content but remove padding used by the message window.
        return s.replace("\u3000", " ").strip()


