from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from hcb_tool.core.binary_io import u32le
from hcb_tool.formats.base import FormatPlugin

from .constants import PLUGIN_DISPLAY_NAME, PLUGIN_ID, PLUGIN_VERSION
from .parser import _HCBParser
from .text_codec import encode_text

class HCBPlugin(FormatPlugin):
    plugin_id = PLUGIN_ID
    display_name = PLUGIN_DISPLAY_NAME
    version = PLUGIN_VERSION

    def probe(self, path: Path, data: bytes) -> float:
        if len(data) < 16:
            return 0.0
        if path.suffix.lower() == ".hcb":
            base = 0.65
        else:
            base = 0.0
        try:
            code_end = u32le(data, 0)
            if not (4 < code_end < len(data)):
                return max(0.0, base - 0.35)
            # A valid HCB code stream usually starts with initstack at offset 4.
            if data[4] == 0x01:
                base += 0.25
            # Trailer after code_end should contain entry offset and import-ish data.
            entry = u32le(data, code_end)
            if 4 <= entry < code_end:
                base += 0.1
        except Exception:
            return 0.0
        return min(1.0, base)

    def disassemble(self, path: Path, decoded: bytes, options: Any | None = None) -> dict:
        options = options or {}
        parser = _HCBParser(path, decoded, text_encoding=options.get("encoding", options.get("text_encoding", "cp932")))
        mode = options.get("mode", "lean")
        # lean/default: build only the data needed for disasm/text/repack, not huge JSONL streams.
        # include_disasm can be disabled by export/import services to avoid constructing a 50MB text blob.
        return parser.build_ir(
            include_instructions=(mode == "full"),
            include_events=(mode == "full"),
            include_disasm=bool(options.get("include_disasm", True)),
        )

    def build_doubleline_entries(self, ir: dict, options: Any | None = None) -> list[dict]:
        """Build an event-aware doubleline view.

        v0.2.2 fixes the missing-speaker problem: dialogue text entries are paired
        with the speaker selected by the preceding speaker resolver call.  The
        visible paired name line is reference-only; edit the real name definition
        entries (source=hcb_name_def) when you want to patch a name slot.
        """
        entries: list[dict] = []
        strings = ir.get("strings", [])
        by_instr = {s.get("instruction_offset_hex"): s for s in strings}
        by_data = {s.get("string_data_offset_hex"): s for s in strings}
        consumed_instr: set[str] = set()

        def next_idx() -> str:
            return f"{len(entries) + 1:08d}"

        def raw_sha_from_string(s: dict | None) -> str:
            if not s:
                return hashlib.sha1(b"").hexdigest()
            return hashlib.sha1(bytes.fromhex(s.get("raw_hex", ""))).hexdigest()

        def text_sha(text: str) -> str:
            return hashlib.sha1(text.encode("utf-8")).hexdigest()

        def base_entry(idx: str, s: dict, tag: str, source: str) -> dict:
            text = s.get("text", "")
            return {
                "format_version": "2",
                "idx": idx,
                "file": ir["file"],
                "off": s.get("instruction_offset_hex", ""),
                "tag": tag,
                "kind": "raw_" + str(ir.get("manifest", {}).get("text_encoding", "cp932")),
                "parts": "1",
                "src": s.get("string_data_offset_hex", ""),
                "rec": str(s.get("instruction_index", "")),
                "len": str(s.get("length_including_nul", "")),
                "join": "none",
                "func": str(s.get("function_index", "")),
                "raw_sha1": raw_sha_from_string(s),
                "text_sha1": text_sha(text),
                "source": source,
                "original": text,
                "edited": text,
            }

        # 1) Physical name definitions. These are the slots that should be patched
        # when a character name needs to change. They usually live near the front of
        # the HCB, inside resolver functions.
        for s in strings:
            if s.get("role") != "name":
                continue
            idx = next_idx()
            e = base_entry(idx, s, "name", "hcb_name_def")
            for k in ("name_kind", "name_real", "name_display", "speaker_resolver_function_offset_hex", "speaker_condition_key"):
                if s.get(k) not in (None, ""):
                    e[k] = str(s.get(k))
            entries.append(e)
            consumed_instr.add(s.get("instruction_offset_hex", ""))

        # 2) Dialogue events. A reference-only name line is placed immediately
        # before each text line, so translators can see which real speaker the line
        # belongs to without blindly guessing from earlier resolver code.
        for ev in ir.get("dialogue_events", []):
            text_s = by_instr.get(ev.get("instruction_offset_hex"))
            if not text_s:
                continue
            pair_name_idx = ""
            speaker = ev.get("speaker_real") or ev.get("speaker_display") or ""
            if speaker:
                name_idx = next_idx()
                text_idx = f"{len(entries) + 2:08d}"
                pair_name_idx = name_idx
                name_src = ev.get("speaker_name_data_offset_hex", "")
                name_s = by_data.get(name_src)
                raw_sha1 = raw_sha_from_string(name_s)
                name_len = str(ev.get("speaker_name_len") or (name_s or {}).get("length_including_nul", ""))
                name_e = {
                    "format_version": "2",
                    "idx": name_idx,
                    "file": ir["file"],
                    "off": ev.get("speaker_name_instruction_offset_hex", ""),
                    "tag": "name",
                    "kind": "speaker_ref",
                    "parts": "1",
                    "src": name_src,
                    "rec": str((name_s or {}).get("instruction_index", "")),
                    "len": name_len,
                    "join": "none",
                    "func": str(ev.get("function_index", "")),
                    "raw_sha1": raw_sha1,
                    "text_sha1": text_sha(speaker),
                    "source": "hcb_speaker_ref",
                    "patchable": "false",
                    "pair": text_idx,
                    "speaker_call": ev.get("speaker_call_offset_hex", ""),
                    "speaker_func": ev.get("speaker_resolver_function_offset_hex", ""),
                    "speaker_key": "" if ev.get("speaker_condition_key") is None else str(ev.get("speaker_condition_key")),
                    "original": f"【{speaker}】",
                    "edited": f"【{speaker}】",
                }
                if ev.get("speaker_display"):
                    name_e["speaker_display"] = ev.get("speaker_display")
                if ev.get("speaker_real"):
                    name_e["speaker_real"] = ev.get("speaker_real")
                entries.append(name_e)
            text_idx = next_idx()
            text_e = base_entry(text_idx, text_s, "text", "hcb_text_call")
            text_e["event"] = str(ev.get("event_id", ""))
            text_e["text_call"] = ev.get("text_call_offset_hex", "")
            if pair_name_idx:
                text_e["pair"] = pair_name_idx
            if speaker:
                text_e["speaker"] = speaker
            if ev.get("speaker_display"):
                text_e["speaker_display"] = ev.get("speaker_display")
            if ev.get("speaker_real"):
                text_e["speaker_real"] = ev.get("speaker_real")
            entries.append(text_e)
            consumed_instr.add(text_s.get("instruction_offset_hex", ""))

        # 3) Choice options.  These are detected from opcode/control-flow pattern
        # (choice append call + stack counter update), not from string appearance.
        for ev in ir.get("choice_events", []):
            choice_s = by_instr.get(ev.get("instruction_offset_hex"))
            if not choice_s:
                continue
            if choice_s.get("instruction_offset_hex", "") in consumed_instr:
                continue
            idx = next_idx()
            e = base_entry(idx, choice_s, "choice", "hcb_choice_option")
            e["event"] = str(ev.get("event_id", ""))
            e["choice_group"] = str(ev.get("choice_group", ""))
            e["choice_index"] = str(ev.get("choice_index", ""))
            e["choice_call"] = str(ev.get("choice_call_offset_hex", ""))
            e["choice_target"] = str(ev.get("choice_render_target_hex", ""))
            e["choice_commit"] = str(ev.get("choice_commit_offset_hex", ""))
            e["choice_commit_target"] = str(ev.get("choice_commit_target_hex", ""))
            e["jump"] = str(ev.get("jump_target_hex", ""))
            entries.append(e)
            consumed_instr.add(choice_s.get("instruction_offset_hex", ""))

        # 4) Chapter/title events.  These are detected only from function/opcode
        # structure.  Real title rows are patchable pushstrings.  Dispatcher-scene
        # fallback rows duplicate the first dialogue as a non-patchable boundary
        # marker; the real dialogue line remains editable in its normal text row.
        for ev in ir.get("chapter_events", []):
            chap_s = by_instr.get(ev.get("instruction_offset_hex"))
            if not chap_s:
                continue
            detect_rule = str(ev.get("detect_rule", ""))
            synthetic_scene = detect_rule == "dispatcher_scene_function_call"
            if chap_s.get("instruction_offset_hex", "") in consumed_instr and not synthetic_scene:
                continue
            idx = next_idx()
            e = base_entry(idx, chap_s, "chapter", "hcb_chapter_call")
            e["event"] = str(ev.get("event_id", ""))
            e["chapter_id"] = str(ev.get("chapter_id", ""))
            e["chapter_title"] = str(ev.get("title", ""))
            e["chapter_call"] = str(ev.get("chapter_call_offset_hex", ""))
            e["chapter_target"] = str(ev.get("chapter_target_hex", ""))
            e["chapter_start"] = str(ev.get("chapter_start_offset_hex", ev.get("chapter_call_offset_hex", "")))
            e["detect_rule"] = detect_rule
            e["confidence"] = str(ev.get("confidence", ""))
            if ev.get("body_text_count") not in (None, ""):
                e["body_text_count"] = str(ev.get("body_text_count"))
            if synthetic_scene:
                e["patchable"] = "false"
                e["note"] = str(ev.get("note", "synthetic dispatcher scene boundary"))
            entries.append(e)
            if not synthetic_scene:
                consumed_instr.add(chap_s.get("instruction_offset_hex", ""))

        # 5) Fallback for the remaining pushstrings, preserving the old behaviour
        # while tagging them as unknown/system/asset candidates instead of pretending
        # every string is a dialogue line.  Chapter classification is deliberately
        # not done here; chapter rows must come from hcb_chapter_call above.
        for s in strings:
            off = s.get("instruction_offset_hex", "")
            if off in consumed_instr:
                continue
            idx = next_idx()
            role = s.get("role") or "unknown_string"
            source = "hcb_pushstring"
            if role == "unknown_string":
                role, source = self._classify_fallback_string(s.get("text", ""))
            e = base_entry(idx, s, role, source)
            entries.append(e)
        return entries

    def _classify_fallback_string(self, text: str) -> tuple[str, str]:
        """Lightweight classification for non-event pushstrings.

        This does not replace opcode/event detection.  It only prevents obvious
        assets/internal identifiers from polluting the normal translation view and
        gives route/debug labels a more useful tag than unknown_string.
        """
        t = (text or "").strip()
        if not t:
            return "system", "hcb_empty_string"
        lower = t.lower()
        if "/" in t or "\\" in t:
            return "asset", "hcb_asset_path"
        if re.fullmatch(r"[A-Za-z0-9_./:-]+", t):
            # Things like SHINKU_e01a, BGS_EFFECT01_A, sel_bunner1 are usually
            # script labels / asset keys, not lines to translate.
            return "asset", "hcb_asset_key"
        # Do not classify chapters from string content here.  Chapter/title rows
        # are emitted only when the opcode/call-target pattern identifies a
        # dedicated chapter renderer.
        return "unknown_string", "hcb_pushstring"

    def apply_doubleline_entries(self, ir: dict, entries: list[dict], options: Any | None = None) -> tuple[list[dict], list[dict]]:
        by_idx = {e["idx"]: e for e in self.build_doubleline_entries(ir, options)}
        patches: list[dict] = []
        report: list[dict] = []
        touched: dict[int, str] = {}
        for e in entries:
            idx = e.get("idx")
            base = by_idx.get(idx)
            row = {
                "idx": idx,
                "file": e.get("file"),
                "tag": e.get("tag"),
                "source": e.get("source", ""),
                "status": "OK",
                "reason": "",
                "policy": "raw-first-in-place",
            }
            if base is None:
                row.update(status="FAIL", reason="idx not found in IR")
                report.append(row)
                continue
            for key in ("file", "src", "len", "tag"):
                if str(e.get(key, "")) != str(base.get(key, "")):
                    row.update(status="FAIL", reason=f"metadata mismatch: {key}")
                    break
            if row["status"] == "FAIL":
                report.append(row)
                continue
            # Reference-only speaker rows are deliberately visible in doubleline.txt,
            # but they must not patch a dialogue text slot. Patch the hcb_name_def
            # entry if the physical name definition itself should be changed.
            if base.get("source") == "hcb_speaker_ref" or base.get("patchable") == "false":
                if e.get("edited") != base.get("original"):
                    row["warning"] = "speaker_ref is reference-only; edit the matching hcb_name_def entry to patch the real name slot"
                row.update(status="SKIP", reason="reference-only speaker line")
                report.append(row)
                continue
            if e.get("raw_sha1") != base.get("raw_sha1"):
                row.update(status="FAIL", reason="raw_sha1 mismatch; wrong source/IR version")
                report.append(row)
                continue
            if e.get("original") != base.get("original") or e.get("text_sha1") != base.get("text_sha1"):
                row["warning"] = "original line changed or text_sha1 mismatch; edited line still used after metadata validation"
            edited = e.get("edited", "")
            if edited == base.get("original"):
                row.update(status="SKIP", reason="unchanged; keep original raw bytes")
                report.append(row)
                continue
            try:
                enc = encode_text(edited, str(ir.get("manifest", {}).get("text_encoding", "cp932")))
            except UnicodeEncodeError as exc:
                row.update(status="FAIL", reason=f"text encode failed: {exc}")
                report.append(row)
                continue
            slot_len = int(base["len"])
            required = len(enc) + 1
            row["original_len"] = slot_len
            row["encoded_len"] = required
            if required > slot_len:
                row.update(status="FAIL", reason="encoded text exceeds original pushstring slot")
                report.append(row)
                continue
            patch_bytes = enc + b"\0" + (b"\0" * (slot_len - required))
            src = int(str(base["src"]), 16)
            data_hex = patch_bytes.hex()
            if src in touched and touched[src] != data_hex:
                row.update(status="FAIL", reason=f"conflicting edits for same string slot at 0x{src:08X}")
                report.append(row)
                continue
            touched[src] = data_hex
            patches.append({
                "idx": idx,
                "offset": src,
                "offset_hex": f"0x{src:08X}",
                "length": slot_len,
                "data_hex": data_hex,
                "text": edited,
            })
            report.append(row)
        return patches, report

