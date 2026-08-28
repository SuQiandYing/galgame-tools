from __future__ import annotations

import re
from pathlib import Path

from hcb_tool.services.hcb_source import load_ir_from_source
from hcb_tool.text.doubleline_exporter import export_doubleline
from hcb_tool.services.import_service import ImportDoubleLineService


def _safe_filename(text: str, max_len: int = 72) -> str:
    text = (text or "").strip() or "未命名"
    text = re.sub(r"[\\/:*?\"<>|\r\n\t]+", "_", text)
    text = re.sub(r"\s+", " ", text).strip(" .")
    return (text[:max_len] or "未命名")


def _hex_to_int(v) -> int:
    try:
        s = str(v or "")
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except Exception:
        return 10**18


def _chapter_start_int(e: dict) -> int:
    return _hex_to_int(e.get("chapter_start") or e.get("off"))


def _sort_entries(entries: list[dict]) -> list[dict]:
    by_idx = {str(e.get("idx")): e for e in entries}

    def key(e: dict):
        off = _hex_to_int(e.get("off"))
        sub = 1
        # Speaker reference rows point to the name slot, but should stay right
        # before the paired dialogue row.
        if e.get("source") == "hcb_speaker_ref" and e.get("pair"):
            paired = by_idx.get(str(e.get("pair")))
            if paired:
                off = _hex_to_int(paired.get("off"))
                sub = 0
        return (off, sub, str(e.get("idx", "")))

    return sorted(entries, key=key)


class ExportChapterTextService:
    """Export chapter txt using real HCB chapter-title call opcodes.

    This does *not* split every VM function.  Function/opcode 0x01 is only the VM
    function boundary; the real chapter title is a pushstring consumed by a stable
    chapter/title renderer call target.  The HCB plugin emits those rows as
    `source=hcb_chapter_call`, and this service uses only those opcode-derived rows
    as chapter boundaries.
    """

    def run(self, source: str | Path, output_dir: str | Path, options: dict | None = None) -> dict:
        options = options or {}
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ir, plugin = load_ir_from_source(source, options, include_disasm=False)
        entries = plugin.build_doubleline_entries(ir, options)
        entries = _sort_entries(entries)

        files: list[dict] = []

        # 0) Physical real-name slots stay separate.  They are referenced by later
        # dialogue but are not themselves chapter boundaries.
        name_defs = [dict(e) for e in entries if e.get("source") == "hcb_name_def"]
        if name_defs:
            for e in name_defs:
                e["chapter"] = "name_definitions"
                e["chapter_title"] = "真实人名定义槽"
            name_path = out / "000_真实人名定义槽.txt"
            export_doubleline(name_defs, name_path)
            files.append({"chapter": "name_definitions", "title": "真实人名定义槽", "entries": len(name_defs), "path": str(name_path)})

        body = [dict(e) for e in entries if e.get("source") != "hcb_name_def"]
        chapter_marks = [e for e in body if e.get("source") == "hcb_chapter_call" and e.get("tag") == "chapter"]
        chapter_marks = sorted(chapter_marks, key=_chapter_start_int)

        chapter_count = 0
        split_rule = "opcode_chapter_call"
        if chapter_marks:
            split_rule = str(chapter_marks[0].get("detect_rule") or "opcode_chapter_call")
            # Optional preface text before the first body-title opcode.  For
            # route-table chapters the visible marks live in a menu function before
            # the body offsets, so a "preface" would swallow unrelated menu/system
            # strings; skip it there.
            has_external_body_marks = any(m.get("detect_rule") in ("route_table_function_dispatch_call", "dispatcher_scene_function_call") for m in chapter_marks)
            first_off = _chapter_start_int(chapter_marks[0])
            preface = [] if has_external_body_marks else [dict(e) for e in body if e.get("source") != "hcb_chapter_call" and _hex_to_int(e.get("off")) < first_off]
            if preface:
                chapter_count += 1
                for e in preface:
                    e["chapter"] = "preface"
                    e["chapter_title"] = "前置文本"
                path = out / f"{chapter_count:03d}_前置文本.txt"
                export_doubleline(preface, path)
                files.append({"chapter": "preface", "title": "前置文本", "entries": len(preface), "path": str(path)})

            for i, mark in enumerate(chapter_marks):
                start = _chapter_start_int(mark)
                end = _chapter_start_int(chapter_marks[i + 1]) if i + 1 < len(chapter_marks) else 10**18
                title = str(mark.get("original") or mark.get("chapter_title") or f"chapter_{i+1:03d}").strip() or f"chapter_{i+1:03d}"
                # Include the visible chapter marker itself even when it came from a
                # route-table function before the body split offset.  Other content
                # is selected by body/function offset.
                items = [dict(mark)]
                seen_idx = {str(mark.get("idx"))}
                for e in body:
                    if str(e.get("idx")) in seen_idx:
                        continue
                    off = _hex_to_int(e.get("off"))
                    if start <= off < end:
                        items.append(dict(e))
                        seen_idx.add(str(e.get("idx")))
                if len(items) <= 1:
                    # A title with no body entries is only a menu/debug row; keep it
                    # out of exported chapters so it cannot masquerade as success.
                    continue
                chapter_count += 1
                chapter_id = str(mark.get("chapter_id") or f"chapter_{chapter_count:05d}")
                for e in items:
                    e["chapter"] = chapter_id
                    e["chapter_title"] = title
                filename = f"{chapter_count:03d}_{_safe_filename(title)}.txt"
                path = out / filename
                export_doubleline(items, path)
                files.append({
                    "chapter": chapter_id,
                    "title": title,
                    "entries": len(items),
                    "path": str(path),
                    "chapter_call": mark.get("chapter_call", ""),
                    "chapter_target": mark.get("chapter_target", ""),
                    "chapter_start": mark.get("chapter_start", mark.get("off", "")),
                    "detect_rule": mark.get("detect_rule", ""),
                })
        else:
            split_rule = "chapter_detection_failed_no_fallback"
            diagnosis = ir.get("chapter_diagnosis", {}) or {
                "status": "FAIL",
                "reason": "IR contains no hcb_chapter_call rows",
                "chapters": 0,
            }
            from hcb_tool.services.io_utils import write_json
            write_json(out / "_chapter_diagnosis.json", diagnosis)
            probe = diagnosis.get("dispatcher_scene_probe") if isinstance(diagnosis, dict) else None
            if probe:
                write_json(out / "_scene_dispatcher_probe.json", probe)
            status = diagnosis.get("status", "FAIL") if isinstance(diagnosis, dict) else "FAIL"
            reason = diagnosis.get("reason", "") if isinstance(diagnosis, dict) else ""
            (out / "_chapter_error.txt").write_text(
                "章节识别失败：未找到足够强的 function/opcode/call 章节证据。\n"
                "不会再生成 001_全文.txt 伪章节。\n"
                f"status = {status}\n"
                f"reason = {reason}\n"
                "请查看 _chapter_diagnosis.json；如存在 _scene_dispatcher_probe.json，说明只能识别到场景/调度器级别。\n",
                encoding="utf-8",
            )

        index_lines = [
            "# HCB chapter text export",
            "# split_rule = function/opcode chapter boundary; not keyword matching; no 001_全文 fallback",
            "# chapter rows are source=hcb_chapter_call in the txt metadata",
            f"source = {source}",
            f"encoding = {options.get('encoding', options.get('text_encoding', 'cp932'))}",
            f"chapters = {chapter_count}",
            f"name_definitions = {len(name_defs)}",
            "",
        ]
        for f in files:
            index_lines.append(f"{f['chapter']}\tentries={f['entries']}\t{Path(f['path']).name}\t{f['title']}")
        (out / "_chapter_index.txt").write_text("\n".join(index_lines) + "\n", encoding="utf-8")
        from hcb_tool.services.io_utils import write_json
        write_json(out / "_chapter_diagnosis.json", ir.get("chapter_diagnosis", {}))
        return {
            "source": str(source),
            "output_dir": str(out),
            "split_rule": split_rule,
            "chapters": chapter_count,
            "name_definitions": len(name_defs),
            "entries": sum(f["entries"] for f in files),
            "files": files[:50],
            "index": str(out / "_chapter_index.txt"),
        }


class ImportChapterTextService:
    def run(self, source: str | Path, chapter_dir: str | Path, output_dir: str | Path, options: dict | None = None) -> dict:
        return ImportDoubleLineService().run(source, chapter_dir, output_dir, options)
