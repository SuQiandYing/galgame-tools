from __future__ import annotations

from pathlib import Path

from hcb_tool.services.hcb_source import load_ir_from_source
from hcb_tool.services.repack_service import RepackService
from hcb_tool.text.doubleline_importer import parse_doubleline_path


class ImportDoubleLineService:
    def run(self, source: str | Path, txt_path: str | Path, output_dir: str | Path, options: dict | None = None) -> dict:
        # source can be project_ir.json/disassembly project or old ir.json.  Direct .hcb debug avoids saving 500MB+ ir.json.
        options = options or {}
        ir, plugin = load_ir_from_source(source, options, include_disasm=False)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        entries = parse_doubleline_path(txt_path)
        patches, report = plugin.apply_doubleline_entries(ir, entries, options)
        # Default lean import writes only the readable report; JSONL is debug-only.
        if options.get("debug_report", False):
            from hcb_tool.services.io_utils import write_jsonl
            write_jsonl(output_dir / "import_report.jsonl", report)
        fail_count = sum(1 for r in report if r.get("status") == "FAIL")
        ok_count = sum(1 for r in report if r.get("status") == "OK")
        skip_count = sum(1 for r in report if r.get("status") == "SKIP")
        text_report = [
            "[IMPORT]",
            f"source = {source}",
            f"doubleline_or_chapter_dir = {txt_path}",
            f"entries = {len(entries)}",
            f"patches = {len(patches)}",
            f"ok = {ok_count}",
            f"skip = {skip_count}",
            f"fail = {fail_count}",
            f"status = {'PASS' if fail_count == 0 else 'FAIL'}",
            "",
        ]
        for r in report:
            if r.get("status") == "FAIL":
                text_report.append(f"[ENTRY] idx={r.get('idx')} status=FAIL reason={r.get('reason')}")
        (output_dir / "import_report.txt").write_text("\n".join(text_report) + "\n", encoding="utf-8")
        if fail_count:
            return {"status": "FAIL", "patches": len(patches), "report_path": str(output_dir / "import_report.txt")}
        stem = Path(ir["source_path"]).name
        rebuilt = output_dir / stem
        repack_result = RepackService().run(ir, rebuilt, patches=patches, verify=True)
        return {"status": "PASS", "patches": len(patches), "output_path": str(rebuilt), "repack": repack_result}
