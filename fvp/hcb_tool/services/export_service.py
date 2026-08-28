from __future__ import annotations

from pathlib import Path

from hcb_tool.services.hcb_source import load_ir_from_source
from hcb_tool.text.doubleline_exporter import export_doubleline


class ExportDoubleLineService:
    def run(self, source: str | Path, output_txt: str | Path, options: dict | None = None) -> dict:
        # v0.2.5: only one extraction view: all opcode-derived/string entries.
        # No clean/translate/dialogue selector; the user edits one complete view.
        options = options or {}
        ir, plugin = load_ir_from_source(source, options, include_disasm=False)
        entries = plugin.build_doubleline_entries(ir, options)
        export_doubleline(entries, output_txt)
        counts: dict[str, int] = {}
        for e in entries:
            tag = str(e.get("tag", ""))
            counts[tag] = counts.get(tag, 0) + 1
        return {
            "source": str(source),
            "output_txt": str(output_txt),
            "profile": "all",
            "entries": len(entries),
            "tag_counts": counts,
            "encoding": ir.get("manifest", {}).get("text_encoding", options.get("encoding", "cp932")),
        }
