from __future__ import annotations

from pathlib import Path

from hcb_tool.core.binary_io import read_bytes
from hcb_tool.core.region_map import Region, write_coverage_text
from hcb_tool.formats.registry import find_best_plugin
from hcb_tool.services.io_utils import write_csv, write_json, write_jsonl
from hcb_tool.services.hcb_source import PROJECT_IR_NAME
from hcb_tool.text.doubleline_exporter import export_doubleline
from hcb_tool.services.repack_service import RepackService


class DisassembleService:
    """Disassemble service.

    v0.2.3 changes the default to lean output because full IR/JSONL can easily
    exceed hundreds of MB.  Lean mode writes only the real disassembly plus small
    reports.  Text export/repack/chapter export are separate commands/services.
    """

    def run(self, input_paths: list[str | Path], output_dir: str | Path, options: dict | None = None) -> dict:
        options = options or {}
        mode = options.get("mode", "lean")
        if mode not in {"lean", "compact", "full"}:
            raise ValueError("mode must be lean, compact, or full")
        out_root = Path(output_dir)
        out_root.mkdir(parents=True, exist_ok=True)
        summary: list[dict] = []
        for raw_path in input_paths:
            path = Path(raw_path)
            data = read_bytes(path)
            plugin, score = find_best_plugin(path, data)
            decoded, layer_info = plugin.decode_layers(data, options)
            ir = plugin.disassemble(path, decoded, {**options, "mode": mode, "include_disasm": True})
            ir["probe_score"] = score
            ir["layer_info"] = layer_info

            stem_dir = out_root / path.stem
            stem_dir.mkdir(parents=True, exist_ok=True)
            disasm_text = ir.get("disasm_text", "")
            (stem_dir / "disasm.txt").write_text(disasm_text, encoding="utf-8")

            regions = [Region(start=int(r["start"]), end=int(r["end"]), type=r["type"], confidence=r.get("confidence", ""), note=r.get("note", "")) for r in ir["regions"]]
            coverage_txt = write_coverage_text(ir["manifest"]["coverage"], regions)
            (stem_dir / "coverage_report.txt").write_text(coverage_txt, encoding="utf-8")
            write_json(stem_dir / "manifest.json", ir["manifest"])

            # v0.3 extraction principle: all text/chapter/name/choice exports read this
            # machine-readable disassembly result, not the raw HCB again.  It is kept
            # compact by dropping the huge human disassembly text blob.
            project_ir = dict(ir)
            project_ir.pop("disasm_text", None)
            project_ir.setdefault("manifest", {})["derived_from"] = "disassembly_project"
            project_ir["project_ir_name"] = PROJECT_IR_NAME
            write_json(stem_dir / PROJECT_IR_NAME, project_ir)

            # Optional exports.  Default lean mode deliberately avoids all huge JSON/CSV files.
            if options.get("export_text", False):
                entries = plugin.build_doubleline_entries(ir, options)
                export_doubleline(entries, stem_dir / "doubleline.txt")
            if options.get("baseline_repack", False):
                baseline = stem_dir / f"{path.stem}.baseline_repacked{path.suffix}"
                RepackService().run(ir, baseline, patches=[], verify=True)

            if mode in {"compact", "full"}:
                # compact is now a debug/audit mode, not the GUI default.
                ir_for_json = dict(ir)
                ir_for_json.pop("disasm_text", None)
                if mode != "full":
                    ir_for_json.pop("instructions", None)
                    ir_for_json.pop("events", None)
                    ir_for_json.pop("opcode_frequency", None)
                    # Keep strings/xrefs in CSV only to avoid a giant ir.json.
                    ir_for_json.pop("strings", None)
                    ir_for_json.pop("xrefs", None)
                write_json(stem_dir / "ir.json", ir_for_json)
                write_json(stem_dir / "region_map.json", ir["regions"])
                write_json(stem_dir / "imports.json", ir["imports"])
                write_jsonl(stem_dir / "unknowns.jsonl", ir["unknowns"])
                write_csv(stem_dir / "strings.csv", ir["strings"])
                write_csv(stem_dir / "xrefs.csv", ir["xrefs"])
                write_csv(stem_dir / "imports.csv", ir["imports"])
                if mode == "full":
                    write_jsonl(stem_dir / "instructions.jsonl", ir["instructions"])
                    write_jsonl(stem_dir / "strings.jsonl", ir["strings"])
                    write_jsonl(stem_dir / "xrefs.jsonl", ir["xrefs"])
                    write_jsonl(stem_dir / "events.jsonl", ir["events"])
                    entries = plugin.build_doubleline_entries(ir, options)
                    export_doubleline(entries, stem_dir / "doubleline.txt")

            summary_row = dict(ir["manifest"])
            summary_row["output_dir"] = str(stem_dir)
            summary.append(summary_row)
        write_csv(out_root / "_summary.csv", summary)
        write_json(out_root / "_summary.json", summary)
        self._write_readme(out_root, summary, mode)
        return {"output_dir": str(out_root), "mode": mode, "files": summary}

    def _write_readme(self, out_root: Path, summary: list[dict], mode: str) -> None:
        if mode == "lean":
            desc = "Lean mode output: disasm.txt + project_ir.json + coverage_report.txt + manifest.json. Text/chapter extraction should read project_ir.json."
        elif mode == "compact":
            desc = "Compact debug mode output: lean files plus compact ir.json and CSV tables."
        else:
            desc = "Full debug mode output: includes large instructions/events/jsonl; use only when you need machine-audit dumps."
        lines = [
            "# HCB modular tool output",
            "",
            f"mode = {mode}",
            desc,
            f"files = {len(summary)}",
            "",
            "| file | functions | instructions | strings | imports | coverage | errors |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for r in summary:
            cov = r.get("coverage", {}).get("coverage_percent", 0)
            lines.append(f"| {r['file']} | {r['functions']} | {r['instructions']} | {r['strings']} | {r['imports']} | {cov} | {r['parse_errors']} |")
        (out_root / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
