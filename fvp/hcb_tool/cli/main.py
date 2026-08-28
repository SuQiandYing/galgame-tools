from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hcb_tool import __version__
from hcb_tool.services.disassemble_service import DisassembleService
from hcb_tool.services.export_service import ExportDoubleLineService
from hcb_tool.services.import_service import ImportDoubleLineService
from hcb_tool.services.repack_service import RepackService
from hcb_tool.services.verify_service import VerifyService
from hcb_tool.services.hcb_source import load_ir_from_source
from hcb_tool.services.chapter_service import ExportChapterTextService, ImportChapterTextService


def _expand_inputs(items: list[str]) -> list[Path]:
    out: list[Path] = []
    for item in items:
        p = Path(item)
        if p.is_dir():
            out.extend(sorted(p.glob("*.hcb")))
        else:
            out.append(p)
    return out


def _add_common(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--encoding", default="cp932", help="string encoding for HCB pushstring decode/encode, default cp932")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hcb-tool", description="HCB disassembler, all-text/chapter exporter/importer, raw-first repacker and verifier")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("disasm", help="generate disasm.txt + project_ir.json for extraction")
    p.add_argument("inputs", nargs="+")
    p.add_argument("-o", "--outdir", required=True)
    p.add_argument("--mode", choices=["lean", "compact", "full"], default="lean", help="lean=disasm.txt + compact project_ir.json; compact/full are debug modes")
    p.add_argument("--with-text", action="store_true", help="also export doubleline.txt in the same run")
    p.add_argument("--with-baseline-repack", action="store_true", help="also write baseline repacked HCB and hash report")
    _add_common(p)

    p = sub.add_parser("export-text", help="export one complete doubleline.txt from disassembly project_ir.json")
    p.add_argument("source", help="project_ir.json or disassembly project dir preferred; .hcb still supported for debug")
    p.add_argument("-o", "--output", required=True)
    _add_common(p)

    p = sub.add_parser("export-chapters", help="export real chapter-title opcode split txt files")
    p.add_argument("source", help="project_ir.json or disassembly project dir preferred; .hcb still supported for debug")
    p.add_argument("-o", "--outdir", required=True)
    _add_common(p)

    p = sub.add_parser("import-text", help="import doubleline.txt and raw-first repack")
    p.add_argument("source", help="project_ir.json or disassembly project dir preferred; .hcb still supported for debug")
    p.add_argument("txt", help="doubleline.txt")
    p.add_argument("-o", "--outdir", required=True)
    _add_common(p)

    p = sub.add_parser("import-chapters", help="import a folder of chapter txt files and raw-first repack")
    p.add_argument("source", help="project_ir.json or disassembly project dir preferred; .hcb still supported for debug")
    p.add_argument("chapter_dir", help="folder created by export-chapters")
    p.add_argument("-o", "--outdir", required=True)
    _add_common(p)

    p = sub.add_parser("repack", help="baseline raw-first repack/copy from original .hcb")
    p.add_argument("source")
    p.add_argument("-o", "--output", required=True)
    _add_common(p)

    p = sub.add_parser("verify", help="byte/hash verify two files")
    p.add_argument("original")
    p.add_argument("rebuilt")
    p.add_argument("-o", "--outdir")

    sub.add_parser("gui", help="open tkinter GUI")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        opts = {"encoding": getattr(args, "encoding", "cp932")}
        if args.cmd == "disasm":
            inputs = _expand_inputs(args.inputs)
            result = DisassembleService().run(inputs, args.outdir, {**opts, "mode": args.mode, "export_text": args.with_text, "baseline_repack": args.with_baseline_repack})
        elif args.cmd == "export-text":
            result = ExportDoubleLineService().run(args.source, args.output, {**opts, "require_project_ir": True})
        elif args.cmd == "export-chapters":
            result = ExportChapterTextService().run(args.source, args.outdir, {**opts, "require_project_ir": True})
        elif args.cmd == "import-text":
            result = ImportDoubleLineService().run(args.source, args.txt, args.outdir, {**opts, "require_project_ir": True})
        elif args.cmd == "import-chapters":
            result = ImportChapterTextService().run(args.source, args.chapter_dir, args.outdir, {**opts, "require_project_ir": True})
        elif args.cmd == "repack":
            ir, _plugin = load_ir_from_source(args.source, opts, include_disasm=False)
            result = RepackService().run(ir, args.output, patches=[], verify=True)
        elif args.cmd == "verify":
            v = VerifyService().run(args.original, args.rebuilt, args.outdir)
            result = {"original": v.original, "rebuilt": v.rebuilt, "result": v.result}
        elif args.cmd == "gui":
            from hcb_tool.gui.main_window import main as gui_main
            gui_main()
            return 0
        else:
            raise AssertionError(args.cmd)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
