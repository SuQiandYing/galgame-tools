# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .dpk import unpack_dpk, repack_dpk
from .pipeline import disasm_project, export_asm_project, export_text_project, export_project, import_and_repack, smoke_roundtrip, verify_project
from .utils import verify_files
from .dacz import load_profiles


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="daclocalizer", description="DPK/DACZ localization tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("unpack-dpk", help="Unpack DPK to files + vfs_manifest")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)

    p = sub.add_parser("repack-dpk", help="Repack an extracted DPK folder")
    p.add_argument("extract_dir", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)

    p = sub.add_parser("disasm", help="Stage 1: DPK unpack + DACZ decode + full IR")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.add_argument("--encoding", default="cp932")
    p.add_argument("--no-clean", action="store_true")

    p = sub.add_parser("export-asm", help="Stage 2: generate ASM audit view from IR")
    p.add_argument("workspace", type=Path)

    p = sub.add_parser("export-text", help="Stage 3: generate per-source DSAT from IR; if input is DPK, also performs stages 1-2 for compatibility")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.add_argument("--encoding", default="cp932")
    p.add_argument("--no-clean", action="store_true")

    p = sub.add_parser("import-text", help="Stage 4+5: import edited DSAT and rebuild script.dpk")
    p.add_argument("workspace", type=Path)
    p.add_argument("dsat", type=Path, help="DSAT file, texts directory, or texts/by_source directory")
    p.add_argument("-o", "--out", type=Path, required=True)
    p.add_argument("--encoding", default="cp932")
    p.add_argument("--allow-lengthen", action="store_true", help="Allow whole-script and DPK dynamic relocation")
    p.add_argument("--in-place", action="store_true", help="Reject entries longer than the source text")

    p = sub.add_parser("repack", help="Alias of import-text for staged GUI/CLI naming")
    p.add_argument("workspace", type=Path)
    p.add_argument("dsat", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.add_argument("--encoding", default="cp932")
    p.add_argument("--allow-lengthen", action="store_true")
    p.add_argument("--in-place", action="store_true")

    p = sub.add_parser("smoke-roundtrip", help="Export + import without edits and verify byte-exact hash")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--out", type=Path, required=True)
    p.add_argument("--encoding", default="cp932")


    p = sub.add_parser("profiles", help="List script crypto auto-detect profiles")
    p = sub.add_parser("verify", help="Stage 6: byte-level verify and hexdiff")
    p.add_argument("original", type=Path)
    p.add_argument("rebuilt", type=Path)
    p.add_argument("-o", "--out", type=Path, default=Path("reports"))

    args = ap.parse_args(argv)
    if args.cmd == "unpack-dpk":
        res = unpack_dpk(args.input, args.out)
        print(json.dumps({"ok": True, "out": str(args.out), "file_count": len(res["files"])}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "repack-dpk":
        res = repack_dpk(args.extract_dir, args.out)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "disasm":
        res = disasm_project(args.input, args.out, args.encoding, clean=not args.no_clean)
        print(json.dumps({"ok": True, "workspace": str(args.out), "scripts": len(res["scripts"]), "total_text_entries": res["total_text_entries"]}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "export-asm":
        res = export_asm_project(args.workspace)
        print(json.dumps({"ok": True, **res}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "export-text":
        # Compatibility: if input is a DPK, run stages 1-3; if it is an existing workspace, only export DSAT.
        if args.input.is_file() and args.input.suffix.lower() == ".dpk":
            res = export_project(args.input, args.out, args.encoding, clean=not args.no_clean)
            print(json.dumps({"ok": True, "workspace": str(args.out), "total_text_entries": res["total_text_entries"]}, ensure_ascii=False, indent=2))
        else:
            res = export_text_project(args.input)
            print(json.dumps({"ok": True, **res}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd in {"import-text", "repack"}:
        allow = args.allow_lengthen or not args.in_place
        res = import_and_repack(args.workspace, args.dsat, args.out, args.encoding, allow_lengthen=allow)
        print(json.dumps({"ok": True, "output": str(args.out), "changed": res["patch_report"]["entries_changed"]}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "smoke-roundtrip":
        res = smoke_roundtrip(args.input, args.out, args.encoding)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res["ok"] else 1
    if args.cmd == "profiles":
        items = []
        for prof in load_profiles():
            items.append({
                "profile_id": prof.profile_id,
                "display_name": prof.display_name,
                "algorithm": prof.algorithm,
                "encrypted_exts": prof.encrypted_exts,
                "min_score": prof.probe.get("min_score"),
            })
        print(json.dumps({"profiles": items}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "verify":
        out = args.out
        if out.suffix:
            report = out
            hexdiff = report.with_suffix(report.suffix + ".hexdiff.txt")
            ok = verify_files(args.original, args.rebuilt, report, hexdiff)
        else:
            ok = verify_project(args.original, args.rebuilt, out)
        print(f"[{'OK' if ok else 'FAIL'}] report={out}")
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
