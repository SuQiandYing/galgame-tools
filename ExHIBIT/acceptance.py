"""End-to-end acceptance: export -> translate -> repack -> reload.

Simulates a real localisation pass on a copy of the corpus, translating into
GBK (longer than the Japanese original in bytes for many lines) so the
variable-length path is exercised for real rather than synthetically.

Run: python acceptance.py [rld_dir] [--files N]
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

import rldcore as core
import rldir as ir
import disassembler as dis
import assembler as asm

_results = []


def check(name, cond, detail=""):
    _results.append((bool(cond), name, detail))
    print(f"[{'  ok  ' if cond else ' FAIL '}] {name}"
          + (f"  -- {detail}" if detail and not cond else ""))
    return bool(cond)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rld", nargs="?", default="E:/GuardianPlace/rld")
    ap.add_argument("--files", type=int, default=60)
    ap.add_argument("--encoding", default="gb18030")
    args = ap.parse_args()

    origin = Path(args.rld)
    tmp = Path(tempfile.mkdtemp(prefix="rldaccept_"))
    try:
        work = tmp / "rld"
        work.mkdir()
        picked = sorted(origin.glob("*.rld"))[:args.files]
        names = {p.name for p in picked}
        for extra in ("defChara.rld",):
            q = origin / extra
            if q.exists() and extra not in names:
                picked.append(q)
        for p in picked:
            shutil.copy2(p, work / p.name)
        before = {p.name: sha(p) for p in work.glob("*.rld")}
        print(f"=== {len(before)} files from {origin} ===")

        text_dir = tmp / "rld_text"
        out_dir = tmp / "rld_rebuilt"
        quiet = lambda *a, **k: None

        rep = dis.export([work], text_dir, want_texts=True, want_asm=True,
                         target_encoding=args.encoding, log=quiet)
        check("export decoded every file",
              rep["files_decoded"] == rep["files_total"],
              f"{rep['files_decoded']}/{rep['files_total']}")
        check("export produced dialogue", rep["tags"].get("msg", 0) > 0,
              str(dict(rep["tags"])))
        check("export produced speaker names",
              rep["name_kinds"].get("table", 0) > 0
              and rep["name_kinds"].get("override", 0) >= 0,
              str(dict(rep["name_kinds"])))
        check("coverage is complete", rep["min_byte_coverage"] == 1.0)
        check("no self-check failures", not rep["selfcheck_failed"],
              str(rep["selfcheck_failed"][:3]))
        check("originals untouched by export",
              all(sha(work / n) == h for n, h in before.items()))
        check("asm listing written",
              any((text_dir / "asm").rglob("*.asm.txt")))

        # --- zero-edit repack ------------------------------------------
        rep0, _ = asm.repack([work], text_dir, out_dir,
                             target_encoding=args.encoding, log=quiet)
        same = [n for n, h in before.items()
                if (out_dir / n).exists() and sha(out_dir / n) == h]
        check("zero-edit repack reproduces every byte",
              len(same) == len(before), f"{len(same)}/{len(before)}")
        check("zero-edit repack reports identity",
              rep0["strategy"] == "identity")

        # --- translate for real ----------------------------------------
        translated = changed_files = 0
        for tf in sorted((text_dir / "texts").rglob("*.rld.txt")):
            lines = tf.read_text(encoding="utf-8-sig").split("\n")
            hit = False
            for i, line in enumerate(lines):
                if not line.startswith("●"):
                    continue
                parts = line.split("●")
                if len(parts) < 4 or parts[2] not in ("msg", "choice"):
                    continue
                body = parts[3]
                if not body or body == "*":
                    continue
                # A plausible Chinese rendering: same marker tokens kept.
                new = "【中文译文】" + body[:6] + "，测试变长回封。"
                if "$b" in body:
                    new += " $b"
                lines[i] = f"●{parts[1]}●{parts[2]}●{new}"
                translated += 1
                hit = True
            if hit:
                tf.write_text("\n".join(lines), encoding="utf-8-sig")
                changed_files += 1
        print(f"    translated {translated} lines across {changed_files} files")

        out2 = tmp / "rld_translated"
        rep2, _ = asm.repack([work], text_dir, out2,
                             target_encoding=args.encoding, log=quiet)
        check("translated repack was not rejected",
              not rep2["rejected"], str(rep2["rejected"][:3]))
        check("translated repack passed verification",
              not rep2["verify_failed"], str(rep2["verify_failed"][:3]))
        check("translated repack applied every edit",
              rep2["entries_changed"] == translated,
              f"{rep2['entries_changed']} vs {translated}")
        check("translated files differ from the originals",
              all(sha(out2 / n) != h for n, h in before.items()
                  if (out2 / n).exists() and n in
                  {Path(f).name for f, _ in rep2["size_changes"]}))
        check("originals still untouched after repack",
              all(sha(work / n) == h for n, h in before.items()))

        # --- reload the rebuilt output ---------------------------------
        session = dis.Session(dis.collect_sources([out2]), tmp / "verify",
                              source_encoding=args.encoding,
                              target_encoding=args.encoding, log=quiet)
        session.resolve_keys()
        session.build_name_table()
        check("rebuilt output decodes with the same key",
              not session.unresolved, f"{len(session.unresolved)} unresolved")
        bad_cov, found_cn, checked = [], 0, 0
        for doc in session.documents():
            cov = ir.coverage(doc)
            if cov["byte_coverage"] != 1.0 or cov["op_delta"] != 1:
                bad_cov.append(doc.path.name)
            ir.extract_texts(doc, session.name_table, session.source_encoding)
            checked += 1
            for t in doc.texts:
                if "中文译文" in t.source:
                    found_cn += 1
        check("rebuilt output re-parses with full coverage",
              not bad_cov, str(bad_cov[:3]))
        check("the Chinese text is really present in the rebuilt files",
              found_cn == translated, f"found {found_cn} of {translated}")
        check("rebuilt name table still readable",
              len(session.name_table) > 0, f"{len(session.name_table)} entries")

        # --- single-file edit isolation ---------------------------------
        one = sorted(f for f, d in rep2["size_changes"])
        if one:
            target = Path(one[0]).name
            out3 = tmp / "rld_one"
            # restore all texts, then edit exactly one file again
            shutil.rmtree(text_dir)
            dis.export([work], text_dir, want_texts=True,
                       target_encoding=args.encoding, log=quiet)
            tf = text_dir / "texts" / (target + ".txt")
            lines = tf.read_text(encoding="utf-8-sig").split("\n")
            for i, line in enumerate(lines):
                if line.startswith("●") and line.split("●")[2] == "msg":
                    p = line.split("●")
                    lines[i] = f"●{p[1]}●{p[2]}●{p[3]}{p[3]}"
                    break
            tf.write_text("\n".join(lines), encoding="utf-8-sig")
            rep3, _ = asm.repack([work], text_dir, out3,
                                 target_encoding=args.encoding, log=quiet)
            others = [n for n in before
                      if n != target and (out3 / n).exists()
                      and sha(out3 / n) != before[n]]
            check("editing one file leaves the others byte-identical",
                  not others, f"{len(others)} changed: {others[:3]}")
            check("the edited file did change",
                  (out3 / target).exists()
                  and sha(out3 / target) != before[target])

        # --- wrong target encoding is reported, not silently mangled ---
        shutil.rmtree(text_dir)
        dis.export([work], text_dir, want_texts=True,
                   target_encoding="cp932", log=quiet)
        tf = next((text_dir / "texts").rglob("*.rld.txt"))
        lines = tf.read_text(encoding="utf-8-sig").split("\n")
        for i, line in enumerate(lines):
            if line.startswith("●") and line.split("●")[2] == "msg":
                p = line.split("●")
                lines[i] = f"●{p[1]}●{p[2]}●简体中文无法用日文编码表示"
                break
        tf.write_text("\n".join(lines), encoding="utf-8-sig")
        rep4, _ = asm.repack([work], text_dir, tmp / "rld_badenc",
                             target_encoding="cp932", log=quiet)
        msg = " ".join(rep4["rejected"])
        check("un-representable characters are rejected with a suggestion",
              bool(rep4["rejected"]) and "改用" in msg, msg[:120])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    failed = [r for r in _results if not r[0]]
    print(f"\n{len(_results) - len(failed)}/{len(_results)} checks passed")
    for _, name, detail in failed:
        print(f"  FAILED: {name}  {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
