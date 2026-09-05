"""Edited text surfaces + source RLD -> rebuilt RLD.

Does not reconstruct from the asm listing. It re-parses the source binary
(deterministic) and applies the diff between a freshly rendered surface and
the user's edited file. So only changed lines are interpreted, conflicts fall
out of a set intersection, and no ASM grammar parser is needed.

Length changes are the normal case: a translated line is usually a different
size, so entries are re-serialised and the whole op stream is rewritten with
recomputed offsets. Ops carry no absolute pointers -- verified across 2797
files -- so no pointer table needs relocating; the header's op_offset and
op_count are the only positional fields, and they are written from the IR.
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import struct
import sys
import time
from pathlib import Path

from opcodelist import DIALECT, IR_VERSION, TOOL_VERSION
import rldcore as core
import rldir as ir
import disassembler as dis
import subs

_C = DIALECT["container"]
_O = DIALECT["op"]

RE_SRC = re.compile(r"^○(?P<idx>\d{8})○(?P<tag>[a-z_]+)○(?P<text>.*)$")
RE_DST = re.compile(r"^●(?P<idx>\d{8})●(?P<tag>[a-z_]+)●(?P<text>.*)$")
RE_HDR_SHA = re.compile(r"src_sha256=([0-9a-f]{64})")
RE_HDR_ENC = re.compile(r"target=([\w\-]+)")


class ImportError_(core.RldError):
    code = "IMPORT_REJECTED"


# ---------------------------------------------------------------------------
# reading the translated surface
# ---------------------------------------------------------------------------

def parse_text_file(path: Path):
    """Read a dual-line file into {idx: (tag, source, target)} plus header."""
    raw = path.read_text(encoding="utf-8-sig")
    lines = raw.split("\n")
    head = [l for l in lines[:6] if l.startswith("#")]
    joined = "\n".join(head)
    m = RE_HDR_SHA.search(joined)
    if not m:
        raise ImportError_(f"{path.name}: 文件头缺少 src_sha256")
    sha = m.group(1)
    enc = RE_HDR_ENC.search(joined)
    target_encoding = enc.group(1) if enc else None

    entries = {}
    pending = None
    for lineno, line in enumerate(lines, 1):
        line = line.rstrip("\r")
        ms = RE_SRC.match(line)
        if ms:
            pending = (int(ms.group("idx")), ms.group("tag"),
                       ms.group("text"), lineno)
            continue
        md = RE_DST.match(line)
        if md:
            if pending is None:
                raise ImportError_(
                    f"{path.name}:{lineno} 译文行没有对应的原文行")
            sidx, stag, stext, sline = pending
            didx = int(md.group("idx"))
            if didx != sidx:
                raise ImportError_(
                    f"{path.name}:{lineno} idx 不一致：原文 {sidx:08d}，"
                    f"译文 {didx:08d}")
            if md.group("tag") != stag:
                raise ImportError_(
                    f"{path.name}:{lineno} tag 不一致：原文 {stag}，"
                    f"译文 {md.group('tag')}")
            if sidx in entries:
                raise ImportError_(f"{path.name}:{lineno} idx {sidx:08d} 重复")
            entries[sidx] = (stag, stext, md.group("text"), lineno)
            pending = None
    if pending is not None:
        raise ImportError_(
            f"{path.name}:{pending[3]} 原文行 {pending[0]:08d} 缺少译文行")
    return dict(sha256=sha, target_encoding=target_encoding, entries=entries)


def validate_import(doc, parsed, path, target_encoding, subs_table=None):
    """The import checklist. Any failure rejects the whole file.

    Rejects rather than repairs: a mismatch means the file no longer describes
    this source, and guessing which side is right would silently drop work.
    """
    if parsed["sha256"] != doc.src_sha256:
        raise ImportError_(
            f"{path.name}: 文件头哈希与当前源文件不符（译文可能来自旧版导出）")
    by_idx = {t.idx: t for t in doc.texts}
    edits = {}
    for idx, (tag, src, dst, lineno) in parsed["entries"].items():
        entry = by_idx.get(idx)
        if entry is None:
            raise ImportError_(f"{path.name}:{lineno} idx {idx:08d} 不存在于该源文件")
        if tag != entry.tag:
            raise ImportError_(
                f"{path.name}:{lineno} idx {idx:08d} tag 应为 {entry.tag}")
        if src != entry.source:
            raise ImportError_(
                f"{path.name}:{lineno} idx {idx:08d} 原文行被改动。\n"
                f"    IR:   {entry.source!r}\n    文件: {src!r}")
        if dst == "":
            raise ImportError_(
                f"{path.name}:{lineno} idx {idx:08d} 译文行为空"
                f"（空行表示内容被误删，未翻译应保留原文）")
        if entry.translate_policy == "frozen" and dst != src:
            raise ImportError_(
                f"{path.name}:{lineno} idx {idx:08d} 是锁定条目，不可修改"
                f"（{entry.tag_subtype or entry.tag}）")
        if dst != src:
            # Translations are authored in plain simplified Chinese; the glyph
            # table swaps each character for a cp932-storable stand-in that the
            # font hook renders as the intended Chinese.
            stored = subs_table.to_cp932(dst) if subs_table else dst
            try:
                ir.from_display(stored, target_encoding)
            except UnicodeEncodeError as exc:
                bad = stored[exc.start:exc.end]
                original = dst[exc.start:exc.end] if exc.start < len(dst) else bad
                hint = (f"（替换表里没有 {original!r}）" if subs_table
                        else _suggest_encoding(bad))
                raise ImportError_(
                    f"{path.name}:{lineno} idx {idx:08d} 译文编码 "
                    f"{target_encoding} 无法表示 {bad!r}{hint}")
            edits[idx] = stored
    missing = set(by_idx) - set(parsed["entries"])
    if missing:
        raise ImportError_(
            f"{path.name}: 缺少 {len(missing)} 条条目"
            f"（首个 idx={min(missing):08d}），不接受不完整的译文文件")
    return edits


def _suggest_encoding(text):
    # gb18030 before gbk: the Japanese source already contains symbols gbk
    # cannot encode (the music note U+266A appears in real dialogue), so gbk
    # would reject lines the translator never touched.
    for cand in ("gb18030", "gbk", "big5", "cp949", "utf-8"):
        try:
            text.encode(cand)
        except (UnicodeEncodeError, LookupError):
            continue
        return f"可改用 {cand}"
    return "该字符在常见编码中均无法表示"


# ---------------------------------------------------------------------------
# rebuilding
# ---------------------------------------------------------------------------

def apply_edits(doc, edits, target_encoding):
    """Rewrite each edited text unit inside its owning string."""
    new_strings = {}
    for entry in doc.texts:
        if entry.idx not in edits:
            continue
        replacement = ir.from_display(edits[entry.idx], target_encoding)
        key = (entry.op_index, entry.slot)
        current = new_strings.get(key)
        if current is None:
            current = doc.ops[entry.op_index].strings[entry.slot][1]
        if entry.kind in ("whole", "choice_bare", "speaker_slot"):
            # speaker_slot replaces the whole slot: the "*" that meant "look up
            # the character table" becomes the literal name to display. Only
            # reached for entries the translator actually changed, so unedited
            # lines keep their "*" and the table lookup stays intact.
            new_strings[key] = replacement
        else:
            sep = entry.sep.encode(target_encoding)
            parts = current.split(sep)
            if entry.field_index >= len(parts):
                raise core.RldError(
                    f"{doc.path}: idx {entry.idx} 字段 {entry.field_index} 越界")
            parts[entry.field_index] = replacement
            new_strings[key] = sep.join(parts)
    return new_strings


def serialise(doc, new_strings, target_encoding):
    """Re-emit the whole file from the IR with the given string overrides."""
    body = bytearray()
    term = _O["string_terminator"]
    for op in doc.ops:
        body += struct.pack("<I", op.control)
        for v in op.inits:
            body += struct.pack("<I", v)
        for si, (off, raw) in enumerate(op.strings):
            data = new_strings.get((op.index, si), raw)
            if term in data:
                raise core.RldError(
                    f"{doc.path}: op {op.index} 串 {si} 含终止符字节")
            body += data + term
    tail = doc.plain[doc.stream_end:]
    head = bytearray(doc.plain[:doc.op_offset])
    struct.pack_into("<I", head, _C["op_offset_field"], doc.op_offset)
    struct.pack_into("<I", head, _C["op_count_field"],
                     len(doc.ops) - core.REQUIRED_DELTA)
    return bytes(head) + bytes(body) + bytes(tail)


def verify_rebuild(doc, plain_out, edits, new_strings, target_encoding):
    """Post-conditions for a variable-length repack.

    Checks that the output re-parses, that every edit is present, and that
    untouched strings are byte-identical. "Loads without crashing" is not
    evidence the edit landed, so the new bytes are looked up explicitly.
    """
    problems = []
    try:
        redoc = ir.parse(doc.path, core.apply_cipher(plain_out, doc.key),
                         doc.key)
    except core.RldError as exc:
        return [f"输出无法重新解析：{exc}"]
    if len(redoc.ops) != len(doc.ops):
        problems.append(f"op 数改变：{len(doc.ops)} → {len(redoc.ops)}")
    if redoc.declared_count + core.REQUIRED_DELTA != len(redoc.ops):
        problems.append("op_count 字段与实际 op 数不一致")
    cov = ir.coverage(redoc)
    if cov["byte_coverage"] != 1.0 or cov["gaps"] or cov["overlaps"]:
        problems.append("重新解析后字节覆盖不完整")
    changed = unchanged = 0
    for op_old, op_new in zip(doc.ops, redoc.ops):
        if op_old.control != op_new.control or op_old.inits != op_new.inits:
            problems.append(f"op {op_old.index} 的控制字或参数被改动")
            break
        for si, (_, raw_old) in enumerate(op_old.strings):
            raw_new = op_new.strings[si][1]
            expected = new_strings.get((op_old.index, si), raw_old)
            if raw_new != expected:
                problems.append(f"op {op_old.index} 串 {si} 写入内容不符")
            elif (op_old.index, si) in new_strings:
                changed += 1
            else:
                unchanged += 1
                if raw_new != raw_old:
                    problems.append(f"op {op_old.index} 串 {si} 未编辑却发生变化")
    return problems


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

def repack(inputs, text_dir, out_dir, source_encoding=None,
           target_encoding=None, log=print, progress=None, dry_run=False,
           subs_table=None):
    """Apply edited texts to sources and write rebuilt RLD files."""
    sources = dis.collect_sources(inputs)
    if not sources:
        raise core.RldError("没有找到 .rld 文件")
    text_dir = Path(text_dir)
    texts_root = text_dir / "texts" if (text_dir / "texts").is_dir() else text_dir
    out_dir = Path(out_dir)

    session = dis.Session(sources, text_dir, source_encoding,
                          target_encoding, log)
    session.resolve_keys()
    session.build_name_table()
    target_encoding = target_encoding or session.target_encoding
    if subs_table is None:
        subs_table = subs.load()
    if subs_table:
        log(f"字形替换表：{len(subs_table)} 条"
            f"（{getattr(subs_table.source, 'name', '内置')}）")

    report = dict(tool_version=TOOL_VERSION, started=time.strftime("%F %T"),
                  files_total=len(sources), files_written=0, files_skipped=0,
                  entries_changed=0, bytes_delta=0, strategy=None,
                  subs_entries=len(subs_table) if subs_table else 0,
                  rejected=[], verify_failed=[], size_changes=[])
    plans = []

    for doc in session.documents(progress=progress):
        rel = session.rel(doc.path)
        tpath = texts_root / rel.parent / (rel.name + ".txt")
        if not tpath.exists():
            report["files_skipped"] += 1
            continue
        check = dis.selfcheck(doc)
        if not check["passed"]:
            report["rejected"].append(f"{rel}: 零编辑自检未通过，不能回封")
            continue
        ir.extract_texts(doc, session.name_table, session.source_encoding)
        try:
            parsed = parse_text_file(tpath)
            enc = parsed["target_encoding"] or target_encoding
            edits = validate_import(doc, parsed, tpath, enc, subs_table)
        except core.RldError as exc:
            report["rejected"].append(str(exc))
            continue
        if not edits:
            plans.append((doc, {}, {}, enc, 0))
            continue
        new_strings = apply_edits(doc, edits, enc)
        out_plain = serialise(doc, new_strings, enc)
        delta = len(out_plain) - len(doc.plain)
        plans.append((doc, edits, new_strings, enc, delta))
        report["entries_changed"] += len(edits)
        report["bytes_delta"] += delta
        if delta:
            report["size_changes"].append((str(rel), delta))

    report["strategy"] = ("identity" if report["entries_changed"] == 0
                          else "full-restream")
    if dry_run:
        return report, plans

    out_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = out_dir / dis.WORKDIR / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    for doc, edits, new_strings, enc, delta in plans:
        rel = session.rel(doc.path)
        dest = out_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not edits:
            out_bytes = doc.raw
        else:
            out_plain = serialise(doc, new_strings, enc)
            problems = verify_rebuild(doc, out_plain, edits, new_strings, enc)
            if problems:
                report["verify_failed"].append(f"{rel}: {problems[0]}")
                failed = tmp_dir / "failed"
                failed.mkdir(parents=True, exist_ok=True)
                (failed / rel.name).write_bytes(
                    core.apply_cipher(out_plain, doc.key))
                continue
            out_bytes = core.apply_cipher(out_plain, doc.key)
            # the cipher is symmetric, so re-decoding must give back the plain
            if core.apply_cipher(out_bytes, doc.key) != out_plain:
                report["verify_failed"].append(f"{rel}: 重新加密不可逆")
                continue
        tmp = tmp_dir / (rel.name + ".part")
        tmp.write_bytes(out_bytes)
        tmp.replace(dest)
        report["files_written"] += 1

    reports_dir = out_dir / dis.WORKDIR / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "repack_report.json").write_text(
        json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
    return report, plans


def main(argv=None):
    ap = argparse.ArgumentParser(description="ExHIBIT RLD 文本回封")
    ap.add_argument("inputs", nargs="+", help="原始 rld 文件或文件夹")
    ap.add_argument("-t", "--texts", required=True, help="译文目录")
    ap.add_argument("-o", "--out", required=True, help="输出目录")
    ap.add_argument("--source-encoding", default=None)
    ap.add_argument("--target-encoding", default=None)
    ap.add_argument("--subs", default=None,
                    help="字形替换表 json，缺省自动查找 subs_cn_jp.json")
    ap.add_argument("--no-subs", action="store_true",
                    help="禁用字形替换，按字面写入")
    ap.add_argument("--dry-run", action="store_true", help="只预览，不写文件")
    args = ap.parse_args(argv)

    table = subs.SubsTable() if args.no_subs else subs.load(args.subs)
    report, _ = repack(args.inputs, args.texts, args.out,
                       source_encoding=args.source_encoding,
                       target_encoding=args.target_encoding,
                       dry_run=args.dry_run, subs_table=table)
    print(f"\n改动 {report['entries_changed']} 条译文，"
          f"长度变化 {report['bytes_delta']:+d} 字节")
    print(f"  方式 {report['strategy']}")
    if args.dry_run:
        print("  （预览模式，未写出任何文件）")
    else:
        print(f"  已写出 {report['files_written']} 个文件 → {args.out}")
    if report["files_skipped"]:
        print(f"  跳过 {report['files_skipped']} 个（没有对应译文）")
    for line in report["rejected"][:10]:
        print(f"  拒绝：{line}")
    for line in report["verify_failed"][:10]:
        print(f"  校验失败：{line}")
    return 1 if (report["rejected"] or report["verify_failed"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
