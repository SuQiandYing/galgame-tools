"""Source RLD -> in-memory IR -> dual-line text files, asm listing, reports.

Two independent entry points, both taking source bytes:
  export_texts()  -> texts/<mirrored path>.txt   (the translator's surface)
  export_asm()    -> asm/<mirrored path>.asm.txt (the structural surface)

Neither reads the other's output. The zero-edit roundtrip self-check and the
coverage certificate run regardless of which products were requested.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sys
import time
from pathlib import Path

from opcodelist import DIALECT, IR_VERSION, TOOL_VERSION
import rldcore as core
import rldir as ir
import subs

KEYFILE = "keys.json"
WORKDIR = "_work"

# Below this many inputs, recovery borrows sibling files as key donors.
# Measured: 4 files suffice for the plurality vote, 2 are unreliable.
MIN_KEY_SAMPLES = 8


# ---------------------------------------------------------------------------
# key cache
# ---------------------------------------------------------------------------

def _key_cache_path(out_dir: Path) -> Path:
    return out_dir / WORKDIR / KEYFILE


def load_keys(out_dir: Path):
    """Previously recovered keys, keyed by the zero-region anchor."""
    path = _key_cache_path(out_dir)
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {tuple(int(x) for x in item["anchor"]): [int(x) for x in item["key"]]
            for item in data.get("keys", [])}


def save_keys(out_dir: Path, groups, blob_of=None):
    """Cache recovered keys so later runs (and single-file drops) reuse them."""
    path = _key_cache_path(out_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"tool_version": TOOL_VERSION, "keys": []}
    for g in groups:
        if not g.paths:
            continue
        first = g.paths[0]
        data = blob_of(first) if blob_of else Path(first).read_bytes()
        payload["keys"].append({
            "anchor": list(core.anchor_of(data)),
            "key": list(g.key),
            "files": len(g.paths),
            "info": g.info,
        })
    path.write_text(json.dumps(payload, indent=1), encoding="utf-8")


def builtin_shared_keys():
    """The def.rld keystream, hardcoded once in the engine and shared by every
    ExHIBIT title measured. Bundled because a single file cannot be voted on.
    """
    path = Path(__file__).with_name("key_def_shared.json")
    if not path.exists():
        return {}
    key = json.loads(path.read_text(encoding="utf-8"))
    return {tuple(key[:core.ANCHOR_WORDS]): key}


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------

def collect_sources(inputs):
    """Expand files/folders into a sorted list of .rld paths."""
    out = []
    for item in inputs:
        p = Path(item)
        if p.is_dir():
            out.extend(sorted(q for q in p.rglob("*.rld") if q.is_file()))
        elif p.is_file():
            out.append(p)
    seen, uniq = set(), []
    for p in out:
        rp = p.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        uniq.append(p)
    return uniq


def common_root(paths):
    if not paths:
        return Path(".")
    if len(paths) == 1:
        return paths[0].parent
    import os
    return Path(os.path.commonpath([str(p.parent) for p in paths]))


class Session:
    """One decode pass over a set of sources: keys, IR, name table."""

    def __init__(self, sources, out_dir, source_encoding=None,
                 target_encoding=None, log=print):
        self.sources = list(sources)
        self.out_dir = Path(out_dir)
        self.root = common_root(self.sources)
        self.log = log
        enc = DIALECT["encodings"]
        self.source_encoding = source_encoding or enc["source"]
        self.target_encoding = target_encoding or enc["target"]
        self.subs = subs.load()
        self.keymap = {}
        self.groups = []
        self.unresolved = []
        self.name_table = {}
        self.key_info = []

    def _donors(self, wanted):
        """Sibling .rld files used only to strengthen key recovery.

        Recovery is statistical over a shared keystream, so one file rarely
        carries enough samples. When the user asks for a single file we read
        its neighbours to recover the key, then export only what was asked
        for. Donors are never written to and never appear in the output.
        """
        folders = {p.parent for p in wanted}
        extra = {}
        for folder in folders:
            for q in sorted(folder.glob("*.rld")):
                if q not in wanted and q.is_file():
                    extra[q] = q.read_bytes()
        return extra

    # -- keys ------------------------------------------------------------
    def resolve_keys(self, progress=None):
        blobs = {p: p.read_bytes() for p in self.sources}
        shared = dict(builtin_shared_keys())
        shared.update(load_keys(self.out_dir))
        self.log(f"正在恢复密钥（{len(blobs)} 个文件）…")
        pool = dict(blobs)
        donors = {}
        if len(blobs) < MIN_KEY_SAMPLES:
            donors = self._donors(set(blobs))
            if donors:
                self.log(f"输入文件较少，借用同目录 {len(donors)} 个文件"
                         f"辅助恢复密钥（不会导出它们）")
                pool.update(donors)
        groups, left = core.discover_keys(pool, shared=shared)
        self.groups = []
        for g in groups:
            wanted = [p for p in g.paths if p in blobs]
            for p in wanted:
                self.keymap[p] = g.key
            if wanted:
                self.groups.append(core.KeyGroup(key=g.key, paths=wanted,
                                                 info=g.info))
                self.key_info.append(g.info)
        self.unresolved = [p for p in left if p in blobs]
        self.log(f"密钥恢复完成：{len(self.groups)} 组，"
                 f"{len(self.keymap)}/{len(blobs)} 个文件可解密")
        if self.unresolved:
            names = ", ".join(p.name for p in self.unresolved[:5])
            self.log(f"警告：{len(self.unresolved)} 个文件无法解密：{names}"
                     f"{' …' if len(self.unresolved) > 5 else ''}")
        self._blobs = pool
        return self.groups, self.unresolved

    def blob(self, path):
        return self._blobs[path]

    # -- name table ------------------------------------------------------
    def build_name_table(self):
        """Read the character table, even if it was not one of the inputs.

        Speaker names live in a separate file (defChara.rld). Exporting a
        single scenario file must still show who is speaking, so the table is
        looked up among the inputs first and then beside them on disk.
        """
        target = DIALECT["name_binding"]["table_file"].lower()
        candidates = [p for p in self.sources if p.name.lower() == target]
        for folder in {p.parent for p in self.sources}:
            candidates.extend(q for q in folder.glob("*")
                              if q.name.lower() == target and q not in candidates)
        for p in candidates:
            try:
                data = self._blobs.get(p) or p.read_bytes()
                key = self.keymap.get(p)
                if key is None:
                    for g in self.groups:
                        if core.decodes_cleanly(data, g.key):
                            key = g.key
                            break
                if key is None:
                    continue
                doc = ir.parse(p, data, key, self.source_encoding)
            except (OSError, core.RldError):
                continue
            self.name_table = ir.build_name_table(doc, self.source_encoding)
            self.log(f"人名表：{len(self.name_table)} 条（来自 {p.name}）")
            return self.name_table
        self.log("警告：未找到人名表，说话者将显示为角色编号")
        return {}

    def documents(self, progress=None):
        """Yield a parsed Document per decodable source."""
        total = len(self.sources)
        for i, p in enumerate(self.sources, 1):
            if p not in self.keymap:
                continue
            doc = ir.parse(p, self.blob(p), self.keymap[p],
                           self.source_encoding)
            if progress:
                progress(i, total, p)
            yield doc

    def rel(self, path):
        try:
            return Path(path).relative_to(self.root)
        except ValueError:
            return Path(Path(path).name)


# ---------------------------------------------------------------------------
# self-check
# ---------------------------------------------------------------------------

def selfcheck(doc) -> dict:
    """Zero-edit roundtrip plus byte attribution. Gate for any repack."""
    rebuilt = core.apply_cipher(doc.plain, doc.key)
    identical = rebuilt == doc.raw
    cov = ir.coverage(doc)
    ok = (identical
          and cov["byte_coverage"] == 1.0
          and not cov["gaps"] and not cov["overlaps"]
          and cov["op_delta"] == core.REQUIRED_DELTA)
    return dict(roundtrip_identity=identical, passed=ok, **cov)


# ---------------------------------------------------------------------------
# dual-line text rendering
# ---------------------------------------------------------------------------

def render_texts(doc, source_encoding, target_encoding, rel_path,
                 subs_table=None) -> str:
    """Exported text is the file's literal content, never glyph-translated.

    The substitution table is applied on import only. Running it backwards here
    would rewrite untranslated Japanese into pseudo-Chinese, because the
    stand-in glyphs are ordinary Japanese characters (時 说 這 ...), and the
    O-line would no longer match the bytes it is supposed to verify.
    """
    """Render the translator surface.

    Only fields that are actually verified on import are written, plus the
    speaker, which the translator needs to judge tone. The translated line is
    pre-filled with the original so partial work stays repackable and
    "untranslated" is simply target == source.
    """
    lines = [
        f"# TEXT/{IR_VERSION} ir={IR_VERSION} tool={TOOL_VERSION} "
        f"src_sha256={doc.src_sha256}",
        f"# encoding source={source_encoding} target={target_encoding} file=utf-8",
        "# scope kind=all range=ALL part=1/1",
        "# tags " + " ".join(sorted({t.tag for t in doc.texts})
                             or ["none"]),
        "#",
    ]
    for t in doc.texts:
        meta = [f"idx={t.idx:08d}", f"off=0x{t.offset:08X}", f"tag={t.tag}"]
        if t.speaker:
            meta.append(f"speaker={t.speaker}")
        elif t.name_kind == "virtual":
            meta.append("speaker=-")
        if t.translate_policy == "frozen":
            meta.append("frozen")
        lines.append("# " + " ".join(meta))
        lines.append(f"○{t.idx:08d}○{t.tag}○{t.source}")
        lines.append(f"●{t.idx:08d}●{t.tag}●{t.source}")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_asm(doc, source_encoding, rel_path) -> str:
    """Render the structural surface.

    Every byte of the address space appears: header, pre-stream region, each op
    with its operands and strings, and the trailing region. No raw hex dumps of
    op payloads -- strings use placeholders, operands are decimal/hex literals.
    """
    out = [
        f"; source {rel_path}",
        f"; sha256 {doc.src_sha256}",
        f'.encoding "{source_encoding}"',
        f'.dialect  "{DIALECT["dialect_id"]}" version "{DIALECT["schema_version"]}"',
        '.tier     "T2"',
        f".op_offset 0x{doc.op_offset:08X}",
        f".op_count  {doc.declared_count}   ; excludes the terminator op",
        "",
    ]
    texts = {(t.op_index, t.slot): t for t in doc.texts
             if t.kind == "whole"}
    for op in doc.ops:
        out.append("")
        out.append(f"loc_{op.offset:08X}:")
        out.append(f"    .op    code=0x{op.code:04X} flags=0x{op.flags:X} "
                   f"inits={op.init_count} strings={op.str_count}")
        if op.inits:
            joined = ", ".join(str(v) for v in op.inits)
            out.append(f"    .word  {joined}")
        for si, (off, raw) in enumerate(op.strings):
            shown = ir.to_display(raw, source_encoding)
            entry = texts.get((op.index, si))
            tail = f"   ; idx={entry.idx:08d} tag={entry.tag}" if entry else ""
            out.append(f'    .string sid={off:08X} "{shown}"{tail}')
    if doc.stream_end < len(doc.plain):
        extra = doc.plain[doc.stream_end:]
        out.append("")
        out.append(f"loc_{doc.stream_end:08X}:")
        out.append(f"    .preserve {len(extra)}   ; bytes reproduced verbatim")
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def export(inputs, out_dir, want_texts=True, want_asm=False,
           source_encoding=None, target_encoding=None, log=print,
           progress=None, with_ir=False):
    """Full export pass. Returns a report dict."""
    sources = collect_sources(inputs)
    if not sources:
        raise core.RldError("没有找到 .rld 文件")
    if not (want_texts or want_asm):
        raise core.RldError("请至少选择一种输出")
    out_dir = Path(out_dir)
    session = Session(sources, out_dir, source_encoding, target_encoding, log)
    session.resolve_keys()
    save_keys(out_dir, session.groups, blob_of=session.blob)
    session.build_name_table()

    report = dict(
        tool_version=TOOL_VERSION, dialect=DIALECT["dialect_id"],
        started=time.strftime("%Y-%m-%d %H:%M:%S"),
        files_total=len(sources), files_decoded=0, files_failed=[],
        entries=0, tags=collections.Counter(),
        tag_sources=collections.Counter(),
        policies=collections.Counter(),
        name_kinds=collections.Counter(),
        selfcheck_failed=[], min_byte_coverage=1.0,
        unresolved_files=[str(p) for p in session.unresolved],
        key_groups=session.key_info,
        source_encoding=session.source_encoding,
        target_encoding=session.target_encoding,
    )
    texts_root = out_dir / "texts"
    asm_root = out_dir / "asm"
    index = []

    for doc in session.documents(progress=progress):
        rel = session.rel(doc.path)
        check = selfcheck(doc)
        if not check["passed"]:
            report["selfcheck_failed"].append(str(rel))
            log(f"自检失败，跳过：{rel}")
            continue
        report["min_byte_coverage"] = min(report["min_byte_coverage"],
                                         check["byte_coverage"])
        ir.extract_texts(doc, session.name_table, session.source_encoding)
        report["files_decoded"] += 1
        report["entries"] += len(doc.texts)
        for t in doc.texts:
            report["tags"][t.tag] += 1
            report["tag_sources"][t.tag_source] += 1
            report["policies"][t.translate_policy] += 1
        for b in doc.bindings:
            report["name_kinds"][b.name_kind] += 1

        if want_texts:
            dest = texts_root / rel.parent / (rel.name + ".txt")
            dest.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(dest, render_texts(
                doc, session.source_encoding, session.target_encoding, rel,
                session.subs), DIALECT["encodings"]["text_file"])
            index.append((str(rel), str(dest.relative_to(out_dir)),
                          len(doc.texts)))
        if want_asm:
            dest = asm_root / rel.parent / (rel.name + ".asm.txt")
            dest.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(dest, render_asm(
                doc, session.source_encoding, rel),
                DIALECT["encodings"]["asm"])
        if with_ir:
            _dump_ir(out_dir, rel, doc, check)

    if want_texts and index:
        lines = ["source\ttext_file\tentries"]
        lines += [f"{a}\t{b}\t{c}" for a, b, c in index]
        _atomic_write(texts_root / "_index.tsv", "\n".join(lines) + "\n",
                      "utf-8")

    reports_dir = out_dir / WORKDIR / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    serialisable = dict(report)
    for k in ("tags", "tag_sources", "policies", "name_kinds"):
        serialisable[k] = dict(report[k])
    _atomic_write(reports_dir / "extract_report.json",
                  json.dumps(serialisable, indent=1, ensure_ascii=False),
                  "utf-8")
    return report


def _atomic_write(path: Path, text: str, encoding: str):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    with open(tmp, "w", encoding=encoding, newline="\n") as fh:
        fh.write(text)
        fh.flush()
    tmp.replace(path)


def _dump_ir(out_dir, rel, doc, check):
    d = out_dir / WORKDIR / "ir"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "manifest.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "source": str(rel), "sha256": doc.src_sha256,
            "size": len(doc.raw), "ops": len(doc.ops),
            "entries": len(doc.texts), "coverage": check["byte_coverage"],
        }, ensure_ascii=False) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="ExHIBIT RLD 文本导出（解密 + 提取，无需启动游戏）")
    ap.add_argument("inputs", nargs="+", help="rld 文件或文件夹")
    ap.add_argument("-o", "--out", help="输出目录，缺省为 <输入名>_text")
    ap.add_argument("--asm", action="store_true", help="同时导出 ASM 清单")
    ap.add_argument("--no-texts", action="store_true", help="不导出双行文本")
    ap.add_argument("--source-encoding", default=None)
    ap.add_argument("--target-encoding", default=None)
    ap.add_argument("--with-ir", action="store_true", help="同时导出 IR（排查用）")
    args = ap.parse_args(argv)

    sources = collect_sources(args.inputs)
    if not sources:
        print("没有找到 .rld 文件", file=sys.stderr)
        return 2
    if args.out:
        out = Path(args.out)
    else:
        root = common_root(sources)
        out = root.parent / (root.name + "_text")

    report = export(sources, out,
                    want_texts=not args.no_texts, want_asm=args.asm,
                    source_encoding=args.source_encoding,
                    target_encoding=args.target_encoding,
                    with_ir=args.with_ir)
    print(f"\n已导出 {report['entries']} 条，"
          f"{report['files_decoded']}/{report['files_total']} 个文件 → {out}")
    print(f"  分类  {dict(report['tags'])}")
    print(f"  说话者 {dict(report['name_kinds'])}")
    if report["selfcheck_failed"]:
        print(f"  自检失败 {len(report['selfcheck_failed'])} 个文件")
    if report["unresolved_files"]:
        print(f"  无法解密 {len(report['unresolved_files'])} 个文件")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
