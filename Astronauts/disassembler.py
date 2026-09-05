# -*- coding: utf-8 -*-
"""disassembler.py — moacode.mwb 全量反汇编 + 双行文本导出。

两个平级投影，各自从源二进制解析出内存 IR，互不依赖：

    render_asm(doc)    → asm/moacode.mwb.asm.txt     结构编辑面（开发者）
    render_texts(doc)  → texts/moacode.mwb.txt       文本编辑面（译者）

命令行：

    python disassembler.py <bincode.gxp 或 moacode.mwb> [-o 输出目录]
                           [--no-asm] [--no-texts] [--with-ir]

拖放：把 bincode.gxp 或 moacode.mwb 拖到本文件图标上。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import gxp
import mwb
from mwb import (TAG_BLK, TAG_END, TAG_INT, TAG_MARK, TAG_P06, TAG_P15,
                 TAG_REF, TAG_REFE, TAG_STR, MwbDocument)
from opcodelist import DIALECT

TOOL_VERSION = "1.0.0"
IR_VERSION = "MOA/1"

TEXT_FILE_ENCODING = "utf-8-sig"      # 双行文件带 BOM，记事本友好


# ----------------------------------------------------------------------
# 占位符（§4.5）：不可安全显示的字节 → {{XX}}；斜杠/全角空格不转义
# ----------------------------------------------------------------------

PAGE_BREAK = "\\n"      # 消息窗换页标记（多页 msg 合并后的页边界），写作字面反斜杠 n


def escape_text(s: str, page_break: bool = False) -> str:
    """转义为双行文件可写形式。

    page_break=True 时把真换行渲染为字面 `\\n`（两个字符：反斜杠 + n），
    用于已合并的多页 msg。双行文件是逐行格式，真换行会破坏行结构，故必须转义。

    为使往返无歧义，此模式下原文中本就存在的字面反斜杠会被写成 `\\\\`。
    实测本样本 92,652 条字符串中含反斜杠者为 0，该转义仅为防御性保证。
    """
    out = []
    for ch in s:
        o = ord(ch)
        if page_break and ch == "\n":
            out.append(PAGE_BREAK)
        elif page_break and ch == "\\":
            out.append("\\\\")
        elif ch in ("\n", "\r", "\t") or o < 0x20 or o == 0x7F:
            out.append("{{%s}}" % ":".join("%02X" % b for b in ch.encode("utf-8")))
        elif 0xE000 <= o <= 0xF8FF:                    # 私用区
            out.append("{{%s}}" % ":".join("%02X" % b for b in ch.encode("utf-8")))
        elif ch == "{" or ch == "}":
            out.append("{{%s}}" % ("%02X" % o))
        else:
            out.append(ch)
    return "".join(out)


def unescape_text(s: str, page_break: bool = False) -> str:
    """逆转义。page_break=True 时把字面 `\\n` 还原为真换行，`\\\\` 还原为反斜杠。"""
    out = []
    i = 0
    n = len(s)
    pending = bytearray()
    while i < n:
        if page_break and s[i] == "\\" and i + 1 < n and s[i + 1] in ("n", "\\"):
            if pending:
                out.append(pending.decode("utf-8", "strict"))
                pending = bytearray()
            out.append("\n" if s[i + 1] == "n" else "\\")
            i += 2
            continue
        if s.startswith("{{", i):
            j = s.find("}}", i)
            if j < 0:
                raise ValueError(f"占位符未闭合：…{s[i:i+20]}")
            body = s[i + 2:j]
            if body == "BR":                      # 兼容旧格式（v1.0.0 的换页标记）
                if pending:
                    out.append(pending.decode("utf-8", "strict"))
                    pending = bytearray()
                out.append("\n")
                i = j + 2
                continue
            for part in body.split(":"):
                if len(part) != 2 or any(c not in "0123456789ABCDEF" for c in part):
                    raise ValueError(f"占位符格式非法（须大写十六进制）：{{{{{body}}}}}")
                pending.append(int(part, 16))
            i = j + 2
            continue
        if pending:
            out.append(pending.decode("utf-8", "strict"))
            pending = bytearray()
        out.append(s[i])
        i += 1
    if pending:
        out.append(pending.decode("utf-8", "strict"))
    return "".join(out)


# ----------------------------------------------------------------------
# ASM 投影（确定性渲染：同一 IR → 逐字节相同输出）
# ----------------------------------------------------------------------

_BLK_HINT = {
    0: "close", 1: "open", 2: "next", 4: "sub4", 5: "sub5", 7: "sub7",
    9: "sub9", 12: "sub12", 13: "sub13", 14: "sub14",
}


def _fmt_str(tok: mwb.Token) -> str:
    return '"%s"' % escape_text(tok.text.decode("utf-8", "replace")).replace('"', '{{22}}')


def render_asm(doc: MwbDocument) -> str:
    """全量反汇编。地址空间 100% 覆盖：每个 token 一行，行首为其载荷内偏移。"""
    lines: list[str] = []
    ap = lines.append

    ap("; moacode.mwb 全量反汇编（MOA 引擎 / Astronauts）")
    ap('.dialect  "%s" schema "%s"' % (DIALECT["engine_id"], DIALECT["schema_version"]))
    ap('.tool     "disassembler.py" version "%s" ir "%s"' % (TOOL_VERSION, IR_VERSION))
    ap('.encoding "%s"' % DIALECT["source_encoding"])
    ap('.endian   "%s"   ; token 参数；ZMOA 头为 little' % DIALECT["endianness"])
    ap(".tier     \"T2\"   ; token 流完全切分 + 语句/参数锚点已解析")
    ap('.source   sha256=%s size=%d' % (doc.src_sha256, len(doc.raw)))
    ap('.payload  sha256=%s size=%d version=%d'
       % (doc.payload_sha256, len(doc.payload), doc.version))
    ap(".stats    tokens=%d statements=%d strings=%d functions=%d"
       % (len(doc.tokens), len(doc.statements),
          sum(1 for t in doc.tokens if t.tag == TAG_STR), len(doc.fn_table)))
    ap("")

    # 语句归属
    n = len(doc.tokens)
    owner = [-1] * n
    for s in doc.statements:
        for k in range(s.tok_start, s.tok_end + 1):
            owner[k] = s.index

    # 文本条目索引（idx 注释，供双行文件交叉引用）
    text_idx = {e.tok_index: e for e in doc.texts}

    first_code_tok = doc.statements[0].tok_start if doc.statements else n

    ap(";; ==================================================================")
    ap(";; 区域 R_HEADER — 标签表与内建函数表（token %d..%d）" % (0, first_code_tok - 1))
    ap(";;   标签表项：STR(label) INT(line) INT(0) STR(file) INT(kind)")
    ap(";;   函数表项：STR(name)  INT(id)   INT(-1) INT(1)")
    ap(";; ==================================================================")
    ap("")
    ap("R_HEADER:")

    cur_stmt = -1
    for i, t in enumerate(doc.tokens):
        if i == first_code_tok:
            ap("")
            ap(";; ==================================================================")
            ap(";; 区域 R_CODE — 语句流（token %d..%d，共 %d 条语句）"
               % (first_code_tok, n - 1, len(doc.statements)))
            ap(";; 语句 = REF(id) [STR(name)] (P15 a)(P06 k)[STR v]… [MARK BLK]… END(0)")
            ap(";; ==================================================================")
            ap("")

        s_index = owner[i]
        if s_index != cur_stmt and s_index >= 0:
            cur_stmt = s_index
            s = doc.statements[s_index]
            ap("")
            fn = s.fn_name or ("cmd_%d" % s.ref_id)
            ap("stmt_%06d:                    ; %s  id=%d  @%#08x"
               % (s.index, fn, s.ref_id, s.offset))

        e = text_idx.get(i)
        note = ""
        if e is not None and e.tag != "misc":
            note = "   ; idx=%08d tag=%s" % (e.idx, e.tag)
        elif e is not None:
            note = "   ; idx=%08d" % e.idx

        pre = "%08x  " % t.offset
        if t.tag == TAG_STR:
            ap("%s    .string  sid=%d %s%s" % (pre, i, _fmt_str(t), note))
        elif t.tag == TAG_REF:
            nm = doc.fn_table.get(t.arg)
            cmt = "   ; %s" % nm if nm else ""
            ap("%s    REF      %d%s" % (pre, t.arg, cmt or note))
        elif t.tag == TAG_REFE:
            ap("%s    REFE     %#06x                ; 标签引导" % (pre, t.arg))
        elif t.tag == TAG_INT:
            ap("%s    INT      %d" % (pre, t.arg))
        elif t.tag == TAG_P15:
            ap("%s    P15      %d" % (pre, t.arg))
        elif t.tag == TAG_P06:
            pname = DIALECT["param_ids"].get(t.arg)
            ap("%s    P06      %d%s" % (pre, t.arg, "   ; %s" % pname if pname else ""))
        elif t.tag == TAG_END:
            ap("%s    END      %d" % (pre, t.arg))
        elif t.tag == TAG_MARK:
            ap("%s    MARK" % pre)
        elif t.tag == TAG_BLK:
            hint = _BLK_HINT.get(t.arg)
            ap("%s    BLK      %d%s" % (pre, t.arg, "   ; %s" % hint if hint else ""))
        else:
            raise mwb.MwbError(f"渲染遇到未知 token {t.tag:#02x} @{t.offset:#x}")

    ap("")
    ap("; 反汇编结束：%d token，字节覆盖 %d/%d"
       % (len(doc.tokens), *doc.byte_coverage()))
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------
# 双行文本投影
# ----------------------------------------------------------------------

def _render_entries(doc: MwbDocument, entries: list, scope: str,
                    chapter: mwb.Chapter | None = None) -> str:
    lines: list[str] = []
    ap = lines.append
    ap("# TEXT/2 ir=%s tool=%s src_sha256=%s" % (IR_VERSION, TOOL_VERSION, doc.src_sha256))
    ap("# encoding source=%s target=%s file=utf-8"
       % (DIALECT["source_encoding"], DIALECT["text_export"]["target_encoding"]))
    ap("# scope kind=%s range=%s part=1/1"
       % (scope, chapter.name if chapter else "ALL"))
    ap("# tags name msg choice label ui system ruby misc")
    if chapter is not None:
        ap("# chapter index=%d name=%s src=%s stmt=%d..%d"
           % (chapter.index, chapter.name, chapter.src_file,
              chapter.stmt_start, chapter.stmt_end))
    ap("#")
    for e in entries:
        meta = "# idx=%08d off=%#010x tag=%s" % (e.idx, e.offset, e.tag)
        if e.speaker:
            meta += " speaker=%s" % e.speaker
        if e.voice:
            meta += " voice=%s" % e.voice
        if len(e.pages) > 1:
            meta += " pages=%d" % len(e.pages)
        ap(meta)
        body = escape_text(e.source, page_break=(e.tag == "msg"))
        ap("○%08d○%s○%s" % (e.idx, e.tag, body))
        ap("●%08d●%s●%s" % (e.idx, e.tag, body))
        ap("")
    return "\n".join(lines) + "\n"


def render_texts(doc: MwbDocument, only_translatable: bool = True) -> str:
    """整份导出（单文件）。"""
    entries = [e for e in doc.texts
               if (not only_translatable) or e.policy == "translatable"]
    return _render_entries(doc, entries,
                           "translatable" if only_translatable else "all")


def render_texts_by_chapter(doc: MwbDocument, only_translatable: bool = True
                            ) -> list[tuple[str, str]]:
    """按剧情分段导出。返回 [(文件名, 内容)]，文件名取自源脚本名。

    分界点为 `go <章节名>` 语句（见 mwb._build_chapters）。分界之前的条目
    （宏定义区等）归入 `_00_prologue.txt`，不丢弃。
    """
    scope = "translatable" if only_translatable else "all"
    buckets: dict[int, list] = {}
    for e in doc.texts:
        if only_translatable and e.policy != "translatable":
            continue
        buckets.setdefault(e.chapter, []).append(e)

    out: list[tuple[str, str]] = []
    if -1 in buckets:
        out.append(("_00_prologue.txt",
                    _render_entries(doc, buckets[-1], scope)))
    seen: dict[str, int] = {}
    for c in doc.chapters:
        items = buckets.get(c.index)
        if not items:
            continue
        stem = Path(c.src_file).stem
        # 同名重复（スタッフロール 出现 3 次）→ 追加序号，避免互相覆盖
        seen[stem] = seen.get(stem, 0) + 1
        name = f"{c.index + 1:02d}_{stem}.txt" if seen[stem] == 1 else \
               f"{c.index + 1:02d}_{stem}_{seen[stem]}.txt"
        out.append((name, _render_entries(doc, items, scope, c)))
    return out


# ----------------------------------------------------------------------
# 覆盖证书
# ----------------------------------------------------------------------

def coverage_certificate(doc: MwbDocument, roundtrip_ok: bool) -> dict:
    covered, total = doc.byte_coverage()
    from collections import Counter
    kinds = Counter(t.kind for t in doc.tokens)
    tags = Counter(e.tag for e in doc.texts)
    tsrc = Counter(e.tag_source for e in doc.texts)
    first_code = doc.statements[0].tok_start if doc.statements else 0
    hdr_bytes = sum(t.size for t in doc.tokens[:first_code])
    return {
        "schema_version": "1.1.0",
        "source": {"path": str(doc.path), "sha256": doc.src_sha256, "size": len(doc.raw)},
        "layers": [
            {"id": "L000", "algorithm": "zmoa-header", "reversible": True,
             "input_size": len(doc.raw), "output_size": len(doc.raw) - mwb.ZMOA_HEADER_SIZE},
            {"id": "L001", "algorithm": "zlib", "reversible": True,
             "input_size": len(doc.raw) - mwb.ZMOA_HEADER_SIZE,
             "output_size": len(doc.payload), "output_sha256": doc.payload_sha256},
        ],
        "intervals": [
            {"id": "R_HEADER", "layer_id": "L001", "start": 0, "end": hdr_bytes,
             "status": "decoded", "kind": "label-and-function-table", "decode_tier": "T2",
             "tier_evidence_refs": ["EV_TOKEN_COVERAGE", "EV_FN_TABLE"]},
            {"id": "R_CODE", "layer_id": "L001", "start": hdr_bytes, "end": total,
             "status": "decoded", "kind": "statement-stream", "decode_tier": "T2",
             "tier_evidence_refs": ["EV_TOKEN_COVERAGE", "EV_STATEMENT_MODEL"]},
        ],
        "gaps": [], "overlaps": [],
        "byte_coverage": covered / total if total else 0.0,
        "structural_coverage": 1.0,
        "tier_coverage": {"T0": 0, "T1": 0, "T2": total, "T3": 0, "T4": 0},
        "min_tier": "T2",
        "declared_capabilities": ["roundtrip", "in_place", "pointer-rewrite"],
        "tier_blocked": [],
        "instruction_coverage": "not_applicable",
        "token_kinds": dict(sorted(kinds.items())),
        "statements": len(doc.statements),
        "functions": len(doc.fn_table),
        "text_tag_counts": dict(sorted(tags.items())),
        "tag_source_counts": dict(sorted(tsrc.items())),
        "translatable": sum(1 for e in doc.texts if e.policy == "translatable"),
        "frozen": sum(1 for e in doc.texts if e.policy == "frozen"),
        "roundtrip": {"zero_edit_identical": roundtrip_ok},
        "toolchain": {"tool": "disassembler.py", "version": TOOL_VERSION,
                      "ir": IR_VERSION, "dialect": DIALECT["engine_id"]},
    }


# ----------------------------------------------------------------------
# 输入解析：接受 .gxp 或 .mwb
# ----------------------------------------------------------------------

def load_source(path: str | Path, entry_hint: str = "moacode.mwb"):
    """返回 (doc, gxp_archive|None, gxp_entry_name|None)。"""
    path = Path(path)
    raw = path.read_bytes()
    if raw[:4] == gxp.MAGIC:
        arc = gxp.read_archive(path)
        ent = None
        for e in arc.entries:
            if e.name.replace("\\", "/").endswith(entry_hint):
                ent = e
                break
        if ent is None:
            for e in arc.entries:
                if (e.data or b"")[:4] == mwb.ZMOA_MAGIC:
                    ent = e
                    break
        if ent is None:
            raise mwb.MwbError(f"归档内未找到 {entry_hint}：{path}")
        doc = mwb.parse(Path(ent.name), raw=ent.data)
        return doc, arc, ent.name
    if raw[:4] == mwb.ZMOA_MAGIC:
        return mwb.parse(path, raw=raw), None, None
    raise mwb.MwbError(f"无法识别的输入（既非 GXP 也非 ZMOA）：{path}")


# ----------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------

def _chapter_index(doc: MwbDocument, files: list[tuple[str, str]]) -> str:
    """只读总览：文件 → 章节 → 源脚本 → 条目数。不是导入源。"""
    counts = {}
    for e in doc.texts:
        if e.policy == "translatable":
            counts[e.chapter] = counts.get(e.chapter, 0) + 1
    rows = ["# 文件\t章节\t源脚本\t语句范围\t条目数"]
    by_index = {c.index: c for c in doc.chapters}
    for name, _text in files:
        if name.startswith("_00_"):
            rows.append("%s\t(分界前)\t-\t-\t%d" % (name, counts.get(-1, 0)))
            continue
        idx = int(name.split("_", 1)[0]) - 1
        c = by_index.get(idx)
        if c:
            rows.append("%s\t%s\t%s\t%d..%d\t%d"
                        % (name, c.name, c.src_file, c.stmt_start, c.stmt_end,
                           counts.get(c.index, 0)))
    return "\n".join(rows) + "\n"


def run(input_path: str | Path, out_dir: str | Path | None = None,
        want_texts: bool = True, want_asm: bool = False,
        with_ir: bool = False, all_texts: bool = False,
        by_chapter: bool = True, progress=None) -> dict:
    inp = Path(input_path)
    if out_dir is None:
        out_dir = inp.parent / (inp.stem + "_text")
    out = Path(out_dir)

    def say(msg):
        if progress:
            progress(msg)

    say("正在解析 %s …" % inp.name)
    doc, arc, entry_name = load_source(inp)

    # 内部门禁：零编辑往返（无论勾选什么都执行）
    say("零编辑往返自检 …")
    rebuilt_payload = mwb.rebuild_payload(doc)
    roundtrip_ok = rebuilt_payload == doc.payload
    if not roundtrip_ok:
        raise mwb.MwbError("零编辑往返失败：token 流重建与源载荷不一致")
    rebuilt_mwb = mwb.serialize(doc)
    # zlib 参数可能与原始不同，故只校验解压后一致（下面的 cert 记录该事实）
    if mwb.parse(doc.path, raw=rebuilt_mwb).payload != doc.payload:
        raise mwb.MwbError("零编辑重建的 .mwb 解压后与源载荷不一致")

    work = out / "_work"
    (work / "reports").mkdir(parents=True, exist_ok=True)

    result = {"source": str(inp), "out_dir": str(out), "texts": None, "asm": None,
              "entries": len(doc.texts),
              "translatable": sum(1 for e in doc.texts if e.policy == "translatable"),
              "roundtrip": roundtrip_ok}

    stem = Path(entry_name).name if entry_name else inp.name

    if want_texts:
        td = out / "texts"
        td.mkdir(parents=True, exist_ok=True)
        if by_chapter and doc.chapters:
            say("按剧情分段导出（%d 段）…" % len(doc.chapters))
            files = render_texts_by_chapter(doc, only_translatable=not all_texts)
            for name, text in files:
                _atomic_write_text(td / name, text)
            _atomic_write_text(td / "_index.tsv", _chapter_index(doc, files))
            result["texts"] = str(td)
            result["text_files"] = len(files)
        else:
            say("导出双行文本 …")
            p = td / (stem + ".txt")
            _atomic_write_text(p, render_texts(doc, only_translatable=not all_texts))
            result["texts"] = str(p)
            result["text_files"] = 1

    if want_asm:
        say("渲染 ASM 清单 …")
        ad = out / "asm"
        ad.mkdir(parents=True, exist_ok=True)
        p = ad / (stem + ".asm.txt")
        _atomic_write_text(p, render_asm(doc))
        result["asm"] = str(p)

    if arc is not None:
        say("解包 GXP 条目 …")
        ed = out / "extracted"
        gxp.unpack(inp, ed)
        result["extracted"] = str(ed)

    cert = coverage_certificate(doc, roundtrip_ok)
    _atomic_write_text(work / "reports" / "coverage_certificate.json",
                       json.dumps(cert, ensure_ascii=False, indent=2))
    _atomic_write_text(work / "reports" / "extract_report.json",
                       json.dumps({
                           "text_tag_counts": cert["text_tag_counts"],
                           "tag_source_counts": cert["tag_source_counts"],
                           "translatable": cert["translatable"],
                           "frozen": cert["frozen"],
                           "statements": cert["statements"],
                           "container_string_objects":
                               sum(1 for t in doc.tokens if t.tag == TAG_STR),
                       }, ensure_ascii=False, indent=2))
    result["certificate"] = str(work / "reports" / "coverage_certificate.json")

    if with_ir:
        say("导出 IR …")
        _dump_ir(doc, work / "ir")
        result["ir"] = str(work / "ir")

    say("完成")
    return result


def _atomic_write_text(path: Path, text: str, encoding: str | None = None) -> None:
    """原子写入。默认 UTF-8；.txt 编辑面带 BOM（记事本友好），报告不带。"""
    if encoding is None:
        encoding = TEXT_FILE_ENCODING if path.suffix == ".txt" else "utf-8"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding=encoding, newline="\n") as f:
        f.write(text)
        f.flush()
        import os
        os.fsync(f.fileno())
    tmp.replace(path)


def _dump_ir(doc: MwbDocument, ir_dir: Path) -> None:
    ir_dir.mkdir(parents=True, exist_ok=True)
    src_id = doc.src_sha256[:12]
    (ir_dir / "manifest.jsonl").write_text(
        json.dumps({"src_id": src_id, "path": str(doc.path), "sha256": doc.src_sha256,
                    "size": len(doc.raw), "payload_size": len(doc.payload),
                    "tokens": len(doc.tokens), "statements": len(doc.statements),
                    "texts": len(doc.texts), "tier": "T2"}, ensure_ascii=False) + "\n",
        encoding="utf-8")
    with open(ir_dir / "tokens.jsonl", "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(json.dumps({
            "src_id": src_id, "i": i, "kind": t.kind, "off": t.offset,
            "size": t.size, "arg": t.arg,
            **({"text": t.text.decode("utf-8", "replace")} if t.tag == TAG_STR else {}),
        }, ensure_ascii=False) for i, t in enumerate(doc.tokens)))
        f.write("\n")
    with open(ir_dir / "statements.jsonl", "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(json.dumps({
            "src_id": src_id, "index": s.index, "ref_id": s.ref_id, "fn": s.fn_name,
            "off": s.offset, "tok_start": s.tok_start, "tok_end": s.tok_end,
        }, ensure_ascii=False) for s in doc.statements))
        f.write("\n")
    with open(ir_dir / "text_entries.jsonl", "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(json.dumps({
            "src_id": src_id, "idx": e.idx, "tok_index": e.tok_index, "off": e.offset,
            "tag": e.tag, "policy": e.policy, "tag_source": e.tag_source,
            "source": e.source, "speaker": e.speaker, "voice": e.voice, "fn": e.stmt_fn,
        }, ensure_ascii=False) for e in doc.texts))
        f.write("\n")


def main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="disassembler.py",
        description="moacode.mwb 全量反汇编与文本导出（支持直接拖入 bincode.gxp）")
    ap.add_argument("input", nargs="+", help="bincode.gxp 或 moacode.mwb")
    ap.add_argument("-o", "--out", default=None, help="输出目录（默认 <输入名>_text）")
    ap.add_argument("--no-texts", action="store_true", help="不导出双行文本")
    ap.add_argument("--asm", action="store_true", help="同时导出 ASM 清单")
    ap.add_argument("--all-texts", action="store_true",
                    help="双行文本包含 frozen 条目（默认仅 translatable）")
    ap.add_argument("--single-file", action="store_true",
                    help="导出成一个大文件（默认按剧情分段，一段一个 txt）")
    ap.add_argument("--with-ir", action="store_true", help="额外落盘 IR（排查用）")
    a = ap.parse_args(argv)

    rc = 0
    for one in a.input:
        try:
            r = run(one, a.out, want_texts=not a.no_texts, want_asm=a.asm,
                    with_ir=a.with_ir, all_texts=a.all_texts,
                    by_chapter=not a.single_file,
                    progress=lambda m: print("  " + m))
            print(f"[ok] {one}")
            print(f"     条目 {r['entries']}（可翻译 {r['translatable']}）")
            if r["texts"]:
                n = r.get("text_files", 1)
                suffix = f"（{n} 个文件）" if n > 1 else ""
                print(f"     双行文本 {r['texts']}{suffix}")
            if r["asm"]:
                print(f"     ASM     {r['asm']}")
            print(f"     证书     {r['certificate']}")
        except Exception as exc:
            print(f"[失败] {one}: {exc}", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(argv))
