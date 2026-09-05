# -*- coding: utf-8 -*-
"""assembler.py — 把 texts/ 与 asm/ 的改动回封成 .mwb，并可重打包成 GXP。

不解析完整 ASM 语法：重新解析源二进制得到内存 IR，各自渲染一份**新鲜投影**，
与用户文件做 diff，只取实际改动的行（§2.6）。两面改同一条且取值不同 → 拒绝。

命令行：

    python assembler.py <bincode.gxp 或 moacode.mwb> --from <文本目录>
                        [-o 输出目录] [--gxp-name 自定义名.gxp] [--dry-run]

拖放：把 texts 目录（或其父目录 <输入名>_text）拖到本文件图标上。
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import gxp
import mwb
import disassembler as dis
from disassembler import escape_text, unescape_text
from opcodelist import DIALECT

RE_SRC = re.compile(r"^○(?P<idx>\d{8})○(?P<tag>[a-z_]+)○(?P<text>.*)$")
RE_TGT = re.compile(r"^●(?P<idx>\d{8})●(?P<tag>[a-z_]+)●(?P<text>.*)$")
RE_HDR = re.compile(r"^# TEXT/(?P<ver>\d+)\s+ir=(?P<ir>\S+)\s+tool=(?P<tool>\S+)\s+"
                    r"src_sha256=(?P<sha>[0-9a-f]{64})\s*$")
RE_SCOPE = re.compile(r"^# scope kind=(?P<kind>\S+) range=(?P<range>\S+) "
                      r"part=(?P<cur>\d+)/(?P<tot>\d+)\s*$")
RE_ASM_STR = re.compile(r"^(?P<off>[0-9a-f]{8})\s+\.string\s+sid=(?P<sid>\d+)\s+"
                        r'"(?P<body>.*)"(?:\s+;.*)?$')


class ImportError_(Exception):
    """导入校验失败（列出精确位置）。"""


# 一个 msg 页块的框架开销：MARK(1) + BLK(5) + P15(5) + P06(5) + STR 头尾(6) = 22
_PAGE_BLOCK_OVERHEAD = 1 + 5 + 5 + 5 + 6


@dataclass
class EditSet:
    """一个编辑面的改动集合：{tok_index: 新文本}。"""
    edits: dict[int, str] = field(default_factory=dict)
    source: str = ""
    stats: dict = field(default_factory=dict)


# ----------------------------------------------------------------------
# 双行文本导入（§4.9 全部 13 条校验）
# ----------------------------------------------------------------------

def load_text_edits(doc: mwb.MwbDocument, paths: list[Path]) -> EditSet:
    by_idx = {e.idx: e for e in doc.texts}
    es = EditSet(source="texts")
    parts_seen: dict[int, set[int]] = {}
    total_entries = changed = unchanged = 0

    for path in paths:
        raw = path.read_text(encoding="utf-8-sig")
        lines = raw.split("\n")
        # 1/2 文件头与哈希
        m = RE_HDR.match(lines[0]) if lines else None
        if not m:
            raise ImportError_(f"{path}: 缺少 TEXT/2 文件头")
        if m.group("sha") != doc.src_sha256:
            raise ImportError_(
                f"{path}: src_sha256 与当前源不匹配（文件 {m.group('sha')[:16]}… "
                f"vs 源 {doc.src_sha256[:16]}…）——可能用了旧版译文")
        if m.group("ir") != dis.IR_VERSION:
            raise ImportError_(f"{path}: IR 版本不兼容（{m.group('ir')}）")
        # 3 分片
        scope = None
        for ln in lines[1:5]:
            sm = RE_SCOPE.match(ln)
            if sm:
                scope = sm
                break
        if scope is None:
            raise ImportError_(f"{path}: 缺少 scope 行")
        tot = int(scope.group("tot"))
        cur = int(scope.group("cur"))
        parts_seen.setdefault(tot, set()).add(cur)

        i = 0
        n = len(lines)
        while i < n:
            ln = lines[i]
            if not ln.startswith("○"):
                # 6 分隔符混用检查
                if ln.startswith("●"):
                    raise ImportError_(f"{path}:{i+1}: 译文行前缺少对应的原文行")
                i += 1
                continue
            ms = RE_SRC.match(ln)
            if not ms:
                raise ImportError_(f"{path}:{i+1}: 原文行格式非法（分隔符或 idx 宽度）")
            if i + 1 >= n:
                raise ImportError_(f"{path}:{i+1}: 原文行之后缺少译文行")
            mt = RE_TGT.match(lines[i + 1])
            if not mt:
                raise ImportError_(f"{path}:{i+2}: 译文行格式非法（分隔符或 idx 宽度）")
            # 4/5 idx 与 tag 一致
            if ms.group("idx") != mt.group("idx"):
                raise ImportError_(f"{path}:{i+2}: idx 不一致 "
                                   f"({ms.group('idx')} vs {mt.group('idx')})")
            if ms.group("tag") != mt.group("tag"):
                raise ImportError_(f"{path}:{i+2}: tag 不一致 "
                                   f"({ms.group('tag')} vs {mt.group('tag')})")
            idx = int(ms.group("idx"))
            entry = by_idx.get(idx)
            if entry is None:
                raise ImportError_(f"{path}:{i+1}: idx={idx:08d} 不存在于该源")
            if entry.tag != ms.group("tag"):
                raise ImportError_(f"{path}:{i+1}: idx={idx:08d} tag 与 IR 不符 "
                                   f"（文件 {ms.group('tag')} vs IR {entry.tag}）")
            # 7 原文行逐字符校验（转义方式须与导出侧一致）
            pb = (entry.tag == "msg")
            want = escape_text(entry.source, page_break=pb)
            if ms.group("text") != want:
                raise ImportError_(
                    f"{path}:{i+1}: idx={idx:08d} 原文行被修改\n"
                    f"    IR ：{want}\n    文件：{ms.group('text')}")
            # 13 译文行非空
            tgt_raw = mt.group("text")
            if tgt_raw == "":
                raise ImportError_(f"{path}:{i+2}: idx={idx:08d} 译文行为空"
                                   f"（内容被误删；未翻译应保留原文）")
            # 11 占位符与换页标记
            try:
                new_val = unescape_text(tgt_raw, page_break=pb)
            except ValueError as exc:
                raise ImportError_(f"{path}:{i+2}: idx={idx:08d} 占位符错误：{exc}")
            total_entries += 1
            if new_val == entry.source:
                unchanged += 1
            else:
                # 8 frozen 不得改动
                if entry.policy == "frozen":
                    raise ImportError_(f"{path}:{i+2}: idx={idx:08d} 该条为 frozen"
                                       f"（{entry.tag}），不允许修改")
                # 9 目标编码可表示性
                tenc = DIALECT["text_export"]["target_encoding"]
                try:
                    new_val.encode(tenc)
                except UnicodeEncodeError as exc:
                    bad = new_val[exc.start:exc.end]
                    raise ImportError_(
                        f"{path}:{i+2}: idx={idx:08d} 译文编码 {tenc} 无法表示"
                        f"『{bad}』，改用 utf-8 试试")
                changed += 1
                es.edits[entry.tok_index] = new_val
            i += 2
    # 3 分片完整
    for tot, seen in parts_seen.items():
        if len(seen) != tot:
            missing = sorted(set(range(1, tot + 1)) - seen)
            raise ImportError_(f"分片不完整：共 {tot} 片，缺 {missing}")

    es.stats = {"entries": total_entries, "changed": changed, "unchanged": unchanged}
    return es


# ----------------------------------------------------------------------
# ASM 导入：对新鲜投影做 diff，只解析改动的 .string 行
# ----------------------------------------------------------------------

def _semantic_line(s: str) -> str:
    """去掉注释后的可比较内容。

    注释不是可编辑内容：工具版本升级时注释文字可能变化（实测：param_ids 命名调整
    使 74629 行注释改变），若把注释差异算作结构改动，未编辑的旧清单会被整份拒绝。
    """
    m = RE_ASM_STR.match(s)
    if m:
        return "%s .string sid=%s \"%s\"" % (m.group("off"), m.group("sid"), m.group("body"))
    i = s.find(";")
    return s[:i].rstrip() if i >= 0 else s.rstrip()


def load_asm_edits(doc: mwb.MwbDocument, path: Path) -> EditSet:
    es = EditSet(source="asm")
    fresh = dis.render_asm(doc).split("\n")
    user = path.read_text(encoding="utf-8-sig").split("\n")
    if len(fresh) != len(user):
        raise ImportError_(
            f"{path}: 行数与新鲜投影不符（{len(user)} vs {len(fresh)}）——"
            f"ASM 编辑面不支持增删行（结构改动需 T3）")
    struct_changes = 0
    for lineno, (a, b) in enumerate(zip(fresh, user), start=1):
        if a == b or _semantic_line(a) == _semantic_line(b):
            continue
        ma, mb = RE_ASM_STR.match(a), RE_ASM_STR.match(b)
        if not (ma and mb):
            struct_changes += 1
            continue
        if ma.group("sid") != mb.group("sid") or ma.group("off") != mb.group("off"):
            struct_changes += 1
            continue
        sid = int(mb.group("sid"))
        tok = doc.tokens[sid]
        if tok.tag != mwb.TAG_STR:
            raise ImportError_(f"{path}:{lineno}: sid={sid} 不是字符串 token")
        body = mb.group("body")
        try:
            new_val = unescape_text(body.replace('{{22}}', '"'))
        except ValueError as exc:
            raise ImportError_(f"{path}:{lineno}: 占位符错误：{exc}")
        es.edits[sid] = new_val
    if struct_changes:
        raise ImportError_(
            f"{path}: 检出 {struct_changes} 处结构改动（非字符串行）。"
            f"改写指令或数据需要 T3 指令级理解，当前申报 T2 —— 拒绝执行，不产出损坏文件。")
    es.stats = {"changed": len(es.edits)}
    return es


# ----------------------------------------------------------------------
# 冲突检出与策略协商
# ----------------------------------------------------------------------

def merge_edits(doc: mwb.MwbDocument, text_es: EditSet | None,
                asm_es: EditSet | None) -> dict[int, str]:
    t = text_es.edits if text_es else {}
    a = asm_es.edits if asm_es else {}
    both = set(t) & set(a)
    conflicts = [(k, t[k], a[k]) for k in sorted(both) if t[k] != a[k]]
    if conflicts:
        idx_of = {e.tok_index: e.idx for e in doc.texts}
        msg = ["两个编辑面对同一条给出不同取值（拒绝执行）："]
        for k, tv, av in conflicts[:20]:
            msg.append(f"  idx={idx_of.get(k, -1):08d} sid={k}\n"
                       f"    texts: {tv}\n    asm  : {av}")
        if len(conflicts) > 20:
            msg.append(f"  …另有 {len(conflicts)-20} 处")
        raise ImportError_("\n".join(msg))
    merged = dict(a)
    merged.update(t)
    return merged


def probe_strategies(doc: mwb.MwbDocument, edits: dict[int, str]) -> list[dict]:
    """只读，无副作用。返回全部策略裁决。

    `in_place` 的适用条件是**编辑后占用字节数不超过原槽容量**。对多页 msg，
    "槽"是整个页块区间，容量须按页块框架（每页 22 字节）加页内字节计算——
    只比字符串长度会把"页数改变"误判为等长，从而选中 in_place。
    """
    verdicts = []
    tenc = DIALECT["text_export"]["target_encoding"]
    term = DIALECT["text_export"]["terminator_len"]
    by_tok = {e.tok_index: e for e in doc.texts}

    def new_size(sid: int, val: str) -> tuple[int, int]:
        """返回 (编辑后字节数, 原槽容量)。"""
        e = by_tok.get(sid)
        if e is not None and e.tag == "msg" and e.page_span is not None:
            new = sum(_PAGE_BLOCK_OVERHEAD + len(p.encode(tenc))
                      for p in val.split("\n"))
            return new, e.page_span[1] - e.page_span[0]
        return len(val.encode(tenc)) + term, doc.tokens[sid].arg + term

    over = []
    for sid, val in edits.items():
        n, cap = new_size(sid, val)
        if n != cap:                      # 长度变化（含页数变化）即不适用 in_place
            over.append(sid)

    verdicts.append({
        "strategy_id": "identity", "required_tier": "T1",
        "applicable": not edits,
        "reason_code": "OK" if not edits else "LENGTH_OVERFLOW",
        "blocking_refs": [] if not edits else [f"sid={s}" for s in list(edits)[:5]],
    })
    verdicts.append({
        "strategy_id": "in_place", "required_tier": "T2",
        "applicable": bool(edits) and not over,
        "reason_code": "OK" if (edits and not over) else
                       ("LENGTH_OVERFLOW" if over else "OK"),
        "blocking_refs": [f"sid={s}" for s in over[:5]],
    })
    verdicts.append({
        "strategy_id": "pointer-rewrite", "required_tier": "T2",
        "applicable": bool(edits),
        "reason_code": "OK",
        "estimated_deltas": {
            "ranges": len(edits),
            "bytes": sum(new_size(s, v)[0] - new_size(s, v)[1]
                         for s, v in edits.items()),
        },
    })
    verdicts.append({
        "strategy_id": "full-layout", "required_tier": "T3",
        "applicable": False, "reason_code": "TIER_TOO_LOW",
        "blocking_refs": ["R_CODE"],
    })
    return verdicts


_ORDER = ["identity", "in_place", "pointer-rewrite", "full-layout"]


def select_strategy(verdicts: list[dict]) -> str:
    for name in _ORDER:
        for v in verdicts:
            if v["strategy_id"] == name and v["applicable"]:
                return name
    raise ImportError_("没有可用的回封策略")


# ----------------------------------------------------------------------
# 回封与验证（§6.0.3）
# ----------------------------------------------------------------------

def _expected_strings(doc: mwb.MwbDocument, edits: dict[int, str]) -> list[str]:
    """回封后应当出现的完整字符串序列（按流内顺序）。

    多页 msg 条目按译文的 {{BR}} 分页展开，因此可校验页数变化后的结果。
    """
    by_tok = {e.tok_index: e for e in doc.texts}
    skip: set[int] = set()
    for e in doc.texts:
        for p in e.pages[1:]:
            skip.add(p)
    out: list[str] = []
    for i, t in enumerate(doc.tokens):
        if t.tag != mwb.TAG_STR or i in skip:
            continue
        e = by_tok.get(i)
        val = edits.get(i)
        if val is None:
            val = e.source if e is not None else t.text.decode("utf-8", "replace")
        if e is not None and e.tag == "msg" and e.page_span is not None:
            out.extend(val.split("\n"))
        else:
            out.append(val)
    return out


def repack(doc: mwb.MwbDocument, edits: dict[int, str]) -> tuple[bytes, dict]:
    new_payload = mwb.rebuild_payload(doc, edits)
    new_mwb = mwb.serialize(doc, edits)

    # 1 输出可被自身完整重新解析
    doc2 = mwb.parse(doc.path, raw=new_mwb)
    if doc2.payload != new_payload:
        raise ImportError_("重建校验失败：序列化载荷与预期不一致")
    # 2 覆盖仍为 1.0
    cov2, tot2 = doc2.byte_coverage()
    if cov2 != tot2:
        raise ImportError_(f"重建后字节覆盖不足：{cov2}/{tot2}")
    # 3 语句结构不变：条数与每条的函数绑定一致（页数变化不得影响语句划分）
    if len(doc2.statements) != len(doc.statements):
        raise ImportError_(f"语句数变化：{len(doc.statements)} → {len(doc2.statements)}")
    for s1, s2 in zip(doc.statements, doc2.statements):
        if s1.ref_id != s2.ref_id or s1.fn_name != s2.fn_name:
            raise ImportError_(
                f"语句 {s1.index} 绑定变化：{s1.fn_name}/{s1.ref_id} → {s2.fn_name}/{s2.ref_id}")
    # 4 token 数变化必须恰好由页数增减解释（每页 5 个 token）
    page_delta = 0
    by_tok = {e.tok_index: e for e in doc.texts}
    for sid, val in edits.items():
        e = by_tok.get(sid)
        if e is not None and e.tag == "msg" and e.page_span is not None:
            page_delta += len(val.split("\n")) - len(e.pages)
    tok_delta = len(doc2.tokens) - len(doc.tokens)
    if tok_delta != page_delta * 5:
        raise ImportError_(
            f"token 数变化无法解释：实际 {tok_delta:+d}，页数变化 {page_delta:+d} "
            f"应为 {page_delta * 5:+d}")
    # 5 字符串序列与预期完全一致（同时覆盖“编辑生效”与“未编辑不变”两项）
    expect_strs = _expected_strings(doc, edits)
    got_strs = [t.text.decode("utf-8", "replace")
                for t in doc2.tokens if t.tag == mwb.TAG_STR]
    if len(got_strs) != len(expect_strs):
        raise ImportError_(f"字符串条数不符：期望 {len(expect_strs)} 得到 {len(got_strs)}")
    for k, (a, b) in enumerate(zip(expect_strs, got_strs)):
        if a != b:
            raise ImportError_(f"第 {k} 个字符串不符：期望 {a!r} 得到 {b!r}")
    # 6 长度差可解释
    delta = len(new_payload) - len(doc.payload)
    expect_delta = 0
    for sid, val in edits.items():
        e = by_tok.get(sid)
        if e is not None and e.tag == "msg" and e.page_span is not None:
            old = e.page_span[1] - e.page_span[0]
            new = sum(_PAGE_BLOCK_OVERHEAD + len(p.encode("utf-8"))
                      for p in val.split("\n"))
            expect_delta += new - old
        else:
            expect_delta += len(val.encode("utf-8")) - doc.tokens[sid].arg
    if delta != expect_delta:
        raise ImportError_(f"长度差无法解释：实际 {delta} 期望 {expect_delta}")
    # 7 哈希语义（§6.0）
    if edits and new_payload == doc.payload:
        raise ImportError_("有编辑但载荷未变化 —— 编辑被静默丢弃")
    if not edits and new_payload != doc.payload:
        raise ImportError_("零编辑但载荷发生变化")

    report = {
        "edited_entries": len(edits),
        "payload_size_before": len(doc.payload),
        "payload_size_after": len(new_payload),
        "payload_delta": delta,
        "mwb_size_before": len(doc.raw),
        "mwb_size_after": len(new_mwb),
        "token_count_before": len(doc.tokens),
        "token_count_after": len(doc2.tokens),
        "page_delta": page_delta,
        "statements": len(doc2.statements),
        "reparse_ok": True,
        "byte_coverage_after": 1.0,
        "string_sequence_verified": True,
    }
    return new_mwb, report


# ----------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------

def run(input_path: str | Path, from_dir: str | Path,
        out_dir: str | Path | None = None, gxp_name: str | None = None,
        dry_run: bool = False, progress=None) -> dict:
    inp = Path(input_path)
    src = Path(from_dir)
    if out_dir is None:
        out_dir = inp.parent / (inp.stem + "_rebuilt")
    out = Path(out_dir)

    def say(m):
        if progress:
            progress(m)

    say("正在解析源 %s …" % inp.name)
    doc, arc, entry_name = dis.load_source(inp)

    # 零编辑往返自检（前置门禁）
    if mwb.rebuild_payload(doc) != doc.payload:
        raise ImportError_("零编辑往返自检失败：此文件暂不支持回封")

    stem = Path(entry_name).name if entry_name else inp.name

    tdir = src / "texts" if (src / "texts").is_dir() else src
    # 排除 _index.tsv 一类只读总览（后缀不同已排除，显式跳过以防将来改名）
    text_files = sorted(p for p in tdir.rglob("*.txt")
                        if p.is_file() and not p.name.startswith("_index"))
    text_es = None
    if text_files:
        say("读取双行文本（%d 个文件）…" % len(text_files))
        text_es = load_text_edits(doc, text_files)

    adir = src / "asm"
    asm_es = None
    if adir.is_dir():
        cands = sorted(adir.rglob("*.asm.txt"))
        if cands:
            say("比对 ASM 编辑面 …")
            # 本样本只有一个源工件，故只取第一个清单
            asm_es = load_asm_edits(doc, cands[0])

    if text_es is None and asm_es is None:
        raise ImportError_(f"{src}: 未找到 texts/*.txt 或 asm/*.asm.txt —— 请先输出文本")

    say("冲突检出 …")
    edits = merge_edits(doc, text_es, asm_es)

    verdicts = probe_strategies(doc, edits)
    strategy = select_strategy(verdicts)
    say("策略：%s（改动 %d 条）" % (strategy, len(edits)))

    result = {
        "source": str(inp), "from": str(src), "out_dir": str(out),
        "selected_strategy": strategy,
        "selection_rule": "minimum-capability-among-applicable",
        "verdicts": verdicts,
        "text_stats": text_es.stats if text_es else None,
        "asm_stats": asm_es.stats if asm_es else None,
        "edits": len(edits),
        "conflicts": 0,
        "dry_run": dry_run,
    }
    if dry_run:
        return result

    say("回封并验证 …")
    new_mwb, rep = repack(doc, edits)
    result["repack"] = rep

    out.mkdir(parents=True, exist_ok=True)
    tmp_dir = out / "_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    mwb_out = out / stem
    _atomic_write_bytes(mwb_out, new_mwb, tmp_dir)
    result["mwb"] = str(mwb_out)

    if arc is not None:
        name = gxp_name or inp.name
        if not name.lower().endswith(".gxp"):
            name += ".gxp"
        gxp_out = out / name
        say("重打包 GXP → %s …" % name)
        key = entry_name.replace("\\", "/")
        gxp.repack(inp, gxp_out, replacements={key: new_mwb})
        result["gxp"] = str(gxp_out)

    rdir = out / "_work" / "reports"
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / "repack_verdicts.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        tmp_dir.rmdir()
    except OSError:
        pass
    say("完成")
    return result


def _atomic_write_bytes(path: Path, data: bytes, tmp_dir: Path) -> None:
    tmp = tmp_dir / (path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp.replace(path)


def main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="assembler.py", description="把译文回封成 .mwb / .gxp")
    ap.add_argument("input", help="原 bincode.gxp 或 moacode.mwb")
    ap.add_argument("--from", dest="from_dir", required=True,
                    help="文本目录（含 texts/ 与可选 asm/）")
    ap.add_argument("-o", "--out", default=None, help="输出目录（默认 <输入名>_rebuilt）")
    ap.add_argument("--gxp-name", default=None,
                    help="重打包的 GXP 文件名（可自定义，默认与原名相同）")
    ap.add_argument("--dry-run", action="store_true", help="只预览，不写出")
    a = ap.parse_args(argv)

    try:
        r = run(a.input, a.from_dir, a.out, a.gxp_name, a.dry_run,
                progress=lambda m: print("  " + m))
    except ImportError_ as exc:
        print(f"[拒绝] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[失败] {exc}", file=sys.stderr)
        return 1

    print(f"[ok] 策略 {r['selected_strategy']}，改动 {r['edits']} 条")
    if r.get("text_stats"):
        s = r["text_stats"]
        print(f"     译文 {s['entries']} 条：已改 {s['changed']} / 未改 {s['unchanged']}")
    if r.get("repack"):
        p = r["repack"]
        print(f"     载荷 {p['payload_size_before']} → {p['payload_size_after']} "
              f"（{p['payload_delta']:+d} 字节）")
    if r.get("mwb"):
        print(f"     mwb  {r['mwb']}")
    if r.get("gxp"):
        print(f"     gxp  {r['gxp']}")
    if r["dry_run"]:
        print("     （dry-run，未写出任何文件）")
    return 0


if __name__ == "__main__":
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        sys.exit(2)
    # 拖放：单个目录参数 → 推断源归档
    if len(argv) == 1 and Path(argv[0]).is_dir():
        d = Path(argv[0])
        base = d.name[:-5] if d.name.endswith("_text") else d.name
        for cand in (d.parent / (base + ".gxp"), d.parent / base,
                     d.parent / "bincode.gxp"):
            if cand.is_file():
                argv = [str(cand), "--from", str(d)]
                break
    sys.exit(main(argv))
