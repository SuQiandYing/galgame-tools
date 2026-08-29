# -*- coding: utf-8 -*-
"""CatScene .cst 回封：双行文本 → IR → 重建二进制。

用法：
    python assembler.py <texts 目录或 .txt 文件> [...] [-o 输出目录]
    拖放：把 texts/ 或某个 .txt 拖到本文件图标上。

导入按 §4.9 的 12 条校验逐项执行，任一失败即拒绝整个文件——不静默接受、不部分应用。
回封按 §6.2 协商策略：对全部策略 probe，选能力最小者；run 失败不自动降级。
改写按站点不按值（§6.3）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
import opcodelist as D  # noqa: E402
import disassembler as DIS  # noqa: E402

_F = D.TEXT_FORMAT
_ORIG_RE = re.compile(_F["orig_re"])
_TRAN_RE = re.compile(_F["tran_re"])
_PH_RE = re.compile(_F["placeholder_re"])
_PH_LOOSE = re.compile(_F["placeholder_loose_re"])
_KV_RE = re.compile(_F["kv_re"])
_HDR1_RE = re.compile(_F["header1_re"])
_PART_RE = re.compile(_F["part_re"])


class ImportError_(DIS.CstError):
    """导入校验失败。message 里带 idx 与具体分歧，供界面直接显示。"""


# ---------------------------------------------------------------- 双行文本读取


@dataclass(slots=True)
class Pair:
    idx: int
    tag: str
    source: str
    target: str
    line_no: int
    meta: dict


@dataclass(slots=True)
class TextFile:
    path: Path
    header: dict
    encodings: dict
    scope: dict
    pairs: list[Pair]


def read_text_file(path: Path) -> TextFile:
    raw = path.read_bytes()
    enc = "utf-8-sig" if raw[:3] == b"\xef\xbb\xbf" else "utf-8"
    try:
        lines = raw.decode(enc).splitlines()
    except UnicodeDecodeError as exc:
        raise ImportError_(f"{path.name}: 文件不是 UTF-8：{exc}") from exc
    if len(lines) < 4:
        raise ImportError_(f"{path.name}: 文件头不足 4 行（HEADER_TRUNCATED）")
    m = _HDR1_RE.match(lines[0])
    if not m:
        raise ImportError_(f"{path.name}: 第 1 行不是 '# TEXT/N ...'（HEADER_LINE1）")
    header = dict(_KV_RE.findall(m.group("rest")))
    header["format_version"] = m.group("ver")
    for k in ("ir", "tool", "src_sha256"):
        if k not in header:
            raise ImportError_(f"{path.name}: 文件头缺 {k}=（HEADER_FIELD）")
    if not lines[1].startswith("# encoding"):
        raise ImportError_(f"{path.name}: 第 2 行不是 '# encoding ...'（HEADER_LINE2）")
    encodings = dict(_KV_RE.findall(lines[1]))
    for k in ("source", "target", "file"):
        if k not in encodings:
            raise ImportError_(f"{path.name}: 编码行缺 {k}=（HEADER_FIELD）")
    try:
        "x".encode(encodings["target"])
    except LookupError as exc:
        raise ImportError_(
            f"{path.name}: 译文编码 {encodings['target']} 不是可用的编码名") from exc
    if not lines[2].startswith("# scope"):
        raise ImportError_(f"{path.name}: 第 3 行不是 '# scope ...'（HEADER_LINE3）")
    scope = dict(_KV_RE.findall(lines[2]))
    if scope.get("kind") not in _F["scope_kinds"]:
        raise ImportError_(f"{path.name}: scope kind 非法（SCOPE_KIND）")
    part = scope.get("part", "1/1")
    pm = _PART_RE.fullmatch(part)
    if not pm or not (1 <= int(pm.group(1)) <= int(pm.group(2))):
        raise ImportError_(f"{path.name}: scope part={part} 非法（SCOPE_PART）")
    scope["part_index"], scope["part_total"] = int(pm.group(1)), int(pm.group(2))
    if not lines[3].startswith("# tags"):
        raise ImportError_(f"{path.name}: 第 4 行不是 '# tags ...'（HEADER_LINE4）")
    pairs = _read_pairs(path, lines)
    return TextFile(path, header, encodings, scope, pairs)


def _read_pairs(path: Path, lines: Sequence[str]) -> list[Pair]:
    pairs: list[Pair] = []
    seen: set[int] = set()
    pending: dict = {}
    i = 4
    om, tm = _F["orig_mark"], _F["tran_mark"]
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if line.startswith(_F["comment_prefix"]):
            pending = dict(_KV_RE.findall(line))
            i += 1
            continue
        mo = _ORIG_RE.match(line)
        if not mo:
            if line.startswith(tm):
                raise ImportError_(
                    f"{path.name}:{i + 1}: 出现孤立译文行（ORPHAN_TRANSLATION）")
            if line.startswith(om) or _PH_LOOSE.search(line):
                raise ImportError_(
                    f"{path.name}:{i + 1}: 分隔符混用或行内格式破损（SEPARATOR_MIXED）")
            raise ImportError_(f"{path.name}:{i + 1}: 无法解析的行（LINE_FORMAT）")
        if i + 1 >= len(lines):
            raise ImportError_(
                f"{path.name}:{i + 1}: 原文行之后缺译文行（MISSING_TRANSLATION）")
        nxt = lines[i + 1]
        mt = _TRAN_RE.match(nxt)
        if not mt:
            if nxt.startswith(om):
                raise ImportError_(
                    f"{path.name}:{i + 2}: 连续两行原文，缺译文（SEPARATOR_MIXED）")
            raise ImportError_(
                f"{path.name}:{i + 2}: 译文行格式错误（SEPARATOR_MIXED）")
        if mo.group("idx") != mt.group("idx"):
            raise ImportError_(
                f"{path.name}:{i + 1}: 原文 idx={mo.group('idx')} 与译文 "
                f"idx={mt.group('idx')} 不一致（IDX_MISMATCH）")
        if mo.group("tag") != mt.group("tag"):
            raise ImportError_(
                f"{path.name}:{i + 1}: 原文与译文 tag 不一致（TAG_MISMATCH）")
        if mo.group("tag") not in D.TAG_CLOSED_SET:
            raise ImportError_(
                f"{path.name}:{i + 1}: tag={mo.group('tag')} 不在闭集内（TAG_UNKNOWN）")
        idx = int(mo.group("idx"))
        if idx in seen:
            raise ImportError_(f"{path.name}:{i + 1}: idx={idx} 重复（IDX_DUPLICATE）")
        seen.add(idx)
        if pending:
            if "idx" in pending and int(pending["idx"]) != idx:
                raise ImportError_(
                    f"{path.name}:{i + 1}: 注释行 idx={pending['idx']} 与条目 "
                    f"idx={idx} 错配（META_DESYNC）")
            if "tag" in pending and pending["tag"] != mo.group("tag"):
                raise ImportError_(
                    f"{path.name}:{i + 1}: 注释行 tag 与条目 tag 错配（META_DESYNC）")
        pairs.append(Pair(idx, mo.group("tag"), mo.group("text"),
                          mt.group("text"), i + 1, pending))
        pending = {}
        i += 2
    return pairs


# ---------------------------------------------------------------- IR 载入


@dataclass(slots=True)
class Library:
    root: Path
    ir: Path
    job_sha256: str
    sources: list[dict]
    entries: dict[int, dict]
    by_src: dict[int, list[dict]]
    source_root: Path | None


def load_library(outdir: Path) -> Library:
    ir = outdir / "ir"
    mf = ir / "manifest.jsonl"
    if not mf.exists():
        raise ImportError_(f"找不到 {mf}，请先运行反汇编（IR_MISSING）")
    lines = [json.loads(x) for x in mf.read_text(encoding="utf-8").splitlines() if x]
    if not lines or lines[0].get("kind") != "job-anchor":
        raise ImportError_("manifest 首行不是作业锚，IR 不完整（IR_CORRUPT）")
    job = lines[0]
    sources = lines[1:]
    entries: dict[int, dict] = {}
    by_src: dict[int, list[dict]] = {}
    tp = ir / "text_entries.jsonl"
    if not tp.exists():
        raise ImportError_(f"找不到 {tp}（IR_MISSING）")
    for ln in tp.read_text(encoding="utf-8").splitlines():
        if not ln:
            continue
        e = json.loads(ln)
        if "idx" not in e:
            raise ImportError_("text_entries.jsonl 有条目缺 idx（IR_CORRUPT）")
        if e["idx"] in entries:
            raise ImportError_(f"IR 中 idx={e['idx']} 重复（IR_CORRUPT）")
        entries[e["idx"]] = e
        by_src.setdefault(e["src_id"], []).append(e)
    sroot = job.get("source_root")
    return Library(outdir, ir, job["sha256"], sources, entries, by_src,
                   Path(sroot) if sroot else None)


# ---------------------------------------------------------------- 导入校验


def _ph_bytes(t: str, path: Path, idx: int, which: str) -> list[int]:
    for m in _PH_LOOSE.finditer(t):
        if not _PH_RE.fullmatch(m.group(0)):
            raise ImportError_(
                f"{path.name} idx={idx}: {which}中占位符 {m.group(0)!r} 破损，"
                f"必须形如 {{{{0A}}}} 或 {{{{1B:40}}}}（大写十六进制，两位一字节）"
                f"（PLACEHOLDER_BROKEN）")
    out: list[int] = []
    for m in _PH_RE.finditer(t):
        out.extend(int(h, 16) for h in m.group(1).split(_F["placeholder_sep"]))
    return out


def encode_target(t: str, enc: str, path: Path, idx: int) -> bytes:
    """占位符按原始字节写出，其余按目标编码。不可表示即报出具体字符与候选编码。"""
    out = bytearray()
    pos = 0
    for m in _PH_RE.finditer(t):
        if m.start() > pos:
            out += _enc_chunk(t[pos:m.start()], enc, path, idx)
        out.extend(int(h, 16) for h in m.group(1).split(_F["placeholder_sep"]))
        pos = m.end()
    if pos < len(t):
        out += _enc_chunk(t[pos:], enc, path, idx)
    return bytes(out)


def _enc_chunk(chunk: str, enc: str, path: Path, idx: int) -> bytes:
    try:
        return chunk.encode(enc)
    except UnicodeEncodeError as exc:
        ch = chunk[exc.start:exc.start + 1]
        alts = [c for c in _F["encoding_candidates"] if _can(ch, c)]
        raise ImportError_(
            f"{path.name} idx={idx}: 译文编码 {enc} 无法表示『{ch}』，"
            f"换 {'/'.join(alts) if alts else '其他编码'} 试试"
            f"（ENCODING_UNREPRESENTABLE）") from exc


def _can(ch: str, enc: str) -> bool:
    try:
        ch.encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def validate(tf: TextFile, lib: Library) -> dict[int, bytes]:
    """§4.9 的 12 条按序全过才返回改写集。任一失败即拒绝整个文件。"""
    if tf.header["src_sha256"].lower() != lib.job_sha256.lower():
        raise ImportError_(
            f"{tf.path.name}: 文件头 src_sha256 与当前 IR 不匹配，"
            f"可能是用旧译文覆盖新 dump（SRC_HASH_MISMATCH）")
    if tf.header["ir"] != D.IR_VERSION:
        raise ImportError_(
            f"{tf.path.name}: IR 版本 {tf.header['ir']} 与本工具 {D.IR_VERSION} 不兼容")
    tenc = tf.encodings["target"]
    changes: dict[int, bytes] = {}
    for p in tf.pairs:
        e = lib.entries.get(p.idx)
        if e is None:
            raise ImportError_(
                f"{tf.path.name}:{p.line_no}: idx={p.idx} 不在 IR 中（IDX_UNKNOWN）")
        if e["tag"] != p.tag:
            raise ImportError_(
                f"{tf.path.name}:{p.line_no}: idx={p.idx} 的 tag={p.tag} 与 IR 的 "
                f"{e['tag']} 不一致（TAG_MISMATCH）")
        if p.source != e["source"]:
            raise ImportError_(
                f"{tf.path.name}:{p.line_no}: idx={p.idx} 原文行被改动，"
                f"IR 为 {e['source']!r}，文件为 {p.source!r}（SOURCE_ANCHOR）")
        pol = e["translate_policy"]
        if pol not in _F["policies"]:
            raise ImportError_(
                f"{tf.path.name}: idx={p.idx} 的 policy={pol} 未知（POLICY_UNKNOWN）")
        if pol == "frozen":
            if p.target != p.source:
                raise ImportError_(
                    f"{tf.path.name}:{p.line_no}: idx={p.idx} 被标为不可修改，"
                    f"译文行必须与原文行逐字符相同（FROZEN_MODIFIED）")
            continue
        if not p.target or p.target == p.source:
            continue
        src_ph = _ph_bytes(p.source, tf.path, p.idx, "原文")
        tgt_ph = _ph_bytes(p.target, tf.path, p.idx, "译文")
        if src_ph != tgt_ph:
            raise ImportError_(
                f"{tf.path.name}:{p.line_no}: idx={p.idx} 占位符集合与原文不一致，"
                f"原文 {src_ph}，译文 {tgt_ph}（PLACEHOLDER_BROKEN）")
        nb = encode_target(p.target, tenc, tf.path, p.idx)
        if pol == "length-locked" and len(nb) != e["raw_len"]:
            raise ImportError_(
                f"{tf.path.name}:{p.line_no}: idx={p.idx} 要求等长，原文占 "
                f"{e['raw_len']} 字节，译文 {len(nb)} 字节（LENGTH_LOCKED）")
        cap = e.get("slot_capacity")
        if cap is not None and len(nb) > cap:
            raise ImportError_(
                f"{tf.path.name}:{p.line_no}: idx={p.idx} 译文超长 {len(nb) - cap} "
                f"字节，槽位容量 {cap}（LENGTH_OVERFLOW）")
        changes[p.idx] = nb
    return changes


# ---------------------------------------------------------------- 回封策略


@dataclass(slots=True)
class ProbeVerdict:
    strategy_id: str
    required_tier: str
    applicable: bool
    reason_code: str
    reason_detail: str
    blocking_refs: list[str]
    estimated_deltas: dict


_STRATEGY_ORDER = ("identity", "in_place", "pointer-rewrite", "full-layout")


def _verdict_dict(v: ProbeVerdict) -> dict:
    return {"strategy_id": v.strategy_id, "required_tier": v.required_tier,
            "applicable": v.applicable, "reason_code": v.reason_code,
            "reason_detail": v.reason_detail, "blocking_refs": v.blocking_refs,
            "estimated_deltas": v.estimated_deltas}


def probe_all(doc: DIS.Doc, changes: dict[int, bytes],
              entries: dict[int, dict]) -> list[ProbeVerdict]:
    """只读、无副作用（§6.1），因此可安全地对全部策略批量调用。"""
    tier = D.TIERS["min_tier"]
    delta = 0
    over: list[str] = []
    for idx, nb in changes.items():
        e = entries[idx]
        d = len(nb) - e["raw_len"]
        delta += d
        if d > 0:
            over.append(f"idx={idx:08d}")
    out = []
    for sid in _STRATEGY_ORDER:
        need = {"identity": "T1", "in_place": "T2",
                "pointer-rewrite": "T2", "full-layout": "T3"}[sid]
        if _tier_lt(tier, need):
            out.append(ProbeVerdict(sid, need, False, "TIER_TOO_LOW",
                                    f"本样本申报 {tier}，该策略需要 {need}",
                                    ["R_RECORD_STREAM"], {}))
            continue
        if sid == "identity":
            ok = not changes
            out.append(ProbeVerdict(
                sid, need, ok, "OK" if ok else "LENGTH_OVERFLOW",
                "无编辑" if ok else f"有 {len(changes)} 条编辑，identity 不允许任何变化",
                [] if ok else [f"idx={i:08d}" for i in sorted(changes)][:20],
                {"ranges": 0, "bytes": 0}))
        elif sid == "in_place":
            ok = not over
            out.append(ProbeVerdict(
                sid, need, ok, "OK" if ok else "LENGTH_OVERFLOW",
                "全部编辑不超过原槽容量" if ok
                else f"{len(over)} 条译文长于原文，原地回封会越界",
                over[:20], {"ranges": len(changes), "bytes": delta}))
        elif sid == "pointer-rewrite":
            out.append(ProbeVerdict(
                sid, need, True, "OK",
                "全部引用槽已定位（偏移表逐槽 join_site），可任意变长",
                [], {"ranges": len(changes), "bytes": delta}))
        else:
            out.append(ProbeVerdict(
                sid, need, False, "TIER_TOO_LOW",
                f"结构重排需要 T3 全域指令语义，本样本申报 {tier}",
                ["R_RECORD_STREAM"], {}))
    return out


def _tier_lt(a: str, b: str) -> bool:
    order = ("T0", "T1", "T2", "T3", "T4")
    return order.index(a) < order.index(b)


def select_strategy(verdicts: Sequence[ProbeVerdict],
                    forced: str | None = None) -> ProbeVerdict:
    """在可用策略中选能力最小者。显式指定不适用的策略是错误，不是覆盖（§6.2）。"""
    usable = [v for v in verdicts if v.applicable]
    if forced:
        for v in verdicts:
            if v.strategy_id == forced:
                if not v.applicable:
                    raise DIS.CstError(
                        f"指定的策略 {forced} 不适用：{v.reason_code} "
                        f"{v.reason_detail}")
                return v
        raise DIS.CstError(f"未知策略 {forced}")
    if not usable:
        raise DIS.CstError("没有可用的回封策略：" + "; ".join(
            f"{v.strategy_id}={v.reason_code}" for v in verdicts))
    return min(usable, key=lambda v: _STRATEGY_ORDER.index(v.strategy_id))


# ---------------------------------------------------------------- 回封执行


def repack_source(src_path: Path, src_meta: dict, changes: dict[int, bytes],
                  entries: dict[int, dict], outdir: Path,
                  forced: str | None = None, key: bytes | None = None) -> dict:
    """单源回封。写 tmp → 重新解析验证站点同构 → 原子改名到 rebuilt/（§6.5）。
    产物形态与输入一致：容器进容器出，裸载荷进裸载荷出。"""
    data = src_path.read_bytes()
    if DIS._sha256(data) != src_meta["sha256"]:
        raise ImportError_(
            f"{src_path.name}: 源文件哈希与 IR 记录不符，源已被改动，拒绝回封")
    doc = DIS.parse_bytes(data, src_path, key)
    DIS.discover_text(doc, D.ENCODING["source"])
    base = src_meta["idx_base"]
    local = {idx - base: nb for idx, nb in changes.items()}
    ov: dict[int, bytes] = {}
    for e in doc.text_entries:
        if e.idx in local:
            ov[e.rec_id] = e.prefix + local[e.idx] + e.suffix
    verdicts = probe_all(doc, changes, entries)
    chosen = select_strategy(verdicts, forced)
    rel = src_meta["path"]
    if chosen.strategy_id == "identity":
        # 零编辑：不产出重建文件。原件已经就是想要的结果，复制一份只会让使用者
        # 分不清哪个是改过的。
        return {"path": rel, "strategy": "identity",
                "verdicts": [_verdict_dict(v) for v in verdicts],
                "changed_entries": 0, "relocations": [],
                "size_before": len(data), "size_after": len(data),
                "sha256_after": src_meta["sha256"],
                "verify": {"ok": True, "errors": [], "note": "零编辑，未产出新文件"},
                "output": None}
    rebuilt, info = DIS.repack(doc, ov)
    verify = _verify_sites(doc, rebuilt, src_path)
    tmp = outdir / "tmp" / rel
    DIS._atomic_write_bytes(tmp, rebuilt)
    if not verify["ok"]:
        failed = outdir / "tmp" / "failed" / rel
        failed.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp, failed)
        raise DIS.CstError(
            f"{src_path.name}: 站点同构验证失败，产物留在 {failed}："
            + "; ".join(verify["errors"][:4]))
    final = outdir / "rebuilt" / rel
    final.parent.mkdir(parents=True, exist_ok=True)
    os.replace(tmp, final)
    return {
        "path": rel, "strategy": chosen.strategy_id,
        "verdicts": [_verdict_dict(v) for v in verdicts],
        "changed_entries": len(ov), "relocations": info["relocations"],
        "size_before": len(data), "size_after": len(rebuilt),
        "sha256_after": DIS._sha256(rebuilt), "verify": verify,
        "output": str(final),
    }


def _verify_sites(doc: DIS.Doc, rebuilt: bytes, path: Path) -> dict:
    """回封后重新解析，比较新旧站点集合：数量相同、偏移逐一对应、键值按映射变化。"""
    errs: list[str] = []
    try:
        doc2 = DIS.parse_bytes(rebuilt, path)
    except DIS.CstError as exc:
        return {"ok": False, "errors": [f"重建产物无法重新解析：{exc}"],
                "sites_before": len(doc.join_sites), "sites_after": 0}
    a, b = doc.join_sites, doc2.join_sites
    if len(a) != len(b):
        errs.append(f"站点数量变化：{len(a)} → {len(b)}")
    for x, y in zip(a, b):
        if x.site_offset != y.site_offset:
            errs.append(f"{x.join_id} 站点偏移变化 {x.site_offset} → {y.site_offset}")
            break
        if x.key_kind != y.key_kind:
            errs.append(f"{x.join_id} 键类型变化")
            break
    if len(doc.records) != len(doc2.records):
        errs.append(f"记录数变化：{len(doc.records)} → {len(doc2.records)}")
    else:
        for r1, r2 in zip(doc.records, doc2.records):
            if r1.type_byte != r2.type_byte:
                errs.append(f"记录 {r1.rec_id} 类型字节变化")
                break
    if [ (x.record_count, x.first_record) for x in doc.blocks ] != \
       [ (y.record_count, y.first_record) for y in doc2.blocks ]:
        errs.append("块表结构变化")
    return {"ok": not errs, "errors": errs, "sites_before": len(a),
            "sites_after": len(b)}


# ---------------------------------------------------------------- 批量


def collect_texts(paths: Iterable[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            out.extend(sorted(p.rglob("*.txt")))
        elif p.is_file():
            out.append(p)
        else:
            raise ImportError_(f"输入不存在：{p}")
    if not out:
        raise ImportError_("没有找到双行文本文件（.txt）")
    return out


def find_outdir(texts: Sequence[Path]) -> Path:
    """从 texts/ 反推输出根：texts 的父目录必须含 ir/manifest.jsonl。"""
    for t in texts:
        for anc in [t] + list(t.parents):
            if (anc / "ir" / "manifest.jsonl").exists():
                return anc
    raise ImportError_(
        "无法定位输出目录：从双行文本向上找不到 ir/manifest.jsonl，"
        "请把 output/texts 或 output 目录作为输入")


def run_repack(texts: Sequence[Path], outdir: Path | None = None,
               forced: str | None = None, source_root: Path | None = None,
               progress=None, key: bytes | None = None) -> dict:
    files = collect_texts(texts)
    root = outdir or find_outdir(files)
    lib = load_library(root)
    by_path = {s["path"]: s for s in lib.sources}
    parts: dict[int, set[int]] = {}
    loaded: list[tuple[TextFile, dict[int, bytes]]] = []
    for i, f in enumerate(files):
        tf = read_text_file(f)
        ch = validate(tf, lib)
        parts.setdefault(tf.scope["part_total"], set()).add(tf.scope["part_index"])
        loaded.append((tf, ch))
        if progress:
            progress("verify", i + 1, len(files), f.name)
    for total, seen in parts.items():
        if total > 1 and seen != set(range(1, total + 1)):
            raise ImportError_(
                f"分片不完整：声明 {total} 片，只收到 {sorted(seen)}（SHARD_INCOMPLETE）")
    src_of: dict[str, dict[int, bytes]] = {}
    for tf, ch in loaded:
        rel = tf.scope.get("src") or tf.path.name.removesuffix(".txt")
        cand = [k for k in by_path if k == rel or k.endswith("/" + rel)]
        if len(cand) != 1:
            raise ImportError_(
                f"{tf.path.name}: 无法唯一定位源文件 {rel}，候选 {cand[:4]}")
        src_of.setdefault(cand[0], {}).update(ch)
    covered = {idx for ch in src_of.values() for idx in ch}
    results, failures = [], []
    # 只回封真的有改动的源。全无改动时也要走一次 probe 让使用者看到裁决。
    todo = sorted(k for k, v in src_of.items() if v) or sorted(src_of)[:1]
    for i, rel in enumerate(todo):
        meta = by_path[rel]
        sp = _resolve_source(root, rel, source_root or lib.source_root)
        try:
            results.append(repack_source(sp, meta, src_of[rel], lib.entries,
                                         root, forced, key))
        except DIS.CstError as exc:
            failures.append({"path": rel, "error": str(exc)})
        if progress:
            progress("repack", i + 1, len(todo), rel)
    log = [DIS._dumps(r) for res in results for r in res["relocations"]]
    DIS._atomic_write_text(root / "reports" / "relocation_log.jsonl",
                           "\n".join(log) + "\n" if log else "", "utf-8")
    built = [r for r in results if r["output"]]
    rep = {
        "tool": D.TOOL_VERSION, "job_sha256": lib.job_sha256,
        "text_files": len(files), "sources_touched": len(todo),
        "sources_ok": len(results), "sources_failed": len(failures),
        "sources_rebuilt": len(built), "failures": failures,
        "changed_entries": len(covered),
        "strategies": _tally(r["strategy"] for r in results),
        "relocation_entries": len(log),
        "verdicts": results[0]["verdicts"] if results else [],
        "outputs": [r["output"] for r in built][:20],
        "rebuilt_dir": str(root / "rebuilt"),
        "ok": bool(results) and not failures,
    }
    DIS._atomic_write_text(root / "reports" / "repack_verdicts.json",
                           json.dumps({"results": results, "report": rep},
                                      ensure_ascii=False, indent=2,
                                      sort_keys=True, default=str), "utf-8")
    return rep


def _resolve_source(root: Path, rel: str, hint: Path | None) -> Path:
    """源文件位置：优先用 manifest 里记录的反汇编时输入根，其次就近搜索。"""
    tried = []
    for anc in ([hint] if hint else []) + [root.parent, root, root.parent.parent]:
        p = anc / rel
        tried.append(str(p))
        if p.exists():
            return p
    raise ImportError_(
        f"找不到源文件 {rel}，已尝试 {tried[:3]}。"
        f"请用 --source-root 指定原始 .cst 所在目录")


def _tally(it) -> dict:
    out: dict = {}
    for x in it:
        out[x] = out.get(x, 0) + 1
    return out


# ---------------------------------------------------------------- CLI


def _cli(argv: Sequence[str] | None = None) -> int:
    DIS._utf8_console()
    ap = argparse.ArgumentParser(description="CatScene .cst 文本回封")
    ap.add_argument("inputs", nargs="*", help="texts 目录或 .txt 文件")
    ap.add_argument("-o", "--output", default=None, help="输出根目录（含 ir/ 的那个）")
    ap.add_argument("--source-root", default=None, help="原始 .cst 所在目录")
    ap.add_argument("--strategy", default=None,
                    choices=list(_STRATEGY_ORDER), help="显式指定回封策略")
    ap.add_argument("--key", default=None, help="密钥文件，仅加密样本需要")
    args = ap.parse_args(argv)
    if not args.inputs:
        ap.print_help()
        return 2
    key = Path(args.key).read_bytes() if args.key else None

    def prog(phase, i, n, name):
        if i == n or i % 20 == 0:
            print(f"  [{phase} {i}/{n}] {name}")

    try:
        rep = run_repack([Path(p) for p in args.inputs],
                         Path(args.output) if args.output else None,
                         args.strategy,
                         Path(args.source_root) if args.source_root else None,
                         progress=prog, key=key)
    except DIS.CstError as exc:
        print(f"拒绝：{exc}", file=sys.stderr)
        return 1
    print()
    print(f"译文文件  {rep['text_files']}  全部通过 12 条导入校验")
    print(f"改动条数  {rep['changed_entries']}")
    print(f"回封源    {rep['sources_ok']}/{rep['sources_touched']}"
          f"（实际产出 {rep['sources_rebuilt']} 个文件）")
    print(f"回封方式  {rep['strategies']}")
    print(f"重定位    {rep['relocation_entries']} 处")
    for f in rep["failures"]:
        print(f"    ! {f['path']}: {f['error']}")
    if rep["sources_rebuilt"]:
        print(f"产物      {rep['rebuilt_dir']}")
    else:
        print("产物      无（没有任何译文行被填写，原件即最终结果）")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(_cli())
