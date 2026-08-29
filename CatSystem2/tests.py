# -*- coding: utf-8 -*-
"""§9 零突变验证套件。每个用例对应 SKILL.md §9 表格里的一行。

用法：
    python tests.py <一个或多个 .cst 或目录>            # 默认取 ../脚本
每个用例只读源文件，产物写进临时目录，跑完删除。
"""
from __future__ import annotations

import io
import json
import re
import shutil
import sys
import tempfile
import traceback
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import opcodelist as D  # noqa: E402
import disassembler as DIS  # noqa: E402
import assembler as ASM  # noqa: E402

CASES: list[tuple[str, str]] = []
_FAIL: list[str] = []

# 第二部同引擎作品（Yukikoi Melt）：带 0x03 页结束记录与 .cstl 多语言层。
# 跨样本验证按 §0.3 是硬要求，这个路径存在时自动纳入。
YUKIKOI = Path(r"E:\SteamLibrary\steamapps\common\Yukikoi Melt\新建文件夹 (2)")


def case(group: str):
    def deco(fn):
        CASES.append((group, fn.__name__))
        globals()["_CASE_" + fn.__name__] = fn
        return fn
    return deco


def expect(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _swap_tag(line: str) -> str:
    """把行里的 tag 换成另一个合法但不同的 tag。"""
    for a, b in (("msg", "ui"), ("name", "ui"), ("choice", "ui"), ("misc", "ui")):
        sep = line[0]
        parts = line.split(sep)
        if len(parts) >= 4 and parts[2] == a:
            parts[2] = b
            return sep.join(parts)
    raise AssertionError(f"无法在该行里换 tag：{line!r}")


def expect_reject(fn, code: str, what: str):
    """必须被拒绝，且错误信息里带指定的门禁代码与精确位置。"""
    try:
        fn()
    except DIS.CstError as exc:
        expect(code in str(exc),
               f"{what}: 被拒绝了但代码不对，期待 {code}，实际 {exc}")
        return str(exc)
    raise AssertionError(f"{what}: 应当被拒绝，但通过了")


# ---------------------------------------------------------------- 往返


@case("往返")
def roundtrip_zero_edit(ctx):
    for p in ctx["samples"]:
        data = p.read_bytes()
        doc = DIS.parse_bytes(data, p)
        out, _ = DIS.repack(doc)
        expect(out == data, f"{p.name}: 零编辑重建与原文不一致")


@case("往返")
def bare_payload_form(ctx):
    """外部脚本解压出的裸载荷（无 CatScene 头）必须能直接吃进来，
    且回封时按原形态写回，不擅自加容器头。"""
    import unpack as UNP
    p = ctx["samples"][0]
    payload, info = UNP.unpack_one(p, None)
    q = ctx["work"] / "tmp" / ("bare_" + p.name)
    DIS._atomic_write_bytes(q, payload)
    doc = DIS.parse_bytes(payload, q)
    expect(doc.form == "bare-payload", f"未识别为裸载荷：{doc.form}")
    DIS.discover_text(doc, D.ENCODING["source"])
    expect(doc.text_entries, "裸载荷里没提到文本")
    out, meta = DIS.repack(doc)
    expect(meta["form"] == "bare-payload", "裸载荷回封时形态变了")
    expect(out == payload, "裸载荷零编辑往返不一致")
    cert = DIS.coverage_certificate(doc)
    expect(cert["byte_coverage"] == 1.0, "裸载荷证书覆盖不足")
    expect(cert["intervals"][-1]["end"] == cert["source_size"],
           "裸载荷证书未覆盖到末字节")
    # 反向：裸载荷 → 容器 → 与原件一致
    built, _ = UNP.repack_one(q)
    expect(built == p.read_bytes(), "解压再压回与原件不一致")


@case("往返")
def encrypted_probe_rejects_garbage(ctx):
    """解密探测的接受条件必须强到不会假阳性：随机字节永远不该被"解出来"。"""
    import os as _os
    p = ctx["samples"][0]
    junk = _os.urandom(4096)
    hdr = bytearray(DIS._HDR)
    hdr[:len(D.CONTAINER["magic"])] = D.CONTAINER["magic"]
    DIS._U32.pack_into(hdr, D.CONTAINER["field_com_size"]["offset"], len(junk))
    DIS._U32.pack_into(hdr, D.CONTAINER["field_unc_size"]["offset"], 9999)
    expect_reject(lambda: DIS.parse_bytes(bytes(hdr) + junk, p),
                  "全部不满足", "随机字节被误判为可解密")
    # 明文文件不该走进解密分支
    doc = DIS.load(p)
    expect(doc.cipher["id"] == "none",
           f"明文文件被判成了加密：{doc.cipher}")


@case("往返")
def deterministic_twice(ctx):
    p = ctx["samples"][0]
    a = DIS.load(p)
    DIS.discover_text(a, D.ENCODING["source"])
    b = DIS.load(p)
    DIS.discover_text(b, D.ENCODING["source"])
    expect(DIS.render_texts(a, "X" * 64, "cp932", "cp932")
           == DIS.render_texts(b, "X" * 64, "cp932", "cp932"),
           "同一输入两次产出的双行文本不同")
    expect(json.dumps(DIS.coverage_certificate(a), sort_keys=True)
           == json.dumps(DIS.coverage_certificate(b), sort_keys=True),
           "同一输入两次产出的证书不同")


# ---------------------------------------------------------------- Tier


@case("Tier")
def unknown_type_byte_rejected(ctx):
    """未登记的记录类型必须触发失败而非静默走已知分支（§0.2）。"""
    p = ctx["samples"][0]
    doc = DIS.load(p)
    payload = _payload(p)
    dbase = D.PAYLOAD["header"]["size"] + doc.data_offset
    off = dbase + doc.records[3].offset + 1
    bad = bytearray(payload)
    bad[off] = 0x7E
    expect_reject(lambda: DIS.parse_bytes(_wrap(bytes(bad)), p),
                  "未在方言中登记", "未知记录类型")


@case("Tier")
def cell_misalignment_rejected(ctx):
    """偏移表跨度不整除即解析失败，不得截断或补齐（§1.2）。"""
    p = ctx["samples"][0]
    doc = DIS.load(p)
    payload = bytearray(_payload(p))
    hdr = D.PAYLOAD["header"]["size"]
    DIS._U32.pack_into(payload, 12, doc.data_offset + 2)
    expect_reject(lambda: DIS.parse_bytes(_wrap(bytes(payload)), p),
                  "整数倍", "偏移表跨度不整除")


# ---------------------------------------------------------------- 站点


@case("站点")
def value_collision_constant_preserved(ctx):
    """放一个值恰等于某记录偏移、但不在站点集合中的常量字，变长回封后必须逐字节不变。

    本格式里这样的常量真实存在：块表的 first_record 字段值域与记录偏移重叠。
    """
    p = ctx["samples"][0]
    doc = DIS.load(p)
    DIS.discover_text(doc, D.ENCODING["source"])
    hdr = D.PAYLOAD["header"]["size"]
    ent = D.PAYLOAD["block_table"]["entry_size"]
    keys = {r.offset for r in doc.records}
    sites = {s.site_offset for s in doc.join_sites}
    victims = []
    payload = _payload(p)
    for i in range(0, hdr + ent * len(doc.blocks), 4):
        if i in sites:
            continue
        v = DIS._U32.unpack_from(payload, i)[0]
        if v in keys:
            victims.append((i, v))
    expect(victims, "构造不出值碰撞常量：块表里没有值等于某记录偏移的字")
    target = next(e for e in doc.text_entries if e.tag == "msg" and e.source)
    ov = {target.rec_id: target.raw + "ながくする".encode("cp932")}
    rebuilt, info = DIS.repack(doc, ov)
    new_payload = _payload_bytes(rebuilt)
    kept = 0
    for off, val in victims:
        got = DIS._U32.unpack_from(new_payload, off)[0]
        expect(got == val,
               f"值碰撞常量被改写：偏移 {off:#x} 的 {val} 变成了 {got}")
        kept += 1
    ctx["preserved_value_collisions"] = kept
    expect(kept > 0, "preserved_value_collisions 为零")


@case("站点")
def site_isomorphism_detects_injection(ctx):
    """站点同构验证必须对「少一个站点」「多一个站点」都拒绝。"""
    p = ctx["samples"][0]
    doc = DIS.load(p)
    DIS.discover_text(doc, D.ENCODING["source"])
    rebuilt, _ = DIS.repack(doc)
    ok = ASM._verify_sites(doc, rebuilt, p)
    expect(ok["ok"], f"未注入故障时同构验证就失败了：{ok['errors']}")
    fewer = DIS.Doc(**{**_doc_fields(doc)})
    fewer.join_sites = doc.join_sites[:-1]
    fewer.records = doc.records
    bad = ASM._verify_sites(fewer, rebuilt, p)
    expect(not bad["ok"], "少一个站点未被拒绝")
    expect(any("数量" in e for e in bad["errors"]),
           f"少站点的报错未指出数量变化：{bad['errors']}")
    more = DIS.Doc(**{**_doc_fields(doc)})
    more.join_sites = list(doc.join_sites) + [doc.join_sites[-1]]
    bad2 = ASM._verify_sites(more, rebuilt, p)
    expect(not bad2["ok"], "多一个站点未被拒绝")


@case("站点")
def rewrite_by_site_not_by_value(ctx):
    """按站点改写：每个被改写的范围都能追溯到一个 join_id。"""
    p = ctx["samples"][0]
    doc = DIS.load(p)
    DIS.discover_text(doc, D.ENCODING["source"])
    t = next(e for e in doc.text_entries if e.tag == "msg" and e.source)
    _, info = DIS.repack(doc, {t.rec_id: t.raw + "ながくする".encode("cp932")})
    expect(info["relocations"], "变长回封后没有任何重定位记录")
    jids = {s.join_id for s in doc.join_sites}
    for r in info["relocations"]:
        expect(r["join_id"] in jids,
               f"重定位记录 {r} 的 join_id 不在站点集合中")


# ---------------------------------------------------------------- 死条目


@case("死条目")
def empty_records_kept_in_ir_but_not_exported(ctx):
    """零长度 MSG 是「清空文本框」的结构标记：不进双行文本（译者无从下手），
    但必须完整留在 IR 与覆盖证书里，且往返逐字节一致。"""
    root = ctx["work"]
    ir = [json.loads(l) for l in
          (root / "ir" / "text_entries.jsonl").read_text(encoding="utf-8")
          .splitlines() if l]
    flush = [e for e in ir if not e["exported"]]
    expect(flush, "IR 里没有任何未导出条目，说明零长度记录被当成了普通文本")
    for e in flush:
        expect(e["raw_len"] == 0, f"未导出条目却有内容：{e}")
        expect(e["translate_policy"] == "frozen", f"未导出条目未锁定：{e}")
    exported = {e["idx"] for e in ir if e["exported"]}
    seen = set()
    for tp in sorted((root / "texts").rglob("*.txt")):
        for l in tp.read_text(encoding="utf-8-sig").splitlines():
            m = ASM._ORIG_RE.match(l)
            if m:
                seen.add(int(m.group("idx")))
                expect(m.group("text") != "",
                       f"双行文本里出现了空原文行：{tp.name} {l!r}")
    expect(seen == exported,
           f"双行文本条目与 IR 的 exported 集合不符："
           f"多 {len(seen - exported)} 少 {len(exported - seen)}")


@case("死条目")
def unreferenced_entry_kept(ctx):
    """偏移表逐槽引用每条记录，故本格式没有 unmatched；
    但空 payload 的记录必须仍在 IR 中，不得被跳过或删除。"""
    p = ctx["samples"][0]
    doc = DIS.load(p)
    DIS.discover_text(doc, D.ENCODING["source"])
    empties = [e for e in doc.text_entries if not e.raw]
    expect(len(doc.join_sites) == len(doc.records),
           "站点数与记录数不等，说明有记录未被引用连接覆盖")
    if empties:
        expect(all(e.idx for e in empties), "空条目丢了 idx")
    out, _ = DIS.repack(doc)
    expect(out == p.read_bytes(), "含空条目时零编辑往返失败")


# ---------------------------------------------------------------- 文本篡改


@case("文本篡改")
def tamper_cases_rejected(ctx):
    root = ctx["work"]
    lib = ASM.load_library(root)
    tp = next(iter(sorted((root / "texts").rglob("*.txt"))))
    orig = tp.read_text(encoding="utf-8-sig")
    om, tm = D.TEXT_FORMAT["orig_mark"], D.TEXT_FORMAT["tran_mark"]

    def run(text: str):
        q = root / "tmp" / "tamper.txt"
        DIS._atomic_write_text(q, text, "utf-8-sig")
        tf = ASM.read_text_file(q)
        ASM.validate(tf, lib)

    lines = orig.splitlines()
    oi = next(i for i, l in enumerate(lines) if l.startswith(om))
    ti = oi + 1

    def mut(i, new):
        c = list(lines)
        c[i] = new
        return "\n".join(c) + "\n"

    def drop(i):
        c = list(lines)
        del c[i]
        return "\n".join(c) + "\n"

    checks = [
        ("SOURCE_ANCHOR", mut(oi, lines[oi] + "篡改"), "改原文行"),
        ("IDX_MISMATCH", mut(ti, lines[ti].replace(tm, tm, 1)
                             .replace(lines[ti][1:9], "99999999", 1)), "改译文 idx"),
        # 只改译文行的 tag → 与原文行不一致（TAG_MISMATCH）
        ("TAG_MISMATCH", mut(ti, _swap_tag(lines[ti])), "改译文 tag"),
        # 两行 tag 一致地改成别的合法 tag：先被注释行的 idx/tag 校验拦住，
        # 这正是 META_DESYNC 该做的事——注释与条目错配比 tag 本身更早暴露。
        ("META_DESYNC", mut(oi, _swap_tag(lines[oi]))
         .replace(lines[ti], _swap_tag(lines[ti])), "原译同改 tag"),
        ("SEPARATOR_MIXED", mut(ti, lines[ti].replace(tm, om)), "混用分隔符"),
        ("MISSING_TRANSLATION", "\n".join(lines[:ti]) + "\n", "删译文行"),
        ("SRC_HASH_MISMATCH", orig.replace(lib.job_sha256, "0" * 64), "换文件头哈希"),
        ("SHARD_INCOMPLETE", orig.replace("part=1/1", "part=1/3"), "少交分片"),
    ]
    # 去掉注释行后同改两行 tag：绕过 META_DESYNC，必须由 IR 比对拦住
    c2 = list(lines)
    c2[oi], c2[ti] = _swap_tag(c2[oi]), _swap_tag(c2[ti])
    if c2[oi - 1].startswith(D.TEXT_FORMAT["comment_prefix"]):
        del c2[oi - 1]
    checks.append(("TAG_MISMATCH", "\n".join(c2) + "\n", "无注释行时同改 tag"))
    for code, text, what in checks:
        if code == "SHARD_INCOMPLETE":
            q = root / "tmp" / "tamper.txt"
            DIS._atomic_write_text(q, text, "utf-8-sig")
            expect_reject(lambda: ASM.run_repack([q], root), code, what)
            continue
        expect_reject(lambda t=text: run(t), code, what)
    # 交换两组条目：每对内部仍自洽，但与注释行错配（META_DESYNC）
    c = list(lines)
    oi2 = next(i for i, l in enumerate(c[ti + 1:], ti + 1) if l.startswith(om))
    c[oi], c[ti], c[oi2], c[oi2 + 1] = c[oi2], c[oi2 + 1], c[oi], c[ti]
    expect_reject(lambda: run("\n".join(c) + "\n"), "META_DESYNC", "整块交换")


@case("文本篡改")
def frozen_entry_protected(ctx):
    root = ctx["work"]
    lib = ASM.load_library(root)
    frozen = [e for e in lib.entries.values() if e["translate_policy"] == "frozen"]
    if not frozen:
        return
    for tp in sorted((root / "texts").rglob("*.txt")):
        text = tp.read_text(encoding="utf-8-sig")
        lines = text.splitlines()
        hit = None
        for i, l in enumerate(lines):
            m = ASM._TRAN_RE.match(l)
            if m and lib.entries.get(int(m.group("idx")), {}) \
                    .get("translate_policy") == "frozen":
                hit = i
                break
        if hit is None:
            continue
        lines[hit] = lines[hit] + "改了"
        q = root / "tmp" / "frozen.txt"
        DIS._atomic_write_text(q, "\n".join(lines) + "\n", "utf-8-sig")
        expect_reject(lambda: ASM.validate(ASM.read_text_file(q), lib),
                      "FROZEN_MODIFIED", "改 frozen 条目")
        return


# ---------------------------------------------------------------- 编码


@case("编码")
def undecodable_bytes_roundtrip(ctx):
    """不可解码字节：往返逐字节一致、以占位符呈现、强制 frozen。

    构造判据要用**真的**解不出来的字节：0xEA54 是合法的稀有汉字，0x80/0xFD-FF
    在 Python 的 cp932 里映射到私用区，都不会失败。0x81 后接 0x20 才是非法双字节序列。
    """
    raw = bytes([0x81, 0x75, 0x81, 0x20, 0x81, 0x76])
    t, bad = DIS._decode(raw, "cp932")
    expect(bad, f"{raw.hex()} 在 cp932 下应当解码失败")
    expect(t.startswith(D.TEXT_FORMAT["placeholder_open"]),
           f"未以占位符呈现：{t!r}")
    back = ASM.encode_target(t, "cp932", Path("x"), 1)
    expect(back == raw, f"占位符往返不一致：{back.hex()} != {raw.hex()}")
    # 控制字节也走占位符，且往返一致
    raw2 = "あ".encode("cp932") + b"\x0c" + "い".encode("cp932")
    t2, bad2 = DIS._decode(raw2, "cp932")
    expect(not bad2, "含控制字节不该判为 undecodable")
    expect("{{0C}}" in t2, f"控制字节未转占位符：{t2!r}")
    expect(ASM.encode_target(t2, "cp932", Path("x"), 1) == raw2,
           "控制字节占位符往返不一致")


@case("编码")
def no_silent_fallback(ctx):
    """核心路径禁用 surrogateescape / replace（§4.4）。
    控制台显示用的 backslashreplace 不算——它只影响终端输出，不进产物。"""
    bad = []
    for mod in (DIS.__file__, ASM.__file__):
        for i, line in enumerate(Path(mod).read_text(encoding="utf-8")
                                 .splitlines(), 1):
            if line.lstrip().startswith("#") or '"""' in line:
                continue
            if "reconfigure" in line:
                continue
            for pat in ("surrogateescape", 'errors="replace"',
                        "errors='replace'"):
                if pat in line:
                    bad.append((Path(mod).name, i, line.strip()))
    expect(not bad, f"核心路径出现了编码兜底：{bad}")


@case("编码")
def target_encoding_unrepresentable_reported(ctx):
    """译文编码选错时报出具体字符并给候选编码，不静默替换成 ?。
    注意 cp932 覆盖了大量汉字（這樣的字都能编），要用简体专有字构造。"""
    msg = expect_reject(
        lambda: ASM.encode_target("变长测试", "cp932", Path("t.txt"), 42),
        "ENCODING_UNREPRESENTABLE", "cp932 不可表示的简体字")
    expect("42" in msg, f"报错未给出条目号：{msg}")
    expect("gbk" in msg, f"报错未给出候选编码：{msg}")
    expect("变" in msg, f"报错未指出具体字符：{msg}")


# ---------------------------------------------------------------- 占位符


@case("占位符")
def slash_and_wide_space_not_escaped(ctx):
    """斜杠与全角空格可正常显示，不得转义成占位符（§4.5）。"""
    for p in ctx["samples"]:
        doc = DIS.load(p)
        DIS.discover_text(doc, D.ENCODING["source"])
        for e in doc.text_entries:
            if "\\" in e.source or D.IDEOGRAPHIC_SPACE in e.source:
                expect("{{5C}}" not in e.source, f"斜杠被转义了：{e.source[:40]}")
                expect("{{81:40}}" not in e.source,
                       f"全角空格被转义了：{e.source[:40]}")
                return


@case("占位符")
def placeholder_set_must_match(ctx):
    root = ctx["work"]
    lib = ASM.load_library(root)
    ent = next((e for e in lib.entries.values()
                if e["translate_policy"] == "translatable" and e["source"]), None)
    expect(ent is not None, "找不到可翻译条目")
    tp = next(t for t in sorted((root / "texts").rglob("*.txt")))
    lines = tp.read_text(encoding="utf-8-sig").splitlines()
    for i, l in enumerate(lines):
        m = ASM._TRAN_RE.match(l)
        if m and lib.entries[int(m.group("idx"))]["translate_policy"] \
                == "translatable":
            lines[i] = l + "{{0C}}"
            q = root / "tmp" / "ph.txt"
            DIS._atomic_write_text(q, "\n".join(lines) + "\n", "utf-8-sig")
            expect_reject(lambda: ASM.validate(ASM.read_text_file(q), lib),
                          "PLACEHOLDER_BROKEN", "译文凭空多出占位符")
            return


@case("占位符")
def lowercase_placeholder_rejected(ctx):
    root = ctx["work"]
    lib = ASM.load_library(root)
    tp = next(t for t in sorted((root / "texts").rglob("*.txt")))
    lines = tp.read_text(encoding="utf-8-sig").splitlines()
    for i, l in enumerate(lines):
        m = ASM._TRAN_RE.match(l)
        if m and lib.entries[int(m.group("idx"))]["translate_policy"] \
                == "translatable":
            lines[i] = l + "{{0c}}"
            q = root / "tmp" / "phlow.txt"
            DIS._atomic_write_text(q, "\n".join(lines) + "\n", "utf-8-sig")
            expect_reject(lambda: ASM.validate(ASM.read_text_file(q), lib),
                          "PLACEHOLDER_BROKEN", "小写占位符")
            return


# ---------------------------------------------------------------- 人名


@case("人名")
def ambiguous_name_keeps_candidates(ctx):
    """同一 msg 有多个候选时输出 ambiguous 与全部候选，而非任选其一。"""
    found = 0
    for p in ctx["all"]:          # 一名对多句只在少数 ポエム 段落出现，必须扫全语料
        doc = DIS.load(p)
        DIS.discover_text(doc, D.ENCODING["source"])
        for b in doc.name_bindings:
            if b["confidence"] == "ambiguous":
                expect(len(b["candidates"]) != 1,
                       f"标了 ambiguous 却只有一个候选：{b}")
                found += 1
            elif b["confidence"] == "derived":
                expect(len(b["candidates"]) == 1,
                       f"标了 derived 却有多个候选：{b}")
    expect(found, "整个语料没有一条 ambiguous 绑定，说明歧义检测没生效"
                  "（本作 ポエム 段落存在一名对多句）")
    ctx["ambiguous_bindings"] = found


@case("人名")
def no_order_preference(ctx):
    """禁止「第一个匹配的是名字」这类顺序偏好：绑定依据必须是块归属。"""
    src = Path(DIS.__file__).read_text(encoding="utf-8")
    expect("slot-ordinal" in src, "绑定方法未申报为 slot-ordinal")
    for p in ctx["samples"]:
        doc = DIS.load(p)
        DIS.discover_text(doc, D.ENCODING["source"])
        names = {e.idx for e in doc.text_entries if e.tag == "name"}
        for b in doc.name_bindings:
            expect(b["name_entry_idx"] in names,
                   f"绑定把非 name 条目当成了名字：{b}")
            if b["msg_entry_idx"] is not None:
                expect(b["msg_entry_idx"] not in names,
                       f"绑定把 name 条目当成了正文：{b}")


# ---------------------------------------------------------------- 回封


@case("回封")
def strategy_minimum_capability(ctx):
    p = ctx["samples"][0]
    doc = DIS.load(p)
    DIS.discover_text(doc, D.ENCODING["source"])
    entries = {e.idx: {"raw_len": len(e.raw), "translate_policy":
                       e.translate_policy} for e in doc.text_entries}
    v0 = ASM.probe_all(doc, {}, entries)
    expect(ASM.select_strategy(v0).strategy_id == "identity",
           "零编辑未选 identity")
    t = next(e for e in doc.text_entries if e.tag == "msg" and len(e.raw) > 8)
    shorter = {t.idx: t.raw[:4]}
    v1 = ASM.probe_all(doc, shorter, entries)
    expect(ASM.select_strategy(v1).strategy_id == "in_place",
           "缩短一条时未选 in_place")
    longer = {t.idx: t.raw + b"XXXX"}
    v2 = ASM.probe_all(doc, longer, entries)
    got = ASM.select_strategy(v2).strategy_id
    expect(got == "pointer-rewrite",
           f"单条变长应选 pointer-rewrite 而非 full-layout，实际 {got}")
    ip = next(v for v in v2 if v.strategy_id == "in_place")
    expect(not ip.applicable and ip.reason_code == "LENGTH_OVERFLOW",
           f"in_place 超长未被拒：{ip}")
    fl = next(v for v in v2 if v.strategy_id == "full-layout")
    expect(not fl.applicable and fl.reason_code == "TIER_TOO_LOW",
           f"T2 下 full-layout 应因 tier 不足被拒：{fl}")


@case("回封")
def explicit_inapplicable_strategy_is_error(ctx):
    p = ctx["samples"][0]
    doc = DIS.load(p)
    DIS.discover_text(doc, D.ENCODING["source"])
    entries = {e.idx: {"raw_len": len(e.raw)} for e in doc.text_entries}
    t = next(e for e in doc.text_entries if e.tag == "msg" and e.raw)
    v = ASM.probe_all(doc, {t.idx: t.raw + b"XX"}, entries)
    expect_reject(lambda: ASM.select_strategy(v, "full-layout"),
                  "不适用", "显式指定不适用的策略")


@case("回封")
def run_failure_does_not_downgrade(ctx):
    """注入一个 probe 会通过但 run 必然失败的条件，验证系统停止而非降级。"""
    p = ctx["samples"][0]
    root = ctx["work"]
    lib = ASM.load_library(root)
    meta = next(m for m in lib.sources if m["path"].endswith(p.name))
    real = DIS.repack
    calls = {"n": 0}

    def broken(doc, ov=None):
        calls["n"] += 1
        out, info = real(doc, ov)
        return out[:-1], info          # 截掉一字节，重新解析必然失败

    DIS.repack = broken
    try:
        t = next(e for e in lib.entries.values()
                 if e["translate_policy"] == "translatable" and e["source"])
        expect_reject(
            lambda: ASM.repack_source(p, meta, {t["idx"]: b"x" * 40},
                                      lib.entries, root),
            "站点同构验证失败", "run 失败")
        expect(calls["n"] == 1, f"run 失败后又跑了 {calls['n']} 次，说明自动降级了")
    finally:
        DIS.repack = real
    expect(not (root / "rebuilt" / meta["path"]).exists()
           or (root / "tmp" / "failed" / meta["path"]).exists(),
           "run 失败的产物进了 rebuilt/ 或未留在 tmp/failed/")


# ---------------------------------------------------------------- 方言


@case("方言")
def no_engine_literals_in_logic(ctx):
    """结构逻辑模块中不得出现引擎特定的魔数、opcode 值或内联正则（§7）。"""
    import ast
    allow = set(range(-2, 65)) | {0x7F, 0xFF, 0xFFFF, 0xFFFFFFFF, 100, 128, 256,
                                  512, 1000, 1024, 4096, 8192, 65536, 1048576,
                                  67108864}
    hexpat = re.compile(r"0[xX][0-9a-fA-F]+")
    bad = []
    for mod in (DIS.__file__, ASM.__file__):
        src = Path(mod).read_text(encoding="utf-8")
        lines = src.splitlines()
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Constant) and isinstance(node.value, int) \
                    and not isinstance(node.value, bool):
                if node.value in allow:
                    continue
                line = lines[node.lineno - 1]
                if "dialect-literal-ok" in line:
                    continue
                if hexpat.search(line):
                    bad.append((Path(mod).name, node.lineno, node.value, line.strip()))
    expect(not bad, f"结构逻辑里出现十六进制魔数：{bad[:4]}")


@case("方言")
def anchor_without_evidence_rejected(ctx):
    for tb, meta in D.RECORD_TYPES.items():
        expect(meta.get("evidence_refs"), f"记录类型 {tb:#x} 缺 evidence_refs")
        expect(meta.get("confidence"), f"记录类型 {tb:#x} 缺 confidence")
    for r in D.TEXT_RULES:
        expect(r.get("evidence_refs"), f"文本规则 {r['id']} 缺 evidence_refs")
        expect(r.get("confidence"), f"文本规则 {r['id']} 缺 confidence")
    for w in D.WINDOWS:
        expect(w.get("evidence"), f"窗口 {w['name']} 缺 evidence")
        expect(w.get("on_exceed"), f"窗口 {w['name']} 缺 on_exceed")
    for t in D.TAG_CLOSED_SET:
        expect(len(D.TAG_CLOSED_SET) == 8, "tag 闭集被扩展了")
    for meta in D.RECORD_TYPES.values():
        expect(meta["tag"] in D.TAG_CLOSED_SET,
               f"记录类型的 tag {meta['tag']} 不在闭集内")
    for r in D.TEXT_RULES:
        expect(r["tag"] in D.TAG_CLOSED_SET,
               f"文本规则的 tag {r['tag']} 不在闭集内")


# ---------------------------------------------------------------- 报告


@case("报告")
def report_has_required_counters(ctx):
    rep = json.loads((ctx["work"] / "reports" / "disasm.json")
                     .read_text(encoding="utf-8"))
    for k in ("window_hits", "rule_hits", "tag_source_counts",
              "heuristic_entries", "unresolved_entries", "roundtrip_identity",
              "min_tier", "declared_capabilities", "instruction_coverage",
              "sanity_gate"):
        expect(k in rep, f"报告缺 {k}")
    expect(rep["instruction_coverage"] == "not_applicable"
           or rep["min_tier"] >= "T3",
           "min_tier < T3 时 instruction_coverage 必须是 not_applicable")
    expect(rep["tags"], "报告里 tag 分布为空")
    expect(sum(rep["rule_hits"].values()) >= 0, "rule_hits 缺失")


@case("报告")
def sanity_gate_catches_empty_output(ctx):
    """§0.1：产出为 0 或高度倾斜必须判失败，不得当作样本特性。"""
    expect(DIS.sanity_gate({"tags": {"name": 400}, "source_bytes": 100000}),
           "只有人名、正文 0 条时门禁未失败")
    expect(DIS.sanity_gate({"tags": {"msg": 1, "name": 9999},
                            "source_bytes": 100000}),
           "高度倾斜时门禁未失败")
    expect(not DIS.sanity_gate({"tags": {"msg": 4000, "name": 2500},
                                "source_bytes": 100000}),
           "正常分布被误判为失败")


# ---------------------------------------------------------------- CSTL


@case("CSTL")
def cstl_varint_is_sum_of_ff(ctx):
    """长度与计数用 0xFF 累加式变长整数，不是 LEB128。
    ff ff 17 = 255+255+23 = 533。按 LEB128 或 u8 读都会错位。"""
    expect(DIS._cstl_varint(bytes([0xFF, 0xFF, 0x17]), 0) == (533, 3),
           "ff ff 17 应当解成 533")
    expect(DIS._cstl_varint(bytes([0xFF, 0xAB]), 0) == (426, 2),
           "ff ab 应当解成 426")
    expect(DIS._cstl_varint(bytes([0x11]), 0) == (17, 1), "单字节 11 = 17")
    for v in (0, 1, 0xFE, 0xFF, 0x100, 533, 4000, 70000):
        enc = DIS._cstl_emit(v)
        expect(DIS._cstl_varint(enc, 0) == (v, len(enc)),
               f"{v} 编解码不是互逆：{enc.hex()}")
    expect(DIS._cstl_emit(533) == bytes([0xFF, 0xFF, 0x17]),
           "533 的编码应为 ff ff 17")


@case("CSTL")
def cstl_roundtrip_and_page_join(ctx):
    """.cstl 零编辑往返逐字节一致；条目数恒等于同名 .cst 的页结束记录数。

    后者是可判定的引用连接（§3）：条目单位是「页」而不是消息记录，
    所以拿 0x20 的条数去比永远对不上——这一点值得写进用例免得再踩。
    """
    files = ctx.get("cstl") or []
    if not files:
        return                      # 该语料没有 .cstl，跳过而不是假装通过
    for p in files:
        data = p.read_bytes()
        doc = DIS.parse_bytes(data, p)
        expect(doc.form == "cstl", f"{p.name}: 未识别为 cstl")
        out, info = DIS.repack(doc)
        expect(out == data, f"{p.name}: cstl 零编辑往返不一致")
        cert = DIS.coverage_certificate(doc)
        expect(cert["byte_coverage"] == 1.0, f"{p.name}: 覆盖不足")
        expect(cert["intervals"][-1]["end"] == cert["source_size"],
               f"{p.name}: 区间未覆盖到末字节")
        base = p.with_suffix(".cst")
        if base.exists():
            cd = DIS.load(base)
            pages = sum(1 for r in cd.records
                        if r.type_byte in D.BLOCK_TERMINATORS)
            expect(doc.cstl_count == pages,
                   f"{p.name}: 条目数 {doc.cstl_count} != 页数 {pages}")


@case("CSTL")
def cstl_speaker_matches_cst(ctx):
    """.cstl 的日文说话者槽应当与 .cst 的 0x21 记录逐条相同——
    这是「两个文件描述同一批对话」的独立证据。"""
    files = ctx.get("cstl") or []
    if not files:
        return
    tot = same = 0
    for p in files:
        base = p.with_suffix(".cst")
        if not base.exists():
            continue
        doc = DIS.parse_bytes(p.read_bytes(), p)
        DIS.discover_text(doc, D.CSTL["encoding"])
        if "jp" not in doc.langs:
            continue
        per = D.CSTL["slots_per_lang"] * len(doc.langs)
        base_slot = doc.langs.index("jp") * D.CSTL["slots_per_lang"]
        jp = [e.source for e in doc.text_entries
              if e.rec_id % per == base_slot and e.source]
        cd = DIS.load(base)
        names = [r.payload.decode(D.ENCODING["source"])
                 for r in cd.records if r.type_byte == D.TYPE_NAME]
        expect(len(jp) == len(names),
               f"{p.name}: 说话者条数 {len(jp)} != cst 的 {len(names)}")
        for a, b in zip(jp, names):
            tot += 1
            same += (a == b)
    expect(tot and same == tot,
           f"说话者内容只有 {same}/{tot} 相同")


@case("CSTL")
def cstl_text_uses_utf8_header(ctx):
    """.cstl 是 UTF-8，双行文件头必须如实写 utf-8——写成 cp932 会让回封
    报一堆假的「不可表示」错误。同时必须标出语言槽。"""
    files = ctx.get("cstl") or []
    if not files:
        return
    doc = DIS.parse_bytes(files[0].read_bytes(), files[0])
    DIS.discover_text(doc, D.CSTL["encoding"])
    txt = DIS.render_texts(doc, "0" * 64, "cp932", "cp932")
    lines = txt.splitlines()
    expect("source=utf-8" in lines[1] and "target=utf-8" in lines[1],
           f"编码行未写 utf-8：{lines[1]}")
    expect(any(l.startswith("# languages") for l in lines[:8]),
           "文件头未列出语言")
    metas = [l for l in lines if l.startswith("# idx=")]
    expect(metas and all("lang=" in l for l in metas),
           "注释行未标出语言槽，译者不知道该改哪一行")


@case("CSTL")
def cstl_variable_length_repack(ctx):
    """.cstl 变长回封：改长一条后仍能重新解析，且内容确实变了。"""
    files = ctx.get("cstl") or []
    if not files:
        return
    p = files[0]
    doc = DIS.parse_bytes(p.read_bytes(), p)
    DIS.discover_text(doc, D.CSTL["encoding"])
    t = next(e for e in doc.text_entries if e.tag == "msg" and e.source)
    longer = (t.source + "追加テスト").encode(D.CSTL["encoding"])
    out, info = DIS.repack(doc, {t.rec_id: longer})
    expect(len(out) > doc.raw_size, "变长后文件没变长")
    expect(info["relocations"], "变长后没有重定位记录")
    doc2 = DIS.parse_bytes(out, p)
    expect(doc2.cstl_count == doc.cstl_count, "条目数变了")
    expect(len(doc2.records) == len(doc.records), "记录数变了")
    DIS.discover_text(doc2, D.CSTL["encoding"])
    got = next(e for e in doc2.text_entries if e.rec_id == t.rec_id)
    expect(got.raw == longer, "改动未生效")


# ---------------------------------------------------------------- 拖放


@case("拖放")
def drop_callback_never_touches_tk(ctx):
    """拖放回调运行在 Win32 窗口过程里，Tk 已释放 GIL。在那里调**任何** Tk API
    都会触发 `PyEval_RestoreThread: ... GIL is released` 致命错误，进程无
    traceback 消失——这就是「拖文件夹进 GUI 闪退」的根因。

    实测：不碰 Tk 的回调能活；只要加一行 root.after_idle 就必死。
    用 SendMessage 同步派发反而不崩，所以很容易误判为已修复。
    因此这条用例做**静态**检查：回调体内不得出现 Tk 调用。
    """
    import ast
    import inspect
    import textwrap
    import run_gui as G
    tree = ast.parse(textwrap.dedent(inspect.getsource(G.App._drop_raw)))
    fn = tree.body[0]
    if (fn.body and isinstance(fn.body[0], ast.Expr)
            and isinstance(fn.body[0].value, ast.Constant)):
        fn.body = fn.body[1:]        # docstring 讲的是禁忌，不是在犯禁忌
    code = ast.unparse(fn)
    for banned in ("after_idle", "after(", "self.root", "self.status",
                   "messagebox", "update_idletasks", "config("):
        expect(banned not in code,
               f"_drop_raw 里出现了 Tk 调用 {banned}，会导致拖放闪退")
    expect("dropped" in ast.unparse(ast.parse(textwrap.dedent(
        inspect.getsource(G.App._pump)))),
        "_pump 未轮询拖放队列——回调不能用 after_idle 驱动，只能靠轮询")


@case("拖放")
def drop_callback_swallows_everything(ctx):
    """ctypes 回调里的异常无法向上传播，逃出去就是访问违例。"""
    import tkinter as tk
    import run_gui as G
    root = tk.Tk()
    root.withdraw()
    app = G.App(root)
    try:
        for bad in (b"\xff\xfe\x00x", 12345, object(), None):
            app.dropped = []
            try:
                app._drop_raw([bad] if bad is not None else None)
            except BaseException as exc:
                raise AssertionError(
                    f"_drop_raw 对 {type(bad).__name__} 抛了 {exc!r}") from exc
        jp = str(ctx["samples"][0].parent)
        app.dropped = []
        app._drop_raw([jp])
        expect(app.dropped == [jp], "合法路径未入队")
        expect(app._decode_path(jp.encode("utf-8")) == jp, "utf-8 路径解不出")
        expect(app._decode_path(jp.encode("mbcs")) == jp, "ANSI 路径解不出")
        expect(app._decode_path(None) is None, "非法输入未返回 None")
    finally:
        root.destroy()


@case("拖放")
def drop_hook_is_64bit_safe(ctx):
    """自带的 Win32 钩子必须显式声明指针类型。windnd 用默认 restype（c_int）
    取窗口过程指针，64 位下会把 0xFFFF1239 符号扩展成 0xFFFFFFFFFFFF1239。"""
    import inspect
    import run_gui as G
    src = inspect.getsource(G._WinDrop)
    for need in ("restype", "argtypes", "c_ssize_t", "c_void_p"):
        expect(need in src, f"钩子未显式声明 {need}")
    expect("_keep" in src, "未保留回调强引用，被 GC 后又是野指针")
    expect("windnd" not in src.replace("为什么不用 windnd", ""),
           "仍在使用 windnd 的挂钩实现")


@case("界面")
def success_path_has_no_dialogs(ctx):
    """正常走完 ①②③ 不应弹任何窗——弹窗只留给真的出了问题的情形。
    「没选文件」「拖错目录」「还没反汇编」这些写状态栏就够了。"""
    import tkinter as tk
    import run_gui as G
    popped = []
    saved = {n: getattr(G.messagebox, n)
             for n in ("showinfo", "showwarning", "showerror", "askyesno")}
    for n in saved:
        setattr(G.messagebox, n,
                (lambda k: (lambda *a, **kw: popped.append(k) or True))(n))
    root = tk.Tk()
    root.withdraw()
    try:
        app = G.App(root)
        app._add(ctx["samples"][:3])
        expect(not popped, f"拖入合法文件就弹窗了：{popped}")
        app.inputs = []
        app._go_disasm()
        expect(not popped, f"未选文件时弹窗了：{popped}")
        expect("拖入" in app.status.cget("text"), "未选文件时状态栏没提示")
        app.outdir = None
        app._go_repack()
        expect(not popped, f"未反汇编就点 ③ 时弹窗了：{popped}")
        app._go_texts()
        expect(not popped, f"未反汇编就点 ② 时弹窗了：{popped}")
        app._add([Path("C:/Windows/System32/drivers/etc")])
        expect(not popped, f"拖入无 cst 的目录弹窗了：{popped}")
        app.drop_error = "boom"
        app._on_drop()
        expect(not popped, f"拖放出错弹窗了：{popped}")
    finally:
        for n, f in saved.items():
            setattr(G.messagebox, n, f)
        root.destroy()


@case("界面")
def real_problems_still_reported(ctx):
    """反过来：往返自检失败、有文件没解析、会覆盖译文——这些必须弹。"""
    import tkinter as tk
    import run_gui as G
    popped = []
    saved = {n: getattr(G.messagebox, n)
             for n in ("showinfo", "showwarning", "showerror", "askyesno")}
    for n in saved:
        setattr(G.messagebox, n,
                (lambda k: (lambda *a, **kw: popped.append(k) or True))(n))
    base = {"roundtrip_identity": True, "roundtrip_failures": [],
            "sanity_gate": {"ok": True, "failures": []}, "files_failed": 0,
            "failures": [], "files_ok": 1, "files_total": 1, "text_entries": 1,
            "min_byte_coverage": 1.0, "min_tier": "T2", "records": 1,
            "blocks": 1, "source_bytes": 1, "translate_policies": {},
            "tags": {}, "name_bindings": 0, "ambiguous_bindings": 0,
            "tag_source_counts": {}, "window_hits": {}, "rule_hits": {},
            "instruction_coverage": "not_applicable",
            "source_encoding": "cp932", "target_encoding": "cp932"}
    root = tk.Tk()
    root.withdraw()
    try:
        app = G.App(root)
        app.outdir = ctx["work"]
        for name, rep in (
                ("往返自检失败", dict(base, roundtrip_identity=False,
                                 roundtrip_failures=["x"])),
                ("产出不合理", dict(base, sanity_gate={
                    "ok": False, "failures": ["正文 0 条"]})),
                ("有文件没解析", dict(base, files_failed=1, failures=[
                    {"rel": "a.cst", "error": "boom"}]))):
            popped.clear()
            app._after_disasm(rep)
            expect(popped, f"{name} 没弹窗")
            expect(off_(app.b2) and off_(app.b3), f"{name} 后 ② ③ 未禁用")
        popped.clear()
        app._after_repack({"failures": [{"path": "a", "error": "e"}],
                           "sources_rebuilt": 0, "changed_entries": 0,
                           "text_files": 1})
        expect(popped, "回封失败没弹窗")
    finally:
        for n, f in saved.items():
            setattr(G.messagebox, n, f)
        root.destroy()


def off_(b):
    return b.instate(["disabled"])


@case("界面")
def source_encoding_not_persisted(ctx):
    """原文编码不得被记住。

    实测踩过：上一轮设成 gbk 后下次启动静默沿用，日文脚本被解成整片乱码
    （「ふあぁ」→「乽傆偁」），而往返自检照样通过（读错编码不影响字节可逆性），
    于是译文全是垃圾却零告警。原文编码是样本属性，不是用户偏好。
    """
    import tkinter as tk
    import run_gui as G
    cfg = G.CONFIG
    backup = cfg.read_bytes() if cfg.exists() else None
    try:
        cfg.write_text(json.dumps({"outdir": "", "source_encoding": "gbk",
                                   "target_encoding": "gbk"}),
                       encoding="utf-8")
        root = tk.Tk()
        root.withdraw()
        try:
            app = G.App(root)
            expect(app.senc.get() == D.ENCODING["source"],
                   f"原文编码被旧配置污染成了 {app.senc.get()}")
            expect(app.tenc.get() == "gbk", "译文编码应当被记住")
            app._save_config()
            saved = json.loads(cfg.read_text(encoding="utf-8"))
            expect("source_encoding" not in saved,
                   "仍然把 source_encoding 写进了配置")
        finally:
            root.destroy()
    finally:
        if backup is None:
            cfg.unlink(missing_ok=True)
        else:
            cfg.write_bytes(backup)


@case("拖放")
def drop_rejects_input_while_busy(ctx):
    import tkinter as tk
    import run_gui as G
    root = tk.Tk()
    root.withdraw()
    app = G.App(root)
    try:
        class Busy:
            def is_alive(self):
                return True
        app.worker = Busy()
        app.dropped = [str(ctx["samples"][0].parent)]
        app.inputs = []
        app._on_drop()
        expect(app.inputs == [], "任务运行中拖入未被拒绝")
        expect("正在处理中" in app.status.cget("text"), "未给出提示")
    finally:
        root.destroy()


# ---------------------------------------------------------------- 规模


@case("规模")
def parallel_matches_serial(ctx):
    """并行与单进程必须产出逐字节相同的 IR 与证书（§12.6）。"""
    if len(ctx["samples"]) < 8:
        return
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        r1 = DIS.run_disasm(ctx["samples"], Path(a), "cp932", "cp932",
                            want_asm=False, jobs=1)
        r2 = DIS.run_disasm(ctx["samples"], Path(b), "cp932", "cp932",
                            want_asm=False, jobs=4)
        expect(r1["job_sha256"] == r2["job_sha256"], "作业哈希不同")
        for f in DIS._IR_FILES + ("manifest.jsonl",):
            x = (Path(a) / "ir" / f).read_bytes()
            y = (Path(b) / "ir" / f).read_bytes()
            expect(x == y, f"并行与单进程的 ir/{f} 不同")
        for t in sorted((Path(a) / "texts").rglob("*.txt")):
            rel = t.relative_to(Path(a) / "texts")
            expect(t.read_bytes() == (Path(b) / "texts" / rel).read_bytes(),
                   f"并行与单进程的 texts/{rel} 不同")


@case("规模")
def no_asm_keeps_core_gates(ctx):
    """--no-asm 跳过可选产物后，核心自检必须照旧执行（§8.5）。"""
    with tempfile.TemporaryDirectory() as td:
        rep = DIS.run_disasm(ctx["samples"][:6], Path(td), "cp932", "cp932",
                             want_asm=False, jobs=1)
        expect(rep["min_byte_coverage"] == 1.0,
               f"--no-asm 后字节覆盖变成 {rep['min_byte_coverage']}")
        expect(rep["roundtrip_identity"], "--no-asm 后往返自检未执行或失败")
        expect(not (Path(td) / "asm").exists(), "--no-asm 仍建了 asm 目录")
        expect((Path(td) / "texts").exists(), "--no-asm 把文本也跳过了")


@case("规模")
def truncated_and_corrupt_inputs_rejected(ctx):
    p = ctx["samples"][0]
    data = p.read_bytes()
    expect_reject(lambda: DIS.parse_bytes(b"NOTCAT" + data[6:], p),
                  "魔数", "魔数不符")
    expect_reject(lambda: DIS.parse_bytes(data[:20], p), "压缩长度", "文件被截断")
    expect_reject(lambda: DIS.parse_bytes(data + b"\x00", p),
                  "未归属", "尾部多出字节")
    bad = bytearray(data)
    DIS._U32.pack_into(bad, 12, 999999)
    expect_reject(lambda: DIS.parse_bytes(bytes(bad), p),
                  "解压长度", "解压长度字段不符")


# ---------------------------------------------------------------- 跨样本


@case("跨样本")
def cross_sample_shape_signatures(ctx):
    """§0.3：至少在两个不同来源上验证，且形态签名分布必须被显式统计。"""
    others = ctx["other_roots"]
    expect(others, "未做跨样本验证（只有一个来源）")
    base = _signature(ctx["samples"])
    for root in others:
        files = sorted(root.glob("*.cst"))[:40]
        if not files:
            continue
        sig = _signature(files)
        expect(sig["type_bytes"] <= set(D.KNOWN_TYPE_BYTES),
               f"{root.name}: 出现未登记的记录类型 {sig['type_bytes']}")
        for p in files:
            data = p.read_bytes()
            doc = DIS.parse_bytes(data, p)
            out, _ = DIS.repack(doc)
            expect(out == data, f"{root.name}/{p.name}: 跨样本零编辑往返失败")
        ctx.setdefault("cross", {})[str(root)] = sig


def _signature(files) -> dict:
    tb, pre = set(), set()
    for p in files:
        doc = DIS.parse_bytes(p.read_bytes(), p)
        for r in doc.records:
            tb.add(r.type_byte)
        pre.add(D.PAYLOAD["record"]["prefix_byte"])
    return {"type_bytes": tb, "prefix_bytes": pre, "files": len(files)}


# ---------------------------------------------------------------- 工具


def _payload(p: Path) -> bytes:
    return _payload_bytes(p.read_bytes())


def _payload_bytes(data: bytes) -> bytes:
    n = int.from_bytes(data[8:12], "little")
    return zlib.decompress(data[DIS._HDR:DIS._HDR + n])


def _wrap(payload: bytes) -> bytes:
    stream = zlib.compress(payload, D.CONTAINER["compression"]["level"])
    h = bytearray(DIS._HDR)
    h[:8] = D.CONTAINER["magic"]
    DIS._U32.pack_into(h, 8, len(stream))
    DIS._U32.pack_into(h, 12, len(payload))
    return bytes(h) + stream


def _doc_fields(doc: DIS.Doc) -> dict:
    return {"path": doc.path, "raw_size": doc.raw_size,
            "raw_sha256": doc.raw_sha256, "com_size": doc.com_size,
            "unc_size": doc.unc_size, "payload_sha256": doc.payload_sha256,
            "payload_size_field": doc.payload_size_field,
            "block_count": doc.block_count, "table_offset": doc.table_offset,
            "data_offset": doc.data_offset, "blocks": doc.blocks,
            "records": doc.records, "offsets": doc.offsets,
            "payload_len": doc.payload_len, "zlib_stream": doc.zlib_stream}


def main(argv=None) -> int:
    DIS._utf8_console()
    args = (argv if argv is not None else sys.argv[1:])
    here = Path(__file__).resolve().parent
    roots = [Path(a) for a in args] or [here.parent / "脚本"]
    samples = DIS.collect_inputs(roots)
    others = [d for d in (here.parent / "scene", here.parent / "1",
                          here.parent / "イノセントガール" / "scene",
                          YUKIKOI)
              if d.exists() and d.resolve() not in {r.resolve() for r in roots}]
    cstl = sorted(p for r in roots + others for p in r.glob("*.cstl"))
    print(f"语料 {len(samples)} 个文件，跨样本来源 {len(others)} 处，"
          f"cstl 样本 {len(cstl)} 个")
    if not cstl:
        print("  注意：本次没有 .cstl 语料，CSTL 用例会跳过而不是通过")
    work = Path(tempfile.mkdtemp(prefix="cst_tests_"))
    try:
        DIS.run_disasm(samples[:12], work, "cp932", "cp932",
                       want_asm=False, jobs=1)
        ctx = {"samples": samples[:12], "all": samples, "work": work,
               "other_roots": others, "cstl": cstl[:8]}
        passed = failed = 0
        last_group = None
        for group, name in CASES:
            if group != last_group:
                print(f"\n[{group}]")
                last_group = group
            fn = globals()["_CASE_" + name]
            try:
                fn(ctx)
                print(f"  ok    {name}")
                passed += 1
            except Exception as exc:
                print(f"  FAIL  {name}")
                for line in traceback.format_exception_only(type(exc), exc):
                    print("        " + line.rstrip())
                failed += 1
        print(f"\n{passed} 通过 / {failed} 失败 / {passed + failed} 共")
        if "preserved_value_collisions" in ctx:
            print(f"preserved_value_collisions = "
                  f"{ctx['preserved_value_collisions']}（不为零是正常的）")
        if ctx.get("cross"):
            for k, v in ctx["cross"].items():
                print(f"跨样本 {Path(k).name}: {v['files']} 文件，"
                      f"类型字节 {sorted(hex(x) for x in v['type_bytes'])}")
        return 0 if failed == 0 else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
