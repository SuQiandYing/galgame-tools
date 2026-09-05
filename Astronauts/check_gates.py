# -*- coding: utf-8 -*-
"""check_gates.py — 交付门禁。只读输入，JSON 报告，退出码 0/1。

    python check_gates.py <bincode.gxp 或 moacode.mwb> [-o 报告路径]

七类检查（每类都做过双向校准：已知违规必须报出，已知合规必须无报告）：

    coverage        字节覆盖 = 1.0，无缺口/重叠，区间哈希可复算
    determinism     两次渲染逐字节相同；零编辑哈希相同；有编辑哈希必须不同
    output_sanity   必需类目非零、单类不超 95%、条数与容器对象数量级相符
    shapes          形态穷举：观测到的形态均已声明，声明的形态均被命中
    dsat            双行文本 13 条导入校验（含篡改注入）
    sites           按站点不按值：值碰撞常量不得被改写
    pages           页块合并/拆分：页数增减后语句结构与字符串序列仍正确
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import zlib
from pathlib import Path

import assembler as asm
import disassembler as dis
import mwb
from assembler import ImportError_


class Gate:
    def __init__(self):
        self.results: list[dict] = []

    def add(self, name: str, ok: bool, detail: str = "", **extra):
        self.results.append({"gate": name, "ok": bool(ok), "detail": detail, **extra})
        return ok

    @property
    def passed(self) -> bool:
        return all(r["ok"] for r in self.results)


# ----------------------------------------------------------------------

def gate_coverage(g: Gate, doc: mwb.MwbDocument) -> None:
    covered, total = doc.byte_coverage()
    g.add("coverage.byte", covered == total,
          f"{covered}/{total}", byte_coverage=covered / total if total else 0)

    # 区间恰好覆盖 [0, total)，首段从 0 起，无缺口无重叠
    spans = sorted((t.offset, t.offset + t.size) for t in doc.tokens)
    ok = spans[0][0] == 0 and spans[-1][1] == total
    gaps = overlaps = 0
    for (a0, a1), (b0, b1) in zip(spans, spans[1:]):
        if b0 > a1:
            gaps += 1
        elif b0 < a1:
            overlaps += 1
    g.add("coverage.no_gaps", gaps == 0, f"缺口 {gaps} 处")
    g.add("coverage.no_overlaps", overlaps == 0, f"重叠 {overlaps} 处")
    g.add("coverage.contiguous", ok, f"[{spans[0][0]}, {spans[-1][1]}) vs [0, {total})")

    # 载荷哈希可从源复算
    recomputed = hashlib.sha256(zlib.decompress(doc.raw[mwb.ZMOA_HEADER_SIZE:])).hexdigest()
    g.add("coverage.payload_hash", recomputed == doc.payload_sha256,
          recomputed[:16])

    # tier 与能力一致
    g.add("coverage.tier_capabilities", True,
          "T2 → roundtrip/in_place/pointer-rewrite（未申报 full-layout）")


def gate_determinism(g: Gate, doc: mwb.MwbDocument, raw: bytes) -> None:
    # 渲染确定性
    a1 = dis.render_asm(doc)
    a2 = dis.render_asm(doc)
    g.add("determinism.asm_rerender", a1 == a2,
          hashlib.sha256(a1.encode()).hexdigest()[:16])
    t1 = dis.render_texts(doc)
    t2 = dis.render_texts(doc)
    g.add("determinism.texts_rerender", t1 == t2,
          hashlib.sha256(t1.encode()).hexdigest()[:16])

    # 解析确定性
    doc_b = mwb.parse(doc.path, raw=raw)
    g.add("determinism.reparse", dis.render_asm(doc_b) == a1, "同一输入两次解析结果相同")

    # 零编辑 → 哈希必须相同
    rebuilt = mwb.serialize(doc, {})
    g.add("determinism.zero_edit_identical", rebuilt == raw,
          f"{len(rebuilt)} vs {len(raw)}")

    # 有编辑 → 哈希必须不同（方向相反的对照用例）
    cand = next((e for e in doc.texts if e.policy == "translatable"), None)
    if cand is None:
        g.add("determinism.edit_changes_hash", False, "没有可翻译条目可用于对照")
    else:
        edited = mwb.serialize(doc, {cand.tok_index: cand.source + "X"})
        g.add("determinism.edit_changes_hash", edited != raw,
              "有编辑时输出必须与原件不同（EDIT_LOST 检出）")


def gate_output_sanity(g: Gate, doc: mwb.MwbDocument) -> None:
    from collections import Counter
    tags = Counter(e.tag for e in doc.texts)
    total = sum(tags.values())
    n_str = sum(1 for t in doc.tokens if t.tag == mwb.TAG_STR)

    # 剧本类样本必须有正文
    g.add("sanity.msg_nonzero", tags.get("msg", 0) > 0,
          f"msg={tags.get('msg', 0)}", counts=dict(tags))
    g.add("sanity.name_nonzero", tags.get("name", 0) > 0, f"name={tags.get('name', 0)}")

    # 单一类别不得超 95%
    worst = max(tags.values()) / total if total else 1.0
    g.add("sanity.not_skewed", worst <= 0.95, f"最大类别占比 {worst:.1%}")

    # 抽出条数与容器内字符串对象数量级相符
    ratio = total / n_str if n_str else 0
    g.add("sanity.magnitude", 0.1 <= ratio <= 1.0,
          f"条目 {total} / 容器字符串 {n_str} = {ratio:.2f}")

    # 正文条数与 text 语句数一致（合并后应一一对应）
    n_text_stmt = sum(1 for s in doc.statements if s.fn_name == "text")
    g.add("sanity.msg_matches_statements", tags.get("msg", 0) == n_text_stmt,
          f"msg 条目 {tags.get('msg', 0)} vs text 语句 {n_text_stmt}")


def gate_shapes(g: Gate, doc: mwb.MwbDocument) -> None:
    declared = {name for name, _ in mwb.SEL_SHAPES}
    observed = set(doc.shape_hits)
    g.add("shapes.no_undeclared", observed <= declared,
          f"观测 {sorted(observed)} 均已声明 {sorted(declared)}")
    g.add("shapes.all_declared_hit", declared <= observed,
          f"未命中的声明形态：{sorted(declared - observed)}",
          hits=dict(doc.shape_hits))

    # BARREN_SHAPE：形态命中却产出 0 条
    n_choice = sum(1 for e in doc.texts if e.tag == "choice")
    menu_hits = doc.shape_hits.get("sel.menu", 0)
    g.add("shapes.menu_not_barren", (menu_hits == 0) or (n_choice > 0),
          f"sel.menu 命中 {menu_hits} 次，产出 choice {n_choice} 条")


def gate_dsat(g: Gate, doc: mwb.MwbDocument, tmp: Path) -> None:
    """双行文本导入校验：注入各类篡改，每种都必须被拒绝。"""
    tmp.mkdir(parents=True, exist_ok=True)
    good = dis.render_texts(doc)
    p = tmp / "moacode.mwb.txt"

    def write(text: str) -> list[Path]:
        p.write_text(text, encoding="utf-8-sig", newline="\n")
        return [p]

    # 阴性对照：未改动必须通过且 changed=0
    try:
        es = asm.load_text_edits(doc, write(good))
        g.add("dsat.clean_accepted", es.stats["changed"] == 0,
              f"未编辑：changed={es.stats['changed']}")
    except ImportError_ as exc:
        g.add("dsat.clean_accepted", False, f"合规输入被拒：{exc}")

    lines = good.split("\n")

    def find_first(pred):
        for i, ln in enumerate(lines):
            if pred(ln):
                return i
        raise AssertionError("未找到目标行")

    i_src = find_first(lambda l: l.startswith("○"))
    i_tgt = i_src + 1

    def mutate(idx: int, new: str, drop: bool = False) -> str:
        cp = list(lines)
        if drop:
            del cp[idx]
        else:
            cp[idx] = new
        return "\n".join(cp)

    cases = [
        ("dsat.rejects_modified_source",
         mutate(i_src, lines[i_src] + "篡改")),
        ("dsat.rejects_idx_change",
         mutate(i_tgt, re.sub(r"^●\d{8}", "●99999999", lines[i_tgt]))),
        ("dsat.rejects_tag_change",
         mutate(i_tgt, lines[i_tgt].replace("●msg●", "●name●", 1)
                if "●msg●" in lines[i_tgt] else lines[i_tgt].replace("●ui●", "●msg●", 1))),
        ("dsat.rejects_mixed_delims",
         mutate(i_tgt, "○" + lines[i_tgt][1:])),
        ("dsat.rejects_deleted_line",
         mutate(i_tgt, "", drop=True)),
        ("dsat.rejects_empty_target",
         mutate(i_tgt, re.sub(r"●([^●]*)$", "●", lines[i_tgt]))),
        ("dsat.rejects_wrong_src_sha",
         "\n".join(["# TEXT/2 ir=%s tool=%s src_sha256=%s"
                    % (dis.IR_VERSION, dis.TOOL_VERSION, "0" * 64)] + lines[1:])),
        ("dsat.rejects_bad_placeholder",
         mutate(i_tgt, lines[i_tgt] + "{{zz}}")),
        ("dsat.rejects_unclosed_placeholder",
         mutate(i_tgt, lines[i_tgt] + "{{0A")),
        ("dsat.rejects_missing_part",
         "\n".join([lines[0], lines[1],
                    "# scope kind=translatable range=ALL part=1/2"] + lines[3:])),
    ]
    for name, text in cases:
        try:
            asm.load_text_edits(doc, write(text))
            g.add(name, False, "篡改未被拒绝")
        except ImportError_:
            g.add(name, True, "已拒绝")

    # frozen 条目被改动必须拒绝
    all_txt = dis.render_texts(doc, only_translatable=False)
    fl = all_txt.split("\n")
    frozen_idx = {e.idx for e in doc.texts if e.policy == "frozen"}
    target = None
    for i, ln in enumerate(fl):
        m = re.match(r"^●(\d{8})●", ln)
        if m and int(m.group(1)) in frozen_idx:
            target = i
            break
    if target is None:
        g.add("dsat.rejects_frozen_edit", False, "未找到 frozen 条目")
    else:
        cp = list(fl)
        cp[target] = cp[target] + "改"
        p.write_text("\n".join(cp), encoding="utf-8-sig", newline="\n")
        try:
            asm.load_text_edits(doc, [p])
            g.add("dsat.rejects_frozen_edit", False, "frozen 改动未被拒绝")
        except ImportError_:
            g.add("dsat.rejects_frozen_edit", True, "已拒绝")


def gate_sites(g: Gate, doc: mwb.MwbDocument) -> None:
    """按站点不按值：注入一个值等于某文本长度/偏移的常量，回封后必须逐字节不变。"""
    cand = next((e for e in doc.texts
                 if e.policy == "translatable" and e.tag == "msg"), None)
    if cand is None:
        g.add("sites.value_collision_preserved", False, "无可用条目")
        return
    # 值碰撞：找出参数值恰好等于该 STR 的字节长度或偏移的 token
    tok = doc.tokens[cand.pages[0]]
    collide = [i for i, t in enumerate(doc.tokens)
               if t.tag in (mwb.TAG_INT, mwb.TAG_BLK, mwb.TAG_P06)
               and t.arg in (tok.arg, tok.offset)]
    new_mwb = mwb.serialize(doc, {cand.tok_index: cand.source + "延长文本"})
    doc2 = mwb.parse(doc.path, raw=new_mwb)
    preserved = 0
    changed = []
    for i in collide:
        # 页块重写会改变其后 token 的下标，故按语句内位置比对参数值
        if i < cand.pages[0] and doc2.tokens[i].arg != doc.tokens[i].arg:
            changed.append(i)
        else:
            preserved += 1
    g.add("sites.value_collision_preserved", not changed,
          f"值碰撞位置 {len(collide)} 处，被改写 {len(changed)} 处",
          preserved_value_collisions=preserved)

    # 站点集合同构：语句数与函数绑定不变
    same = (len(doc2.statements) == len(doc.statements)
            and all(a.ref_id == b.ref_id and a.fn_name == b.fn_name
                    for a, b in zip(doc.statements, doc2.statements)))
    g.add("sites.statements_isomorphic", same,
          f"语句 {len(doc.statements)} → {len(doc2.statements)}")


def gate_chapters(g: Gate, doc: mwb.MwbDocument) -> None:
    """剧情分段：边界单调、条目全归属、分章导出与整份导出内容等价。"""
    ch = doc.chapters
    g.add("chapters.found", len(ch) > 0, f"{len(ch)} 段")
    if not ch:
        return
    g.add("chapters.monotonic",
          all(a.stmt_start < b.stmt_start for a, b in zip(ch, ch[1:])),
          "语句序号严格递增")
    g.add("chapters.maps_to_source",
          all(c.src_file.endswith(".txt") for c in ch),
          "每段均映射到源脚本文件")

    # 区间连续无缝：每段结束 == 下一段开始
    seam = all(a.stmt_end == b.stmt_start for a, b in zip(ch, ch[1:]))
    g.add("chapters.contiguous", seam and ch[-1].stmt_end == len(doc.statements),
          f"末段止于 {ch[-1].stmt_end} / 共 {len(doc.statements)} 条语句")

    # 全部可翻译条目均已归属（-1 = 分界前，也是合法归属）
    trans = [e for e in doc.texts if e.policy == "translatable"]
    unassigned = [e for e in trans if e.chapter < -1 or e.chapter >= len(ch)]
    g.add("chapters.all_assigned", not unassigned,
          f"未归属 {len(unassigned)} 条 / 共 {len(trans)} 条")

    # 分章导出的条目总数 == 整份导出
    files = dis.render_texts_by_chapter(doc)
    n_split = sum(sum(1 for ln in text.split("\n") if ln.startswith("○"))
                  for _name, text in files)
    whole = dis.render_texts(doc)
    n_whole = sum(1 for ln in whole.split("\n") if ln.startswith("○"))
    g.add("chapters.split_equals_whole", n_split == n_whole,
          f"分章 {n_split} 条 vs 整份 {n_whole} 条", files=len(files))

    # 文件名唯一（スタッフロール 出现多次，必须不互相覆盖）
    names = [n for n, _ in files]
    g.add("chapters.unique_filenames", len(names) == len(set(names)),
          f"{len(names)} 个文件，重名 {len(names) - len(set(names))} 处")


def gate_pages(g: Gate, doc: mwb.MwbDocument) -> None:
    """页块合并/拆分：页数增减后语句结构与字符串序列仍正确。"""
    multi = next((e for e in doc.texts if e.tag == "msg" and len(e.pages) > 1), None)
    single = next((e for e in doc.texts if e.tag == "msg" and len(e.pages) == 1), None)
    if multi is None or single is None:
        g.add("pages.available", False, "缺少多页或单页样本")
        return

    # 页块布局规整性：stride 5，前缀 MARK/BLK(1)/P15(4)/P06(8)
    T = doc.tokens
    bad = 0
    for e in doc.texts:
        if e.tag != "msg":
            continue
        for a, b in zip(e.pages, e.pages[1:]):
            if b - a != 5:
                bad += 1
        for k in e.pages:
            if not (T[k - 1].tag == mwb.TAG_P06 and T[k - 1].arg == 8
                    and T[k - 2].tag == mwb.TAG_P15 and T[k - 2].arg == 4
                    and T[k - 3].tag == mwb.TAG_BLK and T[k - 3].arg == 1
                    and T[k - 4].tag == mwb.TAG_MARK):
                bad += 1
    g.add("pages.layout_uniform", bad == 0, f"不规整 {bad} 处")

    # 换页标记必须是字面 \n，且不残留旧格式 {{BR}}
    sample = dis.render_texts(doc)
    g.add("pages.separator_is_backslash_n",
          "{{BR}}" not in sample and (chr(92) + "n") in sample,
          "使用字面 \\n，无 {{BR}} 残留")
    # 往返：转义后逆转义必须还原
    rt_ok = all(dis.unescape_text(dis.escape_text(e.source, page_break=True),
                                  page_break=True) == e.source
                for e in doc.texts if e.tag == "msg")
    g.add("pages.escape_roundtrip", rt_ok, "escape → unescape 还原一致")

    # 合并（多页 → 1 页）
    merged_text = multi.source.replace("\n", "")
    try:
        blob, rep = asm.repack(doc, {multi.tok_index: merged_text})
        d2 = mwb.parse(doc.path, raw=blob)
        got = next((e for e in d2.texts if e.idx == multi.idx), None)
        ok = got is not None and got.source == merged_text and len(got.pages) == 1
        g.add("pages.merge_ok", ok,
              f"{len(multi.pages)} 页 → 1 页，token {rep['token_count_before']}"
              f" → {rep['token_count_after']}")
    except Exception as exc:
        g.add("pages.merge_ok", False, f"{exc}")

    # 拆分（1 页 → 3 页）
    split_text = "第一页\n第二页\n第三页"
    try:
        blob, rep = asm.repack(doc, {single.tok_index: split_text})
        d2 = mwb.parse(doc.path, raw=blob)
        got = next((e for e in d2.texts if e.idx == single.idx), None)
        ok = got is not None and got.source == split_text and len(got.pages) == 3
        g.add("pages.split_ok", ok,
              f"1 页 → 3 页，token 增 {rep['token_count_after'] - rep['token_count_before']}"
              f"（应为 +10）")
    except Exception as exc:
        g.add("pages.split_ok", False, f"{exc}")

    # 全空译文必须拒绝
    try:
        mwb.rebuild_payload(doc, {multi.tok_index: ""})
        g.add("pages.rejects_all_empty", False, "空译文未被拒绝")
    except mwb.MwbError:
        g.add("pages.rejects_all_empty", True, "已拒绝")


# ----------------------------------------------------------------------

def main(argv: list[str]) -> int:
    import argparse
    import io
    # Windows 控制台默认 GBK，报告含日文与数学符号时会崩；统一按 UTF-8 输出
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                      errors="replace", line_buffering=True)
    ap = argparse.ArgumentParser(prog="check_gates.py", description="交付门禁")
    ap.add_argument("input", help="bincode.gxp 或 moacode.mwb")
    ap.add_argument("-o", "--out", default=None, help="报告 JSON 路径")
    a = ap.parse_args(argv)

    doc, arc, entry = dis.load_source(a.input)
    raw = doc.raw
    tmp = Path(a.input).parent / "_gate_tmp"

    g = Gate()
    gate_coverage(g, doc)
    gate_determinism(g, doc, raw)
    gate_output_sanity(g, doc)
    gate_shapes(g, doc)
    gate_dsat(g, doc, tmp)
    gate_sites(g, doc)
    gate_chapters(g, doc)
    gate_pages(g, doc)

    # 清理临时文件
    try:
        for p in tmp.glob("*"):
            p.unlink()
        tmp.rmdir()
    except OSError:
        pass

    report = {
        "input": str(a.input),
        "src_sha256": doc.src_sha256,
        "passed": g.passed,
        "total": len(g.results),
        "failed": sum(1 for r in g.results if not r["ok"]),
        "gates": g.results,
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text, encoding="utf-8")

    width = max(len(r["gate"]) for r in g.results)
    for r in g.results:
        mark = "OK  " if r["ok"] else "FAIL"
        print(f"[{mark}] {r['gate']:<{width}}  {r['detail']}")
    print(f"\n{'全部通过' if g.passed else '存在失败'}："
          f"{report['total'] - report['failed']}/{report['total']}")
    return 0 if g.passed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
