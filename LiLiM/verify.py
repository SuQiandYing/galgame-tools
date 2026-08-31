# -*- coding: utf-8 -*-
"""跑全部门禁并汇总（§8.2 / §9）。

零编辑往返、变长回封、以及 skill 自带的门禁脚本，全部在此一次执行。
非剧本脚本（菜单/窗口定义/宏，0 对话 0 旁白行）以 --allow-zero 显式豁免，
豁免依据由本脚本重新核算，不采信声明。
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import aoslib as A
import disassembler as DIS
import opcodelist as D

GATES = Path(r"C:\Users\g2985\.claude\skills\lossless-text-repack\scripts")

SITES_PROBE_EDITS = 6            # dialect-literal-ok: 变长探测改动的条数
SITES_PROBE_SUFFIX = "延長テスト"   # 附加到译文尾部，制造长度变化


def run(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run([sys.executable] + cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def non_scenario_samples(src: Path, ir_bundle=None) -> tuple[list[str], dict[str, float]]:
    """独立重算哪些脚本不属剧本类，用以核对报告的分类，不采信报告自身（§8.3）。

    判据与 disassembler 相同（正文行占比），但在此处由 IR 重新推导，**不读报告**——
    独立性来自「不采信报告的分类结论」，而非「再解析一遍源字节」：解析是确定的，
    两次必得同一份 IR，因此复用 IR 不削弱该校验（§12.8）。
    """
    arc, scripts, _ = ir_bundle or DIS.build_ir(src)
    out: list[str] = []
    ratios: dict[str, float] = {}
    for ir in scripts:
        sc = Counter(ir.shapes)
        body = sc.get("dialogue", 0) + sc.get("narration", 0)
        ratio = body / len(ir.lines) if ir.lines else 0.0
        ratios[ir.name] = ratio
        if not body or ratio < DIS.SCENARIO_BODY_RATIO:
            out.append(ir.name)
    return out, ratios


def run_sites_gate(src: Path, out: Path) -> tuple[int, str]:
    """做一次变长回封，再用 check_sites.py 验证改写是按站点而非按值。

    变长是该门禁生效的前提：等长输出下按值改写与按站点改写不可区分。
    """
    import shutil
    import assembler

    work = out / "tmp" / "sites_probe"
    if work.exists():
        shutil.rmtree(work)
    bundle = DIS.build_ir(src)
    DIS.extract_texts(src, work, bundle, with_ir=True)

    # 挑一个含正文的脚本，把若干条译文改长
    target = next((ir for ir in bundle[1]
                   if sum(1 for s in ir.slots if s.tag == "msg") >= SITES_PROBE_EDITS),
                  None)
    if target is None:
        return 1, "语料中找不到可用于变长探测的脚本"
    tp = work / "texts" / f"{target.name}.txt"
    done = [0]

    def bump(m: "re.Match[str]") -> str:
        if done[0] < SITES_PROBE_EDITS and m.group(2) == "msg":
            done[0] += 1
            return m.group(1) + m.group(3) + SITES_PROBE_SUFFIX
        return m.group(0)

    tp.write_text(re.sub(r"^(●\d{8}●([a-z_]+)●)(.*)$", bump,
                         tp.read_text(encoding="utf-8"), flags=re.M),
                  encoding="utf-8", newline="\n")
    rep = assembler.repack(src, work)
    if rep["length_delta"] == 0:
        return 1, "变长探测未改变长度，门禁无法生效"

    # 门禁需要 old -> new 的映射，从重定位日志补进站点记录
    sites = [json.loads(l) for l in
             (work / "ir" / "join_sites.jsonl").read_text(encoding="utf-8").splitlines()]
    reloc = {r["join_id"]: r for r in
             (json.loads(l) for l in (work / "reports" / "relocation_log.jsonl")
              .read_text(encoding="utf-8").splitlines())}
    for s in sites:
        r = reloc.get(s["join_id"])
        s["new_key_value"] = r["new_value"] if r else s["key_value"]
    mapped = work / "ir" / "join_sites_mapped.jsonl"
    mapped.write_text("".join(json.dumps(s, ensure_ascii=False) + "\n" for s in sites),
                      encoding="utf-8", newline="\n")

    return run([str(GATES / "check_sites.py"), str(src), rep["output"], str(mapped),
                "--relocation-log", str(work / "reports" / "relocation_log.jsonl"),
                "--report", str(out / "reports" / "g_sites.json")])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="门禁汇总")
    ap.add_argument("archive", type=Path)
    ap.add_argument("-o", "--outdir", type=Path, default=None)
    ap.add_argument("--with-sites", action="store_true",
                    help="附加站点级改写门禁（变长回封 + check_sites，耗时数分钟）")
    a = ap.parse_args(argv)

    src = a.archive.resolve()
    out = (a.outdir or DIS.default_outdir(src)).resolve()
    paths = DIS.layout(out)
    rep = paths["reports"]
    results: list[dict] = []
    detail_cap = 400   # dialect-literal-ok: 报告截断长度
    print_cap = 90     # dialect-literal-ok: 终端一行的显示宽度

    def record(name: str, code: int, detail: str = "") -> None:
        results.append({"gate": name, "ok": code == 0,
                        "detail": detail.strip()[:detail_cap]})

    # 解析一次，供本函数内多处复用（§12.8：解析确定，重算只是把 3.2 秒做第二遍）
    bundle = DIS.build_ir(src)

    # --- 1. 零编辑往返（§9 第一步；判定方向：必须逐字节相同）
    import assembler
    rc = assembler.repack(src, out, texts_dir=None, verify_only=True,
                          ir_bundle=bundle)
    record("roundtrip_identity(zero-edit)", 0 if rc["identical"] else 1,
           f"rebuilt_sha={rc['rebuilt_sha256'][:16]} src_sha={rc['src_sha256'][:16]}")

    # --- 2. 渲染确定性（§2.6：两次运行逐字节相同）
    # 必须各自重新解析：若复用同一份 IR，只能证明 render 是纯函数，
    # 而待证的是「同一源字节两次解析+渲染得到相同结果」（§12.8 的反面——
    # 这里的第二次解析确实提供信息，不可省）。渲染全部脚本而非仅第一个。
    ir_a = DIS.build_ir(src)[1]
    ir_b = DIS.build_ir(src)[1]
    a1 = [DIS.render_asm_text(x) for x in ir_a]
    a2 = [DIS.render_asm_text(x) for x in ir_b]
    t1 = [DIS.render_dsat(x) for x in ir_a]
    t2 = [DIS.render_dsat(x) for x in ir_b]
    same = a1 == a2 and t1 == t2
    record("render_determinism", 0 if same else 1,
           f"asm+texts 各 {len(ir_a)} 个文件两轮解析渲染逐字节一致" if same
           else "两轮渲染结果不同")

    # --- 3. 完备性不变式：msg 条数 == 对话行 + 旁白行，逐文件断言
    inv = json.loads((rep / "completeness_invariant.json").read_text(encoding="utf-8"))
    record(f"completeness_invariant({inv['checked_samples']} 个脚本全覆盖)",
           0 if inv["ok"] else 1,
           inv["rule"] if inv["ok"] else json.dumps(inv["violations"][:3], ensure_ascii=False))

    # --- 4. 产出合理性：剧本脚本必须有 msg，不得豁免
    code, txt = run([str(GATES / "check_output_sanity.py"),
                     str(rep / "extract_report.json"),
                     "--report-out", str(rep / "g_sanity.json")])
    record("output_sanity(剧本脚本)", code, txt)

    # 引擎配置脚本（0 对话 0 旁白行）单独判定并显式豁免 msg。
    # 豁免依据由 narrative_free_samples 重算，不采信声明（§8.3）。
    exempt, ratios = non_scenario_samples(src, bundle)
    plumbing = rep / "extract_report_plumbing.json"
    rows = json.loads(plumbing.read_text(encoding="utf-8"))
    textless = json.loads(
        (rep / "extract_report_textless.json").read_text(encoding="utf-8"))["samples"]

    # 分类自检：报告的两类之和必须与独立重算的集合完全一致
    reported = {r["sample"] for r in rows} | {t["sample"] for t in textless}
    unexpected = sorted(reported - set(exempt))
    missing = sorted(set(exempt) - reported)
    record("非剧本分类自检", 1 if (unexpected or missing) else 0,
           f"多归入 {unexpected} 少归入 {missing}" if (unexpected or missing)
           else f"配置 {len(rows)} + 无文本 {len(textless)} == 重算 {len(exempt)}")

    # 无文本脚本：判据是结构而非豁免——非 comment 行不得含非 ASCII 字符
    leak = [t["sample"] for t in textless
            if t["nonascii_outside_comments"] or t["string_literals"]]
    record(f"textless 结构证据({len(textless)} 个)", 1 if leak else 0,
           f"这些脚本在注释外仍有非 ASCII 内容，可能漏抽：{leak}" if leak
           else "非 ASCII 仅出现在 #comment 行，无字符串字面量")

    if rows:
        code, txt = run([str(GATES / "check_output_sanity.py"), str(plumbing),
                         "--allow-zero", "msg",
                         "--report-out", str(rep / "g_sanity_plumbing.json")])
        # 配置脚本按定义是异质总体（菜单/窗口/路由各自密度不同），
        # DENSITY_SPREAD 在此不是可靠判据；按 §8.3 第 4 条记 advisory 而不阻断。
        # 其余任何 code 仍然阻断——豁免只针对这一个判据，且必须逐条核对。
        try:
            j = json.loads((rep / "g_sanity_plumbing.json").read_text(encoding="utf-8"))
            codes = {i["code"] for i in j.get("issues", [])}
            hard = codes - {"DENSITY_SPREAD"}
            advisory = sorted(codes & {"DENSITY_SPREAD"})
        except (OSError, json.JSONDecodeError):
            hard, advisory = {"REPORT_UNREADABLE"}, []
        record(f"output_sanity(配置脚本 {len(rows)} 个)", 1 if hard else 0,
               f"阻断项 {sorted(hard)}" if hard
               else f"advisory={advisory}（异质总体，密度离散不可判）")

    code, txt = run([str(GATES / "check_shapes.py"), str(rep / "shapes.json"),
                     "--corpus-wide", "--report-out", str(rep / "g_shapes.json")])
    record("shapes(corpus-wide)", code, txt)

    code, txt = run([str(GATES / "coverage_certificate.py"), str(src),
                     str(rep / "coverage_certificate.json"),
                     "--report", str(rep / "g_cov.json")])
    record("coverage_certificate", code, txt)

    code, txt = run([str(GATES / "check_dsat.py"), str(paths["ir"]),
                     str(paths["texts"]), "--report", str(rep / "g_dsat.json")])
    record("dsat(13 项导入校验)", code, txt)

    code, txt = run([str(GATES / "check_no_literals.py"), str(Path(__file__).parent),
                     "--exclude", "opcodelist"])
    record("no_literals(方言分层)", code, txt)

    # --- 5. 站点级改写（§6.3）。变长输出上才有判定意义，故需先做一次变长回封。
    #     该门禁在 1.7 MB 样本上需数分钟（其值碰撞扫描为 O(n·k)），默认跳过；
    #     --with-sites 显式开启。跳过时明确记录未执行，不计入通过（§10）。
    if a.with_sites:
        code, txt = run_sites_gate(src, out)
        record("check_sites(按站点不按值)", code, txt)
    else:
        results.append({"gate": "check_sites(按站点不按值)", "ok": None,
                        "detail": "未执行：需 --with-sites（该门禁耗时数分钟）"})

    (rep / "verify.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")

    width = max(len(r["gate"]) for r in results)
    for r in results:
        first = r["detail"].splitlines()[0] if r["detail"] else ""
        mark = "SKIP" if r["ok"] is None else ("PASS" if r["ok"] else "FAIL")
        print(f"[{mark}] {r['gate']:<{width}}  {first[:print_cap]}")
    # 未执行的门禁既不算通过也不算失败，必须显式列出（§10：要报告未执行的阶段）
    failed = [r for r in results if r["ok"] is False]
    skipped = [r for r in results if r["ok"] is None]
    ran = [r for r in results if r["ok"] is not None]
    tail = f"，{len(skipped)} 项未执行" if skipped else ""
    print(f"\n{len(ran) - len(failed)}/{len(ran)} 通过{tail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
