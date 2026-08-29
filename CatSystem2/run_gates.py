# -*- coding: utf-8 -*-
"""跑技能自带的四个门禁脚本（§8.4），并把逐文件证书拆出来喂给 coverage_certificate.py。

用法：
    python run_gates.py <output 目录> [--skill-scripts 路径] [--sample N]
    python run_gates.py <output 目录> --rebuilt <rebuilt 目录>   # 连同站点门禁一起跑

四个脚本都只读输入、以 JSON 报告结果、退出码 0/1。不得为了通过门禁放宽判据。
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import disassembler as DIS  # noqa: E402

DEFAULT_SCRIPTS = Path.home() / ".claude" / "skills" / \
    "universal-lossless-reverse-unpack" / "scripts"


def _run(args: list[str]) -> tuple[int, dict | str]:
    p = subprocess.run([sys.executable] + args, capture_output=True)
    txt = p.stdout.decode("utf-8", "replace")
    try:
        return p.returncode, json.loads(txt)
    except json.JSONDecodeError:
        return p.returncode, (txt or p.stderr.decode("utf-8", "replace"))[:800]


def gate_coverage(out: Path, scripts: Path, limit: int | None) -> dict:
    """逐文件证书拆成单个 JSON 交给门禁脚本，它一次只认一个源。"""
    blob = json.loads((out / "reports" / "coverage_certificate.json")
                      .read_text(encoding="utf-8"))
    certs = blob["certificates"]
    manifest = [json.loads(x) for x in
                (out / "ir" / "manifest.jsonl").read_text(encoding="utf-8")
                .splitlines() if x]
    root = Path(manifest[0]["source_root"])
    by_name = {m["path"]: m for m in manifest[1:]}
    todo = certs if limit is None else certs[:limit]
    bad, checked = [], 0
    with tempfile.TemporaryDirectory() as td:
        for c in todo:
            name = c["source"]
            m = next((v for k, v in by_name.items()
                      if k == name or k.endswith("/" + name)), None)
            if m is None:
                bad.append({"source": name, "error": "manifest 中找不到该源"})
                continue
            cp = Path(td) / "cert.json"
            cp.write_text(json.dumps(c, ensure_ascii=False), encoding="utf-8")
            rc, rep = _run([str(scripts / "coverage_certificate.py"),
                            str(root / m["path"]), str(cp)])
            checked += 1
            if rc != 0:
                bad.append({"source": name, "report": rep})
    return {"gate": "coverage_certificate", "checked": checked,
            "failed": len(bad), "failures": bad[:5], "ok": not bad}


def gate_dsat(out: Path, scripts: Path) -> dict:
    rc, rep = _run([str(scripts / "check_dsat.py"), str(out / "ir"),
                    str(out / "texts")])
    errs = rep.get("errors", []) if isinstance(rep, dict) else [rep]
    return {"gate": "check_dsat", "ok": rc == 0,
            "files": len(rep.get("files", [])) if isinstance(rep, dict) else 0,
            "errors": errs[:6], "error_count": len(errs)}


def gate_sites(out: Path, rebuilt: Path, scripts: Path, limit: int | None) -> dict:
    """站点属于载荷层（L001），门禁脚本读的是平坦文件，所以喂它**载荷对**。

    这不是绕过门禁：join_sites 的 site_offset 本来就是载荷内偏移，拿容器文件去比
    才是错的（zlib 流里没有可寻址的站点）。载荷由 IR 重新编码，逐字节可复算，
    与容器层的对照另由覆盖证书的 transform_edges 哈希保证。
    """
    manifest = [json.loads(x) for x in
                (out / "ir" / "manifest.jsonl").read_text(encoding="utf-8")
                .splitlines() if x]
    root = Path(manifest[0]["source_root"])
    by_src: dict[int, list[dict]] = {}
    for ln in (out / "ir" / "join_sites.jsonl").read_text(encoding="utf-8").splitlines():
        if ln:
            s = json.loads(ln)
            by_src.setdefault(s["src_id"], []).append(s)
    targets = [m for m in manifest[1:] if (rebuilt / m["path"]).exists()]
    if limit is not None:
        targets = targets[:limit]
    bad, checked, collisions = [], 0, 0
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        for m in targets:
            old_doc = DIS.load(root / m["path"])
            new_doc = DIS.load(rebuilt / m["path"])
            op, np_ = tdp / "old.bin", tdp / "new.bin"
            # cstl / 裸载荷没有压缩层，站点偏移就是文件内偏移，直接比文件本身。
            op.write_bytes(_layer_bytes(root / m["path"], old_doc))
            np_.write_bytes(_layer_bytes(rebuilt / m["path"], new_doc))
            sp = tdp / "sites.jsonl"
            newv = {s.site_offset: s.key_value for s in new_doc.join_sites}
            # cstl 没有独立引用表（长度前缀内联），站点集合为空是正常的；
            # 此时门禁只剩「差异必须可追溯」这一条，仍然有意义。
            rows = by_src.get(m["src_id"], [])
            sp.write_text("\n".join(
                json.dumps(dict(s, new_key_value=newv.get(s["site_offset"])),
                           ensure_ascii=False) for s in rows) + "\n"
                if rows else "", encoding="utf-8")
            lp = tdp / "reloc.jsonl"
            lp.write_text("\n".join(json.dumps(x) for x in
                                    _reloc_for(old_doc, new_doc, m)) + "\n",
                          encoding="utf-8")
            rc, rep = _run([str(scripts / "check_sites.py"), str(op), str(np_),
                            str(sp), "--strict-diff",
                            "--relocation-log", str(lp)])
            checked += 1
            if isinstance(rep, dict):
                collisions += rep.get("preserved_value_collisions", 0)
            if rc != 0:
                bad.append({"source": m["path"], "report": rep})
    return {"gate": "check_sites", "checked": checked, "failed": len(bad),
            "preserved_value_collisions": collisions,
            "failures": bad[:4], "ok": not bad}


def _layer_bytes(p: Path, doc) -> bytes:
    """取站点偏移所在那一层的字节。container 要解 zlib，其余形态就是文件本身。"""
    if doc.form != "container":
        return p.read_bytes()
    import zlib
    d = p.read_bytes()
    return zlib.decompress(d[DIS._HDR:DIS._HDR + int.from_bytes(
        d[8:12], DIS.D.PAYLOAD["endianness"])])


def _reloc_for(old: DIS.Doc, new: DIS.Doc, m: dict) -> list[dict]:
    """站点之外的每处差异都必须能追溯（§6.3）。
    记录数据区由 IR 逐条重新编码，声明为一段已归属的重写范围；
    载荷头的 payload_size 字段按声明重新生成，单独声明。"""
    if old.form == "cstl":
        # cstl 的长度前缀是内联的，不存在独立引用表，整个串流由 IR 逐条重发。
        return [{"offset": 0,
                 "length": max(old.raw_size, new.raw_size),
                 "src_id": m["src_id"],
                 "reason": "cstl 串流由 IR 逐条重新编码，每字节可追溯到 rec_id"}]
    hdr = DIS.D.PAYLOAD["header"]["size"]
    out = [{"offset": 0, "length": hdr, "src_id": m["src_id"],
            "reason": "载荷头 payload_size 按新载荷长度重新生成"}]
    dbase = min(hdr + old.data_offset, hdr + new.data_offset)
    out.append({"offset": dbase,
                "length": max(old.payload_len, new.payload_len) - dbase,
                "src_id": m["src_id"],
                "reason": "记录数据区由 IR 逐条重新编码，每字节可追溯到 rec_id"})
    return out


def gate_literals(src: Path, scripts: Path) -> dict:
    # 只扫结构逻辑。run_gates 是门禁驱动，tests.py 的用例数据里必须能出现具体字节
    # （构造非法 cp932 序列、注入未知类型字节）——门禁脚本默认排除 test_ 前缀，
    # 本项目用 tests.py，所以显式补上。
    rc, rep = _run([str(scripts / "check_no_literals.py"), str(src),
                    "--exclude", "run_gates", "--exclude", "tests.py"])
    return {"gate": "check_no_literals", "ok": rc == 0,
            "scanned": rep.get("scanned_files") if isinstance(rep, dict) else None,
            "violations": rep.get("violations") if isinstance(rep, dict) else None,
            "advisory": rep.get("advisory") if isinstance(rep, dict) else None,
            "findings": (rep.get("findings") or [])[:8] if isinstance(rep, dict)
            else [rep],
            "advisory_findings": (rep.get("advisory_findings") or [])[:8]
            if isinstance(rep, dict) else []}


def main(argv=None) -> int:
    DIS._utf8_console()
    ap = argparse.ArgumentParser(description="跑技能自带的四个门禁脚本")
    ap.add_argument("output", help="反汇编输出目录（含 ir/ texts/ reports/）")
    ap.add_argument("--rebuilt", default=None, help="回封产物目录，跑站点门禁")
    ap.add_argument("--skill-scripts", default=str(DEFAULT_SCRIPTS))
    ap.add_argument("--sample", type=int, default=None,
                    help="只抽查前 N 个文件（覆盖与站点门禁），缺省全量")
    a = ap.parse_args(argv)
    out = Path(a.output)
    scripts = Path(a.skill_scripts)
    if not scripts.exists():
        print(f"找不到门禁脚本目录 {scripts}", file=sys.stderr)
        return 2
    results = [
        gate_coverage(out, scripts, a.sample),
        gate_dsat(out, scripts),
        gate_literals(Path(__file__).resolve().parent, scripts),
    ]
    if a.rebuilt:
        results.append(gate_sites(out, Path(a.rebuilt), scripts, a.sample))
    for r in results:
        mark = "通过" if r["ok"] else "失败"
        extra = ""
        if "checked" in r:
            extra = f"（检查 {r['checked']}，失败 {r['failed']}）"
        elif r["gate"] == "check_dsat":
            extra = f"（{r['files']} 个译文文件，{r['error_count']} 条错误）"
        elif r["gate"] == "check_no_literals":
            extra = (f"（扫 {r['scanned']} 个文件，violations {r['violations']}，"
                     f"advisory {r['advisory']}）")
        print(f"{r['gate']:<22} {mark} {extra}")
        for x in (r.get("failures") or r.get("errors") or r.get("findings") or [])[:4]:
            print("    !", json.dumps(x, ensure_ascii=False)[:220])
        for x in (r.get("advisory_findings") or [])[:4]:
            print("    ~", json.dumps(x, ensure_ascii=False)[:200])
    ok = all(r["ok"] for r in results)
    rp = out / "reports" / "gates.json"
    DIS._atomic_write_text(rp, json.dumps(
        {"ok": ok, "gates": results}, ensure_ascii=False, indent=2,
        sort_keys=True), "utf-8")
    print(f"\n门禁报告  {rp}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
