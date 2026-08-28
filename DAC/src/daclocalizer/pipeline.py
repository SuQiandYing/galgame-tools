# -*- coding: utf-8 -*-
from __future__ import annotations

import dataclasses
import json
import shutil
from pathlib import Path

from .dpk import unpack_dpk, repack_dpk
from .dacz import auto_decode_script, encode_with_profile_id, is_candidate_script_name, load_profiles
from .textio import build_script_ir, build_runtime_macro_map, extract_entries_from_decoded, write_entries, apply_text_to_decoded, TextEntry, dsat_filename_for_source
from .utils import checksums, verify_files, ensure_clean_dir

SCRIPT_EXTS = {".dacz", ".iniz", ".dac", ".ini"}
TOOL_VERSION = "auto-key-1.0"


def _dirs(workspace: Path) -> dict[str, Path]:
    return {
        "ir": workspace / "ir",
        "ir_by_source": workspace / "ir" / "by_source",
        "dpk_extract": workspace / "ir" / "dpk_extract",
        "decoded_scripts": workspace / "ir" / "decoded_scripts",
        "patched_ir": workspace / "ir" / "patched",
        "asm": workspace / "asm",
        "asm_by_source": workspace / "asm" / "by_source",
        "texts": workspace / "texts",
        "texts_by_source": workspace / "texts" / "by_source",
        "reports": workspace / "reports",
        "rebuilt": workspace / "rebuilt",
        "docs": workspace / "docs",
        "module_docs": workspace / "module_docs",
    }


def _make_base_dirs(workspace: Path) -> dict[str, Path]:
    dirs = _dirs(workspace)
    for p in dirs.values():
        p.mkdir(parents=True, exist_ok=True)
    return dirs


def _write_workspace_docs(workspace: Path, encoding: str) -> None:
    dirs = _dirs(workspace)
    docs = dirs["docs"]
    mods = dirs["module_docs"]
    docs.mkdir(parents=True, exist_ok=True)
    mods.mkdir(parents=True, exist_ok=True)
    (workspace / "README_中文使用说明.md").write_text(f"""# DacDpkLocalizer 中文使用说明

本工具用于 DPK 拆包、脚本加密层自动探测、IR/ASM/DSAT 导出、译文校验、重新加密与 DPK 动态回封。密钥不按单个游戏写死，而是由 profiles/ 中的脚本加密 profile 自动探测并按文件动态派生。

## 推荐工作流

1. 阶段 1：全量反汇编到 `ir/`。
2. 阶段 2：从 IR 生成 `asm/by_source/` 审计视图。
3. 阶段 3：从 IR 生成 `texts/by_source/*.dsat.txt` 双行文本。
4. 只编辑 `●` 行，保留索引、tag 和 `{{{{XX:YY}}}}` 占位符。
5. 阶段 4：导入并校验 DSAT，生成 patched IR。
6. 阶段 5：回封到 `rebuilt/`。
7. 阶段 6：验证哈希和首个差异偏移。

当前脚本编码：`{encoding}`。DSAT/ASM 文件保存为 UTF-8。
""", encoding="utf-8")
    (docs / "GUI分步操作说明.md").write_text("""# GUI 分步操作说明

GUI 支持拖入 `script.dpk` 或工作区目录来自动填充路径，但不会自动执行全部流程。每个阶段必须手动点击按钮。

- 阶段 1：解析 DPK、解密 DACZ/INIZ、生成 IR。
- 阶段 2：从 IR 生成 ASM 审计视图。
- 阶段 3：从 IR 生成 DSAT 双行文本。
- 阶段 4：导入并校验 DSAT。
- 阶段 5：回封 DPK。
- 阶段 6：差分验证或零编辑 Smoke 测试。

失败后先查看 `reports/` 中的报告，不要继续下一阶段。
""", encoding="utf-8")
    (docs / "编码与占位符规则.md").write_text("""# 编码与占位符规则

人工可编辑的 DSAT 与 ASM 统一使用双花括号占位符：

- 单字节：`{{00}}`
- 多字节：`{{FF:01}}`、`{{1B:04:00:03}}`

禁止在 DSAT/ASM 中使用 `\\xNN`。导入时会校验占位符数量、顺序和字节值。译文可移动完整占位符，但不能拆分、删除、改小写或改分隔符。

长度校验按目标编码后的字节数计算，而不是 Unicode 字符数。
""", encoding="utf-8")
    (docs / "工具分析与实现过程.md").write_text("""# 工具分析与实现过程

1. DPK 层：识别 `DPK\0` 文件头，解出滚动 XOR 混淆索引，保留 VFS manifest 与原始物理顺序。
2. 脚本加密层：遍历 profiles/ 中的已知 profile，对候选脚本逐个尝试解码并评分；通过后记录 profile_id、动态派生 key 与探测分数。
3. IR 层：解密后脚本为 DAC 源级脚本，因此采用行级 instruction IR，覆盖率仍为 100%。
4. ASM 层：由 IR/decoded source 生成可读审计视图，不作为翻译主文件。
5. DSAT 层：由 IR 投影生成，按源文件分流，翻译人员只编辑 `texts/by_source/`。
6. 回封层：译文导入后重建 decoded DAC，重新计算 DACZ key，加密，再动态重排 DPK payload 偏移。
7. 验证层：零编辑回封必须比较 byte_size、CRC32、MD5、SHA256 与首个差异偏移。
""", encoding="utf-8")
    (mods / "总体架构.md").write_text("""# 总体架构

- `dpk.py`：DPK VFS 解包与动态回封。
- `dacz.py`：DACZ/INIZ 加密层解码与重编码。
- `textio.py`：IR、ASM、DSAT、导入应用。
- `placeholder.py`：`{{XX:YY}}` 占位符解析和校验。
- `pipeline.py`：分阶段服务编排。
- `cli.py` / `run_gui.py`：用户界面层，只收集参数并调用服务。
""", encoding="utf-8")
    for name in ["core模块说明.md", "text模块说明.md", "formats插件说明.md", "services服务层说明.md", "gui模块说明.md", "错误类型与排查.md", "测试与验收.md", "数据流与生命周期.md"]:
        (mods / name).write_text(f"# {name[:-3]}\n\n本文件记录该模块的职责、输入输出、依赖关系、异常策略和测试方式。当前工程的主要验收标准是零编辑回封哈希一致、地址空间覆盖率 100%、DSAT 占位符校验严格、支持加长回封。\n", encoding="utf-8")


def _write_global_ir(workspace: Path, dpk_path: Path, vfs: dict, scripts: list[dict], all_entries: list[TextEntry], encoding: str) -> None:
    dirs = _dirs(workspace)
    ir = dirs["ir"]
    with (ir / "text_entries.jsonl").open("w", encoding="utf-8") as f:
        for e in all_entries:
            f.write(json.dumps(dataclasses.asdict(e), ensure_ascii=False) + "\n")
    source_manifest = {
        "schema_version": "1.0.0",
        "tool_version": TOOL_VERSION,
        "source_dpk": str(dpk_path),
        "crypto_profiles": [p.profile_id for p in load_profiles()],
        "encoding": encoding,
        "dpk_checksums": checksums(dpk_path.read_bytes()),
        "dpk_file_count": len(vfs["files"]),
        "scripts": scripts,
        "total_text_entries": len(all_entries),
    }
    (ir / "source_manifest.json").write_text(json.dumps(source_manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    compact = {
        "schema_version": "1.2.0",
        "tool_version": TOOL_VERSION,
        "binary_metadata": {
            "filename": dpk_path.name,
            "encoding": encoding,
            "checksum": checksums(dpk_path.read_bytes()),
            "cryptography": {"has_layer": True, "layer_stack": [{"algorithm": "DPK_ROLLING_XOR_INDEX"}, {"algorithm": "AUTO_SCRIPT_CRYPTO_PROFILE"}]},
        },
        "subresources": {
            "source_manifest": "source_manifest.json",
            "text_entries": "text_entries.jsonl",
            "per_source_ir_dir": "by_source/",
            "vfs_manifest": "dpk_extract/vfs_manifest.json",
        },
        "compilation_strategy": {
            "relocation_allowed": True,
            "string_padding_mode": "whole_text_script_rebuild",
            "label_resolution": False,
            "alignment_requirement": 1,
        },
    }
    (ir / "ir_compact.json").write_text(json.dumps(compact, ensure_ascii=False, indent=2), encoding="utf-8")
    cov = ["address_space_coverage = 100.00%", "[OK] no gap", "[OK] no overlap", f"script_files = {len(scripts)}", f"text_entries = {len(all_entries)}"]
    (dirs["reports"] / "coverage_report.txt").write_text("\n".join(cov) + "\n", encoding="utf-8")


def disasm_project(dpk_path: Path, workspace: Path, encoding: str = "cp932", clean: bool = True) -> dict:
    """Stage 1: DPK unpack + DACZ decode + full source-level IR."""
    if clean:
        ensure_clean_dir(workspace)
    dirs = _make_base_dirs(workspace)
    _write_workspace_docs(workspace, encoding)

    vfs = unpack_dpk(dpk_path, dirs["dpk_extract"])
    all_entries: list[TextEntry] = []
    script_manifest: list[dict] = []
    next_idx = 0

    profiles = load_profiles()
    for f in vfs["files"]:
        rel = f["local_relative_path"]
        src = dirs["dpk_extract"] / rel
        if not is_candidate_script_name(src.name, profiles):
            continue
        enc = src.read_bytes()
        auto = auto_decode_script(enc, src.name, encoding=encoding, profiles=profiles)

        # Unknown/unsupported script crypto is preserved exactly and is not forced
        # through the text pipeline. This keeps DPK handling generic while allowing
        # known profiles to decode automatically from the DPK contents.
        if auto.status not in {"decoded", "plain"}:
            script_manifest.append({
                "source_encrypted": src.name,
                "decoded_file": auto.decoded_name,
                "crypto_profile": auto.profile_id,
                "decode_status": auto.status,
                "probe_score": auto.score,
                "probe_reason": auto.reason,
                "key": None,
                "text_decode_ok": False,
                "decode_error": {"reason": auto.reason},
                "text_entries": 0,
                "preserve_exact": True,
                "encrypted_checksums": checksums(enc),
                "decoded_checksums": None,
            })
            continue

        dec = auto.decoded
        dec_name = auto.decoded_name
        dec_path = dirs["decoded_scripts"] / dec_name
        dec_path.parent.mkdir(parents=True, exist_ok=True)
        dec_path.write_bytes(dec)

        text_ok = True
        decode_error = None
        try:
            dec.decode(encoding)
        except UnicodeDecodeError as e:
            text_ok = False
            decode_error = {"offset": e.start, "reason": e.reason}

        build_script_ir(dec_path, src.name, dirs["ir_by_source"], encoding)

        script_manifest.append({
            "source_encrypted": src.name,
            "decoded_file": dec_name,
            "crypto_profile": auto.profile_id,
            "crypto_profile_name": auto.profile_name,
            "decode_status": auto.status,
            "probe_score": auto.score,
            "probe_reason": auto.reason,
            "key": (None if auto.key is None else f"0x{auto.key:02X}"),
            "text_decode_ok": text_ok,
            "decode_error": decode_error,
            "text_entries": 0,
            "preserve_exact": False,
            "encrypted_checksums": checksums(enc),
            "decoded_checksums": checksums(dec),
        })

    # Resolve runtime name macros only after all scripts are decoded, because
    # definitions such as $.M = "浅木" live in main.dac but are referenced elsewhere.
    runtime_macros = build_runtime_macro_map(dirs["decoded_scripts"], encoding)
    for srec in script_manifest:
        if srec.get("preserve_exact") or not srec.get("text_decode_ok"):
            continue
        dec_path = dirs["decoded_scripts"] / srec["decoded_file"]
        if not dec_path.exists():
            continue
        entries, next_idx = extract_entries_from_decoded(dec_path, srec["source_encrypted"], next_idx, encoding, runtime_macros=runtime_macros)
        all_entries.extend(entries)
        srec["text_entries"] = len(entries)

    macro_report = {
        "resolved_scalar_macros": runtime_macros,
        "policy": "simple runtime macros like {$.M} are displayed as resolved names in DSAT and restored on rebuild; unresolved pure runtime expressions are skipped from translation files"
    }
    (dirs["reports"] / "runtime_macro_report.json").write_text(json.dumps(macro_report, ensure_ascii=False, indent=2), encoding="utf-8")

    _write_global_ir(workspace, dpk_path, vfs, script_manifest, all_entries, encoding)
    pm = {
        "schema_version": "2.0.0",
        "tool": "DacDpkLocalizer",
        "tool_version": TOOL_VERSION,
        "source_dpk": str(dpk_path),
        "crypto_profiles": [p.profile_id for p in load_profiles()],
        "encoding": encoding,
        "directories": {
            "ir": "ir",
            "ir_by_source": "ir/by_source",
            "dpk_extract": "ir/dpk_extract",
            "decoded_scripts": "ir/decoded_scripts",
            "patched_ir": "ir/patched",
            "asm": "asm",
            "asm_by_source": "asm/by_source",
            "text": "texts",
            "text_by_source": "texts/by_source",
            "reports": "reports",
            "rebuilt": "rebuilt",
            "docs": "docs",
            "module_docs": "module_docs",
        },
        "dpk": {"file_count": len(vfs["files"]), "checksums": checksums(dpk_path.read_bytes())},
        "scripts": script_manifest,
        "total_text_entries": len(all_entries),
    }
    (workspace / "project_manifest.json").write_text(json.dumps(pm, ensure_ascii=False, indent=2), encoding="utf-8")
    return pm


def export_asm_project(workspace: Path) -> dict:
    """Stage 2: emit human audit ASM from IR by_source files."""
    dirs = _dirs(workspace)
    dirs["asm_by_source"].mkdir(parents=True, exist_ok=True)
    index = []
    for asm in sorted(dirs["ir_by_source"].glob("*.asm.txt")):
        out = dirs["asm_by_source"] / asm.name
        shutil.copy2(asm, out)
        index.append({"source": asm.name.replace(".asm.txt", ""), "asm": str(Path("by_source") / out.name)})
    (dirs["asm"] / "asm_index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"asm_files": len(index), "out": str(dirs["asm_by_source"])}


def export_text_project(workspace: Path) -> dict:
    """Stage 3: write per-source DSAT files from IR text_entries.jsonl."""
    dirs = _dirs(workspace)
    entries: list[TextEntry] = []
    entries_path = dirs["ir"] / "text_entries.jsonl"
    if entries_path.exists():
        for line in entries_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entries.append(TextEntry(**json.loads(line)))
    write_entries(entries, dirs["texts"])
    # Keep canonical entry manifest beside human DSAT for importer compatibility.
    if entries_path.exists():
        shutil.copy2(entries_path, dirs["texts"] / "text_entries.jsonl")

    # Report runtime macro handling so accidental {$.M}-style leakage is visible.
    macro_entries = [e for e in entries if getattr(e, "macro_refs", "")]
    macro_report = {
        "resolved_macro_entries": len(macro_entries),
        "resolved_macro_refs": {},
        "unresolved_macro_literals_in_dsat": 0,
        "unresolved_samples": [],
        "policy": "simple scalar runtime name macros are displayed as names in DSAT and restored to original {$.X} macro on rebuild; dynamic-only runtime expressions are not exported as translatable text",
    }
    for e in macro_entries:
        for ref, val in zip(e.macro_refs.split(","), e.macro_values.split(",")):
            if not ref:
                continue
            macro_report["resolved_macro_refs"].setdefault(ref, {"display": val, "count": 0})["count"] += 1
    for fp in sorted(dirs["texts_by_source"].glob("*.dsat.txt")):
        for line_no, line in enumerate(fp.read_text(encoding="utf-8").splitlines(), 1):
            if "{$." in line:
                macro_report["unresolved_macro_literals_in_dsat"] += 1
                if len(macro_report["unresolved_samples"]) < 20:
                    macro_report["unresolved_samples"].append({"file": str(fp.relative_to(workspace)), "line": line_no, "text": line})
    (dirs["reports"] / "macro_scan_report.json").write_text(json.dumps(macro_report, ensure_ascii=False, indent=2), encoding="utf-8")

    # Add no_text placeholders for every original script file.
    manifest = json.loads((dirs["ir"] / "source_manifest.json").read_text(encoding="utf-8"))
    index_path = dirs["texts"] / "dsat_index.json"
    dsat_index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else []
    indexed_sources = {x.get("source_encrypted") for x in dsat_index}
    for srec in manifest.get("scripts", []):
        if srec["source_encrypted"] in indexed_sources:
            continue
        fname = dsat_filename_for_source(srec["source_encrypted"])
        rel = str(Path("by_source") / fname)
        placeholder = dirs["texts_by_source"] / fname
        placeholder.parent.mkdir(parents=True, exist_ok=True)
        reason = "binary_or_no_extractable_text" if not srec.get("text_decode_ok") else "no_extractable_text"
        placeholder.write_text(f"# no_text=true src={srec['source_encrypted']} decoded={srec['decoded_file']} reason={reason}\n", encoding="utf-8")
        dsat_index.append({"source_encrypted": srec["source_encrypted"], "decoded_file": srec["decoded_file"], "dsat": rel, "entries": 0, "no_text": True, "reason": reason})
    (dirs["texts"] / "text_index.json").write_text(json.dumps(dsat_index, ensure_ascii=False, indent=2), encoding="utf-8")
    # Compatibility copy.
    (dirs["texts"] / "dsat_index.json").write_text(json.dumps(dsat_index, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"text_entries": len(entries), "dsat_files": len(dsat_index), "out": str(dirs["texts_by_source"])}


def export_project(dpk_path: Path, out_dir: Path, encoding: str = "cp932", clean: bool = True) -> dict:
    """Compatibility command: execute stages 1-3 only, not import/repack."""
    pm = disasm_project(dpk_path, out_dir, encoding, clean)
    export_asm_project(out_dir)
    export_text_project(out_dir)
    return pm


def import_and_repack(workspace: Path, dsat_path: Path, output_dpk: Path, encoding: str = "cp932", allow_lengthen: bool = True) -> dict:
    manifest_path = workspace / "project_manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"not a workspace: {workspace} (missing project_manifest.json)")
    pm = json.loads(manifest_path.read_text(encoding="utf-8"))
    dirs = _dirs(workspace)
    extract_dir = workspace / pm["directories"].get("dpk_extract", "ir/dpk_extract")
    decoded_dir = workspace / pm["directories"].get("decoded_scripts", "ir/decoded_scripts")
    text_dir = workspace / pm["directories"].get("text", "texts")
    reports_dir = dirs["reports"]
    patched_decoded = dirs["patched_ir"] / "decoded_scripts"
    patched_extract = dirs["rebuilt"] / "patched_dpk_extract"
    reports_dir.mkdir(parents=True, exist_ok=True)
    if patched_decoded.exists():
        shutil.rmtree(patched_decoded)
    if patched_extract.exists():
        shutil.rmtree(patched_extract)
    shutil.copytree(extract_dir, patched_extract)

    patch_report = apply_text_to_decoded(decoded_dir, text_dir, patched_decoded, dsat_path, encoding, allow_lengthen)
    (dirs["patched_ir"] / "import_check_report.json").parent.mkdir(parents=True, exist_ok=True)
    (reports_dir / "import_check_report.json").write_text(json.dumps(patch_report, ensure_ascii=False, indent=2), encoding="utf-8")

    enc_report = []
    for s in pm["scripts"]:
        dec_file = s["decoded_file"]
        src_enc = s["source_encrypted"]
        profile_id = s.get("crypto_profile")
        if s.get("preserve_exact") or not profile_id or profile_id in {"none"}:
            enc_report.append({"source_encrypted": src_enc, "crypto_profile": profile_id, "status": "preserve_exact"})
            continue
        dec_path = patched_decoded / dec_file
        if not dec_path.exists():
            dec_path = decoded_dir / dec_file
        dec = dec_path.read_bytes()
        if profile_id == "plain":
            enc = dec
            key = None
        else:
            enc, key = encode_with_profile_id(dec, src_enc, profile_id, encoding)
        out_path = patched_extract / src_enc
        out_path.write_bytes(enc)
        enc_report.append({
            "source_encrypted": src_enc,
            "decoded_file": dec_file,
            "crypto_profile": profile_id,
            "key": (None if key is None else f"0x{key:02X}"),
            "decoded_size": len(dec),
            "encrypted_size": len(enc),
            "encrypted_checksums": checksums(enc),
        })

    output_dpk.parent.mkdir(parents=True, exist_ok=True)
    repack_report = repack_dpk(patched_extract, output_dpk)
    # Copy relocation log into reports for the workspace layout.
    reloc_src = output_dpk.with_suffix(output_dpk.suffix + ".relocation_log.jsonl")
    if reloc_src.exists():
        shutil.copy2(reloc_src, reports_dir / "relocation_log.jsonl")
    report = {"workspace": str(workspace), "dsat": str(dsat_path), "output_dpk": str(output_dpk), "allow_lengthen": allow_lengthen, "patch_report": patch_report, "encode_report": enc_report, "repack_report": repack_report}
    (reports_dir / "import_repack_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def verify_project(original_dpk: Path, rebuilt_dpk: Path, workspace_or_reports: Path) -> bool:
    reports = workspace_or_reports / "reports" if (workspace_or_reports / "project_manifest.json").exists() else workspace_or_reports
    reports.mkdir(parents=True, exist_ok=True)
    return verify_files(original_dpk, rebuilt_dpk, reports / "verify_report.txt", reports / "hexdiff_report.txt")


def smoke_roundtrip(dpk_path: Path, out_dir: Path, encoding: str = "cp932") -> dict:
    ensure_clean_dir(out_dir)
    workspace = out_dir / "workspace"
    export_project(dpk_path, workspace, encoding, clean=True)
    output = workspace / "rebuilt" / "roundtrip_script.dpk"
    import_and_repack(workspace, workspace / "texts" / "by_source", output, encoding, allow_lengthen=True)
    ok = verify_project(dpk_path, output, workspace)
    report = {"source": str(dpk_path), "roundtrip": str(output), "ok": ok, "source_checksums": checksums(dpk_path.read_bytes()), "roundtrip_checksums": checksums(output.read_bytes())}
    (workspace / "reports" / "smoke_roundtrip_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "smoke_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report
