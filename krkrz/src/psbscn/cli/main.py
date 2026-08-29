"""无界面命令行入口。每个子命令对应一个阶段，不存在隐藏的一键全跑。

退出码：0 = 阶段成功，1 = 阶段报告未通过，2 = 用法错误，
3 = 流水线错误（解析/验证/导入失败），错误信息带可定位位置。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..core.errors import PsbError
from ..services import encodings
from ..services.jobs import JobRunner
from ..services.stages import StageResult, StageService
from ..services.toolchain import TOOL_VERSION, probe_toolchain
from ..services.workspace import Workspace, find_scenario_files

EXIT_OK, EXIT_NOT_OK, EXIT_USAGE, EXIT_ERROR = 0, 1, 2, 3


def _force_utf8_streams() -> None:
    """把 stdout/stderr 切到 UTF-8。

    中文 Windows 的控制台默认是 GBK。剧本原文是日文，其中假名恰好能被 CP936
    表示，但汉字与符号存在无法表示的字符——那会让工具在打印诊断信息时抛出
    UnicodeEncodeError，把「报告问题」变成「工具崩溃」。errors="replace" 只影响
    终端显示，产物文件始终以 UTF-8 原样写出。
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def _emit(result: StageResult, as_json: bool) -> int:
    if as_json:
        print(json.dumps(result.to_json(), ensure_ascii=False, indent=2))
    else:
        status = "成功" if result.ok else "未通过"
        print(f"[{result.stage}] {status}")
        for key, value in result.data.items():
            if isinstance(value, (dict, list)):
                rendered = json.dumps(value, ensure_ascii=False)
                if len(rendered) > 400:
                    rendered = rendered[:400] + "..."
                print(f"  {key}: {rendered}")
            else:
                print(f"  {key}: {value}")
        for name, path in result.artifacts.items():
            print(f"  -> {name}: {path}")
        for message in result.messages:
            print(f"  ! {message}")
    return EXIT_OK if result.ok else EXIT_NOT_OK


def _expand(patterns: list[str]) -> list[Path]:
    """把文件、目录和通配符展开为排序后的样本列表。"""
    out: list[Path] = []
    for pattern in patterns:
        path = Path(pattern)
        if path.is_dir():
            out.extend(sorted(path.glob("*.scn")))
        elif path.exists():
            out.append(path)
        else:
            matches = sorted(Path().glob(pattern))
            if not matches:
                raise FileNotFoundError(f"没有匹配到输入：{pattern!r}")
            out.extend(matches)
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_cli.py",
        description="PSB v3（kirikiri/M2 .txt.scn）全量反汇编与无损回封工具。"
                    "每个子命令对应一个阶段。")
    parser.add_argument("--version", action="version",
                        version=f"psbscn {TOOL_VERSION}")
    parser.add_argument("--json", action="store_true",
                        help="输出机器可读的阶段结果")
    parser.add_argument("--quiet", action="store_true",
                        help="不打印进度行")
    sub = parser.add_subparsers(dest="stage", required=True)

    def add_encoding(p: argparse.ArgumentParser) -> None:
        p.add_argument("--encoding", default="utf-8",
                       help="源字符串编码（默认 utf-8）")

    p = sub.add_parser("toolchain", help="报告解释器与可选依赖")

    p = sub.add_parser("probe", help="仅对格式假设打分")
    p.add_argument("sample")

    p = sub.add_parser("parse", help="解析结构并证明字节覆盖")
    p.add_argument("sample")
    p.add_argument("-o", "--out", help="输出 psb_model.json / region_map.jsonl")
    p.add_argument("--strict", action="store_true", default=True)
    p.add_argument("--no-strict", dest="strict", action="store_false",
                   help="容忍文件头校验和不匹配")
    add_encoding(p)

    p = sub.add_parser("disasm", help="全量反汇编 -> 规范化 IR")
    p.add_argument("sample")
    p.add_argument("-o", "--out", required=True, help="IR 输出目录")
    p.add_argument("--target-encoding", default="utf-8")
    add_encoding(p)

    p = sub.add_parser("export-asm", help="从 IR 投影出 ASM 清单")
    p.add_argument("sample")
    p.add_argument("-o", "--out", required=True)
    add_encoding(p)

    p = sub.add_parser("export-text", help="从 IR 投影出 DSAT 翻译文件")
    p.add_argument("ir_dir")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--target-encoding", default="utf-8")

    p = sub.add_parser("import-text", help="校验 DSAT 并生成 ChangeSet")
    p.add_argument("ir_dir")
    p.add_argument("dsat")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--target-encoding", default="utf-8")
    p.add_argument("--strict", action="store_true", default=True)
    p.add_argument("--no-strict", dest="strict", action="store_false",
                   help="允许 DSAT 缺少部分 IR 条目")

    p = sub.add_parser("plan", help="计算布局与重定位计划")
    p.add_argument("sample")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--changeset")
    p.add_argument("--mode", default="lossless-relocatable",
                   choices=["in_place", "lossless-relocatable",
                            "semantic-rebuild"])
    add_encoding(p)

    p = sub.add_parser("repack", help="重序列化为新文件")
    p.add_argument("sample")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--changeset")
    p.add_argument("--mode", default="lossless-relocatable",
                   choices=["in_place", "lossless-relocatable",
                            "semantic-rebuild"])
    p.add_argument("--log-dir")
    add_encoding(p)

    p = sub.add_parser("verify", help="比较原件与重建结果")
    p.add_argument("original")
    p.add_argument("rebuilt")
    p.add_argument("-o", "--out")
    add_encoding(p)

    p = sub.add_parser("smoke-roundtrip",
                       help="零编辑同一性与确定性门禁")
    p.add_argument("sample")
    p.add_argument("-o", "--out")
    add_encoding(p)

    p = sub.add_parser("certificate", help="生成 coverage_certificate.json")
    p.add_argument("sample")
    p.add_argument("-o", "--out", required=True)
    add_encoding(p)

    p = sub.add_parser("batch", help="对多个文件执行反汇编门禁（等价于 disasm）")
    p.add_argument("inputs", nargs="+",
                   help="文件、目录或通配符")
    p.add_argument("-o", "--out", required=True, help="工作区目录")
    p.add_argument("--target-encoding", default="utf-8")
    p.add_argument("--no-asm", dest="asm", action="store_false", default=True)
    p.add_argument("--no-text", dest="text", action="store_false", default=True)
    p.add_argument("--no-certificate", dest="cert", action="store_false",
                   default=True)
    add_encoding(p)

    # 三个懒人操作，与 GUI 的三个按钮一一对应；输出目录固定为输入目录下的
    # `_psbscn`，因此不需要 -o。
    for name, help_text in (
        ("反汇编", "① 全量反汇编：合并 ASM 清单 + 零编辑往返自检"),
        ("提取文本", "② 逐文件导出译文到 texts/（镜像源目录）"),
        ("回封", "③ 按 texts/ 里的译文回封到 rebuilt/ 并验证"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("inputs", nargs="+", help="存放 .scn 的目录或文件")
        p.add_argument("--encoding", default=encodings.DEFAULT_SOURCE,
                       help=f"源字符串编码（默认 {encodings.DEFAULT_SOURCE}，"
                            f"可选 {'/'.join(encodings.SOURCE_ENCODINGS)}）")
        p.add_argument("--target-encoding", default=encodings.DEFAULT_TARGET,
                       help=f"译文写回编码（默认 {encodings.DEFAULT_TARGET}，"
                            f"可选 {'/'.join(encodings.TARGET_ENCODINGS)}）")
        if name == "反汇编":
            p.add_argument("--no-asm", action="store_true",
                           help="不生成 ASM 清单（本作语料 571 MB，约省 20% 时间）；"
                                "零编辑往返自检与覆盖证书照常执行")
            p.add_argument("--with-ir", action="store_true",
                           help="额外落盘一份合库 IR 到 _psbscn/ir/"
                                "（manifest.jsonl 记录每个源在各流中的行区间）")
    return parser


JOB_METHODS = {
    "反汇编": "disassemble",
    "提取文本": "extract_text",
    "回封": "repack_text",
}


def main(argv: list[str] | None = None) -> int:
    _force_utf8_streams()
    parser = build_parser()
    args = parser.parse_args(argv)

    def progress(stage: str, fraction: float, message: str) -> None:
        if not args.quiet and not args.json:
            print(f"  [{stage} {fraction:5.1%}] {message}", file=sys.stderr)

    svc = StageService(progress=progress)
    try:
        if args.stage == "toolchain":
            payload = probe_toolchain()
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return EXIT_OK
        if args.stage == "probe":
            return _emit(svc.probe(args.sample), args.json)
        if args.stage == "parse":
            return _emit(svc.parse(args.sample, args.out,
                                   encoding=args.encoding,
                                   strict=args.strict), args.json)
        if args.stage == "disasm":
            return _emit(svc.disasm(args.sample, args.out,
                                    encoding=args.encoding,
                                    target_encoding=args.target_encoding),
                         args.json)
        if args.stage == "export-asm":
            return _emit(svc.export_asm(args.sample, args.out,
                                        encoding=args.encoding), args.json)
        if args.stage == "export-text":
            return _emit(svc.export_text(args.ir_dir, args.out,
                                         target_encoding=args.target_encoding),
                         args.json)
        if args.stage == "import-text":
            return _emit(svc.import_text(args.ir_dir, args.dsat, args.out,
                                         target_encoding=args.target_encoding,
                                         strict=args.strict), args.json)
        if args.stage == "plan":
            return _emit(svc.plan(args.sample, args.out,
                                  changeset=args.changeset, mode=args.mode,
                                  encoding=args.encoding), args.json)
        if args.stage == "repack":
            return _emit(svc.repack(args.sample, args.out,
                                    changeset=args.changeset, mode=args.mode,
                                    encoding=args.encoding,
                                    log_dir=args.log_dir), args.json)
        if args.stage == "verify":
            return _emit(svc.verify(args.original, args.rebuilt, args.out,
                                    encoding=args.encoding), args.json)
        if args.stage == "smoke-roundtrip":
            return _emit(svc.smoke_roundtrip(args.sample, args.out,
                                             encoding=args.encoding),
                         args.json)
        if args.stage == "certificate":
            return _emit(svc.certificate(args.sample, args.out,
                                         encoding=args.encoding), args.json)
        if args.stage == "batch":
            samples = _expand(args.inputs)
            if not samples:
                print("没有输入文件", file=sys.stderr)
                return EXIT_USAGE
            return _emit(svc.batch_disasm(
                list(samples), args.out, encoding=args.encoding,
                target_encoding=args.target_encoding, export_asm=args.asm,
                export_text=args.text, certificate=args.cert), args.json)
        if args.stage in JOB_METHODS:
            files = find_scenario_files(args.inputs)
            if not files:
                print("在所选位置未找到 PSB 剧本文件"
                      "（已按 PSB\\0 签名递归检查）", file=sys.stderr)
                return EXIT_USAGE
            src = encodings.check(args.encoding)
            dst = encodings.check(args.target_encoding)
            if not args.quiet and not args.json:
                ws = Workspace.beside(args.inputs[0])
                print(f"找到 {len(files)} 个文件，输出目录 {ws.root}"
                      f"（源编码 {src} → 目标编码 {dst}）", file=sys.stderr)
            runner = JobRunner(svc)
            method = getattr(runner, JOB_METHODS[args.stage])
            extra: dict[str, bool] = {}
            if args.stage == "反汇编":
                extra = {"write_asm": not args.no_asm,
                         "write_ir": args.with_ir}
            outcome = method(args.inputs, encoding=src, target_encoding=dst,
                             **extra)
            return _emit(outcome.as_stage_result(), args.json)
    except PsbError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except (FileNotFoundError, IsADirectoryError, PermissionError,
            ValueError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    parser.error(f"未处理的阶段 {args.stage!r}")
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
