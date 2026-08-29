# -*- coding: utf-8 -*-
"""单独的解封装工具：.cst → 裸载荷（可选带解密探测）。

这是「先批量解压、再拿别的工具看内容」这种工作流的入口，等价于常见的
uncomFile 脚本（读 [8:12] 压缩长度、[12:16] 解压长度、zlib.decompress 后落盘），
但多做三件事：

  1. 校验魔数与两个长度字段，不匹配即报错停下，而不是产出半个文件。
  2. zlib 解不开时按 opcodelist.CIPHER_PROBES 逐个试解密候选，
     接受条件是「合法 zlib + 长度相符 + 载荷头自洽」三条硬约束（不猜）。
  3. 校验解出的载荷结构完整（块表、偏移表、记录流全部可解析），并报出记录数。

用法：
    python unpack.py <文件或目录> [...] [-o 输出目录] [--key key.dat] [--repack]
    拖放：把文件或文件夹拖到本文件图标上（产出到输入目录旁的 unpacked/）。

  --repack  反向操作：把裸载荷重新封装成 .cst（加 CatScene 头 + zlib 压缩）

原始文件永不写入（铁律 1）。
"""
from __future__ import annotations

import argparse
import sys
import zlib
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
import opcodelist as D  # noqa: E402
import disassembler as DIS  # noqa: E402


def unpack_one(path: Path, key: bytes | None) -> tuple[bytes, dict]:
    """返回（裸载荷, 说明）。任何不一致抛 CstError。"""
    data = path.read_bytes()
    doc = DIS.parse_bytes(data, path, key)
    if doc.form == "bare-payload":
        raise DIS.CstError(f"{path.name}: 已经是裸载荷，无需再解")
    payload = zlib.decompress(doc.zlib_stream) if doc.cipher["id"] == "none" \
        else DIS._decode_layer(doc.zlib_stream, doc.unc_size, path, key)[0]
    return payload, {
        "in_size": len(data), "out_size": len(payload),
        "records": len(doc.records), "blocks": len(doc.blocks),
        "cipher": doc.cipher["id"], "sha256": DIS._sha256(payload)}


def repack_one(path: Path) -> tuple[bytes, dict]:
    """裸载荷 → .cst 容器。"""
    data = path.read_bytes()
    doc = DIS.parse_bytes(data, path)
    if doc.form != "bare-payload":
        raise DIS.CstError(f"{path.name}: 已经是完整 .cst 容器，无需再封")
    stream = zlib.compress(data, D.CONTAINER["compression"]["level"])
    out = bytearray(DIS._HDR)
    out[:len(D.CONTAINER["magic"])] = D.CONTAINER["magic"]
    DIS._U32.pack_into(out, D.CONTAINER["field_com_size"]["offset"], len(stream))
    DIS._U32.pack_into(out, D.CONTAINER["field_unc_size"]["offset"], len(data))
    built = bytes(out) + stream
    # 自检：封回去必须能再解出同样的载荷
    check = DIS.parse_bytes(built, path)
    if zlib.decompress(check.zlib_stream) != data:
        raise DIS.CstError(f"{path.name}: 封装自检失败，产物已丢弃")
    return built, {"in_size": len(data), "out_size": len(built),
                   "records": len(doc.records),
                   "sha256": DIS._sha256(built)}


def main(argv: Sequence[str] | None = None) -> int:
    DIS._utf8_console()
    ap = argparse.ArgumentParser(
        description="CatScene .cst 解封装 / 重封装（不做文本提取，那是 disassembler.py）")
    ap.add_argument("inputs", nargs="*")
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--key", default=None, help="密钥文件，仅加密样本需要")
    ap.add_argument("--repack", action="store_true",
                    help="反向：裸载荷 → .cst")
    a = ap.parse_args(argv)
    if not a.inputs:
        ap.print_help()
        return 2
    key = None
    if a.key:
        kp = Path(a.key)
        if not kp.is_file():
            print(f"错误：密钥文件不存在 {kp}", file=sys.stderr)
            return 1
        key = kp.read_bytes()
        print(f"密钥 {kp.name}（{len(key)} 字节）")
    try:
        files = DIS.collect_inputs(Path(p) for p in a.inputs)
    except DIS.CstError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1
    base = DIS.common_parent(files)
    out = Path(a.output) if a.output else base / ("repacked" if a.repack
                                                 else "unpacked")
    print(f"输入 {len(files)} 个文件 → {out}")
    ok = 0
    fails = []
    ciphers: dict[str, int] = {}
    for p in files:
        try:
            blob, info = (repack_one(p) if a.repack else unpack_one(p, key))
        except DIS.CstError as exc:
            fails.append((p.name, str(exc)))
            continue
        rel = DIS._rel(p, base)
        DIS._atomic_write_bytes(out / rel, blob)
        c = info.get("cipher", "-")
        ciphers[c] = ciphers.get(c, 0) + 1
        ok += 1
        if ok <= 3 or ok % 50 == 0:
            print(f"  {rel}  {info['in_size']:,} → {info['out_size']:,} 字节，"
                  f"{info['records']:,} 条记录")
    print()
    print(f"成功 {ok}/{len(files)}")
    if not a.repack:
        print(f"解封装方式 {ciphers}")
    for name, err in fails[:8]:
        print(f"  ! {name}: {err}")
    print(f"产物 {out}")
    return 0 if ok and not fails else 1


if __name__ == "__main__":
    sys.exit(main())
