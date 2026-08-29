"""探针评分与分析/解包决策。

`disasm_required` 是硬门禁：对 PSB 剧本文件恒为 true。
`unpack_mode` 是另一个基于证据的独立决策。对这些文件的判定是 `not-required`：
值图与字符串表直接可见，不存在压缩、加密或混淆层，chunk 表为空。不会为了寻找
文本而创建 `extracted/` 目录——文本在已解析的结构中本来就可寻址。
"""
from __future__ import annotations

from typing import Any

from ..core.types import CaseDecision, ProbeClaim
from ..formats import psb_spec as S
from ..formats.psb_header import read_header

PLUGIN_ID = "m2.psb.v3.scenario"


def probe(data: bytes, *, name: str = "") -> ProbeClaim:
    """对 PSB v3 剧本假设打分，但不提交解析。"""
    conflicts: list[str] = []
    claims: dict[str, Any] = {"name": name}
    score = 0.0

    if len(data) < S.HEADER_LENGTH_V3:
        return ProbeClaim(PLUGIN_ID, 0.0, "unknown", "little",
                          {"reason": "长度小于 PSB 文件头"},
                          conflicts=("too-short",), evidence="observed")
    if data[:4] != S.SIGNATURE:
        return ProbeClaim(PLUGIN_ID, 0.0, "unknown", "little",
                          {"signature": data[:4].hex()},
                          conflicts=("signature-mismatch",),
                          evidence="observed")
    score += 0.40
    claims["signature"] = "PSB\\0"

    header = read_header(data, strict=False)
    claims["version"] = header.version
    claims["header_encrypt"] = header.header_encrypt
    if header.version in S.SUPPORTED_VERSIONS:
        score += 0.15
    else:
        conflicts.append(f"unsupported-version-{header.version}")
    if header.header_encrypt == 0:
        score += 0.10
    else:
        conflicts.append("encrypted-header")

    checksum_ok = header.checksum == header.computed_checksum()
    claims["checksum_ok"] = checksum_ok
    claims["checksum_algorithm"] = "adler32(header[0x08:0x28])"
    score += 0.20 if checksum_ok else 0.0
    if not checksum_ok:
        conflicts.append("header-checksum-mismatch")

    chunkless = header.offset_chunk_data == len(data)
    claims["chunkless"] = chunkless
    score += 0.15 if chunkless else 0.0
    if not chunkless:
        conflicts.append("embedded-chunk-data")

    claims["sections_ordered"] = (
        S.HEADER_LENGTH_V3 == header.offset_names <= header.offset_entries
        <= header.offset_strings <= header.offset_strings_data
        <= header.offset_chunk_offsets <= header.offset_chunk_lengths
        <= header.offset_chunk_data)
    return ProbeClaim(
        plugin=PLUGIN_ID, score=round(score, 4),
        format_version=f"PSB v{header.version}", endianness="little",
        claims=claims,
        required_ranges=((0, S.HEADER_LENGTH_V3),
                         (header.offset_names, header.offset_entries),
                         (header.offset_entries, header.offset_strings)),
        conflicts=tuple(conflicts), evidence="observed")


MIN_SCORE = 0.85


def decide(claim: ProbeClaim, *, want_repack: bool = False) -> CaseDecision:
    """按决策矩阵把探针结论映射为案件决策。"""
    if claim.score < MIN_SCORE or claim.conflicts:
        return CaseDecision(
            analysis_mode="bytecode-disasm", disasm_required=True,
            unpack_mode="blocked", text_source="unknown",
            text_entries="none",
            decision_evidence_refs=(f"PROBE:{claim.plugin}",),
            decision_rationale=(
                "PROBE_SCORE_BELOW_THRESHOLD_OR_CONFLICT:"
                + ",".join(claim.conflicts or ("low-score",))))
    return CaseDecision(
        analysis_mode="bytecode-disasm",
        disasm_required=True,
        unpack_mode="full" if want_repack else "not-required",
        text_source="embedded",
        text_entries="targeted-evidence-only",
        decision_evidence_refs=(
            f"PROBE:{claim.plugin}", "CLAIM:chunkless", "CLAIM:checksum_ok"),
        decision_rationale=(
            "DIRECT_BYTECODE_VISIBLE_NO_ENVELOPE：值图与字符串表可直接寻址，"
            "无需解码任何压缩、加密或混淆层；chunk 表为空"))
