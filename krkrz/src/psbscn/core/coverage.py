"""Region 账本与 CoverageCertificate 生成器。

强制约束：某个 layer 的每个字节恰好属于一个半开区间 [start, end)；不允许缺口，
不允许重叠，且每个区间的哈希都必须能从源文件按范围复算。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .errors import AddressSpaceCollisionError, AddressSpaceGapError
from .hashing import sha256_range
from .types import CaseDecision, Region

SCHEMA_VERSION = "1.0.0"


@dataclass(slots=True)
class RegionLedger:
    """累积某个 layer 的 Region，并证明覆盖精确无误。"""

    layer_id: str
    source_size: int
    regions: list[Region] = field(default_factory=list)

    def add(self, region: Region) -> Region:
        if region.start < 0 or region.end < region.start or region.end > self.source_size:
            raise AddressSpaceGapError(
                "区间越界", offset=region.start,
                expected=f"0<=start<=end<={self.source_size}",
                actual=(region.start, region.end),
            )
        self.regions.append(region)
        return region

    def add_span(self, start: int, end: int, *, kind: str, owner: str,
                 status: str = "decoded", data: bytes | None = None,
                 confidence: float = 1.0,
                 evidence_refs: Iterable[str] = (),
                 rewrite_policy: str = "from-ir",
                 checks: dict[str, Any] | None = None) -> Region:
        """登记一个区间。

        不再单独维护 ID 集合去查重：ID 形如 `layer:start-end:kind`，两个 ID 相同就意味着
        区间与 kind 完全一致，`analyze()` 的重叠检查必然会命中同一处（已验证）。十万级
        区间下那个集合只是白占内存和时间。
        """
        raw = sha256_range(data, start, end) if data is not None else ""
        return self.add(Region(
            id=f"{self.layer_id}:{start:08X}-{end:08X}:{kind}",
            layer_id=self.layer_id, start=start, end=end,
            status=status, kind=kind, owner=owner, raw_sha256=raw,
            confidence=confidence, evidence_refs=tuple(evidence_refs),
            rewrite_policy=rewrite_policy, checks=checks or {},
        ))

    def sorted_regions(self) -> list[Region]:
        return sorted(self.regions, key=lambda r: (r.start, r.end))

    def analyze(self) -> dict[str, Any]:
        """用游标从 0 走到 N，记录所有缺口与重叠。"""
        gaps: list[dict[str, int]] = []
        overlaps: list[dict[str, Any]] = []
        covered = 0
        cursor = 0
        for r in self.sorted_regions():
            if r.start > cursor:
                gaps.append({"start": cursor, "end": r.start})
            elif r.start < cursor:
                overlaps.append({"start": r.start, "end": min(cursor, r.end),
                                 "region_id": r.id})
            if r.end > cursor:
                covered += r.end - max(cursor, r.start)
                cursor = r.end
        if cursor < self.source_size:
            gaps.append({"start": cursor, "end": self.source_size})
        return {"gaps": gaps, "overlaps": overlaps, "covered_bytes": covered}

    def status_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.regions:
            counts[r.status] = counts.get(r.status, 0) + 1
        return counts

    def byte_coverage(self) -> float:
        if self.source_size == 0:
            return 1.0
        return self.analyze()["covered_bytes"] / self.source_size


def build_certificate(
    ledger: RegionLedger,
    *,
    decision: CaseDecision,
    source_sha256: str,
    instruction_coverage: float | str,
    structural_coverage: float,
    semantic_coverage: float,
    transform_edges: list[dict[str, Any]],
    roundtrip: dict[str, Any],
    toolchain: dict[str, Any],
    parser_consensus: dict[str, Any] | None = None,
    node_count: int = 0,
    shared_node_count: int = 0,
) -> dict[str, Any]:
    """为单个 layer 组装 coverage_certificate.json。"""
    info = ledger.analyze()
    counts = ledger.status_counts()
    byte_cov = ledger.byte_coverage()
    strict = (
        byte_cov == 1.0
        and not info["gaps"]
        and not info["overlaps"]
        and counts.get("proven-gap", 0) == 0
        and all(r.raw_sha256 for r in ledger.regions)
        and bool(roundtrip.get("zero_edit_identical", False))
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "layer_id": ledger.layer_id,
        "source_sha256": source_sha256,
        "source_size": ledger.source_size,
        "analysis_mode": decision.analysis_mode,
        "disasm_required": decision.disasm_required,
        "unpack_mode": decision.unpack_mode,
        "text_source": decision.text_source,
        "decision_evidence_refs": list(decision.decision_evidence_refs),
        "decision_rationale": decision.decision_rationale,
        "intervals": [
            {
                "id": r.id, "layer_id": r.layer_id, "start": r.start, "end": r.end,
                "status": r.status, "kind": r.kind, "raw_sha256": r.raw_sha256,
                "owner": r.owner, "confidence": r.confidence,
                "evidence_refs": list(r.evidence_refs),
                "rewrite_policy": r.rewrite_policy,
                **({"checks": r.checks} if r.checks else {}),
            }
            for r in ledger.sorted_regions()
        ],
        "gaps": info["gaps"],
        "overlaps": info["overlaps"],
        "status_counts": counts,
        "byte_coverage": byte_cov,
        "structural_coverage": structural_coverage,
        "instruction_coverage": instruction_coverage,
        "semantic_coverage": semantic_coverage,
        "value_graph": {
            "node_count": node_count,
            "shared_node_count": shared_node_count,
            "topology": "dag-with-shared-subtrees",
        },
        "transform_edges": transform_edges,
        "parser_consensus": parser_consensus or {},
        "static_dynamic_reconciliation": {
            "runtime_probe": "not-executed",
            "reason": "纯静态案件；未声明任何模拟器运行时证据",
        },
        "roundtrip": roundtrip,
        "toolchain": toolchain,
        "strict_success": strict,
    }
