"""所有阶段共用的规范化数据模型。

术语沿用技能契约：SourceArtifact、Layer/TransformEdge、Region、VmDefinition、
CanonicalIR、ChangeSet、LayoutPlan、CoverageCertificate。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

RegionStatus = Literal[
    "decoded",
    "structured-unknown",
    "unknown_opaque_block",
    "opaque-preserved",
    "padding",
    "proven-gap",
]

Evidence = Literal["observed", "derived", "inferred", "unresolved"]

AnalysisMode = Literal["host-disasm", "bytecode-disasm", "mixed-disasm", "data-text-only"]

UnpackDecision = Literal["not-required", "targeted", "full", "blocked", "skipped-by-plan"]

TextTag = Literal["name", "msg", "choice", "label", "ui", "system", "ruby"]

RepackMode = Literal["in_place", "lossless-relocatable", "semantic-rebuild"]


@dataclass(frozen=True, slots=True)
class SourceArtifact:
    """输入文件的只读指纹。"""

    path: str
    byte_size: int
    sha256: str
    md5: str
    crc32: int


@dataclass(frozen=True, slots=True)
class ProbeClaim:
    """带评分的格式假设，以及它成立所依赖的区间。"""

    plugin: str
    score: float
    format_version: str
    endianness: str
    claims: dict[str, Any] = field(default_factory=dict)
    required_ranges: tuple[tuple[int, int], ...] = ()
    conflicts: tuple[str, ...] = ()
    evidence: Evidence = "derived"


@dataclass(slots=True)
class Region:
    """某一 layer 中半开区间 [start, end) 的唯一归属记录。"""

    id: str
    layer_id: str
    start: int
    end: int
    status: RegionStatus
    kind: str
    owner: str
    raw_sha256: str = ""
    confidence: float = 1.0
    evidence_refs: tuple[str, ...] = ()
    rewrite_policy: str = "from-ir"
    checks: dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(slots=True)
class TransformEdge:
    """可重放的父层 -> 子层变换关系。"""

    parent_layer: str
    child_layer: str
    parent_span: tuple[int, int]
    input_sha256: str
    output_sha256: str
    algorithm: str
    parameters: dict[str, Any] = field(default_factory=dict)
    key_ref: str | None = None
    tool_fingerprint: str = ""
    replay_command: str = ""
    reversible: bool = True


@dataclass(slots=True)
class TextEntry:
    """从 IR 投影出来的一个可翻译单元。"""

    idx: int
    file: str
    off: int
    inst: int
    tag: TextTag
    source: str
    target: str
    encoding: str
    policy: str
    node_offset: int
    string_id: int
    path: str
    speaker: str | None = None
    speaker_confidence: str = "derived"
    ph_count: int = 0
    ph_bytes: int = 0
    ph_hash: str = ""
    ph_policy: str = "strict-preserve"
    # 指向同一物理节点的其他剧本路径（值图去重的结果）。它们共享同一份存储，
    # 因此只能有一条译文。
    aliases: tuple[str, ...] = ()


@dataclass(slots=True)
class CaseDecision:
    """写入 case.json 的决策快照；CLI、GUI 与报告共用同一套枚举。"""

    analysis_mode: AnalysisMode = "bytecode-disasm"
    disasm_required: bool = True
    unpack_mode: UnpackDecision = "not-required"
    text_source: str = "embedded"
    text_entries: str = "targeted-evidence-only"
    decision_evidence_refs: tuple[str, ...] = ()
    decision_rationale: str = "DIRECT_BYTECODE_VISIBLE"

    def to_json(self) -> dict[str, Any]:
        return {
            "analysis_mode": self.analysis_mode,
            "disasm_required": self.disasm_required,
            "unpack_mode": self.unpack_mode,
            "text_source": self.text_source,
            "text_entries": self.text_entries,
            "decision_evidence_refs": list(self.decision_evidence_refs),
            "decision_rationale": self.decision_rationale,
        }


@dataclass(slots=True)
class ChangeSet:
    """按约定不可变的编辑记录，在计算 ImpactClosure 之前生成。"""

    source_sha256: str
    edits: list[dict[str, Any]] = field(default_factory=list)
    origin: str = "dsat-import"

    def is_empty(self) -> bool:
        return not self.edits


@dataclass(slots=True)
class LayoutPlan:
    """顺序、偏移、宽度与回填次序的可执行解。"""

    mode: RepackMode
    node_order: list[int] = field(default_factory=list)
    node_offsets: dict[int, int] = field(default_factory=dict)
    string_order: list[int] = field(default_factory=list)
    string_offsets: dict[int, int] = field(default_factory=dict)
    section_offsets: dict[str, int] = field(default_factory=dict)
    total_size: int = 0
    widened_nodes: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class VerifyReport:
    """原始工件与重建工件的比较结果。"""

    identical: bool
    original: SourceArtifact | None = None
    rebuilt: SourceArtifact | None = None
    first_diff_offset: int | None = None
    expected_byte: int | None = None
    actual_byte: int | None = None
    hexdiff: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
