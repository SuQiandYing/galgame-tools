# -*- coding: utf-8 -*-
"""CatScene (CS2 / Nekopara-era kcClass engine) 方言声明。

本文件是**声明式数据**：没有控制流，可序列化、可 diff、可校验。
结构逻辑在 disassembler.py / assembler.py 中，那两个文件不得出现本文件里的任何魔数。

每个数值的证据登记在 vm_analysis.md，此处只给 evidence_refs。
"""

SCHEMA_VERSION = "1.0.0"
ENGINE_ID = "CATSCENE_CS2"
TOOL_VERSION = "cst-tool/1.0.0"
IR_VERSION = "IR/1"

# ---------------------------------------------------------------- 封装层
CONTAINER = {
    "magic": b"CatScene",
    "magic_size": 8,
    "header_size": 16,
    "field_com_size": {"offset": 8, "width": 4, "kind": "u32"},
    "field_unc_size": {"offset": 12, "width": 4, "kind": "u32"},
    "payload_offset": 16,
    "compression": {
        "algorithm": "zlib",
        "level": 9,
        "wbits": 15,
        "evidence_refs": ["EV_ZLIB_HDR", "EV_ZLIB_LEVEL9"],
        "confidence": "observed",
    },
    "evidence_refs": ["EV_MAGIC", "EV_HEADER16"],
    "confidence": "observed",
}

# ---------------------------------------------------------------- 容器形态
# 两种合法输入形态。第二种是「已经被外部脚本解压过」的裸载荷——常见于先用
# uncomFile 之类的脚本批量解压、再来做文本提取的工作流。
CONTAINER_FORMS = {
    "container": {
        "detect": "magic_matches",
        "description": "原始 .cst：CatScene 头 + zlib 压缩载荷",
        "rebuildable_to_container": True,
        "evidence_refs": ["EV_MAGIC", "EV_HEADER16"],
    },
    "bare-payload": {
        "detect": "payload_header_self_consistent",
        "description": "已解压的裸载荷：没有 CatScene 头，直接是载荷头 + 块表 + "
                       "偏移表 + 记录流。外部解压脚本（zlib.decompress 后直接落盘）"
                       "的产物即此形态。",
        "rebuildable_to_container": False,
        "evidence_refs": ["EV_PAYLOAD_HDR", "EV_BARE_PAYLOAD"],
    },
    "cstl": {
        "detect": "magic_matches_cstl",
        "description": "多语言文本覆盖层（.cstl）。不压缩、不加密，UTF-8。"
                       "与同名 .cst 按「页」一一对应：条目数恒等于 .cst 里"
                       "0x02+0x03 页结束记录的条数。",
        "rebuildable_to_container": False,
        "evidence_refs": ["EV_CSTL_MAGIC", "EV_CSTL_PAGE_JOIN"],
    },
}

# ---------------------------------------------------------------- CSTL 格式
# 长度与计数用 **0xFF 累加式变长整数**（LZ4 风格线性 varint），不是 LEB128：
#   value = 0; while b == 0xFF: value += 255; value += b
# 因此 ff ff 17 = 255+255+23 = 533，ff ab = 255+171 = 426。
# 把它当 LEB128 或 u8 读都会错位——这是本格式最容易踩的坑。
CSTL = {
    "magic": b"CSTL",
    "magic_size": 4,
    "reserved": {"offset": 4, "width": 4, "must_be_zero": True},
    "lang_count": {"offset": 8, "width": 1, "kind": "u8"},
    "varint": {"algorithm": "sum-of-0xFF", "terminator_max": 0xFE,
               "evidence_refs": ["EV_CSTL_VARINT"], "confidence": "observed"},
    # 每条 = 逐语言的 (说话者, 正文)，即 2 × 语言数 个串
    "slots_per_lang": 2,
    "slot_roles": ("name", "msg"),
    "encoding": "utf-8",
    "evidence_refs": ["EV_CSTL_MAGIC", "EV_CSTL_LAYOUT"],
    "confidence": "observed",
}

# .cstl 里每个槽位的标注。空说话者槽表示旁白，不导出（同 EMPTY_TEXT_RECORD 的道理）。
CSTL_SLOTS = {
    "name": {"tag": "name", "tag_subtype": "cstl-speaker",
             "tag_source": "structural", "translate_policy": "translatable",
             "evidence_refs": ["EV_CSTL_SPEAKER_JOIN"], "confidence": "observed"},
    "msg": {"tag": "msg", "tag_subtype": "cstl-message",
            "tag_source": "structural", "translate_policy": "translatable",
            "evidence_refs": ["EV_CSTL_PAGE_JOIN"], "confidence": "observed"},
}

# ---------------------------------------------------------------- 加密层探测
# 本作 980 个文件全为明文，无加密样本，故**未验证**任何具体算法（如实申报）。
# 下面是证据门控的探测框架：候选变换的接受条件是「解出的字节必须是合法 zlib 流，
# 且解压结果的载荷头四个字段自相一致」。这个条件强到几乎不可能假阳性，
# 因此即使没有加密样本也不会误判明文文件。任何候选都必须通过它才被采纳，
# 绝不因为「解出来像文本」就当成明文（铁律 4、§2.2「不得伪造明文」）。
CIPHER_PROBES = [
    {"id": "none", "algorithm": "identity", "params": {},
     "confidence": "observed", "evidence_refs": ["EV_ZLIB_HDR"]},
    {"id": "xor-byte", "algorithm": "xor-single-byte",
     "params": {"range": [1, 256]}, "confidence": "unresolved",
     "evidence_refs": [], "verified_on_sample": False},
    {"id": "xor-keyfile", "algorithm": "xor-repeating-key",
     "params": {"key_source": "user-supplied"}, "confidence": "unresolved",
     "evidence_refs": [], "verified_on_sample": False},
]

CIPHER_ACCEPT = {
    "must_be_valid_zlib": True,
    "must_have_consistent_payload_header": True,
    "must_parse_record_stream": True,
    "note": "三条全过才采纳；任一不过则该候选作废，全部候选作废则标 unresolved "
            "并保留原字节，不猜测",
}

# ---------------------------------------------------------------- 载荷布局
PAYLOAD = {
    "endianness": "little",
    "header": {
        "size": 16,
        "fields": [
            {"name": "payload_size", "offset": 0, "width": 4, "kind": "u32",
             "meaning": "载荷总长减去本 16 字节头", "mutable_on_edit": True},
            {"name": "block_count", "offset": 4, "width": 4, "kind": "u32",
             "meaning": "对话块数量", "mutable_on_edit": False},
            {"name": "table_offset", "offset": 8, "width": 4, "kind": "u32",
             "meaning": "记录偏移表起点，相对本头起点", "mutable_on_edit": False},
            {"name": "data_offset", "offset": 12, "width": 4, "kind": "u32",
             "meaning": "记录数据区起点，相对本头起点", "mutable_on_edit": False},
        ],
        "evidence_refs": ["EV_PAYLOAD_HDR"],
        "confidence": "derived",
    },
    "block_table": {
        "entry_size": 8,
        "fields": [
            {"name": "record_count", "offset": 0, "width": 4, "kind": "u32"},
            {"name": "first_record", "offset": 4, "width": 4, "kind": "u32",
             "key_kind": "table_ordinal"},
        ],
        "invariants": ["blocks_tile_record_stream", "derivable_from_page_break"],
        "evidence_refs": ["EV_BLOCK_TABLE", "EV_BLOCK_DERIVABLE"],
        "confidence": "derived",
    },
    "offset_table": {
        "entry_size": 4,
        "kind": "u32",
        "key_kind": "entry_offset",
        "relative_to": "data_offset",
        "invariants": ["first_is_zero", "monotonic", "contiguous_with_terminator"],
        "evidence_refs": ["EV_OFFSET_TABLE"],
        "confidence": "derived",
    },
    "record": {
        "prefix_byte": 1,
        "prefix_width": 1,
        "type_width": 1,
        "terminator": b"\x00",
        "evidence_refs": ["EV_RECORD_SHAPE"],
        "confidence": "derived",
    },
}

# ---------------------------------------------------------------- 记录类型
# type_byte -> 语义。全部四个取值在 980 个样本中穷举命中，无未知取值。
RECORD_TYPES = {
    0x30: {"mnemonic": "CMD", "role": "code", "tag": "misc",
           "tag_subtype": "command", "translate_policy": "frozen",
           "tag_source": "structural",
           "evidence_refs": ["EV_TYPE_CMD", "EV_PARALLEL_CMD_UNCHANGED"],
           "confidence": "observed"},
    0x20: {"mnemonic": "MSG", "role": "text", "tag": "msg",
           "tag_subtype": "dialogue", "translate_policy": "translatable",
           "tag_source": "structural",
           "evidence_refs": ["EV_TYPE_MSG", "EV_PARALLEL_MSG_CHANGED"],
           "confidence": "observed"},
    0x21: {"mnemonic": "NAME", "role": "text", "tag": "name",
           "tag_subtype": "speaker", "translate_policy": "translatable",
           "tag_source": "structural",
           "evidence_refs": ["EV_TYPE_NAME", "EV_PARALLEL_NAME_CHANGED"],
           "confidence": "observed"},
    0x02: {"mnemonic": "PAGE", "role": "control", "tag": "misc",
           "tag_subtype": "page-break", "translate_policy": "frozen",
           "tag_source": "structural",
           "evidence_refs": ["EV_TYPE_PAGE", "EV_BLOCK_DERIVABLE"],
           "confidence": "observed"},
    0x03: {"mnemonic": "PAGE2", "role": "control", "tag": "misc",
           "tag_subtype": "page-break-alt", "translate_policy": "frozen",
           "tag_source": "structural",
           "evidence_refs": ["EV_TYPE_PAGE2", "EV_BLOCK_DERIVABLE"],
           "confidence": "observed"},
}

TYPE_CMD = 0x30
TYPE_MSG = 0x20
TYPE_NAME = 0x21
TYPE_PAGE = 0x02
TYPE_PAGE2 = 0x03

# 块终止符集合。0x03 是 Yukikoi Melt 里出现的第二种页结束记录（payload 恒空、
# 恒为块尾）。两者都当终止符时，73 个文件的块表逐项可推导——见 EV_TYPE_PAGE2。
BLOCK_TERMINATORS = (TYPE_PAGE, TYPE_PAGE2)

# 零长度 MSG 记录是结构标记而非文本：980 个样本中 2,467/2,468 条紧邻页结束记录，
# 作用是「清空文本框」。它没有任何可翻译内容，因此不导出到双行文本（§4.6：
# 译者无法据此做出任何不同的操作的行，一律不写），但仍完整保留在 IR 与覆盖证书中。
EMPTY_TEXT_RECORD = {
    "applies_to_types": (TYPE_MSG,),
    "condition": "payload_length_zero",
    "tag": "misc",
    "tag_subtype": "page-flush",
    "tag_source": "structural",
    "translate_policy": "frozen",
    "export_to_text_file": False,
    "evidence_refs": ["EV_EMPTY_MSG_BEFORE_PAGE", "EV_PARALLEL_EMPTY_UNCHANGED"],
    "confidence": "observed",
}

# 记录类型必须穷举（§0.2）。未见过的取值一律 unresolved，不走已知分支。
KNOWN_TYPE_BYTES = frozenset(RECORD_TYPES)

# ---------------------------------------------------------------- 编码
ENCODING = {
    "source": "cp932",
    "target": "cp932",
    "text_file": "utf-8-sig",
    "asm": "utf-8",
    "evidence_refs": ["EV_ENCODING_CP932"],
    "confidence": "observed",
}

# ---------------------------------------------------------------- 命令内文本规则
# 前置条件均为「已由记录类型证明是 CMD 记录」，规则只在 CMD 记录的操作数上做次级消歧。
# group(1) = 不可编辑前缀，group(2) = 可编辑文本，group(3) = 不可编辑后缀。
TEXT_RULES = [
    {
        "id": "choice-entry",
        "tag": "choice",
        "tag_subtype": "select-branch",
        "tag_source": "anchor",
        "translate_policy": "translatable",
        "requires_open_command": "fselect",
        "pattern": r"^([0-9]+ [^ ]+ )(.+?)([ ]*)$",
        "evidence_refs": ["EV_FSELECT_BLOCK", "EV_PARALLEL_CHOICE_CHANGED"],
        "confidence": "derived",
    },
    {
        "id": "scene-title",
        "tag": "misc",
        "tag_subtype": "scene-title",
        "tag_source": "anchor",
        "translate_policy": "review-required",
        "requires_open_command": None,
        "pattern": r"^(str [0-9]+ )([^ ].*?)([ ]*)$",
        "evidence_refs": ["EV_STR_SLOT", "EV_PARALLEL_STR_UNCHANGED"],
        "confidence": "derived",
    },
]

# fselect 块的结构终止条件优于固定窗口（§1.6）：遇到第一条不符合 choice 形态的记录即闭合。
CHOICE_OPEN_COMMAND = "fselect"
COMMAND_HEAD_SEPARATOR = " "

# 内联标记，仅用于「这条 msg 是否只含标记与空白」的统计判定，不参与回封改写。
MARKUP_PATTERN = r"\\(pc|[a-z@])"
IDEOGRAPHIC_SPACE = "　"

# ---------------------------------------------------------------- 窗口常量
WINDOWS = [
    {"name": "choice_block_span", "value": 8, "measured_max": 4,
     "evidence": "980 个样本中 fselect 块实测最大 4 条选项（KAG06c/KAG08c_RET1 为 3，"
                 "另有 1 处 4）；本值仅用于报告上限命中，闭合靠结构条件",
     "on_exceed": "blocked"},
    {"name": "name_bind_span", "value": 0, "measured_max": 0,
     "evidence": "绑定不用窗口：块内至多一条 NAME 记录（实测 0 或 1，见 EV_NAME_PER_BLOCK），"
                 "因此绑定由块归属直接给出，无需前瞻",
     "on_exceed": "blocked"},
]

# ---------------------------------------------------------------- 双行文本文件格式
# 这些是**格式声明**（数据），放在方言模块以避免结构逻辑内联正则（§7）。
TEXT_FORMAT = {
    "version": 2,
    "orig_mark": "○",
    "tran_mark": "●",
    "idx_width": 8,
    "header_line1": "# TEXT/2 ir={ir} tool={tool} src_sha256={job_sha256} "
                    "file_sha256={file_sha256}",
    "header_line2": "# encoding source={source} target={target} file=utf-8",
    "header_line3": "# scope kind=partition part=1/1 src={src}",
    "header_line4": "# tags name msg choice label ui system ruby misc",
    "orig_re": r"^○(?P<idx>\d{8})○(?P<tag>[a-z_]+)○(?P<text>.*)$",
    "tran_re": r"^●(?P<idx>\d{8})●(?P<tag>[a-z_]+)●(?P<text>.*)$",
    "meta_line": "# idx={idx} off={off} rec={rec} tag={tag} policy={policy}",
    "meta_line_speaker": "# idx={idx} off={off} rec={rec} tag={tag} policy={policy}"
                         " speaker={speaker}",
    "placeholder_re": r"\{\{([0-9A-F]{2}(?::[0-9A-F]{2})*)\}\}",
    "placeholder_loose_re": r"\{\{[^}]*\}\}",
    "placeholder_open": "{{",
    "placeholder_close": "}}",
    "placeholder_sep": ":",
    "comment_prefix": "#",
    # 解析本工具自有产物（双行文件头）所需的正则，同属格式声明。
    "kv_re": r"(\w+)=(\S+)",
    "header1_re": r"^#\s*TEXT/(?P<ver>\d+)\s+(?P<rest>.*)$",
    "part_re": r"(\d+)/(\d+)",
    "scope_kinds": ("all", "idx-range", "partition"),
    "policies": ("translatable", "length-locked", "review-required", "frozen"),
    "encoding_candidates": ("utf-8", "gbk", "big5", "cp932", "cp949"),
}

# 允许出现在双行文件里的 tag 闭集（§4.2）。方言不得扩展。
TAG_CLOSED_SET = ("name", "msg", "choice", "label", "ui", "system", "ruby", "misc")

# ---------------------------------------------------------------- asm 视图
ASM = {
    "encoding_directive": '.encoding "{enc}"',
    "dialect_directive": '.dialect  "{engine}" version "{ver}"',
    "tier_directive": '.tier     "{tier}"',
    "label_format": "blk_{n:08d}:",
    "record_format": "    {mnemonic:<5} {idx}, {payload}",
    "string_directive": '    .string "{text}"',
    "byte_directive": "    .byte {values}",
    "comment_prefix": ";",
}

# ---------------------------------------------------------------- 分级申报
TIERS = {
    "container_header": "T2",
    "payload_header": "T2",
    "block_table": "T2",
    "offset_table": "T2",
    "record_stream": "T3",
    "min_tier": "T2",
    "declared_capabilities": ["roundtrip", "in_place", "pointer-rewrite"],
    "instruction_coverage": "not_applicable",
}

DECISION = {
    "analysis_mode": "bytecode-disasm",
    "declared_tier": "T2",
    "unpack_mode": "targeted",
    "text_source": "embedded",
    "repack_strategy": "auto",
    "dialect_id": ENGINE_ID,
    "decision_evidence_refs": ["EV_MAGIC", "EV_ZLIB_HDR", "EV_RECORD_SHAPE"],
    "decision_rationale": "文本封在 zlib 压缩载荷内，必须解该层才能观察记录流；"
                          "载荷内既是代码也是文本，故 targeted 而非 full。",
    "user_override": None,
}

# ---------------------------------------------------------------- 产出合理性门禁
# §0.1：以下任一命中即失败，不允许当作「样本特性」放过。
SANITY = {
    "require_nonzero_tags": ("msg", "name"),
    "max_single_tag_share": 0.95,
    "min_msg_per_kib": 0.05,
    "expect_all_type_bytes_known": True,
}
