"""EAGLS / SCPACK 方言声明（声明式数据，无控制流）。

本文件是唯一允许出现引擎特定字面量的地方：密钥、偏移、记录宽度、语句形态、
文本规则、窗口常量。结构逻辑在 profile_scpack.py，它只读取本声明，不含任何
引擎字面量（由 scripts/check_no_literals.py 机械校验）。

每个数值的证据登记在 vm_analysis.md，`evidence_refs` 指向那里的小节。
"""

from __future__ import annotations

SCHEMA_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# PRNG：两层加密共用的 MSVCRT rand()。参数是引擎密码学参数，不是通用常量。
# ---------------------------------------------------------------------------
PRNG = {
    "algorithm": "MSVCRT_RAND",
    "multiplier": 214013,
    "increment": 2531011,
    "mask": 2147483647,
    "shift": 16,
    "evidence_refs": ["EV_PRNG"],
    "confidence": "observed",
}

# ---------------------------------------------------------------------------
# 归档层：SCPACK.idx（索引，整体加密）+ SCPACK.pak（数据，逐条目加密）
# ---------------------------------------------------------------------------
ARCHIVE = {
    "idx_name": "SCPACK.idx",
    "pak_name": "SCPACK.pak",
    # 记录 = 定长文件名 + 偏移 + 长度。宽度由 idx 体积选择（长偏移变体用 int64）。
    "record": {
        "short": {"name_size": 20, "field_width": 4, "field_kind": "u32"},
        "long": {"name_size": 24, "field_width": 8, "field_kind": "i64"},
    },
    # 选择长偏移变体的结构判据（原始 idx 字节数 / 10000 >= 40）。
    "long_offset_probe": {"divisor": 10000, "threshold": 40,
                          "evidence_refs": ["EV_IDX_LONG"]},
    # idx 整体 XOR：密钥按 rand() % len(key) 取字节，种子为文件末 4 字节 u32。
    "idx_cipher": {
        "algorithm": "XOR_PRNG_KEYSTREAM",
        "seed_source": "trailing_u32",
        "seed_field_width": 4,
        "key_candidates": ["1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/-@:^[]"],
        "evidence_refs": ["EV_IDX_KEY"],
        "confidence": "observed",
    },
    "terminator": {"kind": "zero_name_field", "evidence_refs": ["EV_IDX_TERM"]},
    "tail": {"kind": "zero_pad_then_seed", "evidence_refs": ["EV_IDX_TAIL"]},
}

# ---------------------------------------------------------------------------
# 条目层：标签表（明文）+ 零填充 + 脚本正文（加密）+ 1 字节种子（明文）
# ---------------------------------------------------------------------------
ENTRY = {
    "label_record": {
        "size": 36,
        "name_size": 32,
        "offset_field_width": 4,
        "offset_field_kind": "u32",
        "alis_size": 136,
        "evidence_refs": ["EV_LABEL_TABLE"],
        "confidence": "observed",
    },
    # 正文起点由结构推导：标签表结束后第一处非零字节向上取整到 granularity。
    # expected 只作交叉校验，不作为解析依据（§7.5.2 禁止按文件名/常量硬选）。
    "text_offset": {
        "derive": "ceil_first_nonzero_after_label_table",
        "granularity": 100,
        "expected": 3600,
        "alis_fixed": 136000,
        "evidence_refs": ["EV_TEXT_OFFSET"],
        "confidence": "derived",
    },
    "seed_byte": {"position": "last", "width": 1, "signed": True,
                  "evidence_refs": ["EV_ENTRY_SEED"]},
    # 正文加密：v1 = 连续 XOR；v2 = 隔字节 XOR，密钥下标由 rand() 给出。
    "pak_cipher": {
        "algorithm": "XOR_PRNG_STRIDE",
        "key_candidates": ["EAGLS_SYSTEM"],
        "versions": {
            1: {"stride": 1, "index_source": "position", "tail_reserved": 1},
            2: {"stride": 2, "index_source": "prng", "tail_reserved": 1},
        },
        "evidence_refs": ["EV_PAK_KEY", "EV_PAK_CIPHER_V2"],
        "confidence": "observed",
    },
    "encoding": {"source": "cp932", "target": "cp932", "asm": "utf-8"},
}

# ---------------------------------------------------------------------------
# 语句形态（T2 锚点）。EAGLS 正文是 CP932 文本 DSL，不是二进制字节码，因此
# 「指令边界」在字符层面。每个形态自带纯谓词式起始判定，判定失败不回落（§7.5.3）。
# 声明顺序即判定顺序。
# ---------------------------------------------------------------------------
STATEMENT_SHAPES = [
    {
        "id": "nul",
        "kind": "terminator",
        "match": {"first_char_in": "\x00"},
        "span": "single_char",
        "evidence_refs": ["EV_ENTRY_SEED"],
    },
    {
        "id": "whitespace",
        "kind": "trivia",
        "match": {"first_char_in": " \t\r\n"},
        "span": "run_of_chars",
        "run_chars": " \t\r\n",
        "evidence_refs": ["EV_STMT_WS"],
    },
    {
        "id": "label",
        "kind": "label-def",
        "match": {"first_char_in": "$"},
        "span": "until_char",
        "until_char": "\n",
        "include_until": True,
        "name_slot": {"start": 1, "strip": "\r\n"},
        "evidence_refs": ["EV_LABEL_TABLE", "EV_LABEL_DOLLAR"],
        "confidence": "observed",
    },
    {
        "id": "speaker",
        "kind": "param-set",
        "match": {"first_char_in": "#"},
        "span": "until_any_char",
        "until_any": "\r\n",
        "include_until": False,
        "text_slot": {"start": 1},
        "evidence_refs": ["EV_SPEAKER_HASH", "EV_SPEAKER_BINDING"],
        "confidence": "derived",
    },
    {
        "id": "message",
        "kind": "call",
        "match": {"first_char_in": "&", "pattern_id": "message"},
        "span": "pattern",
        "id_group": 1,
        "text_group": 2,
        "evidence_refs": ["EV_MSG_AMP", "EV_MSG_ID_UNIQUE"],
        "confidence": "observed",
    },
    {
        "id": "block-close",
        "kind": "table-slot",
        "match": {"first_char_in": "}", "pattern_id": "block_close"},
        "span": "pattern",
        "evidence_refs": ["EV_BLOCK_PAIR"],
        "confidence": "derived",
    },
    {
        "id": "block-open-bare",
        "kind": "table-slot",
        "match": {"first_char_in": "{"},
        "span": "single_char",
        "evidence_refs": ["EV_BLOCK_PAIR"],
    },
    {
        "id": "call",
        "kind": "call",
        "match": {"first_char_digit": True, "pattern_id": "call_head"},
        "span": "balanced_parens",
        "absorb_trailing": "{",
        "opcode_group": 1,
        "sub_opcode_group": 2,
        "evidence_refs": ["EV_CALL_NUMERIC", "EV_CALL_ARGS"],
        "confidence": "derived",
    },
    {
        "id": "block-open-numbered",
        "kind": "table-slot",
        "match": {"first_char_digit": True, "pattern_id": "block_open"},
        "span": "pattern",
        "evidence_refs": ["EV_BLOCK_PAIR"],
        "confidence": "derived",
    },
    {
        "id": "assign",
        "kind": "push",
        "match": {"first_char_in": ":_@", "first_char_alpha": True,
                  "pattern_id": "assign_head"},
        "span": "rpn_until_statement_boundary",
        "target_group": 1,
        "index_group": 2,
        "evidence_refs": ["EV_ASSIGN", "EV_ASSIGN_RPN"],
        "confidence": "derived",
    },
]

# 形态判定用到的正则。写在方言里而非代码里，因此可审阅、可统计、可单独测试。
PATTERNS = {
    "message": r'&([0-9]+)"([^"]*)"',
    "block_close": r"\}([0-9]+);",
    "block_open": r"([0-9]+),([0-9]+)\{",
    "call_head": r"([0-9]+)(?:,([0-9]+))?\(",
    "assign_head": r"([:_@A-Za-z]\w*)(\[[^\]]*\])?=",
    # 语句起始集合：判定 ASSIGN 的 RPN 何时结束（逗号后是否已是下一条语句）。
    "statement_start": (
        r'\$|#|&[0-9]+"|\}[0-9]+;|\{|[0-9]+(?:,[0-9]+)?[(\{]'
        r'|[:_@A-Za-z]\w*(?:\[[^\]]*\])?=|\x00'
    ),
    # 消息内联标记，例如 (E) 换页、(F=5) 字体、(Y=…) 注音、(C=r,g,b) 颜色。
    "inline_tag": r"\(([A-Z])(?:=([^)]*))?\)",
    "quoted_arg": r'"([^"]*)"',
    "voice_suffix": r"^(?P<name>.*)=(?P<voice>[A-Za-z0-9_]+)$",
}

# RPN 表达式扫描：括号/方括号计深度，引号内忽略，深度 0 的逗号可能是语句结束。
RPN_SCAN = {
    "open_chars": "([",
    "close_chars": ")]",
    "quote_char": '"',
    "separator": ",",
    "abort_chars": "\x00",
    "evidence_refs": ["EV_ASSIGN_RPN"],
}

# 括号平衡扫描（CALL 参数）。
PAREN_SCAN = {"open_char": "(", "close_char": ")", "quote_char": '"'}

# ---------------------------------------------------------------------------
# 调用组：哪些 opcode 的哪个参数槽承载可见文本。槽位序号从 0 起，按逗号切分
# （引号内的逗号不切）。只有列在此处的槽位才会被提取为文本条目 —— 未列出的
# 一律不提取，也不会被静默当作文本（§4.3 无兜底规则）。
# ---------------------------------------------------------------------------
CALLEE_GROUPS = [
    {
        "id": "chapter-title",
        "opcodes": ["47"],
        "text_slots": [0],
        "slot_form": "bare",          # 未加引号的裸参数
        "role": "ui",
        "subtype": "chapter-title",
        "evidence_refs": ["EV_OP47_TITLE"],
        "confidence": "derived",
    },
    {
        "id": "variable-set",
        "opcodes": ["52"],
        "text_slots": [1],
        "slot_form": "quoted",
        "role": "misc",
        "subtype": "variable-value",
        "name_slot": 0,               # 槽 0 是变量名，用于二级消歧
        "evidence_refs": ["EV_OP52_SETVAR"],
        "confidence": "derived",
    },
    {
        "id": "text-format",
        "opcodes": ["151"],
        "text_slots": [1],
        "slot_form": "quoted",
        "role": "ui",
        "subtype": "name-style-label",
        "evidence_refs": ["EV_OP151_FORMAT"],
        "confidence": "inferred",
    },
]

# ---------------------------------------------------------------------------
# 文本规则：只在**已由 CALLEE_GROUPS 证明为文本参数**的候选内做次级消歧
# （§4.3：heuristic 不得从零发现条目）。谓词是 core 实现的闭集，方言只组合。
# 按声明顺序求值，首个命中即返回，命中数逐规则统计写入 rule_hits.json。
# ---------------------------------------------------------------------------
TEXT_RULES = [
    {
        "id": "choice-line",
        "requires_callee_group": "variable-set",
        "predicates": [
            {"kind": "requires_name_slot_prefix", "value": "_Character"},
            {"kind": "contains_script", "value": "cjk-or-kana"},
        ],
        "tag": "choice",
        "tag_source": "heuristic",
        "translate_policy": "translatable",
        "confidence": "inferred",
        "evidence_refs": ["EV_CHOICE_CHARACTER"],
    },
    {
        "id": "protagonist-name",
        "requires_callee_group": "variable-set",
        "predicates": [
            {"kind": "requires_name_slot_prefix", "value": ":NameSuffix"},
            {"kind": "contains_script", "value": "cjk-or-kana"},
        ],
        "tag": "name",
        "tag_source": "heuristic",
        "translate_policy": "translatable",
        "confidence": "inferred",
        "evidence_refs": ["EV_NAMESUFFIX_DEFAULT"],
    },
    {
        "id": "variable-visible-text",
        "requires_callee_group": "variable-set",
        "predicates": [{"kind": "contains_script", "value": "cjk-or-kana"}],
        "tag": "misc",
        "tag_source": "heuristic",
        "translate_policy": "review-required",
        "confidence": "inferred",
        "evidence_refs": ["EV_OP52_SETVAR"],
    },
    {
        "id": "format-string",
        "requires_callee_group": "text-format",
        "predicates": [{"kind": "contains_script", "value": "cjk-or-kana"}],
        "tag": "ui",
        "tag_source": "heuristic",
        "translate_policy": "translatable",
        "confidence": "inferred",
        "evidence_refs": ["EV_OP151_FORMAT"],
    },
    {
        "id": "chapter-title-text",
        "requires_callee_group": "chapter-title",
        "predicates": [{"kind": "min_length", "value": 1}],
        "tag": "ui",
        "tag_source": "anchor",
        "translate_policy": "translatable",
        "confidence": "derived",
        "evidence_refs": ["EV_OP47_TITLE"],
    },
]

# 判定「含日文/中文」用的字符区间。写成区间声明而非代码内正则，才能被审阅。
SCRIPT_RANGES = {
    "cjk-or-kana": [
        [0x3000, 0x303F],   # CJK 标点、全角空格
        [0x3040, 0x309F],   # 平假名
        [0x30A0, 0x30FF],   # 片假名
        [0x4E00, 0x9FFF],   # 汉字
        [0xFF00, 0xFFEF],   # 全角 ASCII / 半角假名
        [0x2010, 0x2027],   # 破折号、省略号
        [0x2500, 0x257F],   # 制表符（──）
        [0x25A0, 0x266F],   # 记号、♪ 等
    ],
}

# ---------------------------------------------------------------------------
# 说话者绑定：`#名前=voiceid` 紧接一条 `&id"正文"`。实测 11,874 处 `#` 之后
# 的下一条语句 100% 是 message，因此 method=slot-ordinal（结构相邻的固定序），
# 不是 adjacency 猜测。
# ---------------------------------------------------------------------------
NAME_BINDING = {
    "method": "slot-ordinal",
    "source_shape": "speaker",
    "target_shape": "message",
    "max_intervening_shapes": ["whitespace"],
    "voice_pattern_id": "voice_suffix",
    # `#:NameSuffix` 表示「说话者是主角」，值存在同名变量里而非写在此处，故为虚拟名
    # （§4.7 name_kind=virtual）。虚拟名必须记来源与解析方式，且**不得**伪造成
    # 可编辑的 name 条目 —— 它的可编辑入口是 variable-set 组里那条 `:NameSuffix` 赋值。
    "virtual_names": {
        ":NameSuffix": {
            "resolve_from": "variable-set",   # 由该调用组的赋值提供实际值
            "variable": ":NameSuffix",
            "fallback_label": "主角",
            # 照常导出 name 条目（§4.6：frozen 条目仍然导出，隐藏会让漏译无法发现），
            # 但锁定为 frozen —— `#` 之后是变量名而非人名，改它会改掉变量引用。
            # 可编辑入口是 variable-set 组里那条赋值，其 idx 写在注释的 edit_at=。
            "emit_entry": True,
            "subtype": "virtual-speaker-ref",
            "translate_policy": "frozen",
            "evidence_refs": ["EV_NAMESUFFIX_DEFAULT", "EV_NAMESUFFIX_VIRTUAL"],
        },
    },
    "evidence_refs": ["EV_SPEAKER_BINDING", "EV_SPEAKER_HASH"],
    "confidence": "derived",
}

# ---------------------------------------------------------------------------
# 窗口常量（§1.6）。每个带实测值与超限行为，不得静默截断。
# ---------------------------------------------------------------------------
WINDOWS = [
    {"name": "idx_key_probe_span", "value": 8192, "measured_max": 8192,
     "evidence": "idx 尾部零填充区长 387,720 字节，取末 8192 字节即可覆盖全部密钥下标",
     "on_exceed": "blocked"},
    {"name": "idx_key_max_len", "value": 1024, "measured_max": 46,
     "evidence": "实测 idx_key 长 46 字节；上限留冗余",
     "on_exceed": "blocked"},
    {"name": "pak_key_max_len", "value": 1024, "measured_max": 12,
     "evidence": "实测 pak_key = EAGLS_SYSTEM，长 12 字节",
     "on_exceed": "blocked"},
    {"name": "text_offset_scan_limit", "value": 136000, "measured_max": 3600,
     "evidence": "标准变体实测 3600；ALIS 变体固定 136000，取其为上限",
     "on_exceed": "blocked"},
]

# 双行文本文件（§4.6）。
DSAT = {
    "format_version": 2,
    "orig_mark": "○",
    "tran_mark": "●",
    "idx_width": 8,
    "file_encoding": "utf-8-sig",
    "tags": ["name", "msg", "choice", "label", "ui", "system", "ruby", "misc"],
    # 解析自有产物格式的正则也写在声明里：位置一致，且可被单独测试。
    "patterns": {
        "header_line1": r"# TEXT/(?P<ver>\d+)(?P<rest>.*)$",
        "meta_field": r"(\w+)=(\S+)",
        "shard": r"(\d+)/(\d+)",
        "placeholder": r"\{\{([0-9A-F]{2}(?::[0-9A-F]{2})*)\}\}",
        "placeholder_loose": r"\{\{[^}]*\}\}",
    },
    "diagnostic_preview_chars": 80,
}

DIALECT = {
    "schema_version": SCHEMA_VERSION,
    "engine_id": "EAGLS_SCPACK",
    "dialect_id": "HENSIN_PKPDL",
    "endianness": "little",
    "prng": PRNG,
    "archive": ARCHIVE,
    "entry": ENTRY,
    "statement_shapes": STATEMENT_SHAPES,
    "patterns": PATTERNS,
    "rpn_scan": RPN_SCAN,
    "paren_scan": PAREN_SCAN,
    "callee_groups": CALLEE_GROUPS,
    "text_rules": TEXT_RULES,
    "script_ranges": SCRIPT_RANGES,
    "name_binding": NAME_BINDING,
    "windows": WINDOWS,
    "dsat": DSAT,
}
