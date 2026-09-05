# -*- coding: utf-8 -*-
"""opcodelist.py — MOA 引擎方言声明（憑夜ノ村 / Astronauts, moacode.mwb）

本文件是**声明式数据**：字节码 tag 编码、容器布局、内建函数表、文本规则。
结构逻辑（token 流解析、重定位、双行导出）在 disassembler.py / assembler.py。

证据等级：所有条目都从 moacode.mwb（sha256 1975e644…a10）全量解析中
`observed` / `derived` 得出，详见 vm_analysis.md。
"""

DIALECT = {
    "schema_version": "1.0.0",
    "engine_id": "MOA_ASTRONAUTS",
    "endianness": "big",          # ZMOA 载荷内的多字节整数一律大端
    "source_encoding": "utf-8",   # 字符串 token 的字节编码（实测：UTF-8）
    "file_encoding": "cp932",     # 备用：游戏 UI 用 CP932，脚本字符串为 UTF-8

    # ------------------------------------------------------------------
    # ZMOA 容器（moacode.mwb 外壳）
    # ------------------------------------------------------------------
    "container": {
        "magic": "ZMOA",
        "header_size": 0x1C,
        "header_endianness": "little",   # 头字段为小端；仅载荷内 token 参数为大端
        "header_fields": [
            {"name": "magic",      "offset": 0x00, "width": 4, "kind": "bytes"},
            {"name": "reserved0",  "offset": 0x04, "width": 4, "kind": "u32"},
            {"name": "reserved1",  "offset": 0x08, "width": 4, "kind": "u32"},
            {"name": "reserved2",  "offset": 0x0C, "width": 4, "kind": "u32"},
            {"name": "version",    "offset": 0x10, "width": 4, "kind": "u32"},   # 实测 100
            {"name": "uncomp_size","offset": 0x14, "width": 4, "kind": "u32"},
            {"name": "comp_size",  "offset": 0x18, "width": 4, "kind": "u32"},
        ],
        "payload": {
            "algorithm": "zlib", "offset": 0x1C,
            # 零编辑逐字节往返要求复用原始压缩参数（实测穷举得出，EV_ZLIB_PARAMS）
            "zlib_params": {"level": 6, "wbits": 15, "memlevel": 8,
                            "strategy": "Z_DEFAULT_STRATEGY"},
        },
    },

    # ------------------------------------------------------------------
    # 字节码 token 集（T1 cell-stream 语义；T2 已解析锚点）
    #   每个 token：tag 字节 + 定长参数；字符串 token 变长但有显式长度字段
    # ------------------------------------------------------------------
    "tokens": {
        "STR":  {"tag": 0x1A, "layout": "u32 len + len bytes + 0x00", "size": "variable"},
        "REF":  {"tag": 0x00, "arg": "u24", "size": 4},     # 命令引用（内建函数 id / 数据 id）
        "REFE": {"tag": 0xFF, "arg": "u24", "size": 4},     # 语句尾的标签引导符（值恒为 0xFFFFFF）
        "INT":  {"tag": 0x05, "arg": "i32", "size": 5},     # 整数立即数
        "P15":  {"tag": 0x15, "arg": "i32", "size": 5},     # 参数标记（a=取值形态：0/1/4/5）
        "P06":  {"tag": 0x06, "arg": "i32", "size": 5},     # 参数编号（40=名前 35=voice 41=块 8=正文 5=串值…）
        "END":  {"tag": 0x07, "arg": "i32", "size": 5},     # 语句终止（0=普通 -1=带标签引用）
        "MARK": {"tag": 0x21, "size": 1},                   # 块标记（恒后随 BLK）
        "BLK":  {"tag": 0x20, "arg": "i32", "size": 5},     # 块操作码（0=闭合 1=开 2=闭 4/5/7/9/12/13/14=子操作）
    },

    # P06 编号 → 语义。分两类：
    #   attr（出现在 P15(0) 之后）= 参数位置标记，不含语义
    #   pid  （出现在 P15(4) 之后）= 值的类别
    # 证据：14211 条带串参语句的位置统计（首参 attr=40 占 12986 条），见 vm_analysis.md §5。
    "param_ids": {
        # --- attr：位置标记 ---
        40: "arg0",               # 首个位置参数
        35: "argN",               # 后续位置参数
        14: "objref",             # 对象引用槽（'栞.COLOR'/'萌香.SHAKE'）
        41: "block-prefix",       # 块起始前缀
        25: "var-scope",
        # --- pid：值类别 ---
        8:  "message-text",       # 正文（唯一的正文槽）
        5:  "string-value",       # 位置参数的串值；语义由函数 + 位置决定（ARG_TAGS）
        2:  "object-name",
        1:  "flag",
        3:  "flag",
        19: "flag",
        55: "flag",
        62: "cond",
        65543: "choice-target",   # 选项跳转标签
        65545: "goif-target",     # 条件跳转标签
        327687: "macro-name",
        393225: "var-name",
    },

    # ------------------------------------------------------------------
    # 内建函数表（源自文件头部 I(id) I(-1) I(1) S(name) 序列，0x1322–0x1A60）
    # ------------------------------------------------------------------
    "builtin_functions": {
        # id: name —— 由 disassembler 从源文件动态读取；此处仅列文本相关锚点作为校验
        "text_id": 910,
        "endtext_id": 911,
        "sel_id": 2000,
        "go_id": 64,
        "gosub_id": 66,
        "goif_id": 65,
    },

    # ------------------------------------------------------------------
    # 文本发现（T2 锚点）：tag 闭集 + 证据
    # ------------------------------------------------------------------
    # 文本角色由「函数 + 位置参数序号」决定（mwb.ARG_TAGS），而非单个 P06 编号。
    # 此处登记规则与证据；实现见 mwb._extract_texts。
    "text_rules": [
        {"id": "msg",
         "anchor": "P15(4) P06(8) STR",
         "tag": "msg", "tag_source": "structural", "confidence": "observed",
         "policy": "translatable", "count_observed": 26160,
         "evidence_refs": ["EV_MSG_ANCHOR"]},
        {"id": "name",
         "anchor": "text 语句第 0 个位置参数",
         "tag": "name", "tag_source": "structural", "confidence": "observed",
         "policy": "translatable", "count_observed": 8381,
         "evidence_refs": ["EV_NAME_ANCHOR"]},
        {"id": "choice",
         "anchor": "sel.menu 形态语句的位置参数（该形态含 P06(65543) 跳转目标）",
         "tag": "choice", "tag_source": "structural", "confidence": "observed",
         "policy": "translatable", "count_observed": 3,
         "evidence_refs": ["EV_SEL_ANCHOR", "EV_SEL_SHAPES"]},
        {"id": "ui",
         "anchor": "setgamedatatitle 语句第 0 个位置参数（存档章节标题）",
         "tag": "ui", "tag_source": "structural", "confidence": "observed",
         "policy": "translatable", "count_observed": 63,
         "evidence_refs": ["EV_UI_TITLE"]},
        {"id": "label",
         "anchor": "07(-1) REFE STR，或 P06 ∈ {65543, 65545, 327687} 的串值",
         "tag": "label", "tag_source": "structural", "confidence": "observed",
         "policy": "frozen", "count_observed": 389,
         "evidence_refs": ["EV_LABEL_ANCHOR"]},
        {"id": "asset-key",
         "anchor": "stand/bg/ev/bgm/se*/vo 的位置参数、attr14 对象引用、转场效果名",
         "tag": "misc", "tag_source": "structural", "confidence": "observed",
         "policy": "frozen",
         "note": "含日文但为资源查找键（'布ずれ（シュ）'、'村長の屋敷部屋_昼'、"
                 "'左から右へ'）。翻译会导致素材加载失败，故 frozen。",
         "evidence_refs": ["EV_ASSET_KEYS"]},
    ],

    # 默认策略：未被 text_rules 命中的字符串 → frozen（函数名、表项名、资源键）
    "default_policy": "frozen",

    # ------------------------------------------------------------------
    # 双行文本导出
    # ------------------------------------------------------------------
    "text_export": {
        "file_text_encoding": "utf-8",      # 双行文件本身
        "target_encoding": "utf-8",         # 译文写回编码 = 源编码（引擎用 UTF-8）
        "terminator_len": 1,                # 字符串 token 自带 0x00 终止符
    },

    # 变长回封：字符串 token 带显式 u32 长度字段，变长后仅该 token 内部
    # 长度字段与字节体变化，语句结构不变 → pointer-rewrite 退化为“本地重写”，
    # 无需移动其他 token，也无需回填外部引用（引擎按 token 流顺序读取）。
    "repack": {
        "supported": ["identity", "in_place", "pointer-rewrite"],
        "note": "长度字段内联于字符串 token，重写本地即可；不存在跨区域指针。",
    },
}
