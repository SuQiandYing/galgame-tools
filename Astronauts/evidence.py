# -*- coding: utf-8 -*-
"""vm_analysis.md 的机器可读证据登记（供工具与文档引用）。"""

EVIDENCE = {
    "EV_ZMOA_HEADER": {
        "level": "observed",
        "desc": "ZMOA 头 0x1C 字节：magic(4) + 保留x3 + version=100 + uncomp_size + comp_size（均 BE），"
                "0x1C 起为 zlib 流。uncomp_size=5237260 与 zlib.decompress 输出长度一致。",
    },
    "EV_ZLIB_PARAMS": {
        "level": "observed",
        "desc": "穷举 level 0–9 × 5 种 strategy × memLevel 8/9：level=6 / "
                "Z_DEFAULT_STRATEGY / memLevel=8 / wbits=15（zlib 默认）复现原始 "
                "683161 字节压缩流，逐字节一致。零编辑重建因此可做到整文件哈希相同；"
                "不复用该参数会得到 668703 字节的不同流（内容仍等价）。",
    },
    "EV_TOKEN_COVERAGE": {
        "level": "derived",
        "desc": "对 5237260 字节解压载荷按 token 语法全量扫描：761110 个 token，0 个未知字节，"
                "字节覆盖 5237260/5237260 = 100%。",
    },
    "EV_ENDIAN": {
        "level": "derived",
        "desc": "字符串 token 长度字段为 BE u32（'1a 00 00 00 09 macro.txt' → len=9）；"
                "文件头 uncomp_size 字节序 00 4f ea 0c = BE 5237260。GXP 外壳本身为 LE（count@0x18=2）。",
    },
    "EV_MSG_ANCHOR": {
        "level": "observed",
        "desc": "P15(4) P06(8) 后恒跟随字符串，共 26160 处；抽样均为对话/旁白正文"
                "（'「……ふふふ」'、'夢――。夢をみているのか？' 等）。",
    },
    "EV_NAME_ANCHOR": {
        "level": "observed",
        "desc": "text 语句内 P15(0) P06(40) P15(4) P06(5) 后的字符串共 8381 处；"
                "取值分布以人名为主（栞 2604、智樹 2793、萌香 1878…），与 voice id（栞=sio、萌香=moe）一致。",
    },
    "EV_SEL_ANCHOR": {
        "level": "observed",
        "desc": "sel(2000) 语句内 attr40 的串值为选项文本（'今は決められない'、'契りを交わす'…），"
                "选项目标标签由 P15(4) P06(65543) 给出（'@YES_KUR' 等）。",
    },
    "EV_LABEL_ANCHOR": {
        "level": "observed",
        "desc": "07(-1) FF(0xFFFFFF) 后的字符串为跳转目标（'KUR_ROUTE'、'スタッフロール'、'@SKIP2'），"
                "与文件头标签表 S(label) I(line) I(0) S(file) I(5) 一一对应。",
    },
    "EV_FN_TABLE": {
        "level": "observed",
        "desc": "0x1322–0x1A60 为内建函数表：I(id) I(-1) I(1) S(name) 重复 158 次；"
                "910=text, 911=endtext, 2000=sel, 64=go, 66=gosub, 65=goif, 2101=wa.time 等。"
                "代码区 REF(id) 后紧随 S(name) 的 40595 条语句与该表一致。",
    },
    "EV_POSITIONAL_ARGS": {
        "level": "derived",
        "desc": "参数为位置式而非语义式：14211 条带串参语句中，12986 条首参 attr=40，"
                "后续参数 attr=35。13 条例外均为 attr14/p2 对象引用槽先出现的情形"
                "（'その他' + staff 资源名），仍不破坏“attr40 = 首个 p5 位置参数”。"
                "因此文本角色由（函数, 位置序号）决定，见 mwb.ARG_TAGS。",
    },
    "EV_SEL_SHAPES": {
        "level": "derived",
        "desc": "sel(2000) 有两个形态：336 条中 2 条含 P06(65543) 跳转目标（真实选项菜单，"
                "其中 1 条带 3 条选项文本），334 条不含（舞台用法，p5 取值为 'staff_01_2'、'T'）。"
                "按“是否含跳转目标”判定形态；两形态均显式声明，无命中即报错。",
    },
    "EV_UI_TITLE": {
        "level": "observed",
        "desc": "setgamedatatitle 的首个位置参数为存档章节标题，共 63 条"
                "（'プロローグ'、'帰郷'、'夜這い２'…），玩家在存档界面可见 → translatable。",
    },
    "EV_ASSET_KEYS": {
        "level": "observed",
        "desc": "stand/bg/ev/bgm/se*/vo 的位置参数与 attr14 对象引用含日文但为资源查找键："
                "'布ずれ（シュ）'（SE 名）、'村長の屋敷部屋_昼'（BG 名）、'左から右へ'（转场名）、"
                "'栞.COLOR'（对象属性）。改写会导致素材加载失败，故 frozen。"
                "判定依据为函数与参数位置，非取值外观。",
    },
    "EV_LABEL_TABLE": {
        "level": "observed",
        "desc": "头部标签表 103 条：STR(label) INT(line) INT(0) STR(file) INT(kind)，"
                "把标签映射到 (源文件, 行号)。行号量级最大 40013，远小于载荷长度 "
                "5237260 —— 证明表中存的是源码行号而非字节偏移。",
    },
    "EV_CHAPTER_BOUNDARY": {
        "level": "derived",
        "desc": "剧情分段边界 = `go <章节名>` 语句，判据：跳转目标在头部标签表中、"
                "映射到 .txt 源文件、且名字不以 @ 开头（@ 前缀为文件内局部标签如 @SKIP2）。"
                "实测 67 个边界，语句序号严格递增，区间连续无缝（末段止于 47251 = 语句总数），"
                "24015 条可翻译条目全部归属零遗漏，与 modlist.dat 的 71 个编译源一致"
                "（差额为未被 go 引用的 macro/vars/sys 等非剧情脚本）。",
    },
    "EV_PAGE_BLOCK": {
        "level": "observed",
        "desc": "text 语句内的正文页块布局 MARK BLK(1) P15(4) P06(8) STR，"
                "相邻页 STR 下标间距恒为 5，15568 条语句全部符合零例外。"
                "每页框架开销 22 字节。页数分布：1 页 6308、2 页 7928、3 页 1332。"
                "因流内无字节偏移引用，增删页块安全。",
    },
    "EV_STATEMENT_MODEL": {
        "level": "derived",
        "desc": "语句 = REF(id) [S(name)] (P15 a P06 k [S v])* [MARK BLK]* (END t) [REFE(0xFFFFFF) S(label)]。"
                "REF 后无名字的 6656 条按 id 直呼（600/1000/50/2000…），其参数形态与同名语句一致。",
    },
}
