# Astronauts脚本文本工具

对 `bincode.gxp` 内的脚本字节码 `moacode.mwb` 做全量反汇编与文本提取，
并支持 GXP 归档的解包与封包（封包名可自定义）。

零编辑重建**逐字节一致**（`.mwb` 与 `.gxp` 整文件哈希相同）；
译文可任意变长，多页正文可改变页数。

## 快速开始

图形界面（推荐，双击即可）：

```
python run_gui.py
```

把 `bincode.gxp` 拖进窗口 → 点「输出文本」→ 翻译 `texts/moacode.mwb.txt`
的 `●` 行 → 点「回封文本」。

命令行：

```bash
# 导出双行文本，按剧情分段（默认）
python disassembler.py ../bincode.gxp -o ./out

# 导出成一个大文件
python disassembler.py ../bincode.gxp -o ./out --single-file

# 同时导出 ASM 清单（改逻辑用，约 30 MB）
python disassembler.py ../bincode.gxp -o ./out --asm

# 回封，封包名可自定义
python assembler.py ../bincode.gxp --from ./out -o ./rebuilt --gxp-name bincode_cn.gxp

# 先预览不写出
python assembler.py ../bincode.gxp --from ./out --dry-run

# 门禁自检（46 项）
python check_gates.py ../bincode.gxp
```

GXP 归档单独操作（适用于本作全部 .gxp：cg / voices / bgms / data / system）：

```bash
python gxp.py list   ../data.gxp
python gxp.py unpack ../data.gxp -o ./data_unpacked
python gxp.py pack   ../data.gxp -d ./data_unpacked -o ./data_mod.gxp
```

## 输出结构

默认**按剧情分段**导出，一段一个 txt，与原始脚本文件对应：

```
out/texts/
  01_共通＿01.txt      188 条
  02_共通＿02.txt      294 条
  …
  64_解放22.txt
  _index.tsv           总览：文件 → 章节 → 源脚本 → 条目数
```

分界点取自代码流里的 `go <章节名>` 跳转（67 处），每段映射到头部标签表中
对应的源脚本名。加 `--single-file` 可退回单个大文件。

## 翻译约定

双行文本格式：`○` 行是原文（**校验锚，不可改动**），`●` 行填译文。

```
# idx=00000730 off=0x00008dcb tag=msg pages=2
○00000730○msg○だが、全体に白く靄がかかり、\n少女の顔はよく分からない。
●00000730●msg●但整体笼罩着白雾，\n看不清少女的脸。
```

- `\n`（反斜杠 + n 两个字符）是消息窗换页。**可以增删**——译文写几个 `\n`
  就分几页，也可以全部去掉合成一页。原文里的多页已经拼成完整句子。
- 导出时 `●` 行预填原文，`●` 行内容 == `○` 行即视为「未翻译」，可安全回封。
- `{{XX}}` 形式（如 `{{0A}}`）是原始字节占位符，不要改动或改小写。
- 默认只导出可翻译条目（24,015 条）。资源名、转场名、跳转标签等已锁定不导出——
  改动它们会导致素材加载失败。加 `--all-texts` 可查看全部条目（锁定条目改动会被拒绝）。

## 文本分类

| tag | 条数 | 内容 |
|---|---|---|
| `msg` | 15,568 | 正文（对话与旁白，多页已合并成完整句子） |
| `name` | 8,381 | 说话人名 |
| `ui` | 63 | 存档章节标题 |
| `choice` | 3 | 选项文本 |

## 产物布局

```
out/
  texts/                         双行文本（译者编辑面），按剧情分段
    01_共通＿01.txt … 64_解放22.txt
    _index.tsv                   只读总览，不是导入源
  asm/moacode.mwb.asm.txt        全量反汇编（开发者编辑面，--asm 时生成）
  extracted/bincode/…            GXP 解包结果
  _work/reports/
    coverage_certificate.json    覆盖证书
    extract_report.json          提取统计
    gates.json                   门禁结果
```

回封时把整个 `texts/` 目录交回工具即可（多文件自动全部读入，
`_index.tsv` 会被跳过）。

## 文件说明

| 文件 | 职责 |
|---|---|
| `opcodelist.py` | 方言声明：token 编码、容器布局、参数编号、文本规则（纯数据） |
| `mwb.py` | ZMOA 容器与 token 流解析 → 内存 IR；序列化与页块重建 |
| `gxp.py` | GXP 归档解包/封包（含 XOR 加解密） |
| `disassembler.py` | IR → ASM 清单 + 双行文本 + 覆盖证书 |
| `assembler.py` | 双编辑面 diff、冲突检出、13 条导入校验、回封与验证 |
| `check_gates.py` | 46 项交付门禁 |
| `run_gui.py` | 两按钮图形界面 |
| `vm_analysis.md` | 格式逆向分析与证据台账 |
| `evidence.py` | 证据登记（机器可读） |

## 能力边界

申报深度 **T2**（token 流完全切分 + 语句/参数锚点已解析），字节覆盖 100%。

可以做：改文本（任意长度）、改页数、改 ASM 中的字符串。

不能做：改 ASM 中的指令与数据结构——那需要 T3 指令级理解。尝试时工具会明确
拒绝并说明原因，不会产出损坏文件。

已知未决问题（5,540 条语句的命令 id 不在内建函数表中、`BLK` 子操作码语义等）
见 `vm_analysis.md` §8。

需要 Python 3.11+，仅用标准库。拖放功能需 `tkinterdnd2` 或 `windnd`，
缺失时自动降级为「浏览…」按钮。
