# 使用说明

需要 Python 3.11+。核心的解析、回封与验证只使用标准库；PySide6 是可选依赖，
仅 GUI 需要。

## 图形界面

```console
cd psb_scn_tool
python run_gui.py
```

把存放 `.scn` 的**文件夹**拖进窗口（也可以拖单个文件，或点击拖放区浏览），
选好编码，然后按顺序点按钮：

| 按钮 | 做什么 | 产物 |
|---|---|---|
| ① 反汇编 | 全量反汇编 + 逐文件零编辑往返自检 | `反汇编.asm.txt`（一份） |
| ② 提取文本 | 逐文件导出可直接编辑的译文 | `texts/<源路径>.dsat.txt`（每源一份） |
| ③ 回封 | 把译文写回并验证 | `rebuilt/*.scn` |

工具按 `PSB\0` 签名递归找出所有剧本文件，不看扩展名。输出统一落在**输入目录下的
`_psbscn/`**。

②可以跳过①直接点。③必须先有②的产物。

### ① 的两个可选项

界面上是两个复选框，命令行是两个开关；**都默认关闭**，关闭时行为与以前完全一致。

| 选项 | 命令行 | 作用 |
|---|---|---|
| 跳过 ASM 清单 | `--no-asm` | 不生成 ASM 审计清单。本作语料 571 MB，约省两成时间。**零编辑往返自检与覆盖证书照常执行** |
| 同时导出 IR | `--with-ir` | 额外写一份合库 IR 到 `_psbscn/ir/` |

只想抽文本翻译时勾第一个。想查 IR 结构（文本条目、字符串表、名称表）时勾第二个。

IR 是**合库**而非一源一目录：整个作业共用一套 JSONL，每条记录带 `src_id`，
`manifest.jsonl` 记下每个源在各流中的行区间 `[start, end)`，所以取单个源的记录仍是一次
顺序区间读：

```python
import itertools, json
man = [json.loads(l) for l in open("_psbscn/ir/manifest.jsonl", encoding="utf-8")]
e = next(m for m in man if m["sample"] == "aki005_1.txt.scn")
start, end = e["line_spans"]["text_entries.jsonl"]
with open("_psbscn/ir/text_entries.jsonl", encoding="utf-8") as fh:
    rows = [json.loads(l) for l in itertools.islice(fh, start, end)]
```

## 编码

界面顶部两个下拉框，都可以手输任意 Python 编码名：

- **源编码** —— 原文用什么编码解码。本作实测 264 个文件全是 `utf-8`；其他 M2
  作品可能是 `cp932`。
- **目标编码** —— 译文写回时用什么编码。改成更窄的编码（如 `cp932`、`ascii`）会让
  无法表示的字符在导入时被**拒绝并报出位置**，而不是被静默替换成问号。

命令行对应 `--encoding` 与 `--target-encoding`。

## 输出目录布局

```text
<输入目录>/_psbscn/
  反汇编.asm.txt      所有文件的反汇编清单，按 "===== file=" 分节（合并）
  texts/              逐文件译文，目录结构镜像源目录
    aki001.txt.scn.dsat.txt
    子目录/xxx.txt.scn.dsat.txt
    _index.tsv        只读总览（源 -> 译文 -> 条目数），不是导入源
  ir/                 仅 --with-ir 时创建；整个作业一套，不是每源一个目录
    manifest.jsonl    每源一行：哈希、条目数、各流的行区间
    text_entries.jsonl  name_map.jsonl  string_map.jsonl  placeholder_map.jsonl
  报告.json           三个操作各自的汇总与逐文件明细
  rebuilt/*.scn       回封结果（要装回游戏）
```

**机器读的合并，人读的分开。** ASM 与报告合并成一份：几百个小文件会让每个文件都付一次
open/close/fsync，还按簇占盘，跨文件查询也得遍历所有目录。译文则必须逐文件对应，否则
idx 会跨文件冲突、无法按剧本分工送审、回封时判不出某条译文属于哪个源。

不落盘逐文件中间 IR。解析是确定性的——同一份源字节加同一个源编码必然产出同一份
IR——所以回封时重算一次即可，省下几百个目录和数百 MB 磁盘。

## 命令行

```console
python run_cli.py 反汇编   ../scn
python run_cli.py 提取文本 ../scn --target-encoding gbk
python run_cli.py 回封     ../scn --target-encoding gbk
```

退出码：`0` 成功，`1` 有文件失败或全部被跳过，`2` 未找到输入或编码名无效，
`3` 流水线错误。全局参数写在子命令**之前**：`python run_cli.py --quiet 反汇编 ../scn`。
`--json` 输出机器可读结果。

### 单阶段命令（调试用）

需要单独跑某一阶段时还有细粒度命令，每个阶段独立输入输出：

```console
python run_cli.py toolchain                              # 报告解释器与可选依赖
python run_cli.py probe            SAMPLE                # 只打分，不提交解析
python run_cli.py parse            SAMPLE -o WS/model    # 解析并证明字节覆盖
python run_cli.py disasm           SAMPLE -o WS/ir
python run_cli.py export-asm       SAMPLE -o WS/asm
python run_cli.py export-text      WS/ir  -o WS/texts
python run_cli.py import-text      WS/ir WS/texts/X.dsat.txt -o WS/patched
python run_cli.py repack           SAMPLE -o WS/rebuilt/X.scn --changeset ...
python run_cli.py verify           SAMPLE WS/rebuilt/X.scn -o WS/reports
python run_cli.py smoke-roundtrip  SAMPLE -o WS/checkpoints
python run_cli.py certificate      SAMPLE -o WS/reports
```

## 编辑翻译文件

`texts/` 下每个源文件对应一份译文，文件头带该源的 sha256：

```text
# psbscn v1.0.0 sample=aki003.txt.scn
# source_sha256=cd720cdb…
# source_encoding=utf-8 target_encoding=utf-8
# 只改 ● 行；# 行与 ○ 行是校验依据，改了会导入失败。
# {{XX}} 是控制字节，必须原样、按顺序保留。

# idx=7 off=0x3C10 inst=0xA44 tag=msg speaker=里久
○7○msg○原文行
●7●msg●译文行
```

元数据行只留导入时真正会校验的字段：`off`/`inst` 用于检出错位，`tag` 用于一致性校验，
`speaker` 供译者判断语气。内部结构路径不再写出（报错信息里的路径取自 IR，不依赖译文
文件），译文体积因此小约四分之一。旧格式带 `file=`/`path=` 的文件仍能导入。

可以只翻一部分文件：`texts/` 里缺哪份，③ 就跳过对应的源文件并如实上报，不会假装成功。

规则，全部为硬错误：

- 只有 `●` 行可以修改；`#`、`###`、`○` 行都是只读的。
- 三行的 `idx` 与 `tag` 必须一致。`idx` 在该文件内唯一。
- 每份译文的 sha256 单独校验。换掉某个源文件只会让**那一份**失效，其他文件照常回封。
- 控制字节以 `{{XX}}` / `{{XX:YY}}` 呈现；占位符序列必须原样保留，顺序一致、全大写。
- 译文必须能用目标编码表示，且不能含 NUL。

行内换行以 `\n` 书写，使一个文本单元保持在单行内。

### 一句话可能在多处引用

PSB 的值图会把相同子树去重，所以 `texts[][7]`、`texts[][8]`（回想日志）常常和正文
`texts[][2]` **指向同一个字符串节点**。它们共享同一份存储，不可能分别翻译，因此译文里
只出现一条，改它就等于改了全部引用处。

这件事**不需要译者知道**，所以译文文件里不做任何标注——多一行注释只会打断阅读，而译者
即使看到也无法据此做任何不同的操作。去重记录保存在 `_psbscn/ir/text_entries.jsonl` 的
`aliases` 字段里，供审计与排查使用（需要时用 `--with-ir` 导出）。

抽查 60 个文件有 117 处这种共享。如果按路径逐条导出，用户在两处写下不同译文时只有一处
能进文件，另一处会被静默丢弃——这才是必须去重的原因。

## 测试

```console
python -m pytest tests
```

154 项测试：编解码往返、非最小宽度保留、trie 编解码、文件头校验门禁、语料零编辑
同一性、精确覆盖、DAG 字节归属、未知类型字节定位、占位符逐字节回写、DSAT 篡改
检测、`in_place` 超长拒绝、变长重定位、共享节点去重、分节 sha256 校验、目标编码
拒绝、批处理取消、重复运行确定性。
