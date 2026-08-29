# PSB/SCN 反汇编与回封工具

针对 kirikiri/M2 引擎 PSB v3 剧本文件（`*.txt.scn`）的反汇编、文本提取与可验证
回封工具。纯 Python 3.11+，核心解析只依赖标准库。

## 用法

```console
cd psb_scn_tool
python run_gui.py
```

把存放 `.scn` 的文件夹拖进窗口，然后点三个按钮：

```
① 反汇编      ② 提取文本      ③ 回封
```

工具按 `PSB\0` 签名递归找出所有剧本文件，产物落在输入目录下的 `_psbscn/`。
翻译只改 `_psbscn/texts/` 里的 `.dsat.txt`（每个源文件一份，目录结构与源一致），
改完点③。可以只翻一部分，缺的那些会被跳过并如实上报。

命令行等价写法：

```console
python run_cli.py 反汇编   ../scn
python run_cli.py 提取文本 ../scn
python run_cli.py 回封     ../scn
```

## 当前状态

对 `../scn` 目录下 264 个文件的全量实测：

- 零编辑往返同一性：264/264 逐字节一致（SHA-256 / MD5 / CRC32 全部一致）
- 字节覆盖：264/264 为 100.00%，无缺口、无重叠
- 覆盖证书严格通过：264/264
- 解析出 10,687,181 个值节点、66,334 个可翻译文本条目
- 全量耗时（16 核并行）：① 反汇编 **26 秒** ② 提取文本 **7 秒** ③ 回封 **24 秒**
  （优化前分别是 3 分 54 秒 / 41 秒 / 2 分 39 秒；① 加 `--no-asm` 约 21 秒）
- 单文件反汇编 2.92 秒 → **2.48 秒**；`plan_and_repack` 461 毫秒
- 并行与串行产出的 ASM 清单、译文与报告逐字节一致
- 测试套件：163 项全部通过

另在 `ライムライト・レモネードジャム[体験版]` 的 `*.ks.scn` 上验证：该作把正文放在
多语言嵌套结构里（`texts[i][1][0][1]`），支持这条分支后抽出 1,271 条（含 838 条正文；
此前只抽出 418 条人名与 UI，且不报错），零编辑往返逐字节一致，变长翻译回封后文件仍能
重新解析、校验和自洽。

## 文档

| 文件 | 内容 |
|---|---|
| [docs/usage.md](docs/usage.md) | 三按钮流程、DSAT 编辑规则、输出布局、单阶段命令 |
| [docs/vm_analysis.md](docs/vm_analysis.md) | 格式分析报告：容器、值类型、剧本语义、影响闭包、未决项 |
| [docs/encoding-and-placeholders.md](docs/encoding-and-placeholders.md) | 编码判定依据与占位符规则 |

## 设计要点

**三个操作各自独立。** 没有隐藏的一键全跑，每个操作有独立入口、独立汇总、独立
失败模式，且不会自动串到下一个。②可以跳过①直接运行；③缺少某份译文时明确跳过并
报告，不会假装成功。

**机器读的合并，人读的分开。** ASM 清单与报告各一份——几百个小文件会让每个文件都付
一次 open/close/fsync，还按簇占盘。译文则严格逐文件对应源文件：合并会让 idx 跨文件
冲突、无法按剧本分工送审、回封时判不出某条译文属于哪个源。

**并行不引入非确定性。** 反汇编按源文件切分到多进程（≥8 个文件时启用），worker 把
各自的 ASM 写到临时文件，主进程按输入顺序拼接，因此产物与串行执行逐字节相同。
`PSBSCN_SERIAL=1` 可强制串行以便对照。

**全量反汇编内含验证门禁。** ①除了产出 ASM 与 IR，还会跑零编辑往返自检——如果
一个文件无法被逐字节重建，它的反汇编结果就不值得信任，此时报告失败而不是照常
输出 ASM。

**三个必须尊重的格式性质**（详见分析报告）：

1. 值区是 DAG 而非树，449,445 处子树共享；按树遍历会误报重叠。
2. 整数宽度不是最小宽度，也无法用有符号解释；宽度必须原样保留而不能重算。
3. 名称 trie 含不可达填充槽位；重新生成的 trie 不会逐字节一致。

## 目录结构

```text
psb_scn_tool/
  run_gui.py                  图形界面入口（PySide6，回退 Tkinter）
  run_cli.py                  命令行入口
  pyproject.toml
  src/psbscn/
    core/      errors, types, hashing, coverage, verify
    formats/   psb_spec, psb_codec, psb_names, psb_strings, psb_graph,
               psb_header, psb_document
    bytecode/  scenario, asm, ir, repack
    text/      placeholders, dsat, importer
    services/  toolchain, decision, stages, workspace, jobs
    cli/       main
    gui/       worker, app, tk_app
  tests/       test_codec, test_roundtrip, test_text, test_pipeline, test_jobs
  docs/
```
