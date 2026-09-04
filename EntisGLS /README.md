# EntisGLS 脚本工具

针对 EntisGLS `.csx` 脚本与 `.noa` 封包的
文本提取 / 回封工具。已用两个不同作品验证（提取、零编辑回封均逐字节一致）：

- `script_onishare_dl.csx`（お兄ちゃんシェアリング DL 版）
- `script_time.csx`（Timepiece Ensemble）

## 环境要求

- Windows 10/11
- Python 3.11+（标准库即可，无需 pip 安装任何依赖）
- 拖放功能需要 `windnd`（可选，`pip install windnd`；没有也能用「浏览…」按钮）

## 最快上手（GUI，推荐）

```
python run_gui.py
```

界面三个区块，全部路径框都可以单独拖入文件或文件夹：

1. **脚本文本**：拖入 `.csx`（或整个脚本目录）→ 点「输 出 文 本」
   → 在「文本输出到」目录下得到 `texts\<脚本名>.csx.txt` 双行译文文件。
2. **回封脚本**：翻译完成后点「回 封 脚 本」
   → 在「脚本输出到」目录下得到同名 `.csx`，复制回游戏即可。
3. **封包（.noa）**：解包 / 封包 `.noa` 封包（详见下文）。

原文编码默认 `cp932`，译文编码默认 `gbk`；换游戏可改。
按钮内部自动执行往返自检与覆盖校验，自检失败会直接告知、不产出坏文件。

## 双行文本文件格式

```text
# idx=00001269 sid=... off=0x... tag=msg
○00001269○msg○「12月21日，蓬莱祭开始啦～！…」
●00001269●msg○「12月21日，蓬莱祭开始啦～！…」   ← 只改 ● 行
```

- **只改 `●` 行**，`○` 行是校验锚，改了会被拒绝。
- 导出时 `●` 行预填原文；没翻的条目保持原样即可，可以随时部分回封。
- `tag=msg`（正文）/ `name`（说话人）/ `choice`（选项）可翻译；
  `misc` 里 `frozen`（资源名、图层键）改了会被拒绝，`review-required` 需人工确认。
- `\n:`、`{{XXXX}}` 这类占位符原样保留，不要删改。

## 命令行用法

### 提取文本

```
python disassembler.py <脚本.csx> [-o 输出目录] [--asm] [--no-texts] [--with-ir]
```

| 选项 | 作用 |
|---|---|
| `-o` | 输出目录（缺省为脚本旁的 `output/`） |
| `--asm` | 同时输出 ASM 清单（改逻辑用） |
| `--no-texts` | 跳过双行文本 |
| `--with-ir` | 同时导出中间表示 `ir/`（排查用） |

例：

```
python disassembler.py "D:\Game\script_time.csx" -o "D:\Game\time_out"
```

产物：

```
time_out\
  texts\script_time.csx.txt      ← 译文文件
  reports\extract_report.json    ← 条目数 / tag 分布 / 门禁结果
  reports\coverage_certificate.json
```

### 回封

```
python assembler.py <脚本.csx> -t <译文.txt> -o <输出.csx>   # 有翻译
python assembler.py <脚本.csx> -o <输出.csx>                 # 零编辑自检
```

- 译文超长会自动改用变长回封（重建字符串表），引用按索引重放，无需手工处理。
- 校验失败时坏文件留在 `failed\` 目录供诊断，不会静默输出。

### 封包 / 解包（.noa）

GUI 里「封包（.noa）」区块直接可用；代码调用对应 `noa.py`：

```
from noa import extract, pack_with_engine, known_password
```

- 常见封包的密码已内置（存于 `profiles\entisgls-cotopha.json`）；
  其它封包在界面密码框手填即可。
- **封包回封必须走 `tools\noa32c.exe`**（引擎会校验条目尾 4 字节，
  纯 Python 重打包过不了校验），GUI 已自动调用。

## 适配新游戏

同引擎新作通常只是调用名/参数不同。做法：

1. 用 `python disassembler.py 新脚本.csx` 跑一次，看报错或
   `extract_report.json` 里 `tag_source_counts.unresolved` 占比；
2. 打开 `vm_analysis.md` 与 `profiles\entisgls-cotopha.json`，
   按报告里的调用形态统计把新调用的槽位角色补进数据档（不改任何代码）；
3. 重跑确认 `unresolved` 占比降到 10% 以下、`msg` 条数符合该作品体量。

## 目录结构

| 文件 | 职责 |
|---|---|
| `run_gui.py` | 图形界面（推荐入口） |
| `disassembler.py` | 提取：`.csx` → 文本 / ASM / 报告 |
| `assembler.py` | 回封：`.csx` + 译文 → 新 `.csx` |
| `noa.py` | `.noa` 封包解包 / 打包（打包调 `tools\noa32c.exe`） |
| `opcodelist.py` | 引擎格式声明（指令集、容器布局，跨作品共用） |
| `profile.py` + `profiles\` | 作品数据档（封包密码、调用槽位角色） |
| `vm_analysis.md` | 格式逆向分析台账与证据 |

## 已知边界

- 少量 `review-required` 条目（约 2–4 千）是尚未证明角色的字符串，
  如实标出而非猜标签；翻译前可人工过一遍。
- Nemesis 压缩封包条目未支持（`data11`–`data18` 中不含此类条目）。
