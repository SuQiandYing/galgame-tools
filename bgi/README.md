# Bgi_asdis

一套用于 `BGI (Buriko General Interpreter) / Ethornell` 游戏引擎脚本文件的反汇编、汇编与文本提取工具，可用于分析和修改 BGI 引擎游戏的脚本函数、参数与对话文本。

## 功能概览

### 1. 剧情脚本处理

用于处理游戏主剧情脚本。

- `src/v1/bgidis.py`: 剧情脚本反汇编器
- `src/v1/bgias.py`: 剧情脚本汇编器
- `src/v1/bgiop.py`: v1 剧情脚本操作码表
- `src/v0/bgidis_v0.py`: v0 剧情脚本反汇编器
- `src/v0/bgias_v0.py`: v0 剧情脚本汇编器
- `src/v0/bgiop_v0.py`: v0 剧情脚本操作码表

### 2. 系统脚本处理

用于处理 `._bp` 系统脚本。

- `src/bp/bpdis.py`: 系统脚本反汇编器
- `src/bp/bpas.py`: 系统脚本汇编器
- `src/bp/bpop.py`: 系统脚本操作码表

### 3. 对话文本提取与导回

用于从 `BSD/BPD` 中提取文本到 `JSON/TXT`，或将翻译后的 `JSON/TXT` 回填回脚本。

- `src/common/bgi_dialog_json.py`: JSON 提取与导回
- `src/common/bgi_dialog_txt.py`: TXT 提取与导回

当前版本支持：

- 提取剧情对话到 `JSON`
- 提取剧情对话到 `TXT` 双行格式
- 提取 BP 脚本文本到 `JSON/TXT`
- 从 `JSON/TXT` 导回并重新构建脚本
- 识别部分用户自定义函数中的字符串参数
- 识别 `grp_::f_200` tips 条目（标题和正文）并提取到 `JSON/TXT`
- 导回 tips 时，以正文第一行 `T` 的译文强制同步标题 `N`，忽略标题行自身的译文
- 提取时跳过仅包含全角空格 `　` 的文本
- 提取时剥离句尾控制符 `<` `>` `&` `.`
- 导回时自动恢复上述句尾控制符

### 4. 图形界面

- `bgi_gui.py`: 图形界面入口

GUI 提供以下操作入口：

- BSD 反汇编与回编
- 剧情脚本 JSON/TXT 提取与导回
- BP 脚本 BPD 反汇编与回编
- BP 脚本 JSON/TXT 提取与导回
- 自动识别脚本版本 `v0 / v1`
- 编码与源编码分离设置
- 解码回退统计提示

## 目录结构

```text
Bgi_asdis/
├─ bgi_gui.py
├─ bss_mapping.json
├─ bss_mapping_v0.json
└─ src/
   ├─ common/
   │  ├─ asdis.py
   │  ├─ bgi_dialog_json.py
   │  └─ bgi_dialog_txt.py
   ├─ v1/
   │  ├─ bgias.py
   │  ├─ bgidis.py
   │  └─ bgiop.py
   ├─ v0/
   │  ├─ bgias_v0.py
   │  ├─ bgidis_v0.py
   │  └─ bgiop_v0.py
   └─ bp/
      ├─ bpas.py
      ├─ bpdis.py
      └─ bpop.py
```

## 文件说明

- `src/common/asdis.py`: 公共汇编/反汇编辅助函数
- `src/common/bgi_dialog_json.py`: BSD/BPD 到 JSON 的提取与导回
- `src/common/bgi_dialog_txt.py`: BSD/BPD 到 TXT 的提取与导回
- `src/v1/bgidis.py`: v1 剧情脚本反汇编
- `src/v1/bgias.py`: v1 剧情脚本汇编
- `src/v1/bgiop.py`: v1 操作码定义
- `src/v0/bgidis_v0.py`: v0 剧情脚本反汇编
- `src/v0/bgias_v0.py`: v0 剧情脚本汇编
- `src/v0/bgiop_v0.py`: v0 操作码定义
- `src/bp/bpdis.py`: `._bp` 系统脚本反汇编
- `src/bp/bpas.py`: `._bp` 系统脚本汇编
- `src/bp/bpop.py`: `._bp` 系统脚本操作码定义
- `bss_mapping.json`: 函数名/符号映射
- `bss_mapping_v0.json`: v0 映射表

## 环境要求

- Python 3.10 及以上，推荐 Python 3.11+
- GUI 需要安装 `PyQt6`
- `darkdetect` 为可选依赖，用于自动识别深浅色模式

安装示例：

```bash
pip install PyQt6 darkdetect
```

如果只使用命令行，不打开 GUI，通常不需要安装 `PyQt6` 以外的额外依赖。

## 使用方法

### GUI 启动

在 `Bgi_asdis` 目录下运行：

```bash
python bgi_gui.py
```

适合大多数日常操作，尤其是：

- 批量反汇编/回编
- JSON/TXT 文本导出导入
- BP 脚本处理
- 自动选择编码和脚本版本

### 命令行使用

以下命令默认在 `Bgi_asdis` 目录执行。

#### 1. 剧情脚本反汇编

```bash
python src/v1/bgidis.py <文件名>
```

作用：将无扩展名剧情脚本反汇编为 `.bsd` 文件。

常用参数：

```bash
python src/v1/bgidis.py <文件名> -c shift_jis -f gbk
python src/v1/bgidis.py <文件名> --strout
python src/v1/bgidis.py <文件名> -e
```

- `-c / --encoding`: 主编码
- `-f / --fallback-encoding`: 回退编码
- `--strout`: 导出字符串表
- `-e / --exact`: 更严格输出模式

#### 2. 剧情脚本汇编

```bash
python src/v1/bgias.py <文件名.bsd>
```

作用：将 `.bsd` 文件汇编回无扩展名剧情脚本。

#### 3. v0 剧情脚本处理

```bash
python src/v0/bgidis_v0.py <文件名>
python src/v0/bgias_v0.py <文件名.bsd>
```

适用于部分旧版 BGI 游戏脚本。

#### 4. 系统脚本反汇编

```bash
python src/bp/bpdis.py <文件名._bp>
```

作用：将 `._bp` 系统脚本反汇编为 `.bpd` 文件。

#### 5. 系统脚本汇编

```bash
python src/bp/bpas.py <文件名.bpd>
```

作用：将 `.bpd` 文件汇编回 `._bp` 系统脚本。

## JSON/TXT 文本工作流

推荐使用 GUI 执行。对于剧情脚本和 BP 脚本，工具既可以先反汇编成 `BSD/BPD` 后再提取，也可以直接对原脚本执行 `JSON/TXT` 提取与导回，内部会自动完成中间步骤。

### 剧情脚本

1. 直接从原始剧情脚本提取为 `.json` 或 `.txt`
2. 翻译文本
3. 将翻译后的 `.json/.txt` 直接导回，构建出新的剧情脚本

如果需要检查底层结构，也可以手动执行：

1. 将原始脚本反汇编为 `.bsd`
2. 从 `.bsd` 提取为 `.json` 或 `.txt`
3. 将翻译后的 `.json/.txt` 导回到 `.bsd`
4. 再把新的 `.bsd` 汇编回脚本文件

### BP 脚本

1. 直接从原始 `._bp` 脚本提取为 `.json` 或 `.txt`
2. 翻译文本
3. 将翻译后的 `.json/.txt` 直接导回，构建出新的 `._bp` 脚本

如果需要，也可以手动走 `BPD` 中间文件流程：

1. 先把 `._bp` 反汇编为 `.bpd`
2. 从 `.bpd` 提取为 `.json` 或 `.txt`
3. 将翻译后的 `.json/.txt` 导回到 `.bpd`
4. 再把新的 `.bpd` 汇编回 `._bp`

### JSON 格式说明

JSON 适合做程序化处理、术语替换、批量校对和版本对比。

剧情脚本导出的 JSON 结构通常为数组，每一项对应一条可导回文本，例如：

```json
[
  {
    "name": "角色名",
    "message": "对话正文"
  },
  {
    "message": "旁白或无名对话"
  }
]
```

注意：

- 不要随意删除条目、调整顺序或改动字段名，否则导回时可能报条目数不匹配
- 剧情脚本里被自动剥离的句尾控制符会在导回时自动恢复，无需手动补回
- 如果使用了用户函数提取，导回时也要保持同样的用户函数配置


### TXT 格式说明

TXT 采用双行格式，便于人工翻译和比对：

```text
☆000001T☆原文
★000001T★译文
```

其中：

- `N`: 名字行
- `T`: 普通文本
- `S`: 选项文本

### 用户函数说明

部分游戏不会把所有可翻译文本都放在标准对话函数里，而是会放进自定义函数中，例如：

- `_Selection`
- 其他项目私有的 UI/选项/提示函数

为此，`Bgi_asdis` 提供了“用户函数名”配置，用来额外提取这些函数中的字符串参数，并在导回时按相同规则回填。

适用范围：

- 剧情脚本 `JSON` 提取
- 剧情脚本 `TXT` 提取
- 剧情脚本 `JSON` 导回
- 剧情脚本 `TXT` 导回

使用方法：

- 在 GUI 的“JSON 提取 / TXT 提取 / JSON 导回 / TXT 导回”页面中填写“用户函数名(可选)”
- 可填写单个函数名，例如：`_Selection`
- 可填写多个函数名，支持用逗号、分号或换行分隔

示例：

```text
_Selection
MyChoiceFunc
ShowTips
```

或：

```text
_Selection, MyChoiceFunc; ShowTips
```

行为说明：

- 提取时，工具会扫描你指定的用户函数调用，并把其中的字符串也纳入导出结果
- `JSON` 模式下，这些字符串会和普通对话一起进入导出文件
- `TXT` 模式下，这些字符串会按 `S` 类型输出
- 导回时，需要填写与提取时相同的用户函数名列表，确保条目顺序与定位一致

注意事项：

- 这里只适合填写“实际承载文本的函数名”
- 如果函数名写错、漏写，相关文本可能无法提取，或导回时条目数不匹配
- 如果游戏脚本里同时存在命名空间或前缀差异，建议按实际反汇编结果填写
- 同一个项目内最好固定使用同一套用户函数配置，避免多人协作时导入顺序不一致

## 编码说明

BGI 脚本常见编码包括：

- `shift_jis`
- `cp932`
- `gbk`
- `utf-8`
- `big5`

本工具支持主编码与回退编码组合使用，例如：

```bash
python src/v1/bgidis.py script.bin -c utf-8 -f shift_jis
```

当字符串无法按主编码严格解码时，工具会尝试回退编码，并在 GUI 或终端中输出解码回退提示与统计信息。

## 当前版本特性

相对原始基础版本，这个版本额外包含：

- 统一的 GUI 入口
- `v0 / v1 / bp / common` 分层目录结构
- 公共 `JSON/TXT` 文本提取模块
- 对用户函数字符串的提取支持
- 头部导出表识别修正
- 编码回退统计
- 对部分文本控制符的提取/导回兼容处理

## 注意事项

- 这是偏底层的脚本工具，虽然已经测试了十几部游戏，但不保证兼容所有 BGI 游戏（特别是 v0 版本的剧情脚本）。
- 不同游戏可能存在自定义操作码、头部结构差异、函数名差异或特殊编码。
- 用户可根据具体游戏自行修改脚本代码、映射表或提取规则。

## 跨引擎移植实例

已有或计划中的相关移植方向示例：

- Ren'Py
- [《樱之诗》](https://github.com/Imavoyc/Sakuranouta-RenPy-Part1)
- [《巧克甜恋3》](https://b23.tv/RtmlI9c)
- [《向日葵的教会与长长的暑假》](https://www.bilibili.com/video/BV1MTxtzkE2Z/)

## 作者

- [KlparetlR](https://github.com/KlparetlR)、[Lite0812](https://github.com/Lite0812)、[Imavoyc](https://github.com/Imavoyc)

## 贡献

如果您对特定 BGI 游戏有更好的支持方案，欢迎提交 PR，或基于本工具继续创建针对特定作品的分支版本。

## 许可

[MIT](https://github.com/KlparetlR/Bgi_asdis/blob/main/LICENSE)
