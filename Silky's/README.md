# SILKY'S ENGINE .MES 文本提取 / 回封工具

针对 `E:\fuyukuru_dl\SILKYSIMAGE\新建文件夹` 的 59 个 `.MES` / `.LIB` 脚本。
格式逆向过程与全部证据见 `vm_analysis.md`。

## 快速上手

```console
python run_gui.py
```

拖放依赖 `tkinterdnd2`（`pip install tkinterdnd2`）。**不要换成 windnd** —— 它在 64 位
Python 上会把窗口过程指针读坏，症状是拖进去直接闪退并打印
`Fatal Python error: PyEval_RestoreThread ... the GIL is released`。那是原生崩溃，
Python 层的 try/except 拦不住。缺 `tkinterdnd2` 时程序照常启动，只是拖放不可用，
用「浏览…」按钮完成全流程。

把脚本文件夹拖进窗口，点「输出文本」，翻译 `texts/` 里的 `●` 行，再点「回封文本」。
原文件全程只读，回封结果写到单独目录，由你自己复制回游戏。

命令行等价入口：

```console
python disassembler.py "..\新建文件夹" -o .\text          # 提取
python disassembler.py "..\新建文件夹" -o .\text --asm    # 同时出 ASM 清单
python assembler.py    "..\新建文件夹" -t .\text -o .\rebuilt   # 回封
```

## 翻译文件格式

只改 `●` 开头的行，`○` 行是校验锚，改了会被拒绝。

```
# idx=00001049 off=0x00018DE8 tag=msg speaker=夕陽 lines=3
○00001049○msg○「やっぱり熾火さんはエッチだなー。\n　わかった。\n　腰を上げて」
●00001049●msg●「やっぱり熾火さんはエッチだなー。\n　わかった。\n　腰を上げて」
```

- **一句话可能占 1~3 个显示行**，用 `\n` 分隔，`lines=N` 标出行数。
  `\n` 的数量由引擎固定，**不能增删**（增删要改指令流，本工具不支持），但每行内容可任意加长。
- `tag=msg` 正文、`tag=choice` 选项、`tag=name` 人名，可自由翻译；`tag=label` 是文件名
  和配置路径，已锁定，改了会报错。
- 译文可以比原文长，这是本地化常态：工具自动改用变长回封并重算全部跳转与标签。
- 译文行不能留空，留空视为误删。未翻译就保持与原文相同。

## 交付物

| 文件 | 职责 |
|---|---|
| `opcodelist.py` | 声明式方言：opcode、锚点、syscall、假名码表、文本规则 |
| `disassembler.py` | 源二进制 → 内存 IR → `texts/` + `asm/` + 覆盖证书 |
| `assembler.py` | 源二进制 + 两个编辑面的改动 → 重建二进制 |
| `run_gui.py` | 两按钮图形界面 |
| `vm_analysis.md` | VM 逆向分析与证据台账 |
| `scripts/` | 8 个可执行门禁 |

## 门禁

```console
python scripts/check_output_sanity.py  text/_work/reports/extract_report.json
python scripts/check_determinism.py    rerun  <src>...
python scripts/check_determinism.py    edit   <src> <rebuilt> [--edited]
python scripts/coverage_certificate.py "..\新建文件夹"
python scripts/check_sites.py          <src> <rebuilt>
python scripts/check_oracle.py         "..\新建文件夹" ..\chs.json
python scripts/check_no_literals.py    . --exclude opcodelist
python scripts/check_variants.py       "..\新建文件夹" --corpus-wide
```

`check_oracle.py` 是最强的一道：`chs.json` 是第三方汉化版的译文库，key 为原文
cp932 字节的 sha1。它与本工具完全独立，因此假名码表或字符串边界一旦有错，
命中率会立刻掉下来。当前 **48086 / 48093 行命中（99.985%）**，未命中的 7 条是
`_SAMPLE.MES` 里的重复填充测试串（`あああ…`），解码正确但汉化版未收录。

## 当前实测状态

两部作品，300 个文件，方言由结构探测自动选择（不看文件名）：

```
             文件      byte_cov  零编辑往返   正文     选项   人名     锁定
新建文件夹   59/59     1.0       逐字节一致   30,136   10     17,362   60,382
1            241/241   1.0       逐字节一致   39,993   52     25,064   60,940
```

选项（`tag=choice`）由 opcode `0x1B` 识别，它的操作数是选中该项后跳转的代码偏移。
新建文件夹的 10 条选项与攻略页完全对应（5 个存档点 × 2 项），且全部通过第三方译文库
哈希校验。变长回封时选项的跳转目标会跟着重算，并验证仍指向**同一条逻辑指令**。

未判定条目 0；理解深度 T3 instruction-stream。

`1` 是同引擎另一部作品：对话用 `0x0B`（不是 `0x0A`），且**不使用假名码表**。
这个差别在字节门禁上完全隐形 —— 用错方言时 241 个文件依然 `byte_coverage=1.0`、
往返逐字节一致，但正文只抽出 114 条（对 25,064 条人名）。靠
`check_output_sanity.py` 和 `check_variants.py` 才能发现。

注意 `1` 的中文是**塞在 cp932 码位里**的（字体 hack 汉化，配套 `chs.ttf` /
`FontHook.ini`），所以译文编码仍然填 `cp932`；只有 cp932 里没有的字会被拒绝，
报错会指出具体是哪个字。

## 已知边界

- 51 个单字节 opcode 原样保留但未逐一命名，命名需要反汇编 `fuyukuru.exe`。
- 不支持增删指令、改变消息行数（`full-layout`），尝试时明确拒绝而非产出坏文件。
- 对话内嵌控制字节（`0x05` 等约 31 种）以 `{{XX}}` 占位符逐字节保留，显示语义未解码。
- 已在两部作品上验证，两个方言分支都被实际命中。`1` 没有第三方译文库可做哈希校验，
  它的正文是靠结构和人工阅读确认的。
- `LIBLARY.LIB` 里有 2 条虚假正文（`ひ` / `そひ`）：该文件中消息 opcode 同时是一个
  真正的无操作数指令。已标为 `heuristic` 而非确认正文，占 70,190 条中的 2 条。
