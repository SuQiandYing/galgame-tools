# DacDpkLocalizer

DPK 拆包/回封、脚本加密 profile 自动探测、IR/ASM/DSAT 导出、译文导入校验和加长回封工具。

## 重要规则

- 不把某个游戏的固定密钥写死到流程里；脚本层通过 `profiles/*.json` 自动探测。
- DSAT 文本按源文件输出到 `texts/by_source/`。
- `５Ｂ`、`４大Ａ` 这类对白演出前缀不会进入正文，会放在元数据 `cue=` 中并回封还原。
- `{ $.M }` 这类运行时变量宏不会作为正文输出。工具会解析简单标量定义，例如 `$.M = "浅木"`、`$.N = "政紀"`，在 DSAT 中显示为普通名字，回封时自动还原为原脚本宏，保证零编辑哈希一致。
- 动态表达式如 `{ $.FILE_COMMENT }`、`{ $.cgcomment[$$cg_no] }` 不作为翻译文本导出。

## 常用命令

```bat
python run_cli.py export-text script.dpk -o workspace --encoding cp932
python run_cli.py import-text workspace workspace\texts\by_source -o workspace\rebuilt\patched_script.dpk --allow-lengthen
python run_cli.py verify script.dpk workspace\rebuilt\patched_script.dpk -o workspace\reports
python run_cli.py smoke-roundtrip script.dpk -o smoke_test --encoding cp932
```

GUI：

```bat
python run_gui.py
```

