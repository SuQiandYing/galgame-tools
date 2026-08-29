"""合并输出布局与 .scn 文件发现。

一个输入目录对应一个 `_psbscn` 目录，里面是**合并**产物：一份 ASM 清单、一份
DSAT 翻译文件、一份报告。只有回封结果必须逐文件写出，因为那是要装回游戏的。

不保留逐文件中间 IR：解析是确定性的，回封时按需重算即可，省下 264 个目录和
数百 MB 磁盘。
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..formats import psb_spec as S

OUT_DIR_NAME = "_psbscn"


@dataclass(frozen=True, slots=True)
class Workspace:
    """合并产物的路径集合，全部由一个根目录派生。"""

    root: Path

    @classmethod
    def beside(cls, input_root: str | Path) -> Workspace:
        """输入目录下的 `_psbscn`；输入是文件时用它所在目录。"""
        p = Path(input_root)
        base = p if p.is_dir() else p.parent
        return cls(base / OUT_DIR_NAME)

    @property
    def asm(self) -> Path:
        return self.root / "反汇编.asm.txt"

    @property
    def dsat(self) -> Path:
        """旧版的单份合并翻译文件。

        新流程不再产出它，但回封仍会在逐文件翻译缺失时回退读取它，以免让已经翻到
        一半的合并文件作废。
        """
        return self.root / "文本.dsat.txt"

    @property
    def texts(self) -> Path:
        """逐文件翻译目录，内部镜像源目录结构。"""
        return self.root / "texts"

    @property
    def ir(self) -> Path:
        """IR 合库目录（仅在显式要求时创建）。

        整个作业共用一套 JSONL，每条记录带 `src_id`；`manifest.jsonl` 记下每个源在
        各文件中的行区间，所以单源查询仍是一次顺序区间读，而不是几百个小目录。
        """
        return self.root / "ir"

    def text_path(self, relative: Path | str) -> Path:
        """某个源文件对应的翻译文件路径，保持相对路径与文件名。

        译文文件必须与源文件一一对应。合并会让 idx 跨文件冲突、无法按剧本分工送审、
        回封时判不出某条译文属于哪个源，也让「本文件对应本源」这层校验失效。
        """
        rel = Path(relative)
        return self.texts / rel.with_name(rel.name + ".dsat.txt")

    @property
    def index(self) -> Path:
        """只读总览（源 -> 译文 -> 条目数），不是导入源。"""
        return self.texts / "_index.tsv"

    @property
    def report(self) -> Path:
        return self.root / "报告.json"

    @property
    def rebuilt(self) -> Path:
        return self.root / "rebuilt"

    def rebuilt_path(self, sample: str) -> Path:
        return self.rebuilt / sample


def relative_key(sample: Path, inputs: list[str] | list[Path]) -> Path:
    """样本相对于输入根的路径，用于镜像目录结构。

    找不到共同根时退回文件名，绝不产生绝对路径、驱动器号或 `..`。
    """
    resolved = sample.resolve()
    for raw in inputs:
        base = Path(raw).resolve()
        base = base if base.is_dir() else base.parent
        try:
            return resolved.relative_to(base)
        except ValueError:
            continue
    return Path(resolved.name)


def is_scenario_file(path: Path) -> bool:
    """按签名判断，而不是按扩展名——扩展名只是弱证据。"""
    try:
        with path.open("rb") as fh:
            return fh.read(4) == S.SIGNATURE
    except OSError:
        return False


def find_scenario_files(paths: list[str] | list[Path]) -> list[Path]:
    """递归收集所有 PSB 剧本文件，按路径排序、去重。

    目录被递归展开；单个文件直接检查签名。输出目录自身会被跳过，避免把上一轮
    的 `rebuilt/` 产物当成新输入。
    """
    found: dict[Path, None] = {}
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if OUT_DIR_NAME in child.parts:
                    continue
                if child.is_file() and is_scenario_file(child):
                    found[child.resolve()] = None
        elif p.is_file() and is_scenario_file(p):
            found[p.resolve()] = None
    return sorted(found)
