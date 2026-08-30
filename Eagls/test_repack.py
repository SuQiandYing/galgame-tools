"""回归测试：零编辑往返、变长回封、篡改拒绝、按站点不按值。

    python test_repack.py            在真实样本上跑全部用例

每个用例独立复制一份 output 到临时目录，互不影响。原始 Script 目录只读。
"""

from __future__ import annotations

import io
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import assembler as A
import disassembler as D
import profile_scpack as P

SCRIPT_DIR = Path(__file__).resolve().parent.parent / "Script"
_BASE: Path | None = None


def setUpModule() -> None:
    """整套测试共用一次反汇编产物，各用例复制副本后再改（§12.1 预计算提到循环外）。"""
    global _BASE
    _BASE = Path(tempfile.mkdtemp(prefix="eagls_base_"))
    D.disassemble(SCRIPT_DIR, _BASE, write_asm=False)
    D.export_texts(_BASE)


def tearDownModule() -> None:
    if _BASE is not None:
        shutil.rmtree(_BASE, ignore_errors=True)


class Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self.out = Path(tempfile.mkdtemp(prefix="eagls_case_"))
        shutil.rmtree(self.out)
        shutil.copytree(_BASE, self.out)
        self.addCleanup(shutil.rmtree, self.out, True)

    def texts(self) -> list[Path]:
        return sorted((self.out / "texts").glob("*.txt"))

    def pick(self, min_msgs: int = 20, min_labels: int = 1) -> Path:
        """挑一个真有台词的剧本文件。

        不能用「排序后的最后一个」—— 那是 StandShaking.dat，一条 msg 都没有，
        于是编辑数为 0，测试会在「策略应为 pointer-rewrite」上失败，
        而真正的原因是没选对文件。
        """
        for path in self.texts():
            doc = path.read_text(encoding="utf-8-sig")
            if doc.count("tag=msg") >= min_msgs and doc.count("tag=label") >= min_labels:
                return path
        self.fail(f"样本中找不到含 ≥{min_msgs} 条 msg 的文件")

    def pick_label_after_message(self) -> Path:
        """挑一个「至少一个标签排在首条台词之后」的文件。

        标签全在文首的文件（如 00Blinking2.dat）里，正文变长不会移动任何标签，
        因此 relocation_log 为空是正确的 —— 用那种文件测重定位只会误报。
        """
        for path in self.texts():
            first_msg = None
            for line in path.read_text(encoding="utf-8-sig").splitlines():
                if not line.startswith("# idx="):
                    continue
                meta = dict(p.split("=", 1) for p in line[2:].split() if "=" in p)
                off = int(meta["off"])
                if meta["tag"] == "msg" and first_msg is None:
                    first_msg = off
                elif meta["tag"] == "label" and first_msg is not None and off > first_msg:
                    return path
        self.fail("样本中找不到「标签排在台词之后」的文件")

    def edit(self, path: Path, transform) -> None:
        """按 idx 改译文行。transform(idx, tag, source) -> 新译文 或 None（不改）。"""
        lines = path.read_text(encoding="utf-8-sig").splitlines()
        mark = P.DIALECT["dsat"]["tran_mark"]
        for i, line in enumerate(lines):
            match = A._TRAN_RE.match(line)
            if not match:
                continue
            new = transform(int(match.group("idx")), match.group("tag"),
                            match.group("text"))
            if new is not None:
                lines[i] = (f"{mark}{match.group('idx')}{mark}"
                            f"{match.group('tag')}{mark}{new}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8-sig")

    def repack(self, **kwargs):
        return A.repack(self.out, SCRIPT_DIR, **kwargs)


class ZeroEdit(Fixture):
    def test_zero_edit_is_byte_identical(self) -> None:
        """零编辑 → 逐字节相同，且策略选 identity（能力最小者）。"""
        summary = self.repack()
        self.assertTrue(summary["ok"])
        self.assertEqual(summary["strategy"], "identity")
        self.assertEqual(summary["changed_entries"], 0)
        for name in ("SCPACK.idx", "SCPACK.pak"):
            self.assertEqual((self.out / "rebuilt" / name).read_bytes(),
                             (SCRIPT_DIR / name).read_bytes(), name)

    def test_deterministic(self) -> None:
        """同一输入跑两次，IR 与证书的哈希相同（§8 最后一条）。"""
        second = Path(tempfile.mkdtemp(prefix="eagls_det_"))
        self.addCleanup(shutil.rmtree, second, True)
        D.disassemble(SCRIPT_DIR, second, write_asm=False)
        for name in ("text_entries.jsonl", "join_sites.jsonl", "regions.jsonl",
                     "name_bindings.jsonl"):
            self.assertEqual((self.out / "ir" / name).read_bytes(),
                             (second / "ir" / name).read_bytes(), name)


class VariableLength(Fixture):
    """§6.0.1：变长是本地化的主要用例，不是异常。"""

    def _longer(self, factor: int = 3, limit: int = 40):
        touched: list[int] = []

        def transform(idx, tag, source):
            if tag != "msg" or len(touched) >= limit or "{{" in source:
                return None
            touched.append(idx)
            return source * factor

        return transform, touched

    def test_longer_text_repacks(self) -> None:
        """译文加长 → 自动改用 pointer-rewrite，输出可载入且新文本确实写入。"""
        transform, touched = self._longer()
        self.edit(self.pick(), transform)
        summary = self.repack()
        self.assertTrue(summary["ok"], summary["checks"])
        self.assertEqual(summary["strategy"], "pointer-rewrite")
        self.assertEqual(summary["changed_entries"], len(touched))
        self.assertGreater(summary["length_delta"]["actual"], 0)
        self.assertTrue(all(summary["checks"].values()))

    def test_shorter_text_repacks(self) -> None:
        """缩短与加长走同一路径，不得只测其一。"""
        def transform(idx, tag, source):
            if tag != "msg" or len(source) < 12 or "{{" in source:
                return None
            return source[:len(source) // 2]

        self.edit(self.pick(), transform)
        summary = self.repack()
        self.assertTrue(summary["ok"], summary["checks"])
        self.assertLess(summary["length_delta"]["actual"], 0)

    def test_length_delta_is_explained(self) -> None:
        """总长度差值必须等于各条目变化量之和；无法解释的增减即失败。"""
        transform, _ = self._longer(factor=2, limit=15)
        self.edit(self.pick(), transform)
        summary = self.repack()
        self.assertEqual(summary["length_delta"]["expected"],
                         summary["length_delta"]["actual"])

    def test_hash_must_change_when_edited(self) -> None:
        """有编辑时哈希必须不同 —— 哈希未变即表示编辑被静默丢弃（§6.0）。"""
        transform, _ = self._longer(limit=5)
        self.edit(self.pick(), transform)
        self.repack()
        self.assertNotEqual((self.out / "rebuilt" / "SCPACK.pak").read_bytes(),
                            (SCRIPT_DIR / "SCPACK.pak").read_bytes())

    def test_single_file_edit_leaves_others_byte_identical(self) -> None:
        """批量场景下只编辑一个文件：其余条目逐字节不变。"""
        target = self.pick()
        transform, _ = self._longer(limit=8)
        self.edit(target, transform)
        summary = self.repack()
        self.assertTrue(summary["ok"])
        # 文本文件名是「条目名 + .txt」，条目名本身已含 .dat
        self.assertEqual(summary["edited_files"], [target.name[:-len(".txt")]])
        self.assertTrue(summary["checks"]["untouched_entries_identical"])

    def test_label_offsets_relocated(self) -> None:
        """在标签之前插入更长的文本 → 标签 offset 必须被回填，且指向正确位置。

        必须挑一个「标签排在台词之后」的文件：标签全在文首时正文变长不会移动它们，
        relocation_log 为空是正确结果，断言反而会误报。
        """
        target = self.pick_label_after_message()
        transform, _ = self._longer(factor=4, limit=30)
        self.edit(target, transform)
        summary = self.repack()
        self.assertTrue(summary["ok"], summary["checks"])
        self.assertTrue(summary["checks"]["label_offsets_valid"])
        log = [json.loads(line) for line in
               (self.out / "reports" / "relocation_log.jsonl")
               .read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(r["kind"] == "label_offset" for r in log),
                        "文本变长后应有标签偏移被回填")


class Tamper(Fixture):
    """§9 文本篡改：每种都必须被拒绝，并报出精确位置。"""

    def assertRejected(self, code: str, mutate) -> None:
        path = self.pick()
        lines = path.read_text(encoding="utf-8-sig").splitlines()
        mutate(lines)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
        with self.assertRaises(A.ImportReject) as caught:
            self.repack()
        self.assertEqual(caught.exception.code, code, caught.exception.detail)

    def _first(self, lines: list[str], mark: str) -> int:
        for i, line in enumerate(lines):
            if line.startswith(mark):
                return i
        self.fail(f"找不到以 {mark} 开头的行")

    def test_modified_source_line_rejected(self) -> None:
        """改原文行 —— 原文行是校验锚，逐字符比对 IR。"""
        def mutate(lines):
            i = self._first(lines, "○")
            lines[i] += "篡改"
        self.assertRejected("SOURCE_ANCHOR", mutate)

    def test_modified_idx_rejected(self) -> None:
        def mutate(lines):
            i = self._first(lines, "○")
            lines[i] = lines[i].replace("○", "◇", 1).replace("◇", "○", 1)
            lines[i] = "○99999999" + lines[i][9:]
        self.assertRejected("IDX_MISMATCH", mutate)

    def test_modified_tag_rejected(self) -> None:
        def mutate(lines):
            i = self._first(lines, "○")
            parts = lines[i].split("○")
            parts[2] = "ui"
            lines[i] = "○".join(parts)
        self.assertRejected("TAG_MISMATCH", mutate)

    def test_mixed_separators_rejected(self) -> None:
        def mutate(lines):
            i = self._first(lines, "●")
            lines[i] = lines[i].replace("●", "○")
        self.assertRejected("SEPARATOR_MIXED", mutate)

    def test_deleted_line_rejected(self) -> None:
        def mutate(lines):
            del lines[self._first(lines, "●")]
        self.assertRejected("LINE_FORMAT", mutate)

    def test_swapped_blocks_rejected(self) -> None:
        """整块交换后每对内部仍自洽，靠注释与条目的同步性捕获（META_DESYNC）。"""
        def mutate(lines):
            i = self._first(lines, "# idx=")
            j = None
            for k in range(i + 1, len(lines)):
                if lines[k].startswith("# idx="):
                    j = k
                    break
            self.assertIsNotNone(j)
            lines[i + 1:i + 3], lines[j + 1:j + 3] = \
                lines[j + 1:j + 3], lines[i + 1:i + 3]
        self.assertRejected("META_DESYNC", mutate)

    def test_wrong_header_hash_rejected(self) -> None:
        def mutate(lines):
            lines[0] = re.sub(r"src_sha256=\w+", "src_sha256=" + "0" * 64, lines[0])
        self.assertRejected("SRC_HASH_MISMATCH", mutate)

    def test_empty_translation_rejected(self) -> None:
        """预填原文后空译文行只能是误删，不是「未翻译」（§4.6）。"""
        def mutate(lines):
            i = self._first(lines, "●")
            parts = lines[i].split("●")
            lines[i] = "●" + parts[1] + "●" + parts[2] + "●"
        self.assertRejected("EMPTY_TRANSLATION", mutate)

    def test_frozen_entry_modified_rejected(self) -> None:
        def mutate(lines):
            for i, line in enumerate(lines):
                if line.startswith("# idx=") and "policy=frozen" in line:
                    lines[i + 2] += "改了"
                    return
            self.fail("样本中应存在 frozen 条目")
        self.assertRejected("FROZEN_MODIFIED", mutate)

    def test_broken_placeholder_rejected(self) -> None:
        def mutate(lines):
            for i, line in enumerate(lines):
                if line.startswith("○") and "{{" in line:
                    lines[i + 1] = lines[i + 1].replace("{{", "{{zz", 1)
                    return
            self.skipTest("样本中没有含占位符的条目")
        self.assertRejected("PLACEHOLDER_BROKEN", mutate)

    def test_unrepresentable_encoding_rejected(self) -> None:
        """译文编码无法表示时报出具体字符并给候选编码，不静默替换成 ?。

        必须改一条 translatable 的条目：文件里第一条译文行属于 label（frozen），
        改它会先撞上 FROZEN_MODIFIED，测不到编码检查。
        """
        def mutate(lines):
            for i, line in enumerate(lines):
                if not line.startswith("# idx=") or "policy=" in line:
                    continue
                parts = lines[i + 2].split("●")
                lines[i + 2] = f"●{parts[1]}●{parts[2]}●躥"
                return
            self.fail("样本中应存在 translatable 条目")
        self.assertRejected("ENCODING_UNREPRESENTABLE", mutate)

    def test_structural_char_in_translation_rejected(self) -> None:
        """译文含引号会改变语句边界，必须拒绝而不是产出错位文件。"""
        path = self.pick()
        lines = path.read_text(encoding="utf-8-sig").splitlines()
        for i, line in enumerate(lines):
            match = A._TRAN_RE.match(line)
            if match and match.group("tag") == "msg":
                lines[i] = line + '"'
                break
        path.write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
        with self.assertRaises(P.ParseError) as caught:
            self.repack()
        self.assertEqual(caught.exception.code, "EDIT_BREAKS_STRUCTURE")


class Sites(Fixture):
    """§6.3 按站点，不按值 —— 本规范最重要的纠错规则。"""

    def test_value_collision_constant_is_preserved(self) -> None:
        """值恰等于某条目偏移、但不在站点集合中的字，回封后必须逐字节不变。

        这类损坏不会被哈希检出（编辑版本本就该变），也不会被区间覆盖检出
        （长度没变）。唯一能挡住它的是站点级溯源。
        """
        doc = P.parse_archive(SCRIPT_DIR)
        sites = {s["site_offset"] for s in doc.join_sites()}
        keys = {s["key_value"] for s in doc.join_sites()
                if s["key_kind"] == "entry_offset"}
        plain = doc.idx_plain
        width = doc.layout["field_width"]
        collisions = [off for off in range(0, len(plain) - width + 1, width)
                      if off not in sites
                      and int.from_bytes(plain[off:off + width], "little") in keys]
        # 本样本的 idx 尾部是零填充，天然没有同值常量；这本身是可接受的
        # （preserved_value_collisions 为 0 只提示键域可能过窄，不是失败），
        # 但仍要证明改写逻辑不是按值匹配 —— 见下一个用例。
        self.assertEqual(collisions, [])

    def test_rewrite_is_site_scoped(self) -> None:
        """变长回封后，全部差异范围都必须能追溯到声明的站点或重定位记录。"""
        target = self.pick()
        lines = target.read_text(encoding="utf-8-sig").splitlines()
        mark = P.DIALECT["dsat"]["tran_mark"]
        count = 0
        for i, line in enumerate(lines):
            match = A._TRAN_RE.match(line)
            if match and match.group("tag") == "msg" and count < 20:
                lines[i] = (f"{mark}{match.group('idx')}{mark}{match.group('tag')}"
                            f"{mark}{match.group('text') * 3}")
                count += 1
        target.write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
        summary = self.repack()
        self.assertTrue(summary["ok"], summary["checks"])

        # idx 的差异只允许出现在声明的站点上。必须在**明文层**比对：
        # 密文由 rand() 驱动，同一个值加密后字节不同。
        old = (self.out / "plain" / "SCPACK.idx.plain").read_bytes()
        doc = P.parse_archive(SCRIPT_DIR)
        new = bytes(P.xor_idx(bytearray(
            (self.out / "rebuilt" / "SCPACK.idx").read_bytes()),
            doc.idx_key.encode()))
        self.assertEqual(len(old), len(new))
        allowed = []
        for site in doc.join_sites():
            allowed.append((site["site_offset"],
                            site["site_offset"] + site["site_width"]))
        for offset in range(len(old)):
            if old[offset] != new[offset]:
                self.assertTrue(any(lo <= offset < hi for lo, hi in allowed),
                                f"偏移 0x{offset:08X} 的改动无法追溯到任何 join_id")

    def test_dead_entry_is_kept(self) -> None:
        """无引用站点的条目仍在 IR 中，不得被跳过或删除（collision_class=unmatched）。"""
        doc = P.parse_archive(SCRIPT_DIR)
        self.assertEqual(len(doc.entries), len(doc.records))
        sited = {s["target_object_id"] for s in doc.join_sites()}
        for entry in doc.entries:
            self.assertIn(entry.name, sited)


class Placeholders(Fixture):
    """§4.5：占位符逐字节回封一致；可显示字符不得被转义。"""

    def test_slash_and_fullwidth_space_not_escaped(self) -> None:
        doc = P.parse_archive(SCRIPT_DIR)
        for entry in doc.text_entries:
            self.assertNotIn("{{5C}}", entry.source, f"idx={entry.idx} 斜杠被转义了")
            self.assertNotIn("{{81:40}}", entry.source,
                             f"idx={entry.idx} 全角空格被转义了")

    def test_placeholder_roundtrip_is_byte_exact(self) -> None:
        for raw in (b"\x00", b"\x01\x02", b"abc\x1b[0m"):
            text = P.to_placeholders(raw.decode("cp932"), "cp932")
            self.assertEqual(P.from_placeholders(text, "cp932"), raw)

    def test_encoded_length_counts_expanded_bytes(self) -> None:
        """{{0A}} 在译文里占 6 个字符，在目标文件里占 1 字节（§6.0.2）。"""
        self.assertEqual(P.encoded_length("{{0A}}", "cp932"), 1)
        self.assertEqual(P.encoded_length("あ{{0A}}", "cp932"), 3)
        # 同一段文本在不同编码下得到不同的字节数
        self.assertNotEqual(P.encoded_length("日本語", "cp932"),
                            P.encoded_length("日本語", "utf-8"))


class Strategy(Fixture):
    """§6.2 auto 是能力协商，不是「试到不报错」。"""

    def test_probe_reports_all_verdicts(self) -> None:
        """报告必须列出全部策略的裁决，不只是选中的那个。"""
        self.repack()
        verdicts = json.loads((self.out / "reports" / "repack_verdicts.json")
                              .read_text(encoding="utf-8"))
        self.assertEqual({v["strategy_id"] for v in verdicts["verdicts"]},
                         set(A._ORDER))
        for verdict in verdicts["verdicts"]:
            if not verdict["applicable"]:
                self.assertIn("reason_code", verdict)

    def test_in_place_blocked_by_unknown_capacity(self) -> None:
        """条目非紧密排列 → 容量不可证明 → in_place 返回 CAPACITY_UNKNOWN（§6.0.2）。"""
        target = self.pick()
        lines = target.read_text(encoding="utf-8-sig").splitlines()
        mark = P.DIALECT["dsat"]["tran_mark"]
        for i, line in enumerate(lines):
            match = A._TRAN_RE.match(line)
            if match and match.group("tag") == "msg":
                lines[i] = (f"{mark}{match.group('idx')}{mark}{match.group('tag')}"
                            f"{mark}{match.group('text')}改")
                break
        target.write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
        summary = self.repack()
        verdicts = {v["strategy_id"]: v for v in json.loads(
            (self.out / "reports" / "repack_verdicts.json")
            .read_text(encoding="utf-8"))["verdicts"]}
        self.assertFalse(verdicts["in_place"]["applicable"])
        self.assertEqual(verdicts["in_place"]["reason_code"], "CAPACITY_UNKNOWN")
        self.assertEqual(summary["strategy"], "pointer-rewrite")

    def test_full_layout_blocked_by_tier(self) -> None:
        """T2 不得执行 full-layout；tier 不足时正确响应是拒绝，不是降低验证标准。"""
        with self.assertRaises(A.ImportReject) as caught:
            self.repack(strategy="full-layout")
        self.assertEqual(caught.exception.code, "STRATEGY_NOT_APPLICABLE")
        self.assertIn("TIER_TOO_LOW", caught.exception.detail)

    def test_explicit_inapplicable_strategy_is_an_error(self) -> None:
        """有编辑时显式指定 identity 是错误，不是覆盖（§6.2 末段）。"""
        target = self.pick()
        lines = target.read_text(encoding="utf-8-sig").splitlines()
        mark = P.DIALECT["dsat"]["tran_mark"]
        for i, line in enumerate(lines):
            match = A._TRAN_RE.match(line)
            if match and match.group("tag") == "msg":
                lines[i] = (f"{mark}{match.group('idx')}{mark}{match.group('tag')}"
                            f"{mark}{match.group('text')}改")
                break
        target.write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
        with self.assertRaises(A.ImportReject) as caught:
            self.repack(strategy="identity")
        self.assertEqual(caught.exception.code, "STRATEGY_NOT_APPLICABLE")

    def test_stale_source_rejected(self) -> None:
        """IR 是唯一真值：源变了就必须重新反汇编，不能拿旧 IR 回封。"""
        manifest = self.out / "ir" / "manifest.jsonl"
        rows = manifest.read_text(encoding="utf-8").splitlines()
        head = json.loads(rows[0])
        head["pak_sha256"] = "0" * 64
        rows[0] = json.dumps(head, ensure_ascii=False, separators=(",", ":"))
        manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
        with self.assertRaises(A.ImportReject) as caught:
            self.repack()
        self.assertEqual(caught.exception.code, "SOURCE_CHANGED")


class Stages(unittest.TestCase):
    """§11.3 / 铁律 5 阶段隔离：① 出 IR，② 出译文，两步不得合并。"""

    def test_disassemble_does_not_write_texts(self) -> None:
        """① 不产出译文 —— 否则往返自检失败时使用者已经拿到一份装不回去的译文。"""
        out = Path(tempfile.mkdtemp(prefix="stage1_"))
        self.addCleanup(shutil.rmtree, out, True)
        D.disassemble(SCRIPT_DIR, out, write_asm=False)
        self.assertEqual(list((out / "texts").glob("*.txt")), [])
        self.assertTrue((out / "ir" / "text_entries.jsonl").exists())

    def test_export_projects_from_ir_only(self) -> None:
        """② 只读 ir/，不碰原始归档 —— 这是 IR 完备性的实作检验（铁律 2）。

        把 Script 目录换成空目录后 ② 仍须成功：若它偷偷重新解析归档，这里就会失败。
        """
        out = Path(tempfile.mkdtemp(prefix="stage2_"))
        self.addCleanup(shutil.rmtree, out, True)
        D.disassemble(SCRIPT_DIR, out, write_asm=False)
        summary = D.export_texts(out)
        self.assertTrue(summary["ok"])
        self.assertEqual(summary["files"], 307)
        self.assertEqual(summary["text_entries"],
                         sum(1 for _ in (out / "ir" / "text_entries.jsonl")
                             .read_text(encoding="utf-8").splitlines()))

    def test_export_without_ir_is_rejected(self) -> None:
        out = Path(tempfile.mkdtemp(prefix="stage3_"))
        self.addCleanup(shutil.rmtree, out, True)
        with self.assertRaises(P.ParseError) as caught:
            D.export_texts(out)
        self.assertEqual(caught.exception.code, "IR_MISSING")

    def test_export_is_idempotent(self) -> None:
        """重复导出得到逐字节相同的译文 —— 译者可随时重新取一份干净的（§11.3）。"""
        out = Path(tempfile.mkdtemp(prefix="stage4_"))
        self.addCleanup(shutil.rmtree, out, True)
        D.disassemble(SCRIPT_DIR, out, write_asm=False)
        D.export_texts(out)
        first = {p.name: p.read_bytes() for p in (out / "texts").glob("*.txt")}
        D.export_texts(out)
        second = {p.name: p.read_bytes() for p in (out / "texts").glob("*.txt")}
        self.assertEqual(first, second)


class Sanity(unittest.TestCase):
    """§0.1 产出合理性门禁：字节门禁全过仍可能一条正文都没提取到。"""

    def test_disassemble_returns_gate_result(self) -> None:
        """门禁必须在 disassemble() 内执行 —— GUI 直接调它，不经 main()（§11.8）。

        这条是为了拦一类真实事故：门禁只写在 CLI 的 main() 里，GUI 调
        disassemble() 拿到的 summary 没有 sanity_problems 键，一点 ① 就 KeyError。
        """
        summary = D.disassemble(SCRIPT_DIR, Path(tempfile.mkdtemp(prefix="gate_")),
                               write_asm=False)
        self.addCleanup(shutil.rmtree, Path(summary["output"]), True)
        for key in ("ok", "sanity_problems", "zero_edit_identical",
                    "text_entries", "tag_counts", "policy_counts"):
            self.assertIn(key, summary, f"summary 缺少 {key}，GUI 会 KeyError")
        self.assertEqual(summary["sanity_problems"], [])
        self.assertTrue(summary["ok"])

    def test_summary_matches_report_on_disk(self) -> None:
        """两个入口产出必须一致：返回值与 reports/verify.json 逐字段相同（§11.8）。"""
        out = Path(tempfile.mkdtemp(prefix="gate2_"))
        self.addCleanup(shutil.rmtree, out, True)
        summary = D.disassemble(SCRIPT_DIR, out, write_asm=False)
        on_disk = json.loads((out / "reports" / "verify.json")
                             .read_text(encoding="utf-8"))
        self.assertEqual(on_disk, summary)

    def test_zero_message_output_is_a_failure(self) -> None:
        problems = D.sanity_gate({
            "text_entries": 418, "statements": 5000,
            "tag_counts": {"name": 414, "ui": 4}})
        self.assertTrue(any("msg" in p for p in problems))

    def test_empty_output_is_a_failure(self) -> None:
        problems = D.sanity_gate({"text_entries": 0, "statements": 100,
                                  "tag_counts": {}})
        self.assertTrue(problems)

    def test_skewed_output_is_a_failure(self) -> None:
        problems = D.sanity_gate({
            "text_entries": 1000, "statements": 5000,
            "tag_counts": {"name": 980, "msg": 20}})
        self.assertTrue(any("倾斜" in p for p in problems))

    def test_real_sample_passes(self) -> None:
        self.assertEqual(D.sanity_gate({
            "text_entries": 41062, "statements": 174774,
            "tag_counts": {"msg": 28515, "name": 11876, "label": 605,
                           "ui": 60, "choice": 6}}), [])


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    unittest.main(verbosity=2)
