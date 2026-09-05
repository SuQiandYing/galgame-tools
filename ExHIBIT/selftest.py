"""Self-tests for the RLD toolchain.

The two directions are asserted separately and must not be conflated:
zero edits require an IDENTICAL hash, edits require a DIFFERENT hash plus the
new text actually present in the output. A suite that only checked the first
would pass while silently discarding every translation.

Run: python selftest.py [rld_dir]
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import rldcore as core
import rldir as ir
import disassembler as dis
import assembler as asm

PASS, FAIL = "PASS", "FAIL"
_results = []


def check(name, cond, detail=""):
    _results.append((PASS if cond else FAIL, name, detail))
    mark = "  ok  " if cond else " FAIL "
    print(f"[{mark}] {name}" + (f"  -- {detail}" if detail and not cond else ""))
    return bool(cond)


def _session(rld_dir, work):
    s = dis.Session(dis.collect_sources([rld_dir]), work)
    s.resolve_keys()
    s.build_name_table()
    return s


def t_word_count_rule():
    """The cap must not be masked -- the bug that corrupted the name table."""
    big = 0x10 + 66102 * 4
    got = core.encrypted_word_count(big)
    check("word count caps at 0x3FF0 for a 256 KB file", got == 0x3FF0, str(got))
    check("word count is exact below the cap",
          core.encrypted_word_count(0x10 + 762 * 4) == 762)
    masked = min(66102 & 0xFFFF, 0x3FF0)
    check("cap rule differs from the old masked rule (regression guard)",
          got != masked, f"cap={got} masked={masked}")


def t_cipher_symmetry(s):
    doc = next(s.documents())
    twice = core.apply_cipher(core.apply_cipher(doc.raw, doc.key), doc.key)
    check("cipher is symmetric", twice == doc.raw)


def t_roundtrip(s):
    bad, total = [], 0
    for doc in s.documents():
        total += 1
        if core.apply_cipher(doc.plain, doc.key) != doc.raw:
            bad.append(doc.path.name)
    check(f"zero-edit roundtrip byte-identical on all {total} files",
          not bad, f"{len(bad)} differ: {bad[:4]}")


def t_coverage(s):
    worst, bad = 1.0, []
    for doc in s.documents():
        cov = ir.coverage(doc)
        worst = min(worst, cov["byte_coverage"])
        if cov["gaps"] or cov["overlaps"] or cov["op_delta"] != 1:
            bad.append(doc.path.name)
    check("byte_coverage == 1.0, no gaps/overlaps, op_delta == 1",
          worst == 1.0 and not bad, f"worst={worst} bad={bad[:4]}")


def t_determinism(s):
    doc = next(s.documents())
    ir.extract_texts(doc, s.name_table)
    a = dis.render_texts(doc, s.source_encoding, s.target_encoding, "x")
    b = dis.render_asm(doc, s.source_encoding, "x")
    doc2 = ir.parse(doc.path, doc.raw, doc.key)
    ir.extract_texts(doc2, s.name_table)
    check("text rendering is deterministic",
          a == dis.render_texts(doc2, s.source_encoding, s.target_encoding, "x"))
    check("asm rendering is deterministic",
          b == dis.render_asm(doc2, s.source_encoding, "x"))


def t_placeholders(s):
    enc = s.source_encoding
    for raw in (b"abc", b"\x00\x01", b"\x82\xa0\x0c\x82\xa2",
                b"res\\g\\a.gyu", "全角　空白".encode("cp932")):
        shown = ir.to_display(raw, enc)
        if not check(f"placeholder roundtrip {raw!r}",
                     ir.from_display(shown, enc) == raw, repr(shown)):
            return
    check("backslash is not escaped", ir.to_display(b"a\\b", enc) == "a\\b")
    check("fullwidth space is not escaped",
          "{{" not in ir.to_display("　".encode("cp932"), enc))
    check("length counts placeholder bytes, not characters",
          ir.encoded_length("{{0A}}", enc, terminator=0) == 1)
    check("length includes the terminator",
          ir.encoded_length("ab", enc, terminator=1) == 3)


def t_name_binding(s):
    kinds, names = {}, set()
    for doc in s.documents():
        ir.extract_texts(doc, s.name_table)
        for b in doc.bindings:
            kinds[b.name_kind] = kinds.get(b.name_kind, 0) + 1
            if b.name_kind == "table" and b.resolved_name:
                names.add(b.resolved_name)
    check("character table resolved", len(s.name_table) > 0,
          f"{len(s.name_table)} entries")
    check("table-sourced speakers are bound", kinds.get("table", 0) > 0, str(kinds))
    check("per-line name overrides bound, not lost to the table",
          kinds.get("override", 0) > 0, str(kinds))
    check("unnamed ids stay virtual, not faked into entries",
          kinds.get("virtual", 0) > 0, str(kinds))
    check("real surnames present in the table",
          any(len(n) >= 2 for n in names), str(sorted(names)[:5]))


def t_name_lines(s):
    """Every on-screen name must have an editable line, not just a comment."""
    per_line = table_rule = 0
    msg_with_speaker = msg_total = 0
    for doc in s.documents():
        ir.extract_texts(doc, s.name_table)
        for t in doc.texts:
            if t.kind == "speaker_slot":
                per_line += 1
            if t.site_id == "chara-table-name":
                table_rule += 1
            if t.tag == "msg":
                msg_total += 1
                if t.speaker:
                    msg_with_speaker += 1
    check("table-sourced speakers get their own editable name line",
          per_line > 0, f"{per_line}")
    check("the character table itself is also editable",
          table_rule > 0, f"{table_rule}")
    check("most dialogue lines have a name line or a known speaker",
          msg_with_speaker > msg_total * 0.5,
          f"{msg_with_speaker}/{msg_total}")
    # every name entry must be translatable, none silently frozen
    frozen_names = sum(1 for doc in s.documents()
                       for t in (ir.extract_texts(doc, s.name_table) or doc.texts)
                       if t.tag == "name" and t.translate_policy != "translatable")
    check("no name entry is locked against translation", frozen_names == 0,
          str(frozen_names))


def t_name_writeback(s):
    """Editing a per-line name must write it into the slot; not editing it
    must leave the "*" alone so the table lookup survives byte-for-byte."""
    tmp = Path(tempfile.mkdtemp(prefix="rldname_"))
    quiet = lambda *a, **k: None
    try:
        sample = None
        for doc in s.documents():
            ir.extract_texts(doc, s.name_table)
            if sum(1 for t in doc.texts if t.kind == "speaker_slot") >= 3:
                sample = doc.path
                break
        if not check("found a file with table-sourced speakers",
                     sample is not None):
            return
        td = tmp / "t"
        dis.export([sample], td, want_texts=True,
                   target_encoding="gb18030", log=quiet)
        tf = td / "texts" / (sample.name + ".txt")
        original = tf.read_text(encoding="utf-8-sig")

        r0, _ = asm.repack([sample], td, tmp / "o0",
                           target_encoding="gb18030", log=quiet)
        check("names untouched -> output byte-identical (slot keeps '*')",
              (tmp / "o0" / sample.name).read_bytes() == sample.read_bytes())

        lines = original.split("\n")
        edited = 0
        first = None
        for i, l in enumerate(lines):
            if l.startswith("●") and l.split("●")[2] == "name":
                p = l.split("●")
                new = "译名" + p[3]
                lines[i] = f"●{p[1]}●{p[2]}●{new}"
                if first is None:
                    first = (int(p[1]), new)
                edited += 1
        tf.write_text("\n".join(lines), encoding="utf-8-sig")
        r1, _ = asm.repack([sample], td, tmp / "o1",
                           target_encoding="gb18030", log=quiet)
        check("editing names is accepted",
              not r1["rejected"] and not r1["verify_failed"],
              str(r1["rejected"][:2] + r1["verify_failed"][:2]))
        out = tmp / "o1" / sample.name
        check("editing names changes the file", out.exists()
              and out.read_bytes() != sample.read_bytes())
        if out.exists() and first:
            d = ir.parse(out, out.read_bytes(), s.keymap[sample], "gb18030")
            ir.extract_texts(d, s.name_table, "gb18030")
            got = {t.idx: t.source for t in d.texts}
            check("the translated name is present in the rebuilt file",
                  got.get(first[0]) == first[1],
                  f"{got.get(first[0])!r} != {first[1]!r}")
            spk = [t.speaker for t in d.texts if t.tag == "msg" and t.speaker]
            check("rebuilt dialogue reports the translated speaker",
                  any(str(v).startswith("译名") for v in spk),
                  str(spk[:3]))
            check("rebuilt file still fully covered",
                  ir.coverage(d)["byte_coverage"] == 1.0
                  and ir.coverage(d)["op_delta"] == 1)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def t_sprite_rows_survive(s):
    """Translating names must not touch the sprite definitions.

    Regression guard for the reported "sprites vanish after translating names"
    bug. Its real cause was the old tool's masked word count, whose boundary
    fell inside defChara's 263 sprite rows and rewrote 63 of them as garbage.
    Names and sprites share the same file, so this asserts they stay isolated.
    """
    table_file = None
    for p in s.sources:
        if p.name.lower() == "defchara.rld":
            table_file = p
            break
    if table_file is None:
        check("character table file present", False, "defChara.rld not found")
        return
    doc = ir.parse(table_file, s.blob(table_file), s.keymap[table_file])
    codes = {}
    for op in doc.ops:
        codes[op.code] = codes.get(op.code, 0) + 1
    sprite_code = 0x31
    check("sprite definition rows decode (not garbage)",
          codes.get(sprite_code, 0) > 100, str(codes))
    # every sprite row must be well-formed: numeric id fields
    bad = 0
    for op in doc.ops:
        if op.code != sprite_code or not op.strings:
            continue
        f = op.strings[0][1].split(b",")
        try:
            int(f[0]); int(f[1])
        except (ValueError, IndexError):
            bad += 1
    check("every sprite row has numeric character/pose ids", bad == 0, str(bad))

    tmp = Path(tempfile.mkdtemp(prefix="rldsprite_"))
    quiet = lambda *a, **k: None
    try:
        td = tmp / "t"
        dis.export([table_file], td, want_texts=True,
                   target_encoding="gb18030", log=quiet)
        tf = td / "texts" / (table_file.name + ".txt")
        lines = tf.read_text(encoding="utf-8-sig").split("\n")
        edits = 0
        for i, l in enumerate(lines):
            if l.startswith("●") and l.split("●")[2] == "name":
                p = l.split("●")
                lines[i] = f"●{p[1]}●{p[2]}●译{p[3]}"
                edits += 1
        tf.write_text("\n".join(lines), encoding="utf-8-sig")
        rep, _ = asm.repack([table_file], td, tmp / "o",
                            target_encoding="gb18030", log=quiet)
        check("translating every name is accepted",
              not rep["rejected"] and not rep["verify_failed"],
              str(rep["rejected"][:2] + rep["verify_failed"][:2]))
        out = tmp / "o" / table_file.name
        if not check("rebuilt table written", out.exists()):
            return
        new = ir.parse(out, out.read_bytes(), s.keymap[table_file], "gb18030")
        before = [op.strings[0][1] for op in doc.ops
                  if op.code == sprite_code and op.strings]
        after = [op.strings[0][1] for op in new.ops
                 if op.code == sprite_code and op.strings]
        check("sprite row count unchanged after renaming",
              len(before) == len(after), f"{len(before)} -> {len(after)}")
        check("all sprite rows byte-identical after renaming "
              f"({len(before)} rows, {edits} names changed)",
              before == after)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def t_tags(s):
    tags, frozen = {}, 0
    for doc in s.documents():
        ir.extract_texts(doc, s.name_table)
        for t in doc.texts:
            tags[t.tag] = tags.get(t.tag, 0) + 1
            if t.translate_policy == "frozen":
                frozen += 1
    closed = {"name", "msg", "choice", "label", "ui", "system", "ruby", "misc"}
    check("all tags are in the closed set", set(tags) <= closed, str(set(tags)))
    check("dialogue extracted (msg > 0)", tags.get("msg", 0) > 0, str(tags))
    check("choices extracted", tags.get("choice", 0) > 0, str(tags))
    check("names extracted", tags.get("name", 0) > 0, str(tags))
    check("font names exported frozen, not dropped", frozen > 0)


def _find(lines, prefix):
    for i, l in enumerate(lines):
        if l.startswith(prefix):
            return i
    return None


def _mut_src(L):
    i = _find(L, "○"); p = L[i].split("○")
    L[i] = f"○{p[1]}○{p[2]}○tampered"; return L


def _mut_idx(L):
    i = _find(L, "●"); p = L[i].split("●")
    L[i] = f"●{int(p[1]) + 7:08d}●{p[2]}●{p[3]}"; return L


def _mut_tag(L):
    i = _find(L, "●"); p = L[i].split("●")
    L[i] = f"●{p[1]}●system●{p[3]}"; return L


def _mut_empty(L):
    i = _find(L, "●"); p = L[i].split("●")
    L[i] = f"●{p[1]}●{p[2]}●"; return L


def _mut_delete(L):
    i = _find(L, "●"); return L[:i] + L[i + 1:]


def _mut_sha(L):
    L[0] = L[0][:-64] + "0" * 64; return L


def _mut_mixed(L):
    i = _find(L, "●"); p = L[i].split("●")
    L[i] = f"●{p[1]}○{p[2]}●{p[3]}"; return L


def t_edit_roundtrip(s):
    """The direction that matters: an edit must change the file and verify."""
    tmp = Path(tempfile.mkdtemp(prefix="rldtest_"))
    quiet = lambda *a, **k: None
    try:
        text_dir, sample = tmp / "text", None
        for doc in s.documents():
            ir.extract_texts(doc, s.name_table)
            n = sum(1 for t in doc.texts
                    if t.tag == "msg" and t.translate_policy == "translatable")
            if n >= 3:
                sample = doc.path
                break
        if not check("found a sample file with dialogue", sample is not None):
            return
        dis.export([sample], text_dir, want_texts=True, log=quiet)
        name = sample.name
        tf = text_dir / "texts" / (name + ".txt")
        original = tf.read_text(encoding="utf-8-sig")
        src_bytes = sample.read_bytes()

        rep, _ = asm.repack([sample], text_dir, tmp / "o1", log=quiet)
        out1 = tmp / "o1" / name
        check("no edits -> byte-identical output",
              out1.read_bytes() == src_bytes)
        check("no edits -> identity strategy", rep["strategy"] == "identity")

        # lengthen
        lines = original.split("\n")
        tgt = None
        for i, l in enumerate(lines):
            if l.startswith("●") and l.split("●")[2] == "msg":
                p = l.split("●")
                tgt, newtext = int(p[1]), p[3] * 3
                lines[i] = f"●{p[1]}●{p[2]}●{newtext}"
                break
        tf.write_text("\n".join(lines), encoding="utf-8-sig")
        rep2, _ = asm.repack([sample], text_dir, tmp / "o2", log=quiet)
        out2 = tmp / "o2" / name
        check("lengthened edit accepted",
              not rep2["rejected"] and not rep2["verify_failed"],
              str(rep2["rejected"][:2] + rep2["verify_failed"][:2]))
        check("lengthened edit changes the hash",
              out2.exists() and out2.read_bytes() != src_bytes)
        check("lengthened edit grows the file", rep2["bytes_delta"] > 0,
              f"delta={rep2['bytes_delta']}")
        if out2.exists():
            d2 = ir.parse(out2, out2.read_bytes(), s.keymap[sample])
            ir.extract_texts(d2, s.name_table)
            got = {t.idx: t.source for t in d2.texts}
            check("the longer text is actually in the output",
                  got.get(tgt) == newtext,
                  f"{str(got.get(tgt))[:40]!r} != {newtext[:40]!r}")
            check("output re-parses with full coverage",
                  ir.coverage(d2)["byte_coverage"] == 1.0)
            check("output op count still consistent",
                  ir.coverage(d2)["op_delta"] == 1)
            unchanged_ok = all(
                got.get(t.idx) == t.source
                for t in ir.extract_texts(
                    ir.parse(sample, src_bytes, s.keymap[sample]),
                    s.name_table)
                if t.idx != tgt)
            check("unedited entries are unchanged", unchanged_ok)

        # shorten
        lines = original.split("\n")
        for i, l in enumerate(lines):
            if l.startswith("●") and l.split("●")[2] == "msg":
                p = l.split("●")
                lines[i] = f"●{p[1]}●{p[2]}●{p[3][:2]}"
                break
        tf.write_text("\n".join(lines), encoding="utf-8-sig")
        rep3, _ = asm.repack([sample], text_dir, tmp / "o3", log=quiet)
        check("shortened edit shrinks the file", rep3["bytes_delta"] < 0,
              f"delta={rep3['bytes_delta']}")
        check("shortened edit verifies", not rep3["verify_failed"],
              str(rep3["verify_failed"][:2]))

        # tampering
        for label, mut in (("edited source line", _mut_src),
                           ("changed idx", _mut_idx),
                           ("changed tag", _mut_tag),
                           ("emptied translation", _mut_empty),
                           ("deleted an entry", _mut_delete),
                           ("wrong header hash", _mut_sha),
                           ("mixed separators", _mut_mixed)):
            tf.write_text("\n".join(mut(original.split("\n"))),
                          encoding="utf-8-sig")
            outd = tmp / ("ox_" + label.replace(" ", "_"))
            try:
                r, _ = asm.repack([sample], text_dir, outd, log=quiet)
                rejected = bool(r["rejected"] or r["verify_failed"])
            except core.RldError:
                rejected = True
            check(f"rejected: {label}", rejected)

        # frozen entry must refuse modification
        lines = original.split("\n")
        did = False
        for i, l in enumerate(lines):
            if l.startswith("#") and "frozen" in l:
                for j in range(i, min(i + 4, len(lines))):
                    if lines[j].startswith("●"):
                        p = lines[j].split("●")
                        lines[j] = f"●{p[1]}●{p[2]}●changed"
                        did = True
                        break
                break
        if did:
            tf.write_text("\n".join(lines), encoding="utf-8-sig")
            try:
                r, _ = asm.repack([sample], text_dir, tmp / "ofz", log=quiet)
                rejected = bool(r["rejected"])
            except core.RldError:
                rejected = True
            check("rejected: modified a frozen entry", rejected)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    rld_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "E:/GuardianPlace/rld")
    if not rld_dir.is_dir():
        print(f"not a directory: {rld_dir}")
        return 2
    work = Path(tempfile.mkdtemp(prefix="rldwork_"))
    try:
        print(f"=== corpus: {rld_dir} ===")
        s = _session(rld_dir, work)
        check("all files decoded", not s.unresolved,
              f"{len(s.unresolved)} unresolved")
        t_word_count_rule()
        t_cipher_symmetry(s)
        t_roundtrip(s)
        t_coverage(s)
        t_determinism(s)
        t_placeholders(s)
        t_name_binding(s)
        t_name_lines(s)
        t_name_writeback(s)
        t_sprite_rows_survive(s)
        t_tags(s)
        t_edit_roundtrip(s)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    failed = [r for r in _results if r[0] == FAIL]
    print(f"\n{len(_results) - len(failed)}/{len(_results)} checks passed")
    for _, name, detail in failed:
        print(f"  FAILED: {name}  {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
