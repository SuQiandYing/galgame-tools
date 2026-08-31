"""Rebuild .MES binaries from edits made to texts/ and/or asm/.

Does not parse asm.txt as a language. Instead it re-parses the source binary
(deterministic), renders a fresh projection of each editing surface, diffs the
user's file against that fresh projection, and applies only real changes. This
makes conflict detection a set intersection and removes the need for an ASM
grammar entirely.

Repack strategy is negotiated by probe, never by trial and error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import opcodelist as D
import disassembler as A

TOOL_VERSION = A.TOOL_VERSION

_SRC_RE = re.compile(r"^○(?P<idx>\d{8})○(?P<tag>[a-z_\-]+)○(?P<text>.*)$")
_TGT_RE = re.compile(r"^●(?P<idx>\d{8})●(?P<tag>[a-z_\-]+)●(?P<text>.*)$")
_HDR_SHA = re.compile(r"src_sha256=([0-9a-f]{64})")
_ASM_STR = re.compile(r'^(?P<off>[0-9A-F]{8})\s+(?P<mn>PUSHS|PUSHM)\s+sid=(?P<sid>\d+)\s+"(?P<text>.*)"(?:\s+;.*)?$')


class ImportError_(Exception):
    """Rejection of an edit file. Always names the offending idx."""


class ConflictError(Exception):
    pass


class TierTooLow(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ProbeVerdict:
    strategy_id: str
    applicable: bool
    reason_code: str
    reason_detail: str = ""
    blocking_refs: tuple = ()
    estimated_deltas: dict = None


# ---------------------------------------------------------------------------
# Import validation (SKILL.md 4.9)
# ---------------------------------------------------------------------------
def parse_text_file(path: Path, doc: A.Document) -> dict:
    """Validate a dual-line file against fresh IR. Returns {idx: new_text}."""
    raw = path.read_text(encoding="utf-8-sig")
    lines = raw.split("\n")

    head = [l for l in lines[:6] if l.startswith("#")]
    m = None
    for l in head:
        m = _HDR_SHA.search(l)
        if m:
            break
    if not m:
        raise ImportError_("%s: missing src_sha256 in header" % path.name)
    if m.group(1) != doc.src_sha256:
        raise ImportError_(
            "%s: header src_sha256 %s does not match current source %s "
            "(stale translation file?)" % (path.name, m.group(1)[:16],
                                           doc.src_sha256[:16]))

    by_idx = {e.idx: e for e in doc.texts}
    edits = {}
    seen = set()
    pending = None
    for ln, line in enumerate(lines, 1):
        if not line or line.startswith("#"):
            continue
        ms = _SRC_RE.match(line)
        if ms:
            pending = (ln, int(ms.group("idx")), ms.group("tag"), ms.group("text"))
            continue
        mt = _TGT_RE.match(line)
        if not mt:
            if line.startswith("○") or line.startswith("●"):
                raise ImportError_(
                    "%s line %d: malformed entry line (mixed separators?)"
                    % (path.name, ln))
            continue
        if pending is None:
            raise ImportError_(
                "%s line %d: target line without a preceding source line"
                % (path.name, ln))
        sln, sidx, stag, stext = pending
        pending = None
        tidx, ttag, ttext = int(mt.group("idx")), mt.group("tag"), mt.group("text")

        if tidx != sidx:
            raise ImportError_("%s line %d: idx mismatch %08d vs %08d"
                               % (path.name, ln, sidx, tidx))
        if ttag != stag:
            raise ImportError_("%s line %d: tag mismatch %s vs %s"
                               % (path.name, ln, stag, ttag))
        if sidx in seen:
            raise ImportError_("%s line %d: duplicate idx=%08d" % (path.name, ln, sidx))
        seen.add(sidx)
        entry = by_idx.get(sidx)
        if entry is None:
            raise ImportError_("%s line %d: idx=%08d not present in source"
                               % (path.name, ln, sidx))
        if stag != entry.tag:
            raise ImportError_("%s line %d: idx=%08d tag is %s, source says %s"
                               % (path.name, ln, sidx, stag, entry.tag))
        if stext != entry.source:
            raise ImportError_(
                "%s line %d: idx=%08d source line was edited\n  IR:   %r\n  file: %r"
                % (path.name, ln, sidx, entry.source, stext))
        if ttext == "":
            raise ImportError_(
                "%s line %d: idx=%08d target line is empty. An empty target "
                "means accidental deletion, not 'untranslated' (export "
                "pre-fills it)." % (path.name, ln, sidx))
        if ttext == entry.source:
            continue  # untranslated / intentionally kept
        if entry.translate_policy == "frozen":
            raise ImportError_(
                "%s line %d: idx=%08d is frozen (%s) and must not be changed"
                % (path.name, ln, sidx, entry.tag_subtype or entry.tag))

        target = D.ENCODINGS["target_encoding"]
        want = len(entry.part_offsets)
        got = ttext.count(D.MESSAGE_JOIN_ESCAPE) + 1
        if got != want:
            raise ImportError_(
                "%s line %d: idx=%08d has %d %r separator(s) but the engine "
                "expects %d (this message occupies %d on-screen lines)"
                % (path.name, ln, sidx, got - 1, D.MESSAGE_JOIN_ESCAPE,
                   want - 1, want))
        try:
            for piece in ttext.split(D.MESSAGE_JOIN_ESCAPE):
                A.from_display(piece, target)
        except UnicodeEncodeError as exc:
            bad = ttext[exc.start:exc.end] if exc.start < len(ttext) else "?"
            raise ImportError_(
                "%s line %d: idx=%08d cannot be represented in %s: %r. "
                "Try a wider target encoding (gbk / utf-8)."
                % (path.name, ln, sidx, target, bad)) from None
        except ValueError as exc:
            raise ImportError_("%s line %d: idx=%08d %s"
                               % (path.name, ln, sidx, exc)) from None

        oc, ob = A.placeholder_stats(entry.source)
        nc, nb = A.placeholder_stats(ttext)
        if (oc, ob) != (nc, nb):
            raise ImportError_(
                "%s line %d: idx=%08d placeholder set changed (%d/%d bytes -> "
                "%d/%d bytes); placeholders must be preserved exactly"
                % (path.name, ln, sidx, oc, ob, nc, nb))
        edits[sidx] = ttext

    if pending is not None:
        sln, sidx, _, _ = pending
        raise ImportError_(
            "%s line %d: idx=%08d has a source line but no target line "
            "(deleted?)" % (path.name, sln, sidx))
    expected = {e.idx for e in doc.texts}
    if seen != expected:
        missing = sorted(expected - seen)
        extra = sorted(seen - expected)
        detail = []
        if missing:
            detail.append("missing idx %s%s" % (
                ", ".join("%08d" % i for i in missing[:10]),
                " (+%d more)" % (len(missing) - 10) if len(missing) > 10 else ""))
        if extra:
            detail.append("unknown idx %s" % ", ".join("%08d" % i for i in extra[:10]))
        raise ImportError_(
            "%s: entry set does not match source (%d of %d present); %s"
            % (path.name, len(seen), len(expected), "; ".join(detail)))
    return edits


def parse_asm_file(path: Path, doc: A.Document) -> dict:
    """Diff a user asm file against a fresh render. Returns {idx: new_text}.

    Only string lines are accepted as edits. A changed instruction or data line
    requires full-layout (T3 relocation of every jump), which is refused here
    rather than attempted.
    """
    fresh = A.render_asm(doc).split("\n")
    user = path.read_text(encoding=D.ENCODINGS["asm_encoding"]).split("\n")
    if fresh == user:
        return {}

    by_off = {e.offset: e for e in doc.texts}
    edits = {}
    structural = []
    for ln, (f, u) in enumerate(zip(fresh, user), 1):
        if f == u:
            continue
        mf, mu = _ASM_STR.match(f), _ASM_STR.match(u)
        if mf and mu and mf.group("off") == mu.group("off"):
            off = int(mf.group("off"), 16)
            entry = by_off.get(off)
            if entry is None:
                structural.append((ln, f, u))
                continue
            if entry.translate_policy == "frozen":
                raise ImportError_(
                    "%s line %d: string at 0x%08X is frozen and must not change"
                    % (path.name, ln, off))
            edits[entry.idx] = mu.group("text").replace('\\"', '"')
        else:
            structural.append((ln, f, u))
    if len(user) != len(fresh):
        structural.append((0, "<%d lines>" % len(fresh), "<%d lines>" % len(user)))
    if structural:
        ln, f, u = structural[0]
        raise TierTooLow(
            "%s: %d structural change(s) in the ASM listing. Editing "
            "instructions or data needs tier T3 full-layout relocation, which "
            "this build does not provide; only .string edits are supported.\n"
            "  first at line %d\n    was: %s\n    now: %s"
            % (path.name, len(structural), ln, f.strip(), u.strip()))
    return edits


# ---------------------------------------------------------------------------
# Capacity and length (SKILL.md 6.0.2)
# ---------------------------------------------------------------------------
def split_parts(doc, entry, text: str) -> list:
    """Merged display text -> one stored byte string per engine line.

    The engine fixes the number of lines in a message (each is a separate
    string operand joined by a line-break instruction), so the escape count
    must be preserved exactly. Changing it would require inserting or deleting
    instructions, which is a full-layout operation.
    """
    want = len(entry.part_offsets)
    pieces = text.split(D.MESSAGE_JOIN_ESCAPE)
    if len(pieces) != want:
        raise ImportError_(
            "idx=%08d has %d line break(s) but the engine expects %d "
            "(this message occupies %d on-screen lines). Keep exactly %d "
            "%r separator(s); changing the line count needs full-layout."
            % (entry.idx, len(pieces) - 1, want - 1, want, want - 1,
               D.MESSAGE_JOIN_ESCAPE))
    out = []
    for piece in pieces:
        plain = A.from_display(piece, D.ENCODINGS["target_encoding"])
        stored = A.stored_bytes(doc, entry.opcode, plain)
        if D.STRING_TERMINATOR in stored:
            raise ImportError_(
                "idx=%08d encodes to bytes containing the string terminator"
                % entry.idx)
        out.append(stored)
    return out


def encoded_len(doc, entry, text: str) -> int:
    """Total stored bytes for this entry across all its parts."""
    return sum(len(p) + D.TERMINATOR_LEN for p in split_parts(doc, entry, text))


def slot_capacity(entry) -> int:
    """Original stored size across all parts, including terminators.

    Source is the terminator scan performed at parse time, not a subtraction of
    neighbouring offsets, so alignment padding can never inflate it.
    """
    return sum(len(r) + D.TERMINATOR_LEN for r in entry.part_raw)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------
def probe_all(doc: A.Document, edits: dict) -> list:
    by_idx = {e.idx: e for e in doc.texts}
    over = []
    delta = 0
    for idx, text in edits.items():
        e = by_idx[idx]
        new = encoded_len(doc, e, text)
        cap = slot_capacity(e)
        delta += new - cap
        if new > cap:
            over.append("idx=%08d(+%d)" % (idx, new - cap))

    verdicts = []
    if edits:
        verdicts.append(ProbeVerdict(
            "identity", False, "LENGTH_OVERFLOW" if over else "OK",
            "%d entries edited" % len(edits),
            tuple("idx=%08d" % i for i in sorted(edits))))
    else:
        verdicts.append(ProbeVerdict("identity", True, "OK", "no edits"))
    verdicts.append(ProbeVerdict(
        "in_place", not over and bool(edits),
        "OK" if not over else "LENGTH_OVERFLOW",
        "" if not over else "%d entries exceed their slot" % len(over),
        tuple(over)))
    # Every string reference in this format is a stream-order operand: there are
    # no stored offsets pointing at string bodies, so a length change needs no
    # pointer fix-ups beyond re-emitting jump operands, which are label-relative
    # and recomputed on serialize.
    verdicts.append(ProbeVerdict(
        "pointer-rewrite", bool(edits), "OK" if edits else "OK",
        "variable length supported", (),
        {"entries": len(edits), "bytes": delta}))
    verdicts.append(ProbeVerdict(
        "full-layout", False, "TIER_TOO_LOW",
        "structural relocation not provided by this build"))
    return verdicts


_ORDER = ["identity", "in_place", "pointer-rewrite", "full-layout"]


def select_strategy(verdicts) -> ProbeVerdict:
    for name in _ORDER:
        v = next(x for x in verdicts if x.strategy_id == name)
        if v.applicable:
            return v
    raise ImportError_("no applicable repack strategy: %s"
                       % "; ".join("%s=%s" % (v.strategy_id, v.reason_code)
                                   for v in verdicts))


def apply_edits(doc: A.Document, edits: dict) -> bytes:
    """Rewrite string operands and relocate every code offset that moves.

    A length change shifts all following instructions, so three classes of
    stored offset must be recomputed, not carried over:
      - header label table
      - header entry table
      - JMP/CALL operands (0x14 / 0x15)
    All are code-relative, so the fix is one old->new offset map applied by
    site, never by matching values (a constant that happens to equal an old
    offset must stay untouched).
    """
    by_idx = {e.idx: e for e in doc.texts}
    new_operand = {}
    for idx, text in edits.items():
        e = by_idx[idx]
        # One stored string per engine line, each written to its own site.
        for off, stored in zip(e.part_offsets, split_parts(doc, e, text)):
            new_operand[off] = stored

    # Pass 1: new code-relative position of every instruction.
    remap = {}
    cur = 0
    for x in doc.instructions:
        remap[x.offset - doc.code_start] = cur
        if x.opcode in doc.string_opcodes:
            body = new_operand.get(x.offset, x.operand)
            cur += 1 + len(body) + D.TERMINATOR_LEN
        elif x.size == 5:
            cur += 5
        else:
            cur += 1
    end_old = len(doc.data) - doc.code_start
    remap[end_old] = cur          # one-past-the-end is a legal jump target

    def move(old: int) -> int:
        new = remap.get(old)
        if new is None:
            raise ImportError_(
                "code offset 0x%X does not correspond to an instruction "
                "boundary; refusing to guess a new target" % old)
        return new

    # Pass 2: emit header with relocated tables, then the code.
    out = bytearray()
    out += A._U32_LE.pack(doc.n_labels)
    out += A._U32_LE.pack(doc.n_entries)
    for t in doc.labels:
        out += A._U32_LE.pack(move(t))
    for t in doc.entries:
        out += A._U32_LE.pack(move(t))
    if len(out) != doc.code_start:
        raise ImportError_("header size changed unexpectedly (%d -> %d)"
                           % (doc.code_start, len(out)))

    for x in doc.instructions:
        out.append(x.opcode)
        if x.opcode in doc.string_opcodes:
            out += new_operand.get(x.offset, x.operand)
            out += D.STRING_TERMINATOR
        elif x.opcode == D.OP_CHOICE and x.size == 5:
            # Choice branch target is a code offset and must move with the code,
            # exactly like a jump. Missing this corrupts which branch an option
            # takes while leaving the file loadable.
            out += A._U32_BE.pack(move(x.operand) & 0xFFFFFFFF)
        elif x.size == 5:
            val = x.operand
            if x.opcode in D.OP_JUMP:
                val = move(val)
            out += A._U32_BE.pack(val & 0xFFFFFFFF)
    return bytes(out)


def verify_rebuild(doc: A.Document, rebuilt: bytes, edits: dict,
                   out_path: Path) -> dict:
    """Post-repack checks. Direction differs from zero-edit on purpose."""
    src_hash = doc.src_sha256
    new_hash = hashlib.sha256(rebuilt).hexdigest()
    if not edits:
        if rebuilt != doc.data:
            raise ImportError_(
                "%s: zero edits but rebuild differs from source" % doc.path.name)
    else:
        if new_hash == src_hash:
            raise ImportError_(
                "%s: %d edits applied but output is byte-identical to the "
                "source - the edits were silently lost"
                % (doc.path.name, len(edits)))

    # Output must re-parse, keep full coverage, and contain the new text.
    doc2 = A.parse(out_path, rebuilt)
    cert = A.verify_coverage(doc2)
    A.extract_texts(doc2)
    if len(doc2.texts) != len(doc.texts):
        raise ImportError_(
            "%s: entry count changed after rebuild (%d -> %d)"
            % (doc.path.name, len(doc.texts), len(doc2.texts)))

    by_idx2 = {e.idx: e for e in doc2.texts}
    for idx, text in edits.items():
        got = by_idx2[idx].source
        if got != text:
            raise ImportError_(
                "%s: idx=%08d not present in output as written\n  wrote: %r\n"
                "  read back: %r" % (doc.path.name, idx, text, got))
    by_idx = {e.idx: e for e in doc.texts}
    for e in doc2.texts:
        if e.idx not in edits and e.part_raw != by_idx[e.idx].part_raw:
            raise ImportError_(
                "%s: idx=%08d was not edited but its bytes changed"
                % (doc.path.name, e.idx))

    expected = sum(encoded_len(doc, by_idx[i], t) - slot_capacity(by_idx[i])
                   for i, t in edits.items())
    actual = len(rebuilt) - len(doc.data)
    if actual != expected:
        raise ImportError_(
            "%s: size delta %+d does not match sum of entry deltas %+d"
            % (doc.path.name, actual, expected))
    return {"byte_coverage": cert["byte_coverage"], "size_delta": actual,
            "source_sha256": src_hash, "rebuilt_sha256": new_hash}


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def plan_one(src: Path, base: Path, textdir: Path) -> dict:
    """Collect edits for one source from both editing surfaces. No writes."""
    rel = A._rel(src, base)
    doc = A.parse(src)
    A.verify_coverage(doc)
    if A.serialize(doc) != doc.data:
        raise ImportError_("%s: zero-edit roundtrip failed; refusing to repack"
                           % rel)
    A.extract_texts(doc)

    tfile = textdir / "texts" / (str(rel) + ".txt")
    afile = textdir / "asm" / (str(rel) + ".asm.txt")
    tedits = parse_text_file(tfile, doc) if tfile.is_file() else {}
    aedits = parse_asm_file(afile, doc) if afile.is_file() else {}

    conflicts = []
    for idx in set(tedits) & set(aedits):
        if tedits[idx] != aedits[idx]:
            conflicts.append({"idx": idx, "texts": tedits[idx], "asm": aedits[idx]})
    edits = dict(aedits)
    edits.update(tedits)

    verdicts = probe_all(doc, edits)
    by_idx = {e.idx: e for e in doc.texts}
    longer = sum(1 for i, t in edits.items()
                 if encoded_len(doc, by_idx[i], t) > slot_capacity(by_idx[i]))
    return {"doc": doc, "rel": str(rel), "edits": edits, "verdicts": verdicts,
            "conflicts": conflicts, "longer": longer,
            "sources": {"texts": tfile.is_file(), "asm": afile.is_file()}}


def run_repack(inputs, textdir, outdir=None, dry_run=False, progress=None) -> dict:
    sources, base = A.find_sources(inputs)
    textdir = Path(textdir)
    if outdir is None:
        outdir = base.parent / (base.name + "_rebuilt")
    outdir = Path(outdir)

    plans = []
    failures = []
    for src in sources:
        try:
            plans.append(plan_one(src, base, textdir))
        except (ImportError_, TierTooLow, A.MesParseError) as exc:
            failures.append({"rel": str(A._rel(src, base)), "error": str(exc)})

    conflicts = [{"rel": p["rel"], **c} for p in plans for c in p["conflicts"]]
    edited = [p for p in plans if p["edits"]]
    report = {
        "tool_version": TOOL_VERSION,
        "input_base": str(base),
        "text_dir": str(textdir),
        "output_dir": str(outdir),
        "files_total": len(plans),
        "files_with_edits": len(edited),
        "entries_edited": sum(len(p["edits"]) for p in plans),
        "entries_longer": sum(p["longer"] for p in plans),
        "conflicts": conflicts,
        "failures": failures,
        "repack_verdicts": [
            {"rel": p["rel"],
             "selected": (select_strategy(p["verdicts"]).strategy_id
                          if not p["conflicts"] else None),
             "verdicts": [{"strategy_id": v.strategy_id,
                           "applicable": v.applicable,
                           "reason_code": v.reason_code,
                           "reason_detail": v.reason_detail,
                           "blocking_refs": list(v.blocking_refs),
                           "estimated_deltas": v.estimated_deltas}
                          for v in p["verdicts"]]}
            for p in plans],
    }
    if conflicts or failures or dry_run:
        report["written"] = 0
        if not dry_run:
            report["aborted"] = True
        return report

    written = 0
    strategies = {}
    for i, p in enumerate(plans, 1):
        doc = p["doc"]
        chosen = select_strategy(p["verdicts"])
        strategies[chosen.strategy_id] = strategies.get(chosen.strategy_id, 0) + 1
        dest = outdir / p["rel"]
        rebuilt = apply_edits(doc, p["edits"]) if p["edits"] else A.serialize(doc)
        tmp = outdir / "_tmp" / p["rel"]
        A._atomic_write(tmp, rebuilt)
        try:
            info = verify_rebuild(doc, rebuilt, p["edits"], tmp)
        except ImportError_:
            failed = outdir / "_tmp" / "failed" / p["rel"]
            A._atomic_write(failed, rebuilt)
            tmp.unlink(missing_ok=True)
            raise
        tmp.unlink(missing_ok=True)
        A._atomic_write(dest, rebuilt)
        written += 1
        if progress:
            progress(i, len(plans), p["rel"], chosen.strategy_id, info)
    report["written"] = written
    report["strategies_used"] = strategies
    work = textdir / "_work" / "reports"
    A._atomic_write(work / "repack_verdicts.json",
                    json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8"))
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Rebuild SILKY'S ENGINE .MES scripts from edited text/asm")
    ap.add_argument("inputs", nargs="+", help="original source file(s) or folder(s)")
    ap.add_argument("-t", "--texts", required=True,
                    help="directory holding texts/ and/or asm/")
    ap.add_argument("-o", "--output", default=None, help="output directory")
    ap.add_argument("--dry-run", action="store_true", help="preview only")
    args = ap.parse_args(argv)

    def show(i, n, rel, strat, info):
        print("[%d/%d] %-28s %-16s %+d bytes" % (i, n, rel, strat,
                                                 info["size_delta"]),
              file=sys.stderr)

    try:
        rep = run_repack(args.inputs, args.texts, args.output,
                         dry_run=args.dry_run, progress=show)
    except (ImportError_, TierTooLow, A.MesParseError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    print()
    print("files          %d" % rep["files_total"])
    print("edited         %d files, %d entries (%d longer than original)"
          % (rep["files_with_edits"], rep["entries_edited"], rep["entries_longer"]))
    if rep["conflicts"]:
        print("CONFLICTS      %d - nothing was written" % len(rep["conflicts"]))
        for c in rep["conflicts"][:20]:
            print("  %s idx=%08d\n    texts/: %r\n    asm/:   %r"
                  % (c["rel"], c["idx"], c["texts"], c["asm"]))
        return 1
    for f in rep["failures"]:
        print("FAILED %s: %s" % (f["rel"], f["error"]), file=sys.stderr)
    if rep["failures"]:
        print("nothing was written", file=sys.stderr)
        return 1
    if args.dry_run:
        print("dry run - nothing written")
        return 0
    print("strategies     %s" % ", ".join(
        "%s=%d" % kv for kv in sorted(rep.get("strategies_used", {}).items())))
    print("written        %d files to %s" % (rep["written"], rep["output_dir"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
