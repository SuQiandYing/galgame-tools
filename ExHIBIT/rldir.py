"""In-memory IR: ops, regions, text entries, name bindings, coverage.

The IR is derived from source bytes and is the parsing truth. Text extraction
reads the IR, never the rendered asm -- rendering discards the slot identity
and sharing information extraction needs.
"""
from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field

from opcodelist import DIALECT, text_sites_by_code
import rldcore as core

_C = DIALECT["container"]
_O = DIALECT["op"]
_NB = DIALECT["name_binding"]
_CS = DIALECT["choice_scan"]

_U32 = struct.Struct("<I")
_NON_TEXT = re.compile(DIALECT["non_text_field"])
# Built from the dialect's declared ranges rather than hardcoded here, so a
# title needing different scripts is a declaration change, not a code change.
_SCRIPT = re.compile("[" + "".join(
    f"{chr(lo)}-{chr(hi)}" for lo, hi in DIALECT["script_ranges"]) + "]")
_SITES = text_sites_by_code()


@dataclass
class Op:
    index: int
    offset: int
    control: int
    code: int
    init_count: int
    str_count: int
    flags: int           # control bits 28-31; opaque but must be preserved
    inits: list
    strings: list        # list of (offset, raw_bytes)
    end: int


@dataclass
class TextEntry:
    idx: int
    op_index: int
    offset: int          # absolute offset of the containing string
    code: int
    slot: int
    site_id: str
    kind: str            # whole | field | choice_scan | choice_bare
    sep: str | None
    field_index: int | None
    tag: str
    tag_subtype: str | None
    tag_source: str
    translate_policy: str
    source: str          # display form, placeholders applied
    raw: bytes           # the exact bytes of the text unit
    speaker: str | None = None
    speaker_id: int | None = None
    name_kind: str | None = None


@dataclass
class NameBinding:
    binding_id: int
    msg_entry_idx: int
    name_entry_idx: int | None
    speaker_id: int
    name_kind: str       # table | override | virtual
    method: str
    confidence: str
    resolved_name: str | None


@dataclass
class Document:
    path: object
    raw: bytes           # original file bytes (encrypted)
    plain: bytes         # decrypted bytes
    key: list
    ops: list
    op_offset: int
    declared_count: int
    stream_end: int
    src_sha256: str
    texts: list = field(default_factory=list)
    bindings: list = field(default_factory=list)
    notes: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# placeholders
# ---------------------------------------------------------------------------

def to_display(raw: bytes, encoding: str) -> str:
    """Bytes -> editable text. Undisplayable bytes become {{XX}} placeholders.

    Never falls back to errors="replace": a silently substituted character
    would be re-encoded as different bytes with no trace. Backslashes and
    fullwidth spaces are left alone -- they display fine.
    """
    out = []
    buf = bytearray()

    def flush():
        if buf:
            out.append(buf.decode(encoding))
            buf.clear()

    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if b < 0x20:
            flush()
            out.append("{{%02X}}" % b)
            i += 1
            continue
        # try the longest valid multibyte unit at this position
        for width in (2, 1):
            chunk = raw[i:i + width]
            if len(chunk) < width:
                continue
            try:
                chunk.decode(encoding)
            except UnicodeDecodeError:
                continue
            buf += chunk
            i += width
            break
        else:
            flush()
            group = [raw[i]]
            i += 1
            while i < n:
                try:
                    bytes(group + [raw[i]]).decode(encoding)
                    break
                except UnicodeDecodeError:
                    group.append(raw[i])
                    i += 1
                    if len(group) >= 2:
                        break
            out.append("{{%s}}" % ":".join("%02X" % g for g in group))
    flush()
    return "".join(out)


_PH = re.compile(r"\{\{([0-9A-F]{2}(?::[0-9A-F]{2})*)\}\}")


def from_display(text: str, encoding: str) -> bytes:
    """Editable text -> bytes. Placeholders expand to their literal bytes."""
    out = bytearray()
    pos = 0
    for m in _PH.finditer(text):
        if m.start() > pos:
            out += text[pos:m.start()].encode(encoding)
        for part in m.group(1).split(":"):
            out.append(int(part, 16))
        pos = m.end()
    if pos < len(text):
        out += text[pos:].encode(encoding)
    return bytes(out)


def encoded_length(text: str, encoding: str, terminator: int = 1) -> int:
    """Byte cost of `text` in the target encoding, placeholders expanded."""
    return len(from_display(text, encoding)) + terminator


# ---------------------------------------------------------------------------
# parse
# ---------------------------------------------------------------------------

def parse(path, raw: bytes, key: list, encoding=None) -> Document:
    """Source bytes -> Document. Deterministic: same input, same IR."""
    encoding = encoding or DIALECT["encodings"]["source"]
    if raw[:len(_C["magic"])] != _C["magic"]:
        raise core.ParseError(f"{path}: bad magic")
    plain = core.apply_cipher(raw, key)
    off, declared = struct.unpack_from("<II", plain, _C["op_offset_field"])
    ops = []
    cur = off
    size = len(plain)
    term = _O["string_terminator"]
    index = 0
    while cur < size:
        start = cur
        if cur + _O["control_width"] > size:
            raise core.ParseError(f"{path}: truncated control word at {cur:#x}")
        control = _U32.unpack_from(plain, cur)[0]
        cur += _O["control_width"]
        code = (control >> _O["code_shift"]) & _O["code_mask"]
        ic = (control >> _O["init_count_shift"]) & _O["init_count_mask"]
        sc = (control >> _O["str_count_shift"]) & _O["str_count_mask"]
        flags = (control >> _O["flags_shift"]) & _O["flags_mask"]
        inits = list(struct.unpack_from("<%dI" % ic, plain, cur)) if ic else []
        cur += ic * _O["init_width"]
        strings = []
        for _ in range(sc):
            e = plain.find(term, cur)
            if e < 0:
                raise core.ParseError(
                    f"{path}: unterminated string at {cur:#x}")
            strings.append((cur, plain[cur:e]))
            cur = e + len(term)
        ops.append(Op(index=index, offset=start, control=control, code=code,
                      init_count=ic, str_count=sc, flags=flags, inits=inits,
                      strings=strings, end=cur))
        index += 1
    doc = Document(path=path, raw=bytes(raw), plain=plain, key=key, ops=ops,
                   op_offset=off, declared_count=declared, stream_end=cur,
                   src_sha256=hashlib.sha256(raw).hexdigest())
    if cur != size:
        doc.notes.append(f"stream ends at {cur:#x} but file is {size:#x}")
    return doc


# ---------------------------------------------------------------------------
# text extraction
# ---------------------------------------------------------------------------

def _is_text_field(value: str) -> bool:
    return bool(value) and not _NON_TEXT.match(value) and bool(_SCRIPT.search(value))


def _policy_for(rule, tag, tag_source):
    if "translate_policy" in rule:
        return rule["translate_policy"]
    if tag_source == "unresolved":
        return "review-required"
    if tag == "misc":
        return "review-required"
    if tag == "label":
        return "frozen"
    return "translatable"


def extract_texts(doc: Document, name_table: dict, encoding=None):
    """Populate doc.texts and doc.bindings from the IR.

    Every entry traces to a declared (opcode, slot) site. There is no
    catch-all rule: an unclassified string stays out rather than being folded
    into msg, so the unresolved count stays meaningful.
    """
    encoding = encoding or DIALECT["encodings"]["source"]
    skip_global = set(DIALECT["placeholder_values"])
    idx = 0
    doc.texts = []
    doc.bindings = []
    collected = []
    pending_binds = []

    for op in doc.ops:
        rules = _SITES.get(op.code)
        if not rules:
            continue
        # Entries produced by this op, keyed by string slot. Binding is done
        # after all rules have run so it cannot depend on the order the rules
        # happen to be declared in.
        by_slot = {}
        for rule in rules:
            kind = rule["kind"]
            slot = rule.get("slot")
            skip = set(rule.get("skip_values", []))

            if kind == "whole":
                if slot is None or slot >= len(op.strings):
                    continue
                off, raw = op.strings[slot]
                text = to_display(raw, encoding)
                if not raw or text in skip:
                    continue
                entry = _make(0, op, off, rule, slot, text, raw, None, None)
                collected.append(entry)
                by_slot[slot] = entry

            elif kind == "field":
                if slot is None or slot >= len(op.strings):
                    continue
                off, raw = op.strings[slot]
                sep = rule["sep"]
                fi = rule["field"]
                parts = raw.split(sep.encode(encoding))
                if fi >= len(parts):
                    continue
                unit = parts[fi]
                if not unit:
                    continue
                text = to_display(unit, encoding)
                if text in skip:
                    continue
                if rule.get("translate_policy") != "frozen" \
                        and not _is_text_field(text):
                    continue
                inner = off + sum(len(p) for p in parts[:fi]) + fi * len(sep)
                collected.append(
                    _make(0, op, inner, rule, slot, text, unit, sep, fi))

            elif kind == "choice_scan":
                for si, (off, raw) in enumerate(op.strings):
                    sep = rule["sep"].encode(encoding)
                    if sep not in raw:
                        continue
                    parts = raw.split(sep)
                    base = off
                    for fi, unit in enumerate(parts):
                        start = base
                        base += len(unit) + len(sep)
                        if fi < _CS["min_field"] or not unit:
                            continue
                        text = to_display(unit, encoding)
                        if _CS["asset_hint"] in text or not _is_text_field(text):
                            continue
                        collected.append(
                            _make(0, op, start, rule, si, text, unit,
                                  rule["sep"], fi))

            elif kind == "speaker_slot":
                # An editable name line for a speaker whose name lives in the
                # character table. The slot currently holds "*"; the displayed
                # source is the table's name so the translator edits what they
                # actually see on screen.
                if slot is None or slot >= len(op.strings):
                    continue
                off, raw = op.strings[slot]
                if to_display(raw, encoding) not in rule.get("requires_values", []):
                    continue
                sid = op.inits[_NB["speaker_id_init"]] if op.inits else None
                resolved = name_table.get(sid)
                if not resolved:
                    continue        # virtual/unnamed: nothing to show or edit
                entry = _make(0, op, off, rule, slot, resolved, raw, None, None)
                entry.speaker_id = sid
                entry.name_kind = "table"
                collected.append(entry)
                # Deliberately NOT registered in by_slot: this is not an
                # override, so the body must still bind via the table.

            elif kind == "choice_bare":
                for si, (off, raw) in enumerate(op.strings):
                    if rule.get("sep") and rule["sep"].encode(encoding) in raw:
                        continue
                    if b"\t" in raw:
                        continue
                    text = to_display(raw, encoding)
                    if not _is_text_field(text):
                        continue
                    collected.append(
                        _make(0, op, off, rule, si, text, raw, None, None))

        if op.code == _NB["dialogue_code"]:
            body = by_slot.get(_NB["body_slot"])
            if body is not None:
                pending_binds.append(
                    (op, body, by_slot.get(_NB["override_slot"])))

    # Number entries by where they physically sit in the file, not by the
    # order the rules happened to fire. A speaker-name override is stored
    # BEFORE the line it labels, so rule order would list the name after its
    # own dialogue and read backwards to a translator.
    collected.sort(key=lambda e: (e.offset, e.op_index, e.slot or 0))
    for n, entry in enumerate(collected, 1):
        entry.idx = n
    doc.texts = collected
    for op, body, override in pending_binds:
        _bind(doc, op, body, override, name_table)
    doc.bindings.sort(key=lambda b: b.msg_entry_idx)
    return doc.texts


def _make(idx, op, off, rule, slot, text, raw, sep, fi):
    tag = rule["tag"]
    tag_source = rule["tag_source"]
    return TextEntry(
        idx=idx, op_index=op.index, offset=off, code=op.code, slot=slot,
        site_id=rule["id"], kind=rule["kind"], sep=sep, field_index=fi,
        tag=tag, tag_subtype=rule.get("tag_subtype"), tag_source=tag_source,
        translate_policy=_policy_for(rule, tag, tag_source),
        source=text, raw=bytes(raw))


def _bind(doc, op, body_entry, override, name_table):
    """Attach a speaker to a dialogue body.

    Priority is explicit-id: inits[0] is the character id. An override string
    in slot 0 wins over the table for display; "*" defers to the table. Ids
    absent from the table with no override are virtual (an unnamed narrator)
    and are never fabricated into editable name entries.
    """
    sid = op.inits[_NB["speaker_id_init"]] if op.inits else None
    if override is not None:
        kind = "override"
        resolved = override.source
        name_idx = override.idx
    elif sid in name_table:
        kind = "table"
        resolved = name_table[sid]
        name_idx = None
    else:
        kind = "virtual"
        resolved = None
        name_idx = None
    body_entry.speaker = resolved
    body_entry.speaker_id = sid
    body_entry.name_kind = kind
    doc.bindings.append(NameBinding(
        binding_id=len(doc.bindings) + 1,
        msg_entry_idx=body_entry.idx, name_entry_idx=name_idx,
        speaker_id=sid, name_kind=kind, method=_NB["method"],
        confidence=_NB["confidence"], resolved_name=resolved))


def build_name_table(doc: Document, encoding=None) -> dict:
    """Character id -> surname, from the defChara table ops."""
    encoding = encoding or DIALECT["encodings"]["source"]
    table = {}
    sep = _NB["table_sep"].encode(encoding)
    for op in doc.ops:
        if op.code != _NB["table_code"] or not op.strings:
            continue
        parts = op.strings[0][1].split(sep)
        if len(parts) <= max(_NB["table_id_field"], _NB["table_name_field"]):
            continue
        try:
            cid = int(parts[_NB["table_id_field"]])
        except ValueError:
            continue
        name = parts[_NB["table_name_field"]]
        if name:
            table[cid] = to_display(name, encoding)
    return table


# ---------------------------------------------------------------------------
# coverage
# ---------------------------------------------------------------------------

def coverage(doc: Document) -> dict:
    """Byte-attribution certificate. Every byte belongs to exactly one span."""
    spans = []
    spans.append(dict(start=0, end=_C["header_size"], kind="header",
                      status="decoded"))
    if doc.op_offset > _C["header_size"]:
        spans.append(dict(start=_C["header_size"], end=doc.op_offset,
                          kind="pre-stream", status="opaque-preserved"))
    for op in doc.ops:
        spans.append(dict(start=op.offset, end=op.end, kind="op",
                          status="decoded"))
    if doc.stream_end < len(doc.plain):
        spans.append(dict(start=doc.stream_end, end=len(doc.plain),
                          kind="tail", status="opaque-preserved"))
    spans.sort(key=lambda s: s["start"])
    gaps, overlaps = [], []
    cursor = 0
    for s in spans:
        if s["start"] > cursor:
            gaps.append((cursor, s["start"]))
        elif s["start"] < cursor:
            overlaps.append((s["start"], cursor))
        cursor = max(cursor, s["end"])
    size = len(doc.plain)
    if cursor < size:
        gaps.append((cursor, size))
    covered = size - sum(b - a for a, b in gaps)
    return dict(
        source_size=size,
        span_count=len(spans),
        gaps=gaps, overlaps=overlaps,
        byte_coverage=(covered / size) if size else 1.0,
        op_count_declared=doc.declared_count,
        op_count_parsed=len(doc.ops),
        op_delta=len(doc.ops) - doc.declared_count,
        stream_end=doc.stream_end,
        decode_tier="T2",
        src_sha256=doc.src_sha256,
    )
