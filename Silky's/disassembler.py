"""SILKY'S ENGINE .MES disassembler: source binary -> in-memory IR -> asm.txt / texts/.

Structural logic only. Every engine-specific number lives in opcodelist.py.

Two independent entry points, both taking the source binary as input:
    render_asm_files(...)    -> asm/<mirrored path>.asm.txt
    render_text_files(...)   -> texts/<mirrored path>.txt

The IR is not persisted by default (see vm_analysis.md): parsing is
deterministic, so the source file is itself the most compact IR.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import opcodelist as D

IR_VERSION = "1.0.0"
TOOL_VERSION = "1.0.0"

_U32_LE = struct.Struct("<I")
_U32_BE = struct.Struct(">I")


class MesParseError(Exception):
    """Base for all refusals. Never raised to mean 'guessed and moved on'."""


class HeaderError(MesParseError):
    pass


class UnterminatedString(MesParseError):
    pass


class TruncatedOperand(MesParseError):
    pass


class LabelMisaligned(MesParseError):
    pass


class AddressSpaceGapError(MesParseError):
    pass


class AddressSpaceCollisionError(MesParseError):
    pass


# ---------------------------------------------------------------------------
# IR
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Instruction:
    offset: int          # absolute file offset
    size: int
    opcode: int
    operand: object      # int for u32 ops, bytes for string ops, None otherwise


@dataclass(frozen=True, slots=True)
class TextEntry:
    idx: int
    offset: int          # absolute offset of the first instruction
    opcode: int
    raw: bytes           # operand bytes exactly as stored (still compressed)
    source: str          # expanded, decoded text
    tag: str
    tag_source: str
    tag_subtype: str
    translate_policy: str
    syscall_id: int | None
    speaker: str | None
    matched_rule_id: str | None
    # For a merged multi-part message: the absolute offset and stored bytes of
    # every part, in order. Single-part entries have exactly one element each.
    part_offsets: tuple = ()
    part_raw: tuple = ()


@dataclass(slots=True)
class Document:
    path: Path
    data: bytes
    n_labels: int
    n_entries: int
    labels: tuple
    entries: tuple
    code_start: int
    instructions: list = field(default_factory=list)
    texts: list = field(default_factory=list)
    src_sha256: str = ""
    variant: dict = None          # the VARIANTS entry chosen by structural probe
    variant_scores: tuple = ()    # (id, score-dict) per candidate, for reports

    @property
    def label_targets(self) -> set:
        return {self.code_start + t for t in self.labels}

    @property
    def msg_op(self) -> int:
        return self.variant["message_opcode"]

    @property
    def id_op(self) -> int:
        return self.variant["identifier_opcode"]

    @property
    def string_opcodes(self) -> tuple:
        return (self.variant["identifier_opcode"], self.variant["message_opcode"])

    def is_kana_compressed(self, opcode: int) -> bool:
        return (self.variant["kana_compressed"]
                and opcode == self.variant["message_opcode"])


# ---------------------------------------------------------------------------
# Kana expansion / compression
# ---------------------------------------------------------------------------
def _is_lead(b: int) -> bool:
    for lo, hi in D.CP932_LEAD_RANGES:
        if lo <= b <= hi:
            return True
    return False


_KANA_ENC = {}
_KANA_DEC = {}
for _c in range(D.KANA_CODE_MIN, D.KANA_CODE_MAX + 1):
    try:
        _ch = chr(D.KANA_BASE + _c).encode(D.ENCODINGS["source_encoding"])
    except UnicodeEncodeError:
        continue
    _KANA_DEC[_c] = _ch
    _KANA_ENC.setdefault(_ch, _c)


def expand(raw: bytes) -> bytes:
    """Substitution codes -> real cp932 bytes. cp932 pairs pass through."""
    out = bytearray()
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if _is_lead(b):
            out += raw[i:i + 2]
            i += 2
        elif b in _KANA_DEC:
            out += _KANA_DEC[b]
            i += 1
        else:
            out.append(b)
            i += 1
    return bytes(out)


def plain_bytes(doc, opcode: int, raw: bytes) -> bytes:
    """Stored operand -> plain cp932 bytes, expanding only where this file's
    variant says codes are used. Identifier strings keep '.' as '.', not の,
    and the plain-cp932 variant is never expanded at all."""
    if doc.is_kana_compressed(opcode):
        return expand(raw)
    return raw


def stored_bytes(doc, opcode: int, plain: bytes) -> bytes:
    """Inverse of plain_bytes()."""
    if doc.is_kana_compressed(opcode):
        return compress(plain)
    return plain


def compress(plain: bytes) -> bytes:
    """Inverse of expand(). Used when writing edited text back."""
    out = bytearray()
    i = 0
    n = len(plain)
    while i < n:
        b = plain[i]
        if _is_lead(b) and i + 1 < n:
            pair = plain[i:i + 2]
            code = _KANA_ENC.get(pair)
            if code is not None:
                out.append(code)
            else:
                out += pair
            i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)


# ---------------------------------------------------------------------------
# Placeholders (SKILL.md 4.5)
# ---------------------------------------------------------------------------
def to_display(plain: bytes, encoding: str) -> str:
    """Decode to display text, rendering undecodable/control bytes as {{XX}}."""
    out = []
    i = 0
    n = len(plain)
    pending = bytearray()

    def flush():
        if pending:
            out.append("{{" + ":".join("%02X" % b for b in pending) + "}}")
            pending.clear()

    while i < n:
        b = plain[i]
        if b < D.CONTROL_BYTE_MAX:
            pending.append(b)
            i += 1
            continue
        width = 2 if (_is_lead(b) and i + 1 < n) else 1
        chunk = plain[i:i + width]
        try:
            ch = chunk.decode(encoding)
        except UnicodeDecodeError:
            pending += chunk
            i += width
            continue
        flush()
        out.append(ch)
        i += width
    flush()
    return "".join(out)


def from_display(text: str, encoding: str) -> bytes:
    """Inverse of to_display(). Placeholders become raw bytes verbatim."""
    out = bytearray()
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("{{", i):
            end = text.find("}}", i)
            if end < 0:
                raise ValueError("unterminated placeholder at %d" % i)
            body = text[i + 2:end]
            for part in body.split(":"):
                if len(part) != 2 or any(c not in "0123456789ABCDEF" for c in part):
                    raise ValueError("bad placeholder %r" % body)
                out.append(int(part, 16))
            i = end + 2
        else:
            out += text[i].encode(encoding)
            i += 1
    return bytes(out)


def placeholder_stats(display: str) -> tuple:
    count = 0
    nbytes = 0
    i = 0
    while True:
        i = display.find("{{", i)
        if i < 0:
            break
        end = display.find("}}", i)
        if end < 0:
            break
        count += 1
        nbytes += len(display[i + 2:end].split(":"))
        i = end + 2
    return count, nbytes


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def parse_header(data: bytes, path: Path) -> tuple:
    if len(data) < 8:
        raise HeaderError("%s: shorter than header (%d bytes)" % (path, len(data)))
    n_labels = _U32_LE.unpack_from(data, 0)[0]
    n_entries = _U32_LE.unpack_from(data, 4)[0]
    need = 8 + 4 * n_labels + 4 * n_entries
    if need > len(data):
        raise HeaderError(
            "%s: header tables need %d bytes, file has %d" % (path, need, len(data)))
    labels = struct.unpack_from("<%dI" % n_labels, data, 8) if n_labels else ()
    off = 8 + 4 * n_labels
    entries = struct.unpack_from("<%dI" % n_entries, data, off) if n_entries else ()
    return n_labels, n_entries, labels, entries, need


def _decode_stream(data: bytes, code_start: int, strop: tuple, path: Path):
    """Linear decode under one candidate string-opcode set. Returns instructions."""
    ins = []
    i = code_start
    n = len(data)
    u32 = D.OPERAND_U32
    append = ins.append
    while i < n:
        op = data[i]
        if op in strop:
            j = data.find(D.STRING_TERMINATOR, i + 1)
            if j < 0:
                raise UnterminatedString(
                    "%s: unterminated string operand at 0x%X" % (path, i))
            append(Instruction(i, j + 1 - i, op, data[i + 1:j]))
            i = j + 1
        elif op == D.OP_CHOICE:
            # Context-dependent width: a choice carries a code offset, but the
            # same opcode value is a plain no-operand opcode in library files.
            # Decided by whether the operand resolves inside the file, so this
            # is a test rather than a guess.
            end = i + 1 + D.CHOICE_TARGET_WIDTH
            target = (_U32_BE.unpack_from(data, i + 1)[0]
                      if end <= n else None)
            if target is not None and code_start + target <= n:
                append(Instruction(i, 5, op, target))
                i = end
            else:
                append(Instruction(i, 1, op, None))
                i += 1
        elif op in u32:
            if i + 5 > n:
                raise TruncatedOperand(
                    "%s: truncated 4-byte operand at 0x%X" % (path, i))
            append(Instruction(i, 5, op, _U32_BE.unpack_from(data, i + 1)[0]))
            i += 5
        else:
            append(Instruction(i, 1, op, None))
            i += 1
    return ins


def _score_variant(ins, labels_abs, size: int) -> dict:
    """Structural quality of a decode. Two independent signals, both direct
    consequences of losing synchronisation rather than appearance heuristics:

      label_misses     a label target not landing on an instruction boundary
      lead_byte_ratio  share of distinct opcodes that are cp932 lead bytes

    The lead-byte signal is a ratio, not a count. A correct decode does contain
    a few single-byte opcodes that happen to fall in the lead ranges (measured:
    1 of 29 distinct in FK028, 5 of 75 in LIBLARY.LIB), so requiring exactly
    zero rejects valid files. A desynchronised decode is walking through cp932
    text and lights up most of the range at once (45 of 230 distinct in the
    same file under the wrong variant).
    """
    starts = {x.offset for x in ins}
    missed = sum(1 for t in labels_abs if t not in starts and t != size)
    opcodes = {x.opcode for x in ins}
    leads = sum(1 for op in opcodes if _is_lead(op)) \
        if D.CP932_LEAD_AS_OPCODE_IS_DESYNC else 0
    return {"label_misses": missed,
            "lead_byte_opcodes": leads,
            "lead_byte_ratio": round(leads / max(len(opcodes), 1), 4),
            "distinct_opcodes": len(opcodes), "instructions": len(ins)}


_MIN_MESSAGE_BYTES = 4


def _message_weight(var: dict, ins) -> int:
    """Total bytes held in message-carrying strings long enough to be text.

    Only used to break exact ties between variants. Very short operands are
    excluded because a single misread opcode yields a 1-2 byte "string" that
    would otherwise count as evidence of dialogue.
    """
    op = var["message_opcode"]
    return sum(len(x.operand) for x in ins
               if x.opcode == op and x.operand
               and len(x.operand) >= _MIN_MESSAGE_BYTES)


def select_variant(data: bytes, code_start: int, labels_abs, path: Path) -> tuple:
    """Choose the dialect variant by structural probe (SKILL.md 7.5.2).

    Never keys off file or folder name. Returns (variant, scores) and raises if
    no candidate produces a clean decode.
    """
    scores = []
    viable = []
    for var in D.VARIANTS:
        strop = (var["identifier_opcode"], var["message_opcode"])
        try:
            ins = _decode_stream(data, code_start, strop, path)
        except MesParseError as exc:
            scores.append((var["id"], {"rejected": type(exc).__name__}))
            continue
        sc = _score_variant(ins, labels_abs, len(data))
        scores.append((var["id"], sc))
        if sc["label_misses"] == 0:
            viable.append((sc, var, ins))
    if not viable:
        raise LabelMisaligned(
            "%s: no dialect variant decodes this file cleanly; scores=%s"
            % (path, scores))

    # Rank by distinct opcode count. This is the primary discriminator and it
    # separates the candidates by a wide margin (measured: 33 vs 207 on
    # S04-30.MES, 51 vs 249 corpus-wide), because a desynchronised decode walks
    # through text and invents opcodes that are not in the real instruction set.
    # The lead-byte ratio is kept as a sanity bound on the winner only: using it
    # to filter candidates rejected a valid file at 0.1212 against a 0.12 cut,
    # which is exactly the kind of knife-edge a secondary signal should not
    # decide.
    # Tie-break: prefer the variant that yields more decodable message text.
    # Files with no dialogue at all (LIBLARY.LIB, MAIN.MES and friends) score
    # identically under every variant, because the difference only shows up on
    # dialogue. Ranking by opcode count alone then picks arbitrarily and can
    # read a real 1-byte opcode as a string, which surfaces as a nonsense
    # 2-character "message". Counting plausible message bytes breaks the tie
    # toward the reading that does not invent text.
    def rank(item):
        sc, var, ins = item
        return (sc["distinct_opcodes"], -_message_weight(var, ins))

    viable.sort(key=rank)
    best_sc, best_var, best_ins = viable[0]
    if best_sc["lead_byte_ratio"] > D.MAX_LEAD_BYTE_RATIO_ABSOLUTE:
        raise LabelMisaligned(
            "%s: best variant %s still looks desynchronised "
            "(%.1f%% of opcodes are cp932 lead bytes); scores=%s"
            % (path, best_var["id"], 100 * best_sc["lead_byte_ratio"], scores))
    return best_var, best_ins, tuple(scores)


def parse(path: Path, data: bytes | None = None) -> Document:
    """Source binary -> Document. Deterministic; the single source of truth."""
    if data is None:
        data = path.read_bytes()
    n_labels, n_entries, labels, entries, code_start = parse_header(data, path)
    labels_abs = tuple(code_start + t for t in labels)
    variant, ins, scores = select_variant(data, code_start, labels_abs, path)
    doc = Document(path=path, data=data, n_labels=n_labels, n_entries=n_entries,
                   labels=labels, entries=entries, code_start=code_start,
                   src_sha256=hashlib.sha256(data).hexdigest(),
                   variant=variant, variant_scores=scores)
    doc.instructions = ins

    # Label alignment is the independent constraint that proves the operand
    # width table. A miss means the decode drifted; refuse rather than guess.
    starts = {x.offset for x in ins}
    missed = [t for t in doc.label_targets if t not in starts and t != len(data)]
    if missed:
        raise LabelMisaligned(
            "%s: %d label targets do not land on an instruction boundary "
            "(first 0x%X)" % (path, len(missed), min(missed)))
    return doc


def verify_coverage(doc: Document) -> dict:
    """Byte coverage over [0, len). Raises on gap or overlap."""
    data = doc.data
    intervals = [{
        "id": "R_HEADER", "start": 0, "end": doc.code_start,
        "status": "decoded", "kind": "header",
        "raw_sha256": hashlib.sha256(data[:doc.code_start]).hexdigest(),
        "decode_tier": "T3",
    }]
    cur = doc.code_start
    for x in doc.instructions:
        if x.offset != cur:
            if x.offset > cur:
                raise AddressSpaceGapError(
                    "%s: gap at 0x%X..0x%X" % (doc.path, cur, x.offset))
            raise AddressSpaceCollisionError(
                "%s: overlap at 0x%X" % (doc.path, x.offset))
        cur = x.offset + x.size
    if cur != len(data):
        raise AddressSpaceGapError(
            "%s: instruction stream ends at 0x%X, file is 0x%X"
            % (doc.path, cur, len(data)))
    intervals.append({
        "id": "R_CODE", "start": doc.code_start, "end": len(data),
        "status": "decoded", "kind": "instruction_stream",
        "raw_sha256": hashlib.sha256(data[doc.code_start:]).hexdigest(),
        "decode_tier": "T3",
        "instruction_count": len(doc.instructions),
    })
    return {
        "schema_version": "1.1.0",
        "layer_id": "L000",
        "source": str(doc.path),
        "source_size": len(data),
        "source_sha256": doc.src_sha256,
        "intervals": intervals,
        "gaps": [],
        "overlaps": [],
        "status_counts": {"decoded": len(data)},
        "byte_coverage": 1.0,
        "structural_coverage": 1.0,
        "tier_coverage": {"T0": 0, "T1": 0, "T2": 0, "T3": len(data), "T4": 0},
        "min_tier": "T3",
        "declared_capabilities": ["roundtrip", "in_place", "pointer-rewrite"],
        "tier_blocked": [],
        "instruction_coverage": 1.0,
        "toolchain": {"tool_version": TOOL_VERSION, "ir_version": IR_VERSION,
                      "dialect_id": D.DIALECT_ID},
    }


def serialize(doc: Document) -> bytes:
    """IR -> bytes. Zero-edit output must equal the source byte for byte."""
    out = bytearray(doc.data[:doc.code_start])
    for x in doc.instructions:
        out.append(x.opcode)
        if x.opcode in doc.string_opcodes:
            out += x.operand
            out += D.STRING_TERMINATOR
        elif x.size == 5:
            # Size, not opcode identity: 0x1B is 5 bytes only where its operand
            # resolved (see _decode_stream), so keying off the opcode alone
            # would re-add operand bytes that were never there.
            out += _U32_BE.pack(x.operand & 0xFFFFFFFF)
    return bytes(out)


# ---------------------------------------------------------------------------
# Anchor resolution
# ---------------------------------------------------------------------------
_GROUP_OF_ID = {}
for _g in D.CALLEE_GROUPS:
    for _i in _g["ids"]:
        _GROUP_OF_ID[_i] = _g
_ROLE_ASSET = {"asset"}

_SYSCALL_WINDOW = next(w for w in D.WINDOWS if w["name"] == "syscall_lookahead")
_NAME_WINDOW = next(w for w in D.WINDOWS if w["name"] == "name_binding_lookahead")


def resolve_syscalls(doc: Document) -> tuple:
    """For each string instruction, find the syscall id that consumes it.

    Returns (syscall_of_index, window_hits). Only walks forward within the
    declared window; on exceeding it the candidate is dropped, never silently
    extended.
    """
    ins = doc.instructions
    n = len(ins)
    limit = _SYSCALL_WINDOW["value"]
    syscall_of = {}
    hits = 0
    for k in range(n):
        if ins[k].opcode not in doc.string_opcodes:
            continue
        sid = None
        stop = min(k + 1 + limit, n)
        for j in range(k + 1, stop):
            if ins[j].opcode == D.SYSCALL_OPCODE:
                prev = ins[j - 1]
                if prev.opcode == D.OP_PUSH_IMM:
                    sid = prev.operand
                break
        else:
            if stop == k + 1 + limit:
                hits += 1
        syscall_of[k] = sid
    return syscall_of, hits


def _preceding_kind(doc, ins, k: int):
    """Name of the structure that directly precedes instruction k, or None.

    Only the choice registration is recognised today; it is what turns an option
    string into tag=choice instead of stray dialogue.
    """
    if k == 0:
        return None
    prev = ins[k - 1]
    if prev.opcode == D.OP_CHOICE and prev.operand is not None:
        return "choice"
    return None


_REGEX_CACHE = {}


def _regex(pattern: str):
    """Compile once per pattern. Patterns come from the dialect, never inline."""
    rx = _REGEX_CACHE.get(pattern)
    if rx is None:
        rx = _REGEX_CACHE[pattern] = __import__("re").compile(pattern)
    return rx


def _contains_script(text: str, script: str) -> bool:
    try:
        ranges = D.SCRIPT_RANGES[script]
    except KeyError:
        raise MesParseError("unknown script %r" % script) from None
    for ch in text:
        cp = ord(ch)
        for lo, hi in ranges:
            if lo <= cp <= hi:
                return True
    return False


def _match_predicates(preds, text: str) -> bool:
    for p in preds:
        kind = p["kind"]
        val = p["value"]
        if kind == "starts_with":
            if not text.startswith(val):
                return False
        elif kind == "ends_with":
            if not text.endswith(val):
                return False
        elif kind == "max_length":
            if len(text) > val:
                return False
        elif kind == "min_length":
            if len(text) < val:
                return False
        elif kind == "matches_regex":
            if not _regex(val).match(text):
                return False
        elif kind == "contains_script":
            if not _contains_script(text, val):
                return False
        else:
            raise MesParseError("unknown predicate kind %r" % kind)
    return True


def classify(doc, opcode: int, syscall_id, text: str, preceding=None) -> tuple:
    """-> (tag, tag_source, subtype, matched_rule_id). No fallback rule.

    Rules declare which *role* of string they apply to (message vs identifier);
    the concrete opcode for that role comes from this file's variant, so the
    same rule set serves every title.
    """
    group = _GROUP_OF_ID.get(syscall_id) if syscall_id is not None else None
    role = "message" if opcode == doc.msg_op else "identifier"
    for rule in D.TEXT_RULES:
        if rule["requires_role"] != role:
            continue
        need_prev = rule.get("requires_preceding_opcode")
        if need_prev is not None and need_prev != preceding:
            continue
        need = rule.get("requires_callee_group")
        if need is not None:
            if group is None:
                continue
            if need == "asset":
                if group["role"] not in _ROLE_ASSET:
                    continue
            elif group["id"] != need:
                continue
        if not _match_predicates(rule.get("predicates", ()), text):
            continue
        return rule["tag"], rule["tag_source"], rule["subtype"], rule["id"]
    return "misc", "unresolved", "", None


def extract_texts(doc: Document) -> dict:
    """Build TextEntry list on the in-memory IR. Never reads asm.txt."""
    enc = D.ENCODINGS["source_encoding"]
    syscall_of, window_hits = resolve_syscalls(doc)
    ins = doc.instructions
    n = len(ins)

    display_cache = {}
    for k in range(n):
        x = ins[k]
        if x.opcode in doc.string_opcodes:
            display_cache[k] = to_display(plain_bytes(doc, x.opcode, x.operand), enc)

    # Speaker binding: a bracketed name pushed for the name syscall binds to
    # the next message string within the declared window. method=slot-ordinal
    # equivalent: structural bracket + syscall group, so confidence=derived.
    speaker_of = {}
    name_limit = _NAME_WINDOW["value"]
    for k in range(n):
        if ins[k].opcode != doc.id_op:
            continue
        text = display_cache.get(k, "")
        tag, _, _, _ = classify(doc, doc.id_op, syscall_of.get(k), text,
                                _preceding_kind(doc, ins, k))
        if tag != "name":
            continue
        stop = min(k + 1 + name_limit, n)
        for j in range(k + 1, stop):
            if ins[j].opcode == doc.msg_op:
                speaker_of[j] = text.strip("【】")
                break

    entries = []
    rule_hits = {}
    group_sizes = {}
    idx = 0
    k = 0
    while k < n:
        x = ins[k]
        if x.opcode not in doc.string_opcodes or not x.operand:
            k += 1
            continue

        # Collect a run of message strings joined by the line-break sequence.
        parts = [k]
        nxt = k + 1
        if x.opcode == doc.msg_op:
            while len(parts) < D.MESSAGE_JOIN_MAX_PARTS:
                span = len(D.MESSAGE_JOIN_OPCODES)
                after = nxt + span
                if after >= n:
                    break
                if tuple(ins[j].opcode for j in range(nxt, after)) != \
                        D.MESSAGE_JOIN_OPCODES:
                    break
                if ins[after].opcode != doc.msg_op or not ins[after].operand:
                    break
                parts.append(after)
                nxt = after + 1

        group_sizes[len(parts)] = group_sizes.get(len(parts), 0) + 1
        display = D.MESSAGE_JOIN_ESCAPE.join(display_cache[p] for p in parts)
        sid = next((syscall_of.get(p) for p in parts
                    if syscall_of.get(p) is not None), None)
        tag, tsrc, subtype, rule_id = classify(
            doc, x.opcode, sid, display, _preceding_kind(doc, ins, k))
        policy = D.TRANSLATE_POLICY.get(tag, "review-required")
        if tsrc == "unresolved":
            policy = "review-required"
        rule_hits[rule_id or "_unmatched"] = rule_hits.get(rule_id or "_unmatched", 0) + 1
        idx += 1
        entries.append(TextEntry(
            idx=idx, offset=x.offset, opcode=x.opcode, raw=x.operand,
            source=display, tag=tag, tag_source=tsrc, tag_subtype=subtype,
            translate_policy=policy, syscall_id=sid,
            speaker=speaker_of.get(k), matched_rule_id=rule_id,
            part_offsets=tuple(ins[p].offset for p in parts),
            part_raw=tuple(ins[p].operand for p in parts)))
        k = nxt
    doc.texts = entries
    return {"window_hits": {_SYSCALL_WINDOW["name"]: window_hits},
            "rule_hits": rule_hits,
            "group_sizes": {str(a): b for a, b in sorted(group_sizes.items())}}


# ---------------------------------------------------------------------------
# Rendering: asm.txt
# ---------------------------------------------------------------------------
_MNEMONIC = {}
for _op, _d in D.OPERAND_U32.items():
    _MNEMONIC[_op] = _d["mnemonic"]
# String mnemonics are per role; the opcode carrying each role is per variant.
_ROLE_MNEMONIC = {"identifier": "PUSHS", "message": "PUSHM"}


def _mnemonic(doc, op: int) -> str:
    if op == doc.msg_op:
        return _ROLE_MNEMONIC["message"]
    if op == doc.id_op:
        return _ROLE_MNEMONIC["identifier"]
    return _MNEMONIC.get(op)

_SYSCALL_NAME = {}
for _g in D.CALLEE_GROUPS:
    for _i in _g["ids"]:
        _SYSCALL_NAME[_i] = _g["id"]


def render_asm(doc: Document) -> str:
    """IR -> asm text. Must be byte-identical for identical IR."""
    enc = D.ENCODINGS["source_encoding"]
    labels = {}
    for t in sorted(doc.label_targets):
        labels[t] = "loc_%08X" % t

    out = [
        "; SILKY'S ENGINE .MES disassembly",
        '.encoding "%s"' % enc,
        '.dialect  "%s" version "%s"' % (D.DIALECT_ID, D.SCHEMA_VERSION),
        '.tier     "T3"',
        ".source   \"%s\" sha256 %s" % (doc.path.name, doc.src_sha256),
        "",
        "; header: %d labels, %d entries, code starts at 0x%X"
        % (doc.n_labels, doc.n_entries, doc.code_start),
    ]
    for i, t in enumerate(doc.labels):
        out.append(".label   %d -> loc_%08X" % (i, doc.code_start + t))
    for i, t in enumerate(doc.entries):
        out.append(".entry   %d -> loc_%08X" % (i, doc.code_start + t))

    syscall_of, _ = resolve_syscalls(doc)
    ins = doc.instructions
    for k, x in enumerate(ins):
        if x.offset in labels:
            out.append("")
            out.append("%s:" % labels[x.offset])
        op = x.opcode
        mn = _mnemonic(doc, op)
        if op in doc.string_opcodes:
            display = to_display(plain_bytes(doc, op, x.operand), enc)
            sid = syscall_of.get(k)
            note = ""
            if sid is not None:
                note = "  ; syscall 0x%02X %s" % (sid, _SYSCALL_NAME.get(sid, "?"))
            out.append('%08X  %-6s sid=%d "%s"%s'
                       % (x.offset, mn, x.offset, display.replace('"', '\\"'), note))
        elif op in D.OPERAND_U32:
            val = x.operand
            if op in D.OP_JUMP:
                tgt = doc.code_start + val
                name = labels.get(tgt) or ("loc_%08X" % tgt)
                out.append("%08X  %-6s %s" % (x.offset, mn, name))
            else:
                out.append("%08X  %-6s 0x%08X" % (x.offset, mn, val))
        else:
            if op == D.SYSCALL_OPCODE:
                prev = ins[k - 1] if k else None
                sid = (prev.operand if prev is not None
                       and prev.opcode == D.OP_PUSH_IMM else None)
                if sid is not None:
                    out.append("%08X  %-6s ; id=0x%02X %s"
                               % (x.offset, "SYSCALL", sid,
                                  _SYSCALL_NAME.get(sid, "?")))
                else:
                    out.append("%08X  %-6s" % (x.offset, "SYSCALL"))
            else:
                out.append("%08X  .op    0x%02X" % (x.offset, op))
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Rendering: dual-line text
# ---------------------------------------------------------------------------
def render_texts(doc: Document) -> str:
    """IR -> dual-line translation file. Target line is pre-filled with source."""
    enc = D.ENCODINGS
    tags = sorted({e.tag for e in doc.texts})
    out = [
        "# TEXT/2 ir=%s tool=%s src_sha256=%s" % (IR_VERSION, TOOL_VERSION, doc.src_sha256),
        "# encoding source=%s target=%s file=%s"
        % (enc["source_encoding"], enc["target_encoding"], "utf-8"),
        "# scope kind=all range=ALL part=1/1",
        "# tags %s" % " ".join(tags),
        "#",
    ]
    for e in doc.texts:
        meta = "# idx=%08d off=0x%08X tag=%s" % (e.idx, e.offset, e.tag)
        if e.speaker:
            meta += " speaker=%s" % e.speaker
        if len(e.part_offsets) > 1:
            # Tells the translator how many on-screen lines this becomes, and
            # that the \n count is fixed by the engine.
            meta += " lines=%d" % len(e.part_offsets)
        out.append(meta)
        out.append("○%08d○%s○%s" % (e.idx, e.tag, e.source))
        out.append("●%08d●%s●%s" % (e.idx, e.tag, e.source))
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Discovery and output layout
# ---------------------------------------------------------------------------
SCRIPT_SUFFIXES = (".mes", ".lib")
_RESERVED_DIRS = {"texts", "asm", "rebuilt", "reports", "ir", "tmp", "_work"}


def find_sources(inputs) -> tuple:
    """-> (sorted source paths, common parent directory)."""
    paths = []
    roots = []
    for raw in inputs:
        p = Path(raw).resolve()
        if p.is_dir():
            roots.append(p)
            for f in sorted(p.rglob("*")):
                if f.is_file() and f.suffix.lower() in SCRIPT_SUFFIXES:
                    if _RESERVED_DIRS & {q.name for q in f.parents}:
                        continue
                    paths.append(f)
        elif p.is_file():
            roots.append(p.parent)
            paths.append(p)
        else:
            raise MesParseError("input not found: %s" % p)
    if not paths:
        raise MesParseError("no .MES/.LIB files found in: %s" % ", ".join(map(str, inputs)))
    base = roots[0] if len(set(roots)) == 1 else Path(*Path(
        __import__("os").path.commonpath([str(r) for r in roots])).parts)
    return sorted(set(paths)), base


def _rel(path: Path, base: Path) -> Path:
    try:
        return path.relative_to(base)
    except ValueError:
        return Path(path.name)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / (path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        __import__("os").fsync(fh.fileno())
    tmp.replace(path)


# ---------------------------------------------------------------------------
# Per-file worker
# ---------------------------------------------------------------------------
def process_one(args) -> dict:
    src, base, outdir, want_texts, want_asm, want_ir = args
    src = Path(src)
    base = Path(base)
    outdir = Path(outdir)
    rel = _rel(src, base)
    res = {"src": str(src), "rel": str(rel), "ok": False, "error": None}
    try:
        doc = parse(src)
        cert = verify_coverage(doc)

        # Zero-edit roundtrip self-check. Runs regardless of which outputs were
        # requested: skipping an optional artifact must not skip a core gate.
        rebuilt = serialize(doc)
        identical = rebuilt == doc.data
        cert["roundtrip"] = {
            "zero_edit_identical": identical,
            "source_sha256": doc.src_sha256,
            "rebuilt_sha256": hashlib.sha256(rebuilt).hexdigest(),
        }
        if not identical:
            res["error"] = "roundtrip mismatch: rebuild is not byte-identical"
            res["certificate"] = cert
            return res

        stats = extract_texts(doc)
        counts = {}
        tsrc = {}
        for e in doc.texts:
            counts[e.tag] = counts.get(e.tag, 0) + 1
            tsrc[e.tag_source] = tsrc.get(e.tag_source, 0) + 1
        cert["tag_source_counts"] = tsrc

        if want_texts:
            body = render_texts(doc)
            _atomic_write(outdir / "texts" / (str(rel) + ".txt"),
                          body.encode("utf-8-sig"))
        if want_asm:
            body = render_asm(doc)
            _atomic_write(outdir / "asm" / (str(rel) + ".asm.txt"),
                          body.encode(D.ENCODINGS["asm_encoding"]))
        if want_ir:
            recs = [{
                "idx": e.idx, "off": e.offset, "opcode": e.opcode,
                "tag": e.tag, "tag_source": e.tag_source,
                "subtype": e.tag_subtype, "policy": e.translate_policy,
                "syscall_id": e.syscall_id, "speaker": e.speaker,
                "rule": e.matched_rule_id, "source": e.source,
                "raw_sha256": hashlib.sha256(e.raw).hexdigest(),
            } for e in doc.texts]
            blob = "\n".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False)
                             for r in recs)
            _atomic_write(outdir / "ir" / (str(rel) + ".text_entries.jsonl"),
                          blob.encode("utf-8"))

        res.update(ok=True, certificate=cert, tag_counts=counts,
                   entry_count=len(doc.texts), instruction_count=len(doc.instructions),
                   size=len(doc.data), **stats)
    except MesParseError as exc:
        res["error"] = str(exc)
    except Exception as exc:  # unexpected: report honestly, do not swallow
        res["error"] = "%s: %s" % (type(exc).__name__, exc)
    return res


def run_extract(inputs, outdir=None, want_texts=True, want_asm=False,
                want_ir=False, jobs=None, progress=None) -> dict:
    """Main entry point for both CLI and GUI. Returns a report dict."""
    if not want_texts and not want_asm:
        raise MesParseError("nothing to do: enable dual-line text and/or ASM output")
    sources, base = find_sources(inputs)
    if outdir is None:
        outdir = base.parent / (base.name + "_text")
    outdir = Path(outdir)

    tasks = [(str(s), str(base), str(outdir), want_texts, want_asm, want_ir)
             for s in sources]
    results = []
    use_pool = (jobs is None or jobs > 1) and len(tasks) >= 8
    if use_pool:
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            for i, r in enumerate(pool.map(process_one, tasks, chunksize=4), 1):
                results.append(r)
                if progress:
                    progress(i, len(tasks), r)
    else:
        for i, t in enumerate(tasks, 1):
            r = process_one(t)
            results.append(r)
            if progress:
                progress(i, len(tasks), r)

    results.sort(key=lambda r: r["rel"])
    ok = [r for r in results if r["ok"]]
    failed = [r for r in results if not r["ok"]]
    tag_totals = {}
    tsrc_totals = {}
    rule_totals = {}
    window_totals = {}
    for r in ok:
        for k, v in r["tag_counts"].items():
            tag_totals[k] = tag_totals.get(k, 0) + v
        for k, v in r["certificate"]["tag_source_counts"].items():
            tsrc_totals[k] = tsrc_totals.get(k, 0) + v
        for k, v in r["rule_hits"].items():
            rule_totals[k] = rule_totals.get(k, 0) + v
        for k, v in r["window_hits"].items():
            window_totals[k] = window_totals.get(k, 0) + v

    report = {
        "tool_version": TOOL_VERSION,
        "dialect_id": D.DIALECT_ID,
        "declared": dict(D.DECLARED),
        "input_base": str(base),
        "output_dir": str(outdir),
        "files_total": len(results),
        "files_ok": len(ok),
        "files_failed": len(failed),
        "failures": [{"rel": r["rel"], "error": r["error"]} for r in failed],
        "entries_total": sum(r["entry_count"] for r in ok),
        "bytes_total": sum(r["size"] for r in ok),
        "instructions_total": sum(r["instruction_count"] for r in ok),
        "tag_counts": tag_totals,
        "tag_source_counts": tsrc_totals,
        "rule_hits": rule_totals,
        "window_hits": window_totals,
        "roundtrip_all_identical": all(
            r["certificate"]["roundtrip"]["zero_edit_identical"] for r in ok),
        "min_byte_coverage": min((r["certificate"]["byte_coverage"] for r in ok),
                                 default=0.0),
        "outputs": {"texts": want_texts, "asm": want_asm, "ir": want_ir},
    }

    work = outdir / "_work" / "reports"
    _atomic_write(work / "extract_report.json",
                  json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8"))
    certs = {r["rel"]: r["certificate"] for r in ok}
    _atomic_write(work / "coverage_certificate.json",
                  json.dumps(certs, indent=2, ensure_ascii=False).encode("utf-8"))
    _atomic_write(work / "rule_hits.json",
                  json.dumps(rule_totals, indent=2, ensure_ascii=False).encode("utf-8"))
    _atomic_write(work / "window_hits.json",
                  json.dumps(window_totals, indent=2, ensure_ascii=False).encode("utf-8"))
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Extract text / disassemble SILKY'S ENGINE .MES scripts")
    ap.add_argument("inputs", nargs="+", help="source file(s) or folder(s)")
    ap.add_argument("-o", "--output", default=None, help="output directory")
    ap.add_argument("--no-texts", action="store_true", help="skip dual-line text")
    ap.add_argument("--asm", action="store_true", help="also render ASM listing")
    ap.add_argument("--with-ir", action="store_true", help="also persist IR")
    ap.add_argument("-j", "--jobs", type=int, default=None)
    args = ap.parse_args(argv)

    def show(i, n, r):
        state = "ok" if r["ok"] else "FAIL"
        line = "[%d/%d] %-28s %s" % (i, n, r["rel"], state)
        if not r["ok"]:
            line += "  %s" % r["error"]
        print(line, file=sys.stderr)

    try:
        rep = run_extract(args.inputs, args.output,
                          want_texts=not args.no_texts, want_asm=args.asm,
                          want_ir=args.with_ir, jobs=args.jobs, progress=show)
    except MesParseError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    print()
    print("files          %d ok, %d failed" % (rep["files_ok"], rep["files_failed"]))
    print("text entries   %d" % rep["entries_total"])
    print("byte coverage  %.4f" % rep["min_byte_coverage"])
    print("roundtrip      %s" % ("byte-identical"
                                 if rep["roundtrip_all_identical"] else "MISMATCH"))
    print("tags           %s" % ", ".join(
        "%s=%d" % kv for kv in sorted(rep["tag_counts"].items())))
    print("tag sources    %s" % ", ".join(
        "%s=%d" % kv for kv in sorted(rep["tag_source_counts"].items())))
    print("output         %s" % rep["output_dir"])
    for f in rep["failures"]:
        print("FAILED %s: %s" % (f["rel"], f["error"]), file=sys.stderr)
    return 0 if rep["files_failed"] == 0 and rep["roundtrip_all_identical"] else 1


if __name__ == "__main__":
    sys.exit(main())
