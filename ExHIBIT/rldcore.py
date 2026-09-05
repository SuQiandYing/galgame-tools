"""Engine-agnostic core: cipher, key recovery, IR parse, coverage.

Reads every engine-specific constant from `opcodelist.DIALECT`. Contains no
hex magic numbers, opcode tables or inline regexes of its own -- those belong
to the dialect (checkable mechanically).

The in-memory IR is the single parsing truth. It is derived from the source
bytes on demand and is not persisted by default: parsing is deterministic, so
a cached copy would only add a staleness failure mode.
"""
from __future__ import annotations

import array
import collections
import hashlib
import json
import math
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from opcodelist import DIALECT

_C = DIALECT["container"]
_X = DIALECT["cipher"]
_O = DIALECT["op"]
_KR = DIALECT["key_recovery"]

HDR = _X["body_offset"]
WORD = _X["word_size"]
PERIOD = _X["key_period"]
CAP = _X["word_cap"]
ZERO_LO, ZERO_HI = _KR["zero_region"]
ANCHOR_WORDS = _KR["anchor_words"]
REQUIRED_DELTA = _KR["require_op_delta"]

_U32 = struct.Struct("<I")
_U32X2 = struct.Struct("<II")
_HOST_LE = struct.pack("=I", 1) == struct.pack("<I", 1)


class RldError(Exception):
    """Base for all tool errors; carries a machine-readable code."""
    code = "RLD_ERROR"


class KeyRecoveryError(RldError):
    code = "KEY_RECOVERY_FAILED"


class ParseError(RldError):
    code = "PARSE_FAILED"


class AddressSpaceError(RldError):
    code = "ADDRESS_SPACE"


# ---------------------------------------------------------------------------
# cipher
# ---------------------------------------------------------------------------

def encrypted_word_count(size: int) -> int:
    """How many u32 words the engine enciphers for a file of `size` bytes.

    Cap only. The original tool also masked with 0xFFFF, which silently left
    ~97% of any file above 256 KB in ciphertext -- in this game that is exactly
    defChara.rld, the character-name table.
    """
    n = (size - HDR) >> 2
    if n < 0:
        return 0
    if _X["mask_word_count"]:
        n &= 0xFFFF
    return min(n, CAP)


def _words(data: bytes, count: int) -> array.array:
    """Little-endian u32 view of `count` words starting at HDR."""
    w = array.array("I")
    w.frombytes(bytes(data[HDR:HDR + count * WORD]))
    if not _HOST_LE:
        w.byteswap()
    return w


def _to_bytes(w: array.array) -> bytes:
    if not _HOST_LE:
        w = w[:]
        w.byteswap()
    return w.tobytes()


def apply_cipher(data: bytes, key: list) -> bytes:
    """XOR the enciphered span with the keystream. Symmetric: also encrypts."""
    n = encrypted_word_count(len(data))
    if n == 0:
        return bytes(data)
    w = _words(data, n)
    for i in range(n):
        k = key[i & (PERIOD - 1)]
        if k is None:
            raise KeyRecoveryError(f"keystream slot {i & (PERIOD - 1)} unknown")
        w[i] ^= k
    return bytes(data[:HDR]) + _to_bytes(w) + bytes(data[HDR + n * WORD:])


decrypt = apply_cipher
encrypt = apply_cipher


# ---------------------------------------------------------------------------
# op stream walk (shared by parser and key validation)
# ---------------------------------------------------------------------------

def _split_control(op: int):
    code = (op >> _O["code_shift"]) & _O["code_mask"]
    ic = (op >> _O["init_count_shift"]) & _O["init_count_mask"]
    sc = (op >> _O["str_count_shift"]) & _O["str_count_mask"]
    flags = (op >> _O["flags_shift"]) & _O["flags_mask"]
    return code, ic, sc, flags


def walk(plain: bytes):
    """Walk the op stream to EOF.

    Returns (ops, declared_count, end_offset, reason). `op_count` in the header
    excludes the trailing terminator op, so a correct decode yields
    ops == declared_count + 1 and end_offset == len(plain).
    """
    if len(plain) < HDR:
        return 0, 0, 0, "truncated-header"
    off, declared = _U32X2.unpack_from(plain, _C["op_offset_field"])
    cur = off
    n = 0
    size = len(plain)
    if off < HDR or off > size:
        return 0, declared, cur, "bad-op-offset"
    term = _O["string_terminator"]
    while cur < size:
        if cur + _O["control_width"] > size:
            return n, declared, cur, "short-control"
        op = _U32.unpack_from(plain, cur)[0]
        cur += _O["control_width"]
        code, ic, sc, flags = _split_control(op)
        cur += ic * _O["init_width"]
        if cur > size:
            return n, declared, cur, "short-inits"
        for _ in range(sc):
            e = plain.find(term, cur)
            if e < 0:
                return n, declared, cur, "unterminated-string"
            cur = e + len(term)
        if cur > size:
            return n, declared, cur, "overrun"
        n += 1
    return n, declared, cur, "ok"


def decodes_cleanly(data: bytes, key: list) -> bool:
    """Strict gate for a candidate key.

    Landing on EOF is not sufficient: measured on real corpora, wrong keys
    produce streams that reach exact EOF with op tallies off by -56, -868 and
    similar. Requiring ops == op_count + 1 is what distinguishes a real decode
    from a coincidence.
    """
    try:
        plain = apply_cipher(data, key)
    except KeyRecoveryError:
        return False
    n, declared, end, why = walk(plain)
    return why == "ok" and end == len(plain) and n - declared == REQUIRED_DELTA


def parse_progress(data: bytes, key: list) -> int:
    """Bytes walked before breaking, plus a bonus for a full clean decode.

    A graded oracle: it keeps improving as individual keystream slots get
    fixed, so repair can hill-climb instead of waiting for whole files to flip.
    """
    try:
        plain = apply_cipher(data, key)
    except KeyRecoveryError:
        return -1
    n, declared, end, why = walk(plain)
    clean = why == "ok" and end == len(plain) and n - declared == REQUIRED_DELTA
    return end + (len(plain) if clean else 0)


# ---------------------------------------------------------------------------
# key recovery
# ---------------------------------------------------------------------------

def anchor_of(data: bytes) -> tuple:
    """Ciphertext of the zero region: equals the keystream when it is zero."""
    w = array.array("I")
    w.frombytes(bytes(data[ZERO_LO:ZERO_HI]))
    if not _HOST_LE:
        w.byteswap()
    return tuple(w)


def anchor_is_valid(blobs) -> bool:
    """Only trust the zero region if every file agrees on it.

    When the plaintext there is all zero, the stored bytes ARE the keystream,
    so files sharing a key look identical. Disagreement means the region holds
    real data (DemonBusters keeps an import list there) and using it as known
    plaintext would inject a wrong key and split one key into fake groups.
    """
    it = iter(blobs)
    try:
        first = anchor_of(next(it))
    except StopIteration:
        return False
    return all(anchor_of(d) == first for d in it)


def _slot_samples(blobs):
    samples = [[] for _ in range(PERIOD)]
    for d in blobs:
        n = encrypted_word_count(len(d))
        w = _words(d, n)
        for i, v in enumerate(w):
            samples[i & (PERIOD - 1)].append(v)
    return samples


def word_vote(blobs, topn=None):
    """Ranked whole-word candidates per keystream slot."""
    topn = topn or _KR["vote_topn"]
    slots = [collections.Counter() for _ in range(PERIOD)]
    for d in blobs:
        n = encrypted_word_count(len(d))
        w = _words(d, n)
        for i, v in enumerate(w):
            slots[i & (PERIOD - 1)][v] += 1
    return [[v for v, _ in s.most_common(topn)] for s in slots]


def _byte_logprob(counter, floor=0.3):
    total = sum(counter.values())
    if total < 2048:
        return None
    denom = total + 77
    return [math.log((counter.get(b, 0) + floor) / denom) for b in range(256)]


def _model_from_key(blobs, key):
    freq = collections.Counter()
    for d in blobs:
        n = encrypted_word_count(len(d))
        w = _words(d, n)
        for i in range(n):
            k = key[i & (PERIOD - 1)]
            if k is None:
                continue
            v = w[i] ^ k
            freq[v & 0xFF] += 1
            freq[(v >> 8) & 0xFF] += 1
            freq[(v >> 16) & 0xFF] += 1
            freq[(v >> 24) & 0xFF] += 1
    return _byte_logprob(freq)


def recover_per_lane(blobs, use_anchor=None, rounds=None):
    """Per-byte-lane likelihood with the byte model refit each round.

    Beats whole-word voting because a u32 never has to be guessed atomically:
    each slot is 4 independent 256-way choices. Seeded from the plaintext tail
    past the cipher cap, then refit on whatever has been decrypted so far.
    """
    rounds = rounds or _KR["lane_rounds"]
    if use_anchor is None:
        use_anchor = anchor_is_valid(blobs)
    a = anchor_of(blobs[0])
    key = [a[k] if (use_anchor and k < ANCHOR_WORDS) else None
           for k in range(PERIOD)]
    samples = _slot_samples(blobs)

    seed = collections.Counter()
    for d in blobs:
        n = encrypted_word_count(len(d))
        seed.update(d[HDR + n * WORD:])
    lp = _byte_logprob(seed) or _model_from_key(blobs, key)
    if lp is None:
        return key

    previous = None
    for _ in range(rounds):
        for k in range(PERIOD):
            if use_anchor and k < ANCHOR_WORDS:
                continue
            sample = samples[k]
            if not sample:
                continue
            value = 0
            for lane in range(4):
                shift = 8 * lane
                counts = collections.Counter((v >> shift) & 0xFF for v in sample)
                best, best_score = 0, -math.inf
                for guess in range(256):
                    score = 0.0
                    for byte, mult in counts.items():
                        score += lp[byte ^ guess] * mult
                    if score > best_score:
                        best_score, best = score, guess
                value |= best << shift
            key[k] = value
        refit = _model_from_key(blobs, key)
        if refit is not None:
            lp = refit
        snapshot = tuple(key)
        if snapshot == previous:
            break
        previous = snapshot
    return key


def recover_key(blobs, verbose=False):
    """Recover one keystream from files known to share it.

    Runs two independent estimators and lets the structural parse arbitrate.
    This is not belt-and-braces: their failure modes are complementary --
    measured, per-lane scored 38/38 where word-vote got 5/38 on one title and
    the ranking inverted on another. Either estimator alone fails somewhere.
    """
    blobs = list(blobs)
    if not blobs:
        raise KeyRecoveryError("no files supplied")
    total = len(blobs)
    use_anchor = anchor_is_valid(blobs)
    candidates = word_vote(blobs)
    anchor = anchor_of(blobs[0])

    key_lane = recover_per_lane(blobs, use_anchor=use_anchor)
    if use_anchor:
        key_word = [anchor[k] if k < ANCHOR_WORDS
                    else (candidates[k][0] if candidates[k] else None)
                    for k in range(PERIOD)]
    else:
        key_word = [candidates[k][0] if candidates[k] else None
                    for k in range(PERIOD)]

    scored = []
    for tag, key in (("per-lane", key_lane), ("word-vote", key_word)):
        ok = sum(1 for d in blobs if decodes_cleanly(d, key))
        scored.append((ok, tag, list(key)))
    scored.sort(key=lambda row: -row[0])
    best_ok, method, key = scored[0]
    if verbose:
        detail = ", ".join(f"{t}={o}/{total}" for o, t, _ in scored)
        print(f"      estimators: {detail}")
    if best_ok == total:
        return key, {"method": method, "repaired": 0, "decoded": best_ok,
                     "total": total, "used_zero_anchor": use_anchor}

    # Structural repair. Scored on a small probe subset to keep the oracle
    # cheap; the full set still gates the result.
    probe = sorted(blobs, key=len)[:_KR["probe_files"]]

    def progress(k):
        return sum(parse_progress(d, k) for d in probe)

    current = progress(key)
    low = ANCHOR_WORDS if use_anchor else 0
    disagree = [k for k in range(low, PERIOD) if key_lane[k] != key_word[k]]
    agree = [k for k in range(low, PERIOD) if key_lane[k] == key_word[k]]
    repaired = 0
    for sweep in range(_KR["repair_sweeps"]):
        improved = False
        for k in disagree + agree:
            pool = []
            for v in (key_lane[k], key_word[k], *candidates[k]):
                if v is not None and v not in pool:
                    pool.append(v)
            if len(pool) < 2:
                continue
            keep = key[k]
            for v in pool:
                if v == keep:
                    continue
                key[k] = v
                score = progress(key)
                if score > current:
                    current, keep, improved = score, v, True
                    repaired += 1
            key[k] = keep
        best_ok = sum(1 for d in blobs if decodes_cleanly(d, key))
        if verbose:
            print(f"      repair sweep {sweep + 1}: {best_ok}/{total}")
        if best_ok == total or not improved:
            break
    return key, {"method": method + "+repair", "repaired": repaired,
                 "decoded": best_ok, "total": total,
                 "used_zero_anchor": use_anchor}


@dataclass
class KeyGroup:
    """One keystream plus the files proven to decode with it."""
    key: list
    paths: list
    info: dict


def discover_keys(files: dict, shared=None, verbose=False):
    """Partition files into key groups, then recover each key.

    Peels iteratively: recover a key from what is left, claim every file that
    decodes cleanly under it, repeat. Grouping is decided by the structural
    gate alone -- never by filename, and never by assuming the zero region
    holds zeros (it does not in every title).
    """
    remaining = dict(files)
    groups = []
    shared = shared or {}
    for _ in range(_KR["max_keys_per_dir"]):
        if not remaining:
            break
        blobs = list(remaining.values())
        key = None
        info = {"method": "shared", "repaired": 0}
        for anchor, candidate in shared.items():
            if any(anchor == anchor_of(d) for d in blobs):
                key = candidate
                break
        if key is None:
            key, info = recover_key(blobs, verbose=verbose)
        claimed = [p for p, d in remaining.items() if decodes_cleanly(d, key)]
        if not claimed:
            break
        info = dict(info, claimed=len(claimed))
        groups.append(KeyGroup(key=key, paths=claimed, info=info))
        if verbose:
            print(f"      key group: claimed {len(claimed)}, "
                  f"{len(remaining) - len(claimed)} left")
        for p in claimed:
            remaining.pop(p)
    return groups, list(remaining)
