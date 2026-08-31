"""Declarative dialect for SILKY'S ENGINE .MES bytecode.

Data only: opcode numbers, anchor patterns, syscall IDs, encodings, window
constants, text rules. No control flow, no parsing logic. Every entry that
drives a tier claim carries evidence_refs pointing into vm_analysis.md.

See vm_analysis.md for the evidence ledger behind each value here.
"""

SCHEMA_VERSION = "1.0.0"
ENGINE_ID = "SILKYS_MES"
DIALECT_ID = "SILKYS_MES_FUYUKURU"

# ---------------------------------------------------------------------------
# Container / header
# ---------------------------------------------------------------------------
# u32 n_labels, u32 n_entries, u32 labels[n_labels], u32 entries[n_entries]
# Header integers are LITTLE endian; instruction operands are BIG endian.
# Mixing these up is the single easiest way to break this format.
HEADER = {
    "endianness": "little",
    "fields": [
        {"name": "n_labels", "offset": 0, "width": 4, "kind": "u32"},
        {"name": "n_entries", "offset": 4, "width": 4, "kind": "u32"},
    ],
    "tables": [
        {"name": "labels", "count_field": "n_labels", "width": 4,
         "base": "code_start", "evidence_refs": ["EV_HEADER_LABELS"]},
        {"name": "entries", "count_field": "n_entries", "width": 4,
         "base": "code_start", "evidence_refs": ["EV_HEADER_ENTRIES"]},
    ],
    "evidence_refs": ["EV_HEADER_LAYOUT"],
    "confidence": "derived",
}

CODE = {
    "endianness": "big",
    "evidence_refs": ["EV_OPERAND_ENDIAN"],
    "confidence": "derived",
}

# ---------------------------------------------------------------------------
# Opcodes
# ---------------------------------------------------------------------------
# Exactly four opcodes take a 4-byte big-endian operand. Omitting 0x19 from
# this set makes the linear decoder drift: the observed distinct-opcode count
# inflates from 51 to all 256, and 154 dialogue strings fail the hash oracle.
# That inflation is the diagnostic signal, not a cosmetic detail.
OPERAND_U32 = {
    0x32: {"mnemonic": "PUSH", "operand": "imm32",
           "evidence_refs": ["EV_PUSH_IMM"], "confidence": "observed"},
    0x14: {"mnemonic": "JMP", "operand": "code_offset",
           "evidence_refs": ["EV_JUMP_TARGETS"], "confidence": "derived"},
    0x15: {"mnemonic": "CALL", "operand": "code_offset",
           "evidence_refs": ["EV_JUMP_TARGETS"], "confidence": "derived"},
    0x19: {"mnemonic": "OP19", "operand": "imm32",
           "evidence_refs": ["EV_OP19_WIDTH"], "confidence": "derived"},
}

# NUL-terminated string operands.
OPERAND_STRING = {
    0x33: {"mnemonic": "PUSHS", "role": "identifier",
           "evidence_refs": ["EV_STR_OPCODES"], "confidence": "observed"},
    0x0A: {"mnemonic": "PUSHM", "role": "message",
           "evidence_refs": ["EV_STR_OPCODES"], "confidence": "observed"},
}

# Every other byte value is a single-byte opcode with no operand. Only these
# 51 opcodes occur across the whole corpus once 0x19 is handled correctly.
OBSERVED_OPCODES = [
    0x00, 0x01, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0A, 0x0C, 0x0D, 0x0E, 0x0F,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1E, 0x1F, 0x27,
    0x32, 0x33, 0x34, 0x36, 0x37, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x42,
    0x43, 0x57, 0x67, 0x7B, 0x98, 0xA1, 0xA6, 0xD6, 0xD9, 0xFA, 0xFB, 0xFC,
    0xFD, 0xFE, 0xFF,
]

# ---------------------------------------------------------------------------
# Anchors
# ---------------------------------------------------------------------------
SYSCALL_OPCODE = 0x18

ANCHORS = [
    {"id": "syscall", "kind": "call", "opcode": SYSCALL_OPCODE,
     "id_source": "preceding_push_imm32",
     "operand_slots": [{"ordinal": 1, "name": "syscall_id", "width": 4}],
     "evidence_refs": ["EV_SYSCALL_DISPATCH"], "confidence": "derived"},
]

# Syscall IDs grouped by the role of the string operand they consume.
CALLEE_GROUPS = [
    {"id": "message", "ids": [0x16], "role": "msg",
     "evidence_refs": ["EV_MSG_SYSCALL"], "confidence": "derived"},
    {"id": "name_or_image", "ids": [0x1D], "role": "name",
     "evidence_refs": ["EV_NAME_SYSCALL"], "confidence": "derived"},
    {"id": "voice", "ids": [0x12], "role": "asset",
     "evidence_refs": ["EV_ASSET_SYSCALLS"], "confidence": "derived"},
    {"id": "image", "ids": [0x1B, 0x13], "role": "asset",
     "evidence_refs": ["EV_ASSET_SYSCALLS"], "confidence": "derived"},
    {"id": "sound", "ids": [0x10], "role": "asset",
     "evidence_refs": ["EV_ASSET_SYSCALLS"], "confidence": "derived"},
    {"id": "video", "ids": [0x17], "role": "asset",
     "evidence_refs": ["EV_ASSET_SYSCALLS"], "confidence": "derived"},
    {"id": "script", "ids": [0x15], "role": "asset",
     "evidence_refs": ["EV_ASSET_SYSCALLS"], "confidence": "derived"},
    {"id": "config", "ids": [0x19, 0x0F], "role": "config",
     "evidence_refs": ["EV_CONFIG_SYSCALL"], "confidence": "derived"},
]

WINDOWS = [
    {"name": "syscall_lookahead", "value": 12, "measured_max": 9,
     "evidence": "max instructions between a string push and its consuming "
                 "syscall, measured across all 59 corpus files",
     "on_exceed": "stop"},
    {"name": "name_binding_lookahead", "value": 40, "measured_max": 27,
     "evidence": "max instructions between a 0x1D name push and the next "
                 "0x16 message push, measured across all 59 corpus files",
     "on_exceed": "stop"},
]

# ---------------------------------------------------------------------------
# Kana substitution table
# ---------------------------------------------------------------------------
# Inside string operands, bytes 0x01..0x53 are NOT cp932 bytes. They are
# single-byte codes for hiragana, offset directly into the Unicode hiragana
# block:  char = chr(0x3040 + code).
#
# Derived, not guessed: 25 codes were solved independently by brute-forcing
# single-code strings against the sha1 oracle in chs.json, and all 25 fit this
# one rule with zero exceptions. Full-corpus check: 48077 hits / 6 misses,
# where all 6 misses are repeated-filler test strings in _SAMPLE.MES that
# decode correctly but were never translated.
KANA_CODE_MIN = 0x01
KANA_CODE_MAX = 0x53
KANA_BASE = 0x3040

# cp932 double-byte lead-byte ranges. A byte in these ranges consumes the
# following byte and is emitted literally.
CP932_LEAD_RANGES = ((0x81, 0x9F), (0xE0, 0xEF))

# Named roles so structural logic never spells an opcode number itself.
# These are the DEFAULT (fuyukuru) values; select_dialect() may override the
# string opcodes and kana scope per file. See VARIANTS below.
OP_PUSH_IMM = 0x32          # supplies the syscall id
OP_JUMP = (0x14, 0x15)      # operands are code-relative and must be relocated
OP_MESSAGE_STRING = 0x0A    # dialogue
OP_IDENTIFIER_STRING = 0x33  # names, filenames, config keys

# One spoken line is emitted as 1..3 consecutive message strings joined by this
# exact opcode sequence, which is the engine's line-break instruction. All
# 17947 separators in the corpus are this sequence with no variants, and group
# sizes are only 1, 2 or 3.
#
# The parts are merged into a single editable entry so a translator sees the
# whole sentence; the separator is shown as the escape below and split back on
# repack. Two properties make this safe, both measured:
#   - no jump or label target ever points at a non-first part (0 of 12609
#     multi-part groups), so merging cannot break control flow;
#   - no dialogue string contains a literal backslash (0 of 48083), so the
#     escape is unambiguous and needs no further quoting.
MESSAGE_JOIN_OPCODES = (0x1C, 0x00)
MESSAGE_JOIN_MAX_PARTS = 3
MESSAGE_JOIN_ESCAPE = "\\n"

# ---------------------------------------------------------------------------
# Choice registration
# ---------------------------------------------------------------------------
# Player-visible choices are registered by opcode 0x1B, whose operand is a
# 4-byte big-endian CODE OFFSET (the branch taken if this option is picked),
# immediately followed by the option text as a message string:
#
#     1B <u32 target>  <message string>  00
#
# Treating 0x1B as a no-operand opcode swallows the target bytes and leaves the
# option text looking like stray dialogue with no consuming syscall, which is
# why these lines previously came out tagged msg by a fallback rule and the
# choice count was zero.
#
# 0x1B is CONTEXT-DEPENDENT: in library files (LIBLARY.LIB) the same value
# occurs as a genuine no-operand opcode. It is read as 5 bytes only when the
# operand resolves inside the file, which is decidable, not a guess. Measured:
#   fuyukuru   10 choices, 0 misaligned targets (2 rejected in LIBLARY.LIB)
#   title "1"  52 choices, 0 misaligned targets
# Cross-check: the 10 fuyukuru choices match the published walkthrough exactly
# (5 save points x 2 options).
OP_CHOICE = 0x1B
CHOICE_TARGET_WIDTH = 4

# Bytes below this are never printable text; rendered as {{XX}} placeholders.
CONTROL_BYTE_MAX = 0x20

# Which string opcodes carry kana-compressed operands. Only 0x0A does.
#
# This is measured, not assumed: across the corpus, 0 of 77689 0x33 strings
# need expansion to hit the sha1 oracle (the 17371 that hit, hit identically
# with or without it), while 46107 of 47928 0x0A strings contain codes.
# Expanding 0x33 corrupts filenames, e.g. black.akb -> black<の>akb, because
# 0x2E is a literal ASCII '.' there rather than a code for の.
KANA_COMPRESSED_OPCODES = (0x0A,)

STRING_TERMINATOR = b"\x00"
TERMINATOR_LEN = 1

# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------
ENCODINGS = {
    "source_encoding": "cp932",
    "target_encoding": "cp932",
    "text_encoding": "utf-8-sig",
    "asm_encoding": "utf-8",
}

# ---------------------------------------------------------------------------
# Text rules
# ---------------------------------------------------------------------------
# Evaluated in declaration order, first match wins. No fallback rule: an entry
# that matches nothing stays tag=misc / tag_source=unresolved so that the
# unresolved count stays honest.
#
# Rules key off the string's ROLE ("message" / "identifier"), not a literal
# opcode, because the opcode carrying each role differs per title (see
# VARIANTS). One rule set therefore serves every variant.
TEXT_RULES = [
    {"id": "message", "subtype": "dialogue",
     "requires_role": "message",
     # Preferred form: the string is consumed by the message syscall.
     "requires_callee_group": "message",
     "tag": "msg", "tag_source": "anchor", "confidence": "derived",
     "evidence_refs": ["EV_MSG_SYSCALL"]},
    {"id": "choice", "subtype": "选项",
     # Declared before the unanchored-message fallback so choices are not
     # absorbed by it. The anchor is the preceding 0x1B choice registration,
     # which is structural: the option text is that instruction's payload.
     "requires_role": "message", "requires_preceding_opcode": "choice",
     "tag": "choice", "tag_source": "structural", "confidence": "observed",
     "evidence_refs": ["EV_CHOICE_BLOCK"]},
    {"id": "message-unanchored", "subtype": "dialogue",
     # Fallback for dialogue whose consuming syscall sits beyond the lookahead
     # window (measured: 23 lines in fuyukuru, 160 in title "1" -- all verified
     # as real dialogue by eye and, for fuyukuru, by the sha1 oracle).
     #
     # Length is deliberately NOT used as a filter here: real dialogue includes
     # 2-character lines such as '……？'. Instead this requires the text to
     # contain at least one double-byte character, which excludes the 1-2 byte
     # fragment produced in library files where the message opcode value also
     # occurs as a genuine no-operand opcode.
     "requires_role": "message",
     "predicates": [{"kind": "contains_script", "value": "cjk-or-kana"}],
     "tag": "msg", "tag_source": "heuristic", "confidence": "inferred",
     "evidence_refs": ["EV_MSG_UNANCHORED"]},
    {"id": "speaker-name", "subtype": "speaker-bracket",
     "requires_role": "identifier", "requires_callee_group": "name_or_image",
     "predicates": [{"kind": "starts_with", "value": "【"},
                    {"kind": "ends_with", "value": "】"}],
     "tag": "name", "tag_source": "structural", "confidence": "observed",
     "evidence_refs": ["EV_NAME_BRACKET"]},
    {"id": "asset-path", "subtype": "asset-filename",
     "requires_role": "identifier", "requires_callee_group": "asset",
     "tag": "label", "tag_source": "anchor", "confidence": "derived",
     "evidence_refs": ["EV_ASSET_SYSCALLS"]},
    {"id": "config-path", "subtype": "config-key",
     "requires_role": "identifier", "requires_callee_group": "config",
     "tag": "label", "tag_source": "anchor", "confidence": "derived",
     "evidence_refs": ["EV_CONFIG_SYSCALL"]},
    # Shape variant: a few dialogue lines are stored uncompressed in 0x33 with
    # no consuming syscall inside the lookahead window. Verified as real
    # dialogue by the sha1 oracle, so it gets an explicit branch rather than a
    # widened window. Declared before the ascii rules so it cannot be shadowed.
    {"id": "message-in-identifier", "subtype": "dialogue",
     "requires_role": "identifier",
     "predicates": [{"kind": "matches_regex",
                     "value": r"^[「【].*[」】]$|^[^\x00-\x7F]"}],
     "tag": "msg", "tag_source": "heuristic", "confidence": "inferred",
     "evidence_refs": ["EV_SHAPE_MSG_IN_0X33"]},
    {"id": "filename", "subtype": "asset-filename",
     "requires_role": "identifier",
     "predicates": [{"kind": "matches_regex",
                     "value": r"^[\x20-\x7E]*\.(akb|ogg|wav|mes|vsd|inc|lib)$"}],
     "tag": "label", "tag_source": "heuristic", "confidence": "inferred",
     "evidence_refs": ["EV_ASSET_EXTENSIONS"]},
    {"id": "transition-code", "subtype": "transition-code",
     "requires_role": "identifier",
     "predicates": [{"kind": "matches_regex", "value": r"^[fw][io]$"}],
     "tag": "label", "tag_source": "heuristic", "confidence": "inferred",
     "evidence_refs": ["EV_TRANSITION_CODES"]},
    {"id": "ascii-token", "subtype": "internal-token",
     "requires_role": "identifier",
     "predicates": [{"kind": "matches_regex", "value": r"^[\x20-\x7E]+$"}],
     "tag": "label", "tag_source": "heuristic", "confidence": "inferred",
     "evidence_refs": ["EV_ASCII_TOKENS"]},
]

# tag -> translate_policy. Anything left unresolved becomes review-required.
TRANSLATE_POLICY = {
    "name": "translatable",
    "msg": "translatable",
    "choice": "translatable",
    "ui": "translatable",
    "system": "translatable",
    "ruby": "translatable",
    "label": "frozen",
    "misc": "review-required",
}

TAG_SUBTYPES = [
    "dialogue", "speaker-bracket", "asset-filename", "config-key",
]

DECLARED = {
    "profile_id": "silkys_mes",
    "dialect_id": DIALECT_ID,
    "analysis_mode": "bytecode-disasm",
    "declared_tier": "T3",
    "unpack_mode": "not-required",
    "text_source": "embedded",
}

# ---------------------------------------------------------------------------
# Dialect variants (L1/L2 per SKILL.md 7.5)
# ---------------------------------------------------------------------------
# Same engine, same container, same header, same prologue bytes, same 5-byte
# operand set. What differs between titles is which opcode carries dialogue and
# whether the kana substitution table is in use.
#
# Selection is by STRUCTURAL PROBE only -- never by folder or file name
# (7.5.2). The probe decodes the file under each candidate and scores it; a
# wrong string set desynchronises the linear decode, which shows up as cp932
# lead bytes appearing as opcodes and as an inflated distinct-opcode count.
#
# Measured discriminator on the two corpora:
#   fuyukuru  (59 files)  str={0x33,0x0A}: 51 opcodes    str={0x33,0x0B}: fails
#   title "1" (241 files) str={0x33,0x0B}: 65 opcodes    str={0x33,0x0A}: 249
VARIANTS = [
    {
        "id": "SILKYS_MES_FUYUKURU",
        "message_opcode": 0x0A,
        "identifier_opcode": 0x33,
        "kana_compressed": True,
        "evidence_refs": ["EV_STR_OPCODES", "EV_KANA_TABLE"],
        "notes": "Japanese release; dialogue in 0x0A with kana substitution.",
    },
    {
        "id": "SILKYS_MES_0B_PLAIN",
        "message_opcode": 0x0B,
        "identifier_opcode": 0x33,
        "kana_compressed": False,
        "evidence_refs": ["EV_VARIANT_0B"],
        "notes": "Dialogue in 0x0B, stored as plain cp932 with no substitution "
                 "codes (10 distinct stray single bytes vs 80 in the "
                 "kana-compressed variant).",
    },
]

# A desynchronised decode walks through cp932 text and reports much of the
# lead-byte range as opcodes. A correct decode still shows a few, because some
# real single-byte opcodes fall in those ranges.
#
# This is NOT used to choose between variants -- the distinct-opcode count does
# that, and it separates them by a wide margin. This bound only catches the case
# where *every* candidate is desynchronised, so nothing silently decodes text as
# code.
#
# Observed on both corpora: correct decodes reach 0.1212 (S04-30.MES, 4 of 33),
# wrong variants reach 0.2222 on the same file. Filtering candidates at 0.12
# rejected that valid file, which is why the ratio was demoted to a bound on the
# winner instead of a selector.
CP932_LEAD_AS_OPCODE_IS_DESYNC = True
MAX_LEAD_BYTE_RATIO_ABSOLUTE = 0.18

# Unicode ranges backing the contains_script predicate. Data, so it lives here
# rather than in the structural logic. Kana, CJK ideographs and the fullwidth /
# CJK punctuation that dialogue actually uses; ASCII and control characters are
# deliberately excluded, which is what lets the predicate reject a misread
# opcode pair such as '\x1d2'.
SCRIPT_RANGES = {
    "cjk-or-kana": (
        (0x3000, 0x303F),   # CJK symbols and punctuation
        (0x3040, 0x30FF),   # hiragana + katakana
        (0x3400, 0x4DBF),   # CJK ext A
        (0x4E00, 0x9FFF),   # CJK unified ideographs
        (0xF900, 0xFAFF),   # CJK compatibility ideographs
        (0xFF01, 0xFF60),   # fullwidth forms
        (0x2010, 0x2027),   # dashes and quotes used in dialogue
        (0x2500, 0x257F),   # box drawing, used as rules in text
        (0x25A0, 0x25FF),   # geometric shapes, used as bullets
    ),
}
