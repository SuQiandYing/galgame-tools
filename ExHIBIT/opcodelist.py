"""Declarative dialect for the ExHIBIT RLD script format.

Data only -- no control flow, no parsing logic. Every numeric constant that is
specific to this engine lives here so that `disassembler.py` / `assembler.py`
stay engine-agnostic and can be checked mechanically for stray literals.

Evidence tags (EV_*) are documented in vm_analysis.md. Confidence levels
follow the skill's ladder: observed > derived > inferred > unresolved.
"""

SCHEMA_VERSION = "1.0.0"
TOOL_VERSION = "1.0.0"
IR_VERSION = "2"

DIALECT = {
    "schema_version": SCHEMA_VERSION,
    "engine_id": "EXHIBIT_RLD",
    "dialect_id": "EXHIBIT_RLD_V3",
    "endianness": "little",

    # ---- container -------------------------------------------------------
    # Header is plaintext; everything after it is XOR-enciphered by u32.
    "container": {
        "magic": b"\x00DLR",
        "magic_offset": 0,
        "version_offset": 4,
        "version_value": 3,
        "op_offset_field": 8,      # u32: byte offset of the op stream
        "op_count_field": 12,      # u32: op tally, EXCLUDES the terminator op
        "header_size": 0x10,
        "evidence_refs": ["EV_HEADER"],
        "confidence": "observed",
    },

    # ---- cipher ----------------------------------------------------------
    # plain[i] = enc[i] ^ keystream[i & 0xFF], u32 words, starting at 0x10.
    # `word_cap` is the engine's own limit: words at or past it are stored in
    # the clear. The original tool additionally masked the word count with
    # 0xFFFF, which corrupts any file above 256 KB -- see EV_CAP_NOT_MASK.
    "cipher": {
        "algorithm": "xor-u32-periodic",
        "body_offset": 0x10,
        "word_size": 4,
        "key_period": 256,
        "word_cap": 0x3FF0,
        "mask_word_count": False,
        "evidence_refs": ["EV_CIPHER", "EV_CAP_NOT_MASK"],
        "confidence": "observed",
    },

    # ---- key recovery ----------------------------------------------------
    # Static recovery, no runtime key dump. See vm_analysis.md §Key recovery.
    "key_recovery": {
        # Region whose plaintext is all zero in most titles, making the
        # ciphertext there equal to the keystream itself. NOT universal:
        # DemonBusters stores an import list here, so the tool verifies that
        # every file agrees before trusting it (EV_ZERO_REGION_NOT_UNIVERSAL).
        "zero_region": [0x10, 0x110],
        "anchor_words": 64,
        "vote_topn": 8,
        "lane_rounds": 8,
        "repair_sweeps": 3,
        "probe_files": 24,
        "max_keys_per_dir": 6,
        # Files whose op tally must equal op_count + 1 to count as decoded.
        "require_op_delta": 1,
        "evidence_refs": ["EV_ZERO_REGION", "EV_OP_DELTA_ONE"],
        "confidence": "derived",
    },

    # ---- op encoding -----------------------------------------------------
    # control u32 layout:
    #   bits  0-15  code
    #   bits 16-23  init_count   (u32 operands following the control word)
    #   bits 24-27  str_count    (NUL-terminated strings following those)
    #   bits 28-31  flags        NOT reserved -- carries real data
    #
    # The flag nibble is populated across the corpus (value 2 on 32,964 ops,
    # 0 on 8,256, and 1/3/4/5/6 on the rest), so it must be preserved verbatim
    # and must not be validated as zero. Its meaning is not decoded; the ops
    # are reproduced byte-for-byte regardless, so this stays a T2 declaration.
    "op": {
        "control_width": 4,
        "code_mask": 0xFFFF,
        "code_shift": 0,
        "init_count_mask": 0xFF,
        "init_count_shift": 16,
        "str_count_mask": 0xF,
        "str_count_shift": 24,
        "flags_mask": 0xF,
        "flags_shift": 28,
        "init_width": 4,
        "string_terminator": b"\x00",
        "evidence_refs": ["EV_OP_LAYOUT", "EV_OP_FLAG_NIBBLE"],
        "confidence": "observed",
    },

    # ---- encodings -------------------------------------------------------
    "encodings": {
        "source": "cp932",
        "target": "cp932",
        "text_file": "utf-8-sig",
        "asm": "utf-8",
        "evidence_refs": ["EV_ENCODING"],
    },

    # ---- text sites ------------------------------------------------------
    # Each rule names an (opcode, string slot) position and, when the string is
    # a delimited record, which field inside it is human-visible. Positions and
    # percentages come from measuring all 64,174 strings of the corpus; see
    # vm_analysis.md for the per-slot table.
    #
    # kind:  whole  -> the entire string is the text
    #        field  -> one field of a sep-delimited record is the text
    # tag values are the skill's closed set: name msg choice label ui system
    # ruby misc
    "text_sites": [
        {
            "id": "dialogue-body",
            "code": 0x1C, "slot": 1, "kind": "whole",
            "tag": "msg", "tag_source": "anchor",
            "count": 25626, "cjk_ratio": 0.98,
            "evidence_refs": ["EV_MSG_1C"], "confidence": "derived",
        },
        {
            # Slot 0 of the dialogue op is the speaker-name override. "*"
            # (25,007 of 25,626) means "use the defChara table"; anything else
            # is shown verbatim instead. Both paths must be translatable or
            # 619 on-screen names go untranslated.
            "id": "speaker-override",
            "code": 0x1C, "slot": 0, "kind": "whole",
            "tag": "name", "tag_source": "structural",
            "skip_values": ["*", ""],
            "count": 619,
            "evidence_refs": ["EV_NAME_OVERRIDE"], "confidence": "derived",
        },
        {
            # The same slot when it holds "*". The name shown on screen then
            # comes from the character table, so the slot itself contains no
            # text -- but the translator still needs to see and edit the name
            # at the line it belongs to. Exported with the table's name filled
            # in; if it is left unchanged the slot keeps its "*" and the table
            # lookup is preserved byte-for-byte, so this costs nothing until
            # someone actually edits it (EV_NAME_SLOT_WRITEBACK).
            "id": "speaker-from-table",
            "code": 0x1C, "slot": 0, "kind": "speaker_slot",
            "tag": "name", "tag_source": "binding",
            "requires_values": ["*"],
            "count": 21103,
            "evidence_refs": ["EV_NAME_OVERRIDE", "EV_NAME_SLOT_WRITEBACK"],
            "confidence": "derived",
        },
        {
            # defChara.rld character table: id,?,?,surname,,,,,,,,,,
            "id": "chara-table-name",
            "code": 0x30, "slot": 0, "kind": "field",
            "sep": ",", "field": 3,
            "tag": "name", "tag_source": "structural",
            "count": 44, "cjk_ratio": 1.00,
            "evidence_refs": ["EV_CHARA_TABLE"], "confidence": "observed",
        },
        {
            # Save/load slot caption carrying a scene description.
            "id": "scene-caption",
            "code": 0xBF, "slot": 0, "kind": "field",
            "sep": ",", "field": 6,
            "tag": "ui", "tag_source": "anchor",
            "skip_values": ["*"],
            "count": 466, "cjk_ratio": 0.93,
            "evidence_refs": ["EV_SCENE_CAPTION"], "confidence": "derived",
        },
        {
            # Choice menu. TAB-delimited; the option labels sit in a run of
            # fields whose start index varies per record, so the field index
            # cannot be fixed -- resolved by scanning (see choice_scan).
            "id": "choice-menu",
            "code": 0x15, "slot": None, "kind": "choice_scan",
            "sep": "\t",
            "tag": "choice", "tag_source": "anchor",
            "count": 33,
            "evidence_refs": ["EV_CHOICE"], "confidence": "derived",
        },
        {
            # Bare choice strings (no record wrapper) seen in D0152_01.
            "id": "choice-bare",
            "code": 0x15, "slot": None, "kind": "choice_bare",
            "tag": "choice", "tag_source": "anchor",
            "count": 3,
            "evidence_refs": ["EV_CHOICE"], "confidence": "derived",
        },
        {
            # Font family name. Visible-looking Japanese but NOT dialogue:
            # rewriting it breaks font selection, so it is exported frozen.
            "id": "font-family",
            "code": 0x5E, "slot": 0, "kind": "field",
            "sep": ",", "field": 30,
            "tag": "misc", "tag_subtype": "font-family-name",
            "tag_source": "structural",
            "translate_policy": "frozen",
            "count": 1667,
            "evidence_refs": ["EV_FONT_NAME"], "confidence": "observed",
        },
    ],

    # Values that mean "absent" and must never be emitted as translatable.
    "placeholder_values": ["*", ""],

    # Field values matching this are structural, not text (numbers, register
    # expressions like "R1001＝4", asset paths).
    "non_text_field": r"^[\-0-9,\.\*＜＝＞;=<>\s]*$",

    # Choice scanning: within a TAB record, a field is an option label if it
    # is neither numeric nor an asset path and contains kana/ideographs.
    "choice_scan": {
        "min_field": 5,
        "asset_hint": "res\\",
        "evidence_refs": ["EV_CHOICE"],
    },

    # Character ranges that count as visible Japanese/Chinese text.
    # Deliberately excludes the fullwidth forms block (U+FF01-FF60): the engine
    # uses ＝ ＜ ＞ as comparison operators inside numeric script expressions,
    # so including it reported pure-parameter records as 95-100% text.
    "script_ranges": [
        [0x3040, 0x30FF],    # hiragana + katakana
        [0x3400, 0x4DBF],    # CJK ext A
        [0x4E00, 0x9FFF],    # CJK unified
    ],

    # ---- markup & control bytes -----------------------------------------
    # Measured over all 64,174 strings: TAB/FF/LF appear inside records, and
    # "$b" is the only markup token. None may be altered by translation.
    "control_bytes": {0x09: "TAB", 0x0A: "LF", 0x0C: "FF"},
    "markup_tokens": ["$b"],
    "evidence_refs": ["EV_CONTROL_BYTES"],

    # ---- name binding ----------------------------------------------------
    # inits[0] of the dialogue op is the character id. id 1 (3,902 uses) is
    # absent from the table and always pairs with "*" -- an unnamed narrator,
    # recorded as virtual so it is never faked into an editable entry.
    "name_binding": {
        "dialogue_code": 0x1C,
        "speaker_id_init": 0,
        "override_slot": 0,
        "body_slot": 1,
        "table_code": 0x30,
        "table_file": "defChara.rld",
        "table_sep": ",",
        "table_id_field": 0,
        "table_name_field": 3,
        "virtual_ids": [1],
        "method": "explicit-id",
        "evidence_refs": ["EV_NAME_OVERRIDE", "EV_CHARA_TABLE", "EV_VIRTUAL_ID1"],
        "confidence": "observed",
    },

    # ---- windows ---------------------------------------------------------
    # No scanning windows are used: the op stream is walked structurally from
    # op_offset to EOF, and strings end at an explicit NUL. Recorded so the
    # absence is deliberate rather than undeclared.
    "windows": [],
}


def text_sites_by_code():
    """Index the text-site rules by opcode."""
    out = {}
    for rule in DIALECT["text_sites"]:
        out.setdefault(rule["code"], []).append(rule)
    return out
