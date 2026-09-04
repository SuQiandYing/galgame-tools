"""Cotopha / EntisGLS CSX v2/v3 dialect declaration.

This module deliberately contains data only.  The parser and serializer live in
``disassembler.py`` and ``assembler.py`` so all engine-specific literals remain
reviewable in this one place.

Evidence references are documented in ``vm_analysis.md``.
"""

from __future__ import annotations

DIALECT = {
    "schema_version": "1.0.0",
    "engine_id": "cotopha-entisgls-csx-v2-v3",
    "endianness": "little",
    "evidence_refs": ["EV_CONTAINER", "EV_REFERENCE_DECODER"],
    "container": {
        "file_magic": b"Entis\x1a\x00\x00",
        "image_type": b"Cotopha Image file",
        "header_size": 0x40,
        "record_header_size": 16,
        "record_tag_width": 8,
        "record_length_width": 8,
        "evidence_refs": ["EV_CONTAINER"],
    },
    # Fields whose value is derived from the size of the section data, and which
    # therefore must be recomputed when a string grows or shrinks.  Reference
    # sites in the image hold conststr *indices*, not byte offsets, so no image
    # word needs relocating — see vm_analysis.md EV_LENGTH_FIELDS.
    "size_fields": {
        "header_total": {"offset": 0x38, "width": 8, "base": 0x40,
                         "means": "sections_end_minus_header"},
        "trailer_sections_end": {"width": 4,
                                 "means": "absolute_sections_end_in_trailer"},
        "evidence_refs": ["EV_LENGTH_FIELDS"],
    },
    "sections": {
        "header": "header  ",
        "image": "image   ",
        "class_info": "classinf",
        "function": "function",
        "init_naked_function": "initnfnc",
        "function_info": "funcinfo",
        "symbol_info": "symblinf",
        "global": "global  ",
        "data": "data    ",
        "const_string": "conststr",
        "link_info": "linkinf ",
        "link_ex64": "linkex64",
        "ref_function": "reffunc ",
        "ref_code": "refcode ",
        "ref_class": "refclass",
        "import_native": "impnativ",
    },
    "string_literal": {
        "interned_marker": 0x80000000,
        "encoding": "utf-16-le",
        "length_type": "u32_code_units",
        "evidence_refs": ["EV_CONSTSTR", "EV_REFERENCE_DECODER"],
    },
    # Sub-records nested inside a section body, keyed by the owning section.
    "nested_records": {
        "import_native": {"native_function_names": b"nativfnc"},
        "evidence_refs": ["EV_CONTAINER"],
    },
    # Code points that cannot be shown literally in a two-line text file and are
    # therefore rendered as byte placeholders (§4.5).
    "placeholder_policy": {
        "control_below": 0x20,
        "delete": 0x7F,
        "private_use": [0xE000, 0xF8FF],
        "line_breaks": [0x0A, 0x0D],
        "evidence_refs": ["EV_TEXT_PLACEHOLDER"],
    },
    "variable_types": {
        0: "object", 1: "reference", 2: "array", 3: "hash",
        4: "integer", 5: "real", 6: "string", 7: "integer64",
        8: "pointer", 9: "class_object", 10: "boolean", 11: "int8",
        12: "uint8", 13: "int16", 14: "uint16", 15: "int32",
        16: "uint32", 17: "array_dimension", 18: "hash_container",
        19: "real32", 20: "real64", 21: "pointer_reference",
        22: "buffer", 23: "function",
    },
    "object_modes": {
        0: "immediate", 1: "stack", 2: "this", 3: "global",
        4: "data", 5: "auto",
    },
    "instructions": {
        0x00: {"mnemonic": "NEW", "handler": "new", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x01: {"mnemonic": "FREE", "handler": "free", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x02: {"mnemonic": "LOAD", "handler": "load", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x03: {"mnemonic": "STORE", "handler": "store", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x04: {"mnemonic": "ENTER", "handler": "enter", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x05: {"mnemonic": "LEAVE", "handler": "leave", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x06: {"mnemonic": "JUMP", "handler": "jump", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x07: {"mnemonic": "CJUMP", "handler": "cjump", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x08: {"mnemonic": "CALL", "handler": "call", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x09: {"mnemonic": "RETURN", "handler": "return", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x0A: {"mnemonic": "ELEMENT", "handler": "element", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x0B: {"mnemonic": "ELEMENT_INDIRECT", "handler": "element_indirect", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x0C: {"mnemonic": "OPERATE", "handler": "operate", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x0D: {"mnemonic": "UNI_OPERATE", "handler": "uni_operate", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x0E: {"mnemonic": "COMPARE", "handler": "compare", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x0F: {"mnemonic": "EX_OPERATE", "handler": "ex_operate", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x10: {"mnemonic": "EX_UNI_OPERATE", "handler": "ex_uni_operate", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x11: {"mnemonic": "EX_CALL", "handler": "ex_call", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x12: {"mnemonic": "EX_RETURN", "handler": "ex_return", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x13: {"mnemonic": "CALL_MEMBER", "handler": "call_member", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x14: {"mnemonic": "CALL_NATIVE_MEMBER", "handler": "call_native_member", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x15: {"mnemonic": "SWAP", "handler": "swap", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x17: {"mnemonic": "CREATE_BUFFER_VSIZE", "handler": "create_buffer_vsize", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x18: {"mnemonic": "POINTER_TO_OBJECT", "handler": "pointer_to_object", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x1A: {"mnemonic": "REFERENCE_FOR_POINTER", "handler": "reference_for_pointer", "evidence_refs": ["EV_REFERENCE_DECODER"]},
        0x1D: {"mnemonic": "CALL_NATIVE_FUNCTION", "handler": "call_native_function", "evidence_refs": ["EV_REFERENCE_DECODER"]},
    },
    "compare_ops": {
        0: "ne", 1: "eq", 2: "lt", 3: "le", 4: "gt", 5: "ge",
        6: "ne_pointer", 7: "eq_pointer",
    },
    "extra_ops": {0: "array_dimension", 1: "hash_container", 2: "move_reference"},
    "extra_uni_ops": {
        0: "deselect", 1: "boolean", 2: "sizeof", 3: "typeof",
        4: "static_cast", 5: "dynamic_cast", 6: "duplicate", 7: "delete",
        8: "delete_array", 9: "load_address", 10: "reference_address",
    },
}

DIALECT["container"]["image_type_offset"] = 0x10
SIZE_FIELDS = DIALECT["size_fields"]
SECTION_TAGS = {value: key for key, value in DIALECT["sections"].items()}
PLACEHOLDER_POLICY = DIALECT["placeholder_policy"]
NATIVE_FUNC_RECORD = DIALECT["nested_records"]["import_native"]["native_function_names"]
INSTRUCTIONS = DIALECT["instructions"]
VARIABLE_TYPES = DIALECT["variable_types"]
OBJECT_MODES = DIALECT["object_modes"]
