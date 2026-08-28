import json
import os

def _default_mapping_path():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "bss_mapping_v0.json")

OPERAND_TEMPLATES = {
    0x0010: "iim",
    0x0011: "",
    0x0012: "zz",
    0x0013: "z",
    0x0014: "z",
    0x0015: "",
    0x0018: "iiiii",
    0x0019: "iiii",
    0x001A: "iii",
    0x001B: "ziii",
    0x001F: "i",
    0x0020: "",
    0x0021: "",
    0x0022: "i",
    0x0023: "i",
    0x0024: "iiiii",
    0x0025: "ii",
    0x0027: "",
    0x0028: "zi",
    0x0029: "zzi",
    0x002A: "i",
    0x002B: "zi",
    0x002C: "ziiiiiiii",
    0x002D: "ziiiiiiii",
    0x002E: "iiiii",
    0x0030: "zi",
    0x0031: "zii",
    0x0032: "i",
    0x0033: "i",
    0x0034: "ii",
    0x0035: "i",
    0x0036: "i",
    0x0037: "",
    0x0038: "iziiiii",
    0x0039: "ii",
    0x003A: "iziiiiiiii",
    0x003B: "iiiiii",
    0x003C: "iiiiiiiiii",
    0x003D: "iiiiiiiiiii",
    0x003F: "i",
    0x0040: "iizii",
    0x0041: "iizii",
    0x0042: "iizi",
    0x0043: "iizi",
    0x0044: "iizi",
    0x0045: "iizi",
    0x0046: "izi",
    0x0047: "izi",
    0x0048: "ii",
    0x0049: "ii",
    0x004A: "izi",
    0x004B: "",
    0x004C: "zi",
    0x004D: "zi",
    0x004E: "i",
    0x004F: "i",
    0x0050: "zi",
    0x0051: "zzi",
    0x0052: "i",
    0x0053: "zi",
    0x0054: "zii",
    0x0055: "ziii",
    0x0060: "iiiii",
    0x0061: "ii",
    0x0062: "iiiiii",
    0x0065: "i",
    0x0066: "ii",
    0x0067: "i",
    0x0068: "i",
    0x0069: "i",
    0x006A: "i",
    0x006B: "i",
    0x006C: "i",
    0x006E: "iii",
    0x006F: "i",
    0x0070: "izi",
    0x0071: "i",
    0x0072: "iii",
    0x0073: "iii",
    0x0074: "izi",
    0x0075: "i",
    0x0076: "iii",
    0x0078: "izi",
    0x0079: "i",
    0x007A: "iii",
    0x0080: "zi",
    0x0081: "z",
    0x0082: "i",
    0x0083: "i",
    0x0084: "izi",
    0x0085: "z",
    0x0086: "i",
    0x0087: "i",
    0x0088: "z",
    0x008C: "i",
    0x008D: "i",
    0x008E: "i",
    0x0090: "i",
    0x0091: "i",
    0x0092: "i",
    0x0093: "i",
    0x0094: "i",
    0x0098: "ii",
    0x0099: "ii",
    0x009A: "ii",
    0x009B: "ii",
    0x009C: "ii",
    0x009D: "ii",
    0x00A0: "c",
    0x00A1: "ic",
    0x00A2: "ic",
    0x00A3: "iic",
    0x00A4: "iic",
    0x00A5: "iic",
    0x00A6: "iic",
    0x00A7: "iic",
    0x00A8: "iic",
    0x00AC: "c",
    0x00AD: "",
    0x00AE: "i",
    0x00AF: "",
    0x00B8: "",
    0x00B9: "i",
    0x00BA: "i",
    0x00C0: "z",
    0x00C1: "z",
    0x00C2: "",
    0x00C4: "i",
    0x00C8: "z",
    0x00C9: "",
    0x00CA: "i",
    0x00D0: "",
    0x00D4: "i",
    0x00D8: "i",
    0x00D9: "i",
    0x00DA: "i",
    0x00DB: "i",
    0x00DC: "i",
    0x00E3: "zz",
    0x00E8: "iiii",
    0x00E9: "",
    0x00EA: "",
    0x00F8: "z",
    0x00F9: "zi",
    0x00FE: "h",
    0x0110: "zz",
    0x0111: "i",
    0x0120: "i",
    0x0121: "i",
    0x0128: "zii",
    0x012A: "ii",
    0x0134: "ii",
    0x0135: "i",
    0x0136: "i",
    0x0138: "iziiiiziii",
    0x013B: "iiiiiiii",
    0x0140: "iiziiii",
    0x0141: "iiziiii",
    0x0142: "iiziii",
    0x0143: "iiziii",
    0x0144: "iiziii",
    0x0145: "iiziii",
    0x0146: "iziii",
    0x0147: "iziii",
    0x0148: "ii",
    0x0149: "ii",
    0x014B: "ziiz",
    0x0150: "zii",
    0x0151: "ziii",
    0x0152: "ii",
    0x0153: "iii",
    0x016E: "iiiiii",
    0x016F: "iiiiiii",
    0x0170: "izzii",
    0x0172: "izii",
    0x0176: "izii",
    0x01C0: "zz",
    0x01C1: "zz",
    0x0249: "z",
    0x024C: "zziii",
    0x024D: "z",
    0x024E: "zz",
    0x024F: "z",
}

SPECIAL_OPS = {0x00A9, 0x00B0, 0x00B4, 0x00FD}
ALTERNATE_OPERAND_TEMPLATES = {
    0x0022: ("",),
    0x0023: ("",),
    0x0024: ("i", ""),
    0x0025: ("",),
    0x0027: ("zi",),
    0x0028: ("",),
    0x0029: ("",),
    0x002A: ("",),
    0x002B: ("",),
    0x0030: ("",),
    0x0031: ("",),
    0x0032: ("",),
    0x0033: ("",),
    0x0034: ("",),
    0x0035: ("",),
    0x0038: ("",),
    0x0039: ("",),
    0x003A: ("",),
    0x003C: ("iiiii",),
    0x003D: ("iiiiii", "iiiiiiiii", "iiiiiiiiiiiii"),
    0x0080: ("izii", ""),
    0x0081: ("",),
    0x0082: ("", "iii", "hh"),
    0x00E8: ("iii",),
    0x0148: ("zziiiii",),
    0x0149: ("z",),
}


def parse_mapping_opcode(key):
    if key.startswith("@"):
        return int(key[1:], 16)
    if "_" in key:
        return int(key.split("_")[1], 16)
    return None


def load_name_maps(mapping_path=None):
    mapping_path = mapping_path or _default_mapping_path()
    op_to_name = {}
    name_to_op = {}
    for op in set(OPERAND_TEMPLATES.keys()) | SPECIAL_OPS:
        base = f"f_{op:03x}"
        op_to_name[op] = base
        name_to_op[base] = op
    try:
        with open(mapping_path, "r", encoding="utf-8") as f:
            mapping = json.load(f)
        for key, name in mapping.items():
            try:
                op = parse_mapping_opcode(key)
            except Exception:
                continue
            if op is None:
                continue
            if op in op_to_name:
                op_to_name[op] = name
                if name not in name_to_op:
                    name_to_op[name] = op
    except Exception:
        pass
    return op_to_name, name_to_op


def get_operand_templates(op):
    base = OPERAND_TEMPLATES.get(op)
    if base is None:
        return []
    extra = list(ALTERNATE_OPERAND_TEMPLATES.get(op, ()))
    return [base] + extra
