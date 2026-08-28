#!/usr/bin/env python3

import argparse
import base64
import glob
import os
import struct

import asdis
from bgiop_v0 import OPERAND_TEMPLATES, SPECIAL_OPS, get_operand_templates, load_name_maps


def read_c_string(data, pos):
    end = data.find(b"\x00", pos)
    if end == -1:
        raise ValueError(f"未找到字符串结尾，offset={pos}")
    return data[pos:end], end + 1


def fmt_label(addr):
    return f"L{addr:05x}"


def bytes_to_token(raw, encoding):
    try:
        text = asdis.decode_with_placeholders(raw, encoding)
        return '"' + asdis.escape(text) + '"'
    except Exception:
        return 'b64("' + base64.b64encode(raw).decode("ascii") + '")'


def _simulate_template(data, pos, template):
    cur = pos
    z_values = []
    for t in template:
        if t == "h":
            if cur + 2 > len(data):
                return None, None
            cur += 2
        elif t in ("i", "m", "c"):
            if cur + 4 > len(data):
                return None, None
            cur += 4
        elif t == "z":
            end = data.find(b"\x00", cur)
            if end == -1:
                return None, None
            z_values.append(data[cur:end])
            cur = end + 1
        else:
            return None, None
    return cur, z_values


def _is_known_opcode(data, pos):
    if pos + 2 > len(data):
        return False
    op = struct.unpack_from("<H", data, pos)[0]
    return op in OPERAND_TEMPLATES or op in SPECIAL_OPS


def _advance_past_padding(data, pos):
    cur = pos
    while cur + 4 <= len(data):
        if struct.unpack_from("<H", data, cur)[0] != 0:
            break
        if not _is_known_opcode(data, cur + 2):
            break
        cur += 2
    return cur


def _template_score(data, next_pos):
    if next_pos is None:
        return -1
    if next_pos >= len(data):
        return 2
    padded_pos = _advance_past_padding(data, next_pos)
    if padded_pos != next_pos and padded_pos < len(data):
        return 2
    if next_pos + 2 > len(data):
        return 1
    if _is_known_opcode(data, next_pos):
        return 3
    return 0


def _text_score(raw):
    if raw is None:
        return -2
    if len(raw) == 0:
        return 0
    try:
        text = raw.decode("cp932")
    except Exception:
        return -2
    ctrl = 0
    for ch in text:
        o = ord(ch)
        if o < 0x20 and ch not in ("\r", "\n", "\t"):
            ctrl += 1
    if ctrl > 0:
        return -2
    return 2


def _write_strdata_hex(f, raw):
    if not raw:
        return
    hex_str = raw.hex()
    for i in range(0, len(hex_str), 128):
        f.write(f'#strdata "{hex_str[i:i + 128]}"\n')


def _write_exact_tail(f, tail, encoding):
    pos = 0
    while pos < len(tail):
        if tail[pos] == 0:
            zero_end = pos
            while zero_end < len(tail) and tail[zero_end] == 0:
                zero_end += 1
            _write_strdata_hex(f, tail[pos:zero_end])
            pos = zero_end
            continue
        end = tail.find(b"\x00", pos)
        if end == -1:
            _write_strdata_hex(f, tail[pos:])
            break
        raw = tail[pos:end]
        if _text_score(raw) >= 0:
            f.write(bytes_to_token(raw, encoding) + "\n")
        else:
            _write_strdata_hex(f, tail[pos:end + 1])
        pos = end + 1


def _format_debug_args(args, encoding, string_refs):
    out = []
    for kind, value in args:
        if kind == "c":
            out.append(fmt_label(value))
        elif kind in ("i", "h"):
            out.append(str(value))
        elif kind == "m":
            out.append(fmt_label(value) if value in string_refs else str(value))
        elif kind == "z":
            out.append(bytes_to_token(value, encoding))
        else:
            raise ValueError(f"未知参数类型: {kind}")
    return ", ".join(out)


def _format_instruction_text(op_to_name, op, args, encoding, string_refs):
    name = op_to_name.get(op, f"f_{op:03x}")
    arg_text = _format_debug_args(args, encoding, string_refs)
    if arg_text:
        return f"{name}({arg_text})"
    return f"{name}()"


def _write_debug_tail(f, tail, code_end, string_refs):
    if not tail:
        return
    f.write("\n#strings\n")
    current_pos = 0
    rel_refs = {offset - code_end: token for offset, token in string_refs.items() if code_end <= offset < code_end + len(tail)}
    sorted_rel_offsets = sorted(rel_refs)
    while current_pos < len(tail):
        if current_pos in rel_refs:
            abs_offset = code_end + current_pos
            f.write(f"{fmt_label(abs_offset)}: {rel_refs[current_pos]}\n")
            end = tail.find(b"\x00", current_pos)
            if end == -1:
                current_pos = len(tail)
            else:
                current_pos = end + 1
            continue
        next_ref_pos = len(tail)
        for off in sorted_rel_offsets:
            if off > current_pos:
                next_ref_pos = off
                break
        _write_strdata_hex(f, tail[current_pos:next_ref_pos])
        current_pos = next_ref_pos


def _write_debug_file(debug_path, instructions, data, code_end, tail, op_to_name, encoding, string_refs):
    hex_width = 16
    for idx, (addr, _op, _args, _pad_bytes) in enumerate(instructions):
        next_addr = instructions[idx + 1][0] if idx + 1 < len(instructions) else code_end
        hex_width = max(hex_width, len(data[addr:next_addr].hex()))
    with open(debug_path, "w", encoding="utf-8", newline="\n") as f:
        for idx, (addr, op, args, _pad_bytes) in enumerate(instructions):
            next_addr = instructions[idx + 1][0] if idx + 1 < len(instructions) else code_end
            last_addr = max(addr, next_addr - 1)
            raw = data[addr:next_addr]
            text = _format_instruction_text(op_to_name, op, args, encoding, string_refs)
            f.write(f"{addr:05x}-{last_addr:05x}  {raw.hex():<{hex_width}}  {text}\n")
        _write_debug_tail(f, tail, code_end, string_refs)


def _pick_template(data, pos, templates, preferred_template=None):
    if len(templates) == 1:
        return templates[0]
    best = None
    best_tuple = None
    for tmpl in templates:
        next_pos, z_values = _simulate_template(data, pos, tmpl)
        score = _template_score(data, next_pos)
        z_score = sum(_text_score(raw) for raw in (z_values or []))
        pref = 4 if preferred_template == tmpl else 0
        has_z = 1 if "z" in tmpl else 0
        length_bias = -len(tmpl)
        rank = (score, pref, length_bias, z_score, has_z, len(z_values or []), -(next_pos or 0))
        if best_tuple is None or rank > best_tuple:
            best = tmpl
            best_tuple = rank
    return best


def parse_instruction(data, pos, labels, largest_code_addr, template_hints=None):
    start = pos
    if pos + 2 > len(data):
        raise ValueError("脚本在读取 opcode 时提前结束")
    op = struct.unpack_from("<H", data, pos)[0]
    pos += 2
    args = []

    def read_i32():
        nonlocal pos
        if pos + 4 > len(data):
            raise ValueError(f"脚本在读取 int32 时提前结束，offset={pos}")
        value = struct.unpack_from("<i", data, pos)[0]
        pos += 4
        return value

    def read_c():
        nonlocal largest_code_addr
        value = read_i32()
        labels.add(value)
        if value > largest_code_addr:
            largest_code_addr = value
        return ("c", value)

    if op in SPECIAL_OPS:
        count = read_i32()
        if count < 0:
            raise ValueError(f"非法 count={count}，offset={start}")
        if op == 0x00A9:
            for _ in range(count):
                args.append(read_c())
        elif op in (0x00B0, 0x00B4):
            for _ in range(count):
                raw, pos = read_c_string(data, pos)
                args.append(("z", raw))
        elif op == 0x00FD:
            for _ in range(count):
                raw, pos = read_c_string(data, pos)
                args.append(("z", raw))
                args.append(read_c())
        else:
            raise ValueError(f"未知特殊 opcode: 0x{op:04x}")
        pad_bytes = b""
        return start, op, args, pos, largest_code_addr, pad_bytes

    if op not in OPERAND_TEMPLATES:
        raise ValueError(f"未知 V0 opcode: 0x{op:04x} @ 0x{start:05x}")

    templates = get_operand_templates(op)
    preferred_template = None
    if template_hints:
        preferred_template = template_hints.get(op)
    template = _pick_template(data, pos, templates, preferred_template=preferred_template)
    if template is None:
        raise ValueError(f"opcode 模板解析失败: 0x{op:04x} @ 0x{start:05x}")
    if template_hints is not None and len(templates) > 1:
        template_hints[op] = template

    for t in template:
        if t == "h":
            if pos + 2 > len(data):
                raise ValueError(f"脚本在读取 int16 时提前结束，offset={pos}")
            value = struct.unpack_from("<h", data, pos)[0]
            pos += 2
            args.append(("h", value))
        elif t == "i":
            args.append(("i", read_i32()))
        elif t == "c":
            args.append(read_c())
        elif t == "m":
            args.append(("m", read_i32()))
        elif t == "z":
            raw, pos = read_c_string(data, pos)
            args.append(("z", raw))
        else:
            raise ValueError(f"未知 operand type: {t}")
    raw_end = pos
    pos = _advance_past_padding(data, pos)
    pad_bytes = data[raw_end:pos]
    return start, op, args, pos, largest_code_addr, pad_bytes


def resolve_message_token(data, code_end, offset, encoding):
    if not (code_end <= offset < len(data)):
        return None
    end = data.find(b"\x00", offset)
    if end == -1:
        return None
    raw = data[offset:end]
    return bytes_to_token(raw, encoding)


def format_args(args, encoding, data=None, code_end=None, resolve_m_strings=False):
    out = []
    for kind, value in args:
        if kind == "c":
            out.append(fmt_label(value))
        elif kind in ("i", "h"):
            out.append(str(value))
        elif kind == "m":
            if resolve_m_strings and data is not None and code_end is not None:
                token = resolve_message_token(data, code_end, value, encoding)
                if token is not None:
                    out.append(token)
                    continue
            out.append(str(value))
        elif kind == "z":
            out.append(bytes_to_token(value, encoding))
        else:
            raise ValueError(f"未知参数类型: {kind}")
    return ", ".join(out)


def estimate_code_end(data):
    scan_pos = 0
    min_msg_offset = len(data)
    last_terminator_end = 0
    last_good_end = 0
    template_hints = {}
    while scan_pos < len(data) and scan_pos < min_msg_offset:
        try:
            _, op, args, next_pos, _, _ = parse_instruction(data, scan_pos, set(), -1, template_hints=template_hints)
        except Exception:
            if min_msg_offset < len(data):
                return min_msg_offset
            if last_terminator_end > 0:
                return last_terminator_end
            if last_good_end > 0:
                return last_good_end
            return scan_pos
        if next_pos <= scan_pos:
            break
        last_good_end = next_pos
        if op == 0x00C2:
            last_terminator_end = next_pos
        for kind, value in args:
            if kind == "m" and next_pos <= value < len(data):
                if value < min_msg_offset:
                    min_msg_offset = value
        scan_pos = next_pos
    if min_msg_offset < len(data):
        return min_msg_offset
    if last_terminator_end > 0:
        return last_terminator_end
    if last_good_end > 0:
        return last_good_end
    return len(data)


def disassemble_file(path, output_path=None, encoding="cp932", mapping_path=None, exact_mode=False, debug=False):
    op_to_name, _ = load_name_maps(mapping_path)
    with open(path, "rb") as f:
        data = f.read()

    code_end = estimate_code_end(data)
    if code_end < 0:
        code_end = 0
    if code_end > len(data):
        code_end = len(data)

    pos = 0
    labels = set()
    largest_code_addr = -1
    instructions = []
    template_hints = {}
    string_refs = {}

    while pos < code_end:
        try:
            start, op, args, pos, largest_code_addr, pad_bytes = parse_instruction(
                data, pos, labels, largest_code_addr, template_hints=template_hints
            )
        except Exception:
            code_end = pos
            break
        instructions.append((start, op, args, pad_bytes))
        for kind, value in args:
            if kind == "m":
                token = resolve_message_token(data, code_end, value, encoding)
                if token is not None and value not in string_refs:
                    string_refs[value] = token
        if pos > code_end:
            code_end = start
            instructions.pop()
            pos = code_end
            break

    tail = data[code_end:]

    if output_path is None:
        output_path = path + ".bsd"
    with open(output_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("#v0\n")
        f.write("\n")
        has_written_instruction = False
        for addr, op, args, pad_bytes in instructions:
            if addr in labels:
                if has_written_instruction:
                    f.write("\n")
                f.write(f"{fmt_label(addr)}:\n")
            name = op_to_name.get(op, f"f_{op:03x}")
            arg_text = format_args(args, encoding, data=data, code_end=code_end, resolve_m_strings=not exact_mode)
            if arg_text:
                f.write(f"\t{name}({arg_text});\n")
            else:
                f.write(f"\t{name}();\n")
            if exact_mode and pad_bytes:
                pad_hex = pad_bytes.hex()
                f.write(f'#code_padding "{pad_hex}"\n')
            has_written_instruction = True
        if exact_mode and tail:
            f.write("\n")
            _write_exact_tail(f, tail, encoding)
    if debug:
        debug_path = output_path + ".debug.txt"
        _write_debug_file(debug_path, instructions, data, code_end, tail, op_to_name, encoding, string_refs)
    return output_path, len(instructions), code_end, len(tail)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+")
    parser.add_argument("-c", "--encoding", default="cp932")
    parser.add_argument("-m", "--mapping")
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-e", "--exact", action="store_true")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    for pattern in args.files:
        for script in glob.glob(pattern):
            if not os.path.isfile(script):
                continue
            base, ext = os.path.splitext(script)
            if ext:
                continue
            if args.output and len(args.files) == 1 and len(glob.glob(pattern)) == 1:
                out = args.output
            else:
                out = None
            out_path, insn_count, code_end, tail_size = disassemble_file(
                script,
                output_path=out,
                encoding=args.encoding,
                mapping_path=args.mapping,
                exact_mode=args.exact,
                debug=args.debug,
            )
            print(f"Disassembled {script} -> {out_path} (insn={insn_count}, code_end={code_end}, tail={tail_size})")


if __name__ == "__main__":
    main()
