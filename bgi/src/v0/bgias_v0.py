#!/usr/bin/env python3

import argparse
import base64
import glob
import os
import re
import struct

import asdis
from bgiop_v0 import OPERAND_TEMPLATES, SPECIAL_OPS, get_operand_templates, load_name_maps


RE_B64 = re.compile(r'^b64\("([A-Za-z0-9+/=]*)"\)$')
RE_LABEL = re.compile(r"^L[0-9A-Fa-f]+$")
RE_TAIL = re.compile(r'^#tail_b64\s+"([A-Za-z0-9+/=]*)"$')
RE_STRDATA = re.compile(r'^#strdata\s+"([0-9A-Fa-f]*)"$')
RE_CODE_PADDING = re.compile(r'^#code_padding\s+"([0-9A-Fa-f]*)"$')
RE_ENCODING = re.compile(r'^#encoding\s+"(.+)"$')
RE_TEMPLATE = re.compile(r'^#template\s+0x([0-9A-Fa-f]{1,4})\s+"([hicmz]*)"$')


def parse_string_token(token, encoding):
    token = token.strip()
    m = RE_B64.match(token)
    if m:
        return base64.b64decode(m.group(1).encode("ascii"))
    if token.startswith('"') and token.endswith('"'):
        text = asdis.unescape(token[1:-1])
        return asdis.encode_with_placeholders(
            text,
            lambda chunk: chunk.encode(encoding)
        )
    raise ValueError(f"无效字符串参数: {token}")


def split_args(arg_text):
    arg_text = arg_text.strip()
    if not arg_text:
        return []
    tmp = arg_text.replace("\\\\", asdis.backslash_replace).replace('\\"', asdis.quote_replace)
    quotes = asdis.get_quotes(tmp, 0)
    if len(quotes) % 2 != 0:
        raise ValueError("参数字符串引号不匹配")
    tmp = asdis.replace_quote_commas(tmp, quotes)
    parts = [x.strip() for x in tmp.split(",")]
    return [p.replace(asdis.comma_replace, ",").replace(asdis.quote_replace, '\\"').replace(asdis.backslash_replace, "\\\\") for p in parts]


def parse_instruction_line(line):
    m = asdis.re_instr.match(line)
    if not m:
        raise ValueError(f"无效指令格式: {line}")
    name = m.group(1)
    args = split_args(m.group(2))
    return name, args


def parse_source(path):
    entries = []
    labels = {}
    str_data_blob = b""
    encoding = "cp932"
    templates = {}
    with open(path, "r", encoding="utf-8") as f:
        raw_lines = f.read().splitlines()

    for idx, line in enumerate(raw_lines, start=1):
        line = asdis.remove_comment(line.strip())
        if not line:
            continue
        if line == "#v0":
            continue
        em = RE_ENCODING.match(line)
        if em:
            encoding = em.group(1).strip()
            continue
        mm = RE_TEMPLATE.match(line)
        if mm:
            templates[int(mm.group(1), 16)] = mm.group(2)
            continue
        tm = RE_TAIL.match(line)
        if tm:
            str_data_blob += base64.b64decode(tm.group(1).encode("ascii"))
            continue
        sm = RE_STRDATA.match(line)
        if sm:
            str_data_blob += bytes.fromhex(sm.group(1))
            continue
        pm = RE_CODE_PADDING.match(line)
        if pm:
            entries.append(("codepad", bytes.fromhex(pm.group(1)), idx))
            continue
        try:
            str_data_blob += parse_string_token(line, encoding) + b"\x00"
            continue
        except Exception:
            pass
        lm = asdis.re_label.match(line)
        if lm:
            labels[lm.group(1)] = None
            entries.append(("label", lm.group(1), idx))
            continue
        name, args = parse_instruction_line(line)
        entries.append(("insn", (name, args), idx))
    return entries, labels, str_data_blob, encoding, templates


def resolve_op(name, name_to_op):
    if name in name_to_op:
        return name_to_op[name]
    if name.startswith("f_"):
        try:
            return int(name[2:], 16)
        except Exception:
            pass
    raise ValueError(f"无法识别函数名: {name}")


def parse_m_arg(token, encoding):
    if RE_LABEL.match(token):
        return None, token
    try:
        return int(token, 0), None
    except Exception:
        raw = parse_string_token(token, encoding)
        return raw, None


def pick_template_for_assembly(op, args, encoding, custom_templates):
    if op in custom_templates:
        return custom_templates[op]
    templates = get_operand_templates(op)
    if not templates:
        return None
    saw_length_match = False
    last_error = None
    for tmpl in templates:
        if len(args) != len(tmpl):
            continue
        saw_length_match = True
        ok = True
        for t, token in zip(tmpl, args):
            try:
                if t == "h":
                    int(token, 0)
                elif t in ("i", "m"):
                    if t == "m":
                        parse_m_arg(token, encoding)
                    else:
                        int(token, 0)
                elif t == "c":
                    if not RE_LABEL.match(token):
                        int(token, 0)
                elif t == "z":
                    parse_string_token(token, encoding)
                else:
                    ok = False
                    break
            except Exception as e:
                last_error = e
                ok = False
                break
        if ok:
            return tmpl
    if saw_length_match and last_error is not None:
        raise ValueError(f"参数解析失败: {last_error}")
    return None


def measure_with_labels(entries, name_to_op, encoding, custom_templates):
    pos = 0
    labels = {}
    parsed = []
    for kind, payload, line_no in entries:
        if kind == "label":
            labels[payload] = pos
            parsed.append((kind, payload, line_no))
            continue
        if kind == "codepad":
            parsed.append((kind, payload, line_no))
            pos += len(payload)
            continue
        name, args = payload
        op = resolve_op(name, name_to_op)
        if op in OPERAND_TEMPLATES or op in custom_templates:
            try:
                tmpl = pick_template_for_assembly(op, args, encoding, custom_templates)
            except Exception as e:
                raise ValueError(f"line {line_no}: {e}")
            if tmpl is None:
                raise ValueError(f"line {line_no}: 参数数量不匹配")
            size = 2
            for t, token in zip(tmpl, args):
                if t == "h":
                    int(token, 0)
                    size += 2
                elif t in ("i", "m"):
                    if t == "m":
                        parse_m_arg(token, encoding)
                    else:
                        int(token, 0)
                    size += 4
                elif t == "c":
                    if RE_LABEL.match(token):
                        pass
                    else:
                        int(token, 0)
                    size += 4
                elif t == "z":
                    size += len(parse_string_token(token, encoding)) + 1
        elif op in SPECIAL_OPS:
            if op == 0x00A9:
                for token in args:
                    if RE_LABEL.match(token):
                        pass
                    else:
                        int(token, 0)
                size = 2 + 4 + 4 * len(args)
            elif op in (0x00B0, 0x00B4):
                size = 2 + 4
                for token in args:
                    size += len(parse_string_token(token, encoding)) + 1
            elif op == 0x00FD:
                if len(args) % 2 != 0:
                    raise ValueError(f"line {line_no}: f_0fd 参数数量必须为偶数")
                size = 2 + 4
                for i in range(0, len(args), 2):
                    size += len(parse_string_token(args[i], encoding)) + 1
                    token = args[i + 1]
                    if RE_LABEL.match(token):
                        pass
                    else:
                        int(token, 0)
                    size += 4
            else:
                raise ValueError(f"line {line_no}: 未实现特殊 opcode 0x{op:04x}")
        else:
            raise ValueError(f"line {line_no}: 不支持 opcode 0x{op:04x}")
        parsed.append((kind, (op, args), line_no))
        pos += size
    return parsed, labels, pos


def label_or_int(token, labels):
    if RE_LABEL.match(token):
        if token not in labels:
            raise ValueError(f"未定义标签: {token}")
        return labels[token]
    return int(token, 0)


def assemble(path, output_path=None, mapping_path=None, encoding_override=None):
    _, name_to_op = load_name_maps(mapping_path)
    entries, _, str_data_blob, source_encoding, custom_templates = parse_source(path)
    encoding = encoding_override or source_encoding
    parsed, labels, code_size = measure_with_labels(entries, name_to_op, encoding, custom_templates)

    if output_path is None:
        output_path = os.path.splitext(path)[0]

    final_blob = str_data_blob
    string_map = {}

    with open(output_path, "wb") as f:
        for kind, payload, line_no in parsed:
            if kind == "label":
                continue
            if kind == "codepad":
                f.write(payload)
                continue
            op, args = payload
            f.write(struct.pack("<H", op))
            if op in OPERAND_TEMPLATES or op in custom_templates:
                try:
                    tmpl = pick_template_for_assembly(op, args, encoding, custom_templates)
                except Exception as e:
                    raise ValueError(f"line {line_no}: {e}")
                if tmpl is None:
                    raise ValueError(f"line {line_no}: 参数数量不匹配")
                for t, token in zip(tmpl, args):
                    if t == "h":
                        f.write(struct.pack("<h", int(token, 0)))
                    elif t in ("i", "m"):
                        if t == "m":
                            m_val, m_label = parse_m_arg(token, encoding)
                            if m_label is not None:
                                f.write(struct.pack("<i", label_or_int(m_label, labels)))
                            elif isinstance(m_val, int):
                                f.write(struct.pack("<i", m_val))
                            else:
                                raw = m_val
                                key = raw
                                if key in string_map:
                                    off = string_map[key]
                                else:
                                    encoded = raw + b"\x00"
                                    found = final_blob.find(encoded)
                                    if found != -1:
                                        off = code_size + found
                                    else:
                                        off = code_size + len(final_blob)
                                        final_blob += encoded
                                    string_map[key] = off
                                f.write(struct.pack("<i", off))
                        else:
                            f.write(struct.pack("<i", int(token, 0)))
                    elif t == "c":
                        f.write(struct.pack("<i", label_or_int(token, labels)))
                    elif t == "z":
                        raw = parse_string_token(token, encoding)
                        f.write(raw + b"\x00")
                    else:
                        raise ValueError(f"line {line_no}: 未知参数类型 {t}")
            elif op == 0x00A9:
                f.write(struct.pack("<i", len(args)))
                for token in args:
                    f.write(struct.pack("<i", label_or_int(token, labels)))
            elif op in (0x00B0, 0x00B4):
                f.write(struct.pack("<i", len(args)))
                for token in args:
                    raw = parse_string_token(token, encoding)
                    f.write(raw + b"\x00")
            elif op == 0x00FD:
                f.write(struct.pack("<i", len(args) // 2))
                for i in range(0, len(args), 2):
                    raw = parse_string_token(args[i], encoding)
                    f.write(raw + b"\x00")
                    f.write(struct.pack("<i", label_or_int(args[i + 1], labels)))
            else:
                raise ValueError(f"line {line_no}: 不支持 opcode 0x{op:04x}")
        f.write(final_blob)
    return output_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+")
    parser.add_argument("-m", "--mapping")
    parser.add_argument("-c", "--encoding")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    for pattern in args.files:
        matched = [p for p in glob.glob(pattern) if os.path.isfile(p) and p.endswith(".bsd")]
        for script in matched:
            if args.output and len(args.files) == 1 and len(matched) == 1:
                out = args.output
            else:
                out = None
            out_path = assemble(script, output_path=out, mapping_path=args.mapping, encoding_override=args.encoding)
            print(f"Assembled {script} -> {out_path}")


if __name__ == "__main__":
    main()
