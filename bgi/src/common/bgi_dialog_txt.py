import os
import re
import tempfile

from bgi_dialog_json import (
    extract_dialog_entries,
    extract_push_string_entries_from_bpd,
    _replace_bpd_string_line,
    _replace_push_string,
    _replace_v0_call_string,
    _restore_message_suffix,
    _split_dialog_message_parts
)


RE_TARGET_LINE = re.compile(r'^\s*★(\d{6})([NTS])★(.*)$')
RE_TEXT_ESCAPE = re.compile(r'\\([\\nrt])')


def _escape_txt_text(text):
    return str(text).replace('\\', '\\\\').replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')


def _unescape_txt_text(text):
    def repl(match):
        value = match.group(1)
        if value == 'n':
            return '\n'
        if value == 'r':
            return '\r'
        if value == 't':
            return '\t'
        return '\\'
    return RE_TEXT_ESCAPE.sub(repl, str(text))


def _build_units(entries, split_tip_lines=True):
    units = []
    for entry_index, entry in enumerate(entries):
        has_name = entry["name"] is not None and entry["name"] != ""
        if has_name:
            units.append({
                "type": "N",
                "text": entry["name"],
                "line_index": entry["name_line_index"],
                "arg_index": entry.get("name_arg_index"),
                "entry_index": entry_index,
                "entry_type": entry.get("entry_type")
            })
        msg_type = "S" if entry.get("is_select") else "T"
        parts = _split_dialog_message_parts(entry) if split_tip_lines else [entry["message"]]
        for part_index, part in enumerate(parts):
            units.append({
                "type": msg_type,
                "text": part,
                "line_index": entry["message_line_index"],
                "arg_index": entry.get("message_arg_index"),
                "message_suffix": entry.get("message_suffix", ""),
                "entry_index": entry_index,
                "part_index": part_index,
                "part_count": len(parts),
                "entry_type": entry.get("entry_type")
            })
    return units


def extract_dialog_txt_from_bsd(input_path, output_txt, user_function_names=None):
    with open(input_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    entries = extract_dialog_entries(lines, user_function_names=user_function_names)
    units = _build_units(entries)
    out_lines = []
    for idx, unit in enumerate(units, start=1):
        tag = f"{idx:06d}{unit['type']}"
        src_text = _escape_txt_text(unit["text"])
        out_lines.append(f"☆{tag}☆{src_text}\n")
        out_lines.append(f"★{tag}★{src_text}\n")
        out_lines.append("\n")
    out_dir = os.path.dirname(output_txt)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_txt, 'w', encoding='utf-8') as f:
        f.writelines(out_lines)
    return len(entries), len(units)

def extract_push_string_txt_from_bpd(input_path, output_txt):
    with open(input_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    entries, _ = extract_push_string_entries_from_bpd(lines)
    out_lines = []
    for idx, entry in enumerate(entries, start=1):
        tag = f"{idx:06d}T"
        src_text = _escape_txt_text(entry["text"])
        out_lines.append(f"☆{tag}☆{src_text}\n")
        out_lines.append(f"★{tag}★{src_text}\n")
        out_lines.append("\n")
    out_dir = os.path.dirname(output_txt)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_txt, 'w', encoding='utf-8') as f:
        f.writelines(out_lines)
    return len(entries), len(entries)


def _apply_dialog_txt_units(lines, target_items, units, output_bsd, entry_count):
    message_groups = {}
    tip_name_units = {}
    applied = 0
    for idx, (target, unit) in enumerate(zip(target_items, units), start=1):
        if target["id"] != idx:
            raise Exception(f"TXT item id mismatch at {idx}: got={target['id']:06d} expected={idx:06d}")
        if target["type"] != unit["type"]:
            raise Exception(f"TXT item type mismatch at {idx}: got={target['type']} expected={unit['type']}")
        line_index = unit["line_index"]
        if line_index is None:
            raise Exception(f"TXT item {idx} has no target line")

        new_text = str(target["text"])
        if unit["type"] == "N":
            if unit.get("entry_type") == "tip":
                tip_name_units[unit["entry_index"]] = unit
                continue
            if unit.get("arg_index") is None:
                lines[line_index] = _replace_push_string(lines[line_index], new_text)
            else:
                lines[line_index] = _replace_v0_call_string(lines[line_index], int(unit["arg_index"]), new_text)
            applied += 1
            continue

        entry_index = unit["entry_index"]
        group = message_groups.setdefault(entry_index, {
            "parts": [None] * int(unit.get("part_count", 1)),
            "unit": unit
        })
        group["parts"][int(unit.get("part_index", 0))] = new_text

    for entry_index in sorted(message_groups):
        group = message_groups[entry_index]
        parts = group["parts"]
        if any(part is None for part in parts):
            raise Exception(f"TXT entry {entry_index} is incomplete")
        unit = group["unit"]
        line_index = unit["line_index"]
        new_text = _restore_message_suffix("\n".join(parts), unit.get("message_suffix"))
        if unit.get("arg_index") is None:
            lines[line_index] = _replace_push_string(lines[line_index], new_text)
        else:
            lines[line_index] = _replace_v0_call_string(lines[line_index], int(unit["arg_index"]), new_text)
        applied += 1

        tip_name_unit = tip_name_units.get(entry_index)
        if tip_name_unit is not None:
            tip_name_text = parts[0]
            name_line_index = tip_name_unit["line_index"]
            if tip_name_unit.get("arg_index") is None:
                lines[name_line_index] = _replace_push_string(lines[name_line_index], tip_name_text)
            else:
                lines[name_line_index] = _replace_v0_call_string(
                    lines[name_line_index],
                    int(tip_name_unit["arg_index"]),
                    tip_name_text
                )
            applied += 1

    out_dir = os.path.dirname(output_bsd)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_bsd, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    return entry_count, applied, len(units)


def import_dialog_txt_to_bsd(input_bsd, input_txt, output_bsd, user_function_names=None):
    with open(input_bsd, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    entries = extract_dialog_entries(lines, user_function_names=user_function_names)
    units = _build_units(entries)
    with open(input_txt, 'r', encoding='utf-8') as f:
        txt_lines = [line.rstrip('\r\n') for line in f]
    if txt_lines:
        txt_lines[0] = txt_lines[0].lstrip('\ufeff')

    target_items = []
    for line in txt_lines:
        match = RE_TARGET_LINE.match(line)
        if match:
            target_items.append({
                "id": int(match.group(1)),
                "type": match.group(2),
                "text": _unescape_txt_text(match.group(3)),
            })
    if not target_items:
        out_dir = os.path.dirname(output_bsd)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_bsd, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        return len(entries), 0, len(units)

    if len(target_items) == len(units):
        return _apply_dialog_txt_units(lines, target_items, units, output_bsd, len(entries))
    legacy_units = _build_units(entries, split_tip_lines=False)
    if len(target_items) == len(legacy_units):
        return _apply_dialog_txt_units(lines, target_items, legacy_units, output_bsd, len(entries))

    if len(target_items) != len(units):
        raise Exception(f"TXT 条目数与脚本条目数不一致: txt={len(target_items)} expected={len(units)}")

    applied = 0
    for idx, (target, unit) in enumerate(zip(target_items, units), start=1):
        if target["id"] != idx:
            raise Exception(f"第 {idx} 项编号不匹配: txt={target['id']:06d} expected={idx:06d}")
        if target["type"] != unit["type"]:
            raise Exception(f"第 {idx} 项类型不匹配: txt={target['type']} expected={unit['type']}")
        line_index = unit["line_index"]
        if line_index is None:
            raise Exception(f"第 {idx} 项目标行无效")
        new_text = str(target["text"])
        if unit["type"] in {"T", "S"}:
            new_text = _restore_message_suffix(new_text, unit.get("message_suffix"))
        if unit.get("arg_index") is None:
            lines[line_index] = _replace_push_string(lines[line_index], new_text)
        else:
            lines[line_index] = _replace_v0_call_string(lines[line_index], int(unit["arg_index"]), new_text)
        applied += 1

    out_dir = os.path.dirname(output_bsd)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_bsd, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    return len(entries), applied, len(units)

def import_push_string_txt_to_bpd(input_bpd, input_txt, output_bpd):
    with open(input_bpd, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    entries, string_entries = extract_push_string_entries_from_bpd(lines)
    with open(input_txt, 'r', encoding='utf-8') as f:
        txt_lines = [line.rstrip('\r\n') for line in f]
    if txt_lines:
        txt_lines[0] = txt_lines[0].lstrip('\ufeff')

    target_items = []
    for line in txt_lines:
        match = RE_TARGET_LINE.match(line)
        if match:
            target_items.append({
                "id": int(match.group(1)),
                "type": match.group(2),
                "text": _unescape_txt_text(match.group(3)),
            })
    if not target_items:
        out_dir = os.path.dirname(output_bpd)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_bpd, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        return len(entries), 0, len(entries)

    if len(target_items) != len(entries):
        raise Exception(f"TXT 条目数与 push_string 条目数不一致: txt={len(target_items)} expected={len(entries)}")
    if string_entries and len(string_entries) != len(entries):
        raise Exception(f"BPD 字符串区条目数与 push_string 条目数不一致: strings={len(string_entries)} push={len(entries)}")

    applied = 0
    for idx, (target, entry) in enumerate(zip(target_items, entries), start=1):
        if target["id"] != idx:
            raise Exception(f"第 {idx} 项编号不匹配: txt={target['id']:06d} expected={idx:06d}")
        if target["type"] != 'T':
            raise Exception(f"第 {idx} 项类型不匹配: txt={target['type']} expected=T")
        new_text = str(target["text"])
        lines[entry["line_index"]] = _replace_push_string(lines[entry["line_index"]], new_text)
        if string_entries:
            lines[string_entries[idx - 1]["line_index"]] = _replace_bpd_string_line(lines[string_entries[idx - 1]["line_index"]], new_text)
        applied += 1

    out_dir = os.path.dirname(output_bpd)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_bpd, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    return len(entries), applied, len(entries)


def extract_dialog_txt_from_script(input_script, output_txt, encoding='shift_jis', fallback_encoding='gbk', user_function_names=None):
    import bgidis
    with tempfile.TemporaryDirectory(prefix='bgi_txt_extract_') as td:
        temp_bsd = os.path.join(td, os.path.basename(input_script) + '.bsd')
        bgidis.dis(input_script, encoding=encoding, fallback_encoding=fallback_encoding, output_path=temp_bsd)
        return extract_dialog_txt_from_bsd(temp_bsd, output_txt, user_function_names=user_function_names)


def import_dialog_txt_to_script(
    input_script,
    input_txt,
    output_script,
    encoding='shift_jis',
    fallback_encoding='gbk',
    source_encoding=None,
    source_fallback_encoding=None,
    user_function_names=None
):
    import bgidis
    import bgias
    dis_encoding = source_encoding or encoding
    dis_fallback = source_fallback_encoding or fallback_encoding
    with tempfile.TemporaryDirectory(prefix='bgi_txt_import_') as td:
        base_name = os.path.basename(input_script)
        temp_src_bsd = os.path.join(td, base_name + '.src.bsd')
        temp_out_bsd = os.path.join(td, base_name + '.out.bsd')
        bgidis.dis(input_script, encoding=dis_encoding, fallback_encoding=dis_fallback, output_path=temp_src_bsd)
        count, applied, units = import_dialog_txt_to_bsd(
            temp_src_bsd,
            input_txt,
            temp_out_bsd,
            user_function_names=user_function_names
        )
        bgias.asm(temp_out_bsd, encoding=encoding, fallback_encoding=fallback_encoding, output_path=output_script)
        return count, applied, units
