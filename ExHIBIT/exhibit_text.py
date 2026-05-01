import struct
import re
from pathlib import Path

PREFIX_NORMAL_WITH_DISPLAY = "[CWD]"
PREFIX_DISPLAY = "[DSP]"
PREFIX_NORMAL_NO_DISPLAY = "[CND]"

def get_name_table(in_path, out_path, encoding):
    name_table = {}
    with open(in_path, "rb") as f:
        buffer = f.read()

    if buffer[:4] != b"\x00DLR":
        raise ValueError(f"无效的文件格式: {in_path}")

    op_offset = struct.unpack("<I", buffer[8:12])[0]
    op_count = struct.unpack("<I", buffer[12:16])[0]

    with open(out_path, "w", encoding="utf-8") as out:
        current_offset = op_offset
        for index in range(op_count):
            if current_offset + 4 > len(buffer):
                out.write(f"# name table parse truncated at op {index}\n")
                break

            op = struct.unpack("<I", buffer[current_offset:current_offset + 4])[0]
            current_offset += 4

            op_code = op & 0xFFFF
            init_count = (op & 0xFF0000) >> 16
            str_count = (op >> 24) & 0xF

            init_bytes = init_count * 4
            if current_offset + init_bytes > len(buffer):
                out.write(f"# name table init truncated at op {index}\n")
                break
            current_offset += init_bytes

            all_str = []
            for _ in range(str_count):
                if current_offset >= len(buffer):
                    break
                end_offset = current_offset
                while end_offset < len(buffer) and buffer[end_offset] != 0:
                    end_offset += 1
                text = buffer[current_offset:end_offset].decode(encoding, errors="replace")
                all_str.append({"offset": current_offset, "text": text})
                current_offset = end_offset + 1 if end_offset < len(buffer) else end_offset

            if op_code == 0x30 and all_str:
                original_text = all_str[0]["text"]
                out.write(f"{all_str[0]['offset']:08X}:::::{original_text}\n")

                splitted = original_text.split(",")
                if len(splitted) >= 4:
                    try:
                        char_id = int(splitted[0].strip())
                        name_table[char_id] = splitted[3].strip()
                    except ValueError:
                        pass
    return name_table

def dump_text(in_path, out_path, name_table, encoding):
    with open(in_path, "rb") as f:
        buffer = f.read()

    if buffer[:4] != b"\x00DLR":
        return

    op_offset = struct.unpack("<I", buffer[8:12])[0]
    op_count = struct.unpack("<I", buffer[12:16])[0]

    with open(out_path, "w", encoding="utf-8") as out:
        current_offset = op_offset
        for _ in range(op_count):
            op = struct.unpack("<I", buffer[current_offset:current_offset + 4])[0]
            current_offset += 4

            op_code = op & 0xFFFF
            init_count = (op & 0xFF0000) >> 16
            str_count = (op >> 24) & 0xF

            all_init = []
            for _ in range(init_count):
                all_init.append(struct.unpack("<I", buffer[current_offset:current_offset + 4])[0])
                current_offset += 4

            all_str = []
            for _ in range(str_count):
                end_offset = current_offset
                while end_offset < len(buffer) and buffer[end_offset] != 0:
                    end_offset += 1
                text = buffer[current_offset:end_offset].decode(encoding, errors="replace")
                text = text.replace("\n", "[n]")
                all_str.append({"offset": current_offset, "text": text})
                current_offset = end_offset + 1

            if op_code == 0x15:
                for sentence in all_str:
                    out.write(f"{sentence['offset']:08X}:::::{sentence['text']}\n")

            elif op_code == 0x1C:
                normal_name = ""
                if all_init:
                    normal_name = name_table.get(all_init[0], "")

                if len(all_str) >= 2:
                    display_candidate = all_str[0]["text"]
                    if display_candidate == "*" or display_candidate.strip() == "":
                        if normal_name:
                            out.write(f"{PREFIX_NORMAL_NO_DISPLAY}{normal_name}\n")
                        for sentence in all_str:
                            out.write(f"{sentence['offset']:08X}:::::{sentence['text']}\n")
                    else:
                        if normal_name:
                            out.write(f"{PREFIX_NORMAL_WITH_DISPLAY}{normal_name}\n")
                        out.write(f"{all_str[0]['offset']:08X}:::::{PREFIX_DISPLAY}{all_str[0]['text']}\n")
                        for sentence in all_str[1:]:
                            out.write(f"{sentence['offset']:08X}:::::{sentence['text']}\n")
                else:
                    if normal_name:
                        out.write(f"{PREFIX_NORMAL_NO_DISPLAY}{normal_name}\n")
                    for sentence in all_str:
                        out.write(f"{sentence['offset']:08X}:::::{sentence['text']}\n")

            elif op_code in (0x30, 0xBF):
                if all_str:
                    out.write(f"{all_str[0]['offset']:08X}:::::{all_str[0]['text']}\n")

def disasm_bin(in_path, out_path, encoding, name_table=None):
    if name_table is None:
        name_table = {}

    with open(in_path, "rb") as f:
        buffer = f.read()

    with open(out_path, "w", encoding="utf-8") as out:
        if buffer[:4] != b"\x00DLR":
            out.write("# invalid DLR file\n")
            return

        op_offset = struct.unpack("<I", buffer[8:12])[0]
        op_count = struct.unpack("<I", buffer[12:16])[0]
        out.write(f"# file={in_path.name}\n")
        out.write(f"# op_offset=0x{op_offset:08X}\n")
        out.write(f"# op_count={op_count}\n\n")

        current_offset = op_offset
        for index in range(op_count):
            if current_offset + 4 > len(buffer):
                out.write(f"# truncated at op_index={index}\n")
                break

            op_pos = current_offset
            op = struct.unpack("<I", buffer[current_offset:current_offset + 4])[0]
            current_offset += 4

            op_code = op & 0xFFFF
            init_count = (op & 0xFF0000) >> 16
            str_count = (op >> 24) & 0xF

            out.write(f"[OP {index:05d}] OFF=0x{op_pos:08X} CODE=0x{op_code:04X} INIT={init_count} STR={str_count}\n")

            all_init = []
            for init_index in range(init_count):
                if current_offset + 4 > len(buffer):
                    out.write(f"  INIT[{init_index}] = <truncated>\n")
                    current_offset = len(buffer)
                    break
                init_val = struct.unpack("<I", buffer[current_offset:current_offset + 4])[0]
                all_init.append(init_val)
                current_offset += 4

            if all_init:
                init_line = ", ".join(f"0x{v:08X}({v})" for v in all_init)
                out.write(f"  INITS: {init_line}\n")

            decoded_strs = []
            for str_index in range(str_count):
                str_offset = current_offset
                end_offset = current_offset
                while end_offset < len(buffer) and buffer[end_offset] != 0:
                    end_offset += 1
                raw = buffer[current_offset:end_offset]
                text = raw.decode(encoding, errors="replace").replace("\n", "[n]")
                decoded_strs.append((str_index, str_offset, text))
                current_offset = end_offset + 1

            if op_code == 0x001C and all_init:
                speaker_id = all_init[0]
                speaker_name = name_table.get(speaker_id, "")
                if speaker_name and decoded_strs:
                    if len(decoded_strs) >= 2:
                        display_candidate = decoded_strs[0][2]
                        if display_candidate == "*" or display_candidate.strip() == "":
                            decoded_strs[0] = (decoded_strs[0][0], decoded_strs[0][1], f"{PREFIX_NORMAL_NO_DISPLAY}{speaker_name}")
                        else:
                            decoded_strs[0] = (decoded_strs[0][0], decoded_strs[0][1], f"{PREFIX_DISPLAY}{display_candidate}")
                            decoded_strs.insert(0, (-1, decoded_strs[0][1], f"{PREFIX_NORMAL_WITH_DISPLAY}{speaker_name}"))
                    else:
                        decoded_strs.insert(0, (-1, decoded_strs[0][1], f"{PREFIX_NORMAL_NO_DISPLAY}{speaker_name}"))

            for str_index, str_offset, text in decoded_strs:
                if str_index == -1:
                    out.write(f"  STR[NAME] OFF=0x{str_offset:08X}: {text}\n")
                else:
                    out.write(f"  STR[{str_index}] OFF=0x{str_offset:08X}: {text}\n")

            out.write("\n")

def inject_text(bin_path, txt_path, out_path, encoding):
    with open(bin_path, "rb") as f:
        buffer = f.read()

    sentences = []
    with open(txt_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")

            idx = line.find(":::::")
            if idx != -1:
                offset = int(line[:idx], 16)
                text = line[idx + 5:]
                text = text.replace("[n]", "\n")
                text = text.replace(PREFIX_NORMAL_WITH_DISPLAY, "")
                text = text.replace(PREFIX_DISPLAY, "")
                text = text.replace(PREFIX_NORMAL_NO_DISPLAY, "")
                sentences.append({"offset": offset, "text": text})
                continue

            match = re.match(r"\s*STR\[(\d+|NAME)\]\s+OFF=0x([0-9A-Fa-f]+):\s?(.*)$", line)
            if match:
                str_index = match.group(1)
                offset = int(match.group(2), 16)
                text = match.group(3)
                text = text.replace("[n]", "\n")

                if str_index == "NAME":
                    continue
                if text.startswith(PREFIX_NORMAL_WITH_DISPLAY):
                    continue
                if text.startswith(PREFIX_NORMAL_NO_DISPLAY):
                    text = "*"
                elif text.startswith(PREFIX_DISPLAY):
                    text = text[len(PREFIX_DISPLAY):]

                sentences.append({"offset": offset, "text": text})

    deduped = {}
    for sentence in sentences:
        deduped[sentence["offset"]] = sentence["text"]
    sentences = [{"offset": offset, "text": text} for offset, text in sorted(deduped.items())]

    new_buffer = bytearray()
    current_offset = 0

    for sentence in sentences:
        new_buffer.extend(buffer[current_offset:sentence["offset"]])
        new_bytes = sentence["text"].encode(encoding, errors="replace")
        new_buffer.extend(new_bytes)
        new_buffer.append(0)

        end_offset = sentence["offset"]
        while end_offset < len(buffer) and buffer[end_offset] != 0:
            end_offset += 1
        current_offset = end_offset + 1

    if current_offset < len(buffer):
        new_buffer.extend(buffer[current_offset:])

    with open(out_path, "wb") as f:
        f.write(new_buffer)

def process_dump(in_dir, out_dir, encoding, log_cb, status_cb):
    try:
        status_cb("正在提取文本...")
        log_cb("--- 提取开始 ---")
        out_dir.mkdir(parents=True, exist_ok=True)

        defchara_bin = in_dir / "defChara.bin"
        defchara_txt = out_dir / "defChara.txt"
        name_table = {}

        if defchara_bin.exists():
            log_cb(f"解析人名表: {defchara_bin.name}")
            name_table = get_name_table(defchara_bin, defchara_txt, encoding)
        else:
            log_cb("警告: 未找到 defChara.bin")

        count = 0
        for filepath in in_dir.rglob("*.bin"):
            if filepath.name == "defChara.bin":
                continue

            rel_path = filepath.relative_to(in_dir)
            out_path = (out_dir / rel_path).with_suffix(".txt")
            out_path.parent.mkdir(parents=True, exist_ok=True)

            dump_text(filepath, out_path, name_table, encoding)
            log_cb(f"已提取: {rel_path}")
            count += 1

        log_cb(f"--- 提取完成，共处理 {count} 个文件 ---")
        status_cb("文本提取完成")
    except Exception as exc:
        log_cb(f"提取报错: {exc}")
        status_cb("提取失败")

def process_full_disasm(in_dir, out_dir, encoding, log_cb, status_cb):
    try:
        status_cb("正在全量反汇编...")
        log_cb("--- 全量反汇编开始 ---")
        out_dir.mkdir(parents=True, exist_ok=True)

        defchara_bin = in_dir / "defChara.bin"
        name_table = {}
        if defchara_bin.exists():
            try:
                name_table = get_name_table(defchara_bin, out_dir / "defChara.txt", encoding)
                log_cb(f"全量反汇编已加载人名表: {defchara_bin.name}")
            except Exception as exc:
                log_cb(f"加载人名表失败: {exc}")

        count = 0
        for filepath in in_dir.rglob("*.bin"):
            rel_path = filepath.relative_to(in_dir)
            out_path = (out_dir / rel_path).with_suffix(".txt")
            out_path.parent.mkdir(parents=True, exist_ok=True)

            if filepath.name == "defChara.bin":
                get_name_table(filepath, out_path, encoding)
                log_cb(f"已导出人名表: {rel_path}")
            else:
                disasm_bin(filepath, out_path, encoding, name_table)
                log_cb(f"已反汇编: {rel_path}")
            count += 1

        log_cb(f"--- 全量反汇编完成，共处理 {count} 个文件 ---")
        status_cb("全量反汇编完成")
    except Exception as exc:
        log_cb(f"全量反汇编报错: {exc}")
        status_cb("全量反汇编失败")

def process_inject(bin_dir, txt_dir, out_dir, encoding, log_cb, status_cb):
    try:
        status_cb("正在回封文本...")
        log_cb("--- 回封开始 ---")
        out_dir.mkdir(parents=True, exist_ok=True)

        count = 0
        for filepath in bin_dir.rglob("*.bin"):
            rel_path = filepath.relative_to(bin_dir)
            txt_path = (txt_dir / rel_path).with_suffix(".txt")
            out_path = out_dir / rel_path

            if not txt_path.exists():
                log_cb(f"跳过: {rel_path.name} (未找到对应txt)")
                continue

            out_path.parent.mkdir(parents=True, exist_ok=True)
            inject_text(filepath, txt_path, out_path, encoding)
            log_cb(f"已回封: {rel_path}")
            count += 1

        log_cb(f"--- 回封完成，共处理 {count} 个文件 ---")
        status_cb("文本回封完成")
    except Exception as exc:
        log_cb(f"回封报错: {exc}")
        status_cb("回封失败")
