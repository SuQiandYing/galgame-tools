# -*- coding: utf-8 -*-
import glob
import os
import struct
import json
import re
import sys
import unicodedata
import traceback
import shutil
import io
from pathlib import Path
from threading import Thread
from tkinter import (
    Tk, ttk, Button, Label, Entry, Frame, filedialog,
    StringVar, Radiobutton, END, messagebox, font as tkFont,
    Toplevel, BooleanVar, Checkbutton, Menu, Listbox, EXTENDED
)
from tkinter.scrolledtext import ScrolledText

# --- 依赖处理: 尝试导入 tkinterdnd2 以支持拖放功能 ---
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_SUPPORT = True
except ImportError:
    DND_SUPPORT = False
    class TkinterDnD:
        class Tk(Tk): pass

# =============================================================================
# BGI BP Script Core Logic (BP脚本核心逻辑)
# [核心功能代码保持不变]
# =============================================================================
def bp_escape(text):
    """处理文本中的转义字符，用于导出。"""
    return text.replace('\a', '\\a').replace('\b', '\\b').replace('\t', '\\t').replace('\n', '\\n').replace('\v', '\\v').replace('\f', '\\f').replace('\r', '\\r')

def bp_unescape(text):
    """还原文本中的转义字符，用于导入。"""
    return text.replace('\\a', '\a').replace('\\b', '\b').replace('\\t', '\t').replace('\\n', '\n').replace('\\v', '\v').replace('\\f', '\f').replace('\\r', '\r')

def bp_get_section_boundary(data):
    """在BP脚本中寻找代码区和文本区的边界。"""
    pos = -1
    while True:
        res = data.find(b'\x17', pos + 1)
        if res == -1: break
        pos = res
    return (pos + 0x10) >> 4 << 4

def bp_split_data(data):
    """将BP脚本数据分割为文件头、代码区和文本区。"""
    section_boundary = bp_get_section_boundary(data)
    hdr_size, = struct.unpack('<I', data[0:4])
    hdr_bytes = data[:hdr_size]
    code_bytes = data[hdr_size:section_boundary]
    text_bytes = data[section_boundary:]
    return hdr_bytes, code_bytes, text_bytes

def bp_get_text_section(text_bytes, senc):
    """从文本区字节中解析出地址和对应的字符串。"""
    strings = text_bytes.split(b'\x00')
    addrs = [0]
    pos = 0
    for string in strings[:-1]:
        pos += len(string) + 1
        addrs.append(pos)
    texts = [s.decode(senc, errors='ignore') for s in strings]
    return {addr: text for addr, text in zip(addrs, texts) if text}

def bp_get_code_section(code_bytes, text_section):
    """从代码区字节中解析出引用文本的指令和地址。"""
    pos = -1
    code_size = len(code_bytes)
    code_section = {}
    id_counter = 1
    texts_map = {}
    while True:
        res = code_bytes.find(b'\x05', pos + 1)
        if res == -1: break
        if res + 3 > len(code_bytes): continue
        word, = struct.unpack('<H', code_bytes[res + 1:res + 3])
        text_addr = word + res - code_size
        if text_addr in text_section:
            text = text_section[text_addr]
            if text not in texts_map:
                texts_map[text] = id_counter
                id_counter += 1
            code_section[res] = (text, texts_map[text])
        pos = res
    return code_section

def bp_dump_text(fo, slang, dlang, id, text, dcopy):
    """将提取的文本按指定格式写入文件。"""
    fo.write(f'<{slang}{id:04d}>{text}\n')
    for lang in dlang:
        fo.write(f'<{lang}{id:04d}>{text if dcopy else ""}\n')
    fo.write('\n')

def _bp_dump_single_file(input_path, output_path, settings):
    """处理单个BP脚本文件的文本导出。"""
    data = open(input_path, 'rb').read()
    hdr_bytes, code_bytes, text_bytes = bp_split_data(data)
    text_section = bp_get_text_section(text_bytes, settings['senc'])
    code_section = bp_get_code_section(code_bytes, text_section)
    with open(output_path, 'w', encoding=settings['denc']) as fo:
        text_set = set()
        for addr in sorted(code_section):
            text, id = code_section[addr]
            if settings['dump_mode'] == 'unique' and text in text_set: continue
            bp_dump_text(fo, settings['slang'], settings['dlang'], id, bp_escape(text), settings['dcopy'])
            text_set.add(text)

def bp_get_text_from_file(fi, ilang):
    """从翻译后的文本文件中读取指定语言的文本。"""
    texts = {}
    re_line = re.compile(r'<(\w\w)(\d+?)>(.*)')
    for line in fi:
        match = re_line.match(line.rstrip('\r\n'))
        if match:
            lang, id_str, text = match.groups()
            if lang == ilang: texts[int(id_str)] = bp_unescape(text)
    return texts

def _bp_insert_single_file(input_bp, input_txt, output_bp, settings):
    """将翻译后的文本插回单个BP脚本文件。"""
    data = open(input_bp, 'rb').read()
    hdr_bytes, code_bytes, text_bytes_orig = bp_split_data(data)
    text_section = bp_get_text_section(text_bytes_orig, settings['senc'])
    code_section = bp_get_code_section(code_bytes, text_section)
    with open(input_txt, 'r', encoding=settings['denc']) as fi:
        texts = bp_get_text_from_file(fi, settings['ilang'])
    code_bytes_mut = bytearray(code_bytes)
    text_bytes_new = b''
    code_size = len(code_bytes_mut)
    text_dict, offset = {}, 0
    for addr in sorted(code_section):
        orig_text, id = code_section[addr]
        if settings['insert_mode'] == 'unique' and orig_text in text_dict:
            _, doffset = text_dict[orig_text]
            struct.pack_into('<H', code_bytes_mut, addr + 1, doffset + code_size - addr)
        else:
            new_text = texts.get(id, orig_text)
            nbytes = new_text.encode(settings['ienc']) + b'\x00'
            text_bytes_new += nbytes
            if settings['insert_mode'] == 'unique': text_dict[orig_text] = (id, offset)
            struct.pack_into('<H', code_bytes_mut, addr + 1, offset + code_size - addr)
            offset += len(nbytes)
    with open(output_bp, 'wb') as fo:
        fo.write(hdr_bytes); fo.write(code_bytes_mut); fo.write(text_bytes_new)

# =============================================================================
# BGI Script Core Logic - 方案A (BGI脚本核心逻辑)
# =============================================================================
def core_dump_scripts(input_dir, output_dir, log_callback):
    """(方案A-步骤1) 从BGI脚本目录批量导出文本。"""
    log_callback("--- 开始文本导出任务 (方案A) ---", "INFO")
    if not os.path.isdir(input_dir): log_callback(f"错误: 输入目录 '{input_dir}' 不存在。", "ERROR"); return False
    if not os.path.isdir(output_dir): os.makedirs(output_dir); log_callback(f"创建输出目录: '{output_dir}'", "INFO")
    files = [f for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))]
    if not files: log_callback("输入目录为空，任务中止。", "WARN"); return False
    for file in files:
        sc_path = os.path.join(input_dir, file)
        ex_path = os.path.join(output_dir, file + ".txt")
        log_callback(f"正在处理: {file}", "INFO")
        try:
            with open(sc_path, 'rb') as sc_file:
                if sc_file.read(20) != b'BurikoCompiledScript': log_callback(f"警告: {file} 不是有效的脚本文件，已跳过。", "WARN"); continue
                sc_file.seek(0); test = b''
                while test != b'\x01\x00\x00\x00': test = sc_file.read(4)
                if not test: continue
                sc_file.seek(-4, 1); offset = sc_file.tell()
                while test != b'\x03\x00\x00\x00': test = sc_file.read(4)
                if not test: continue
                locate = struct.unpack('<L', sc_file.read(4))[0]
                sc_file.seek(locate + offset); text_in_file = sc_file.read(); sc_file.seek(offset)
                end = locate + offset
                with open(ex_path, 'w', encoding="UTF-16") as tx_file:
                    while sc_file.tell() < end:
                        test = sc_file.read(4)
                        if test == b'\x03\x00\x00\x00':
                            address = sc_file.tell()
                            locate_ptr = struct.unpack('<L', sc_file.read(4))[0]
                            text_locate = locate_ptr - locate
                            if not (0 <= text_locate < len(text_in_file)): continue
                            end_of_string = text_in_file.find(b'\x00', text_locate)
                            if end_of_string == -1: continue
                            text_bytes = text_in_file[text_locate:end_of_string]
                            try:
                                text_utf = text_bytes.decode('CP932')
                                if text_utf and unicodedata.east_asian_width(text_utf[0]) != 'Na':
                                    tx_file.write(f'○{address:06d}○{text_utf}\n●{address:06d}●{text_utf}\n\n')
                            except (UnicodeDecodeError, IndexError): continue
            log_callback(f"成功导出: {ex_path}", "SUCCESS")
        except Exception as e: log_callback(f"处理 {file} 时发生错误: {e}\n{traceback.format_exc()}", "ERROR")
    log_callback("--- 文本导出任务 (方案A) 完成 ---", "INFO")
    return True

def _get_clean_lines_from_bgi_txt(filepath, log_callback):
    """从方案A导出的txt文件中提取出所有有效的原文行。"""
    try:
        with open(filepath, 'r', encoding='utf-16') as f: lines = f.readlines()
    except Exception as e: log_callback(f"读取文件 {os.path.basename(filepath)} 失败: {e}", "ERROR"); return []
    control_char_re = re.compile(r'[\u0000-\u001F\u007F-\u009F]')
    simple_lines = []
    for line in lines:
        if line.startswith('●'):
            match = re.match(r'●\d{6}●(.*)', line)
            if match:
                content = control_char_re.sub('', match.group(1)).rstrip('\r\n')
                simple_lines.append(content)
    return simple_lines

def extract_dialogue(filepath, mode, log_callback):
    """(方案A-步骤2) 根据选定模式(A/B)组合原文行，生成纯净对话文本。"""
    simple_lines = _get_clean_lines_from_bgi_txt(filepath, log_callback)
    if not simple_lines: return ""
    formatted_lines, i = [], 0
    DIALOGUE_SYMBOLS = ('「', '（', '『')
    
    if mode == 'B': # 对话在前，人名在后
        while i < len(simple_lines):
            current_line = simple_lines[i]
            next_line = simple_lines[i+1] if (i + 1) < len(simple_lines) else None
            is_dialogue = current_line.startswith(DIALOGUE_SYMBOLS)
            is_next_line_speaker = next_line is not None and not next_line.startswith(DIALOGUE_SYMBOLS) and len(next_line) < 15 and next_line.strip() != ''
            if is_dialogue and is_next_line_speaker:
                formatted_lines.append(f"{next_line}{current_line}"); i += 2
            else: formatted_lines.append(current_line); i += 1
        return "\n".join(formatted_lines)
    elif mode == 'A': # 人名在前，对话在后
        ignore_patterns = [re.compile(p) for p in [r'^\s*$', r'^_', r'\.txt$', r'^#[0-9a-fA-F]{6}$', r'^[a-zA-Z0-9_]+\d*[a-zA-Z]?$']]
        current_speaker = None
        for content in simple_lines:
            if any(p.search(content) for p in ignore_patterns if content): continue
            is_dialogue = content.startswith(DIALOGUE_SYMBOLS) and content.endswith(('」', '）', '』'))
            if is_dialogue:
                formatted_lines.append(f"{current_speaker or ''}{content}"); current_speaker = None
            elif len(content) < 15 and not any(p in content for p in ['。', '、', '…', '？', '！']):
                if current_speaker: formatted_lines.append(current_speaker)
                current_speaker = content
            else:
                if current_speaker: formatted_lines.append(current_speaker); current_speaker = None
                formatted_lines.append(content)
        if current_speaker: formatted_lines.append(current_speaker)
        return "\n".join(formatted_lines)
    return ""

def generate_json_from_bgi_txt(filepath, mode, log_callback):
    """(方案A-步骤2) 将提取的文本转换为JSON格式。"""
    simple_lines = _get_clean_lines_from_bgi_txt(filepath, log_callback)
    if not simple_lines: return [], "文件为空或未提取到有效行。"
    json_result, i = [], 0
    DIALOGUE_SYMBOLS = ('「', '（', '『')
    
    if mode == 'B':
        while i < len(simple_lines):
            current_line = simple_lines[i]
            next_line = simple_lines[i+1] if (i + 1) < len(simple_lines) else None
            is_dialogue = current_line.startswith(DIALOGUE_SYMBOLS)
            is_next_line_speaker = next_line is not None and not next_line.startswith(DIALOGUE_SYMBOLS) and len(next_line) < 15 and next_line.strip() != ''
            if is_dialogue and is_next_line_speaker: json_result.append({"name": next_line, "message": current_line}); i += 2
            else: json_result.append({"message": current_line}); i += 1
    elif mode == 'A':
        ignore_patterns = [re.compile(p) for p in [r'^\s*$', r'^_', r'\.txt$', r'^#[0-9a-fA-F]{6}$', r'^[a-zA-Z0-9_]+\d*[a-zA-Z]?$']]
        current_speaker = None
        for content in simple_lines:
            if any(p.search(content) for p in ignore_patterns if content): continue
            is_dialogue = content.startswith(DIALOGUE_SYMBOLS) and content.endswith(('」', '）', '』'))
            if is_dialogue:
                item = {"name": current_speaker, "message": content} if current_speaker else {"message": content}
                json_result.append(item); current_speaker = None
            elif len(content) < 15 and not any(p in content for p in ['。', '、', '…', '？', '！']):
                if current_speaker: json_result.append({"message": current_speaker})
                current_speaker = content
            else:
                if current_speaker: json_result.append({"message": current_speaker}); current_speaker = None
                json_result.append({"message": content})
        if current_speaker: json_result.append({"message": current_speaker})
    return json_result, None

def core_process_text(input_dir, output_dir, mode, format_type, log_callback):
    """(方案A-步骤2) 批量处理导出的文本，生成纯净文本或JSON。"""
    log_callback("--- 开始纯文本提取任务 (方案A) ---", "INFO")
    if not os.path.isdir(input_dir): log_callback(f"错误: 输入目录 '{input_dir}' 不存在。", "ERROR"); return False
    if not os.path.isdir(output_dir): os.makedirs(output_dir); log_callback(f"创建输出目录: '{output_dir}'", "INFO")
    for file in os.listdir(input_dir):
        if not file.endswith(".txt"): continue
        input_path = os.path.join(input_dir, file)
        log_callback(f"正在处理: {file}", "INFO")
        try:
            if format_type == 'txt':
                output_content = extract_dialogue(input_path, mode, log_callback)
                output_path = os.path.join(output_dir, file)
                with open(output_path, 'w', encoding='utf-8') as f: f.write(output_content)
                log_callback(f"成功提取: {output_path}", "SUCCESS")
            elif format_type == 'json':
                output_content, err = generate_json_from_bgi_txt(input_path, mode, log_callback)
                if err: log_callback(f"处理 {file} 时出错: {err}", "WARN"); continue
                output_path = os.path.join(output_dir, file.replace('.txt', '.json'))
                with open(output_path, 'w', encoding='utf-8') as f: json.dump(output_content, f, ensure_ascii=False, indent=2)
                log_callback(f"成功提取: {output_path}", "SUCCESS")
        except Exception as e: log_callback(f"处理 {file} 时发生严重错误: {e}\n{traceback.format_exc()}", "ERROR")
    log_callback("--- 纯文本提取任务 (方案A) 完成 ---", "INFO")

def core_reconstruct_files(original_dump_dir, translated_clean_dir, output_dir, mode, log_callback):
    """(方案A-步骤3) 将翻译后的纯文本回填到中间文件中。"""
    log_callback("--- 开始文本回填任务 (方案A) ---", "INFO")
    if not all(os.path.isdir(d) for d in [original_dump_dir, translated_clean_dir]): log_callback("错误: 请确保所有输入目录都存在。", "ERROR"); return
    if not os.path.isdir(output_dir): os.makedirs(output_dir); log_callback(f"创建输出目录: '{output_dir}'", "INFO")
    dialogue_re = re.compile(r'^(.*?)(「.*」|『.*』|（.*）)$')
    for file in os.listdir(original_dump_dir):
        if not file.endswith(".txt"): continue
        original_dump_path = os.path.join(original_dump_dir, file)
        translated_clean_path = os.path.join(translated_clean_dir, file)
        output_path = os.path.join(output_dir, file)
        if not os.path.exists(translated_clean_path): log_callback(f"警告: 找不到对应的翻译纯文本 {translated_clean_path}，跳过 {file}。", "WARN"); continue
        log_callback(f"正在回填: {file}", "INFO")
        try:
            original_combined_text = extract_dialogue(original_dump_path, mode, log_callback)
            original_combined_lines = [line for line in original_combined_text.split('\n') if line.strip() or line == '']
            with open(translated_clean_path, 'r', encoding='utf-8') as f: translated_lines = [line.strip('\r\n') for line in f.readlines()]
            if len(original_combined_lines) != len(translated_lines): log_callback(f"错误: {file} 的原文行数({len(original_combined_lines)})与译文行数({len(translated_lines)})不匹配！请检查。", "ERROR"); continue
            translation_map = dict(zip(original_combined_lines, translated_lines))
            original_uncombined_lines = _get_clean_lines_from_bgi_txt(original_dump_path, log_callback)
            deconstructed_translated_lines, i = [], 0
            DIALOGUE_SYMBOLS = ('「', '（', '『')
            while i < len(original_uncombined_lines):
                line1, line2 = original_uncombined_lines[i], original_uncombined_lines[i + 1] if (i + 1) < len(original_uncombined_lines) else None
                combined_key = f"{line2}{line1}" if mode == 'B' and line1.startswith(DIALOGUE_SYMBOLS) and line2 is not None and not line2.startswith(DIALOGUE_SYMBOLS) and len(line2) < 15 and line2.strip() != '' else line1
                is_combined = combined_key != line1
                if combined_key in translation_map:
                    translated_combined = translation_map[combined_key]
                    if is_combined:
                        match = dialogue_re.match(translated_combined)
                        if match: deconstructed_translated_lines.extend([match.group(2), match.group(1)])
                        else: deconstructed_translated_lines.extend([translated_combined, line2])
                    else: deconstructed_translated_lines.append(translated_combined)
                else: deconstructed_translated_lines.append(line1)
                i += 2 if is_combined else 1
            with open(original_dump_path, 'r', encoding='utf-16') as f_orig, open(output_path, 'w', encoding='utf-16') as f_out:
                uncombined_idx = 0
                for line in f_orig:
                    if line.strip().startswith('●'):
                        prefix_match = re.match(r'(●\d{6}●)', line.strip())
                        if prefix_match:
                            prefix = prefix_match.group(1)
                            if uncombined_idx < len(deconstructed_translated_lines):
                                f_out.write(f"{prefix}{deconstructed_translated_lines[uncombined_idx]}\n"); uncombined_idx += 1
                            else: f_out.write(line)
                        else: f_out.write(line)
                    else: f_out.write(line)
            log_callback(f"成功回填: {output_path}", "SUCCESS")
        except Exception as e: log_callback(f"回填 {file} 时发生严重错误: {e}\n{traceback.format_exc()}", "ERROR")
    log_callback("--- 文本回填任务 (方案A) 完成 ---", "INFO")

def _transcode(uni, encoding):
    """将Unicode字符串安全地转码为指定编码。"""
    return "".join(ch if len(ch.encode(encoding, 'ignore')) > 0 else "·" for ch in uni).encode(encoding)

def core_repack_scripts(original_scripts_dir, translated_texts_dir, output_dir, encoding, log_callback):
    """(方案A-步骤4) 将回填后的文本封包成游戏可执行的脚本文件。"""
    log_callback(f"--- 开始脚本封包任务 (方案A) (编码: {encoding}) ---", "INFO")
    if not all(os.path.isdir(d) for d in [original_scripts_dir, translated_texts_dir]): log_callback("错误: 请确保所有输入目录都存在。", "ERROR"); return
    if not os.path.isdir(output_dir): os.makedirs(output_dir); log_callback(f"创建输出目录: '{output_dir}'", "INFO")
    for file in os.listdir(original_scripts_dir):
        sc_path, tx_path, cn_path = os.path.join(original_scripts_dir, file), os.path.join(translated_texts_dir, file + ".txt"), os.path.join(output_dir, file)
        if not os.path.isfile(sc_path): continue
        if not os.path.isfile(tx_path): log_callback(f"警告: 找不到对应的翻译文件 {tx_path}，跳过 {file}。", "WARN"); continue
        log_callback(f"正在封包: {file}", "INFO")
        try:
            with open(sc_path, 'rb') as f:
                if f.read(20) != b'BurikoCompiledScript': log_callback(f"警告: {file} 不是有效的脚本文件。", "WARN"); continue
                f.seek(0); test = b''
                while test != b'\x01\x00\x00\x00': test = f.read(4)
                if not test: continue
                f.seek(-4, 1); offset = f.tell(); f.seek(0); original_content = f.read()
            with open(cn_path, 'wb') as f: f.write(original_content); new_offset = f.tell()
            text_to_file, processed_lines = b"", set()
            with open(tx_path, 'r', encoding='utf-16-le') as tx_file, open(cn_path, 'rb+') as cn_file:
                for line in tx_file:
                    tx_temp = line.strip()
                    if not tx_temp or tx_temp[0] != '●' or tx_temp in processed_lines: continue
                    processed_lines.add(tx_temp)
                    address, text = int(tx_temp[1:7]), tx_temp[8:]
                    encoded_text = _transcode(text, encoding) + b'\x00'
                    try: locate_in_block = text_to_file.index(encoded_text)
                    except ValueError: locate_in_block = len(text_to_file); text_to_file += encoded_text
                    locate = locate_in_block + new_offset - offset
                    cn_file.seek(address); cn_file.write(struct.pack('<L', locate))
                cn_file.seek(new_offset); cn_file.write(text_to_file)
            log_callback(f"成功封包: {cn_path}", "SUCCESS")
        except Exception as e: log_callback(f"封包 {file} 时发生错误: {e}\n{traceback.format_exc()}", "ERROR")
    log_callback("--- 脚本封包任务 (方案A) 完成 ---", "INFO")

# ==============================================================================
# Sysgrp <-> BMP 图像转换核心逻辑
# ==============================================================================
def flip_vertical(bits: bytes, width: int, depth: int) -> bytes:
    """垂直翻转图像的像素数据。"""
    bytes_per_pixel = depth // 8; stride = width * bytes_per_pixel
    if stride == 0: return bits
    rows = [bits[i:i + stride] for i in range(0, len(bits), stride)]; rows.reverse()
    return b"".join(rows)

def build_bmp(bits: bytes, width: int, height: int, depth: int) -> bytes:
    """根据像素数据构建一个完整的BMP文件。"""
    if depth not in [24, 32]: raise ValueError(f"不支持的位深度: {depth}-bit。")
    bytes_per_pixel = depth // 8; raw_stride = width * bytes_per_pixel
    padded_stride = (raw_stride + 3) & ~3; padding = b'\x00' * (padded_stride - raw_stride)
    padded_bits = b"".join(bits[i:i + raw_stride] + padding for i in range(0, len(bits), raw_stride)) if padding else bits
    image_size = len(padded_bits); bmp_offset = 54; file_size = image_size + bmp_offset
    header = b'BM' + struct.pack('<IHHI', file_size, 0, 0, bmp_offset)
    dib_header = struct.pack('<IiiHHIIIIII', 40, width, height, 1, depth, 0, image_size, 0, 0, 0, 0)
    return header + dib_header + padded_bits

def convert_sysgrp_to_bmp(sysgrp_file: str, output_file: str):
    """将sysgrp格式文件转换为BMP。"""
    with open(sysgrp_file, 'rb') as f:
        try: width, height, depth = struct.unpack('<hhh', f.read(6))
        except struct.error: raise ValueError("文件太小，无法读取图像头。")
        if not (width > 0 and height > 0 and depth > 0): raise ValueError(f"无效的图像尺寸或深度: W={width}, H={height}, D={depth}.")
        f.seek(0x10); bits = f.read()
    flipped_bits = flip_vertical(bits, width, depth)
    bmp_data = build_bmp(flipped_bits, width, height, depth)
    with open(output_file, 'wb') as f: f.write(bmp_data)

def convert_bmp_to_sysgrp(bmp_file: str, output_file: str, should_flip: bool):
    """将BMP文件转换为sysgrp格式。"""
    with open(bmp_file, 'rb') as f:
        if f.read(2) != b'BM': raise ValueError("不是有效的 BMP 文件。")
        f.seek(0x0A); pixel_offset, = struct.unpack('<I', f.read(4))
        f.seek(0x12); width, height = struct.unpack('<ii', f.read(8)); height = abs(height)
        f.seek(0x1C); depth, = struct.unpack('<h', f.read(2)); bytes_per_pixel = depth // 8
        raw_stride = width * bytes_per_pixel; bmp_stride = (raw_stride + 3) & ~3
        f.seek(pixel_offset); padded_bits = f.read(); bits = bytearray()
        for y in range(height): start = y * bmp_stride; bits.extend(padded_bits[start : start + raw_stride])
    final_bits = flip_vertical(bytes(bits), width, depth) if should_flip else bytes(bits)
    with open(output_file, 'wb') as f:
        f.write(struct.pack('<hhh', width, height, depth)); f.write(b'\x00' * 10); f.write(final_bits)

# ==============================================================================
# BGI Source Script Core Logic - 方案B (BGI源码脚本逻辑)
# ==============================================================================
def core_bgi_source_index_of(source: bytes, array_to_find: bytes, start_at: int = 0) -> int:
    """在字节序列中查找子序列，是bytes.find的简单封装。"""
    return source.find(array_to_find, start_at)

def core_bgi_source_decode_file(input_path, output_path, log_callback):
    """(方案B-步骤1) 从BGI源码脚本导出带指针信息的文本。"""
    MAGIC_HEADER = b'BurikoCompiledScriptVer1.00\x00' # 脚本文件头标识
    try:
        with open(input_path, 'rb') as f: script_buffer = f.read()
    except IOError as e: raise IOError(f"读取文件失败: {e}")

    header_length = 0
    if script_buffer.startswith(MAGIC_HEADER):
        # [代码注释] 0x1C是文件头中记录附加头长度信息的位置
        additional_length = struct.unpack_from('<I', script_buffer, 0x1C)[0]
        header_length = 0x1C + additional_length
    
    script_body = script_buffer[header_length:]
    text_offset_label_pattern = b'\x00\x03\x00\x00\x00' # 文本指针前的特征码
    
    first_text_offset = len(script_body)
    first_label_pos = core_bgi_source_index_of(script_body, text_offset_label_pattern)
    if first_label_pos != -1: first_text_offset = struct.unpack_from('<I', script_body, first_label_pos + 5)[0]

    extracted_lines, current_pos = [], 0
    while True:
        text_offset_label = core_bgi_source_index_of(script_body, text_offset_label_pattern, current_pos)
        if text_offset_label == -1: break
        
        pointer_to_offset = text_offset_label + 5
        text_offset = struct.unpack_from('<I', script_body, pointer_to_offset)[0]

        if first_text_offset <= text_offset < len(script_body):
            end_of_text = core_bgi_source_index_of(script_body, b'\x00', text_offset)
            if end_of_text != -1:
                text_block = script_body[text_offset:end_of_text]
                try:
                    decoded_text = text_block.decode('shift_jis', errors='ignore').replace('\n', r'\n')
                    line = f"<{pointer_to_offset},{text_offset},{len(text_block)}>{decoded_text}"
                    extracted_lines.append(line)
                except UnicodeDecodeError:
                    log_callback(f"警告: 文件 {os.path.basename(input_path)} 在偏移 {text_offset} 处解码失败 (Shift-JIS)。", "WARN")
        current_pos = text_offset_label + 1
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(extracted_lines))
    return len(extracted_lines)

def _bgi_source_get_content_lines_and_indices(filepath, mode, log_callback):
    """(方案B-步骤2) 从导出的文件中提取纯文本，并记录原始行号用于回填。"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            full_lines = f.readlines()
    except Exception as e:
        log_callback(f"读取文件失败 {os.path.basename(filepath)}: {e}", "ERROR")
        return None, None

    control_char_re = re.compile(r'[\u0000-\u001F\u007F-\u009F]')
    ignore_patterns = [re.compile(p) for p in [r'^\s*$', r'^_', r'\.txt$', r'^#[0-9a-fA-F]{6}$', r'^[a-zA-Z0-9_]+\d*[a-zA-Z]?$']]
    DIALOGUE_SYMBOLS = ('「', '（', '『')

    content_tuples = []
    for i, line in enumerate(full_lines):
        match = re.search(r'>(.*)', line)
        if not match:
            continue
        content = control_char_re.sub('', match.group(1)).strip()
        
        if any(p.search(content) for p in ignore_patterns):
            continue
        content_tuples.append((i, content))

    if not content_tuples:
        return [], []

    combined_lines = []
    line_indices_map = []
    
    i = 0
    while i < len(content_tuples):
        idx1, line1 = content_tuples[i]
        
        if (i + 1) < len(content_tuples):
            idx2, line2 = content_tuples[i+1]
        else:
            idx2, line2 = -1, None
        
        is_dialogue1 = line1.startswith(DIALOGUE_SYMBOLS)
        is_speaker1 = not is_dialogue1 and len(line1) < 15 and line1.strip() != '' and not any(p in line1 for p in ['。', '、', '…', '？', '！'])
        is_dialogue2 = line2 is not None and line2.startswith(DIALOGUE_SYMBOLS)
        is_speaker2 = line2 is not None and not is_dialogue2 and len(line2) < 15 and line2.strip() != '' and not any(p in line2 for p in ['。', '、', '…', '？', '！'])
        
        # 模式A: 人名 -> 对话
        if mode == 'A' and is_speaker1 and is_dialogue2:
            combined_lines.append(f"{line1}{line2}")
            line_indices_map.append([idx1, idx2])
            i += 2
        # 模式B: 对话 -> 人名
        elif mode == 'B' and is_dialogue1 and is_speaker2:
            combined_lines.append(f"{line2}{line1}")
            line_indices_map.append([idx1, idx2])
            i += 2
        else:
            if line1.strip():
                combined_lines.append(line1)
                line_indices_map.append([idx1])
            i += 1
            
    return combined_lines, line_indices_map

def core_bgi_source_extract_dialogue_from_file(filepath, mode, log_callback):
    """(方案B-步骤2) 提取对话并返回纯文本和索引图。"""
    combined_lines, line_indices_map = _bgi_source_get_content_lines_and_indices(filepath, mode, log_callback)
    if combined_lines is None:
        return None, None
    return "\n".join(combined_lines), line_indices_map

def core_bgi_source_parse_extracted_txt_to_json(filepath, log_callback):
    """(方案B-可选步骤) 将纯文本文件转换为JSON。"""
    result = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                match = re.match(r'^(.*?)((「|『|（).*?(」|』|）))$', line)
                if match:
                    speaker, dialogue = match.group(1).strip(), match.group(2)
                    result.append({"name": speaker, "message": dialogue} if speaker else {"message": dialogue})
                else: result.append({"message": line})
    except Exception as e:
        log_callback(f"转换为JSON时出错: {os.path.basename(filepath)}, {e}", "ERROR"); return None
    return result

def core_bgi_source_parse_json_to_txt(filepath, log_callback):
    """(方案B-可选步骤) 将JSON文件转换回纯文本。"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        lines = [f"{item.get('name', '')}{item.get('message', '')}" for item in json_data]
        return "\n".join(lines)
    except Exception as e:
        log_callback(f"从JSON转换时出错: {os.path.basename(filepath)}, {e}", "ERROR"); return None

def core_bgi_source_repack_dialogue_to_file(translated_filepath, original_filepath, mode, log_callback):
    """(方案B-步骤3) 使用索引图将翻译后的纯文本精确回填。"""
    try:
        map_filepath = translated_filepath + ".map.json"
        if not os.path.exists(map_filepath):
            log_callback(f"错误: 找不到索引文件 '{os.path.basename(map_filepath)}'。请确保它与翻译文件在同一目录。", "ERROR")
            return None

        with open(translated_filepath, 'r', encoding='utf-8') as f:
            translated_lines = [line.strip('\r\n') for line in f.readlines()]
        with open(original_filepath, 'r', encoding='utf-8') as f:
            original_full_lines = f.readlines()
        with open(map_filepath, 'r', encoding='utf-8') as f:
            line_indices_map = json.load(f)

        if len(translated_lines) != len(line_indices_map):
            log_callback(f"错误: 翻译文件行数({len(translated_lines)})与索引文件行数({len(line_indices_map)})不匹配！", "ERROR")
            return None

        new_full_lines = list(original_full_lines)
        dialogue_re = re.compile(r'^(.*?)(「.*」|『.*』|（.*）)$')

        for i, translated_line in enumerate(translated_lines):
            original_indices = line_indices_map[i]
            
            deconstructed_parts = []
            if len(original_indices) == 2: # 这是一个合并行 (人名 + 对话)
                match = dialogue_re.match(translated_line)
                if match:
                    speaker, dialogue = match.group(1), match.group(2)
                    if mode == 'A': deconstructed_parts = [speaker, dialogue]
                    else: deconstructed_parts = [dialogue, speaker]
                else: # 如果正则匹配失败，做降级处理
                    if mode == 'A': deconstructed_parts = [translated_line, '']
                    else: deconstructed_parts = ['', translated_line]
            else: # 这是一个单行
                deconstructed_parts = [translated_line]

            for j, part in enumerate(deconstructed_parts):
                if j < len(original_indices):
                    line_num = original_indices[j]
                    original_line = original_full_lines[line_num]
                    prefix_match = re.match(r'.*>', original_line)
                    prefix = prefix_match.group(0) if prefix_match else '>'
                    new_full_lines[line_num] = f"{prefix}{part}\n"

        return "".join(new_full_lines)

    except Exception as e:
        log_callback(f"回填文件时发生严重错误: {os.path.basename(translated_filepath)}, {e}\n{traceback.format_exc()}", "ERROR")
        return None

def core_bgi_source_encode_file(translated_txt_path, original_script_path, output_path, encoding, log_callback):
    """(方案B-步骤4) 将回填后的文本文件封包回二进制脚本。"""
    MAGIC_HEADER = b'BurikoCompiledScriptVer1.00\x00'
    LINE_INFO_RE = re.compile(r'<(\d+),(\d+),(\d+)>')
    
    def parse_line(line: str):
        """解析带指针信息的行。"""
        match = LINE_INFO_RE.match(line)
        if not match: return None, None
        info = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        text = line[match.end():].replace(r'\n', '\n')
        return info, text

    try:
        with open(original_script_path, 'rb') as f: script_buffer = f.read()
        with open(translated_txt_path, 'r', encoding='utf-8') as f: lines = f.read().splitlines()
    except IOError as e:
        raise IOError(f"读取输入文件失败: {e}")

    header_length, header = 0, b''
    if script_buffer.startswith(MAGIC_HEADER):
        additional_length = struct.unpack_from('<I', script_buffer, 0x1C)[0]
        header_length = 0x1C + additional_length
        header = script_buffer[:header_length]
        
    script_body = script_buffer[header_length:]
    
    min_offset = min((info[1] for line in lines if line.strip() and (info := parse_line(line)[0]))) if any(l.strip() for l in lines) else 0

    control_block = bytearray(script_body[:min_offset])
    text_stream = io.BytesIO()
    
    for line in lines:
        if not line.strip(): continue
        info, text = parse_line(line)
        if not info: 
            log_callback(f"警告: 跳过格式错误的行: {line[:30]}...", "WARN"); continue
            
        pointer_offset, _, _ = info
        new_text_offset = len(control_block) + text_stream.tell()
        control_block[pointer_offset : pointer_offset + 4] = struct.pack('<I', new_text_offset)
        
        try:
            encoded_text = text.encode(encoding, errors='replace')
            text_stream.write(encoded_text)
            text_stream.write(b'\x00')
        except UnicodeEncodeError as e:
            log_callback(f"错误: 文本 '{text[:20]}...' 包含 {encoding} 不支持的字符。 {e}", "ERROR")
            return False

    with open(output_path, 'wb') as f:
        if header: f.write(header)
        f.write(control_block)
        f.write(text_stream.getvalue())
    return True

# =============================================================================
# 自定义对话框
# =============================================================================
class WarningDialog(Toplevel):
    """一个可选择“不再提醒”的自定义警告对话框。"""
    def __init__(self, parent, title, message):
        super().__init__(parent)
        self.transient(parent); self.title(title); self.parent = parent
        self.dont_show_again = BooleanVar()
        frame = ttk.Frame(self, padding="15"); frame.pack(expand=True, fill="both")
        msg_frame = ttk.Frame(frame); msg_frame.pack(pady=10)
        ttk.Label(msg_frame, text="ⓘ", font=("Segoe UI Symbol", 20, "bold"), foreground="blue").pack(side="left", padx=(0, 10))
        ttk.Label(msg_frame, text=message, wraplength=350).pack(side="left")
        control_frame = ttk.Frame(frame); control_frame.pack(pady=10, fill='x')
        ttk.Checkbutton(control_frame, text="不再提醒", variable=self.dont_show_again).pack(side="left", padx=(0, 20))
        ok_button = ttk.Button(control_frame, text="我已了解", command=self.on_ok, width=12, style="Accent.TButton"); ok_button.pack(side="right")
        self.protocol("WM_DELETE_WINDOW", self.on_ok)
        self.geometry(f"+{parent.winfo_rootx()+150}+{parent.winfo_rooty()+150}")
        self.grab_set(); self.focus_set(); ok_button.focus_set()

    def on_ok(self, event=None):
        if self.dont_show_again.get(): self.parent.show_repack_warning = False
        self.destroy()

# =============================================================================
# 主应用程序 GUI
# =============================================================================
class IntegratedToolApp(TkinterDnD.Tk if DND_SUPPORT else Tk):
    CONFIG_FILE = "bgi_tool_config.json"

    def __init__(self):
        super().__init__()
        self.title("BGI 游戏汉化工具箱"); self._load_config()
        self.protocol("WM_DELETE_WINDOW", self._on_closing)
        self._setup_styles(); self._init_vars()
        self._converter_load_history()
        self._create_widgets()
        self._converter_setup_initial_state()
        if not DND_SUPPORT:
            self.log("提示: 未找到 'tkinterdnd2' 模块，文件拖放功能将禁用。", "WARN")
            self.log("      可运行 'pip install tkinterdnd2' 来安装。", "WARN")
        sys.stdout = self; sys.stderr = self

    def _init_vars(self):
        """初始化所有Tkinter变量。"""
        # 方案A变量
        self.dump_input_dir, self.dump_output_dir = StringVar(), StringVar()
        self.proc_input_dir, self.proc_output_dir = StringVar(), StringVar()
        self.proc_mode, self.proc_format = StringVar(value='A'), StringVar(value='txt')
        self.recon_orig_dump_dir, self.recon_trans_clean_dir, self.recon_output_dir = StringVar(), StringVar(), StringVar()
        self.recon_mode = StringVar(value='A')
        self.repack_orig_dir, self.repack_trans_dir, self.repack_output_dir = StringVar(), StringVar(), StringVar()
        self.repack_encoding = StringVar(value='UTF-8')
        self.show_repack_warning = True
        # BP脚本工具变量
        self.bp_dump_input_dir, self.bp_dump_output_dir = StringVar(), StringVar()
        self.bp_insert_orig_dir, self.bp_insert_txt_dir, self.bp_insert_output_dir = StringVar(), StringVar(), StringVar()
        self.bp_slang, self.bp_dlang, self.bp_ilang = StringVar(value='ja'), StringVar(value='cn'), StringVar(value='cn')
        self.bp_senc, self.bp_denc, self.bp_ienc = StringVar(value='cp932'), StringVar(value='utf-8'), StringVar(value='utf-8')
        self.bp_dcopy = BooleanVar(value=True)
        self.bp_dump_mode, self.bp_insert_mode = StringVar(value='unique'), StringVar(value='unique')
        # 图像转换工具变量
        self.converter_files_to_process, self.converter_history_set = [], set()
        self.converter_output_dir, self.converter_should_flip = StringVar(), BooleanVar(value=True)
        self.converter_mode = StringVar(value="to_bmp")
        self.CONVERTER_HISTORY_FILE = "converter_history.log"
        # 方案B (BGI源码脚本) 变量
        self.bgi_source_decode_input, self.bgi_source_decode_output = StringVar(), StringVar()
        self.bgi_source_extract_input, self.bgi_source_extract_output = StringVar(), StringVar()
        self.bgi_source_json_input, self.bgi_source_json_output = StringVar(), StringVar()
        self.bgi_source_repack_trans, self.bgi_source_repack_orig, self.bgi_source_repack_output = StringVar(), StringVar(), StringVar()
        self.bgi_source_encode_repacked, self.bgi_source_encode_orig, self.bgi_source_encode_output = StringVar(), StringVar(), StringVar()
        self.bgi_source_encoding = StringVar(value='cp932')
        self.bgi_source_conversion_mode = StringVar(value='to_json')
        self.bgi_source_extract_mode = StringVar(value='A')
        self.bgi_source_repack_mode = StringVar(value='A')

    def _setup_styles(self):
        """设置UI的整体风格和颜色。"""
        BG_COLOR = "#F0F0F0"; FG_COLOR = "#1E1E1E"; ACCENT_COLOR = "#0078D7"
        self.style = ttk.Style(self); self.style.theme_use('clam')
        self.style.configure('.', background=BG_COLOR, foreground=FG_COLOR, font=('Segoe UI', 9))
        self.style.configure("TFrame", background=BG_COLOR)
        self.style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR)
        self.style.configure("TRadiobutton", background=BG_COLOR, foreground=FG_COLOR)
        self.style.configure("TCheckbutton", background=BG_COLOR, foreground=FG_COLOR)
        self.style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
        self.style.configure("TNotebook.Tab", background="#D0D0D0", foreground=FG_COLOR, padding=(10, 5), font=('Segoe UI', 10), borderwidth=0)
        self.style.map("TNotebook.Tab", background=[("selected", BG_COLOR)], expand=[("selected", [1, 1, 1, 0])])
        self.style.configure("TLabelframe", background=BG_COLOR, borderwidth=1, relief="solid")
        self.style.configure("TLabelframe.Label", background=BG_COLOR, foreground=FG_COLOR, font=('Segoe UI', 10, 'bold'))
        self.style.configure("TButton", padding=5, font=('Segoe UI', 9), background="#E1E1E1", borderwidth=1, relief="solid")
        self.style.map("TButton", background=[('active', '#C9C9C9')])
        self.style.configure("Accent.TButton", padding=5, font=('Segoe UI', 10, 'bold'), foreground='white', background=ACCENT_COLOR)
        self.style.map("Accent.TButton", background=[('active', '#005A9E')])
        self.style.configure("TEntry", fieldbackground="white", borderwidth=1, relief="solid")
        self.style.configure("Vertical.TScrollbar", background=BG_COLOR, troughcolor="#E1E1E1")
        self.style.configure("TProgressbar", troughcolor=BG_COLOR, background=ACCENT_COLOR)
    
    def write(self, text): self.log(text.strip(), "INFO")
    def flush(self): pass
    def _load_config(self):
        """加载上次关闭时的窗口位置和大小配置。"""
        try:
            with open(self.CONFIG_FILE, 'r') as f: self.geometry(json.load(f).get("geometry", "1200x900"))
        except (FileNotFoundError, json.JSONDecodeError): self.geometry("1200x900")
    def _save_config(self):
        """保存当前窗口位置和大小，方便下次打开。"""
        with open(self.CONFIG_FILE, 'w') as f: json.dump({"geometry": self.geometry()}, f)
    def _on_closing(self): self._save_config(); self.destroy()

    def _create_widgets(self):
        """创建主窗口的所有UI组件。"""
        main_frame = ttk.Frame(self, padding="5"); main_frame.pack(fill="both", expand=True)
        log_frame_container = ttk.Frame(main_frame)
        log_frame = ttk.LabelFrame(log_frame_container, text="日志输出"); log_frame.pack(fill="both", expand=True)
        log_toolbar = ttk.Frame(log_frame); log_toolbar.pack(fill='x', padx=5, pady=(5,0))
        ttk.Button(log_toolbar, text="清空日志", command=lambda: self.log_text.delete(1.0, END)).pack(side='right')
        self.log_text = ScrolledText(log_frame, wrap="word", height=15, font=("Consolas", 9), relief="solid", borderwidth=1, bg="white")
        self.log_text.pack(padx=5, pady=5, fill="both", expand=True)
        self.log_text.tag_config("INFO", foreground="black"); self.log_text.tag_config("SUCCESS", foreground="#008000")
        self.log_text.tag_config("WARN", foreground="#FFA500"); self.log_text.tag_config("ERROR", foreground="#FF0000")
        notebook = ttk.Notebook(main_frame); notebook.pack(pady=5, padx=5, fill="both", expand=True)
        tabs = {
            ' ★ 使用必读 ★ ': self._create_instructions_tab, 
            ' 方案A: BGI脚本 ': self._create_bgi_script_tab,
            ' 方案B: BGI源码脚本 ': self._create_bgi_source_tab, 
            ' BP脚本工具 ': self._create_bp_tool_tab, 
            ' 图像转换工具 ': self._create_converter_tab
        }
        for name, creation_func in tabs.items():
            frame = ttk.Frame(notebook, padding="10"); notebook.add(frame, text=name); creation_func(frame)
        log_frame_container.pack(padx=10, pady=(5,10), fill="both", expand=True)

    def log(self, text, level="INFO"):
        """向日志窗口输出信息，并根据级别设置颜色。"""
        if hasattr(self, 'log_text'): self.log_text.insert(END, text + "\n", level); self.log_text.see(END); self.update_idletasks()
    
    def _populate_instructions_text(self, text_widget):
        text_widget.configure(state='normal'); text_widget.delete(1.0, END)
        
        # 定义文本样式
        text_widget.tag_configure("h1", font=('Segoe UI', 16, 'bold'), spacing3=10)
        text_widget.tag_configure("h2", font=('Segoe UI', 12, 'bold'), spacing1=10, spacing3=5)
        text_widget.tag_configure("h3", font=('Segoe UI', 10, 'bold'), spacing1=5, spacing3=3)
        text_widget.tag_configure("p", font=('Segoe UI', 10), lmargin1=10, lmargin2=10)
        text_widget.tag_configure("p_bold", font=('Segoe UI', 10, 'bold'), lmargin1=10, lmargin2=10, foreground="red")
        text_widget.tag_configure("p_blue", font=('Segoe UI', 10), lmargin1=10, lmargin2=10, foreground="blue")
        text_widget.tag_configure("code", font=('Consolas', 10), lmargin1=20, lmargin2=20, background="#E0E0E0", relief="solid", borderwidth=1, spacing1=5, spacing3=5, wrap="word")

        instructions = [
            ("BGI 游戏汉化标准流程", "h1"),
            ("本工具将复杂的汉化过程简化为四个标准步骤：【导出】->【提取】->【回填】->【封包】。\n方案A和方案B都遵循此流程，请根据游戏类型选择合适的方案。", "p_blue"),
            
            ("【第1步: 导出文本】", "h2"),
            ("   • 目标: 从原始游戏脚本中，导出包含文本和格式信息的“中间文件”。", "p"),
            ("   • 操作: 选择【原始游戏脚本】目录作为输入，选择一个【空目录】作为输出。", "p"),

            ("【第2步: 提取纯文本】", "h2"),
            ("   • 目标: 从上一步的“中间文件”中，提取出不含格式代码的“纯文本”，方便翻译。", "p"),
            ("   • 操作: 选择第1步的【输出目录】作为输入，选择一个新的【空目录】作为输出。", "p"),
            ("   • 关键设置 - 提取模式 (A/B):", "h3"),
            ("      此设置至关重要，选错会导致后续步骤失败！请按以下方法判断：", "p_bold"),
            ("      1. 打开一个第1步生成的中间文件（.txt）。", "p"),
            ("      2. 找到一段对话，观察“人名”和“对话内容”的上下顺序：", "p"),
            ("      ▶ 如果是【人名在上，对话在下】，请选【模式A】。", "code"),
            ("      ▶ 如果是【对话在上，人名在下】，请选【模式B】。", "code"),
            
            ("【第3步: 回填译文】", "h2"),
            ("   • 目标: 将翻译好的“纯文本”，根据原始结构，回填到“中间文件”中。", "p"),
            ("   • 操作:", "p"),
            ("      - 输入1: 选择第1步生成的【中间文件】目录。", "p"),
            ("      - 输入2: 选择【翻译完成的纯文本】目录。", "p"),
            ("      - 输出: 选择一个新的【空目录】。", "p"),
            ("   • 注意: 此处的模式(A/B)选择，必须与第2步【完全一致】！", "p_bold"),

            ("【第4步: 封包脚本】", "h2"),
            ("   • 目标: 将回填好译文的“中间文件”制作成最终可用于游戏的新脚本。", "p"),
            ("   • 操作:", "p"),
            ("      - 输入1: 选择第3步生成的【回填后】的目录。", "p"),
            ("      - 输入2: 选择【原始游戏脚本】目录。", "p"),
            ("      - 输出: 选择一个新的【空目录】，用于存放最终成品。", "p"),
            ("   • 编码提示: 通常选 UTF-8。如游戏中乱码，可尝试 GBK (简体) 或 Big5 (繁体)。", "p"),

            ("\n\n方案A vs 方案B", "h1"),
            ("   • 方案A (BGI脚本): 推荐，适用于绝大多数标准 BGI/Ethornell 引擎游戏。", "p"),
            ("   • 方案B (BGI源码脚本): 备用方案。当方案A无效，或脚本是另一种源码格式时使用。", "p"),
            ("      - 特别注意: 方案B在【第2步:提取】时会额外生成 `.map.json` 索引文件，【第3步:回填】时必须保证它和翻译好的txt文件在同一个输入目录中。", "p_bold"),

            ("\n\n其他工具", "h1"),
            ("   • BP脚本工具: 用于处理一些游戏中的 `._bp` 格式脚本文件，流程类似，分为导出和导入。", "p"),
            ("   • 图像转换工具: 用于 `sysgrp` 格式的图片与通用 `BMP` 格式之间的相互转换。", "p"),
        ]

        for text, style in instructions:
            text_widget.insert(END, text + "\n", style)
        
        text_widget.configure(state='disabled')

    def _create_instructions_tab(self, parent):
        inst_frame = ttk.Frame(parent); inst_frame.pack(fill="both", expand=True)
        inst_text = ScrolledText(inst_frame, wrap="word", padx=10, pady=10, relief="flat", bg="#F0F0F0")
        inst_text.pack(fill="both", expand=True); self._populate_instructions_text(inst_text)
    
    def _create_bgi_script_tab(self, parent):
        notebook = ttk.Notebook(parent); notebook.pack(fill="both", expand=True, pady=5)
        tabs = {
            '第1步: 导出': self._create_dump_tab, 
            '第2步: 提取': self._create_process_tab, 
            '第3步: 回填': self._create_reconstruct_tab, 
            '第4步: 封包': self._create_repack_tab
        }
        for name, creation_func in tabs.items():
            frame = ttk.Frame(notebook, padding="15"); notebook.add(frame, text=f' {name} '); creation_func(frame)
    
    def _create_bgi_source_tab(self, parent):
        notebook = ttk.Notebook(parent); notebook.pack(fill="both", expand=True, pady=5)
        tabs = {
            '第1步: 导出': self._create_bgi_source_decode_tab,
            '第2步: 提取': self._create_bgi_source_extract_tab,
            '格式转换(可选)': self._create_bgi_source_json_tools_tab,
            '第3步: 回填': self._create_bgi_source_repack_tab,
            '第4步: 封包': self._create_bgi_source_encode_tab
        }
        for name, creation_func in tabs.items():
            frame = ttk.Frame(notebook, padding="15")
            notebook.add(frame, text=f' {name} ')
            creation_func(frame)

    # --- 方案B (BGI源码脚本) UI创建函数 ---
    def _create_bgi_source_decode_tab(self, parent):
        self._create_path_row(parent, 0, "输入: 原始脚本目录", self.bgi_source_decode_input)
        self._create_path_row(parent, 1, "输出: 导出的中间文件目录", self.bgi_source_decode_output)
        ttk.Button(parent, text="开始导出", command=self._run_bgi_source_decode, style="Accent.TButton").grid(row=2, column=0, columnspan=3, pady=20, ipady=5)
    
    def _create_bgi_source_extract_tab(self, parent):
        self._create_path_row(parent, 0, "输入: 中间文件目录 (第1步产物)", self.bgi_source_extract_input)
        self._create_path_row(parent, 1, "输出: 纯文本 & 索引目录", self.bgi_source_extract_output)
        options_frame = ttk.LabelFrame(parent, text="提取选项", padding=10)
        options_frame.grid(row=2, column=0, columnspan=3, pady=10, sticky="ew")
        self._create_radio_row(options_frame, 0, "提取模式:", [("模式A (人名->对话)", "A"), ("模式B (对话->人名)", "B")], self.bgi_source_extract_mode, is_horizontal=True)
        ttk.Label(options_frame, text="提示: 此步会生成.map.json索引文件，用于第3步回填。", foreground="blue").grid(row=1, column=0, columnspan=2, sticky='w', pady=(5,0))
        ttk.Button(parent, text="开始提取", command=self._run_bgi_source_extract, style="Accent.TButton").grid(row=3, column=0, columnspan=3, pady=20, ipady=5)
    
    def _create_bgi_source_json_tools_tab(self, parent):
        self._create_path_row(parent, 0, "输入目录 (纯文本或JSON)", self.bgi_source_json_input)
        self._create_path_row(parent, 1, "输出目录", self.bgi_source_json_output)
        options_frame = ttk.LabelFrame(parent, text="转换选项", padding=10)
        options_frame.grid(row=2, column=0, columnspan=3, pady=10, sticky="ew")
        self._create_radio_row(options_frame, 0, "转换方向:", [("TXT -> JSON", "to_json"), ("JSON -> TXT", "from_json")], self.bgi_source_conversion_mode, is_horizontal=True)
        ttk.Button(parent, text="开始转换", command=self._run_bgi_source_conversion, style="Accent.TButton").grid(row=3, column=0, columnspan=3, pady=20, ipady=5)
    
    def _create_bgi_source_repack_tab(self, parent):
        self._create_path_row(parent, 0, "输入1: 翻译后纯文本 (+.map.json) 目录", self.bgi_source_repack_trans)
        self._create_path_row(parent, 1, "输入2: 原始中间文件目录 (第1步产物)", self.bgi_source_repack_orig)
        self._create_path_row(parent, 2, "输出: 回填后的中间文件目录", self.bgi_source_repack_output)
        options_frame = ttk.LabelFrame(parent, text="回填选项", padding=10)
        options_frame.grid(row=3, column=0, columnspan=3, pady=10, sticky="ew")
        self._create_radio_row(options_frame, 0, "使用模式 (须与第2步一致):", [("模式A (人名->对话)", "A"), ("模式B (对话->人名)", "B")], self.bgi_source_repack_mode, is_horizontal=True)
        ttk.Button(parent, text="开始回填", command=self._run_bgi_source_repack, style="Accent.TButton").grid(row=4, column=0, columnspan=3, pady=20, ipady=5)
    
    def _create_bgi_source_encode_tab(self, parent):
        self._create_path_row(parent, 0, "输入1: 回填后的中间文件目录", self.bgi_source_encode_repacked)
        self._create_path_row(parent, 1, "输入2: 原始脚本目录", self.bgi_source_encode_orig)
        self._create_path_row(parent, 2, "输出: 新的游戏脚本目录 (最终成品)", self.bgi_source_encode_output)
        encoding_frame = ttk.LabelFrame(parent, text="封包编码", padding=10)
        encoding_frame.grid(row=3, column=0, columnspan=3, pady=10, sticky="ew")
        bgi_source_encoding_options = [("UTF-8", "UTF-8"), ("GBK (简体)", "gbk"), ("Big5 (繁体)", "big5"), ("CP932 (日文)", "cp932")]
        self._create_radio_row(encoding_frame, 0, "", bgi_source_encoding_options, self.bgi_source_encoding, is_horizontal=True)
        ttk.Button(parent, text="开始封包", command=self._run_bgi_source_encode, style="Accent.TButton").grid(row=4, column=0, columnspan=3, pady=20, ipady=5)
    
    # --- 方案A (BGI脚本) UI创建函数 ---
    def _create_mode_explanation_frame(self, parent):
        frame = ttk.LabelFrame(parent, text="模式(A/B)判断方法", padding=(10, 5))
        explanation_text = ("1. 使用【第1步:导出】功能，生成中间文件 (.txt)。\n"
                            "2. 打开该文件，找到一句带说话人的对话。\n\n"
                            "▶ 模式A (人名在上，对话在下)\n"
                            "   ●012345●爱丽丝\n"
                            "   ●012346●「你好。」\n\n"
                            "▶ 模式B (对话在上，人名在下)\n"
                            "   ●012345●「你好。」\n"
                            "   ●012346●爱丽丝")
        Label(frame, text=explanation_text, justify='left', font=('Segoe UI', 9)).pack(anchor='w', padx=5, pady=5)
        return frame
    
    def _create_dump_tab(self, parent):
        self._create_path_row(parent, 0, "输入: 原始脚本目录", self.dump_input_dir)
        self._create_path_row(parent, 1, "输出: 导出的中间文件目录", self.dump_output_dir)
        ttk.Button(parent, text="开始导出", command=self._run_dump, style="Accent.TButton").grid(row=2, column=0, columnspan=3, pady=20, ipady=5)
    
    def _create_process_tab(self, parent):
        self._create_path_row(parent, 0, "输入: 中间文件目录 (第1步产物)", self.proc_input_dir)
        self._create_path_row(parent, 1, "输出: 纯文本目录 (用于翻译)", self.proc_output_dir)
        options_frame = ttk.LabelFrame(parent, text="提取选项", padding=10); options_frame.grid(row=2, column=0, columnspan=3, pady=10, sticky="ew")
        self._create_radio_row(options_frame, 0, "提取模式:", [("模式A (人名->对话)", "A"), ("模式B (对话->人名)", "B")], self.proc_mode, is_horizontal=True)
        self._create_radio_row(options_frame, 1, "输出格式:", [("纯文本 (.txt)", "txt"), ("JSON (.json)", "json")], self.proc_format, is_horizontal=True)
        self._create_mode_explanation_frame(parent).grid(row=3, column=0, columnspan=3, pady=10, sticky="ew")
        ttk.Button(parent, text="开始提取", command=self._run_process, style="Accent.TButton").grid(row=4, column=0, columnspan=3, pady=20, ipady=5)
    
    def _create_reconstruct_tab(self, parent):
        self._create_path_row(parent, 0, "输入1: 原始中间文件目录 (第1步产物)", self.recon_orig_dump_dir)
        self._create_path_row(parent, 1, "输入2: 翻译完成的纯文本目录", self.recon_trans_clean_dir)
        self._create_path_row(parent, 2, "输出: 回填后的中间文件目录", self.recon_output_dir)
        options_frame = ttk.LabelFrame(parent, text="回填选项", padding=10); options_frame.grid(row=3, column=0, columnspan=3, pady=10, sticky="ew")
        self._create_radio_row(options_frame, 0, "使用模式 (须与第2步一致):", [("模式A", "A"), ("模式B", "B")], self.recon_mode, is_horizontal=True)
        ttk.Button(parent, text="开始回填", command=self._run_reconstruct, style="Accent.TButton").grid(row=4, column=0, columnspan=3, pady=20, ipady=5)
    
    def _create_repack_tab(self, parent):
        self._create_path_row(parent, 0, "输入1: 回填后的中间文件目录 (第3步产物)", self.repack_trans_dir)
        self._create_path_row(parent, 1, "输入2: 原始脚本目录", self.repack_orig_dir)
        self._create_path_row(parent, 2, "输出: 新的游戏脚本目录 (最终成品)", self.repack_output_dir)
        encoding_frame = ttk.LabelFrame(parent, text="封包编码", padding=10); encoding_frame.grid(row=3, column=0, columnspan=3, pady=10, sticky="ew")
        repack_options = [("UTF-8", "UTF-8"), ("GBK (简体)", "gbk"), ("Big5 (繁体)", "big5"), ("CP932 (日文)", "CP932")]
        self._create_radio_row(encoding_frame, 0, "", repack_options, self.repack_encoding, is_horizontal=True)
        ttk.Button(parent, text="开始封包", command=self._run_repack, style="Accent.TButton").grid(row=4, column=0, columnspan=3, pady=20, ipady=5)
    
    def _create_bp_tool_tab(self, parent):
        notebook = ttk.Notebook(parent); notebook.pack(fill="both", expand=True, pady=5)
        dump_frame = ttk.Frame(notebook, padding="15"); notebook.add(dump_frame, text=' 导出 (Dump) ')
        self._create_path_row(dump_frame, 0, "输入: 原始 ._bp 脚本目录", self.bp_dump_input_dir); self._create_path_row(dump_frame, 1, "输出: .txt 文本目录", self.bp_dump_output_dir)
        dump_settings = ttk.LabelFrame(dump_frame, text="导出设置", padding=10); dump_settings.grid(row=2, column=0, columnspan=3, pady=10, sticky="ew")
        self._create_entry_row(dump_settings, 0, "源语言 (slang)", self.bp_slang); self._create_entry_row(dump_settings, 1, "目标语言 (dlang)", self.bp_dlang)
        self._create_entry_row(dump_settings, 2, "源编码 (senc)", self.bp_senc); self._create_entry_row(dump_settings, 3, "文本编码 (denc)", self.bp_denc)
        ttk.Checkbutton(dump_settings, text="导出时复制原文到目标语言行", variable=self.bp_dcopy).grid(row=4, column=0, columnspan=2, sticky='w', pady=5)
        self._create_radio_row(dump_settings, 5, "导出模式:", [("唯一 (Unique)", "unique"), ("顺序 (Sequential)", "sequential")], self.bp_dump_mode, is_horizontal=True)
        ttk.Button(dump_frame, text="开始导出", command=self._run_bp_dump, style="Accent.TButton").grid(row=3, column=0, columnspan=3, pady=20, ipady=5)
        insert_frame = ttk.Frame(notebook, padding="15"); notebook.add(insert_frame, text=' 导入 (Insert) ')
        self._create_path_row(insert_frame, 0, "输入1: 原始 ._bp 脚本目录", self.bp_insert_orig_dir); self._create_path_row(insert_frame, 1, "输入2: 翻译后 .txt 文本目录", self.bp_insert_txt_dir)
        self._create_path_row(insert_frame, 2, "输出: 新的 ._bp 脚本目录", self.bp_insert_output_dir)
        insert_settings = ttk.LabelFrame(insert_frame, text="导入设置", padding=10); insert_settings.grid(row=3, column=0, columnspan=3, pady=10, sticky="ew")
        self._create_entry_row(insert_settings, 0, "导入语言 (ilang)", self.bp_ilang); self._create_entry_row(insert_settings, 1, "导入编码 (ienc)", self.bp_ienc)
        self._create_radio_row(insert_settings, 2, "导入模式:", [("唯一 (Unique)", "unique"), ("顺序 (Sequential)", "sequential")], self.bp_insert_mode, is_horizontal=True)
        ttk.Button(insert_frame, text="开始导入", command=self._run_bp_insert, style="Accent.TButton").grid(row=4, column=0, columnspan=3, pady=20, ipady=5)
    
    def _create_converter_tab(self, parent):
        top_frame = ttk.Frame(parent); top_frame.pack(fill="x", side="top", pady=(0, 10))
        btn_frame = ttk.Frame(top_frame); btn_frame.pack(fill="x", pady=5)
        ttk.Button(btn_frame, text="选择文件", command=self._converter_select_files).pack(side="left", expand=True, fill="x", padx=2)
        ttk.Button(btn_frame, text="历史记录", command=self._converter_open_history_window).pack(side="left", expand=True, fill="x", padx=2)
        self.converter_btn_clear = ttk.Button(btn_frame, text="清空列表", command=self._converter_clear_list); self.converter_btn_clear.pack(side="left", expand=True, fill="x", padx=2)
        out_frame = ttk.Frame(top_frame); out_frame.pack(fill="x", pady=5)
        ttk.Label(out_frame, text="输出目录:").pack(side="left"); ttk.Entry(out_frame, textvariable=self.converter_output_dir, state="readonly").pack(side="left", expand=True, fill="x", padx=5)
        ttk.Button(out_frame, text="...", command=self._converter_select_output_dir, width=4).pack(side="left")
        list_frame = ttk.LabelFrame(parent, text="待处理文件列表 (可拖放文件/文件夹至此)"); list_frame.pack(fill="both", expand=True, side="top")
        self.converter_file_listbox = Listbox(list_frame, selectmode=EXTENDED, relief="solid", borderwidth=1, bg="white"); self.converter_file_listbox.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.converter_file_listbox.yview); scrollbar.pack(side="right", fill="y", pady=5)
        self.converter_file_listbox.config(yscrollcommand=scrollbar.set)
        if DND_SUPPORT: self.converter_file_listbox.drop_target_register(DND_FILES); self.converter_file_listbox.dnd_bind('<<Drop>>', self._converter_handle_drop)
        self._converter_create_context_menu(); self.converter_file_listbox.bind("<Button-3>", self._converter_show_context_menu)
        bottom_frame = ttk.Frame(parent); bottom_frame.pack(fill="x", side="bottom", pady=(10, 0))
        mode_frame = ttk.LabelFrame(bottom_frame, text="转换选项", padding="10"); mode_frame.pack(fill="x", pady=(0, 10))
        ttk.Radiobutton(mode_frame, text="游戏格式 (sysgrp) -> 通用BMP", variable=self.converter_mode, value="to_bmp").pack(anchor="w")
        ttk.Radiobutton(mode_frame, text="通用BMP -> 游戏格式 (sysgrp)", variable=self.converter_mode, value="to_sysgrp").pack(anchor="w")
        ttk.Separator(mode_frame, orient='horizontal').pack(fill='x', pady=5)
        ttk.Checkbutton(mode_frame, text="转换时垂直翻转BMP (用于标准BMP)", variable=self.converter_should_flip).pack(anchor="w")
        self.converter_progress = ttk.Progressbar(bottom_frame, orient="horizontal", mode="determinate"); self.converter_progress.pack(fill="x", pady=5)
        self.converter_status_label = ttk.Label(bottom_frame, text="请选择文件或拖放至列表以开始"); self.converter_status_label.pack(anchor="w")
        self.converter_btn_convert = ttk.Button(bottom_frame, text="开始转换", command=self._converter_start_conversion, style="Accent.TButton"); self.converter_btn_convert.pack(fill="x", ipady=5, pady=(5, 0))
    
    def _create_path_row(self, parent, r, label_text, var):
        """创建一个包含“标签-输入框-浏览按钮”的标准化行。"""
        ttk.Label(parent, text=label_text).grid(row=r, column=0, padx=5, pady=8, sticky="w")
        entry = ttk.Entry(parent, textvariable=var, width=70); entry.grid(row=r, column=1, padx=5, pady=8, sticky="ew")
        ttk.Button(parent, text="浏览...", command=lambda v=var: self._browse_dir(v)).grid(row=r, column=2, padx=5, pady=8)
        parent.grid_columnconfigure(1, weight=1)
    
    def _create_entry_row(self, parent, r, label_text, var):
        """创建一个包含“标签-短输入框”的行。"""
        ttk.Label(parent, text=label_text + ":").grid(row=r, column=0, padx=5, pady=4, sticky="w")
        ttk.Entry(parent, textvariable=var, width=20).grid(row=r, column=1, padx=5, pady=4, sticky="w")
    
    def _create_radio_row(self, parent, r, label_text, options, var, is_horizontal=False):
        """创建一行单选按钮。"""
        if label_text: ttk.Label(parent, text=label_text).grid(row=r, column=0, padx=5, pady=5, sticky="w")
        frame = ttk.Frame(parent); frame.grid(row=r, column=1, padx=5, pady=5, sticky="w", columnspan=2)
        for i, (text, value) in enumerate(options):
            rb = ttk.Radiobutton(frame, text=text, variable=var, value=value)
            if is_horizontal: rb.pack(side="left", padx=10)
            else: rb.pack(anchor='w')
    
    def _browse_dir(self, dir_var):
        """打开文件夹选择对话框并设置变量。"""
        directory = filedialog.askdirectory()
        if directory: dir_var.set(directory)
        
    def _run_dump(self):
        input_dir, output_dir = self.dump_input_dir.get(), self.dump_output_dir.get()
        if not all([input_dir, output_dir]): messagebox.showerror("错误", "请选择所有必需的目录！"); return
        if core_dump_scripts(input_dir, output_dir, self.log):
            self.log(">>> 自动填充: 已将路径自动填入后续步骤。", "SUCCESS")
            self.proc_input_dir.set(output_dir); self.recon_orig_dump_dir.set(output_dir); self.repack_orig_dir.set(input_dir)
            messagebox.showinfo("成功", "文本导出任务完成！\n路径已自动填充到后续步骤。")
    
    def _run_process(self):
        input_dir, output_dir = self.proc_input_dir.get(), self.proc_output_dir.get()
        if not all([input_dir, output_dir]): messagebox.showerror("错误", "请选择所有必需的目录！"); return
        core_process_text(input_dir, output_dir, self.proc_mode.get(), self.proc_format.get(), self.log)
        self.log(">>> 自动填充: 已将路径自动填入后续步骤。", "SUCCESS"); self.recon_trans_clean_dir.set(output_dir)
        messagebox.showinfo("成功", "纯文本提取任务完成！\n路径已自动填充到后续步骤。")
    
    def _run_reconstruct(self):
        output_dir = self.recon_output_dir.get()
        if not all([self.recon_orig_dump_dir.get(), self.recon_trans_clean_dir.get(), output_dir]): messagebox.showerror("错误", "请选择所有必需的目录！"); return
        core_reconstruct_files(self.recon_orig_dump_dir.get(), self.recon_trans_clean_dir.get(), output_dir, self.recon_mode.get(), self.log)
        self.log(">>> 自动填充: 已将路径自动填入后续步骤。", "SUCCESS"); self.repack_trans_dir.set(output_dir)
        messagebox.showinfo("成功", "文本回填任务完成！\n路径已自动填充到后续步骤。")
    
    def _run_repack(self):
        # [修改] 输入路径名统一
        repacked_dir, orig_dir, output_dir = self.repack_trans_dir.get(), self.repack_orig_dir.get(), self.repack_output_dir.get()
        if not all([orig_dir, repacked_dir, output_dir]): messagebox.showerror("错误", "请选择所有必需的目录！"); return
        if self.show_repack_warning:
            msg = ("警告：您将要执行【封包】操作。\n\n"
                   "请确认“输入1”是第3步【回填】后生成的文件夹，而不是第2步的纯文本文件夹。\n\n"
                   "选择错误将导致封包失败。")
            dialog = WarningDialog(self, "操作确认", msg)
            self.wait_window(dialog)
        core_repack_scripts(orig_dir, repacked_dir, output_dir, self.repack_encoding.get(), self.log)
        messagebox.showinfo("成功", "脚本封包任务完成！\n现在可以测试生成的脚本了。")
    
    def _run_bp_dump(self):
        input_dir, output_dir = self.bp_dump_input_dir.get(), self.bp_dump_output_dir.get()
        if not all([input_dir, output_dir]): messagebox.showerror("错误", "请选择所有必需的目录！"); return
        settings = {'slang': self.bp_slang.get(), 'dlang': [self.bp_dlang.get()], 'senc': self.bp_senc.get(), 'denc': self.bp_denc.get(), 'dcopy': self.bp_dcopy.get(), 'dump_mode': self.bp_dump_mode.get()}
        self.log("--- 开始 BP 脚本导出任务 ---", "INFO"); os.makedirs(output_dir, exist_ok=True)
        Thread(target=self._bp_dump_task, args=(input_dir, output_dir, settings), daemon=True).start()
    
    def _bp_dump_task(self, input_dir, output_dir, settings):
        processed_count = 0
        for filename in os.listdir(input_dir):
            if filename.endswith('._bp'):
                self.log(f"正在导出: {filename}", "INFO")
                try:
                    _bp_dump_single_file(os.path.join(input_dir, filename), os.path.join(output_dir, f"{os.path.splitext(filename)[0]}.txt"), settings); processed_count += 1
                except Exception as e: self.log(f"导出 {filename} 时发生错误: {e}\n{traceback.format_exc()}", "ERROR")
        self.log(f"--- BP 脚本导出完成，共处理 {processed_count} 个文件。---", "INFO")
        if processed_count > 0: self.log(">>> 自动填充: 已将路径自动填入导入步骤。", "SUCCESS"); self.bp_insert_orig_dir.set(input_dir); self.bp_insert_txt_dir.set(output_dir)
    
    def _run_bp_insert(self):
        orig_dir, txt_dir, output_dir = self.bp_insert_orig_dir.get(), self.bp_insert_txt_dir.get(), self.bp_insert_output_dir.get()
        if not all([orig_dir, txt_dir, output_dir]): messagebox.showerror("错误", "请选择所有必需的目录！"); return
        settings = {'ilang': self.bp_ilang.get(), 'ienc': self.bp_ienc.get(), 'senc': self.bp_senc.get(), 'denc': self.bp_denc.get(), 'insert_mode': self.bp_insert_mode.get()}
        self.log("--- 开始 BP 脚本导入任务 ---", "INFO"); os.makedirs(output_dir, exist_ok=True)
        Thread(target=self._bp_insert_task, args=(orig_dir, txt_dir, output_dir, settings), daemon=True).start()
    
    def _bp_insert_task(self, orig_dir, txt_dir, output_dir, settings):
        processed_count = 0
        for filename in os.listdir(orig_dir):
            if filename.endswith('._bp'):
                bp_path, txt_path = os.path.join(orig_dir, filename), os.path.join(txt_dir, f"{os.path.splitext(filename)[0]}.txt")
                if not os.path.exists(txt_path): self.log(f"警告: 找不到 {os.path.basename(txt_path)}，跳过。", "WARN"); continue
                self.log(f"正在导入: {filename}", "INFO")
                try:
                    _bp_insert_single_file(bp_path, txt_path, os.path.join(output_dir, filename), settings); processed_count += 1
                except Exception as e: self.log(f"导入 {filename} 时发生错误: {e}\n{traceback.format_exc()}", "ERROR")
        self.log(f"--- BP 脚本导入完成，共处理 {processed_count} 个文件。---", "INFO")
    
    def _run_bgi_source_decode(self):
        input_dir, output_dir = self.bgi_source_decode_input.get(), self.bgi_source_decode_output.get()
        if not all([input_dir, output_dir]): messagebox.showerror("错误", "请选择所有必需的目录！"); return
        def task():
            self.log(f"--- 开始文本导出任务 (方案B) ---", "INFO"); os.makedirs(output_dir, exist_ok=True)
            processed_count, total_lines = 0, 0
            for filename in os.listdir(input_dir):
                input_path = os.path.join(input_dir, filename)
                if not os.path.isfile(input_path): continue
                output_path = os.path.join(output_dir, f"{filename}.txt")
                self.log(f"正在导出: {filename}", "INFO")
                try:
                    lines = core_bgi_source_decode_file(input_path, output_path, self.log); total_lines += lines; processed_count += 1
                except Exception as e: self.log(f"导出 {filename} 时发生错误: {e}", "ERROR")
            self.log(f"--- 文本导出任务完成，共处理 {processed_count} 个文件，导出 {total_lines} 行文本。---", "INFO")
            if processed_count > 0:
                self.log(">>> 自动填充: 已将路径自动填入后续步骤。", "SUCCESS")
                self.bgi_source_extract_input.set(output_dir); self.bgi_source_repack_orig.set(output_dir); self.bgi_source_encode_orig.set(input_dir)
                messagebox.showinfo("成功", "文本导出任务完成！")
        Thread(target=task, daemon=True).start()

    def _run_bgi_source_extract(self):
        input_dir, output_dir = self.bgi_source_extract_input.get(), self.bgi_source_extract_output.get()
        mode = self.bgi_source_extract_mode.get()
        if not all([input_dir, output_dir]): messagebox.showerror("错误", "请选择所有必需的目录！"); return
        def task():
            self.log(f"--- 开始纯文本提取任务 (方案B, 模式: {mode}) ---", "INFO"); os.makedirs(output_dir, exist_ok=True); processed = 0
            for filename in os.listdir(input_dir):
                if filename.lower().endswith(".txt"):
                    self.log(f"正在提取: {filename}", "INFO")
                    clean_text, line_map = core_bgi_source_extract_dialogue_from_file(os.path.join(input_dir, filename), mode, self.log)
                    if clean_text is not None and line_map is not None:
                        with open(os.path.join(output_dir, filename), 'w', encoding='utf-8') as f_out: f_out.write(clean_text)
                        map_filename = os.path.join(output_dir, filename + ".map.json")
                        with open(map_filename, 'w', encoding='utf-8') as f_map: json.dump(line_map, f_map)
                        processed += 1
            self.log(f"--- 纯文本提取任务完成，共处理 {processed} 个文件。---", "INFO")
            if processed > 0:
                self.log(">>> 自动填充: 已将路径自动填入后续步骤。", "SUCCESS")
                self.bgi_source_json_input.set(output_dir); self.bgi_source_repack_trans.set(output_dir)
                messagebox.showinfo("成功", "纯文本提取任务完成！\n请确保翻译后，.txt和.map.json文件在同一目录。")
        Thread(target=task, daemon=True).start()
    
    def _run_bgi_source_conversion(self):
        input_dir, output_dir = self.bgi_source_json_input.get(), self.bgi_source_json_output.get()
        mode = self.bgi_source_conversion_mode.get()
        if not all([input_dir, output_dir]): messagebox.showerror("错误", "请选择所有必需的目录！"); return
        def task():
            if mode == 'to_json':
                self.log("--- 开始 TXT -> JSON 转换 ---", "INFO"); os.makedirs(output_dir, exist_ok=True); processed = 0
                for filename in os.listdir(input_dir):
                    if filename.lower().endswith('.txt'):
                        self.log(f"处理中: {filename}", "INFO")
                        json_data = core_bgi_source_parse_extracted_txt_to_json(os.path.join(input_dir, filename), self.log)
                        if json_data is not None:
                            out_path = os.path.join(output_dir, f"{os.path.basename(filename)}.json")
                            with open(out_path, 'w', encoding='utf-8') as f: json.dump(json_data, f, ensure_ascii=False, indent=2)
                            processed += 1
                self.log(f"--- 转换完成，共处理 {processed} 个文件。---", "INFO")
                if processed > 0: messagebox.showinfo("成功", "TXT -> JSON 转换完成！")
            elif mode == 'from_json':
                self.log("--- 开始 JSON -> TXT 转换 ---", "INFO"); os.makedirs(output_dir, exist_ok=True); processed = 0
                for filename in os.listdir(input_dir):
                    if filename.lower().endswith('.json'):
                        self.log(f"处理中: {filename}", "INFO")
                        txt_data = core_bgi_source_parse_json_to_txt(os.path.join(input_dir, filename), self.log)
                        if txt_data is not None:
                            out_name = filename[:-5] if filename.lower().endswith('.txt.json') else filename.replace('.json', '.txt')
                            with open(os.path.join(output_dir, out_name), 'w', encoding='utf-8') as f: f.write(txt_data)
                            processed += 1
                self.log(f"--- 转换完成，共处理 {processed} 个文件。---", "INFO")
                if processed > 0: self.bgi_source_repack_trans.set(output_dir); messagebox.showinfo("成功", "JSON -> TXT 转换完成！")
        Thread(target=task, daemon=True).start()
    
    def _run_bgi_source_repack(self):
        trans_dir, orig_dir, output_dir = self.bgi_source_repack_trans.get(), self.bgi_source_repack_orig.get(), self.bgi_source_repack_output.get()
        mode = self.bgi_source_repack_mode.get()
        if not all([trans_dir, orig_dir, output_dir]): messagebox.showerror("错误", "请选择所有必需的目录！"); return
        def task():
            self.log(f"--- 开始文本回填任务 (方案B, 模式: {mode}) ---", "INFO"); os.makedirs(output_dir, exist_ok=True); processed = 0
            for filename in os.listdir(trans_dir):
                if filename.lower().endswith('.txt'):
                    trans_path = os.path.join(trans_dir, filename)
                    orig_path = os.path.join(orig_dir, filename)
                    if not os.path.exists(orig_path): self.log(f"警告: 找不到原始中间文件 {filename}，跳过。", "WARN"); continue
                    self.log(f"正在回填: {filename}", "INFO")
                    repacked_text = core_bgi_source_repack_dialogue_to_file(trans_path, orig_path, mode, self.log)
                    if repacked_text is not None:
                        with open(os.path.join(output_dir, filename), 'w', encoding='utf-8') as f: f.write(repacked_text)
                        processed += 1
            self.log(f"--- 文本回填任务完成，共处理 {processed} 个文件。---", "INFO")
            if processed > 0: self.bgi_source_encode_repacked.set(output_dir); messagebox.showinfo("成功", "文本回填任务完成！")
        Thread(target=task, daemon=True).start()
    
    def _run_bgi_source_encode(self):
        repacked_dir, orig_dir, output_dir = self.bgi_source_encode_repacked.get(), self.bgi_source_encode_orig.get(), self.bgi_source_encode_output.get()
        encoding = self.bgi_source_encoding.get()
        if not all([repacked_dir, orig_dir, output_dir]): messagebox.showerror("错误", "请选择所有必需的目录！"); return
        def task():
            self.log(f"--- 开始脚本封包任务 (方案B, 编码: {encoding}) ---", "INFO"); os.makedirs(output_dir, exist_ok=True); processed = 0
            for filename in os.listdir(repacked_dir):
                if filename.lower().endswith('.txt'):
                    repacked_path = os.path.join(repacked_dir, filename)
                    original_name = filename[:-4]; original_path = os.path.join(orig_dir, original_name)
                    if not os.path.exists(original_path): self.log(f"警告: 找不到原始脚本文件 {original_name}，跳过。", "WARN"); continue
                    self.log(f"正在封包: {original_name}", "INFO")
                    if core_bgi_source_encode_file(repacked_path, original_path, os.path.join(output_dir, original_name), encoding, self.log):
                        processed += 1
            self.log(f"--- 脚本封包任务完成，共处理 {processed} 个文件。---", "INFO")
            if processed > 0: messagebox.showinfo("成功", "脚本封包任务完成！")
        Thread(target=task, daemon=True).start()
    
    # --- 以下是图像转换工具的函数，保持不变 ---
    def _converter_create_context_menu(self):
        self.converter_context_menu = Menu(self, tearoff=0, bg="white", fg="black")
        self.converter_context_menu.add_command(label="移除选中项", command=self._converter_remove_selected_from_list)
        self.converter_context_menu.add_separator()
        self.converter_context_menu.add_command(label="全部清空", command=self._converter_clear_list)
    def _converter_show_context_menu(self, event):
        if self.converter_files_to_process: self.converter_context_menu.tk_popup(event.x_root, event.y_root)
    def _converter_setup_initial_state(self):
        default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output_images")
        if not self.converter_output_dir.get():
            if not os.path.exists(default_path):
                try: os.makedirs(default_path)
                except OSError as e: self.log(f"创建默认图片输出目录失败: {e}", "ERROR"); default_path = ""
            self.converter_output_dir.set(default_path)
        self._converter_update_ui_state()
    def _converter_update_ui_state(self):
        has_files = bool(self.converter_files_to_process)
        self.converter_btn_clear.config(state="normal" if has_files else "disabled")
        self.converter_btn_convert.config(state="normal" if has_files and self.converter_output_dir.get() else "disabled")
    def _converter_handle_drop(self, event):
        files_to_add = []
        try: dropped_items = self.tk.splitlist(event.data)
        except: dropped_items = event.data.strip().replace('{', '').replace('}', '').split()
        for item_path in (p.strip() for p in dropped_items):
            if not os.path.exists(item_path): self.log(f"警告: 拖放路径不存在: {item_path}", "WARN"); continue
            if os.path.isdir(item_path):
                for root, _, filenames in os.walk(item_path): files_to_add.extend(os.path.join(root, f) for f in filenames)
            else: files_to_add.append(item_path)
        newly_added = [f for f in files_to_add if f not in self.converter_files_to_process]
        if newly_added:
            self.converter_files_to_process.extend(newly_added)
            self._converter_update_file_list()
            self.converter_status_label.config(text=f"已从拖放添加 {len(newly_added)} 个新文件。")
            self.converter_file_listbox.config(bg="#E6F2FA"); self.after(500, lambda: self.converter_file_listbox.config(bg="white"))
        else: self.converter_status_label.config(text="拖放的文件已在列表中。")
    def _converter_select_files(self):
        files = filedialog.askopenfilenames(title="选择要转换的文件")
        if files:
            newly_added = [f for f in files if f not in self.converter_files_to_process]
            if newly_added:
                self.converter_files_to_process.extend(newly_added)
                self._converter_update_file_list(); self.converter_status_label.config(text=f"已添加 {len(newly_added)} 个文件。")
    def _converter_select_output_dir(self):
        directory = filedialog.askdirectory(title="选择输出文件夹")
        if directory: self.converter_output_dir.set(directory); self._converter_update_ui_state()
    def _converter_update_file_list(self):
        self.converter_file_listbox.delete(0, END)
        for file in self.converter_files_to_process: self.converter_file_listbox.insert(END, os.path.basename(file))
        self._converter_update_ui_state()
    def _converter_clear_list(self):
        self.converter_files_to_process.clear(); self._converter_update_file_list()
        self.converter_progress['value'] = 0
        self.converter_status_label.config(text="请选择文件或拖放至列表以开始")
    def _converter_remove_selected_from_list(self):
        for i in sorted(self.converter_file_listbox.curselection(), reverse=True): del self.converter_files_to_process[i]
        self._converter_update_file_list()
    def _converter_start_conversion(self):
        if not self.converter_files_to_process: return
        self.converter_btn_convert.config(state="disabled")
        self.converter_progress['maximum'] = len(self.converter_files_to_process); self.converter_progress['value'] = 0
        Thread(target=self._converter_task, daemon=True).start()
    def _converter_load_history(self):
        try:
            with open(self.CONVERTER_HISTORY_FILE, 'r', encoding='utf-8') as f:
                self.converter_history_set = {line.strip() for line in f if line.strip() and os.path.exists(line.strip())}
        except FileNotFoundError: pass
    def _converter_save_history(self):
        with open(self.CONVERTER_HISTORY_FILE, 'w', encoding='utf-8') as f: f.write('\n'.join(sorted(list(self.converter_history_set))))
    def _converter_open_history_window(self):
        history_win = Toplevel(self); history_win.title("文件历史记录"); history_win.geometry("600x400"); history_win.transient(self); history_win.grab_set()
        list_frame = ttk.Frame(history_win, padding=10); list_frame.pack(fill="both", expand=True)
        hist_listbox = Listbox(list_frame, selectmode=EXTENDED, bg="white"); hist_listbox.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=hist_listbox.yview); scrollbar.pack(side="right", fill="y"); hist_listbox.config(yscrollcommand=scrollbar.set)
        for item in sorted(list(self.converter_history_set)): hist_listbox.insert(END, item)
        btn_frame = ttk.Frame(history_win, padding=10); btn_frame.pack(fill="x")
        def add_selected():
            for i in hist_listbox.curselection():
                if (p:=hist_listbox.get(i)) not in self.converter_files_to_process: self.converter_files_to_process.append(p)
            self._converter_update_file_list(); history_win.destroy()
        def clear_history():
            if messagebox.askyesno("确认", "您确定要永久清除所有历史记录吗？"):
                self.converter_history_set.clear(); self._converter_save_history(); hist_listbox.delete(0, END)
        ttk.Button(btn_frame, text="添加选中项至列表", command=add_selected, style="Accent.TButton").pack(side="left", expand=True, padx=5)
        ttk.Button(btn_frame, text="清空历史记录", command=clear_history).pack(side="left", expand=True, padx=5)
        ttk.Button(btn_frame, text="取消", command=history_win.destroy).pack(side="right", expand=True, padx=5)
    def _converter_task(self):
        self.log("--- 开始图像转换任务 ---", "INFO")
        success_count, failed, skipped, copied = 0, [], [], 0
        output_path, mode, flip = self.converter_output_dir.get(), self.converter_mode.get(), self.converter_should_flip.get()
        newly_processed = set()
        total_files = len(self.converter_files_to_process)
        for i, input_file in enumerate(self.converter_files_to_process):
            self.converter_status_label.config(text=f"({i+1}/{total_files}) 正在处理: {os.path.basename(input_file)}"); self.converter_progress['value'] = i + 1
            base_name = os.path.splitext(os.path.basename(input_file))[0]
            try:
                if mode == "to_bmp":
                    output_file_path = os.path.join(output_path, f"{base_name}.bmp")
                    with open(input_file, 'rb') as f:
                        if f.read(2) == b'BM':
                            shutil.copy2(input_file, output_file_path); copied += 1; self.log(f"已复制 (本身是BMP): {input_file}", "INFO")
                        else:
                            convert_sysgrp_to_bmp(input_file, output_file_path); success_count += 1; self.log(f"成功转换 -> BMP: {input_file}", "SUCCESS")
                else:
                    output_file_path = os.path.join(output_path, f"{base_name}.out")
                    convert_bmp_to_sysgrp(input_file, output_file_path, flip); success_count += 1; self.log(f"成功转换 -> Sysgrp: {input_file}", "SUCCESS")
                newly_processed.add(input_file)
            except ValueError as e: skipped.append(f"{os.path.basename(input_file)}: {e}"); self.log(f"跳过: {input_file}, 原因: {e}", "WARN")
            except Exception as e: failed.append(f"{os.path.basename(input_file)}: {e}"); self.log(f"失败: {input_file}, 原因: {e}\n{traceback.format_exc()}", "ERROR")
        self.converter_history_set.update(newly_processed); self._converter_save_history()
        final_status = f"完成！转换:{success_count}, 复制:{copied}, 失败:{len(failed)}, 跳过:{len(skipped)}."
        self.converter_status_label.config(text=final_status); self.log(f"--- 图像转换任务完成: {final_status} ---", "INFO")
        self.converter_btn_convert.config(state="normal"); self._converter_update_ui_state()
        message = f"转换任务完成！\n\n总文件数: {total_files}\n成功转换: {success_count}\n直接复制 (已是BMP): {copied}\n失败: {len(failed)}\n跳过 (格式无效): {len(skipped)}"
        if failed or skipped: messagebox.showwarning("任务完成但有状况", f"{message}\n\n详细信息请查看下方日志区域。")
        else: messagebox.showinfo("任务完成", message)

if __name__ == "__main__":
    app = IntegratedToolApp()
    app.mainloop()