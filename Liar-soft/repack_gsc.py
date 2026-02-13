# -*- coding: utf-8 -*-
import struct
import glob
import os
import re

def repack_gsc(gsc_path, txt_path, out_path):
    with open(gsc_path, 'rb') as f:
        data = bytearray(f.read())
    
    params = list(struct.unpack_from('iiiiiiiii', data, 0))
    str_offset_start = params[1] + params[2]
    num_strings = params[3] // 4
    
    string_offsets = []
    for i in range(num_strings):
        off = struct.unpack_from('i', data, str_offset_start + i*4)[0]
        string_offsets.append(off)
    
    str_data_start = str_offset_start + params[3]
    strings = []
    for i in range(num_strings):
        start = str_data_start + string_offsets[i]
        if i < num_strings - 1:
            end = str_data_start + string_offsets[i+1] - 1
        else:
            end = str_data_start + params[4] - 1
        raw = data[start:end]
        strings.append(raw)

    translation_map = {}
    if os.path.exists(txt_path):
        with open(txt_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Match ●ID●TYPE●Translation
            # Regex captures the ID (Group 1) and the translation (Group 2)
            # It matches ●, then digits, then ●, then any characters (TYPE), then ●, then everything until the next line starting with ○ or ● or end of file.
            matches = re.finditer(r'^●(\d+)●.*?●(.*?)(?=\n[○●]|\Z)', content, re.DOTALL | re.MULTILINE)
            for m in matches:
                idx = int(m.group(1))
                trans_s = m.group(2).strip()
                translation_map[idx] = trans_s.encode('cp932', errors='ignore')

    new_strings = list(strings)
    for idx, trans_bytes in translation_map.items():
        if idx < len(new_strings):
            new_strings[idx] = trans_bytes

    new_str_data = bytearray()
    new_offsets = []
    for s_bytes in new_strings:
        new_offsets.append(len(new_str_data))
        new_str_data.extend(s_bytes)
        new_str_data.append(0)

    new_str_table_bin = bytearray()
    for off in new_offsets:
        new_str_table_bin.extend(struct.pack('i', off))
    
    new_params = list(params)
    new_params[3] = len(new_str_table_bin)
    new_params[4] = len(new_str_data)

    # 关键：更新文件总大小 (params[0])
    # 公式：Header(36) + Junk(p1-36) + Commands(p2) + Table(p3) + Data(p4) + Trailer(15)
    new_total_size = params[1] + params[2] + new_params[3] + new_params[4] + 15
    new_params[0] = new_total_size

    new_file = struct.pack('iiiiiiiii', *new_params)
    new_file += data[36:params[1]]
    new_file += data[params[1]:params[1]+params[2]]
    new_file += new_str_table_bin
    new_file += new_str_data
    
    # 关键：补全 15 字节的空填充
    new_file += b'\x00' * 15

    with open(out_path, 'wb') as f:
        f.write(new_file)
    
    return True

def main():
    target_dir = os.getcwd()
    txt_dir = os.path.join(target_dir, 'extracted_txt_files')
    repack_dir = os.path.join(target_dir, 'repacked_gsc')
    
    if not os.path.exists(repack_dir):
        os.makedirs(repack_dir)
        
    gsc_files = glob.glob(os.path.join(target_dir, '*.gsc'))
    
    for gsc_path in gsc_files:
        fname = os.path.basename(gsc_path)
        txt_path = os.path.join(txt_dir, os.path.splitext(fname)[0] + '.txt')
        out_path = os.path.join(repack_dir, fname)
        
        if os.path.exists(txt_path):
            print(f"Repacking: {fname}...")
            repack_gsc(gsc_path, txt_path, out_path)
        else:
            print(f"Skipping {fname} (no txt found)")

    print(f"\nRepacking complete. Files saved to: {repack_dir}")

if __name__ == "__main__":
    main()
