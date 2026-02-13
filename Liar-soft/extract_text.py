# -*- coding: utf-8 -*-
import struct
import glob
import os

def parse_gsc_to_text(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    
    # Header params
    params = list(struct.unpack_from('iiiiiiiii', data, 0))
    
    # Read strings section
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
        try:
            s = raw.decode('cp932', errors='ignore').replace('\x00', '')
        except:
            s = repr(raw)
        strings.append(s)
    
    CommandsLibrary = {
        0x03: ('i', 'JUMP_UNLESS'), 0x05: ('i', 'JUMP'), 0x0D: ('i', 'PAUSE'),
        0x0C: ('ii', 'CALL_SCRIPT'), 0x0E: ('hiiiiiiiiiiiiii', 'CHOICE'),
        0x14: ('ii', 'IMAGE_GET'), 0x1A: ('', 'IMAGE_SET'), 0x1C: ('iii', 'BLEND_IMG'),
        0x1E: ('iiiiii', 'IMAGE_DEF'), 0x51: ('iiiiiii', 'MESSAGE'),
        0x52: ('iiiiii', 'APPEND_MESSAGE'), 0x53: ('i', 'CLEAR_MESSAGE_WINDOW'),
        0x79: ('ii', 'GET_DIRECTORY'), 0xC8: ('iiiiiiiiiii', 'READ_SCENARIO'),
        0xFF: ('iiiii', 'SPRITE'),
    }

    results = []
    cmd_start = params[1]
    pos = cmd_start
    cmd_end = cmd_start + params[2]
    
    while pos < cmd_end:
        code = struct.unpack_from('H', data, pos)[0]
        pos += 2
        
        fmt_info = CommandsLibrary.get(code)
        if fmt_info:
            fmt, name = fmt_info
        else:
            if (code & 0xf000) == 0xf000: fmt = 'hh'
            elif (code & 0xf000) == 0x0000: fmt = ''
            else: fmt = 'hhh'
        
        args = []
        for c in fmt:
            if c in ('i', 'I'):
                if pos + 4 > len(data): break
                val = struct.unpack_from(c, data, pos)[0]
                pos += 4
                args.append(val)
            elif c in ('h', 'H'):
                if pos + 2 > len(data): break
                val = struct.unpack_from(c, data, pos)[0]
                pos += 2
                args.append(val)
        
        if code == 0x51:  # MESSAGE
            if len(args) > 5:
                name_idx = args[4]
                text_idx = args[5]
                results.append({"type": "NAME", "idx": name_idx})
                results.append({"type": "TEXT", "idx": text_idx})
        
        elif code == 0x52:  # APPEND_MESSAGE
            if len(args) > 4:
                text_idx = args[4]
                results.append({"type": "APPEND", "idx": text_idx})
                
        elif code == 0x0E:  # CHOICE
            for ci in [1, 7, 8, 9, 10, 11]:
                if ci < len(args):
                    results.append({"type": "CHOICE", "idx": args[ci]})

    return results, strings

def main():
    target_dir = os.getcwd()
    gsc_files = sorted(glob.glob(os.path.join(target_dir, '*.gsc')))
    output_dir = os.path.join(target_dir, 'extracted_txt_files')
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    for fpath in gsc_files:
        fname = os.path.basename(fpath)
        out_fname = os.path.splitext(fname)[0] + '.txt'
        out_path = os.path.join(output_dir, out_fname)
        
        try:
            entries, strings = parse_gsc_to_text(fpath)
            if not entries:
                continue
                
            indices_seen = set()
            with open(out_path, 'w', encoding='utf-8') as out:
                for entry in entries:
                    idx = entry['idx']
                    if idx < 0 or idx >= len(strings) or idx in indices_seen:
                        continue
                    text = strings[idx].strip()
                    if not text:
                        continue
                    
                    t_type = entry['type']
                    out.write(f"○{idx:04d}○{t_type}○{strings[idx]}\n")
                    out.write(f"●{idx:04d}●{t_type}●{strings[idx]}\n\n")
                    indices_seen.add(idx)
            
            if indices_seen:
                print(f"Extracted: {fname} -> {out_fname}")
            else:
                if os.path.exists(out_path):
                    os.remove(out_path)
        except Exception as e:
            print(f"Error parsing {fname}: {e}")
    
    print(f"\nExtraction complete. Format: ○ID○TYPE○ORIGINAL")

if __name__ == "__main__":
    main()
