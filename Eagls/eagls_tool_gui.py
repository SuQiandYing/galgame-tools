import os
import re
import json
import io
import math
import struct
import sys
import argparse
from pathlib import Path
from typing import Tuple, List, Dict
import threading

# GUI Libraries
import customtkinter as ctk
from tkinterdnd2 import DND_FILES, TkinterDnD

# --- Core Logic from scpacker.py ---

IDX_FILE = "SCPACK.idx"
PAK_FILE = "SCPACK.pak"

class MSVCRTRand:
    def __init__(self, seed: int = 0) -> None:
        self.__seed = seed
    @property
    def seed(self) -> int: return self.__seed
    @seed.setter
    def seed(self, seed: int) -> None: self.__seed = seed
    def rand(self) -> int:
        self.__seed = (214013 * self.__seed + 2531011) & 0x7FFFFFFF
        return self.__seed >> 16

def read_uint32(buffer: io.BytesIO) -> int: return struct.unpack("<I", buffer.read(4))[0]
def write_uint32(buffer: io.BytesIO, value: int) -> None: buffer.write(struct.pack("<I", value))
def read_int64(buffer: io.BytesIO) -> int: return struct.unpack("<q", buffer.read(8))[0]
def write_int64(buffer: io.BytesIO, value: int) -> None: buffer.write(struct.pack("<q", value))
def uint8_to_int8(value: int) -> int: return struct.unpack("<b", struct.pack("<B", value))[0]

def decrypt_idx(idx_bin: bytearray, idx_key: str) -> bytearray:
    idx_buf = io.BytesIO(idx_bin)
    idx_buf.seek(-4, 2)
    seed = read_uint32(idx_buf)
    rnd = MSVCRTRand(seed)
    key = idx_key.encode()
    for i in range(len(idx_bin) - 4):
        a = rnd.rand() % len(key)
        idx_bin[i] ^= key[a]
    return idx_bin

def find_idx_key(idx_bin: bytearray) -> str:
    def try_finding(key_len: int, seed: int, start: int) -> str:
        rnd = MSVCRTRand(seed)
        for _ in range(start): rnd.rand()
        local_seed = rnd.seed
        known_key = bytearray(key_len)
        key = bytearray(key_len)
        for i in range(start, len(idx_bin) - 4):
            b = idx_bin[i]
            a = rnd.rand() % key_len
            if known_key[a] == 0:
                known_key[a], key[a] = 1, b
            elif key[a] != b: return ""
        if any(b == 0 for b in known_key): return ""
        return key.decode()

    idx_buf = io.BytesIO(idx_bin)
    idx_buf.seek(-4, 2)
    seed = read_uint32(idx_buf)
    start = len(idx_bin) - 4 - 8192
    for key_len in range(1, 1024):
        res = try_finding(key_len, seed, start)
        if res: return res
    raise Exception("Could not find idx_key")

def get_data(idx_bin, pak_bin, long_offsets):
    name_size = 24 if long_offsets else 20
    idx_buf, pak_buf = io.BytesIO(idx_bin), io.BytesIO(pak_bin)
    data_dict = {}
    while True:
        filename_bytes = idx_buf.read(name_size)
        if not filename_bytes or not filename_bytes[0]: break
        filename = filename_bytes.decode().split("\x00", 1)[0]
        if long_offsets:
            idx_buf.seek(8, 1)
            length = read_int64(idx_buf)
        else:
            idx_buf.seek(4, 1)
            length = read_uint32(idx_buf)
        data_dict[filename] = bytearray(pak_buf.read(length))
    return data_dict

def decrypt_slice(data, text_offset, pak_key, version):
    key = pak_key.encode()
    if version == 1:
        for i in range(text_offset, len(data)):
            data[i] ^= key[(i - text_offset) % len(key)]
    elif version == 2:
        rnd = MSVCRTRand(uint8_to_int8(data[-1]))
        for i in range(text_offset, len(data) - 1, 2):
            data[i] ^= key[rnd.rand() % len(key)]
    return data

def find_pak_key(data_dict, label_dict, text_offset):
    def v1(key_len):
        key, known = bytearray(key_len), bytearray(key_len)
        for entry, data in data_dict.items():
            for label, offset in label_dict.get(entry, []):
                lbl = b"$" + label
                for i in range(len(lbl)):
                    target_idx = text_offset + offset + i
                    if target_idx >= len(data): break
                    a, b = (offset + i) % key_len, lbl[i] ^ data[target_idx]
                    if known[a] == 0: known[a], key[a] = 1, b
                    elif key[a] != b: return None
        if any(b == 0 for b in known): return None
        return key.decode(errors='replace')


    
    def v2(key_len):
        key, known = bytearray(key_len), bytearray(key_len)
        rnd = MSVCRTRand()
        for entry, data in data_dict.items():
            if len(data) == 0: continue
            index, rnd.seed = 0, uint8_to_int8(data[-1])
            for label, offset in label_dict.get(entry, []):
                lbl = b"$" + label
                for _ in range(index, offset, 2): rnd.rand(); index += 2
                off = offset + 1 if offset % 2 else offset
                l_start = 1 if offset % 2 else 0
                for i in range(0, len(lbl) - l_start, 2):
                    target_idx = text_offset + off + i
                    if target_idx >= len(data) - 1: 
                        rnd.rand(); index += 2; continue
                    a = rnd.rand() % key_len; index += 2
                    b = lbl[l_start + i] ^ data[target_idx]
                    if known[a] == 0: known[a], key[a] = 1, b
                    elif key[a] != b: return None
        if any(b == 0 for b in known): return None
        return key.decode(errors='replace')



    if text_offset is None: raise Exception("Could not determine text offset. Try ALIS mode or check your script archives.")
    for kl in range(1, 1024):
        res = v1(kl)
        if res: return res, 1
    for kl in range(1, 1024):
        res = v2(kl)
        if res: return res, 2
    raise Exception("Could not find pak_key. Is the archive encrypted?")


def get_labels_info(data_dict, label_size, alis):
    label_dict, textoffsets = {}, []
    for entry, data in data_dict.items():
        buf = io.BytesIO(data)
        labels = []
        while True:
            lbl_bytes = buf.read(label_size - 4)
            if not lbl_bytes or not lbl_bytes[0]: 
                if lbl_bytes: buf.seek(4, 1)
                break
            labels.append((lbl_bytes.split(b"\0", 1)[0], read_uint32(buf)))
        if not alis and labels:
            while True:
                chunk = buf.read(label_size)
                if not chunk: break
                if any(b != 0 for b in chunk):
                    textoffsets.append(int(math.ceil((buf.tell() - label_size) / 100.0)) * 100)
                    break
        label_dict[entry] = labels
    
    if alis: return label_dict, 136000
    if not textoffsets: return label_dict, None
    # Use the most frequent text_offset if it's dominant
    from collections import Counter
    most_common, count = Counter(textoffsets).most_common(1)[0]
    if count / len(textoffsets) > 0.8: return label_dict, most_common
    return label_dict, None


# --- Integrated Logic Class ---

class EaglsCore:
    def __init__(self, logger_callback):
        self.log = logger_callback
        self.NAME_PATTERN = re.compile(r'#([^=(&\n\r]+)')
        self.MSG_PATTERN = re.compile(r'&(\d+)"([^"]*)"')

    def unpack(self, script_path: Path, out_dir: Path, alis: bool, encoding: str):
        idx_path, pak_path = script_path / IDX_FILE, script_path / PAK_FILE
        idx_bin = bytearray(idx_path.read_bytes())
        pak_bin = bytearray(pak_path.read_bytes())
        long_off = (len(idx_bin) / 10000) >= 40
        idx_key = find_idx_key(idx_bin)
        idx_bin = decrypt_idx(idx_bin, idx_key)
        data_dict = get_data(idx_bin, pak_bin, long_off)
        label_size = 136 if alis else 36
        label_dict, text_off = get_labels_info(data_dict, label_size, alis)
        pak_key, ver = find_pak_key(data_dict, label_dict, text_off)
        
        out_dir.mkdir(exist_ok=True, parents=True)
        for filename, data in data_dict.items():
            data = decrypt_slice(data, text_off, pak_key, ver)
            txt_name = filename.rsplit(".", 1)[0] + ".txt"
            with open(out_dir / txt_name, "w", newline="", encoding=encoding, errors="replace") as f:
                f.write(data[text_off:-ver].decode(encoding, errors="replace"))
        self.log(f"Unpack finished: {len(data_dict)} files.")

    def fix_offsets(self, data_dict, label_dict, label_size, text_offset, version):
        for entry, data in data_dict.items():
            if entry not in label_dict or not label_dict[entry]: continue
            data_buf = io.BytesIO(data)
            script = data[text_offset:-version]
            index = 0
            for label, offset in label_dict[entry]:
                data_buf.seek(label_size, 1)
                try:
                    new_offset = script.index(b"$" + label, index)
                    if offset != new_offset:
                        data_buf.seek(-4, 1)
                        write_uint32(data_buf, new_offset)
                    index = new_offset + 1
                except ValueError:
                    continue
            data_dict[entry] = bytearray(data_buf.getvalue())
        return data_dict

    def fix_offsets(self, data_dict, label_dict, label_size, text_offset, version):
        for entry, data in data_dict.items():
            if entry not in label_dict or not label_dict[entry]: continue
            data_buf = io.BytesIO(data)
            script = data[text_offset:-version]
            index = 0
            for label, offset in label_dict[entry]:
                data_buf.seek(label_size, 1)
                try:
                    target = b"$" + label
                    new_offset = script.index(target, index)
                    if offset != new_offset:
                        data_buf.seek(-4, 1)
                        write_uint32(data_buf, new_offset)
                    index = new_offset + 1
                except ValueError: continue
            data_dict[entry] = bytearray(data_buf.getvalue())
        return data_dict

    def export_json(self, src_dir: Path, out_dir: Path, encoding: str):
        out_dir.mkdir(parents=True, exist_ok=True)
        for filepath in src_dir.glob("*.txt"):
            with open(filepath, 'r', encoding=encoding, errors='replace') as f:
                content = f.read()
            json_data, cur_name = [], None
            matches = []
            for m in self.NAME_PATTERN.finditer(content):
                matches.append({'type': 'name', 'value': m.group(1), 'start': m.start()})
            for m in self.MSG_PATTERN.finditer(content):
                matches.append({'type': 'msg', 'v': m.group(2), 'start': m.start()})
            matches.sort(key=lambda x: x['start'])
            if not any(m['type'] == 'msg' for m in matches): continue
            for m in matches:
                if m['type'] == 'name': cur_name = m['value']
                else:
                    item = {"name": cur_name, "message": m['v']} if cur_name else {"message": m['v']}
                    json_data.append(item); cur_name = None
            with open(out_dir / (filepath.name + ".json"), 'w', encoding='utf-8') as f:
                json.dump(json_data, f, ensure_ascii=False, indent=2)
        self.log("Export finished.")

    def import_json(self, src_dir: Path, json_dir: Path, out_dir: Path, encoding: str):
        out_dir.mkdir(parents=True, exist_ok=True)
        for filepath in src_dir.glob("*.txt"):
            json_path = json_dir / (filepath.name + ".json")
            with open(filepath, 'r', encoding=encoding, errors='replace') as f: content = f.read()
            if not json_path.exists():
                with open(out_dir / filepath.name, 'w', encoding=encoding, errors='replace') as f: f.write(content)
                continue
            with open(json_path, 'r', encoding='utf-8') as f: data = json.load(f)
            msgs = [i['message'] for i in data if 'message' in i]
            names = [i['name'] for i in data if 'name' in i]
            mc, nc = [0], [0]
            def r_msg(m):
                if mc[0] < len(msgs):
                    t = msgs[mc[0]]; mc[0] += 1
                    return f'&{m.group(1)}"{t}"'
                return m.group(0)
            def r_name(m):
                if nc[0] < len(names):
                    t = names[nc[0]]; nc[0] += 1
                    return f'#{t}'
                return m.group(0)
            res = self.NAME_PATTERN.sub(r_name, content)
            res = self.MSG_PATTERN.sub(r_msg, res)
            with open(out_dir / filepath.name, 'w', encoding=encoding, errors='replace') as f: f.write(res)
        self.log(f"Import finished: {len(msgs)} messages processed.")
    
    def run_safe(self, func, *args):
        try:
            func(*args)
        except Exception as e:
            self.log(f"CRITICAL ERROR: {str(e)}")
            import traceback
            traceback.print_exc()


    def pack(self, script_path: Path, data_dir: Path, alis: bool, encoding: str):
        # Simplification: we reuse some scpacker.py structures
        idx_path, pak_path = script_path / IDX_FILE, script_path / PAK_FILE
        idx_bin = bytearray(idx_path.read_bytes())
        pak_bin = bytearray(pak_path.read_bytes())
        idx_key = find_idx_key(idx_bin)
        idx_bin_dec = decrypt_idx(bytearray(idx_bin), idx_key)
        long_off = (len(idx_bin) / 10000) >= 40
        data_old = get_data(idx_bin_dec, pak_bin, long_off)
        label_size = 136 if alis else 36
        label_dict, text_off = get_labels_info(data_old, label_size, alis)
        pak_key, ver = find_pak_key(data_old, label_dict, text_off)

        data_new = {}
        for entry, d_old in data_old.items():
            txt_name = entry.rsplit(".", 1)[0] + ".txt"
            d_old = decrypt_slice(d_old, text_off, pak_key, ver)
            try:
                with open(data_dir / txt_name, "r", encoding=encoding, errors="replace") as f:
                    body = f.read().encode(encoding, errors="replace")
                data_new[entry] = d_old[:text_off] + body + d_old[-ver:]
            except: data_new[entry] = d_old

        # CRITICAL: Fix absolute offsets in script headers before encryption
        self.log("正在修正脚本偏移量...")
        data_new = self.fix_offsets(data_new, label_dict, label_size, text_off, ver)

        # Re-encrypt and write

        new_idx, new_pak = io.BytesIO(), io.BytesIO()
        idx_dec_buf = io.BytesIO(idx_bin_dec)
        name_size = 24 if long_off else 20
        base_addr = 0
        while True:
            fname_bytes = idx_dec_buf.read(name_size)
            if not fname_bytes or not fname_bytes[0]: break
            name = fname_bytes.decode().split("\x00", 1)[0]
            d = data_new[name]
            new_idx.write(fname_bytes)
            if long_off:
                if not base_addr: base_addr = read_int64(idx_dec_buf); idx_dec_buf.seek(8, 1)
                else: idx_dec_buf.seek(16, 1)
                write_int64(new_idx, new_pak.tell() + base_addr); write_int64(new_idx, len(d))
            else:
                if not base_addr: base_addr = read_uint32(idx_dec_buf); idx_dec_buf.seek(4, 1)
                else: idx_dec_buf.seek(8, 1)
                write_uint32(new_idx, new_pak.tell() + base_addr); write_uint32(new_idx, len(d))
            new_pak.write(decrypt_slice(bytearray(d), text_off, pak_key, ver))
        new_idx.write(fname_bytes); new_idx.write(idx_dec_buf.read())
        idx_path.write_bytes(decrypt_idx(bytearray(new_idx.getvalue()), idx_key))
        pak_path.write_bytes(new_pak.getvalue())
        self.log("Pack finished.")

# --- GUI Application ---

class EaglsApp(TkinterDnD.DnDWrapper, ctk.CTk):
    def __init__(self):
        super().__init__()
        self.TkdndVersion = TkinterDnD._require(self)
        
        self.title("EAGLS/ALIS 综合汉化助手")
        self.geometry("900x650")
        ctk.set_appearance_mode("dark")
        
        self.core = EaglsCore(self.log)
        self.setup_ui()

    def setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # Drop Zone
        self.drop_label = ctk.CTkLabel(self, text="将 文件夹 或 SCPACK.idx 拖入此处", height=120, fg_color="#2B2B2B", corner_radius=10)
        self.drop_label.grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        self.drop_label.drop_target_register(DND_FILES)
        self.drop_label.dnd_bind('<<Drop>>', self.handle_drop)

        # Path Display
        self.path_var = ctk.StringVar(value="当前未选择路径")
        self.path_label = ctk.CTkLabel(self, textvariable=self.path_var, font=("微软雅黑", 12))
        self.path_label.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        # Config Area
        config_frame = ctk.CTkFrame(self)
        config_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        
        ctk.CTkLabel(config_frame, text="脚本编码:").grid(row=0, column=0, padx=10, pady=10)
        self.enc_var = ctk.StringVar(value="cp932")
        self.enc_menu = ctk.CTkOptionMenu(config_frame, values=["cp932", "gbk", "shift_jis", "utf-8"], variable=self.enc_var)
        self.enc_menu.grid(row=0, column=1, padx=10, pady=10)
        
        self.alis_var = ctk.BooleanVar(value=False)
        self.alis_cb = ctk.CTkCheckBox(config_frame, text="ALIS 变体", variable=self.alis_var)
        self.alis_cb.grid(row=0, column=2, padx=20, pady=10)

        # Tabs / Buttons
        btn_frame = ctk.CTkFrame(self)
        btn_frame.grid(row=3, column=0, padx=20, pady=10, sticky="nsew")
        btn_frame.columnconfigure((0,1), weight=1)
        
        ctk.CTkButton(btn_frame, text="解包 (Unpack)", command=self.run_unpack).grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        ctk.CTkButton(btn_frame, text="导出 JSON (Export)", command=self.run_export).grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        ctk.CTkButton(btn_frame, text="注入译文 (Import)", command=self.run_import).grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        ctk.CTkButton(btn_frame, text="封包 (Pack)", command=self.run_pack).grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        # Log Console
        self.log_text = ctk.CTkTextbox(self, height=180, font=("Consolas", 11))
        self.log_text.grid(row=4, column=0, padx=20, pady=20, sticky="ew")
        self.log("工具就绪。支持拖拽操作。")

    def log(self, msg):
        self.log_text.insert("end", f"[{threading.current_thread().name}] {msg}\n")
        self.log_text.see("end")

    def handle_drop(self, event):
        path = event.data.strip('{}')
        self.path_var.set(path)
        self.log(f"已选择路径: {path}")

    def get_path(self):
        p = self.path_var.get()
        if p == "当前未选择路径": return None
        return Path(p)

    def run_thread(self, target, args):
        threading.Thread(target=target, args=args, name="Worker", daemon=True).start()

    def run_safe(self, func, *args):
        try:
            func(*args)
        except Exception as e:
            self.log(f"操作失败: {str(e)}")
            import traceback
            traceback.print_exc()

    def run_unpack(self):
        p = self.get_path()
        if not p: return
        src = p if p.is_dir() else p.parent
        self.run_thread(self.run_safe, (self.core.unpack, src, src / "Script_Raw", self.alis_var.get(), self.enc_var.get()))

    def run_export(self):
        p = self.get_path()
        if not p or not p.is_dir(): return
        # Auto-detect Script_Raw if current dir is empty
        src = p
        if not list(p.glob("*.txt")) and (p / "Script_Raw").exists():
            src = p / "Script_Raw"
            self.log(f"No txt in root, using subfolder: {src}")
        self.run_thread(self.run_safe, (self.core.export_json, src, src / "Export_JSON", self.enc_var.get()))

    def run_import(self):
        p = self.get_path()
        if not p or not p.is_dir(): return
        src = p
        if not list(p.glob("*.txt")) and (p / "Script_Raw").exists():
            src = p / "Script_Raw"
            self.log(f"Using subfolder for import: {src}")
        json_dir = src / "Export_JSON"
        if not json_dir.exists(): self.log("错误: 未找到 Export_JSON 目录"); return
        self.run_thread(self.run_safe, (self.core.import_json, src, json_dir, src.parent / "Script_Translated", self.enc_var.get()))

    def run_pack(self):
        p = self.get_path()
        if not p: return
        archive_dir = p if p.is_dir() else p.parent
        # Try to find Script_Translated relative to archive or root
        data_dir = archive_dir / "Script_Translated"
        if not data_dir.exists() and (archive_dir / "Script_Raw" / "Script_Translated").exists():
             data_dir = archive_dir / "Script_Raw" / "Script_Translated"
        
        if not data_dir.exists(): self.log("错误: 未找到 Script_Translated 目录"); return
        self.run_thread(self.run_safe, (self.core.pack, archive_dir, data_dir, self.alis_var.get(), self.enc_var.get()))


if __name__ == "__main__":
    app = EaglsApp()
    app.mainloop()
