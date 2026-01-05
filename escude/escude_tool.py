# -*- coding:utf-8 -*-
import os
import sys
import struct
import json
import shutil
import random
from io import BytesIO
from dataclasses import dataclass
from typing import List, Tuple, Optional

os.environ["QT_QPA_FONTDIR"] = ""

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QFileDialog,
                             QTextEdit, QProgressBar, QFrame, QLineEdit,
                             QGraphicsDropShadowEffect, QStackedWidget, QMessageBox, 
                             QComboBox, QRadioButton, QButtonGroup, QListWidget,
                             QListWidgetItem, QSplitter, QScrollArea, QSizePolicy)
from PyQt6.QtCore import (Qt, QThread, pyqtSignal, QPropertyAnimation, QEasingCurve, 
                          QPoint, QRectF, QUrl, QSettings, pyqtProperty, QMimeData)
from PyQt6.QtGui import (QFont, QColor, QPainter, QPainterPath, QDragEnterEvent, 
                         QDropEvent, QDesktopServices, QPen, QCloseEvent, QLinearGradient,
                         QFontDatabase)

FONT_FAMILY = "Microsoft YaHei"
FONT_FALLBACKS = ["Yu Gothic", "Meiryo", "MS Gothic", "SimSun", "Segoe UI", "Arial"]
MONO_FONT = "Consolas"
MONO_FALLBACKS = ["MS Gothic", "Yu Gothic", "Source Code Pro", "Courier New", "monospace"]

def get_app_font(size=10, bold=False):
    font = QFont("Microsoft YaHei", size)
    if bold: font.setBold(True)
    return font

def get_jp_font(size=10):
    """获取适合显示日文的字体"""
    # 优先尝试常见的日文字体
    jp_fonts = ["Yu Gothic", "Meiryo", "MS Gothic", "Microsoft YaHei", "SimSun"]
    for name in jp_fonts:
        if name in QFontDatabase().families():
            return QFont(name, size)
    return QFont("sans-serif", size)


def get_mono_font(size=11):
    font = QFont(MONO_FONT)
    font.setFamilies([MONO_FONT] + MONO_FALLBACKS)
    font.setPointSize(size)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    return font

def get_jp_font(size=10):
    font = QFont("Yu Gothic")
    font.setFamilies(["Yu Gothic", "Meiryo", "MS Gothic", "Microsoft YaHei", "SimSun"])
    font.setPointSize(size)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    return font

OPDICT = {
    '01': '', '02': 'I', '03': '', '04': 'I', '05': 'I', '06': '', '07': 'I', '09': 'I',
    '0a': 'I', '0b': 'I', '0c': 'I', '0d': 'I', '0e': '', '0f': 'I', '10': 'I', '11': 'I',
    '12': '', '14': '', '13': '', '16': '', '18': '', '19': '', '1a': '', '1b': '',
    '1c': '', '1d': '', '1e': '', '1f': '', '20': '', '21': '', '22': '', '23': '',
    '24': '', '25': '', '26': '', '27': '', '28': 'I', '29': 's', '2a': '', '2b': 'sI',
    '2c': 'I', '2d': 'I'
}

ENCODINGS = {
    "日文 (CP932/Shift-JIS)": "cp932",
    "简体中文 (CP936/GBK)": "cp936", 
    "繁体中文 (Big5)": "big5",
    "UTF-8": "utf-8"
}

CONFIG_FILE = "acpx_config.json"
SHIFT_JIS = 'cp932'

ENUM_ENTRY_SIZE = 132
ENUM_HEADER_SIZE = 16
ENUM_MAGIC = b'LIST'

THEMES = {
    "🌸 樱花 (Sakura)": {
        "bg_grad": ["#Fce4ec", "#F3E5F5", "#E1BEE7"],
        "accent": "#ff80ab",
        "btn_hover": "#ff4081",
        "text_main": "#333333",
        "text_dim": "#555555",
        "card_bg": "rgba(255, 255, 255, 0.65)",
        "input_bg": "rgba(255,255,255,0.5)",
        "input_focus": "rgba(255,255,255,0.9)",
        "border": "rgba(255, 255, 255, 0.8)"
    },
    "🌊 深海 (Ocean)": {
        "bg_grad": ["#E3F2FD", "#BBDEFB", "#90CAF9"],
        "accent": "#2196F3",
        "btn_hover": "#1976D2",
        "text_main": "#0D47A1",
        "text_dim": "#1565C0",
        "card_bg": "rgba(255, 255, 255, 0.75)",
        "input_bg": "rgba(255,255,255,0.6)",
        "input_focus": "#FFFFFF",
        "border": "rgba(255, 255, 255, 0.8)"
    },
    "🍃 薄荷 (Mint)": {
        "bg_grad": ["#E0F2F1", "#B2DFDB", "#80CBC4"],
        "accent": "#009688",
        "btn_hover": "#00796B",
        "text_main": "#004D40",
        "text_dim": "#00695C",
        "card_bg": "rgba(255, 255, 255, 0.7)",
        "input_bg": "rgba(255,255,255,0.5)",
        "input_focus": "#FFFFFF",
        "border": "rgba(255, 255, 255, 0.8)"
    },
    "🌙 暗夜 (Night)": {
        "bg_grad": ["#232526", "#414345", "#232526"],
        "accent": "#BB86FC",
        "btn_hover": "#985EFF",
        "text_main": "#E0E0E0",
        "text_dim": "#B0B0B0",
        "card_bg": "rgba(30, 30, 30, 0.75)",
        "input_bg": "rgba(60, 60, 60, 0.5)",
        "input_focus": "rgba(80, 80, 80, 0.9)",
        "border": "rgba(80, 80, 80, 0.8)"
    },
    "🍊 活力 (Sunset)": {
        "bg_grad": ["#FFF3E0", "#FFE0B2", "#FFCC80"],
        "accent": "#FF9800",
        "btn_hover": "#F57C00",
        "text_main": "#E65100",
        "text_dim": "#EF6C00",
        "card_bg": "rgba(255, 255, 255, 0.7)",
        "input_bg": "rgba(255,255,255,0.5)",
        "input_focus": "#FFFFFF",
        "border": "rgba(255, 255, 255, 0.8)"
    }
}

class BytesReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0
    def read(self, n):
        res = self.data[self.pos:self.pos+n]
        self.pos += n
        return res
    def readU32(self):
        if self.pos + 4 > len(self.data): return 0
        return struct.unpack('<I', self.read(4))[0]
    def seek(self, pos):
        self.pos = pos
    def tell(self):
        return self.pos
    def is_end(self):
        return self.pos >= len(self.data)
    def read_until_zero(self, terminator=b'\x00'):
        start = self.pos
        end = self.data.find(terminator, start)
        if end == -1: end = len(self.data)
        res = self.data[start:end]
        self.pos = end + len(terminator)
        return res

class EscudeCrypto:
    def __init__(self, key: int):
        self._key = key & 0xFFFFFFFF

    @property
    def key(self) -> int:
        self._key ^= 0x65AC9365
        self._key &= 0xFFFFFFFF
        term1 = ((self._key >> 1) ^ self._key) >> 3
        term2 = ((self._key << 1) ^ self._key) & 0xFFFFFFFF
        term2 = (term2 << 3) & 0xFFFFFFFF
        self._key ^= (term1 ^ term2)
        self._key &= 0xFFFFFFFF
        return self._key

    def decrypt(self, data: bytes) -> bytes:
        output = bytearray(data)
        length = len(output)
        for i in range(0, length & ~3, 4):
            current_key = self.key
            chunk = struct.unpack_from('<I', output, i)[0]
            decrypted = chunk ^ current_key
            struct.pack_into('<I', output, i, decrypted)
        return bytes(output)

    def encrypt(self, data: bytes) -> bytes:
        return self.decrypt(data)

class MsbBitStream:
    def __init__(self, data: bytes):
        self.input = BytesIO(data)
        self.bits = 0
        self.cached_bits = 0

    def get_bits(self, count: int) -> int:
        while self.cached_bits < count:
            b = self.input.read(1)
            if not b:
                return -1
            byte_val = ord(b)
            self.bits = (self.bits << 8) | byte_val
            self.cached_bits += 8
        mask = (1 << count) - 1
        self.cached_bits -= count
        return (self.bits >> self.cached_bits) & mask

class LzwDecoder:
    def __init__(self, data: bytes, unpacked_size: int):
        self.bit_stream = MsbBitStream(data)
        self.output = bytearray(unpacked_size)
        self.unpacked_size = unpacked_size

    def unpack(self) -> bytes:
        dst = 0
        lzw_dict_size = 0x8900
        lzw_dict = [0] * lzw_dict_size 
        token_width = 9
        dict_pos = 0
        
        while dst < len(self.output):
            token = self.bit_stream.get_bits(token_width)
            if token == -1:
                break
            if token == 0x100:
                break
            elif token == 0x101:
                token_width += 1
                if token_width > 24:
                    raise ValueError("Invalid compressed stream (Token Width > 24)")
            elif token == 0x102:
                token_width = 9
                dict_pos = 0
            else:
                if dict_pos >= len(lzw_dict):
                    raise ValueError("Invalid compressed stream (Dict Full)")
                lzw_dict[dict_pos] = dst
                dict_pos += 1
                if token < 0x100:
                    self.output[dst] = token
                    dst += 1
                else:
                    token -= 0x103
                    if token >= dict_pos:
                        raise ValueError("Invalid compressed stream (Token out of bounds)")
                    src = lzw_dict[token]
                    ref_next = 0
                    if token + 1 < len(lzw_dict):
                        ref_next = lzw_dict[token + 1]
                    if src >= len(self.output): 
                        raise ValueError("Dict reference out of bounds")
                    count = min(len(self.output) - dst, ref_next - src + 1)
                    if count < 0:
                        raise ValueError(f"Invalid count: {count}")
                    for i in range(count):
                        self.output[dst + i] = self.output[src + i]
                    dst += count
        return bytes(self.output)

@dataclass
class BinEntry:
    n_offset: int
    d_offset: int
    length: int

    @staticmethod
    def struct_fmt() -> str:
        return "<3I"

    @staticmethod
    def size() -> int:
        return struct.calcsize(BinEntry.struct_fmt())

@dataclass
class BinHeader:
    file_count: int
    name_tbl_len: int
    entries: List[BinEntry]

    @staticmethod
    def parse(data: bytes) -> 'BinHeader':
        fmt_head = "<2I"
        head_size = struct.calcsize(fmt_head)
        file_count, name_tbl_len = struct.unpack_from(fmt_head, data, 0)
        entries = []
        offset = head_size
        entry_size = BinEntry.size()
        entry_fmt = BinEntry.struct_fmt()
        for _ in range(file_count):
            n_off, d_off, ln = struct.unpack_from(entry_fmt, data, offset)
            entries.append(BinEntry(n_off, d_off, ln))
            offset += entry_size
        return BinHeader(file_count, name_tbl_len, entries)

    def pack(self) -> bytes:
        out = bytearray()
        out.extend(struct.pack("<2I", self.file_count, self.name_tbl_len))
        for entry in self.entries:
            out.extend(struct.pack(BinEntry.struct_fmt(), entry.n_offset, entry.d_offset, entry.length))
        return bytes(out)

class EscudeManager:
    @staticmethod
    def unpack_archive(file_path: str, output_dir: str, logger=print):
        with open(file_path, 'rb') as f:
            f.seek(0x8)
            raw_key = struct.unpack('<I', f.read(4))[0]
            temp_crypto = EscudeCrypto(raw_key)
            decryption_key = temp_crypto.key
            f.seek(0xC)
            enc_count = struct.unpack('<I', f.read(4))[0]
            file_count = enc_count ^ decryption_key
            header_size = (file_count * 12) + 8
            crypto = EscudeCrypto(raw_key)
            f.seek(0xC)
            encrypted_header = f.read(header_size)
            header_data = crypto.decrypt(encrypted_header)
            bin_header = BinHeader.parse(header_data)
            if bin_header.file_count != file_count:
                logger(f"警告: 文件数不匹配 {bin_header.file_count} != {file_count}")
            name_table_start = 0xC + 8 + (bin_header.file_count * 12)
            os.makedirs(output_dir, exist_ok=True)
            extracted = 0
            for entry in bin_header.entries:
                name_offset_abs = name_table_start + entry.n_offset
                f.seek(name_offset_abs)
                file_name = EscudeManager.read_cstring(f)
                f.seek(entry.d_offset)
                content = f.read(entry.length)
                if content.startswith(b'acp\x00'):
                    content = EscudeManager.decompress(content)
                out_path = os.path.join(output_dir, file_name)
                os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else output_dir, exist_ok=True)
                with open(out_path, 'wb') as out_f:
                    out_f.write(content)
                extracted += 1
                logger(f"  解包: {file_name}")
        logger(f"完成! 共解包 {extracted} 个文件到 {output_dir}")
        return bin_header

    @staticmethod
    def read_cstring(f) -> str:
        chars = []
        while True:
            b = f.read(1)
            if b == b'\x00' or not b:
                break
            chars.append(b)
        return b"".join(chars).decode(SHIFT_JIS, errors='replace')

    @staticmethod
    def decompress(data: bytes) -> bytes:
        if len(data) < 8:
            return data
        magic = data[0:4]
        if magic != b'acp\x00':
            return data
        unpacked_len = struct.unpack('>I', data[4:8])[0]
        decoder = LzwDecoder(data[8:], unpacked_len)
        decoder.unpack()
        return decoder.output

    @staticmethod
    def pack_archive(folder_path: str, output_file: str, logger=print):
        files = []
        for root, dirs, filenames in os.walk(folder_path):
            for filename in filenames:
                if filename == "FileList.lst":
                    continue
                rel_path = os.path.relpath(os.path.join(root, filename), folder_path)
                files.append((rel_path, os.path.join(root, filename)))
        bin_entries = []
        file_blobs = []
        name_blob = bytearray()
        for rel_path, full_path in files:
            with open(full_path, 'rb') as f:
                content = f.read()
            file_blobs.append(content)
            try:
                enc_name = rel_path.encode(SHIFT_JIS)
            except UnicodeEncodeError:
                enc_name = rel_path.encode(SHIFT_JIS, errors='replace')
            name_offset_rel = len(name_blob)
            name_blob.extend(enc_name)
            name_blob.append(0)
            entry = BinEntry(n_offset=name_offset_rel, d_offset=0, length=len(content))
            bin_entries.append(entry)
        header_struct_size = 8 + (len(files) * 12)
        name_tbl_len = len(name_blob)
        data_start_offset = 0xC + header_struct_size + name_tbl_len
        current_off = data_start_offset
        for i in range(len(bin_entries)):
            bin_entries[i].d_offset = current_off
            current_off += bin_entries[i].length
        header_obj = BinHeader(len(files), name_tbl_len, bin_entries)
        header_bytes = header_obj.pack()
        key_int = random.getrandbits(32)
        key_bytes = struct.pack('<I', key_int)
        crypto = EscudeCrypto(key_int)
        encrypted_header = crypto.encrypt(header_bytes)
        with open(output_file, 'wb') as out_f:
            out_f.write(b'ESC-ARC2')
            out_f.write(key_bytes)
            out_f.write(encrypted_header)
            out_f.write(name_blob)
            for blob in file_blobs:
                out_f.write(blob)
        logger(f"完成! 共打包 {len(files)} 个文件到 {output_file}")

    @staticmethod
    def load_script(path: str) -> Tuple[List[str], dict]:
        with open(path, 'rb') as f:
            data = f.read()
        if data[:8].decode('ascii', errors='ignore') != "ESCR1_00":
            raise ValueError("无效的脚本签名 (需要 ESCR1_00)")
        offset = 8
        str_count = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        str_offsets = []
        for _ in range(str_count):
            off = struct.unpack_from('<I', data, offset)[0]
            str_offsets.append(off)
            offset += 4
        vm_len = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        vm_data = data[offset : offset+vm_len]
        offset += vm_len
        unk1 = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        string_table_start = offset
        strings = []
        for rel_off in str_offsets:
            abs_off = string_table_start + rel_off
            st = EscudeManager.read_cstring_bytes(data, abs_off)
            strings.append(st)
        decoded_strings = [EscudeManager.decode_script_string(s) for s in strings]
        context = {
            'vm_data': vm_data,
            'unk1': unk1,
            'header_sig': b"ESCR1_00"
        }
        return decoded_strings, context

    @staticmethod
    def read_cstring_bytes(data: bytes, offset: int) -> str:
        end = data.find(b'\x00', offset)
        if end == -1:
            end = len(data)
        raw = data[offset:end]
        return raw.decode(SHIFT_JIS, errors='replace')

    @staticmethod
    def decode_script_string(text: str) -> str:
        half = "!?｡｢｣､･ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝﾞﾟ"
        full = "！？。「」、…をぁぃぅぇぉゃゅょっーあいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわん゛゜"
        res = []
        for char in text:
            if char in half:
                idx = half.index(char)
                res.append(full[idx])
            else:
                res.append(char)
        return "".join(res)

    @staticmethod
    def encode_script_string(text: str) -> str:
        half = "!?｡｢｣､･ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝﾞﾟ"
        full = "！？。「」、…をぁぃぅぇぉゃゅょっーあいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわん゛゜"
        res = []
        for char in text:
            if char in full:
                idx = full.index(char)
                res.append(half[idx])
            else:
                res.append(char)
        return "".join(res)

    @staticmethod
    def save_script(path: str, strings: List[str], context: dict):
        enc_strings = [EscudeManager.encode_script_string(s) for s in strings]
        str_blob = bytearray()
        offsets = []
        current_len = 0
        for s in enc_strings:
            offsets.append(current_len)
            b = s.encode(SHIFT_JIS, errors='replace') + b'\x00'
            str_blob.extend(b)
            current_len += len(b)
        with open(path, 'wb') as f:
            f.write(context['header_sig'])
            f.write(struct.pack('<I', len(strings)))
            for off in offsets:
                f.write(struct.pack('<I', off))
            vm_data = context['vm_data']
            f.write(struct.pack('<I', len(vm_data)))
            f.write(vm_data)
            f.write(struct.pack('<I', context['unk1']))
            f.write(str_blob)

    @staticmethod
    def load_enum_scr(filepath):
        """读取enum_scr.bin文件 - 分行显示逻辑"""
        with open(filepath, 'rb') as f:
            data = f.read()
        
        if data[:4] != ENUM_MAGIC:
            raise ValueError(f"Invalid magic: expected 'LIST', got {data[:4]}")
        
        data_size = struct.unpack_from('<I', data, 4)[0]
        unknown1 = struct.unpack_from('<I', data, 8)[0]
        unknown2 = struct.unpack_from('<I', data, 12)[0]
        
        num_blocks = (len(data) - ENUM_HEADER_SIZE) // ENUM_ENTRY_SIZE
        
        sub_entries = []
        for i in range(num_blocks):
            offset = ENUM_HEADER_SIZE + i * ENUM_ENTRY_SIZE
            block_data = bytearray(data[offset:offset+ENUM_ENTRY_SIZE])
            
            # 提取字符串
            pos = 0
            block_strings = []
            while pos < ENUM_ENTRY_SIZE:
                # 跳过控制字符和 0xFF，但不跳过空格 (0x20)
                # 很多时候名字前面可能有空格或者就是空格
                # 按照用户要求，将空格 (0x20) 也作为分隔符处理 (separate=(\x00|\x20))
                while pos < ENUM_ENTRY_SIZE and (block_data[pos] <= 0x20 or block_data[pos] == 0xFF):
                    pos += 1
                if pos >= ENUM_ENTRY_SIZE:
                    break
                
                start = pos
                while pos < ENUM_ENTRY_SIZE and block_data[pos] != 0x00 and block_data[pos] != 0x20 and block_data[pos] != 0xFF:
                    pos += 1
                
                if pos > start:
                    raw = block_data[start:pos]
                    try:
                        # 不使用 strip()，保留原始空格，只在显示时处理
                        s = raw.decode('cp932')
                        
                        # 垃圾过滤 - 更加宽松
                        is_garbage = False
                        if not s: is_garbage = True
                        # 只有当全是控制字符时才算垃圾
                        if all(ord(c) < 0x20 for c in s): is_garbage = True
                        if s in ['', '＿']: is_garbage = True
                        # 允许长度为1或2的任何字符，只要能解码
                            
                        if not is_garbage:
                            block_strings.append({
                                'off': start,
                                'len': len(raw),
                                'text': s
                            })
                    except:
                        pass
                pos += 1
            
            # 如果没有找到任何字符串，也要保留一个空的
            if not block_strings:
                sub_entries.append({
                    'main_index': i,
                    'sub_index': 0,
                    'name': '',
                    'off': 0,
                    'len': 0,
                    'raw_block': block_data
                })
            else:
                # 不再进行文本去重，保留块内所有独立的字符串条目
                s_idx = 0
                for info in block_strings:
                    sub_entries.append({
                        'main_index': i,
                        'sub_index': s_idx,
                        'name': info['text'],
                        'off': info['off'],
                        'len': info['len'],
                        'raw_block': block_data
                    })
                    s_idx += 1
        
        return {
            'data_size': data_size,
            'unknown1': unknown1,
            'unknown2': unknown2,
            'raw_header': data[:ENUM_HEADER_SIZE],
            'entries': sub_entries # 现在 entries 是平坦的子条目列表
        }

    @staticmethod
    def save_enum_scr(filepath, enum_data):
        """写入enum_scr.bin文件 - 精准回封逻辑"""
        # 按 main_index 重新组织块
        blocks_map = {}
        for entry in enum_data['entries']:
            m_idx = entry['main_index']
            if m_idx not in blocks_map:
                blocks_map[m_idx] = {
                    'raw': bytearray(entry.get('raw_block', b'\x00' * ENUM_ENTRY_SIZE)),
                    'subs': []
                }
            blocks_map[m_idx]['subs'].append(entry)
            
        max_idx = max(blocks_map.keys()) if blocks_map else -1
        
        with open(filepath, 'wb') as f:
            # Header
            if 'raw_header' in enum_data:
                f.write(enum_data['raw_header'])
            else:
                f.write(ENUM_MAGIC)
                f.write(struct.pack('<I', (max_idx + 1) * ENUM_ENTRY_SIZE + 8))
                f.write(struct.pack('<I', enum_data.get('unknown1', 0)))
                f.write(struct.pack('<I', enum_data.get('unknown2', 0x4284)))
            
            for i in range(max_idx + 1):
                block_info = blocks_map.get(i)
                if not block_info:
                    f.write(b'\x00' * ENUM_ENTRY_SIZE)
                    continue
                
                raw = block_info['raw']
                # 按偏移排序，避免写入冲突
                subs = sorted(block_info['subs'], key=lambda x: x['off'])
                
                for entry in subs:
                    if not entry['name'] or entry['len'] == 0:
                        continue
                    
                    try:
                        new_bytes = entry['name'].encode('cp932')
                        # 计算限制空间：不撞到下一个子条目的起始位置，且不超过块末尾
                        limit = ENUM_ENTRY_SIZE - entry['off']
                        
                        # 查找下一个被占用的位置
                        next_occupied = ENUM_ENTRY_SIZE
                        for other in subs:
                            if other['off'] > entry['off']:
                                next_occupied = other['off']
                                break
                        
                        limit = next_occupied - entry['off']
                        
                        # 写入
                        write_len = min(len(new_bytes), limit - 1)
                        for k in range(write_len):
                            raw[entry['off'] + k] = new_bytes[k]
                        
                        # 补零
                        if entry['off'] + write_len < ENUM_ENTRY_SIZE:
                            raw[entry['off'] + write_len] = 0x00
                    except:
                        pass
                
                f.write(raw)



    @staticmethod
    def export_enum_to_txt(enum_data, output_path):
        """导出enum_scr为TXT文件"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# enum_scr.bin 导出\n")
            f.write("# 格式: [主索引.子索引] 名称\n")
            f.write("#\n")
            
            for entry in enum_data['entries']:
                f.write(f"[{entry['main_index']:3d}.{entry['sub_index']}] {entry['name']}\n")

    @staticmethod
    def import_enum_from_txt(txt_path, current_enum_data):
        """从TXT文件导入名称"""
        if not current_enum_data: return None
        
        new_names = {}
        with open(txt_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('[') and ']' in line:
                    try:
                        idx_part = line[1:line.find(']')]
                        name = line[line.find(']')+1:].strip()
                        new_names[idx_part.strip()] = name
                    except:
                        continue
        
        for entry in current_enum_data['entries']:
            key = f"{entry['main_index']:3d}.{entry['sub_index']}"
            if key in new_names:
                entry['name'] = new_names[key]
        
        return current_enum_data

    @staticmethod
    def export_enum_to_json(enum_data, output_path):
        """导出enum_scr为JSON文件"""
        import base64
        export_data = {
            'header': {
                'data_size': enum_data['data_size'],
                'unknown1': enum_data['unknown1'],
                'unknown2': enum_data['unknown2'],
                'raw_header': base64.b64encode(enum_data.get('raw_header', b'')).decode('ascii')
            },
            'entries': []
        }
        
        for entry in enum_data['entries']:
            export_data['entries'].append({
                'main_index': entry['main_index'],
                'sub_index': entry['sub_index'],
                'name': entry['name'],
                'off': entry['off'],
                'len': entry['len'],
                'raw_block': base64.b64encode(entry.get('raw_block', b'')).decode('ascii')
            })
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

    @staticmethod
    def import_enum_from_json(json_path):
        """从JSON文件导入enum_scr"""
        import base64
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        header = data['header']
        return {
            'data_size': header['data_size'],
            'unknown1': header['unknown1'],
            'unknown2': header['unknown2'],
            'raw_header': base64.b64decode(header.get('raw_header', '')),
            'entries': [
                {
                    'main_index': e['main_index'],
                    'sub_index': e['sub_index'],
                    'name': e['name'],
                    'off': e['off'],
                    'len': e['len'],
                    'raw_block': bytearray(base64.b64decode(e.get('raw_block', '')))
                }
                for e in data['entries']
            ]
        }

def xor_bytes(data, key=0x55):
    return bytes([b ^ key for b in data])

def extract_names(db_scripts_path, src_encoding='cp932', logger=print):
    with open(db_scripts_path, 'rb') as f:
        data = f.read()
    names = [{"name": ""}]
    if data[:4] == b'mdb\x00':
        logger("检测到 MDB 格式数据库")
        name_start = data.find(b'\x88\xea\x8e\xf7')
        if name_start == -1:
            name_start = 1400
        i = name_start
        while i < len(data):
            end = data.find(b'\x00', i)
            if end == -1 or end == i:
                i += 1
                continue
            chunk = data[i:end]
            if len(chunk) >= 1:
                try:
                    text = chunk.decode(src_encoding)
                    if text in ['登場人物', '名前', '文字色', 'itsu', 'kago', 'wman', 'other']:
                        break
                    if len(text) >= 1:
                        names.append({"name": text})
                except:
                    pass
            i = end + 1
    else:
        reader = BytesReader(data)
        reader.read(8)
        count = reader.readU32()
        size = reader.readU32()
        offsets = [reader.readU32() for _ in range(count)]
        header_end = reader.tell()
        for i in range(count):
            reader.seek(header_end + offsets[i])
            s_bytes = reader.read_until_zero(b'\x00')
            try:
                name = s_bytes.decode(src_encoding)
                names.append({"name": name})
            except:
                names.append({"name": ""})
    logger(f"提取了 {len(names)} 个人名")
    return names

def pack_names(names, db_scripts_path, output_path, dst_encoding='cp932', logger=print):
    with open(db_scripts_path, 'rb') as f:
        data = bytearray(f.read())
    if data[:4] == b'mdb\x00':
        logger("检测到 MDB 格式，进行人名替换...")
        original_names = []
        name_start = data.find(b'\x88\xea\x8e\xf7')
        if name_start == -1:
            name_start = 1400
        name_positions = []
        i = name_start
        while i < len(data):
            end = data.find(b'\x00', i)
            if end == -1 or end == i:
                i += 1
                continue
            chunk = data[i:end]
            if len(chunk) >= 1:
                try:
                    text = chunk.decode('cp932')
                    if text in ['登場人物', '名前', '文字色', 'itsu', 'kago', 'wman', 'other']:
                        break
                    if len(text) >= 1:
                        original_names.append(text)
                        name_positions.append((i, end))
                except:
                    pass
            i = end + 1
        new_names = [n.get("name", "") for n in names[1:]]
        if len(new_names) != len(original_names):
            logger(f"警告: 人名数量不匹配 (原始:{len(original_names)}, 新:{len(new_names)})")
        replaced = 0
        for idx, (start, end) in enumerate(name_positions):
            if idx >= len(new_names):
                break
            old_name = original_names[idx]
            new_name = new_names[idx]
            if old_name != new_name:
                old_bytes = old_name.encode('cp932')
                new_bytes = new_name.encode(dst_encoding, errors='ignore')
                if len(new_bytes) <= len(old_bytes):
                    padding = len(old_bytes) - len(new_bytes)
                    new_bytes = new_bytes + b'\x00' * padding
                    data[start:end] = new_bytes
                    replaced += 1
                    logger(f"  替换: {old_name} -> {new_name}")
                else:
                    logger(f"  跳过: {new_name} (新名字太长)")
        with open(output_path, 'wb') as f:
            f.write(data)
        logger(f"已替换 {replaced} 个人名到 {os.path.basename(output_path)}")
        return True
    magic = data[:8]
    encoded_names = []
    for i, entry in enumerate(names):
        if i == 0:
            encoded_names.append(b'')
        else:
            name = entry.get("name", "")
            encoded_names.append(name.encode(dst_encoding, errors='ignore'))
    name_data = b'\x00'.join(encoded_names) + b'\x00'
    offsets = []
    cur = 0
    for enc in encoded_names:
        offsets.append(cur)
        cur += len(enc) + 1
    new_data = bytes(magic)
    new_data += struct.pack('<I', len(encoded_names))
    new_data += struct.pack('<I', len(name_data))
    for off in offsets:
        new_data += struct.pack('<I', off)
    new_data += name_data
    with open(output_path, 'wb') as f:
        f.write(new_data)
    logger(f"已打包 {len(names)} 个人名到 {os.path.basename(output_path)}")
    return True

class ACPX_001:
    def __init__(self, data=None):
        self.magic = b'@mess:__'
        self.strings = []
        self.is_valid = False
        if data:
            if len(data) < 16:
                return
            magic = data[:8]
            if magic == b'@mess:__':
                self.is_valid = True
                reader = BytesReader(data)
                reader.read(8)
                count = reader.readU32()
                size = reader.readU32()
                offsets = [reader.readU32() for _ in range(count)]
                header_end = reader.tell()
                for i in range(count):
                    reader.seek(header_end + offsets[i])
                    s_bytes = reader.read_until_zero(b'\x55')
                    self.strings.append(xor_bytes(s_bytes, 0x55))
    
    def save(self):
        encoded = [xor_bytes(s, 0x55) for s in self.strings]
        data = b'\x55'.join(encoded) + b'\x55'
        offsets = []
        cur = 0
        for s in encoded:
            offsets.append(cur)
            cur += len(s) + 1
        res = self.magic + struct.pack('<II', len(offsets), len(data))
        res += b''.join([struct.pack('<I', o) for o in offsets])
        res += data
        return res

class ACPX_Bin:
    def __init__(self, bin_data, mess_data=None):
        reader = BytesReader(bin_data)
        self.magic = reader.read(8)
        self.code_len = reader.readU32()
        self.num_bin_str = reader.readU32()
        self.bin_str_len = reader.readU32()
        self.num_001_str = reader.readU32()
        code_bytes = reader.read(self.code_len)
        self.bin_str_offsets = [reader.readU32() for _ in range(self.num_bin_str)]
        self.bin_str_data = reader.read(self.bin_str_len)
        self.mess = None
        if mess_data:
            self.mess = ACPX_001(mess_data)
        self.commands = []
        c_reader = BytesReader(code_bytes)
        while not c_reader.is_end():
            op_byte = c_reader.read(1)
            if not op_byte: break
            op = op_byte.hex()
            args = []
            if op in OPDICT:
                for t in OPDICT[op]:
                    if t in 'Is': args.append(c_reader.readU32())
            self.commands.append({'op': op, 'args': args})

    def get_text_with_names(self, names, src_encoding='cp932'):
        res = []
        current_name = ""
        for cmd in self.commands:
            if cmd['op'] == '28':
                idx = cmd['args'][0]
                current_name = names[idx]["name"] if idx < len(names) else ""
            elif cmd['op'] in ('29', '2b'):
                idx = cmd['args'][0]
                if self.mess and idx < len(self.mess.strings):
                    text = self.mess.strings[idx].decode(src_encoding, errors='ignore')
                    if current_name:
                        res.append({"name": current_name, "message": text})
                    else:
                        res.append({"message": text})
                current_name = ""
        return res



def unpack_text(bin_dir, output_dir, names, src_encoding='cp932', logger=print):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    count = 0
    skipped = 0
    
    for root, dirs, files in os.walk(bin_dir):
        for f in files:
            if f.endswith('.bin'):
                rel_path = os.path.relpath(root, bin_dir)
                out_folder = output_dir if rel_path == '.' else os.path.join(output_dir, rel_path)
                if not os.path.exists(out_folder):
                    os.makedirs(out_folder)
                logger(f"处理 {f}...")
                bin_path = os.path.join(root, f)
                with open(bin_path, 'rb') as f_bin: bin_data = f_bin.read()
                
                try:
                    if bin_data[:8] == b'ESCR1_00':
                        strings, context = EscudeManager.load_script(bin_path)
                        
                        out_name = os.path.splitext(f)[0] + ".txt"
                        out_path = os.path.join(out_folder, out_name)
                        with open(out_path, 'w', encoding='utf-8') as f_out:
                            for i, s in enumerate(strings):
                                if s.strip():
                                    f_out.write(f"○{i:06d}○{s}\n")
                                    f_out.write(f"●{i:06d}●{s}\n\n")
                        count += 1
                        logger(f"  [ESCR] 提取 {len(strings)} 条文本 -> {out_name}")
                        continue
                    
                    mess_path = bin_path.replace('.bin', '.001')
                    if not os.path.exists(mess_path):
                        logger(f"  跳过: 找不到对应的 .001 文件")
                        skipped += 1
                        continue
                    with open(mess_path, 'rb') as f_mess: mess_data = f_mess.read()
                    acpx = ACPX_Bin(bin_data, mess_data)
                    if not acpx.mess or not acpx.mess.is_valid:
                        logger(f"  跳过: .001 文件格式不匹配 (需要 @mess:__ 格式)")
                        skipped += 1
                        continue
                    lines = acpx.get_text_with_names(names, src_encoding)
                    out_name = os.path.splitext(f)[0] + ".txt"
                    out_path = os.path.join(out_folder, out_name)
                    with open(out_path, 'w', encoding='utf-8') as f_out:
                        line_num = 0
                        for line in lines:
                            name = line.get("name", "")
                            message = line.get("message", "")
                            if name:
                                f_out.write(f"○{line_num:06d}○{name}\n")
                                f_out.write(f"●{line_num:06d}●{name}\n\n")
                                line_num += 1
                            f_out.write(f"○{line_num:06d}○{message}\n")
                            f_out.write(f"●{line_num:06d}●{message}\n\n")
                            line_num += 1
                    count += 1
                    logger(f"  提取 {len(lines)} 条文本 -> {out_name}")
                except Exception as e:
                    logger(f"  错误: {e}")
                    skipped += 1
    logger(f"完成! 共处理 {count} 个文件, 跳过 {skipped} 个")

def parse_txt_line(line):
    line = line.strip()
    if not line:
        return None
    if not line.startswith("●"):
        return None
    import re
    match = re.match(r'^●(\d{6})●(.*)$', line)
    if match:
        idx = int(match.group(1))
        text = match.group(2)
        return {"idx": idx, "text": text}
    return None

def parse_txt_file(txt_lines):
    parsed = []
    for line in txt_lines:
        p = parse_txt_line(line)
        if p:
            parsed.append(p)
    result = []
    i = 0
    while i < len(parsed):
        current = parsed[i]
        text = current["text"]
        if text.startswith("「") or not any(c in text for c in "「」"):
            if i > 0 and not parsed[i-1]["text"].startswith("「"):
                name = parsed[i-1]["text"]
                result.append({"name": name, "message": text})
            else:
                result.append({"message": text})
        i += 1
    return result

def pack_text(txt_dir, bin_dir, output_dir, names, dst_encoding='cp932', logger=print):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    count = 0
    for root, dirs, files in os.walk(txt_dir):
        for f in files:
            if f.endswith('.txt') and not f.endswith('.txt.json'):
                rel_path = os.path.relpath(root, txt_dir)
                out_folder = output_dir if rel_path == '.' else os.path.join(output_dir, rel_path)
                if not os.path.exists(out_folder):
                    os.makedirs(out_folder)
                name = f.replace('.txt', '')
                src_bin_dir = bin_dir if rel_path == '.' else os.path.join(bin_dir, rel_path)
                mess_path = os.path.join(src_bin_dir, f"{name}.001")
                bin_path = os.path.join(src_bin_dir, f"{name}.bin")
                if not os.path.exists(mess_path) or not os.path.exists(bin_path):
                    logger(f"跳过 {f}: 找不到原始 .bin 或 .001")
                    continue
                with open(os.path.join(root, f), 'r', encoding='utf-8') as f_txt:
                    txt_lines = f_txt.readlines()
                lines = parse_txt_file(txt_lines)
                with open(mess_path, 'rb') as f_mess:
                    mess_data = f_mess.read()
                with open(bin_path, 'rb') as f_bin:
                    bin_data = f_bin.read()
                try:
                    acpx = ACPX_Bin(bin_data, mess_data)
                    msg_idx = 0
                    for cmd in acpx.commands:
                        if cmd['op'] in ('29', '2b'):
                            idx = cmd['args'][0]
                            if msg_idx < len(lines) and idx < len(acpx.mess.strings):
                                acpx.mess.strings[idx] = lines[msg_idx]['message'].encode(dst_encoding, errors='ignore')
                            msg_idx += 1
                    out_mess_path = os.path.join(out_folder, f"{name}.001")
                    with open(out_mess_path, 'wb') as f_out:
                        f_out.write(acpx.mess.save())
                    out_bin_path = os.path.join(out_folder, f"{name}.bin")
                    with open(out_bin_path, 'wb') as f_out:
                        f_out.write(bin_data)
                    count += 1
                    logger(f"打包 {name}")
                except Exception as e:
                    logger(f"错误打包 {name}: {e}")
    logger(f"完成! 共打包 {count} 个文件")

class AnimButton(QPushButton):
    def __init__(self, btn_type, func, parent=None):
        super().__init__(parent)
        self.setFixedSize(46, 32)
        self.clicked.connect(func)
        self.btn_type = btn_type
        self._hover_progress = 0.0
        self.parent_win = parent
        self.anim = QPropertyAnimation(self, b"hoverProgress")
        self.anim.setDuration(200)
        self.anim.setEasingCurve(QEasingCurve.Type.OutQuad)
        self.icon_color = QColor(0,0,0)

    @pyqtProperty(float)
    def hoverProgress(self): return self._hover_progress
    @hoverProgress.setter
    def hoverProgress(self, val): self._hover_progress = val; self.update()

    def enterEvent(self, e):
        self.anim.setStartValue(self.hoverProgress); self.anim.setEndValue(1.0); self.anim.start()
        super().enterEvent(e)
    def leaveEvent(self, e):
        self.anim.setStartValue(self.hoverProgress); self.anim.setEndValue(0.0); self.anim.start()
        super().leaveEvent(e)
    
    def update_icon_color(self, c):
        self.icon_color = QColor(c)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self.btn_type == "close":
            bg_col = QColor(232, 17, 35, int(255 * self._hover_progress))
            icon_col = self.icon_color if self._hover_progress < 0.5 else QColor(255, 255, 255)
        else:
            bg_col = QColor(0, 0, 0, int(20 * self._hover_progress))
            icon_col = self.icon_color
        p.fillRect(self.rect(), bg_col)
        pen = QPen(icon_col); pen.setWidthF(1.5); p.setPen(pen)
        w, h = self.width(), self.height(); cx, cy = w/2, h/2
        if self.btn_type == "close":
            p.drawLine(QPoint(int(cx-5), int(cy-5)), QPoint(int(cx+5), int(cy+5)))
            p.drawLine(QPoint(int(cx+5), int(cy-5)), QPoint(int(cx-5), int(cy+5)))
        elif self.btn_type == "max":
            is_max = False
            if self.parent_win and hasattr(self.parent_win, 'is_max'): is_max = self.parent_win.is_max
            if is_max:
                p.drawRect(QRectF(cx-2, cy-5, 7, 7))
                p.drawLine(QPoint(int(cx-5), int(cy-2)), QPoint(int(cx-5), int(cy+5))) 
                p.drawLine(QPoint(int(cx-5), int(cy+5)), QPoint(int(cx+2), int(cy+5))) 
                p.drawLine(QPoint(int(cx+2), int(cy+5)), QPoint(int(cx+2), int(cy+2))) 
            else: p.drawRect(QRectF(cx-5, cy-5, 10, 10))
        elif self.btn_type == "min":
            p.drawLine(QPoint(int(cx-5), int(cy)), QPoint(int(cx+5), int(cy)))

class IOSButton(QPushButton):
    def __init__(self, text, color="#007AFF", parent=None):
        super().__init__(text, parent)
        self.base_color = color
        self.setFont(get_app_font(10, bold=True))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(42)
        self.setMinimumWidth(100)
        self.shadow = QGraphicsDropShadowEffect()
        self.shadow.setBlurRadius(12)
        self.shadow.setColor(QColor(0,0,0,35))
        self.shadow.setOffset(0, 3)
        self.setGraphicsEffect(self.shadow)
        self.update_style()
    
    def set_theme_color(self, c):
        self.base_color = c
        self.update_style()

    def update_style(self):
        try:
            hover_color = QColor(self.base_color).lighter(110).name()
        except:
            hover_color = self.base_color
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {self.base_color}; 
                color: white; 
                border-radius: 10px; 
                border: none; 
                padding: 8px 16px; 
                font-family: 'Microsoft YaHei', 'SimSun', sans-serif;
                font-size: 13px;
                font-weight: bold;
            }} 
            QPushButton:hover {{
                background-color: {hover_color};
            }}
            QPushButton:pressed {{
                background-color: {self.base_color};
            }}
            QPushButton:disabled {{
                background-color: rgba(128,128,128,0.5);
            }}
        """)
        
    def enterEvent(self, e): 
        self.shadow.setBlurRadius(20)
        self.shadow.setOffset(0, 5)
        super().enterEvent(e)
        
    def leaveEvent(self, e): 
        self.shadow.setBlurRadius(12)
        self.shadow.setOffset(0, 3)
        super().leaveEvent(e)

class IOSCard(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("IOSCard {background-color: rgba(255, 255, 255, 0.65); border-radius: 18px; border: 1px solid rgba(255, 255, 255, 0.8);}")
        s = QGraphicsDropShadowEffect()
        s.setBlurRadius(25)
        s.setColor(QColor(0,0,0,18))
        s.setOffset(0, 6)
        self.setGraphicsEffect(s)
    
    def update_theme(self, bg, border):
        self.setStyleSheet(f"IOSCard {{background-color: {bg}; border-radius: 18px; border: 1px solid {border};}}")

class IOSInput(QLineEdit):
    def __init__(self, ph="", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(ph)
        self.setFixedHeight(38)
        self.setFont(get_app_font(11))
        self.setStyleSheet("""
            QLineEdit {
                background-color: rgba(255,255,255,0.5); 
                border: 1px solid rgba(0,0,0,0.1); 
                border-radius: 8px; 
                padding: 0 12px; 
                font-size: 12px; 
                color: #333;
            } 
            QLineEdit:focus {
                border: 2px solid #007AFF; 
                background-color: rgba(255,255,255,0.9);
            }
        """)
    
    def update_theme(self, bg, focus_bg, accent, text):
        self.setStyleSheet(f"""
            QLineEdit {{
                background-color: {bg}; 
                border: 1px solid rgba(128,128,128,0.2); 
                border-radius: 8px; 
                padding: 0 12px; 
                font-size: 12px; 
                color: {text};
                font-family: 'Microsoft YaHei', 'SimSun', sans-serif;
            }} 
            QLineEdit:focus {{
                border: 2px solid {accent}; 
                background-color: {focus_bg};
            }}
        """)

class DropZoneInput(IOSInput):
    def __init__(self, ph="", accept_dir=True, accept_file=True, file_filter=None, parent=None):
        super().__init__(ph, parent)
        self.accept_dir = accept_dir
        self.accept_file = accept_file
        self.file_filter = file_filter
        self.setAcceptDrops(True)
        self._drag_highlight = False
    
    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls():
            urls = e.mimeData().urls()
            if urls:
                path = urls[0].toLocalFile()
                is_dir = os.path.isdir(path)
                is_file = os.path.isfile(path)
                
                accept = False
                if is_dir and self.accept_dir:
                    accept = True
                elif is_file and self.accept_file:
                    if self.file_filter:
                        if any(path.lower().endswith(ext) for ext in self.file_filter):
                            accept = True
                    else:
                        accept = True
                
                if accept:
                    e.setDropAction(Qt.DropAction.CopyAction)
                    e.accept()
                    self._drag_highlight = True
                    self._update_drag_style()
                    return
        e.ignore()
    
    def dragLeaveEvent(self, e):
        self._drag_highlight = False
        self._update_drag_style()
        super().dragLeaveEvent(e)
    
    def dropEvent(self, e: QDropEvent):
        self._drag_highlight = False
        self._update_drag_style()
        if e.mimeData().hasUrls():
            urls = e.mimeData().urls()
            if urls:
                path = urls[0].toLocalFile()
                self.setText(path)
                e.accept()
                return
        e.ignore()
    
    def _update_drag_style(self):
        if self._drag_highlight:
            self.setStyleSheet(self.styleSheet() + " QLineEdit { border: 2px dashed #007AFF !important; }")
        else:
            pass

class IOSLog(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(get_mono_font(11))
        self.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0,0,0,0.03); 
                border: none; 
                border-radius: 12px; 
                padding: 12px; 
                font-family: 'Consolas', 'Source Code Pro', monospace; 
                font-size: 11px; 
                color: #333;
                line-height: 1.4;
            }
        """)
        
    def mouseReleaseEvent(self, e):
        super().mouseReleaseEvent(e)
        anchor = self.anchorAt(e.pos())
        if anchor: QDesktopServices.openUrl(QUrl.fromLocalFile(anchor))
        
    def update_theme(self, text, bg):
        self.setStyleSheet(f"""
            QTextEdit {{
                background-color: {bg}; 
                border: none; 
                border-radius: 12px; 
                padding: 12px; 
                font-family: 'Consolas', 'Source Code Pro', monospace; 
                font-size: 11px; 
                color: {text};
                line-height: 1.4;
            }}
        """)

class Worker(QThread):
    log = pyqtSignal(str)
    prog = pyqtSignal(int)
    done = pyqtSignal(str)
    err = pyqtSignal(str)
    
    def __init__(self, mode, params):
        super().__init__()
        self.mode = mode
        self.params = params
    
    def run(self):
        try:
            if self.mode == 'unpack_text':
                input_d = self.params['input_dir']
                output_d = self.params['output_dir']
                data_input_d = self.params['data_input_dir']
                src_enc = self.params['src_encoding']
                db_scripts_path = os.path.join(data_input_d, "db_scripts.bin") if data_input_d else ""
                
                names = [{"name": ""}]
                if data_input_d and os.path.exists(db_scripts_path):
                    self.log.emit("\n[步骤1] 从 db_scripts.bin 提取角色名...")
                    names = extract_names(db_scripts_path, src_enc, logger=self.log.emit)
                    os.makedirs(output_d, exist_ok=True)
                    names_file = os.path.join(output_d, 'names.txt')
                    with open(names_file, 'w', encoding='utf-8') as f:
                        for item in names:
                            f.write(item.get("name", "") + "\n")
                    self.log.emit(f"角色名已保存: {names_file}")
                else:
                    self.log.emit("\n[步骤1] 跳过角色名提取 (未设置data目录)")
                self.log.emit("\n[步骤2] 提取对话文本...")
                unpack_text(input_d, output_d, names, src_enc, logger=self.log.emit)
                self.log.emit(f"\n{'='*50}")
                self.log.emit("提取完成!")
                self.log.emit(f"TXT文件已保存到: {output_d}")
                self.done.emit("提取成功")
                
            elif self.mode == 'pack_text':
                input_d = self.params['input_dir']
                output_d = self.params['output_dir']
                data_input_d = self.params['data_input_dir']
                data_output_d = self.params['data_output_dir']
                dst_enc = self.params['dst_encoding']
                db_scripts_path = os.path.join(data_input_d, "db_scripts.bin")
                
                names_file = os.path.join(input_d, 'names.txt')
                self.log.emit("\n[步骤1] 读取角色名...")
                with open(names_file, 'r', encoding='utf-8') as f:
                    names = [{"name": line.strip()} for line in f.readlines()]
                self.log.emit(f"已加载 {len(names)} 个角色名")
                self.log.emit("\n[步骤2] 导入对话文本...")
                os.makedirs(output_d, exist_ok=True)
                pack_text(input_d, data_input_d, output_d, names, dst_enc, logger=self.log.emit)
                self.log.emit("\n[步骤3] 导入角色名到 db_scripts.bin...")
                os.makedirs(data_output_d, exist_ok=True)
                db_out_path = os.path.join(data_output_d, "db_scripts.bin")
                pack_names(names, db_scripts_path, db_out_path, dst_enc, logger=self.log.emit)
                self.log.emit(f"\n{'='*50}")
                self.log.emit("导入完成!")
                self.done.emit("导入成功")
                
            elif self.mode == 'unpack_archive':
                EscudeManager.unpack_archive(self.params['input'], self.params['output'], logger=self.log.emit)
                self.done.emit(self.params['output'])
                
            elif self.mode == 'pack_archive':
                EscudeManager.pack_archive(self.params['folder'], self.params['output'], logger=self.log.emit)
                self.done.emit("打包成功")
                
            elif self.mode == 'decompress':
                with open(self.params['file'], 'rb') as f:
                    data = f.read()
                decompressed = EscudeManager.decompress(data)
                out_path = self.params['file'] + ".dec"
                with open(out_path, 'wb') as f:
                    f.write(decompressed)
                self.log.emit(f"解压完成!")
                self.log.emit(f"原始大小: {len(data):,} 字节")
                self.log.emit(f"解压后: {len(decompressed):,} 字节")
                self.done.emit(out_path)
        except Exception as e:
            import traceback
            self.err.emit(f"{str(e)}\n{traceback.format_exc()}")

class EscudeApp(QMainWindow):
    EDGE_NONE = 0; EDGE_LEFT = 1; EDGE_TOP = 2
    EDGE_RIGHT = 4; EDGE_BOTTOM = 8; EDGE_MARGIN = 6

    def __init__(self):
        super().__init__()
        self.settings = QSettings("EscudeEditor", "ACPXTool")
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setMouseTracking(True)
        self.resize(1150, 820)
        self.setMinimumSize(950, 680)
        self.is_dragging = False
        self.is_resizing = False
        self.resize_edge = self.EDGE_NONE
        self.drag_start_pos = QPoint()
        self.old_geometry = QRectF()
        self.title_bar_height = 52
        
        self.current_theme_name = "🌊 深海 (Ocean)"
        self.theme = THEMES[self.current_theme_name]
        
        self.script_strings = []
        self.script_context = None
        self.script_path = None
        self.search_results = []
        self.search_index = -1
        self.worker = None
        
        self.enum_data = None
        self.enum_path = None
        self.enum_search_results = []
        self.enum_search_index = -1
        
        self.setup_ui()
        self.setAcceptDrops(True)
        self.is_max = False
        self.load_settings()
        self.apply_theme(self.current_theme_name)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        grad_colors = self.theme["bg_grad"]
        gradient = QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0.0, QColor(grad_colors[0]))
        gradient.setColorAt(0.6, QColor(grad_colors[1]))
        gradient.setColorAt(1.0, QColor(grad_colors[2]))
        path = QPainterPath()
        path.addRoundedRect(QRectF(self.rect()), 20, 20)
        painter.fillPath(path, gradient)
        pen = QPen(QColor(0, 0, 0, 15))
        pen.setWidth(1)
        painter.strokePath(path, pen)

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        central.setMouseTracking(True)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)
        
        title_bar = QHBoxLayout()
        title_bar.setSpacing(8)
        self.title_label = QLabel("Escude 翻译工具箱")
        self.title_label.setFont(get_app_font(13, bold=True))
        self.title_label.setMouseTracking(True)
        
        self.btn_min = AnimButton("min", self.showMinimized, self)
        self.btn_max = AnimButton("max", self.toggle_max, self)
        self.btn_close = AnimButton("close", self.close, self)
        title_bar.addWidget(self.title_label)
        title_bar.addStretch()
        title_bar.addWidget(self.btn_min)
        title_bar.addWidget(self.btn_max)
        title_bar.addWidget(self.btn_close)
        main_layout.addLayout(title_bar)
        
        content_layout = QHBoxLayout()
        content_layout.setSpacing(12)
        
        self.left_card = IOSCard()
        self.left_card.setMouseTracking(True)
        self.left_card.setFixedWidth(280)
        left_layout = QVBoxLayout(self.left_card)
        left_layout.setContentsMargins(20, 20, 20, 20)
        left_layout.setSpacing(12)
        
        theme_layout = QHBoxLayout()
        self.lbl_theme = QLabel("🎨 界面风格")
        self.lbl_theme.setFont(get_app_font(11, bold=True))
        self.combo_theme = QComboBox()
        self.combo_theme.setFont(get_app_font(10))
        self.combo_theme.addItems(THEMES.keys())
        self.combo_theme.currentTextChanged.connect(self.apply_theme)
        self.combo_theme.setFixedHeight(32)
        self.combo_theme.setCursor(Qt.CursorShape.PointingHandCursor)
        theme_layout.addWidget(self.lbl_theme)
        theme_layout.addWidget(self.combo_theme, 1)
        left_layout.addLayout(theme_layout)
        
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFixedHeight(1)
        line.setStyleSheet("background: rgba(0,0,0,0.08);")
        left_layout.addWidget(line)
        
        self.lbl_enc = QLabel("编码设置")
        self.lbl_enc.setFont(get_app_font(11, bold=True))
        left_layout.addWidget(self.lbl_enc)
        
        enc_layout1 = QHBoxLayout()
        self.lbl_src_enc = QLabel("原始编码:")
        self.lbl_src_enc.setFont(get_app_font(10))
        self.combo_src_enc = QComboBox()
        self.combo_src_enc.setFont(get_app_font(10))
        self.combo_src_enc.addItems(ENCODINGS.keys())
        self.combo_src_enc.setFixedHeight(30)
        enc_layout1.addWidget(self.lbl_src_enc)
        enc_layout1.addWidget(self.combo_src_enc, 1)
        left_layout.addLayout(enc_layout1)
        
        enc_layout2 = QHBoxLayout()
        self.lbl_dst_enc = QLabel("目标编码:")
        self.lbl_dst_enc.setFont(get_app_font(10))
        self.combo_dst_enc = QComboBox()
        self.combo_dst_enc.setFont(get_app_font(10))
        self.combo_dst_enc.addItems(ENCODINGS.keys())
        self.combo_dst_enc.setCurrentIndex(1)
        self.combo_dst_enc.setFixedHeight(30)
        enc_layout2.addWidget(self.lbl_dst_enc)
        enc_layout2.addWidget(self.combo_dst_enc, 1)
        left_layout.addLayout(enc_layout2)
        
        self.lbl_enc_hint = QLabel("日文用CP932，简中用CP936")
        self.lbl_enc_hint.setFont(get_app_font(9))
        self.lbl_enc_hint.setWordWrap(True)
        left_layout.addWidget(self.lbl_enc_hint)
        
        left_layout.addStretch()
        
        line2 = QFrame()
        line2.setFrameShape(QFrame.Shape.HLine)
        line2.setFixedHeight(1)
        line2.setStyleSheet("background: rgba(0,0,0,0.08);")
        left_layout.addWidget(line2)
        
        self.lbl_drop_hint = QLabel("💡 支持拖放文件/文件夹到输入框")
        self.lbl_drop_hint.setFont(get_app_font(9))
        self.lbl_drop_hint.setWordWrap(True)
        left_layout.addWidget(self.lbl_drop_hint)
        
        self.btn_reset = IOSButton("重置所有设置")
        self.btn_reset.clicked.connect(self.reset_all)
        left_layout.addWidget(self.btn_reset)
        
        self.right_card = IOSCard()
        self.right_card.setMouseTracking(True)
        right_layout = QVBoxLayout(self.right_card)
        right_layout.setContentsMargins(20, 20, 20, 20)
        right_layout.setSpacing(10)
        
        self.stack = QStackedWidget()
        self.stack.setMouseTracking(True)
        
        self.setup_text_page()
        self.setup_archive_page()
        self.setup_script_page()
        self.setup_enum_page()
        self.setup_help_page()
        
        self.tab_container = QWidget()
        self.tab_container.setFixedHeight(44)
        tc_layout = QHBoxLayout(self.tab_container)
        tc_layout.setContentsMargins(6, 6, 6, 6)
        tc_layout.setSpacing(6)
        self.btn_tab_text = QPushButton("1. 文本提取/导入")
        self.btn_tab_archive = QPushButton("2. 封包解包")
        self.btn_tab_script = QPushButton("3. 脚本编辑")
        self.btn_tab_enum = QPushButton("4. Enum编辑")
        self.btn_tab_help = QPushButton("5. 使用说明")
        self.tabs = [self.btn_tab_text, self.btn_tab_archive, self.btn_tab_script, self.btn_tab_enum, self.btn_tab_help]
        for i, b in enumerate(self.tabs):
            b.setCheckable(True)
            b.setFixedHeight(32)
            b.setMinimumWidth(100)
            b.setFont(get_app_font(10, bold=True))
            b.clicked.connect(lambda checked, idx=i: self.switch_tab(idx))
            tc_layout.addWidget(b)
        tc_layout.addStretch()
        
        right_layout.addWidget(self.tab_container)
        right_layout.addWidget(self.stack, 1)
        
        self.log_area = IOSLog()
        self.log_area.setMinimumHeight(120)
        self.log_area.setMaximumHeight(180)
        right_layout.addWidget(self.log_area)
        
        self.progress = QProgressBar()
        self.progress.setFixedHeight(4)
        self.progress.setTextVisible(False)
        right_layout.addWidget(self.progress)
        
        content_layout.addWidget(self.left_card)
        content_layout.addWidget(self.right_card, 1)
        main_layout.addLayout(content_layout)

    def setup_text_page(self):
        page = QWidget()
        scroll = QScrollArea()
        scroll.setWidget(page)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        layout = QVBoxLayout(page)
        layout.setSpacing(10)
        layout.setContentsMargins(4, 4, 4, 4)
        
        self.lbl_text_title = QLabel("游戏文本提取/导入")
        self.lbl_text_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_text_title.setFont(get_app_font(14, bold=True))
        layout.addWidget(self.lbl_text_title)
        
        mode_layout = QHBoxLayout()
        mode_layout.setSpacing(20)
        self.rb_unpack = QRadioButton("提取文本 (游戏→TXT)")
        self.rb_pack = QRadioButton("导入文本 (TXT→游戏)")
        self.rb_unpack.setFont(get_app_font(11))
        self.rb_pack.setFont(get_app_font(11))
        self.rb_unpack.setChecked(True)
        self.mode_group = QButtonGroup()
        self.mode_group.addButton(self.rb_unpack, 0)
        self.mode_group.addButton(self.rb_pack, 1)
        self.mode_group.buttonClicked.connect(self.on_mode_change)
        mode_layout.addStretch()
        mode_layout.addWidget(self.rb_unpack)
        mode_layout.addWidget(self.rb_pack)
        mode_layout.addStretch()
        layout.addLayout(mode_layout)
        
        grid = QVBoxLayout()
        grid.setSpacing(8)
        
        self.lbl_input = QLabel("脚本目录:")
        self.lbl_input.setFont(get_app_font(10, bold=True))
        grid.addWidget(self.lbl_input)
        input_row = QHBoxLayout()
        input_row.setSpacing(6)
        self.in_input_dir = DropZoneInput("包含 .bin 和 .001 文件的文件夹 (支持拖放)", accept_dir=True, accept_file=False)
        self.btn_browse_input = QPushButton("📂")
        self.btn_browse_input.setFixedSize(38, 38)
        self.btn_browse_input.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_browse_input.clicked.connect(lambda: self.browse_dir(self.in_input_dir))
        input_row.addWidget(self.in_input_dir, 1)
        input_row.addWidget(self.btn_browse_input)
        grid.addLayout(input_row)
        
        self.lbl_output = QLabel("输出目录:")
        self.lbl_output.setFont(get_app_font(10, bold=True))
        grid.addWidget(self.lbl_output)
        output_row = QHBoxLayout()
        output_row.setSpacing(6)
        self.in_output_dir = DropZoneInput("TXT文件输出位置 (支持拖放)", accept_dir=True, accept_file=False)
        self.btn_browse_output = QPushButton("📂")
        self.btn_browse_output.setFixedSize(38, 38)
        self.btn_browse_output.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_browse_output.clicked.connect(lambda: self.browse_dir(self.in_output_dir))
        output_row.addWidget(self.in_output_dir, 1)
        output_row.addWidget(self.btn_browse_output)
        grid.addLayout(output_row)
        
        self.lbl_data_input = QLabel("data目录:")
        self.lbl_data_input.setFont(get_app_font(10, bold=True))
        grid.addWidget(self.lbl_data_input)
        data_input_row = QHBoxLayout()
        data_input_row.setSpacing(6)
        self.in_data_input_dir = DropZoneInput("包含 db_scripts.bin 的文件夹 (支持拖放)", accept_dir=True, accept_file=False)
        self.btn_browse_data_input = QPushButton("📂")
        self.btn_browse_data_input.setFixedSize(38, 38)
        self.btn_browse_data_input.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_browse_data_input.clicked.connect(lambda: self.browse_dir(self.in_data_input_dir))
        data_input_row.addWidget(self.in_data_input_dir, 1)
        data_input_row.addWidget(self.btn_browse_data_input)
        grid.addLayout(data_input_row)
        
        self.lbl_data_output = QLabel("data输出:")
        self.lbl_data_output.setFont(get_app_font(10, bold=True))
        grid.addWidget(self.lbl_data_output)
        data_output_row = QHBoxLayout()
        data_output_row.setSpacing(6)
        self.in_data_output_dir = DropZoneInput("翻译后的 db_scripts.bin 输出位置 (支持拖放)", accept_dir=True, accept_file=False)
        self.btn_browse_data_output = QPushButton("📂")
        self.btn_browse_data_output.setFixedSize(38, 38)
        self.btn_browse_data_output.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_browse_data_output.clicked.connect(lambda: self.browse_dir(self.in_data_output_dir))
        data_output_row.addWidget(self.in_data_output_dir, 1)
        data_output_row.addWidget(self.btn_browse_data_output)
        grid.addLayout(data_output_row)
        
        layout.addLayout(grid)
        
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.btn_auto_fill = IOSButton("一键设置同目录")
        self.btn_auto_fill.clicked.connect(self.auto_fill_paths)
        self.btn_swap = IOSButton("交换输入输出")
        self.btn_swap.clicked.connect(self.swap_paths)
        btn_row.addWidget(self.btn_auto_fill)
        btn_row.addWidget(self.btn_swap)
        layout.addLayout(btn_row)
        
        layout.addStretch()
        
        self.btn_run_text = IOSButton("开始提取文本")
        self.btn_run_text.setFixedHeight(48)
        self.btn_run_text.clicked.connect(self.run_text_task)
        layout.addWidget(self.btn_run_text)
        
        self.stack.addWidget(scroll)

    def setup_archive_page(self):
        page = QWidget()
        scroll = QScrollArea()
        scroll.setWidget(page)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        layout = QVBoxLayout(page)
        layout.setSpacing(10)
        layout.setContentsMargins(4, 4, 4, 4)
        
        self.lbl_archive_title = QLabel("游戏资源包管理 (ESC-ARC2)")
        self.lbl_archive_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_archive_title.setFont(get_app_font(14, bold=True))
        layout.addWidget(self.lbl_archive_title)
        
        self.lbl_unpack_title = QLabel("解包资源包")
        self.lbl_unpack_title.setFont(get_app_font(11, bold=True))
        layout.addWidget(self.lbl_unpack_title)
        
        unpack_row1 = QHBoxLayout()
        unpack_row1.setSpacing(6)
        self.in_archive_input = DropZoneInput("选择 .bin 资源包文件 (支持拖放)", accept_dir=False, accept_file=True, file_filter=['.bin'])
        self.btn_browse_archive = QPushButton("📂")
        self.btn_browse_archive.setFixedSize(38, 38)
        self.btn_browse_archive.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_browse_archive.clicked.connect(self.browse_archive_file)
        unpack_row1.addWidget(self.in_archive_input, 1)
        unpack_row1.addWidget(self.btn_browse_archive)
        layout.addLayout(unpack_row1)
        
        unpack_row2 = QHBoxLayout()
        unpack_row2.setSpacing(6)
        self.in_archive_output = DropZoneInput("解包输出目录 (留空自动创建)", accept_dir=True, accept_file=False)
        self.btn_browse_archive_out = QPushButton("📂")
        self.btn_browse_archive_out.setFixedSize(38, 38)
        self.btn_browse_archive_out.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_browse_archive_out.clicked.connect(lambda: self.browse_dir(self.in_archive_output))
        unpack_row2.addWidget(self.in_archive_output, 1)
        unpack_row2.addWidget(self.btn_browse_archive_out)
        layout.addLayout(unpack_row2)
        
        self.btn_unpack_archive = IOSButton("解包资源")
        self.btn_unpack_archive.clicked.connect(self.do_unpack_archive)
        layout.addWidget(self.btn_unpack_archive)
        
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFixedHeight(1)
        line.setStyleSheet("background: rgba(0,0,0,0.08);")
        layout.addWidget(line)
        
        self.lbl_pack_title = QLabel("打包资源包")
        self.lbl_pack_title.setFont(get_app_font(11, bold=True))
        layout.addWidget(self.lbl_pack_title)
        
        pack_row1 = QHBoxLayout()
        pack_row1.setSpacing(6)
        self.in_pack_folder = DropZoneInput("选择要打包的文件夹 (支持拖放)", accept_dir=True, accept_file=False)
        self.btn_browse_pack_folder = QPushButton("📂")
        self.btn_browse_pack_folder.setFixedSize(38, 38)
        self.btn_browse_pack_folder.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_browse_pack_folder.clicked.connect(lambda: self.browse_dir(self.in_pack_folder))
        pack_row1.addWidget(self.in_pack_folder, 1)
        pack_row1.addWidget(self.btn_browse_pack_folder)
        layout.addLayout(pack_row1)
        
        pack_row2 = QHBoxLayout()
        pack_row2.setSpacing(6)
        self.in_pack_output = DropZoneInput("输出文件路径", accept_dir=False, accept_file=True)
        self.btn_browse_pack_out = QPushButton("💾")
        self.btn_browse_pack_out.setFixedSize(38, 38)
        self.btn_browse_pack_out.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_browse_pack_out.clicked.connect(self.browse_save_archive)
        pack_row2.addWidget(self.in_pack_output, 1)
        pack_row2.addWidget(self.btn_browse_pack_out)
        layout.addLayout(pack_row2)
        
        self.btn_pack_archive = IOSButton("打包资源")
        self.btn_pack_archive.clicked.connect(self.do_pack_archive)
        layout.addWidget(self.btn_pack_archive)
        
        line2 = QFrame()
        line2.setFrameShape(QFrame.Shape.HLine)
        line2.setFixedHeight(1)
        line2.setStyleSheet("background: rgba(0,0,0,0.08);")
        layout.addWidget(line2)
        
        self.lbl_decompress_title = QLabel("解压单个文件 (ACP格式)")
        self.lbl_decompress_title.setFont(get_app_font(11, bold=True))
        layout.addWidget(self.lbl_decompress_title)
        
        decomp_row = QHBoxLayout()
        decomp_row.setSpacing(6)
        self.in_decompress_file = DropZoneInput("选择要解压的文件 (支持拖放)", accept_dir=False, accept_file=True)
        self.btn_browse_decomp = QPushButton("📂")
        self.btn_browse_decomp.setFixedSize(38, 38)
        self.btn_browse_decomp.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_browse_decomp.clicked.connect(self.browse_decompress_file)
        decomp_row.addWidget(self.in_decompress_file, 1)
        decomp_row.addWidget(self.btn_browse_decomp)
        layout.addLayout(decomp_row)
        
        self.btn_decompress = IOSButton("解压文件")
        self.btn_decompress.clicked.connect(self.do_decompress)
        layout.addWidget(self.btn_decompress)
        
        layout.addStretch()
        self.stack.addWidget(scroll)

    def setup_script_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(8)
        layout.setContentsMargins(4, 4, 4, 4)
        
        self.lbl_script_title = QLabel("ESCR1_00 脚本工具")
        self.lbl_script_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_script_title.setFont(get_app_font(14, bold=True))
        layout.addWidget(self.lbl_script_title)
        
        self.lbl_script_desc = QLabel("批量解包/封包 ESCR1_00 脚本 (script.bin~)")
        self.lbl_script_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_script_desc.setFont(get_app_font(10))
        layout.addWidget(self.lbl_script_desc)
        
        batch_frame = QFrame()
        batch_frame.setStyleSheet("QFrame { background: rgba(0,0,0,0.02); border-radius: 8px; }")
        batch_layout = QVBoxLayout(batch_frame)
        batch_layout.setSpacing(6)
        batch_layout.setContentsMargins(12, 12, 12, 12)
        
        self.lbl_escr_input = QLabel("脚本目录 (script.bin~):")
        self.lbl_escr_input.setFont(get_app_font(10, bold=True))
        batch_layout.addWidget(self.lbl_escr_input)
        escr_input_row = QHBoxLayout()
        escr_input_row.setSpacing(6)
        self.in_escr_input = DropZoneInput("包含 .bin 脚本文件的文件夹 (支持拖放)", accept_dir=True, accept_file=False)
        self.btn_browse_escr_input = QPushButton("📂")
        self.btn_browse_escr_input.setFixedSize(38, 38)
        self.btn_browse_escr_input.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_browse_escr_input.clicked.connect(lambda: self.browse_dir(self.in_escr_input))
        escr_input_row.addWidget(self.in_escr_input, 1)
        escr_input_row.addWidget(self.btn_browse_escr_input)
        batch_layout.addLayout(escr_input_row)
        
        self.lbl_escr_output = QLabel("TXT输出目录:")
        self.lbl_escr_output.setFont(get_app_font(10, bold=True))
        batch_layout.addWidget(self.lbl_escr_output)
        escr_output_row = QHBoxLayout()
        escr_output_row.setSpacing(6)
        self.in_escr_output = DropZoneInput("TXT文件输出位置 (留空自动创建)", accept_dir=True, accept_file=False)
        self.btn_browse_escr_output = QPushButton("📂")
        self.btn_browse_escr_output.setFixedSize(38, 38)
        self.btn_browse_escr_output.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_browse_escr_output.clicked.connect(lambda: self.browse_dir(self.in_escr_output))
        escr_output_row.addWidget(self.in_escr_output, 1)
        escr_output_row.addWidget(self.btn_browse_escr_output)
        batch_layout.addLayout(escr_output_row)
        
        escr_btn_row = QHBoxLayout()
        escr_btn_row.setSpacing(10)
        self.btn_escr_extract = IOSButton("批量解包 →TXT")
        self.btn_escr_extract.clicked.connect(self.do_escr_extract_all)
        self.btn_escr_pack = IOSButton("批量封包 →BIN")
        self.btn_escr_pack.clicked.connect(self.do_escr_pack_all)
        escr_btn_row.addWidget(self.btn_escr_extract)
        escr_btn_row.addWidget(self.btn_escr_pack)
        batch_layout.addLayout(escr_btn_row)
        
        layout.addWidget(batch_frame)
        
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFixedHeight(1)
        line.setStyleSheet("background: rgba(0,0,0,0.08);")
        layout.addWidget(line)
        
        self.lbl_single_edit = QLabel("单文件编辑:")
        self.lbl_single_edit.setFont(get_app_font(10, bold=True))
        layout.addWidget(self.lbl_single_edit)
        
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self.btn_open_script = IOSButton("打开脚本")
        self.btn_open_script.clicked.connect(self.open_script)
        self.btn_save_script = IOSButton("保存")
        self.btn_save_script.clicked.connect(self.save_script)
        self.btn_save_script_as = IOSButton("另存为")
        self.btn_save_script_as.clicked.connect(self.save_script_as)
        btn_row.addWidget(self.btn_open_script)
        btn_row.addWidget(self.btn_save_script)
        btn_row.addWidget(self.btn_save_script_as)
        layout.addLayout(btn_row)
        
        self.lbl_script_path = QLabel("未打开任何文件")
        self.lbl_script_path.setFont(get_app_font(9))
        layout.addWidget(self.lbl_script_path)
        
        self.script_list = QListWidget()
        self.script_list.setFont(get_mono_font(10))
        self.script_list.itemClicked.connect(self.on_script_select)
        self.script_list.itemDoubleClicked.connect(lambda: self.in_script_edit.setFocus())
        self.script_list.setMinimumHeight(100)
        layout.addWidget(self.script_list, 1)
        
        self.lbl_edit = QLabel("编辑选中文本 (按Enter保存并跳转下一行):")
        self.lbl_edit.setFont(get_app_font(10))
        layout.addWidget(self.lbl_edit)
        self.in_script_edit = IOSInput()
        self.in_script_edit.returnPressed.connect(self.on_script_edit_commit)
        layout.addWidget(self.in_script_edit)
        
        search_row = QHBoxLayout()
        search_row.setSpacing(6)
        self.in_search = IOSInput("搜索文本...")
        self.in_search.returnPressed.connect(self.search_script)
        self.btn_search = IOSButton("搜索")
        self.btn_search.setFixedWidth(70)
        self.btn_search.clicked.connect(self.search_script)
        self.btn_search_next = IOSButton("下一个")
        self.btn_search_next.setFixedWidth(70)
        self.btn_search_next.clicked.connect(self.search_next)
        search_row.addWidget(self.in_search, 1)
        search_row.addWidget(self.btn_search)
        search_row.addWidget(self.btn_search_next)
        layout.addLayout(search_row)
        
        self.stack.addWidget(page)

    def setup_enum_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(8)
        layout.setContentsMargins(4, 4, 4, 4)
        
        self.lbl_enum_title = QLabel("enum_scr.bin 编辑工具")
        self.lbl_enum_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_enum_title.setFont(get_app_font(14, bold=True))
        layout.addWidget(self.lbl_enum_title)
        
        self.lbl_enum_desc = QLabel("用于编辑场景索引/角色名称 (LIST格式)")
        self.lbl_enum_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_enum_desc.setFont(get_app_font(10))
        layout.addWidget(self.lbl_enum_desc)
        
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self.btn_open_enum = IOSButton("打开 enum_scr.bin")
        self.btn_open_enum.clicked.connect(self.open_enum)
        self.btn_save_enum = IOSButton("保存")
        self.btn_save_enum.clicked.connect(self.save_enum)
        self.btn_save_enum_as = IOSButton("另存为")
        self.btn_save_enum_as.clicked.connect(self.save_enum_as)
        btn_row.addWidget(self.btn_open_enum)
        btn_row.addWidget(self.btn_save_enum)
        btn_row.addWidget(self.btn_save_enum_as)
        layout.addLayout(btn_row)
        
        export_row = QHBoxLayout()
        export_row.setSpacing(8)
        self.btn_export_enum_txt = IOSButton("导出TXT")
        self.btn_export_enum_txt.clicked.connect(self.export_enum_txt)
        self.btn_export_enum_json = IOSButton("导出JSON")
        self.btn_export_enum_json.clicked.connect(self.export_enum_json)
        self.btn_import_enum_txt = IOSButton("导入TXT")
        self.btn_import_enum_txt.clicked.connect(self.import_enum_txt)
        self.btn_import_enum_json = IOSButton("导入JSON")
        self.btn_import_enum_json.clicked.connect(self.import_enum_json)
        export_row.addWidget(self.btn_export_enum_txt)
        export_row.addWidget(self.btn_export_enum_json)
        export_row.addWidget(self.btn_import_enum_txt)
        export_row.addWidget(self.btn_import_enum_json)
        layout.addLayout(export_row)
        
        self.lbl_enum_path = QLabel("未打开任何文件")
        self.lbl_enum_path.setFont(get_app_font(9))
        layout.addWidget(self.lbl_enum_path)
        
        self.enum_list = QListWidget()
        self.enum_list.setFont(get_jp_font(10))
        self.enum_list.itemClicked.connect(self.on_enum_select)
        self.enum_list.itemDoubleClicked.connect(lambda: self.in_enum_edit.setFocus())
        self.enum_list.setMinimumHeight(100)
        layout.addWidget(self.enum_list, 1)
        
        self.lbl_enum_edit = QLabel("编辑选中条目 (按Enter保存并跳转下一行):")
        self.lbl_enum_edit.setFont(get_app_font(10))
        layout.addWidget(self.lbl_enum_edit)
        self.in_enum_edit = IOSInput()
        self.in_enum_edit.returnPressed.connect(self.on_enum_edit_commit)
        layout.addWidget(self.in_enum_edit)
        
        search_row = QHBoxLayout()
        search_row.setSpacing(6)
        self.in_enum_search = IOSInput("搜索条目...")
        self.in_enum_search.returnPressed.connect(self.search_enum)
        self.btn_enum_search = IOSButton("搜索")
        self.btn_enum_search.setFixedWidth(70)
        self.btn_enum_search.clicked.connect(self.search_enum)
        self.btn_enum_search_next = IOSButton("下一个")
        self.btn_enum_search_next.setFixedWidth(70)
        self.btn_enum_search_next.clicked.connect(self.search_enum_next)
        search_row.addWidget(self.in_enum_search, 1)
        search_row.addWidget(self.btn_enum_search)
        search_row.addWidget(self.btn_enum_search_next)
        layout.addLayout(search_row)
        
        self.stack.addWidget(page)

    def setup_help_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        
        self.lbl_help_title = QLabel("使用说明")
        self.lbl_help_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_help_title.setFont(get_app_font(14, bold=True))
        layout.addWidget(self.lbl_help_title)
        
        self.help_text = QTextEdit()
        self.help_text.setReadOnly(True)
        self.help_text.setFont(get_app_font(10))
        self.help_text.setStyleSheet("QTextEdit {background-color: rgba(0,0,0,0.02); border: none; border-radius: 12px; padding: 12px;}")
        self.help_text.setText("""
【Escude 翻译工具箱 使用指南】

═══════════════════════════════════════════════

【文本提取/导入】- 游戏剧本翻译的主要工具

  ▶ 提取文本 (游戏脚本 → TXT)
    1. 设置"脚本目录"为包含 .bin/.001 文件的文件夹
    2. 设置"输出目录"为TXT文件保存位置
    3. 设置"data目录"为游戏data文件夹 (可选)
    4. 点击"开始提取文本"
    
  ▶ TXT格式说明:
    - 有角色名: 角色名「对话内容」
    - 无角色名: 对话内容
    - 每行一条对话，翻译时保持格式不变

  ▶ 导入文本 (TXT → 游戏脚本)
    1. 切换到"导入文本"模式
    2. 设置路径后点击"开始导入文本"

═══════════════════════════════════════════════

【封包解包】- 处理游戏资源包

  ▶ 解包: 选择 .bin 文件，点击解包
  ▶ 打包: 选择文件夹，指定输出路径，点击打包

═══════════════════════════════════════════════

【脚本编辑】- 编辑 ESCR1_00 格式脚本

  用于直接编辑 db_scripts.bin 等系统脚本文件。

═══════════════════════════════════════════════

【翻译工作流程】

  1. 解包 script.bin 和 data.bin
  2. 用"提取文本"导出TXT
  3. 翻译TXT文件 (保持格式: 角色名「翻译」)
  4. 用"导入文本"生成新脚本
  5. 打包新的资源包
  6. 替换游戏原文件测试

═══════════════════════════════════════════════

【拖放支持】

  所有输入框都支持拖放文件或文件夹，
  直接将文件拖到对应输入框即可自动填充路径。
""")
        layout.addWidget(self.help_text)
        
        self.stack.addWidget(page)

    def apply_theme(self, theme_name):
        if theme_name not in THEMES: return
        self.current_theme_name = theme_name
        self.theme = THEMES[theme_name]
        t = self.theme
        
        self.update()
        
        font_family = "'Microsoft YaHei', 'SimSun', 'Segoe UI', sans-serif"
        
        main_labels = [self.title_label, self.lbl_text_title, self.lbl_archive_title, 
                       self.lbl_script_title, self.lbl_help_title, self.lbl_enum_title]
        dim_labels = [self.lbl_theme, self.lbl_enc, self.lbl_src_enc, self.lbl_dst_enc,
                      self.lbl_enc_hint, self.lbl_input, self.lbl_output, self.lbl_data_input,
                      self.lbl_data_output, self.lbl_unpack_title, self.lbl_pack_title,
                      self.lbl_decompress_title, self.lbl_script_desc, self.lbl_script_path,
                      self.lbl_edit, self.lbl_escr_input, self.lbl_escr_output, self.lbl_single_edit,
                      self.lbl_drop_hint, self.lbl_enum_desc, self.lbl_enum_path, self.lbl_enum_edit]
        
        for l in main_labels: 
            l.setStyleSheet(f"color: {t['text_main']}; font-family: {font_family};")
        for l in dim_labels: 
            l.setStyleSheet(f"color: {t['text_dim']}; font-family: {font_family};")
        
        for btn in [self.btn_min, self.btn_max, self.btn_close]: 
            btn.update_icon_color(t['text_main'])
        
        self.left_card.update_theme(t['card_bg'], t['border'])
        self.right_card.update_theme(t['card_bg'], t['border'])
        
        inputs = [self.in_input_dir, self.in_output_dir, self.in_data_input_dir, self.in_data_output_dir,
                  self.in_archive_input, self.in_archive_output, self.in_pack_folder, self.in_pack_output,
                  self.in_decompress_file, self.in_script_edit, self.in_search, self.in_escr_input, self.in_escr_output,
                  self.in_enum_edit, self.in_enum_search]
        for i in inputs: 
            i.update_theme(t['input_bg'], t['input_focus'], t['accent'], t['text_main'])
        
        small_btn_style = f"""
            QPushButton {{
                background-color: rgba(255,255,255,0.85); 
                color: {t['text_main']}; 
                border-radius: 8px; 
                border: 1px solid {t['accent']}; 
                font-size: 14px; 
                font-family: {font_family};
            }} 
            QPushButton:hover {{
                background-color: {t['accent']}; 
                color: white;
            }}
        """
        for btn in [self.btn_browse_input, self.btn_browse_output, self.btn_browse_data_input,
                    self.btn_browse_data_output, self.btn_browse_archive, self.btn_browse_archive_out,
                    self.btn_browse_pack_folder, self.btn_browse_pack_out, self.btn_browse_decomp,
                    self.btn_browse_escr_input, self.btn_browse_escr_output]:
            btn.setStyleSheet(small_btn_style)
        
        action_btns = [self.btn_reset, self.btn_auto_fill, self.btn_swap, self.btn_run_text,
                       self.btn_unpack_archive, self.btn_pack_archive, self.btn_decompress,
                       self.btn_open_script, self.btn_save_script, self.btn_save_script_as,
                       self.btn_search, self.btn_search_next, self.btn_escr_extract, self.btn_escr_pack,
                       self.btn_open_enum, self.btn_save_enum, self.btn_save_enum_as,
                       self.btn_export_enum_txt, self.btn_export_enum_json,
                       self.btn_import_enum_txt, self.btn_import_enum_json,
                       self.btn_enum_search, self.btn_enum_search_next]
        for b in action_btns: 
            b.set_theme_color(t['accent'])
        
        combo_style = f"""
            QComboBox {{ 
                border: 1px solid rgba(128,128,128,0.3); 
                border-radius: 6px; 
                padding: 2px 8px; 
                background: {t['input_bg']}; 
                color: {t['text_main']}; 
                font-family: {font_family}; 
            }}
            QComboBox::drop-down {{ 
                border: none; 
                width: 20px;
            }}
            QComboBox QAbstractItemView {{ 
                background: {t['card_bg']}; 
                selection-background-color: {t['accent']}; 
                color: {t['text_main']}; 
                font-family: {font_family}; 
            }}
        """
        self.combo_theme.setStyleSheet(combo_style)
        self.combo_src_enc.setStyleSheet(combo_style)
        self.combo_dst_enc.setStyleSheet(combo_style)
        
        self.tab_container.setStyleSheet(f"background: {t['input_bg']}; border-radius: 12px;")
        self.switch_tab(self.stack.currentIndex())
        
        rb_style = f"QRadioButton {{ color: {t['text_main']}; spacing: 6px; font-family: {font_family}; }}"
        self.rb_unpack.setStyleSheet(rb_style)
        self.rb_pack.setStyleSheet(rb_style)
        
        bg_log = "rgba(255,255,255,0.1)" if "Night" in theme_name else "rgba(0,0,0,0.02)"
        self.log_area.update_theme(t['text_main'], bg_log)
        self.help_text.setStyleSheet(f"QTextEdit {{background-color: {bg_log}; border: none; border-radius: 12px; padding: 12px; color: {t['text_main']}; font-family: {font_family};}}")
        self.script_list.setStyleSheet(f"QListWidget {{background-color: {bg_log}; border: none; border-radius: 8px; padding: 4px; color: {t['text_main']}; font-family: 'Consolas', monospace;}}")
        self.enum_list.setStyleSheet(f"QListWidget {{background-color: {bg_log}; border: none; border-radius: 8px; padding: 4px; color: {t['text_main']}; font-family: 'Yu Gothic', 'Meiryo', 'MS Gothic', 'Microsoft YaHei';}}")
        self.progress.setStyleSheet(f"QProgressBar {{border:none; background:rgba(0,0,0,0.08); border-radius:2px;}} QProgressBar::chunk {{background: {t['accent']}; border-radius:2px;}}")

    def switch_tab(self, idx):
        self.stack.setCurrentIndex(idx)
        t = self.theme
        font_family = "'Microsoft YaHei', 'SimSun', sans-serif"
        base = f"border:none; border-radius: 8px; font-weight: bold; font-family: {font_family}; font-size: 11px;"
        active = f"{base} background-color: {t['accent']}; color: white;"
        inactive = f"{base} background-color: transparent; color: {t['text_dim']};"
        for i, b in enumerate(self.tabs): 
            b.setChecked(i == idx)
            b.setStyleSheet(active if i == idx else inactive)

    def toggle_max(self):
        if self.is_max: 
            self.showNormal()
            self.is_max = False
        else: 
            self.showMaximized()
            self.is_max = True
        self.btn_max.update()

    def log(self, m):
        self.log_area.append(m)
        self.log_area.verticalScrollBar().setValue(self.log_area.verticalScrollBar().maximum())

    def browse_dir(self, target_input):
        path = QFileDialog.getExistingDirectory(self, "选择文件夹")
        if path: target_input.setText(path)

    def browse_archive_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择资源包", "", "资源包 (*.bin);;所有文件 (*.*)")
        if path:
            self.in_archive_input.setText(path)
            if not self.in_archive_output.text():
                self.in_archive_output.setText(path + "~")

    def browse_save_archive(self):
        path, _ = QFileDialog.getSaveFileName(self, "保存资源包", "", "资源包 (*.bin);;所有文件 (*.*)")
        if path: self.in_pack_output.setText(path)

    def browse_decompress_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*.*)")
        if path: self.in_decompress_file.setText(path)

    def on_mode_change(self):
        if self.rb_unpack.isChecked():
            self.btn_run_text.setText("开始提取文本")
            self.lbl_input.setText("脚本目录:")
            self.lbl_output.setText("输出目录:")
        else:
            self.btn_run_text.setText("开始导入文本")
            self.lbl_input.setText("TXT目录:")
            self.lbl_output.setText("脚本输出:")

    def auto_fill_paths(self):
        input_d = self.in_input_dir.text()
        if not input_d:
            QMessageBox.information(self, "提示", "请先设置脚本目录")
            return
        base_dir = input_d
        parent_dir = os.path.dirname(base_dir)
        
        if self.rb_unpack.isChecked():
            if not self.in_output_dir.text():
                self.in_output_dir.setText(base_dir + "_txt")
            if not self.in_data_input_dir.text():
                data_dir = os.path.join(parent_dir, "data")
                if os.path.exists(data_dir):
                    self.in_data_input_dir.setText(data_dir)
        else:
            if not self.in_output_dir.text():
                self.in_output_dir.setText(base_dir.replace("_txt", "_new"))
            if not self.in_data_output_dir.text():
                self.in_data_output_dir.setText(os.path.join(parent_dir, "data_new"))
        self.log("已自动填充关联路径")

    def swap_paths(self):
        input_d = self.in_input_dir.text()
        output_d = self.in_output_dir.text()
        self.in_input_dir.setText(output_d)
        self.in_output_dir.setText(input_d)
        if self.rb_unpack.isChecked():
            self.rb_pack.setChecked(True)
        else:
            self.rb_unpack.setChecked(True)
        self.on_mode_change()
        self.log("已交换输入输出路径")

    def run_text_task(self):
        input_d = self.in_input_dir.text()
        output_d = self.in_output_dir.text()
        data_input_d = self.in_data_input_dir.text()
        data_output_d = self.in_data_output_dir.text()
        
        if not input_d or not output_d:
            QMessageBox.warning(self, "错误", "请设置输入和输出目录")
            return
        if not os.path.exists(input_d):
            QMessageBox.warning(self, "错误", f"输入目录不存在: {input_d}")
            return
        
        src_enc = ENCODINGS.get(self.combo_src_enc.currentText(), 'cp932')
        dst_enc = ENCODINGS.get(self.combo_dst_enc.currentText(), 'cp936')
        
        self.log_area.clear()
        self.progress.setValue(0)
        self.setEnabled(False)
        
        if self.rb_unpack.isChecked():
            self.log("=" * 50)
            self.log("开始提取文本")
            self.log("=" * 50)
            params = {
                'input_dir': input_d,
                'output_dir': output_d,
                'data_input_dir': data_input_d,
                'src_encoding': src_enc
            }
            self.worker = Worker('unpack_text', params)
        else:
            if not data_input_d or not data_output_d:
                QMessageBox.warning(self, "错误", "导入模式需要设置 data目录 和 data输出")
                self.setEnabled(True)
                return
            names_file = os.path.join(input_d, "names.txt")
            if not os.path.exists(names_file):
                QMessageBox.warning(self, "错误", f"找不到 names.txt: {names_file}")
                self.setEnabled(True)
                return
            self.log("=" * 50)
            self.log("开始导入文本")
            self.log("=" * 50)
            params = {
                'input_dir': input_d,
                'output_dir': output_d,
                'data_input_dir': data_input_d,
                'data_output_dir': data_output_d,
                'dst_encoding': dst_enc
            }
            self.worker = Worker('pack_text', params)
        
        self.worker.log.connect(self.log)
        self.worker.done.connect(self.on_task_done)
        self.worker.err.connect(self.on_task_error)
        self.worker.start()

    def do_unpack_archive(self):
        input_path = self.in_archive_input.text()
        output_path = self.in_archive_output.text()
        if not input_path:
            QMessageBox.warning(self, "错误", "请选择资源包文件")
            return
        if not os.path.exists(input_path):
            QMessageBox.warning(self, "错误", f"文件不存在: {input_path}")
            return
        if not output_path:
            output_path = input_path + "~"
            self.in_archive_output.setText(output_path)
        
        self.log_area.clear()
        self.setEnabled(False)
        self.log(f"正在解包: {os.path.basename(input_path)}")
        
        self.worker = Worker('unpack_archive', {'input': input_path, 'output': output_path})
        self.worker.log.connect(self.log)
        self.worker.done.connect(self.on_archive_unpack_done)
        self.worker.err.connect(self.on_task_error)
        self.worker.start()

    def do_pack_archive(self):
        folder = self.in_pack_folder.text()
        output = self.in_pack_output.text()
        if not folder or not output:
            QMessageBox.warning(self, "错误", "请设置文件夹和输出路径")
            return
        if not os.path.exists(folder):
            QMessageBox.warning(self, "错误", f"文件夹不存在: {folder}")
            return
        
        self.log_area.clear()
        self.setEnabled(False)
        self.log(f"正在打包: {folder}")
        
        self.worker = Worker('pack_archive', {'folder': folder, 'output': output})
        self.worker.log.connect(self.log)
        self.worker.done.connect(self.on_task_done)
        self.worker.err.connect(self.on_task_error)
        self.worker.start()

    def do_decompress(self):
        file_path = self.in_decompress_file.text()
        if not file_path:
            QMessageBox.warning(self, "错误", "请选择文件")
            return
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "错误", f"文件不存在: {file_path}")
            return
        
        self.log_area.clear()
        self.setEnabled(False)
        self.log(f"正在解压: {os.path.basename(file_path)}")
        
        self.worker = Worker('decompress', {'file': file_path})
        self.worker.log.connect(self.log)
        self.worker.done.connect(self.on_task_done)
        self.worker.err.connect(self.on_task_error)
        self.worker.start()

    def on_task_done(self, result):
        self.setEnabled(True)
        self.progress.setValue(100)
        QMessageBox.information(self, "完成", result)

    def on_archive_unpack_done(self, output_path):
        self.setEnabled(True)
        self.progress.setValue(100)
        QMessageBox.information(self, "解包完成", f"文件已解包到:\n{output_path}")

    def on_task_error(self, error):
        self.setEnabled(True)
        self.progress.setValue(0)
        self.log(f"\n错误:\n{error}")
        error_msg = error.split('\n')[0] if '\n' in error else error
        QMessageBox.critical(self, "错误", error_msg)

    def open_script(self):
        path, _ = QFileDialog.getOpenFileName(self, "打开脚本", "", "脚本文件 (*.bin);;所有文件 (*.*)")
        if not path: return
        try:
            strings, context = EscudeManager.load_script(path)
            self.script_strings = strings
            self.script_context = context
            self.script_path = path
            self.script_list.clear()
            for i, s in enumerate(strings):
                self.script_list.addItem(f"[{i}] {s}")
            self.lbl_script_path.setText(f"当前文件: {os.path.basename(path)} (共 {len(strings)} 条)")
            QMessageBox.information(self, "打开成功", f"已加载 {len(strings)} 条文本")
        except Exception as e:
            QMessageBox.critical(self, "打开失败", f"无法加载脚本:\n{e}\n\n只支持 ESCR1_00 格式")

    def save_script(self):
        if not self.script_context:
            QMessageBox.warning(self, "错误", "请先打开脚本文件")
            return
        try:
            EscudeManager.save_script(self.script_path, self.script_strings, self.script_context)
            QMessageBox.information(self, "保存成功", f"已保存到:\n{self.script_path}")
        except Exception as e:
            QMessageBox.critical(self, "保存失败", str(e))

    def save_script_as(self):
        if not self.script_context:
            QMessageBox.warning(self, "错误", "请先打开脚本文件")
            return
        path, _ = QFileDialog.getSaveFileName(self, "另存为", "", "脚本文件 (*.bin);;所有文件 (*.*)")
        if not path: return
        try:
            EscudeManager.save_script(path, self.script_strings, self.script_context)
            self.script_path = path
            self.lbl_script_path.setText(f"当前文件: {os.path.basename(path)} (共 {len(self.script_strings)} 条)")
            QMessageBox.information(self, "保存成功", f"已保存到:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "保存失败", str(e))

    def on_script_select(self, item):
        idx = self.script_list.row(item)
        if 0 <= idx < len(self.script_strings):
            self.in_script_edit.setText(self.script_strings[idx])
            self.in_script_edit.setFocus()

    def on_script_edit_commit(self):
        idx = self.script_list.currentRow()
        if 0 <= idx < len(self.script_strings):
            new_text = self.in_script_edit.text()
            self.script_strings[idx] = new_text
            self.script_list.item(idx).setText(f"[{idx}] {new_text}")
            if idx < len(self.script_strings) - 1:
                self.script_list.setCurrentRow(idx + 1)
                self.in_script_edit.setText(self.script_strings[idx + 1])
                self.in_script_edit.selectAll()

    def search_script(self):
        query = self.in_search.text()
        if not query: 
            QMessageBox.information(self, "搜索", "请输入搜索内容")
            return
        self.search_results = []
        for i, s in enumerate(self.script_strings):
            if query.lower() in s.lower():
                self.search_results.append(i)
        if self.search_results:
            self.search_index = 0
            self.goto_search_result()
            self.log(f"找到 {len(self.search_results)} 个匹配项")
        else:
            QMessageBox.information(self, "搜索", "未找到匹配内容")

    def search_next(self):
        if not self.search_results:
            self.search_script()
            return
        self.search_index = (self.search_index + 1) % len(self.search_results)
        self.goto_search_result()
        self.log(f"匹配项 {self.search_index + 1}/{len(self.search_results)}")

    def goto_search_result(self):
        if self.search_results and 0 <= self.search_index < len(self.search_results):
            idx = self.search_results[self.search_index]
            self.script_list.setCurrentRow(idx)
            self.script_list.scrollToItem(self.script_list.item(idx))
            if 0 <= idx < len(self.script_strings):
                self.in_script_edit.setText(self.script_strings[idx])

    def do_escr_extract_all(self):
        input_dir = self.in_escr_input.text()
        output_dir = self.in_escr_output.text()
        
        if not input_dir:
            QMessageBox.warning(self, "错误", "请设置脚本目录")
            return
        if not os.path.exists(input_dir):
            QMessageBox.warning(self, "错误", f"目录不存在: {input_dir}")
            return
        
        if not output_dir:
            output_dir = input_dir + "_txt"
            self.in_escr_output.setText(output_dir)
        
        os.makedirs(output_dir, exist_ok=True)
        
        self.log_area.clear()
        self.log("=" * 50)
        self.log(f"批量解包 ESCR1_00 脚本")
        self.log(f"输入: {input_dir}")
        self.log(f"输出: {output_dir}")
        self.log("=" * 50)
        
        count = 0
        errors = 0
        
        for f in os.listdir(input_dir):
            if not f.endswith('.bin'):
                continue
            bin_path = os.path.join(input_dir, f)
            try:
                strings, context = EscudeManager.load_script(bin_path)
                txt_name = f.replace('.bin', '.txt')
                txt_path = os.path.join(output_dir, txt_name)
                
                with open(txt_path, 'w', encoding='utf-8') as out_f:
                    for i, s in enumerate(strings):
                        out_f.write(f"◇{i:06d}◇{s}\n")
                        out_f.write(f"◆{i:06d}◆{s}\n\n")
                
                count += 1
                self.log(f"  OK: {f} ({len(strings)} 条)")
            except Exception as e:
                errors += 1
                self.log(f"  FAIL: {f} - {e}")
        
        self.log("")
        self.log(f"完成! {count} 成功, {errors} 失败")
        self.log(f"输出目录: {output_dir}")
        QMessageBox.information(self, "完成", f"解包完成!\n{count} 成功, {errors} 失败\n输出: {output_dir}")

    def do_escr_pack_all(self):
        txt_dir = self.in_escr_output.text()
        template_dir = self.in_escr_input.text()
        
        if not txt_dir:
            QMessageBox.warning(self, "错误", "请设置TXT目录")
            return
        if not os.path.exists(txt_dir):
            QMessageBox.warning(self, "错误", f"TXT目录不存在: {txt_dir}")
            return
        if not template_dir or not os.path.exists(template_dir):
            QMessageBox.warning(self, "错误", "请设置原始脚本目录作为模板")
            return
        
        output_dir = txt_dir.replace('_txt', '_new')
        if output_dir == txt_dir:
            output_dir = txt_dir + "_packed"
        os.makedirs(output_dir, exist_ok=True)
        
        self.log_area.clear()
        self.log("=" * 50)
        self.log(f"批量封包 ESCR1_00 脚本")
        self.log(f"TXT目录: {txt_dir}")
        self.log(f"模板目录: {template_dir}")
        self.log(f"输出目录: {output_dir}")
        self.log("=" * 50)
        
        count = 0
        errors = 0
        
        for f in os.listdir(txt_dir):
            if not f.endswith('.txt'):
                continue
            txt_path = os.path.join(txt_dir, f)
            template_name = f.replace('.txt', '.bin')
            template_path = os.path.join(template_dir, template_name)
            
            if not os.path.exists(template_path):
                self.log(f"  SKIP: {f} - 找不到模板 {template_name}")
                errors += 1
                continue
            
            try:
                strings, context = EscudeManager.load_script(template_path)
                
                new_strings = {}
                with open(txt_path, 'r', encoding='utf-8') as in_f:
                    for line in in_f:
                        line = line.rstrip('\n\r')
                        if line.startswith('◆') and '◆' in line[1:]:
                            parts = line.split('◆')
                            if len(parts) >= 3:
                                try:
                                    idx = int(parts[1])
                                    text = '◆'.join(parts[2:])
                                    new_strings[idx] = text
                                except ValueError:
                                    continue
                
                for idx, text in new_strings.items():
                    if 0 <= idx < len(strings):
                        strings[idx] = text
                
                out_path = os.path.join(output_dir, template_name)
                EscudeManager.save_script(out_path, strings, context)
                
                count += 1
                self.log(f"  OK: {f} ({len(new_strings)} 条)")
            except Exception as e:
                errors += 1
                self.log(f"  FAIL: {f} - {e}")
        
        self.log("")
        self.log(f"完成! {count} 成功, {errors} 失败")
        self.log(f"输出目录: {output_dir}")
        QMessageBox.information(self, "完成", f"封包完成!\n{count} 成功, {errors} 失败\n输出: {output_dir}")

    # ========== Enum 操作方法 ==========

    def open_enum(self):
        path, _ = QFileDialog.getOpenFileName(self, "打开 enum_scr.bin", "", "Enum文件 (*.bin);;所有文件 (*.*)")
        if not path: return
        try:
            self.enum_data = EscudeManager.load_enum_scr(path)
            self.enum_path = path
            self.enum_list.clear()
            for entry in self.enum_data['entries']:
                disp = f"[{entry['main_index']:3d}.{entry['sub_index']}] {entry['name']}"
                self.enum_list.addItem(disp)
            self.lbl_enum_path.setText(f"当前文件: {os.path.basename(path)} (共 {len(self.enum_data['entries'])} 条)")
            QMessageBox.information(self, "打开成功", f"已加载 {len(self.enum_data['entries'])} 条记录")
        except Exception as e:
            QMessageBox.critical(self, "打开失败", f"无法加载文件:\n{e}\n\n只支持 LIST 格式的 enum_scr.bin")

    def save_enum(self):
        if not self.enum_data:
            QMessageBox.warning(self, "错误", "请先打开 enum_scr.bin 文件")
            return
        try:
            EscudeManager.save_enum_scr(self.enum_path, self.enum_data)
            QMessageBox.information(self, "保存成功", f"已保存到:\n{self.enum_path}")
        except Exception as e:
            QMessageBox.critical(self, "保存失败", str(e))

    def save_enum_as(self):
        if not self.enum_data:
            QMessageBox.warning(self, "错误", "请先打开 enum_scr.bin 文件")
            return
        path, _ = QFileDialog.getSaveFileName(self, "另存为", "", "Enum文件 (*.bin);;所有文件 (*.*)")
        if not path: return
        try:
            EscudeManager.save_enum_scr(path, self.enum_data)
            self.enum_path = path
            self.lbl_enum_path.setText(f"当前文件: {os.path.basename(path)} (共 {len(self.enum_data['entries'])} 条)")
            QMessageBox.information(self, "保存成功", f"已保存到:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "保存失败", str(e))

    def export_enum_txt(self):
        if not self.enum_data:
            QMessageBox.warning(self, "错误", "请先打开 enum_scr.bin 文件")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出TXT", "", "文本文件 (*.txt);;所有文件 (*.*)")
        if not path: return
        try:
            EscudeManager.export_enum_to_txt(self.enum_data, path)
            QMessageBox.information(self, "导出成功", f"已导出到:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "导出失败", str(e))

    def export_enum_json(self):
        if not self.enum_data:
            QMessageBox.warning(self, "错误", "请先打开 enum_scr.bin 文件")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出JSON", "", "JSON文件 (*.json);;所有文件 (*.*)")
        if not path: return
        try:
            EscudeManager.export_enum_to_json(self.enum_data, path)
            QMessageBox.information(self, "导出成功", f"已导出到:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "导出失败", str(e))

    def import_enum_txt(self):
        if not self.enum_data:
            QMessageBox.warning(self, "错误", "请先打开 enum_scr.bin 文件作为模板")
            return
        path, _ = QFileDialog.getOpenFileName(self, "导入TXT", "", "文本文件 (*.txt);;所有文件 (*.*)")
        if not path: return
        try:
            self.enum_data = EscudeManager.import_enum_from_txt(path, self.enum_data)
            self.enum_list.clear()
            for entry in self.enum_data['entries']:
                disp = f"[{entry['main_index']:3d}.{entry['sub_index']}] {entry['name']}"
                self.enum_list.addItem(disp)
            QMessageBox.information(self, "导入成功", f"已从TXT导入数据")
        except Exception as e:
            QMessageBox.critical(self, "导入失败", str(e))

    def import_enum_json(self):
        path, _ = QFileDialog.getOpenFileName(self, "导入JSON", "", "JSON文件 (*.json);;所有文件 (*.*)")
        if not path: return
        try:
            self.enum_data = EscudeManager.import_enum_from_json(path)
            self.enum_path = None
            self.enum_list.clear()
            for entry in self.enum_data['entries']:
                disp = f"[{entry['main_index']:3d}.{entry['sub_index']}] {entry['name']}"
                self.enum_list.addItem(disp)
            self.lbl_enum_path.setText(f"已从JSON导入 (共 {len(self.enum_data['entries'])} 条)")
            QMessageBox.information(self, "导入成功", f"已从JSON导入 {len(self.enum_data['entries'])} 条记录")
        except Exception as e:
            QMessageBox.critical(self, "导入失败", str(e))

    def on_enum_select(self, item):
        idx = self.enum_list.row(item)
        if self.enum_data and 0 <= idx < len(self.enum_data['entries']):
            self.in_enum_edit.setText(self.enum_data['entries'][idx]['name'])
            self.in_enum_edit.setFocus()

    def on_enum_edit_commit(self):
        idx = self.enum_list.currentRow()
        if self.enum_data and 0 <= idx < len(self.enum_data['entries']):
            new_name = self.in_enum_edit.text()
            entry = self.enum_data['entries'][idx]
            entry['name'] = new_name
            self.enum_list.item(idx).setText(f"[{entry['main_index']:3d}.{entry['sub_index']}] {new_name}")
            if idx < len(self.enum_data['entries']) - 1:
                self.enum_list.setCurrentRow(idx + 1)
                self.in_enum_edit.setText(self.enum_data['entries'][idx + 1]['name'])
                self.in_enum_edit.selectAll()

    def search_enum(self):
        query = self.in_enum_search.text()
        if not query:
            QMessageBox.information(self, "搜索", "请输入搜索内容")
            return
        if not self.enum_data:
            QMessageBox.warning(self, "错误", "请先打开文件")
            return
        self.enum_search_results = []
        for i, entry in enumerate(self.enum_data['entries']):
            if query.lower() in entry['name'].lower():
                self.enum_search_results.append(i)
        if self.enum_search_results:
            self.enum_search_index = 0
            self.goto_enum_search_result()
            self.log(f"找到 {len(self.enum_search_results)} 个匹配项")
        else:
            QMessageBox.information(self, "搜索", "未找到匹配内容")

    def search_enum_next(self):
        if not self.enum_search_results:
            self.search_enum()
            return
        self.enum_search_index = (self.enum_search_index + 1) % len(self.enum_search_results)
        self.goto_enum_search_result()
        self.log(f"匹配项 {self.enum_search_index + 1}/{len(self.enum_search_results)}")

    def goto_enum_search_result(self):
        if self.enum_search_results and 0 <= self.enum_search_index < len(self.enum_search_results):
            idx = self.enum_search_results[self.enum_search_index]
            self.enum_list.setCurrentRow(idx)
            self.enum_list.scrollToItem(self.enum_list.item(idx))
            if self.enum_data and 0 <= idx < len(self.enum_data['entries']):
                self.in_enum_edit.setText(self.enum_data['entries'][idx]['name'])

    def reset_all(self):
        self.in_input_dir.clear()
        self.in_output_dir.clear()
        self.in_data_input_dir.clear()
        self.in_data_output_dir.clear()
        self.in_archive_input.clear()
        self.in_archive_output.clear()
        self.in_pack_folder.clear()
        self.in_pack_output.clear()
        self.in_decompress_file.clear()
        self.in_escr_input.clear()
        self.in_escr_output.clear()
        self.combo_src_enc.setCurrentIndex(0)
        self.combo_dst_enc.setCurrentIndex(1)
        self.rb_unpack.setChecked(True)
        self.on_mode_change()
        self.log_area.clear()
        self.progress.setValue(0)
        self.script_list.clear()
        self.script_strings = []
        self.script_context = None
        self.script_path = None
        self.in_script_edit.clear()
        self.in_search.clear()
        self.search_results = []
        self.search_index = -1
        self.lbl_script_path.setText("未打开任何文件")
        self.enum_list.clear()
        self.enum_data = None
        self.enum_path = None
        self.in_enum_edit.clear()
        self.in_enum_search.clear()
        self.enum_search_results = []
        self.enum_search_index = -1
        self.lbl_enum_path.setText("未打开任何文件")
        self.log("已重置所有设置")

    def load_settings(self):
        self.in_input_dir.setText(self.settings.value("input_dir", ""))
        self.in_output_dir.setText(self.settings.value("output_dir", ""))
        self.in_data_input_dir.setText(self.settings.value("data_input_dir", ""))
        self.in_data_output_dir.setText(self.settings.value("data_output_dir", ""))
        self.combo_src_enc.setCurrentIndex(self.settings.value("src_enc_idx", 0, type=int))
        self.combo_dst_enc.setCurrentIndex(self.settings.value("dst_enc_idx", 1, type=int))
        mode = self.settings.value("mode", "unpack")
        if mode == "pack":
            self.rb_pack.setChecked(True)
        self.on_mode_change()
        self.current_theme_name = self.settings.value("theme", "🌊 深海 (Ocean)")
        idx = self.combo_theme.findText(self.current_theme_name)
        if idx >= 0: self.combo_theme.setCurrentIndex(idx)

    def save_settings(self):
        self.settings.setValue("input_dir", self.in_input_dir.text())
        self.settings.setValue("output_dir", self.in_output_dir.text())
        self.settings.setValue("data_input_dir", self.in_data_input_dir.text())
        self.settings.setValue("data_output_dir", self.in_data_output_dir.text())
        self.settings.setValue("src_enc_idx", self.combo_src_enc.currentIndex())
        self.settings.setValue("dst_enc_idx", self.combo_dst_enc.currentIndex())
        self.settings.setValue("mode", "pack" if self.rb_pack.isChecked() else "unpack")
        self.settings.setValue("theme", self.current_theme_name)

    def closeEvent(self, event: QCloseEvent):
        self.save_settings()
        if self.worker and self.worker.isRunning():
            self.worker.quit()
            self.worker.wait(1000)
        event.accept()

    def _calc_cursor_pos(self, p):
        r = self.rect(); m = self.EDGE_MARGIN; edge = self.EDGE_NONE
        if p.x() <= m: edge |= self.EDGE_LEFT
        if p.x() >= r.width() - m: edge |= self.EDGE_RIGHT
        if p.y() <= m: edge |= self.EDGE_TOP
        if p.y() >= r.height() - m: edge |= self.EDGE_BOTTOM
        return edge

    def _set_cursor_shape(self, edge):
        if edge == (self.EDGE_LEFT | self.EDGE_TOP) or edge == (self.EDGE_RIGHT | self.EDGE_BOTTOM): 
            self.setCursor(Qt.CursorShape.SizeFDiagCursor)
        elif edge == (self.EDGE_RIGHT | self.EDGE_TOP) or edge == (self.EDGE_LEFT | self.EDGE_BOTTOM): 
            self.setCursor(Qt.CursorShape.SizeBDiagCursor)
        elif edge & self.EDGE_LEFT or edge & self.EDGE_RIGHT: 
            self.setCursor(Qt.CursorShape.SizeHorCursor)
        elif edge & self.EDGE_TOP or edge & self.EDGE_BOTTOM: 
            self.setCursor(Qt.CursorShape.SizeVerCursor)
        else: 
            self.setCursor(Qt.CursorShape.ArrowCursor)

    def _is_in_title_bar(self, pos):
        return pos.y() <= self.title_bar_height and pos.x() < self.width() - 150

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            pos = e.position().toPoint()
            edge = self._calc_cursor_pos(pos)
            if edge != self.EDGE_NONE and not self.is_max:
                self.is_resizing = True
                self.resize_edge = edge
                self.drag_start_pos = e.globalPosition().toPoint()
                self.old_geometry = QRectF(self.geometry())
            elif self._is_in_title_bar(pos):
                self.is_dragging = True
                self.drag_start_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()
            e.accept()
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e):
        pos = e.position().toPoint()
        if self.is_resizing and not self.is_max:
            delta = e.globalPosition().toPoint() - self.drag_start_pos
            new_geo = self.old_geometry.toRect()
            if self.resize_edge & self.EDGE_LEFT: new_geo.setLeft(new_geo.left() + delta.x())
            if self.resize_edge & self.EDGE_RIGHT: new_geo.setRight(new_geo.right() + delta.x())
            if self.resize_edge & self.EDGE_TOP: new_geo.setTop(new_geo.top() + delta.y())
            if self.resize_edge & self.EDGE_BOTTOM: new_geo.setBottom(new_geo.bottom() + delta.y())
            if new_geo.width() < self.minimumWidth():
                if self.resize_edge & self.EDGE_LEFT: new_geo.setLeft(new_geo.right() - self.minimumWidth())
                else: new_geo.setRight(new_geo.left() + self.minimumWidth())
            if new_geo.height() < self.minimumHeight():
                if self.resize_edge & self.EDGE_TOP: new_geo.setTop(new_geo.bottom() - self.minimumHeight())
                else: new_geo.setBottom(new_geo.top() + self.minimumHeight())
            self.setGeometry(new_geo)
            e.accept()
        elif self.is_dragging:
            if self.is_max:
                self.showNormal()
                self.is_max = False
                new_pos = e.globalPosition().toPoint()
                self.drag_start_pos = QPoint(self.width() // 2, 25)
                self.move(new_pos - self.drag_start_pos)
            else:
                self.move(e.globalPosition().toPoint() - self.drag_start_pos)
            e.accept()
        else:
            if not self.is_max:
                self._set_cursor_shape(self._calc_cursor_pos(pos))
            else:
                self.setCursor(Qt.CursorShape.ArrowCursor)
        super().mouseMoveEvent(e)
            
    def mouseReleaseEvent(self, e):
        self.is_dragging = False
        self.is_resizing = False
        self.resize_edge = self.EDGE_NONE
        if not self.is_max:
            self._set_cursor_shape(self._calc_cursor_pos(e.position().toPoint()))
        super().mouseReleaseEvent(e)
    
    def mouseDoubleClickEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            pos = e.position().toPoint()
            if self._is_in_title_bar(pos):
                self.toggle_max()
                e.accept()
                return
        super().mouseDoubleClickEvent(e)

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls(): 
            e.setDropAction(Qt.DropAction.CopyAction)
            e.accept()

    def dragMoveEvent(self, e):
        if e.mimeData().hasUrls():
            e.setDropAction(Qt.DropAction.CopyAction)
            e.accept()

    def dropEvent(self, e: QDropEvent):
        urls = e.mimeData().urls()
        if not urls:
            e.ignore()
            return
        
        paths = []
        for u in urls:
            p = u.toLocalFile()
            if p:
                paths.append(p)
        
        if not paths:
            e.ignore()
            return
        
        first_path = paths[0]
        is_dir = os.path.isdir(first_path)
        is_file = os.path.isfile(first_path)
        
        current_tab = self.stack.currentIndex()
        
        if current_tab == 0:
            if is_dir:
                self.in_input_dir.setText(first_path)
                self.log(f"已设置脚本目录: {first_path}")
                    
        elif current_tab == 1:
            if is_dir:
                self.in_pack_folder.setText(first_path)
                self.log(f"已设置打包文件夹: {first_path}")
                if not self.in_pack_output.text():
                    self.in_pack_output.setText(first_path.rstrip('/\\') + "_packed.bin")
            elif is_file:
                if first_path.lower().endswith('.bin'):
                    self.in_archive_input.setText(first_path)
                    if not self.in_archive_output.text():
                        self.in_archive_output.setText(first_path + "~")
                    self.log(f"已设置资源包: {os.path.basename(first_path)}")
                else:
                    self.in_decompress_file.setText(first_path)
                    self.log(f"已设置解压文件: {os.path.basename(first_path)}")
                    
        elif current_tab == 2:
            if is_dir:
                self.in_escr_input.setText(first_path)
                self.log(f"已设置脚本目录: {first_path}")
            elif is_file and first_path.lower().endswith('.bin'):
                try:
                    strings, context = EscudeManager.load_script(first_path)
                    self.script_strings = strings
                    self.script_context = context
                    self.script_path = first_path
                    self.script_list.clear()
                    for i, s in enumerate(strings):
                        self.script_list.addItem(f"[{i}] {s}")
                    self.lbl_script_path.setText(f"当前文件: {os.path.basename(first_path)} (共 {len(strings)} 条)")
                    self.log(f"已加载脚本: {os.path.basename(first_path)} ({len(strings)} 条)")
                except Exception as ex:
                    self.log(f"加载脚本失败: {ex}")
        
        e.accept()

if __name__ == "__main__":
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    os.environ["QT_QPA_FONTDIR"] = ""
    
    app = QApplication(sys.argv)
    
    app.setFont(get_app_font(10))
    
    w = EscudeApp()
    w.show()
    sys.exit(app.exec())
