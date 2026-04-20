import os
import struct
import re
import io
from enum import Enum
from typing import List, Dict, Optional

class InstructionType(Enum):
    UNKNOW = 0
    LOAD_ENCRYPT_STR = 1  # 0x69-0x6D: 对话加密字符串
    LOAD_PLAIN_STR = 2    # 0x48-0x68: 普通字符串（路径/菜单等）
    LOAD_PREFIX_STR = 3   # 0x3B-0x47: 带前缀字节的字符串

STR_TYPES = {InstructionType.LOAD_ENCRYPT_STR, InstructionType.LOAD_PLAIN_STR, InstructionType.LOAD_PREFIX_STR}

class Instruct:
    def __init__(self, address: int, length: int, inst_type: InstructionType, opcode: int = 0):
        self.address = address
        self.new_address = 0
        self.length = length
        self.inst_type = inst_type
        self.opcode = opcode
        self.str_offset = 0   # 从 address 到字符串数据起始的偏移量
        self.str_length = 0   # 字符串数据长度（不含 null 终止符）

class BinaryReader:
    def __init__(self, data: bytes):
        self.stream = io.BytesIO(data)

    def read_byte(self) -> int:
        return ord(self.stream.read(1))

    def read_int16(self) -> int:
        return struct.unpack('<h', self.stream.read(2))[0]

    def read_uint16(self) -> int:
        return struct.unpack('<H', self.stream.read(2))[0]

    def read_int32(self) -> int:
        return struct.unpack('<i', self.stream.read(4))[0]

    def read_uint32(self) -> int:
        return struct.unpack('<I', self.stream.read(4))[0]

    def read_bytes(self, size: int) -> bytes:
        return self.stream.read(size)

    def read_cstring(self) -> bytes:
        buffer = bytearray()
        while True:
            b = self.stream.read(1)
            if not b or b[0] == 0:
                break
            buffer.append(b[0])
        return bytes(buffer)

    @property
    def position(self) -> int:
        return self.stream.tell()

    @position.setter
    def position(self, pos: int):
        self.stream.seek(pos)

    @property
    def length(self) -> int:
        curr = self.stream.tell()
        self.stream.seek(0, io.SEEK_END)
        end = self.stream.tell()
        self.stream.seek(curr)
        return end

class BinaryWriter:
    def __init__(self):
        self.stream = io.BytesIO()

    def write_byte(self, value: int):
        self.stream.write(struct.pack('B', value))

    def write_int16(self, value: int):
        self.stream.write(struct.pack('<h', value))

    def write_uint16(self, value: int):
        self.stream.write(struct.pack('<H', value))

    def write_int32(self, value: int):
        self.stream.write(struct.pack('<i', value))

    def write_uint32(self, value: int):
        self.stream.write(struct.pack('<I', value))

    def write_bytes(self, value: bytes):
        self.stream.write(value)

    def get_data(self) -> bytes:
        return self.stream.getvalue()

    @property
    def position(self) -> int:
        return self.stream.tell()

class Script:
    def __init__(self):
        self.jmp_addr_list = []
        self.unk_list = []
        self.code_section = b""
        self.instructs = []

    def load(self, file_path: str):
        with open(file_path, "rb") as f:
            data = f.read()
        
        reader = BinaryReader(data)
        self.jmp_addr_list = []
        self.unk_list = []
        self.instructs = []

        num_cmd = reader.read_int32()
        for _ in range(num_cmd):
            self.jmp_addr_list.append(reader.read_uint32())
        
        for _ in range(num_cmd):
            self.unk_list.append(reader.read_uint16())
        
        code_size = reader.length - reader.position
        self.code_section = reader.read_bytes(code_size)
        self.parse()

    def save(self, file_path: str):
        writer = BinaryWriter()
        writer.write_int32(len(self.jmp_addr_list))
        for addr in self.jmp_addr_list:
            writer.write_uint32(addr)
        for unk in self.unk_list:
            writer.write_uint16(unk)
        writer.write_bytes(self.code_section)
        
        dirname = os.path.dirname(file_path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(file_path, "wb") as f:
            f.write(writer.get_data())

    def parse(self):
        reader = BinaryReader(self.code_section)
        reader.read_byte() # Version
        reader.read_int16() # 0xAB

        while reader.position < reader.length:
            self.read_cmd(reader)

        total_inst_len = sum(inst.length for inst in self.instructs)
        if total_inst_len != reader.length - 3:
             # Just a warning instead of error to be more robust, or maybe check original logic
             print(f"Warning: Failed parsing code accurately. {total_inst_len} != {reader.length - 3}")

    def read_cmd(self, reader: BinaryReader):
        addr = reader.position
        inst_type = InstructionType.UNKNOW
        opcode = reader.read_byte()
        str_offset = 0
        str_length = 0

        if opcode >= 0x3B:
            if opcode >= 0x48:
                if opcode >= 0x69:
                    if opcode >= 0x6E:
                        reader.read_int16()
                        reader.read_int16()
                        reader.read_int16()
                        reader.read_int16()
                    else:
                        inst_type = InstructionType.LOAD_ENCRYPT_STR
                        str_offset = reader.position - addr
                        str_start = reader.position
                        reader.read_cstring()
                        str_length = reader.position - str_start - 1
                else:
                    inst_type = InstructionType.LOAD_PLAIN_STR
                    str_offset = reader.position - addr
                    str_start = reader.position
                    reader.read_cstring()
                    str_length = reader.position - str_start - 1
            else:
                inst_type = InstructionType.LOAD_PREFIX_STR
                reader.read_byte()  # prefix byte
                str_offset = reader.position - addr
                str_start = reader.position
                reader.read_cstring()
                str_length = reader.position - str_start - 1
        else:
            reader.read_byte()
            reader.read_byte()

        if reader.position < reader.length:
            next_byte = reader.read_byte()
            if next_byte == 0x77:
                reader.read_int16()
                reader.read_int16()
                reader.read_int16()
                reader.read_int16()
            else:
                reader.position -= 1
        
        length = reader.position - addr
        inst = Instruct(addr, length, inst_type, opcode)
        inst.str_offset = str_offset
        inst.str_length = str_length
        self.instructs.append(inst)

    def decrypt_string(self, data: bytearray):
        for i in range(len(data)):
            val = (data[i] + 0x20) & 0xFF
            if val == 0x24:
                val = 0x20
            data[i] = val

    def encrypt_string(self, data: bytearray):
        for i in range(len(data)):
            val = data[i]
            if val == 0x20:
                val = 0x24
            val = (val - 0x20) & 0xFF
            data[i] = val

    def export_text(self, text_path: str, encoding: str, all_text: bool = False):
        target_types = STR_TYPES if all_text else {InstructionType.LOAD_ENCRYPT_STR}
        strings_to_export = [inst for inst in self.instructs if inst.inst_type in target_types]
        if not strings_to_export:
            return

        with open(text_path, "w", encoding="utf-8") as f:
            for inst in strings_to_export:
                if inst.str_length <= 0:
                    continue
                
                # 使用精确的 str_offset 和 str_length 提取字符串数据
                data = bytearray(self.code_section[inst.address + inst.str_offset : inst.address + inst.str_offset + inst.str_length])
                
                # 仅对加密字符串执行解密
                if inst.inst_type == InstructionType.LOAD_ENCRYPT_STR:
                    self.decrypt_string(data)
                
                try:
                    s = data.decode(encoding)
                except UnicodeDecodeError:
                    s = data.decode('latin-1') # fallback

                s = s.replace("\r", "\\r").replace("\n", "\\n")
                prefix = "name◆" if inst.opcode == 0x69 else ""
                f.write(f"◇{inst.address:08X}◇{prefix}{s}\n")
                f.write(f"◆{inst.address:08X}◆{prefix}{s}\n\n")

    def import_text(self, text_path: str, encoding: str, all_text: bool = False):
        translated = {}
        if not os.path.exists(text_path):
            return

        with open(text_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                line = line.strip()
                if not line or not line.startswith("◆"):
                    continue
                
                match = re.match(r"◆([0-9A-Fa-f]+)◆(?:name◆)?(.*)$", line)
                if match:
                    offset = int(match.group(1), 16)
                    content = match.group(2).replace("\\r", "\r").replace("\\n", "\n")
                    translated[offset] = content
        
        if not translated:
            return

        new_code_stream = BinaryWriter()
        new_code_stream.write_bytes(self.code_section[0:3]) # Version and 0xAB

        for inst in self.instructs:
            inst.new_address = new_code_stream.position
            
            target_types = STR_TYPES if all_text else {InstructionType.LOAD_ENCRYPT_STR}
            if inst.inst_type in target_types and inst.address in translated:
                s = translated[inst.address]
                data = bytearray(s.encode(encoding, errors='replace'))
                
                # 仅对加密字符串执行加密
                if inst.inst_type == InstructionType.LOAD_ENCRYPT_STR:
                    self.encrypt_string(data)
                
                # 写入前缀部分（opcode + 可能的前缀字节）
                new_code_stream.write_bytes(self.code_section[inst.address : inst.address + inst.str_offset])
                # 写入新字符串数据
                new_code_stream.write_bytes(data)
                # 写入 null 终止符
                new_code_stream.write_byte(0)
                # 保留后缀部分（如 0x77 + 4个int16）
                suffix_start = inst.address + inst.str_offset + inst.str_length + 1  # +1 跳过原始 null
                suffix_data = self.code_section[suffix_start : inst.address + inst.length]
                if suffix_data:
                    new_code_stream.write_bytes(suffix_data)
            else:
                new_code_stream.write_bytes(self.code_section[inst.address : inst.address + inst.length])
            
            # Update jump addresses
            for idx, jmp_addr in enumerate(self.jmp_addr_list):
                if (jmp_addr & 0x7FFFFFFF) == inst.address:
                    addr_val = jmp_addr & 0x80000000
                    addr_val |= (inst.new_address & 0x7FFFFFFF)
                    self.jmp_addr_list[idx] = addr_val

        self.code_section = new_code_stream.get_data()
