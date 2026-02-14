import struct
import os
import json


class SilkyMesScript:
    default_encoding = "GBK"
    technical_instances = (">", "<")

    # [Opcode, struct, name].
    command_library = (
        (0x00, '', 'RETURN'),
        (0x01, 'I', ''),  # Found only in LIBLARY.LIB
        (0x02, '', ''),
        (0x03, '', ''),  # Found only in LIBLARY.LIB
        (0x04, '', ''),
        (0x05, '', ''),
        (0x06, '', ''),  # Found only in LIBLARY.LIB

        (0x0A, 'S', 'STR_CRYPT'),
        (0x0B, 'S', 'STR_UNCRYPT'),
        (0x0C, '', ''),
        (0x0D, '', ''),
        (0x0E, '', ''),
        (0x0F, '', ''),

        (0x10, 'B', ''),
        (0x11, '', ''),
        (0x14, '>I', 'JUMP'),
        (0x15, '>I', 'MSG_OFSETTER'),
        (0x16, '>I', 'SPEC_OFSETTER'),  # Found only in LIBLARY.LIB
        (0x17, '', ''),
        (0x18, '', ''),
        (0x19, '>I', 'MESSAGE'),
        (0x1A, '>I', ''),
        (0x1B, '>I', ''),
        (0x1C, 'B', 'TO_NEW_STRING'),

        (0x32, 'i', 'PUSH'),
        (0x33, 'S', 'PUSH_STR'),
        (0x34, '', ''),
        (0x35, '', ''),
        (0x36, 'B', 'JUMP_2'),
        (0x37, '', ''),
        (0x38, '', ''),
        (0x3A, '', ''),
        (0x3B, '', ''),
        (0x3C, '', ''),
        (0x3D, '', ''),
        (0x3E, '', ''),
        (0x3F, '', ''),

        (0x40, '', ''),
        (0x41, '', ''),
        (0x42, '', ''),
        (0x43, '', ''),

        (0xFA, '', ''),
        (0xFB, '', ''),
        (0xFC, '', ''),
        (0xFD, '', ''),
        (0xFE, '', ''),
        (0xFF, '', ''),
    )
    offsets_library = (
        (0x14, 0),
        (0x15, 0),
        (0x16, 0),
        (0x1b, 0),
    )

    # Pre-built lookup tables (class-level, built once)
    _cmd_by_opcode = {entry[0]: (i, entry) for i, entry in enumerate(command_library)}
    _cmd_by_name = {}
    for _i, _entry in enumerate(command_library):
        if _entry[2]:
            _cmd_by_name[_entry[2]] = (_i, _entry)
    _offset_by_opcode = {entry[0]: entry for entry in offsets_library}

    def __init__(self, mes_name: str, txt_name: str, encoding: str = "", debug: bool = False, verbose: bool = False,
                 hackerman_mode: bool = False):
        self._verbose = verbose
        if encoding == "":
            self.encoding = self.default_encoding
        else:
            self.encoding = encoding
        self._hackerman_mode = hackerman_mode
        self._debug = debug
        self._mes_name = mes_name
        self._txt_name = txt_name
        self._prm = [0, 0]
        self._offsets = []
        self._first_offsets = []
        self._second_offsets = []

        self.get_I.instances = ("I", "i")
        self.get_H.instances = ("H", "h")
        self.get_B.instances = ("B", "b")
        self.get_S.instances = ("S",)
        self.set_I.instances = self.get_I.instances
        self.set_H.instances = self.get_H.instances
        self.set_B.instances = self.get_B.instances
        self.set_S.instances = self.get_S.instances

    # User methods.

    def disassemble(self) -> None:
        """Disassemble Silky Engine mes script."""
        self._offsets = []
        self._prm, self._first_offsets, self._second_offsets = self._diss_header()
        self._diss_other_offsets()
        if self._verbose:
            print("Parameters:", self._prm)
            print("First offsets:", len(self._first_offsets), self._first_offsets)
            print("Second offsets:", len(self._second_offsets), self._second_offsets)
            print("True offsets:", len(self._offsets), self._offsets)
        self._disassemble_commands()

    def assemble(self) -> None:
        """Assemble Silky Engine mes script."""
        self._prm, self._first_offsets, self._second_offsets, self._offsets = self._assemble_offsets_and_parameters()
        if self._verbose:
            print("Parameters:", self._prm)
            print("First offsets:", self._first_offsets)
            print("True offsets:", self._offsets)
        self._assemble_script_file()

    # Technical methods for assembling.

    def _resolve_command(self, command_string: str):
        """Resolve a command string (name or hex) to (index, entry). Uses lookup dicts."""
        # Try by name first (includes STR_UNCRYPT -> STR_CRYPT mapping)
        if command_string == 'STR_UNCRYPT':
            lookup = self._cmd_by_name.get('STR_CRYPT')
            if lookup:
                return lookup
        lookup = self._cmd_by_name.get(command_string)
        if lookup:
            return lookup
        # Try by hex
        try:
            opcode = int(command_string, 16)
        except ValueError:
            raise SilkyMesArchiveError("Error! There is no such command.\n{}".format(command_string))
        lookup = self._cmd_by_opcode.get(opcode)
        if lookup:
            return lookup
        raise SilkyMesArchiveError("Error! There is no such command.\n{}".format(command_string))

    def _assemble_script_file(self) -> None:
        with open(self._txt_name, 'r', encoding='utf-8-sig') as in_file:
            all_lines = in_file.readlines()

        try:
            os.rename(self._mes_name, self._mes_name + '.bak')
        except OSError:
            pass

        buf = bytearray()
        message_count = 0
        search_offset = [i[0] for i in self._offsets]

        for parameter in self._prm:
            buf += struct.pack('I', parameter)
        for first_offset in self._first_offsets:
            buf += struct.pack('I', first_offset)
        for second_offset in self._second_offsets:
            buf += struct.pack('I', second_offset)

        i = 0
        total = len(all_lines)
        while i < total:
            line = all_lines[i]
            i += 1
            if line == '' or len(line) <= 1 or line == '\n' or line[0] == '$':
                continue
            if line[1] == '0':
                buf += bytes.fromhex(line[3:].rstrip('\n'))
            elif line[1] == '1':
                command_string = line[3:].rstrip('\n')
                command_index, entry = self._resolve_command(command_string)
                buf += struct.pack('B', entry[0])

                if i >= total:
                    break
                arg_line = all_lines[i]
                i += 1
                argument_list = json.loads(arg_line)

                this_command = entry[0]
                if this_command == 0x19:
                    argument_list[0] = message_count
                    message_count += 1
                else:
                    offset_entry = self._offset_by_opcode.get(this_command)
                    if offset_entry:
                        offset_set = offset_entry[1]
                        indexer = search_offset.index(argument_list[offset_set])
                        argument_list[offset_set] = self._offsets[indexer][1]

                buf += self.set_args(argument_list, entry[1], self.encoding)

        with open(self._mes_name, 'wb') as out_file:
            out_file.write(buf)

    def _assemble_offsets_and_parameters(self) -> tuple:
        """Assemble offsets and parameters of Silky Engine's mes archive."""
        with open(self._txt_name, 'r', encoding='utf-8-sig') as in_file:
            all_lines = in_file.readlines()

        first_offsets = []
        second_offsets = []
        offsets = []
        prm = [0, 0]

        pointer = 0
        message_count = 0

        i = 0
        total = len(all_lines)
        while i < total:
            line = all_lines[i]
            i += 1
            if line == '' or len(line) <= 1 or line == '\n' or line[0] == '$':
                continue

            if line[1] == '0':  # "Free bytes".
                pointer += len(line[3:].rstrip('\n').split(' '))
            elif line[1] == '1':  # Command.
                command_string = line[3:].rstrip('\n')
                command_index, entry = self._resolve_command(command_string)

                if entry[0] == 0x19:
                    message_count += 1
                    first_offsets.append(pointer)

                pointer += 1

                if i >= total:
                    break
                arg_line = all_lines[i]
                i += 1
                argument_list = json.loads(arg_line)
                if entry[0] == 0x19:
                    argument_list[0] = 0
                argument_bytes = self.set_args(argument_list, entry[1], self.encoding)
                pointer += len(argument_bytes)

            elif line[1] == '2':  # If label (of true offset).
                offset_number = int(line[3:].rstrip('\n'))
                offsets.append([offset_number, pointer])

            elif line[1] == '3':  # If special header's label.
                second_offsets.append(pointer)

        prm[0] = message_count
        prm[1] = len(second_offsets)

        return prm, first_offsets, second_offsets, offsets

    # Technical methods for disassembling.

    def _disassemble_commands(self) -> None:
        """Disassemble Silky Engine mes script commands."""
        pointer = self.get_true_offset(0)
        out_parts = []  # Collect output as list, join at end

        with open(self._mes_name, 'rb') as in_file:
            data = in_file.read()

        sorted_offset = sorted(list(enumerate(self._offsets)), key=lambda x: x[1])
        search_offset = [i[1] for i in sorted_offset]
        initial_sorted_offset = sorted_offset.copy()
        initial_search_offset = search_offset.copy()

        second_offsets_set = set(self.get_true_offset(i) for i in self._second_offsets)

        stringer = ''
        data_len = len(data)
        pos = pointer  # current position in data

        # Pre-build a dict for fast offset lookup
        # offset_at_pos: {position -> list of (original_index, offset_value)}
        offset_at_pos = {}
        for orig_idx, offset_val in sorted_offset:
            offset_at_pos.setdefault(offset_val, []).append(orig_idx)

        while pos < data_len:
            # Offsets functionality
            if pos in offset_at_pos:
                if stringer:
                    out_parts.append('#0-{}\n'.format(stringer.lstrip(' ')))
                    stringer = ''
                for orig_idx in offset_at_pos[pos]:
                    if self._debug:
                        out_parts.append("#2-{} {}\n".format(orig_idx, pos))
                    else:
                        out_parts.append("#2-{}\n".format(orig_idx))

            if pos in second_offsets_set:
                if stringer:
                    out_parts.append('#0-{}\n'.format(stringer.lstrip(' ')))
                    stringer = ''
                if self._debug:
                    out_parts.append("#3 {}\n".format(pos))
                else:
                    out_parts.append("#3\n")

            # Commands functionality
            current_byte = data[pos]
            pos += 1

            lookup = self._cmd_by_opcode.get(current_byte)
            if lookup is not None:
                lib_index, entry = lookup
                if stringer:
                    out_parts.append('#0-{}\n'.format(stringer.lstrip(' ')))
                    stringer = ''

                # Write command name
                cmd_name = entry[2]
                if cmd_name == '':
                    analyzer = '{:02x}'.format(current_byte)
                    out_parts.append("#1-")
                    out_parts.append(analyzer)
                elif cmd_name == 'STR_CRYPT':
                    out_parts.append("#1-STR_UNCRYPT")
                else:
                    out_parts.append("#1-")
                    out_parts.append(cmd_name)

                if self._debug:
                    out_parts.append(' {}\n'.format(pos - 1))
                else:
                    out_parts.append('\n')

                # Parse arguments from binary data
                arguments_list, bytes_read = self._get_args_from_bytes(data, pos, entry[1], current_byte, self.encoding)
                pos += bytes_read

                # Handle offset resolution
                offset_entry = self._offset_by_opcode.get(current_byte)
                if offset_entry:
                    first_indexer = offset_entry[1]
                    evil_offset = self.get_true_offset(arguments_list[first_indexer])
                    indexer = initial_search_offset.index(evil_offset)
                    arguments_list[first_indexer] = initial_sorted_offset[indexer][0]

                if current_byte == 0x19:
                    arguments_list[0] = "*MESSAGE_NUMBER*"

                out_parts.append(json.dumps(arguments_list, ensure_ascii=False))
                out_parts.append('\n')
            else:
                stringer += ' {:02x}'.format(current_byte)

        if stringer:
            out_parts.append('#0-{}\n'.format(stringer.lstrip(' ')))

        with open(self._txt_name, 'w', encoding='utf-8-sig') as out_file:
            out_file.write(''.join(out_parts))

    @staticmethod
    def _get_args_from_bytes(data: bytes, pos: int, args: str, current_byte: int, encoding: str):
        """Parse arguments directly from bytes buffer. Returns (arguments_list, bytes_consumed)."""
        arguments_list = []
        start_pos = pos
        appendix = ""
        for argument in args:
            if argument in SilkyMesScript.technical_instances:
                appendix = argument
                continue

            if argument in ('I', 'i'):
                fmt = appendix + argument
                val = struct.unpack_from(fmt, data, pos)[0]
                pos += 4
                arguments_list.append(val)
            elif argument in ('H', 'h'):
                fmt = appendix + argument
                val = struct.unpack_from(fmt, data, pos)[0]
                pos += 2
                arguments_list.append(val)
            elif argument in ('B', 'b'):
                fmt = appendix + argument
                val = struct.unpack_from(fmt, data, pos)[0]
                pos += 1
                arguments_list.append(val)
            elif argument == 'S':
                # Read null-terminated string
                end = data.index(b'\x00', pos)
                raw = data[pos:end]
                pos = end + 1
                result = SilkyMesScript._decode_string(current_byte, raw, encoding)
                arguments_list.append(result)
            appendix = ""

        return arguments_list, pos - start_pos

    @staticmethod
    def _decode_string(mode: int, raw: bytes, encoding: str) -> str:
        """Decode a raw string based on mode (0x0A=encrypted, 0x0B/0x33=plain)."""
        if mode == 0x0A:
            enc_lower = encoding.lower().replace('-', '').replace('_', '')
            is_utf8 = enc_lower in ('utf8', 'utf8sig')
            decoded = bytearray()
            i = 0
            raw_len = len(raw)
            while i < raw_len:
                byte_val = raw[i]
                if not SilkyMesScript._is_multibyte_lead(byte_val, encoding):
                    # Single-byte: apply decryption
                    zlo = byte_val - 0x7D62
                    high = (zlo & 0xff00) >> 8
                    low = zlo & 0xff
                    decoded.append(high)
                    decoded.append(low)
                    i += 1
                else:
                    if is_utf8:
                        char_len = SilkyMesScript._utf8_byte_count(byte_val)
                        for j in range(char_len):
                            if i < raw_len:
                                decoded.append(raw[i])
                                i += 1
                    else:
                        decoded.append(raw[i])
                        i += 1
                        if i < raw_len:
                            decoded.append(raw[i])
                            i += 1
            try:
                return bytes(decoded).decode(encoding)
            except UnicodeDecodeError:
                return bytes(decoded).hex(' ')
        elif mode in (0x33, 0x0B):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                return raw.hex(' ')
        else:
            return raw.hex(' ')

    def _diss_other_offsets(self) -> None:
        """Disassemble other offsets from the Silky Engine script."""
        pointer = self.get_true_offset(0)

        with open(self._mes_name, 'rb') as f:
            data = f.read()

        data_len = len(data)
        pos = pointer
        offsets_set = set(self._offsets)

        while pos < data_len:
            current_byte = data[pos]
            pos += 1

            lookup = self._cmd_by_opcode.get(current_byte)
            if lookup is not None:
                _, entry = lookup
                arguments_list, bytes_read = self._get_args_from_bytes(data, pos, entry[1], current_byte, self.encoding)
                pos += bytes_read

                offset_entry = self._offset_by_opcode.get(current_byte)
                if offset_entry:
                    good_offset = self.get_true_offset(arguments_list[offset_entry[1]])
                    if good_offset not in offsets_set:
                        self._offsets.append(good_offset)
                        offsets_set.add(good_offset)

    def _diss_header(self) -> tuple:
        """Disassemble Silky Engine mes header."""
        first_offsets = []
        second_offsets = []
        with open(self._mes_name, 'rb') as mes_file:
            prm = list(struct.unpack('II', mes_file.read(8)))
            for i in range(prm[0]):
                first_offsets.append(struct.unpack('I', mes_file.read(4))[0])
            for i in range(prm[1]):
                second_offsets.append(struct.unpack('I', mes_file.read(4))[0])

        return prm, first_offsets, second_offsets

    # Offsets methods.

    def get_true_offset(self, raw_offset: int) -> int:
        return raw_offset + self._prm[0] * 4 + self._prm[1] * 4 + 8

    def set_true_offset(self, raw_offset):
        return raw_offset - self._prm[0] * 4 - self._prm[1] * 4 - 8

    # Structure packing technicals methods.

    @staticmethod
    def set_args(argument_list, args: str, current_encoding: str) -> bytes:
        args_bytes = b''
        appendix = ""
        current_argument = 0
        for argument in args:
            if argument in SilkyMesScript.technical_instances:
                appendix = argument
                continue

            if argument in SilkyMesScript.set_I.instances:
                args_bytes += SilkyMesScript.set_I(argument_list[current_argument], appendix+argument)
            elif argument in SilkyMesScript.set_H.instances:
                args_bytes += SilkyMesScript.set_H(argument_list[current_argument], appendix+argument)
            elif argument in SilkyMesScript.set_B.instances:
                args_bytes += SilkyMesScript.set_B(argument_list[current_argument], appendix+argument)
            elif argument in SilkyMesScript.set_S.instances:
                args_bytes += SilkyMesScript.set_S(argument_list[current_argument], current_encoding)
            current_argument += 1

        return args_bytes

    @staticmethod
    def set_B(arguments: int, command: str) -> bytes:
        return struct.pack(command, arguments)

    @staticmethod
    def set_H(arguments: int, command: str) -> bytes:
        return struct.pack(command, arguments)

    @staticmethod
    def set_I(arguments: int, command: str) -> bytes:
        return struct.pack(command, arguments)

    @staticmethod
    def set_S(arguments: str, encoding: str) -> bytes:
        return arguments.encode(encoding) + b'\x00'

    # Structure extraction technical methods (kept for compatibility).

    @staticmethod
    def get_args(in_file, args: str, current_byte: int, current_encoding: str) -> list:
        arguments_list = []
        appendix = ""
        for argument in args:
            if argument in SilkyMesScript.technical_instances:
                appendix = argument
            elif argument in SilkyMesScript.get_I.instances:
                arguments_list.append(SilkyMesScript.get_I(in_file, appendix+argument))
            elif argument in SilkyMesScript.get_H.instances:
                arguments_list.append(SilkyMesScript.get_H(in_file, appendix+argument))
            elif argument in SilkyMesScript.get_B.instances:
                arguments_list.append(SilkyMesScript.get_B(in_file, appendix+argument))
            elif argument in SilkyMesScript.get_S.instances:
                leng, result = SilkyMesScript.get_S(current_byte, in_file, current_encoding)
                arguments_list.append(result)
        return arguments_list

    @staticmethod
    def get_B(file_in, definer: str) -> int:
        return struct.unpack(definer, file_in.read(1))[0]

    @staticmethod
    def get_H(file_in, definer: str) -> int:
        return struct.unpack(definer, file_in.read(2))[0]

    @staticmethod
    def get_I(file_in, definer: str) -> int:
        return struct.unpack(definer, file_in.read(4))[0]

    @staticmethod
    def _is_multibyte_lead(byte_val: int, encoding: str) -> bool:
        enc = encoding.lower().replace('-', '').replace('_', '')
        if enc in ('gbk', 'gb2312', 'gb18030', 'cp932', 'shiftjis', 'shift_jis', 'sjis'):
            return byte_val >= 0x81
        elif enc in ('utf8', 'utf8sig'):
            return byte_val >= 0xC0
        else:
            return byte_val >= 0x81

    @staticmethod
    def _utf8_byte_count(lead_byte: int) -> int:
        if lead_byte < 0x80:
            return 1
        elif lead_byte < 0xC0:
            return 1
        elif lead_byte < 0xE0:
            return 2
        elif lead_byte < 0xF0:
            return 3
        else:
            return 4

    @staticmethod
    def get_S(mode: int, in_file, encoding: str) -> tuple:
        """Get string from the mode and input file."""
        length = 0
        string = b''
        byte = in_file.read(1)
        while byte != b'\x00':
            string += byte
            length += 1
            byte = in_file.read(1)
        result = SilkyMesScript._decode_string(mode, string, encoding)
        return length, result

    # --- Text extraction / import helpers ---

    # Name block detection pattern:
    # PUSH_STR["character_name"] + PUSH[83886080] + PUSH[486539264] + 18[] +
    # PUSH_STR["name"] + PUSH_STR["main.inc"] + ...
    # Known PUSH values that appear right after a character-name PUSH_STR
    _NAME_BLOCK_PUSH_VALS = frozenset([83886080, 167772160])

    @classmethod
    def _detect_name_block(cls, lines, i, total):
        """Check if line i is a PUSH_STR that's part of a character name block.

        Pattern A: PUSH_STR[name] -> PUSH[83886080]  -> PUSH[...] -> 18[]
        Pattern B: PUSH_STR[name] -> PUSH[167772160] -> PUSH[...] -> 34[] -> PUSH[...] -> 18[]

        Returns the character name string if detected, else None.
        """
        if i + 7 >= total:
            return None
        cl = lines[i].rstrip('\n')
        if cl != '#1-PUSH_STR':
            return None

        arg = cls._parse_json_str(lines[i + 1].rstrip('\n'))
        # Must be non-ASCII (character name)
        try:
            arg.encode('ascii')
            return None
        except UnicodeEncodeError:
            pass

        # Check PUSH_STR -> PUSH -> ...
        if lines[i + 2].rstrip('\n') != '#1-PUSH':
            return None
        try:
            push_val = json.loads(lines[i + 3].rstrip('\n'))
            if not (isinstance(push_val, list) and push_val[0] in cls._NAME_BLOCK_PUSH_VALS):
                return None
        except (json.JSONDecodeError, IndexError, KeyError):
            return None

        # Pattern A: PUSH[val] -> PUSH[...] -> 18[]
        if (i + 6 < total and
            lines[i + 4].rstrip('\n') == '#1-PUSH' and
            lines[i + 6].rstrip('\n') == '#1-18'):
            return arg

        # Pattern B: PUSH[val] -> PUSH[...] -> 34[] -> PUSH[...] -> 18[]
        if (i + 10 < total and
            lines[i + 4].rstrip('\n') == '#1-PUSH' and
            lines[i + 6].rstrip('\n') == '#1-34' and
            lines[i + 8].rstrip('\n') == '#1-PUSH' and
            lines[i + 10].rstrip('\n') == '#1-18'):
            return arg

        return None

    _BLOCK_INTERNAL_OPCODES = frozenset([
        '#1-PUSH', '#1-PUSH_STR', '#1-RETURN',
        '#1-ff', '#1-fe', '#1-fd', '#1-fc', '#1-fb', '#1-fa',
        '#1-JUMP_2', '#1-3a', '#1-3b', '#1-3c', '#1-3d', '#1-3e', '#1-3f',
        '#1-40', '#1-41', '#1-42', '#1-43',
        '#1-34', '#1-35', '#1-37', '#1-38',
        '#1-10', '#1-11', '#1-0c', '#1-0d', '#1-0e', '#1-0f',
        '#1-02', '#1-03', '#1-04', '#1-05', '#1-06',
        '#1-17', '#1-18',
    ])

    _BLOCK_END_OPCODES = frozenset([
        '#1-MESSAGE', '#1-JUMP', '#1-MSG_OFSETTER', '#1-SPEC_OFSETTER',
        '#1-1a', '#1-1b',
    ])

    @staticmethod
    def _is_label_or_free(line: str) -> bool:
        return line.startswith('#0-') or line.startswith('#2-') or line.startswith('#3')

    @classmethod
    def _collect_text_block(cls, lines, start, total):
        """Collect all STR_UNCRYPT text parts belonging to one dialogue block.

        Returns (text_parts, next_i, detected_name, name_arg_line_idx) where:
        - text_parts: list of (arg_line_index, text_string, part_type) tuples
          For ruby_reading: arg_line_index is the int line index of the reading STR_UNCRYPT arg
        - detected_name: character name found inside the block (or None)
        - name_arg_line_idx: line index of the name's PUSH_STR arg (or None)
        """
        text_parts = []
        detected_name = None
        name_arg_line_idx = None
        i = start
        in_ruby = False

        while i < total:
            cl = lines[i].rstrip('\n')

            # Check for name block inside the text block
            name = cls._detect_name_block(lines, i, total)
            if name is not None:
                detected_name = name
                name_arg_line_idx = i + 1  # The arg line of PUSH_STR
                i += 2
                continue

            if cl == '#1-STR_UNCRYPT':
                arg_line = lines[i + 1].rstrip('\n') if i + 1 < total else '[]'
                text_val = cls._parse_json_str(arg_line)

                if in_ruby:
                    text_parts.append((i + 1, text_val, 'ruby_part'))
                else:
                    text_parts.append((i + 1, text_val, 'text'))
                i += 2

            elif cl == '#1-TO_NEW_STRING':
                arg_line = lines[i + 1].rstrip('\n') if i + 1 < total else '[0]'
                to_new_arg = cls._parse_json_first_int(arg_line)
                if to_new_arg == 1:
                    in_ruby = True
                    text_parts.append((None, None, 'ruby_switch'))
                i += 2

            elif cl == '#1-RETURN' and in_ruby:
                i += 2
                in_ruby = False
                cls._finalize_ruby(text_parts)

            elif cl in cls._BLOCK_END_OPCODES:
                break

            elif cl in cls._BLOCK_INTERNAL_OPCODES:
                i += 2

            elif cls._is_label_or_free(cl):
                i += 1

            elif cl.startswith('#1-'):
                i += 2

            elif cl.startswith('$'):
                i += 1

            else:
                i += 1

        return text_parts, i, detected_name, name_arg_line_idx

    @staticmethod
    def _finalize_ruby(text_parts):
        """Convert the last sequence of ruby_part entries into a ruby annotation.

        The reading's STR_UNCRYPT arg line index (int) is stored in the
        ruby_reading entry so import_text can update it.
        """
        ruby_texts = []
        while text_parts and text_parts[-1][2] == 'ruby_part':
            ruby_texts.insert(0, text_parts.pop())

        # Pop the ruby_switch entry
        if text_parts and text_parts[-1][2] == 'ruby_switch':
            text_parts.pop()

        if not ruby_texts or not text_parts:
            text_parts.extend(ruby_texts)
            return

        readings = [t[1] for t in ruby_texts if t[1].strip()]
        if readings:
            reading = readings[-1]
        else:
            reading = ''.join(t[1] for t in ruby_texts)

        # Collect ALL ruby_part line indices (separator + reading)
        all_ruby_line_indices = [t[0] for t in ruby_texts]

        last_idx, last_text, _ = text_parts[-1]
        text_parts[-1] = (last_idx, last_text, 'ruby_base')
        # Store all ruby part line indices so import_text can clear them all
        text_parts.append((all_ruby_line_indices, reading, 'ruby_reading'))

    @staticmethod
    def extract_text(opcode_txt_path: str, text_txt_path: str) -> int:
        """Extract translatable text from opcode txt into a clean text file.

        Output format (per dialogue block with name):
        ◇0001◇name◇奈緒矢
        ◆0001◆name◆奈緒矢
        ◇0002◇original_text
        ◆0002◆(translated text, initially same as original)
        (blank line separator)

        Name and text get separate sequential indices.
        Returns the number of entries extracted.
        """
        with open(opcode_txt_path, 'r', encoding='utf-8-sig') as f:
            lines = f.readlines()

        entries = []  # list of (name_or_None, text_parts)
        i = 0
        total = len(lines)

        while i < total:
            line = lines[i].rstrip('\n')

            if line == '#1-MESSAGE':
                i += 2  # skip MESSAGE + argument
                text_parts, i, block_name, _ = SilkyMesScript._collect_text_block(lines, i, total)
                if text_parts:
                    entries.append((block_name, text_parts))

            elif line == '#1-STR_UNCRYPT':
                text_parts, i, block_name, _ = SilkyMesScript._collect_text_block(lines, i, total)
                if text_parts:
                    entries.append((block_name, text_parts))
            else:
                i += 1

        # Write clean text file — name and text each get their own index
        seq = 0
        with open(text_txt_path, 'w', encoding='utf-8-sig') as out:
            for name, parts in entries:
                if name is not None:
                    out.write(f'\u25c7{seq:04d}\u25c7name\u25c7{name}\n')
                    out.write(f'\u25c6{seq:04d}\u25c6name\u25c6{name}\n')
                    seq += 1
                    out.write('\n')
                display = SilkyMesScript._build_display_text(parts)
                out.write(f'\u25c7{seq:04d}\u25c7{display}\n')
                out.write(f'\u25c6{seq:04d}\u25c6{display}\n')
                out.write('\n')
                seq += 1

        return seq

    @staticmethod
    def _build_display_text(parts):
        """Build a display string from text_parts."""
        display_parts = []
        j = 0
        while j < len(parts):
            line_idx, text, ptype = parts[j]
            if ptype == 'ruby_base':
                if j + 1 < len(parts) and parts[j + 1][2] == 'ruby_reading':
                    reading = parts[j + 1][1]
                    display_parts.append('{' + text + '|' + reading + '}')
                    j += 2
                else:
                    display_parts.append(text)
                    j += 1
            elif ptype == 'ruby_reading':
                j += 1
            else:
                display_parts.append(text)
                j += 1
        return '\\n'.join(display_parts)

    @staticmethod
    def import_text(opcode_txt_path: str, text_txt_path: str, output_txt_path: str) -> int:
        """Import translated text back into the opcode txt file.

        Reads ◆ lines for both names and text.
        Name lines: ◆0001◆name◆翻译名
        Text lines: ◆0002◆翻译文本

        Returns the number of entries imported.
        """
        import re as _re

        # Parse translated entries from text file
        translations = {}      # seq_idx -> translated string
        name_translations = {} # seq_idx -> translated name
        with open(text_txt_path, 'r', encoding='utf-8-sig') as f:
            for tline in f:
                tline = tline.rstrip('\n')
                if not tline.startswith('\u25c6'):
                    continue
                # Split: ◆0001◆name◆翻译名  or  ◆0001◆翻译文本
                rest = tline[1:]  # strip leading ◆
                parts = rest.split('\u25c6')
                if len(parts) >= 3 and parts[1] == 'name':
                    # Name entry: ◆0001◆name◆翻译名
                    try:
                        name_translations[int(parts[0])] = parts[2]
                    except ValueError:
                        pass
                elif len(parts) >= 2:
                    # Text entry: ◆0001◆翻译文本
                    try:
                        translations[int(parts[0])] = parts[1]
                    except ValueError:
                        pass

        # Re-parse opcode txt with the same logic as extract_text
        with open(opcode_txt_path, 'r', encoding='utf-8-sig') as f:
            lines = f.readlines()

        # Walk through opcode lines, assign sequential indices matching extract_text
        seq = 0
        i = 0
        total = len(lines)

        while i < total:
            line = lines[i].rstrip('\n')

            is_message_block = (line == '#1-MESSAGE')
            is_standalone_str = (line == '#1-STR_UNCRYPT')

            if is_message_block:
                i += 2

            if is_message_block or is_standalone_str:
                text_parts, i, block_name, name_line_idx = SilkyMesScript._collect_text_block(lines, i, total)
                if text_parts:
                    # Name gets its own seq index (if present)
                    if block_name is not None:
                        if name_line_idx is not None and seq in name_translations:
                            trans_name = name_translations[seq]
                            lines[name_line_idx] = json.dumps([trans_name], ensure_ascii=False) + '\n'
                        seq += 1

                    # Text gets next seq index
                    if seq in translations:
                        trans = translations[seq]
                        trans_parts = trans.split('\\n')

                        # Parse ruby from translated text: {base|reading}
                        cleaned_parts = []
                        ruby_map = {}  # part_index -> reading (or None if no ruby)
                        for pidx, p in enumerate(trans_parts):
                            m = _re.search(r'\{([^|]+)\|([^}]+)\}', p)
                            if m:
                                cleaned_parts.append(_re.sub(r'\{([^|]+)\|[^}]+\}', r'\1', p))
                                ruby_map[pidx] = m.group(2)
                            else:
                                cleaned_parts.append(p)
                                ruby_map[pidx] = None

                        # Update text/ruby_base lines
                        str_line_indices = [
                            li for li, _, pt in text_parts
                            if pt == 'text' or pt == 'ruby_base'
                        ]

                        for j, li in enumerate(str_line_indices):
                            if li is not None and j < len(cleaned_parts):
                                lines[li] = json.dumps([cleaned_parts[j]], ensure_ascii=False) + '\n'

                        # Handle ruby_reading: update or clear reading text
                        for j, (data, text, ptype) in enumerate(text_parts):
                            if ptype == 'ruby_reading' and isinstance(data, list):
                                base_idx = j - 1
                                base_part_idx = None
                                if base_idx >= 0 and text_parts[base_idx][2] == 'ruby_base':
                                    base_li = text_parts[base_idx][0]
                                    for si, sli in enumerate(str_line_indices):
                                        if sli == base_li:
                                            base_part_idx = si
                                            break

                                if (base_part_idx is not None and
                                    base_part_idx in ruby_map and
                                    ruby_map[base_part_idx] is not None):
                                    # Translation kept ruby: update reading (last line)
                                    lines[data[-1]] = json.dumps([ruby_map[base_part_idx]], ensure_ascii=False) + '\n'
                                else:
                                    # Translation removed ruby: clear ALL ruby parts (separator + reading)
                                    for li in data:
                                        lines[li] = json.dumps([""], ensure_ascii=False) + '\n'

                    seq += 1
            else:
                i += 1

        with open(output_txt_path, 'w', encoding='utf-8-sig') as out:
            out.writelines(lines)

        return seq

    @staticmethod
    def _parse_json_str(arg_line: str) -> str:
        try:
            val = json.loads(arg_line)
            if isinstance(val, list) and len(val) > 0:
                return str(val[0])
        except (json.JSONDecodeError, IndexError):
            pass
        return arg_line

    @staticmethod
    def _parse_json_first_int(arg_line: str) -> int:
        try:
            val = json.loads(arg_line)
            if isinstance(val, list) and len(val) > 0:
                return int(val[0])
        except (json.JSONDecodeError, IndexError, ValueError):
            pass
        return 0


class SilkyMesArchiveError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)
