# BGI ._bp file opcode table

import asdis
import re
import struct

re_fcn = re.compile(r'([A-Za-z_][A-Za-z0-9_:]*)\(.*\)')

offsets = set()
subop_group_ops = {0x7F, 0x80, 0x81, 0x90, 0x91, 0x92, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xFF}
current_text_encoding = 'cp932'

def _make_subop_sizes(subops, payload_sizes=None):
	sizes = {sub: 0 for sub in subops}
	if payload_sizes:
		sizes.update(payload_sizes)
	return sizes

def _expand_subop_ranges(spec):
	subops = []
	for chunk in spec.split(','):
		chunk = chunk.strip()
		if not chunk:
			continue
		if '-' in chunk:
			start, end = chunk.split('-', 1)
			subops.extend(range(int(start, 16), int(end, 16) + 1))
		else:
			subops.append(int(chunk, 16))
	return subops

subop_size_table = {
	0x7F: _make_subop_sizes(_expand_subop_ranges('00, 80-86, 88-8B')),
	0x80: _make_subop_sizes(_expand_subop_ranges('00-21, 24-2D, 2F-41, 44-4C, 50, 52-54, 58-5A, 5C-71, 74, 78-7B, 80-85, 88-8B, 90-91, 94-9A, 9C-A1, A8-A9, AC, AF-B1, B4-B6, C0-C1, C4-C5, CF-D4, D8-DE, E0-E3, E8-EA, EC-EE, F0-FE')),
	0x81: _make_subop_sizes(_expand_subop_ranges('00-04, 06-11, 14, 16-19, 1B, 1D-21, 27-2D, 2F-32, 34-3E, 44, 48, 60-6F, 80, 8C-8F, B0, B7-B9, D0-D5, D8, DA, E0, E9-EA, EC-ED, F2, F7')),
	0x90: _make_subop_sizes(_expand_subop_ranges('00-24, 28-29, 2C, 30-3A, 3C-3D, 3F-4A, 4C-4D, 50-51, 53-5D, 60-61, 64-66, 70-71, 74-76, 78-7A, 80-89, 90-92, 94-A7, AF-B1, B4-BA, BC-C8, CA, CC-D1, D4-E1, E4-E5, E8-E9, F0-F8, FA-FD')),
	0x91: _make_subop_sizes(_expand_subop_ranges('00, 03-06, 09-1F, 31, 33, 36-38, 3D-4A, 55, 60-61, 64-69, 70-71, 73-76, 78-7F, 88-8E, 90-9F, B8, BA-BD, BF, DB, F0-F3, F7-FB')),
	0x92: _make_subop_sizes(_expand_subop_ranges('00-01, 0E-1F, 31, 3D, 88-8A, 8C-8E, 90-91, 94-95, 97-99, 9B-9F, F0-F2, F4-F6')),
	0xA0: _make_subop_sizes(_expand_subop_ranges('00, 08-09, 10-12, 14-19, 1C, 20-28, 2C, 2F, 80-81, 84-86, C0')),
	0xB0: _make_subop_sizes(_expand_subop_ranges('00, 02-06, 08, 10-12, 14-1C, 1E-2A, 60-63, 66-68, 6A, 6C-6D, 6F, 80-87, 8C, 8F, A0-A3, C0-C8, CF, F0')),
	0xC0: _make_subop_sizes(_expand_subop_ranges('00-01, 04-06, 08-0D, 0F-10, 18, 1A-1B, 1F-20, 24-25, 28-29, 2C-2D, 40-4F, C0-C3, F0')),
	0xD0: _make_subop_sizes(_expand_subop_ranges('00-01, 04-05, 10-12, 14-18, 20-23, 28, 2C-2D, 40-41, 60-6A, 70-72, 74-75, 78-7B, 80-81, 84, 87-88, 8A, 8C-8E, C0-C2, C4-C8')),
	0xE0: _make_subop_sizes(_expand_subop_ranges('00, 20, 3F-40, 80, 90-93, C0, C2')),
	0xFF: _make_subop_sizes([0xF0, 0xF1, 0xF8]),
}

def clear_offsets():
	offsets.clear()

def normalize_encoding(encoding):
	if not encoding:
		return 'cp932'
	return str(encoding).strip() or 'cp932'

def set_text_encoding(encoding):
	global current_text_encoding
	current_text_encoding = normalize_encoding(encoding)

def get_string(code, addr, *args):
	pos0 = addr + args[0]
	pos1 = code.find(b'\x00', pos0)
	raw = code[pos0:pos1]
	if any((x < 0x20 and x not in (0x09, 0x0A, 0x0D)) for x in raw):
		return '@hex:%s' % raw.hex()
	try:
		string = raw.decode(current_text_encoding)
	except UnicodeDecodeError:
		return '@hex:%s' % raw.hex()
	string = asdis.escape(string)
	return string
	
def get_offset(code, addr, *args):
	offset = addr + args[0]
	offsets.add(offset)
	return offset

def get_offset_from_base(base, rel):
	offset = base + rel
	offsets.add(offset)
	return offset

def get_op_entry(op):
	return ops.get(op)

def _parse_int_token(token):
	token = token.strip()
	if token.startswith('L-'):
		return -int(token[2:], 16)
	if token.startswith('L'):
		return int(token[1:], 16)
	if token.startswith('0x') or token.startswith('-0x'):
		return int(token, 16)
	return int(token)

def decode_sleb128(code, pos):
	result = 0
	shift = 0
	size = 0
	while True:
		byte = code[pos + size]
		size += 1
		result |= (byte & 0x7F) << shift
		shift += 7
		if (byte & 0x80) == 0:
			break
	if byte & 0x40:
		result |= - (1 << shift)
	return result, size

def encode_sleb128(value):
	out = bytearray()
	more = True
	while more:
		byte = value & 0x7F
		value >>= 7
		sign_bit = byte & 0x40
		if (value == 0 and sign_bit == 0) or (value == -1 and sign_bit != 0):
			more = False
		else:
			byte |= 0x80
		out.append(byte & 0xFF)
	return bytes(out)

def decode_typed_sleb128(code, pos):
	value, size = decode_sleb128(code, pos)
	return value & 0x3, value >> 2, size

def encode_typed_sleb128(type_id, value):
	return encode_sleb128((value << 2) | (type_id & 0x3))

def _scan_sleb128_sequence(code, pos, count):
	size = 0
	for _ in range(count):
		_, n = decode_sleb128(code, pos + size)
		size += n
	return size

def _validate_sleb128_sequence(raw, count):
	pos = 0
	for _ in range(count):
		if pos >= len(raw):
			raise Exception('truncated sleb128 sequence')
		_, n = decode_sleb128(raw, pos)
		pos += n
	if pos != len(raw):
		raise Exception('unexpected trailing bytes in sleb128 sequence')
	return pos

def _format_list(values, value_formatter=str):
	return '[%s]' % ', '.join(value_formatter(x) for x in values)

def _decode_sleb128_values(raw, count):
	values = []
	pos = 0
	for _ in range(count):
		value, n = decode_sleb128(raw, pos)
		values.append(value)
		pos += n
	return values

def _decode_multi_offsets(raw):
	return [x[0] for x in struct.iter_unpack('<H', raw)]

def _parse_list_token(token):
	value = token.strip()
	if not value.startswith('[') or not value.endswith(']'):
		raise Exception('invalid list token %s' % token)
	body = value[1:-1].strip()
	if not body:
		return []
	return [_parse_int_token(item.strip()) for item in body.split(',')]

def _encode_sleb128_values(values):
	out = bytearray()
	for value in values:
		out.extend(encode_sleb128(value))
	return bytes(out)

def _encode_multi_offsets(values):
	out = bytearray()
	for value in values:
		out.extend(struct.pack('<H', value & 0xFFFF))
	return bytes(out)

def decode_var_instr(op, code, addr, pos):
	if op in subop_group_ops:
		sub = code[pos]
		extra_size = _get_subop_size(op, sub)
		name = _get_subop_group_name(op)
		if extra_size == 0:
			return '%s(%#04x)' % (name, sub), 1
		raw = code[pos+1:pos+1+extra_size]
		if len(raw) != extra_size:
			raise Exception('truncated sub-op payload op %02x sub %02x @ offset %05x' % (op, sub, addr))
		return '%s(%#04x, "%s")' % (name, sub, raw.hex()), 1 + extra_size
	if op == 0x03:
		mode = struct.unpack('b', code[pos:pos+1])[0]
		if mode >= 0:
			count = mode + 1
			payload_size = _scan_sleb128_sequence(code, pos + 1, count)
			raw = code[pos + 1:pos + 1 + payload_size]
			values = _decode_sleb128_values(raw, count)
			return 'pushx(%#x, %s)' % (mode & 0xFF, _format_list(values)), 1 + payload_size
		if (mode & 0x7C) != 0:
			return 'pushx(%#x)' % (mode & 0xFF), 1
		width = mode & 0x3
		if width == 0:
			value = struct.unpack('b', code[pos + 1:pos + 2])[0]
			return 'pushx(%#x, %d)' % (mode & 0xFF, value), 2
		if width == 1:
			value, = struct.unpack('<h', code[pos + 1:pos + 3])
			return 'pushx(%#x, %d)' % (mode & 0xFF, value), 3
		if width == 2:
			value, = struct.unpack('<i', code[pos + 1:pos + 5])
			return 'pushx(%#x, %d)' % (mode & 0xFF, value), 5
		value, = struct.unpack('<q', code[pos + 1:pos + 9])
		return 'pushx(%#x, %d)' % (mode & 0xFF, value), 9
	if op == 0x0D:
		type_id, imm, n = decode_typed_sleb128(code, pos)
		return 'store_typed_imm(%#x, %d)' % (type_id, imm), n
	if op == 0x0E:
		rel, = struct.unpack('<H', code[pos:pos+2])
		type_id, imm, n = decode_typed_sleb128(code, pos + 2)
		return 'store_rel_typed_imm(%#x, %#x, %d)' % (rel, type_id, imm), 2 + n
	if op == 0x12:
		imm, n = decode_sleb128(code, pos)
		return 'add_base_imm(%d)' % imm, n
	if op == 0x15:
		flag = code[pos]
		if flag & 0x08:
			rel, = struct.unpack('<h', code[pos+1:pos+3])
			dst = get_offset_from_base(addr + 3, rel)
			return 'jc(%#x, L%05x)' % (flag, dst), 3
		return 'jc(%#x)' % flag, 1
	if op == 0x1A:
		t, = struct.unpack('<H', code[pos:pos+2])
		imm, n = decode_sleb128(code, pos + 2)
		return 'load_base_typed_add(%#x, %d)' % (t, imm), 2 + n
	if op == 0x1B:
		t, = struct.unpack('<H', code[pos:pos+2])
		imm, n = decode_sleb128(code, pos + 2)
		return 'ret2(%#x, %d)' % (t, imm), 2 + n
	if op == 0x1F:
		imm, n = decode_sleb128(code, pos)
		return 'load_offset_typed(%d)' % imm, n
	if op == 0x2C:
		imm, n = decode_sleb128(code, pos)
		return 'add_imm(%d)' % imm, n
	if op == 0x2D:
		imm, n = decode_sleb128(code, pos)
		return 'mul_imm(%d)' % imm, n
	if op == 0x2E:
		imm, n = decode_sleb128(code, pos)
		return 'mad_imm(%d)' % imm, n
	if op == 0x2F:
		imm, n = decode_sleb128(code, pos)
		return 'div_imm(%d)' % imm, n
	if op == 0x36:
		flag = code[pos]
		imm, n = decode_sleb128(code, pos + 1)
		return 'cmp_imm(%#x, %d)' % (flag, imm), 1 + n
	if op == 0x37:
		flag = code[pos]
		rel, = struct.unpack('<h', code[pos+1:pos+3])
		imm, n = decode_sleb128(code, pos + 3)
		dst = get_offset_from_base(addr + 3, rel)
		return 'cmp_imm_jc(%#x, L%05x, %d)' % (flag, dst, imm), 3 + n
	if op == 0x3B:
		flag = code[pos]
		rel, = struct.unpack('<h', code[pos+1:pos+3])
		dst = get_offset_from_base(addr + 3, rel)
		return 'jcmp(%#x, L%05x)' % (flag, dst), 3
	if op == 0x3F:
		flag = code[pos]
		imm, n = decode_sleb128(code, pos + 1)
		return 'cmp_store_imm(%#x, %d)' % (flag, imm), 1 + n
	if op == 0xD5:
		rel, = struct.unpack('<H', code[pos:pos+2])
		imm, n = decode_sleb128(code, pos + 2)
		return 'load_code_ref_add_imm(%#x, %d)' % (rel, imm), 2 + n
	if op == 0xD6:
		rel, = struct.unpack('<H', code[pos:pos+2])
		type_id, imm, n = decode_typed_sleb128(code, pos + 2)
		return 'load_code_ref_indexed_typed(%#x, %#x, %d)' % (rel, type_id, imm), 2 + n
	if op == 0xD7:
		rel0, rel1 = struct.unpack('<HH', code[pos:pos+4])
		type_id, imm, n = decode_typed_sleb128(code, pos + 4)
		return 'store_code_ref_indexed_typed(%#x, %#x, %#x, %d)' % (rel0, rel1, type_id, imm), 4 + n
	if op == 0xD8:
		rel, = struct.unpack('<H', code[pos:pos+2])
		imm, n = decode_sleb128(code, pos + 2)
		return 'load_code_ref_scaled_add(%#x, %d)' % (rel, imm), 2 + n
	if op == 0xDA:
		flag = code[pos]
		rel, = struct.unpack('<H', code[pos+1:pos+3])
		imm, n = decode_sleb128(code, pos + 3)
		return 'cmp_code_ref_imm(%#x, %#x, %d)' % (flag, rel, imm), 3 + n
	if op == 0xDB:
		flag = code[pos]
		rel, = struct.unpack('<H', code[pos+1:pos+3])
		type_id, imm0, n0 = decode_typed_sleb128(code, pos + 3)
		imm1, n1 = decode_sleb128(code, pos + 3 + n0)
		return 'cmp_code_ref_indexed_imm(%#x, %#x, %#x, %d, %d)' % (flag, rel, type_id, imm0, imm1), 3 + n0 + n1
	if op == 0xDC:
		flag = code[pos]
		rel, ref = struct.unpack('<hH', code[pos+1:pos+5])
		imm, n = decode_sleb128(code, pos + 5)
		dst = get_offset_from_base(addr + 5 + n, rel)
		return 'jc_cmp_code_ref_imm(%#x, L%05x, %#x, %d)' % (flag, dst, ref, imm), 5 + n
	if op == 0xDD:
		flag = code[pos]
		rel, ref = struct.unpack('<hH', code[pos+1:pos+5])
		type_id, imm0, n0 = decode_typed_sleb128(code, pos + 5)
		imm1, n1 = decode_sleb128(code, pos + 5 + n0)
		dst = get_offset_from_base(addr + 5 + n0 + n1, rel)
		return 'jc_cmp_code_ref_indexed_imm(%#x, L%05x, %#x, %#x, %d, %d)' % (flag, dst, ref, type_id, imm0, imm1), 5 + n0 + n1
	if op == 0xDE:
		rel, ref = struct.unpack('<hH', code[pos:pos+4])
		dst = get_offset_from_base(addr + 4, rel)
		return 'jc_test_code_ref(L%05x, %#x)' % (dst, ref), 4
	if op == 0xDF:
		rel, ref = struct.unpack('<hH', code[pos:pos+4])
		type_id, imm, n = decode_typed_sleb128(code, pos + 4)
		dst = get_offset_from_base(addr + 4 + n, rel)
		return 'jc_test_code_ref_indexed(L%05x, %#x, %#x, %d)' % (dst, ref, type_id, imm), 4 + n
	if op == 0xEA:
		rel0, rel1 = struct.unpack('<HH', code[pos:pos+4])
		imm, n = decode_sleb128(code, pos + 4)
		return 'store_indirect_imm(%#x, %#x, %d)' % (rel0, rel1, imm), 4 + n
	if op == 0xEC:
		imm, n = decode_sleb128(code, pos)
		return 'memcpy_stack(%d)' % imm, n
	if op == 0xED:
		rel, = struct.unpack('<H', code[pos:pos+2])
		imm, n = decode_sleb128(code, pos + 2)
		return 'memcpy_rel_stack(%#x, %d)' % (rel, imm), 2 + n
	if op == 0xE2 or op == 0xE3:
		count = code[pos] + 1
		raw = code[pos + 1:pos + 1 + count * 2]
		if len(raw) != count * 2:
			raise Exception('truncated multi-offset payload op %02x @ offset %05x' % (op, addr))
		name = 'store_multi' if op == 0xE2 else 'load_multi'
		offsets = _decode_multi_offsets(raw)
		return '%s(%s)' % (name, _format_list(offsets, lambda x: '%#x' % x)), 1 + count * 2
	if op == 0xE4:
		rel, = struct.unpack('<H', code[pos:pos+2])
		type_id, imm, n = decode_typed_sleb128(code, pos + 2)
		return 'load_rel_add(%#x, %#x, %d)' % (rel, type_id, imm), 2 + n
	if op == 0xE5:
		rel, = struct.unpack('<H', code[pos:pos+2])
		type_id, imm, n = decode_typed_sleb128(code, pos + 2)
		return 'load_indexed(%#x, %#x, %d)' % (rel, type_id, imm), 2 + n
	if op == 0xE6:
		rel, = struct.unpack('<H', code[pos:pos+2])
		type_id, imm, n = decode_typed_sleb128(code, pos + 2)
		return 'store_rel_add(%#x, %#x, %d)' % (rel, type_id, imm), 2 + n
	if op == 0xE7:
		rel, = struct.unpack('<H', code[pos:pos+2])
		type_id, imm, n = decode_typed_sleb128(code, pos + 2)
		return 'store_indexed(%#x, %#x, %d)' % (rel, type_id, imm), 2 + n
	if op == 0xF0:
		ptr, rel = struct.unpack('<IH', code[pos:pos+6])
		imm, n = decode_sleb128(code, pos + 6)
		return 'store_ptr_add(%#x, %#x, %d)' % (ptr, rel, imm), 6 + n
	if op == 0xF1:
		rel0, rel1 = struct.unpack('<HH', code[pos:pos+4])
		imm, n = decode_sleb128(code, pos + 4)
		return 'store_rel_add32(%#x, %#x, %d)' % (rel0, rel1, imm), 4 + n
	if op == 0xF2:
		rel0, rel1, rel2 = struct.unpack('<HHH', code[pos:pos+6])
		imm, n = decode_sleb128(code, pos + 6)
		return 'store_indirect_add32(%#x, %#x, %#x, %d)' % (rel0, rel1, rel2, imm), 6 + n
	raise Exception('unknown variable instruction op %02x @ offset %05x' % (op, addr))

def get_instr_size(op, args):
	if op in subop_group_ops:
		if len(args) < 1 or len(args) > 2:
			raise Exception('invalid arg count for sub-op group')
		sub = _parse_int_token(args[0]) & 0xFF
		extra_size = _get_subop_size(op, sub)
		if extra_size == 0:
			if len(args) != 1:
				raise Exception('unexpected payload for sub-op group')
			return 2
		if len(args) != 2:
			raise Exception('missing payload for sub-op group')
		raw = _parse_hex_blob_token(args[1])
		if len(raw) != extra_size:
			raise Exception('invalid payload size for sub-op group %02x sub %02x: got %d expect %d' % (op, sub, len(raw), extra_size))
		return 2 + extra_size
	if op == 0x03:
		if len(args) not in (1, 2, 3):
			raise Exception('invalid arg count for pushx')
		mode = _parse_int_token(args[0]) & 0xFF
		smode = struct.unpack('b', struct.pack('B', mode))[0]
		if smode >= 0:
			if len(args) not in (2, 3):
				raise Exception('missing payload for pushx multi form')
			if args[1].strip().startswith('['):
				values = _parse_list_token(args[1])
				if len(values) != smode + 1:
					raise Exception('invalid pushx multi value count: got %d expect %d' % (len(values), smode + 1))
				raw = _encode_sleb128_values(values)
			else:
				raw = _parse_hex_blob_token(args[1])
			_validate_sleb128_sequence(raw, smode + 1)
			return 2 + len(raw)
		if (mode & 0x7C) != 0:
			if len(args) != 1:
				raise Exception('unexpected payload for pushx reserved form')
			return 2
		if len(args) != 2:
			raise Exception('missing immediate for pushx scalar form')
		width = mode & 0x3
		return 2 + (1 if width == 0 else 2 if width == 1 else 4 if width == 2 else 8)
	if op == 0x0D:
		if len(args) != 2:
			raise Exception('invalid arg count for store_typed_imm')
		type_id = _parse_int_token(args[0]) & 0x3
		imm = _parse_int_token(args[1])
		return 1 + len(encode_typed_sleb128(type_id, imm))
	if op == 0x0E:
		if len(args) != 3:
			raise Exception('invalid arg count for store_rel_typed_imm')
		type_id = _parse_int_token(args[1]) & 0x3
		imm = _parse_int_token(args[2])
		return 1 + 2 + len(encode_typed_sleb128(type_id, imm))
	if op == 0x15:
		if len(args) == 1:
			return 2
		if len(args) == 2:
			return 4
		raise Exception('invalid arg count for jc')
	if op == 0x1A:
		if len(args) != 2:
			raise Exception('invalid arg count for load_base_typed_add')
		return 1 + 2 + len(encode_sleb128(_parse_int_token(args[1])))
	if op in (0x12, 0x1F, 0x2C, 0x2D, 0x2E, 0x2F):
		if len(args) != 1:
			raise Exception('invalid arg count for variable op')
		return 1 + len(encode_sleb128(_parse_int_token(args[0])))
	if op == 0x36:
		if len(args) != 2:
			raise Exception('invalid arg count for cmp_imm')
		return 2 + len(encode_sleb128(_parse_int_token(args[1])))
	if op == 0x37:
		if len(args) != 3:
			raise Exception('invalid arg count for cmp_imm_jc')
		return 4 + len(encode_sleb128(_parse_int_token(args[2])))
	if op == 0x1B:
		if len(args) != 2:
			raise Exception('invalid arg count for ret2')
		return 1 + 2 + len(encode_sleb128(_parse_int_token(args[1])))
	if op == 0x3B:
		if len(args) != 2:
			raise Exception('invalid arg count for jcmp')
		return 4
	if op == 0x3F:
		if len(args) != 2:
			raise Exception('invalid arg count for cmp_store_imm')
		return 2 + len(encode_sleb128(_parse_int_token(args[1])))
	if op == 0xD5:
		if len(args) != 2:
			raise Exception('invalid arg count for load_code_ref_add_imm')
		return 1 + 2 + len(encode_sleb128(_parse_int_token(args[1])))
	if op == 0xD6:
		if len(args) != 3:
			raise Exception('invalid arg count for load_code_ref_indexed_typed')
		type_id = _parse_int_token(args[1]) & 0x3
		imm = _parse_int_token(args[2])
		return 1 + 2 + len(encode_typed_sleb128(type_id, imm))
	if op == 0xD7:
		if len(args) != 4:
			raise Exception('invalid arg count for store_code_ref_indexed_typed')
		type_id = _parse_int_token(args[2]) & 0x3
		imm = _parse_int_token(args[3])
		return 1 + 2 + 2 + len(encode_typed_sleb128(type_id, imm))
	if op == 0xD8:
		if len(args) != 2:
			raise Exception('invalid arg count for load_code_ref_scaled_add')
		return 1 + 2 + len(encode_sleb128(_parse_int_token(args[1])))
	if op == 0xDA:
		if len(args) != 3:
			raise Exception('invalid arg count for cmp_code_ref_imm')
		return 1 + 1 + 2 + len(encode_sleb128(_parse_int_token(args[2])))
	if op == 0xDB:
		if len(args) != 5:
			raise Exception('invalid arg count for cmp_code_ref_indexed_imm')
		type_id = _parse_int_token(args[2]) & 0x3
		imm0 = _parse_int_token(args[3])
		imm1 = _parse_int_token(args[4])
		return 1 + 1 + 2 + len(encode_typed_sleb128(type_id, imm0)) + len(encode_sleb128(imm1))
	if op == 0xDC:
		if len(args) != 4:
			raise Exception('invalid arg count for jc_cmp_code_ref_imm')
		return 1 + 1 + 2 + 2 + len(encode_sleb128(_parse_int_token(args[3])))
	if op == 0xDD:
		if len(args) != 6:
			raise Exception('invalid arg count for jc_cmp_code_ref_indexed_imm')
		type_id = _parse_int_token(args[3]) & 0x3
		imm0 = _parse_int_token(args[4])
		imm1 = _parse_int_token(args[5])
		return 1 + 1 + 2 + 2 + len(encode_typed_sleb128(type_id, imm0)) + len(encode_sleb128(imm1))
	if op == 0xDE:
		if len(args) != 2:
			raise Exception('invalid arg count for jc_test_code_ref')
		return 5
	if op == 0xDF:
		if len(args) != 4:
			raise Exception('invalid arg count for jc_test_code_ref_indexed')
		type_id = _parse_int_token(args[2]) & 0x3
		imm = _parse_int_token(args[3])
		return 1 + 2 + 2 + len(encode_typed_sleb128(type_id, imm))
	if op == 0xEA:
		if len(args) != 3:
			raise Exception('invalid arg count for store_indirect_imm')
		return 1 + 4 + len(encode_sleb128(_parse_int_token(args[2])))
	if op == 0xEC:
		if len(args) != 1:
			raise Exception('invalid arg count for memcpy_stack')
		return 1 + len(encode_sleb128(_parse_int_token(args[0])))
	if op == 0xED:
		if len(args) != 2:
			raise Exception('invalid arg count for memcpy_rel_stack')
		return 1 + 2 + len(encode_sleb128(_parse_int_token(args[1])))
	if op == 0xE2 or op == 0xE3:
		if len(args) not in (1, 2):
			raise Exception('invalid arg count for multi-offset op')
		if args[0].strip().startswith('['):
			values = _parse_list_token(args[0])
			raw = _encode_multi_offsets(values)
		else:
			raw = _parse_hex_blob_token(args[0])
		if len(raw) == 0 or len(raw) % 2 != 0:
			raise Exception('invalid multi-offset payload')
		return 2 + len(raw)
	if op in (0xE4, 0xE5, 0xE6, 0xE7):
		if len(args) != 3:
			raise Exception('invalid arg count for typed indexed op')
		type_id = _parse_int_token(args[1]) & 0x3
		imm = _parse_int_token(args[2])
		return 1 + 2 + len(encode_typed_sleb128(type_id, imm))
	if op == 0xF0:
		if len(args) != 3:
			raise Exception('invalid arg count for store_ptr_add')
		return 1 + 4 + 2 + len(encode_sleb128(_parse_int_token(args[2])))
	if op == 0xF1:
		if len(args) != 3:
			raise Exception('invalid arg count for store_rel_add32')
		return 1 + 2 + 2 + len(encode_sleb128(_parse_int_token(args[2])))
	if op == 0xF2:
		if len(args) != 4:
			raise Exception('invalid arg count for store_indirect_add32')
		return 1 + 2 + 2 + 2 + len(encode_sleb128(_parse_int_token(args[3])))
	entry = get_op_entry(op)
	if entry is None:
		raise Exception('unknown instruction op %02x' % op)
	return struct.calcsize(entry[0]) + 1

def _resolve_arg_value(arg, symbols):
	if arg in symbols:
		return symbols[arg]
	return _parse_int_token(arg)

def _get_subop_group_name(op):
	fcn, = re_fcn.match(ops[op][1]).groups()
	return fcn

def _get_subop_size(op, sub):
	return subop_size_table.get(op, {}).get(sub, 0)

def _parse_hex_blob_token(token):
	value = token.strip()
	if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
		value = value[1:-1]
	if value.startswith('0x') or value.startswith('0X'):
		value = value[2:]
	if len(value) % 2 != 0:
		raise Exception('invalid sub-op hex blob %s' % token)
	if value:
		return bytes.fromhex(value)
	return b''

def encode_var_instr(op, args, pos, symbols):
	if op in subop_group_ops:
		sub = _parse_int_token(args[0]) & 0xFF
		extra_size = _get_subop_size(op, sub)
		if extra_size == 0:
			if len(args) != 1:
				raise Exception('unexpected payload for sub-op group')
			return struct.pack('BB', op, sub)
		if len(args) != 2:
			raise Exception('missing payload for sub-op group')
		raw = _parse_hex_blob_token(args[1])
		if len(raw) != extra_size:
			raise Exception('invalid payload size for sub-op group %02x sub %02x: got %d expect %d' % (op, sub, len(raw), extra_size))
		return struct.pack('BB', op, sub) + raw
	if op == 0x03:
		mode = _parse_int_token(args[0]) & 0xFF
		smode = struct.unpack('b', struct.pack('B', mode))[0]
		if smode >= 0:
			if args[1].strip().startswith('['):
				values = _parse_list_token(args[1])
				if len(values) != smode + 1:
					raise Exception('invalid pushx multi value count: got %d expect %d' % (len(values), smode + 1))
				raw = _encode_sleb128_values(values)
			else:
				raw = _parse_hex_blob_token(args[1])
			_validate_sleb128_sequence(raw, smode + 1)
			return struct.pack('BB', op, mode) + raw
		if (mode & 0x7C) != 0:
			return struct.pack('BB', op, mode)
		value = _parse_int_token(args[1])
		width = mode & 0x3
		if width == 0:
			return struct.pack('<BBb', op, mode, value)
		if width == 1:
			return struct.pack('<BBh', op, mode, value)
		if width == 2:
			return struct.pack('<BBi', op, mode, value)
		return struct.pack('<BBq', op, mode, value)
	if op == 0x0D:
		type_id = _parse_int_token(args[0]) & 0x3
		imm = _parse_int_token(args[1])
		return struct.pack('B', op) + encode_typed_sleb128(type_id, imm)
	if op == 0x0E:
		rel = _parse_int_token(args[0]) & 0xFFFF
		type_id = _parse_int_token(args[1]) & 0x3
		imm = _parse_int_token(args[2])
		return struct.pack('<BH', op, rel) + encode_typed_sleb128(type_id, imm)
	if op == 0x12:
		return struct.pack('B', op) + encode_sleb128(_parse_int_token(args[0]))
	if op == 0x15:
		if len(args) == 1:
			flag = _parse_int_token(args[0]) & 0xFF
			return struct.pack('BB', op, flag)
		flag = _parse_int_token(args[0]) & 0xFF
		target = _resolve_arg_value(args[1], symbols)
		rel = target - (pos + 3)
		return struct.pack('<BBh', op, flag, rel)
	if op == 0x1A:
		t = _parse_int_token(args[0]) & 0xFFFF
		imm = _parse_int_token(args[1])
		return struct.pack('<BH', op, t) + encode_sleb128(imm)
	if op == 0x1B:
		t = _parse_int_token(args[0]) & 0xFFFF
		imm = _parse_int_token(args[1])
		return struct.pack('<BH', op, t) + encode_sleb128(imm)
	if op == 0x1F:
		return struct.pack('B', op) + encode_sleb128(_parse_int_token(args[0]))
	if op == 0x2C:
		return struct.pack('B', op) + encode_sleb128(_parse_int_token(args[0]))
	if op == 0x2D:
		return struct.pack('B', op) + encode_sleb128(_parse_int_token(args[0]))
	if op == 0x2E:
		return struct.pack('B', op) + encode_sleb128(_parse_int_token(args[0]))
	if op == 0x2F:
		return struct.pack('B', op) + encode_sleb128(_parse_int_token(args[0]))
	if op == 0x36:
		flag = _parse_int_token(args[0]) & 0xFF
		imm = _parse_int_token(args[1])
		return struct.pack('BB', op, flag) + encode_sleb128(imm)
	if op == 0x37:
		flag = _parse_int_token(args[0]) & 0xFF
		target = _resolve_arg_value(args[1], symbols)
		imm = _parse_int_token(args[2])
		rel = target - (pos + 3)
		return struct.pack('<BBh', op, flag, rel) + encode_sleb128(imm)
	if op == 0x3B:
		flag = _parse_int_token(args[0]) & 0xFF
		target = _resolve_arg_value(args[1], symbols)
		rel = target - (pos + 3)
		return struct.pack('<BBh', op, flag, rel)
	if op == 0x3F:
		flag = _parse_int_token(args[0]) & 0xFF
		imm = _parse_int_token(args[1])
		return struct.pack('BB', op, flag) + encode_sleb128(imm)
	if op == 0xD5:
		rel = _parse_int_token(args[0]) & 0xFFFF
		imm = _parse_int_token(args[1])
		return struct.pack('<BH', op, rel) + encode_sleb128(imm)
	if op == 0xD6:
		rel = _parse_int_token(args[0]) & 0xFFFF
		type_id = _parse_int_token(args[1]) & 0x3
		imm = _parse_int_token(args[2])
		return struct.pack('<BH', op, rel) + encode_typed_sleb128(type_id, imm)
	if op == 0xD7:
		rel0 = _parse_int_token(args[0]) & 0xFFFF
		rel1 = _parse_int_token(args[1]) & 0xFFFF
		type_id = _parse_int_token(args[2]) & 0x3
		imm = _parse_int_token(args[3])
		return struct.pack('<BHH', op, rel0, rel1) + encode_typed_sleb128(type_id, imm)
	if op == 0xD8:
		rel = _parse_int_token(args[0]) & 0xFFFF
		imm = _parse_int_token(args[1])
		return struct.pack('<BH', op, rel) + encode_sleb128(imm)
	if op == 0xDA:
		flag = _parse_int_token(args[0]) & 0xFF
		rel = _parse_int_token(args[1]) & 0xFFFF
		imm = _parse_int_token(args[2])
		return struct.pack('<BBH', op, flag, rel) + encode_sleb128(imm)
	if op == 0xDB:
		flag = _parse_int_token(args[0]) & 0xFF
		rel = _parse_int_token(args[1]) & 0xFFFF
		type_id = _parse_int_token(args[2]) & 0x3
		imm0 = _parse_int_token(args[3])
		imm1 = _parse_int_token(args[4])
		return struct.pack('<BBH', op, flag, rel) + encode_typed_sleb128(type_id, imm0) + encode_sleb128(imm1)
	if op == 0xDC:
		flag = _parse_int_token(args[0]) & 0xFF
		target = _resolve_arg_value(args[1], symbols)
		ref = _parse_int_token(args[2]) & 0xFFFF
		imm = _parse_int_token(args[3])
		imm_raw = encode_sleb128(imm)
		rel = target - (pos + 5 + len(imm_raw))
		return struct.pack('<BBhH', op, flag, rel, ref) + imm_raw
	if op == 0xDD:
		flag = _parse_int_token(args[0]) & 0xFF
		target = _resolve_arg_value(args[1], symbols)
		ref = _parse_int_token(args[2]) & 0xFFFF
		type_id = _parse_int_token(args[3]) & 0x3
		imm0 = _parse_int_token(args[4])
		imm1 = _parse_int_token(args[5])
		imm0_raw = encode_typed_sleb128(type_id, imm0)
		imm1_raw = encode_sleb128(imm1)
		rel = target - (pos + 5 + len(imm0_raw) + len(imm1_raw))
		return struct.pack('<BBhH', op, flag, rel, ref) + imm0_raw + imm1_raw
	if op == 0xDE:
		target = _resolve_arg_value(args[0], symbols)
		ref = _parse_int_token(args[1]) & 0xFFFF
		rel = target - (pos + 4)
		return struct.pack('<BhH', op, rel, ref)
	if op == 0xDF:
		target = _resolve_arg_value(args[0], symbols)
		ref = _parse_int_token(args[1]) & 0xFFFF
		type_id = _parse_int_token(args[2]) & 0x3
		imm = _parse_int_token(args[3])
		imm_raw = encode_typed_sleb128(type_id, imm)
		rel = target - (pos + 4 + len(imm_raw))
		return struct.pack('<BhH', op, rel, ref) + imm_raw
	if op == 0xEA:
		rel0 = _parse_int_token(args[0]) & 0xFFFF
		rel1 = _parse_int_token(args[1]) & 0xFFFF
		imm = _parse_int_token(args[2])
		return struct.pack('<BHH', op, rel0, rel1) + encode_sleb128(imm)
	if op == 0xEC:
		return struct.pack('B', op) + encode_sleb128(_parse_int_token(args[0]))
	if op == 0xED:
		rel = _parse_int_token(args[0]) & 0xFFFF
		imm = _parse_int_token(args[1])
		return struct.pack('<BH', op, rel) + encode_sleb128(imm)
	if op == 0xE2 or op == 0xE3:
		if args[0].strip().startswith('['):
			raw = _encode_multi_offsets(_parse_list_token(args[0]))
		else:
			raw = _parse_hex_blob_token(args[0])
		if len(raw) == 0 or len(raw) % 2 != 0:
			raise Exception('invalid multi-offset payload')
		count = len(raw) // 2
		return struct.pack('BB', op, count - 1) + raw
	if op in (0xE4, 0xE5, 0xE6, 0xE7):
		rel = _parse_int_token(args[0]) & 0xFFFF
		type_id = _parse_int_token(args[1]) & 0x3
		imm = _parse_int_token(args[2])
		return struct.pack('<BH', op, rel) + encode_typed_sleb128(type_id, imm)
	if op == 0xF0:
		ptr = _parse_int_token(args[0]) & 0xFFFFFFFF
		rel = _parse_int_token(args[1]) & 0xFFFF
		imm = _parse_int_token(args[2])
		return struct.pack('<BIH', op, ptr, rel) + encode_sleb128(imm)
	if op == 0xF1:
		rel0 = _parse_int_token(args[0]) & 0xFFFF
		rel1 = _parse_int_token(args[1]) & 0xFFFF
		imm = _parse_int_token(args[2])
		return struct.pack('<BHH', op, rel0, rel1) + encode_sleb128(imm)
	if op == 0xF2:
		rel0 = _parse_int_token(args[0]) & 0xFFFF
		rel1 = _parse_int_token(args[1]) & 0xFFFF
		rel2 = _parse_int_token(args[2]) & 0xFFFF
		imm = _parse_int_token(args[3])
		return struct.pack('<BHHH', op, rel0, rel1, rel2) + encode_sleb128(imm)
	raise Exception('unknown variable instruction op %02x @ offset %05x' % (op, pos))

var_ops = {0x03, 0x0D, 0x0E, 0x12, 0x15, 0x1A, 0x1B, 0x1F, 0x2C, 0x2D, 0x2E, 0x2F, 0x36, 0x37, 0x3B, 0x3F, 0xD5, 0xD6, 0xD7, 0xD8, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xEA, 0xEC, 0xED, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xF0, 0xF1, 0xF2} | subop_group_ops

def is_var_op(op):
	return op in var_ops

ops = {
0x00: ('b', 'push_byte(%#x)', None), # 压栈8位立即数
0x01: ('<h', 'push_word(%#x)', None), # 压栈16位立即数
0x02: ('<i', 'push_dword(%#x)', None), # 压栈32位立即数
0x03: ('', 'pushx(%#x)', None), # 扩展立即数/多立即数压栈

0x04: ('<h', 'push_base_offset(%#x)', None), # 压栈base相对地址
0x05: ('<h', 'push_string("%s")', get_string), # 压栈字符串常量
0x06: ('<h', 'push_offset(L%05x)', get_offset), # 压栈代码标签地址

0x08: ('b', 'load(%#x)', None), # 读取局部/寄存槽值
0x09: ('b', 'move(%#x)', None), # 写入局部/寄存槽值
0x0A: ('b', 'move_arg(%#x)', None), # 写入参数区槽位
0x0B: ('b', 'read_data(%#x)', None), # 读取数据段/全局槽
0x0C: ('BB', 'copystack(%#x, %#x)', None), # 栈区块复制
0x0D: ('', 'store_typed_imm(%#x, %d)', None), # 按类型槽写立即数
0x0E: ('', 'store_rel_typed_imm(%#x, %#x, %d)', None), # 按相对槽与类型写立即数

0x10: ('', 'load_base()', None), # 读取base指针
0x11: ('', 'store_base()', None), # 写入base指针
0x12: ('', 'add_base_imm(%d)', None), # base按立即数偏移
0x13: ('<h', 'add_base_word(%d)', None), # base按16位立即数偏移
0x0F: ('<H', 'store_base_typed(%#x)', None), # 按类型槽写base

0x14: ('', 'jmp()', None), # 无条件跳转
0x15: ('', 'jc(%#x)', None), # 条件跳转
0x16: ('', 'call()', None), # 调用子程序
0x17: ('', 'ret()', None), # 函数返回
0x18: ('<I', 'load_typed_ptr(%#x)', None), # 读取类型化指针
0x19: ('<H', 'load_base_typed(%#x)', None), # 读取base类型槽
0x1A: ('', 'load_base_typed_add(%#x, %d)', None), # 读取base类型槽并加偏移
0x1B: ('', 'ret2(%#x, %d)', None), # 带类型与值返回
0x1C: ('<Hb', 'shift_base_typed(%#x, %d)', None), # base类型槽位移
0x1D: ('<H', 'mul_base_typed(%#x)', None), # base类型槽乘法
0x1E: ('<H', 'div_base_typed(%#x)', None), # base类型槽除法
0x1F: ('', 'load_offset_typed(%d)', None), # 读取偏移类型槽

0x20: ('', 'add()', None), # 加法
0x21: ('', 'sub()', None), # 减法
0x22: ('', 'mul()', None), # 乘法
0x23: ('', 'div()', None), # 除法
0x24: ('', 'mod()', None), # 取模
0x25: ('', 'and()', None), # 按位与
0x26: ('', 'or()', None), # 按位或
0x27: ('', 'xor()', None), # 按位异或
0x28: ('', 'not()', None), # 按位非
0x29: ('', 'shl()', None), # 左移
0x2A: ('', 'shr()', None), # 逻辑右移
0x2B: ('', 'sar()', None), # 算术右移
0x2C: ('', 'add_imm(%d)', None), # 立即数加法
0x2D: ('', 'mul_imm(%d)', None), # 立即数乘法
0x2E: ('', 'mad_imm(%d)', None), # 乘加运算
0x2F: ('', 'div_imm(%d)', None), # 立即数除法

0x30: ('', 'eq()', None), # 相等比较
0x31: ('', 'neq()', None), # 不等比较
0x32: ('', 'leq()', None), # 小于等于比较
0x33: ('', 'geq()', None), # 大于等于比较
0x34: ('', 'lt()', None), # 小于比较
0x35: ('', 'gt()', None), # 大于比较
0x36: ('', 'cmp_imm(%#x, %d)', None), # 与立即数比较
0x37: ('', 'cmp_imm_jc(%#x, L%05x, %d)', None), # 与立即数比较后条件跳转

0x38: ('', 'bool_and()', None), # 逻辑与
0x39: ('', 'bool_or()', None), # 逻辑或
0x3A: ('', 'bool_zero()', None), # 判零
0x3B: ('', 'jcmp(%#x, L%05x)', None), # 比较后条件跳转
0x3C: ('b', 'shift_imm(%d)', None), # 立即数位移
0x3E: ('B', 'cmp_store(%#x)', None), # 按标志保存比较结果
0x3F: ('', 'cmp_store_imm(%#x, %d)', None), # 与立即数比较后保存结果

0x40: ('', 'ternary()', None), # 三目选择

0x42: ('', 'muldiv()', None), # 先乘后除
0x43: ('', 'arctan()', None), # 反正切
0x44: ('', 'veclen()', None), # 向量长度
0x45: ('', 'rotate3d()', None), # 三维旋转
0x46: ('', 'lerp()', None), # 线性插值
0x47: ('', 'lerpfix()', None), # 定点线性插值

0x48: ('', 'sin()', None), # 正弦
0x49: ('', 'cos()', None), # 余弦
0x50: ('', 'add64()', None), # 64位加法
0x51: ('', 'sub64()', None), # 64位减法
0x52: ('', 'mul64()', None), # 64位乘法
0x53: ('', 'div64()', None), # 64位除法
0x54: ('', 'mod64()', None), # 64位取模
0x55: ('', 'pow()', None), # 幂运算
0x56: ('', 'mul64high()', None), # 64位乘法高位
0x57: ('', 'divfix()', None), # 定点除法
0x58: ('', 'addpd()', None), # 点积/向量加
0x59: ('', 'subpd()', None), # 向量减
0x5A: ('', 'mulp()', None), # 向量乘
0x5B: ('', 'divvec4fix()', None), # vec4定点除
0x5D: ('', 'normalizevec()', None), # 向量归一化
0x5E: ('', 'scalevec4fix()', None), # vec4定点缩放
0x5F: ('', 'divvec4scalar()', None), # vec4标量除

0x60: ('', 'memcpy()', None), # 内存拷贝
0x61: ('', 'memclr()', None), # 内存清零
0x62: ('', 'memset()', None), # 内存填充
0x63: ('', 'memcmp()', None), # 内存比较
0x64: ('', 'memcpymulti()', None), # 批量内存拷贝
0x65: ('', 'memcmpmulti()', None), # 批量内存比较

0x66: ('', 'strstr()', None), # 字符串查找
0x67: ('', 'strreplace()', None), # 字符串替换
0x68: ('', 'strlen()', None), # 字符串长度
0x69: ('', 'streq()', None), # 字符串比较
0x6A: ('', 'strcpy()', None), # 字符串拷贝
0x6B: ('', 'concat()', None), # 字符串拼接
0x6C: ('', 'getchar()', None), # 取字符
0x6D: ('', 'tolower()', None), # 转小写
0x6E: ('', 'quote()', None), # 字符串加引号/转义
0x6F: ('', 'sprintf()', None), # 格式化字符串
0x70: ('', 'malloc()', None), # 分配内存
0x71: ('', 'free()', None), # 释放内存
0x73: ('', 'regsetinstalledfolder()', None), # 注册安装目录
0x74: ('', 'enablewritelog()', None), # 开关日志写入
0x75: ('', 'stralloc()', None), # 分配字符串缓冲

0x77: ('', 'getgamestate()', None), # 读取游戏状态
0x78: ('', 'confirm()', None), # 弹确认框
0x79: ('', 'message()', None), # 弹消息框
0x7A: ('', 'assert()', None), # 断言检查
0x7B: ('', 'dumpmem()', None), # 内存转储
0x7C: ('', 'listselectdlg()', None), # 列表选择对话框

0x7D: ('', 'drawhexdump()', None), # 显示十六进制转储

0x7E: ('', 'setclipboardtext()', None), # 设置剪贴板文本
0x7F: ('B', 'sys0(%#04x)', None), # 系统子操作组0
0x80: ('B', 'sys1(%#04x)', None), # 系统子操作组1
0x81: ('B', 'sys2(%#04x)', None), # 系统子操作组2

0x90: ('B', 'grp1(%#04x)', None), # 图形/通用子操作组1
0x91: ('B', 'grp2(%#04x)', None), # 图形/通用子操作组2
0x92: ('B', 'grp3(%#04x)', None), # 图形/通用子操作组3

0xA0: ('B', 'snd1(%#04x)', None), # 音频子操作组

0xB0: ('B', 'usr1(%#04x)', None), # 用户扩展组1

0xC0: ('B', 'usr2(%#04x)', None), # 用户扩展组2
0xD0: ('B', 'usr3(%#04x)', None), # 用户扩展组3
0xD4: ('<H', 'load_code_ref32(%#x)', None), # 读取当前 IP 回溯引用的 32 位常量
0xD5: ('', 'load_code_ref_add_imm(%#x, %d)', None), # 读取当前 IP 回溯引用并叠加 sleb128 立即数
0xD6: ('', 'load_code_ref_indexed_typed(%#x, %#x, %d)', None), # 读取 code-ref 指向表项的类型化索引值
0xD7: ('', 'store_code_ref_indexed_typed(%#x, %#x, %#x, %d)', None), # 向 code-ref 指向表项写入类型化索引值
0xD8: ('', 'load_code_ref_scaled_add(%#x, %d)', None), # 读取 code-ref 作为步长并与栈值做缩放加法
0xDA: ('', 'cmp_code_ref_imm(%#x, %#x, %d)', None), # 比较 code-ref 常量与 sleb128 立即数
0xDB: ('', 'cmp_code_ref_indexed_imm(%#x, %#x, %#x, %d, %d)', None), # 比较 code-ref 索引值与立即数
0xDC: ('', 'jc_cmp_code_ref_imm(%#x, L%05x, %#x, %d)', None), # 比较 code-ref 常量与立即数后条件跳转
0xDD: ('', 'jc_cmp_code_ref_indexed_imm(%#x, L%05x, %#x, %#x, %d, %d)', None), # 比较 code-ref 索引值与立即数后条件跳转
0xDE: ('', 'jc_test_code_ref(L%05x, %#x)', None), # 测试 code-ref 常量是否为零后条件跳转
0xDF: ('', 'jc_test_code_ref_indexed(L%05x, %#x, %#x, %d)', None), # 测试 code-ref 索引值是否为零后条件跳转
0xE0: ('B', 'usr4(%#04x)', None), # 用户扩展组4
0xE2: ('', 'store_multi("%s")', None), # 批量写入多个16位槽偏移
0xE3: ('', 'load_multi("%s")', None), # 批量读取多个16位槽偏移
0xE4: ('', 'load_rel_add(%#x, %#x, %d)', None), # 读取相对槽并附加类型化偏移
0xE5: ('', 'load_indexed(%#x, %#x, %d)', None), # 按相对槽索引读取
0xE6: ('', 'store_rel_add(%#x, %#x, %d)', None), # 写入相对槽并附加类型化偏移
0xE7: ('', 'store_indexed(%#x, %#x, %d)', None), # 按相对槽索引写入
0xE8: ('<H', 'select_store(%#x)', None), # 选择目标槽写入
0xE9: ('<HH', 'store_indirect(%#x, %#x)', None), # 间接槽写入
0xEA: ('', 'store_indirect_imm(%#x, %#x, %d)', None), # 间接槽写入并附加立即数
0xEC: ('', 'memcpy_stack(%d)', None), # 按长度复制栈区块
0xED: ('', 'memcpy_rel_stack(%#x, %d)', None), # 从相对槽复制到栈区块
0xEE: ('<h', 'call_base_rel(%d)', None), # 按base相对位移调用
0xEF: ('<I', 'call_ptr(%#x)', None), # 按绝对指针调用
0xF0: ('', 'store_ptr_add(%#x, %#x, %d)', None), # 指针目标写入并附加偏移
0xF1: ('', 'store_rel_add32(%#x, %#x, %d)', None), # 双相对槽写入并附加32位偏移
0xF2: ('', 'store_indirect_add32(%#x, %#x, %#x, %d)', None), # 三重间接写入并附加32位偏移
0xF4: ('<HIHh', 'store_affine_imm(%#x, %#x, %#x, %d)', None), # 仿射写入（绝对地址）
0xF5: ('<HHhHh', 'store_affine_rel(%#x, %#x, %d, %#x, %d)', None), # 仿射写入（相对槽）
0xF7: ('<HHh', 'load_affine_rel(%#x, %#x, %d)', None), # 仿射读取（相对槽）
0xF8: ('<IHh', 'load_affine_imm(%#x, %#x, %d)', None), # 仿射读取（绝对地址）
0xF9: ('<HhHh', 'load_affine_stack(%#x, %d, %#x, %d)', None), # 仿射读取（栈/相对槽）
0xFA: ('<IHh', 'load_ptr_indexed(%#x, %#x, %d)', None), # 指针索引读取
0xFB: ('<HHh', 'load_indirect_indexed(%#x, %#x, %d)', None), # 间接索引读取
0xFF: ('B', 'userscript(%#04x)', None), # 用户脚本子操作组

}

rops = {}

def make_rops():
	aliases = {
		'dispatch_7f': 'sys0',
		'dispatch_80': 'sys1',
		'dispatch_81': 'sys2',
		'dispatch_90': 'grp1',
		'dispatch_91': 'grp2',
		'dispatch_92': 'grp3',
		'dispatch_a0': 'snd1',
		'dispatch_b0': 'usr1',
		'dispatch_c0': 'usr2',
		'dispatch_d0': 'usr3',
		'dispatch_e0': 'usr4',
		'dispatch_ff': 'userscript',
	}
	for op in ops:
		fcn, = re_fcn.match(ops[op][1]).groups()
		rops[fcn] = op
	for alias, target in aliases.items():
		if target in rops:
			rops[alias] = rops[target]

make_rops()
