#!/usr/bin/env python3

# BGI ._bp file disassembler

import glob
import os
import struct
import sys

import asdis
import bpop

last_string_refs = {}
last_string_ref_order = []
last_debug_string_refs = {}
last_str_data_offset = 0

def get_code_end(data):
	candidates = []
	for pos, op in enumerate(data):
		if op != 0x17:
			continue
		pad_end = ((pos + 1 + 0x0F) // 0x10) * 0x10
		if pad_end > len(data):
			continue
		if any(data[i] != 0 for i in range(pos + 1, pad_end)):
			continue
		candidates.append(pos + 1)
	if candidates:
		return candidates[-1]
	pos = -1
	while 1:
		res = data.find(b'\x17', pos+1)
		if res == -1:
			break
		pos = res
	return pos+1

def _encode_text(text, encoding):
	value = asdis.unescape(text)
	if value.lower().startswith('@hex:'):
		blob = value[5:]
		if len(blob) % 2 != 0:
			raise ValueError('invalid hex text blob')
		return bytes.fromhex(blob)
	return value.encode(bpop.normalize_encoding(encoding))

def out_smart_strdata(fo, str_data, string_refs, str_data_offset, code_refs_order, encoding, force_output=False):
	valid_refs = {k: v for k, v in string_refs.items() if 0 <= k - str_data_offset < len(str_data)}
	current_calc_pos = 0
	seen_offsets = set()
	is_standard = True
	for abs_offset in code_refs_order:
		if abs_offset not in valid_refs or abs_offset in seen_offsets:
			continue
		seen_offsets.add(abs_offset)
		rel_offset = abs_offset - str_data_offset
		if rel_offset != current_calc_pos:
			is_standard = False
			break
		current_calc_pos += len(_encode_text(valid_refs[abs_offset], encoding)) + 1
	if is_standard and current_calc_pos != len(str_data):
		is_standard = False
	if is_standard and len(seen_offsets) != len(valid_refs):
		is_standard = False
	if is_standard and not force_output:
		return
	current_pos = 0
	str_data_len = len(str_data)
	rel_refs = {k - str_data_offset: v for k, v in valid_refs.items()}
	sorted_rel_offsets = sorted(rel_refs)
	while current_pos < str_data_len:
		if current_pos in rel_refs:
			string = rel_refs[current_pos]
			fo.write('"%s"\n' % string)
			current_pos += len(_encode_text(string, encoding)) + 1
			continue
		next_ref_pos = str_data_len
		for off in sorted_rel_offsets:
			if off > current_pos:
				next_ref_pos = off
				break
		gap_data = str_data[current_pos:next_ref_pos]
		hex_str = gap_data.hex()
		for i in range(0, len(hex_str), 128):
			fo.write('#strdata "%s"\n' % hex_str[i:i+128])
		current_pos = next_ref_pos

def parse(code, exact_mode=False):
	global last_string_refs, last_string_ref_order, last_debug_string_refs, last_str_data_offset
	bpop.clear_offsets()
	inst = {}
	string_refs = {}
	string_ref_order = []
	debug_string_refs = {}
	size = get_code_end(code)
	pos = 0
	while pos < size:
		addr = pos
		op = code[addr]
		entry = bpop.get_op_entry(op)
		if entry is None:
			raise Exception('size unknown for op %02x @ offset %05x' % (op, addr))
		pos += 1
		if bpop.is_var_op(op):
			text, n = bpop.decode_var_instr(op, code, addr, pos)
			inst[addr] = text
			pos += n
			continue
		fmt, pfmt, fcn = entry
		if fmt:
			n = struct.calcsize(fmt)
			raw_args = struct.unpack(fmt, code[pos:pos+n])
			args = raw_args
			if fcn:
				args = fcn(code, addr, *raw_args)
			if op == 0x05:
				target = addr + raw_args[0]
				debug_string_refs[addr] = (target, args)
				string_refs[target] = args
				string_ref_order.append(target)
				if exact_mode:
					inst[addr] = 'push_string("%s")' % args
				else:
					inst[addr] = pfmt % args
			else:
				inst[addr] = pfmt % args
			pos += n
		else:
			inst[addr] = pfmt
	offsets = bpop.offsets.copy()
	last_string_refs = string_refs
	last_string_ref_order = string_ref_order
	last_debug_string_refs = debug_string_refs
	last_str_data_offset = size
	return inst, offsets, size, code[size:]
	
def out(fo, inst, offsets):
	addrs = sorted(inst)
	extra_offsets = sorted(x for x in offsets if x not in inst)
	eidx = 0
	for addr in addrs:
		while eidx < len(extra_offsets) and extra_offsets[eidx] < addr:
			fo.write('\nL%05x:\n' % extra_offsets[eidx])
			eidx += 1
		if addr in offsets:
			fo.write('\nL%05x:\n' % addr)
		fo.write('\t%s;\n' % inst[addr])
	while eidx < len(extra_offsets):
		fo.write('\nL%05x:\n' % extra_offsets[eidx])
		eidx += 1

def out_strdata(fo, str_data, encoding):
	if not str_data:
		return
	fo.write('\n#strings\n')
	out_smart_strdata(fo, str_data, last_string_refs, last_str_data_offset, last_string_ref_order, encoding, True)

def out_debug_strdata(fo, str_data, encoding):
	if not str_data:
		return
	fo.write('\n#strings\n')
	valid_refs = {k: v for k, v in last_string_refs.items() if 0 <= k - last_str_data_offset < len(str_data)}
	current_pos = 0
	rel_refs = {k - last_str_data_offset: v for k, v in valid_refs.items()}
	sorted_rel_offsets = sorted(rel_refs)
	while current_pos < len(str_data):
		if current_pos in rel_refs:
			abs_offset = last_str_data_offset + current_pos
			string = rel_refs[current_pos]
			fo.write('L%05x: "%s"\n' % (abs_offset, string))
			current_pos += len(_encode_text(string, encoding)) + 1
			continue
		next_ref_pos = len(str_data)
		for off in sorted_rel_offsets:
			if off > current_pos:
				next_ref_pos = off
				break
		gap_data = str_data[current_pos:next_ref_pos]
		hex_str = gap_data.hex()
		for i in range(0, len(hex_str), 128):
			fo.write('#strdata "%s"\n' % hex_str[i:i+128])
		current_pos = next_ref_pos

def out_debug(fo, inst, code, size, encoding):
	addrs = sorted(inst)
	for idx, addr in enumerate(addrs):
		next_addr = addrs[idx + 1] if idx + 1 < len(addrs) else size
		last_addr = next_addr - 1
		raw = code[addr:next_addr]
		text = inst[addr]
		if addr in last_debug_string_refs:
			target, string = last_debug_string_refs[addr]
			text = 'push_string(L%05x) // "%s"' % (target, string)
		fo.write('%05x-%05x  %-16s  %s\n' % (addr, last_addr, raw.hex(), text))
	out_debug_strdata(fo, code[size:], encoding)

def dis(file, debug=False, exact_mode=False, encoding='cp932', output_path=None):
	bpop.set_text_encoding(encoding)
	ofile = output_path or (os.path.splitext(file)[0] + '.bpd')
	fi = open(file, 'rb')
	hdrsize, = struct.unpack('<I', fi.read(4))
	fi.seek(hdrsize, 0)
	code = fi.read()
	fi.close()
	inst, offsets, size, str_data = parse(code, exact_mode=exact_mode)
	fo = open(ofile, 'w', encoding='utf-8')
	out(fo, inst, offsets)
	if exact_mode:
		out_strdata(fo, str_data, encoding)
	fo.close()
	if debug:
		dbg_file = os.path.splitext(file)[0] + '.bpd.debug.txt'
		fd = open(dbg_file, 'w', encoding='utf-8')
		out_debug(fd, inst, code, size, encoding)
		fd.close()
	
if __name__ == '__main__':
	debug = False
	exact_mode = False
	encoding = 'cp932'
	args = []
	argv = sys.argv[1:]
	i = 0
	while i < len(argv):
		arg = argv[i]
		if arg in ('-d', '--debug'):
			debug = True
		elif arg in ('-e', '--exact'):
			exact_mode = True
		elif arg in ('-c', '--encoding') and i + 1 < len(argv):
			encoding = argv[i + 1]
			i += 1
		else:
			args.append(arg)
		i += 1
	if len(args) < 1:
		print('Usage: bpdis.py [--debug] [--exact] [-c|--encoding <enc>] <file(s)>')
		print('(only ._bp files amongst <file(s)> will be processed)')
		print('  -e, --exact: Output exact trailing string area and keep push_string as readable strings')
		sys.exit(1)
	for arg in args:
		for script in glob.glob(arg):
			base, ext = os.path.splitext(script)
			if ext == '._bp':
				print('Disassembling %s...' % script)
				dis(script, debug=debug, exact_mode=exact_mode, encoding=encoding)
	
