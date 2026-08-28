#!/usr/bin/env python3

# BGI ._bp file assembler

import glob
import os
import re
import struct
import sys

import asdis
import bpop

re_auto_label = re.compile(r'^L([0-9A-Fa-f]+)$')

def _parse_strdata_line(line):
	if asdis.re_strdata.match(line):
		hex_str, = asdis.re_strdata.match(line).groups()
		return bytes.fromhex(hex_str)
	return None

def _encode_text_token(token, encoding):
	text = asdis.unescape(token[1:-1])
	if text.lower().startswith('@hex:'):
		blob = text[5:]
		if len(blob) % 2 != 0:
			raise ValueError('invalid hex text blob')
		return bytes.fromhex(blob)
	return text.encode(bpop.normalize_encoding(encoding))

def _parse_string_data_line(line, encoding):
	line = line.strip()
	if len(line) >= 2 and line[0] == '"' and line[-1] == '"':
		return _encode_text_token(line, encoding) + b'\x00', line
	return None

def parse_instr(line, n):
	strings = []
	fcn, argstr = asdis.re_instr.match(line).groups()
	argstr = argstr.strip()
	if argstr:
		argstr = argstr.replace('\\\\', asdis.backslash_replace).replace('\\"', asdis.quote_replace)
		quotes = asdis.get_quotes(argstr, n)
		if len(quotes) %2 != 0:
			raise asdis.QuoteMismatch('Mismatched quotes @ line %d' % n)
		argstr = asdis.replace_quote_commas(argstr, quotes)
		brackets = 0
		in_quote = False
		argchars = list(argstr)
		for i, ch in enumerate(argchars):
			if ch == '"':
				in_quote = not in_quote
			elif in_quote:
				continue
			elif ch == '[':
				brackets += 1
			elif ch == ']':
				brackets -= 1
				if brackets < 0:
					raise asdis.InvalidInstructionFormat('Mismatched brackets @ line %d' % n)
			elif ch == ',' and brackets > 0:
				argchars[i] = asdis.comma_replace
		if brackets != 0:
			raise asdis.InvalidInstructionFormat('Mismatched brackets @ line %d' % n)
		argstr = ''.join(argchars)
		args = [x.strip().replace(asdis.comma_replace, ',').replace(asdis.quote_replace, '\\"').replace(asdis.backslash_replace, '\\\\') for x in argstr.split(',')]
		for arg in args:
			if arg and arg[0] == '"' and arg[-1] == '"':
				strings.append(arg)
	else:
		args = []
	return fcn, args, strings

def parse(asmtxt, encoding='cp932'):
	instrs = []
	symbols = {}
	text_set = set()
	text_list = []
	explicit_items = []
	for line in asmtxt.split('\n'):
		line = asdis.remove_comment(line.strip())
		if not line:
			continue
		if asdis.re_strings_start.match(line):
			continue
		chunk = _parse_strdata_line(line)
		if chunk is not None:
			explicit_items.append((None, chunk))
			continue
		string_chunk = _parse_string_data_line(line, encoding)
		if string_chunk is not None:
			chunk, token = string_chunk
			explicit_items.append((token, chunk))
	explicit_blob = b'' if explicit_items else None
	pos = 0
	for id, line in enumerate(asmtxt.split('\n')):
		line = line.strip()
		line = asdis.remove_comment(line)
		if not line:
			continue
		if asdis.re_strings_start.match(line):
			continue
		chunk = _parse_strdata_line(line)
		if chunk is not None:
			continue
		string_chunk = _parse_string_data_line(line, encoding)
		if string_chunk is not None:
			continue
		if asdis.re_label.match(line):
			symbol, = asdis.re_label.match(line).groups()
			m = re_auto_label.match(symbol)
			if m:
				symbols[symbol] = int(m.group(1), 16)
			else:
				symbols[symbol] = pos
		elif asdis.re_instr.match(line):
			fcn, args, strings = parse_instr(line, id+1)
			record = fcn, args, pos, id+1
			if explicit_blob is None:
				collect_strings = fcn == 'push_string' and len(args) == 1
				for text in strings:
					if not collect_strings:
						continue
					if text in text_set:
						continue
					text_set.add(text)
					text_list.append(text)
			instrs.append(record)
			try:
				op = bpop.rops[fcn]
			except KeyError:
				raise asdis.InvalidFunction('Invalid function @ line %d' % (id+1))
			pos += bpop.get_instr_size(op, args)
		else:
			raise asdis.InvalidInstructionFormat('Invalid instruction format @ line %d' % (id+1))
	texts = []
	if explicit_blob is None:
		while pos % 0x10 != 0:
			pos += 1
		for text in text_list:
			symbols[text] = pos
			data = _encode_text_token(text, encoding)
			texts.append(data)
			pos += len(data) + 1
		while pos % 0x10 != 0:
			pos += 1
	else:
		explicit_offsets = {}
		explicit_blob_builder = bytearray()
		cursor = 0
		for token, chunk in explicit_items:
			if token is not None:
				explicit_offsets.setdefault(token, []).append(pos + cursor)
			explicit_blob_builder.extend(chunk)
			cursor += len(chunk)
		explicit_blob = bytes(explicit_blob_builder)
		usage = {}
		for idx, (fcn, args, ipos, n) in enumerate(instrs):
			if fcn != 'push_string' or len(args) != 1 or not args[0] or args[0][0] != '"':
				continue
			token = args[0]
			if token not in explicit_offsets:
				raise asdis.InvalidInstructionFormat('Missing string data for push_string @ line %d' % n)
			ref_idx = usage.get(token, 0)
			offsets = explicit_offsets[token]
			target = offsets[ref_idx] if ref_idx < len(offsets) else offsets[0]
			usage[token] = ref_idx + 1
			instrs[idx] = (fcn, [token, 'L%05x' % target], ipos, n)
		pos += len(explicit_blob)
	size = pos
	return instrs, symbols, texts, size, explicit_blob

def out(fo, instrs, symbols, texts, size, explicit_blob=None):
	hdr = struct.pack('<IIII', 0x10, size, 0, 0)
	fo.write(hdr)
	for fcn, args, pos, n in instrs:
		op = bpop.rops[fcn]
		if bpop.is_var_op(op):
			fo.write(bpop.encode_var_instr(op, args, pos, symbols))
			continue
		entry = bpop.get_op_entry(op)
		if entry is None:
			raise asdis.InvalidFunction('Invalid function @ line %d' % n)
		fo.write(struct.pack('B', op))
		if op == 0x05 and len(args) >= 1:
			target_arg = args[1] if len(args) >= 2 else args[0]
			if len(args) == 1 and target_arg in symbols:
				target = symbols[target_arg]
				fo.write(struct.pack('<h', target - pos))
				continue
			if target_arg in symbols:
				target = symbols[target_arg]
			elif target_arg.startswith('L-'):
				target = -int(target_arg[2:], 16)
			elif target_arg.startswith('L'):
				target = int(target_arg[1:], 16)
			elif target_arg.startswith('0x') or target_arg.startswith('-0x'):
				target = int(target_arg, 16)
			else:
				target = int(target_arg)
			fo.write(struct.pack('<h', target - pos))
			continue
		arglist = []
		for arg in args:
			if arg in symbols:
				arglist.append(symbols[arg]-pos)
			elif arg.startswith('L-'):
				value = -int(arg[2:], 16)
				if op == 0x06:
					arglist.append(value - pos)
				else:
					arglist.append(value)
			elif arg.startswith('L'):
				value = int(arg[1:], 16)
				if op == 0x06:
					arglist.append(value - pos)
				else:
					arglist.append(value)
			elif arg.startswith('0x') or arg.startswith('-0x'):
				arglist.append(int(arg, 16))
			elif arg:
				arglist.append(int(arg))
		fmt = entry[0]
		if fmt:
			fo.write(struct.pack(fmt, *tuple(arglist)))
	if explicit_blob is not None:
		fo.write(explicit_blob)
	else:
		while fo.tell() % 0x10 != 0:
			fo.write(b'\x00')
		for text in texts:
			fo.write(text + b'\x00')
		while fo.tell() % 0x10 != 0:
			fo.write(b'\x00')

def asm(file, encoding='cp932', output_path=None):
	ofile = output_path or (os.path.splitext(file)[0] + '._bp')
	asmtxt = open(file, 'r', encoding='utf-8').read()
	instrs, symbols, texts, size, explicit_blob = parse(asmtxt, encoding=encoding)
	out(open(ofile, 'wb'), instrs, symbols, texts, size, explicit_blob)

if __name__ == '__main__':
	encoding = 'cp932'
	args = []
	argv = sys.argv[1:]
	i = 0
	while i < len(argv):
		arg = argv[i]
		if arg in ('-c', '--encoding') and i + 1 < len(argv):
			encoding = argv[i + 1]
			i += 1
		else:
			args.append(arg)
		i += 1
	if len(args) < 1:
		print('Usage: bpas.py [-c|--encoding <enc>] <file(s)>')
		print('(only .bpd files amongst <file(s)> will be processed)')
		sys.exit(1)
	for arg in args:
		for script in glob.glob(arg):
			base, ext = os.path.splitext(script)
			if ext == '.bpd':
				print('Assembling %s...' % script)
				asm(script, encoding=encoding)
