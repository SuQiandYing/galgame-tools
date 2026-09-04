"""Cotopha / EntisGLS CSX reader: source binary -> in-memory IR -> projections.

The source file is opened read-only.  Every byte of the file is accounted for by
exactly one region, and the instruction stream is decoded within the bounds that
``funcinfo`` states for each function, so a decode that runs long or short is a
hard failure rather than a silent truncation.

Entry points used by the CLI and the GUI:

    parse_source(path)      -> Image
    render_asm(image)       -> str
    render_texts(image)     -> str
    export(...)             -> writes texts/, asm/, ir/, reports/
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

import profile
from opcodelist import (DIALECT, INSTRUCTIONS, NATIVE_FUNC_RECORD, OBJECT_MODES,
                        PLACEHOLDER_POLICY, SECTION_TAGS, VARIABLE_TYPES)

TOOL_VERSION = "1.0.0"
IR_VERSION = "TEXT/2"

U32 = struct.Struct("<I")
I32 = struct.Struct("<i")
U64 = struct.Struct("<Q")
F64 = struct.Struct("<d")

INTERNED = DIALECT["string_literal"]["interned_marker"]
TEXT_ENCODING = DIALECT["string_literal"]["encoding"]


class CsxError(Exception):
    """Raised when the source bytes contradict the declared dialect."""


class UnknownOpcode(CsxError):
    def __init__(self, opcode: int, offset: int):
        super().__init__(f"undeclared opcode 0x{opcode:02X} at image offset 0x{offset:X}")
        self.opcode = opcode
        self.offset = offset


@dataclass(slots=True)
class Section:
    tag: str
    name: str
    header_offset: int
    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(slots=True)
class ConstString:
    sid: int
    text: str
    sites: tuple[int, ...]
    record_start: int
    record_end: int


@dataclass(slots=True)
class FunctionInfo:
    flags: int
    address: int
    size: int
    reserved: int
    name: str
    record_start: int
    record_end: int

    @property
    def has_bounds(self) -> bool:
        return self.size != 0xFFFFFFFF


@dataclass(slots=True)
class Instruction:
    offset: int
    size: int
    opcode: int
    mnemonic: str
    operands: tuple
    text: str
    string_sites: tuple[int, ...] = ()
    target: int | None = None


@dataclass(slots=True)
class DecodedFunction:
    info: FunctionInfo
    instructions: list[Instruction]
    status: str
    blocked: dict | None = None


@dataclass(slots=True)
class Region:
    ident: str
    start: int
    end: int
    status: str
    kind: str
    decode_tier: str
    owner: str
    raw_sha256: str
    evidence_refs: tuple[str, ...] = ()


@dataclass(slots=True)
class TextEntry:
    idx: int
    sid: int
    text: str
    tag: str
    tag_source: str
    translate_policy: str
    sites: tuple[int, ...]
    speaker: str | None = None
    callees: tuple[str, ...] = ()
    alias_count: int = 0


@dataclass(slots=True)
class Image:
    path: Path
    data: bytes
    sha256: str
    md5: str
    sections: list[Section]
    strings: list[ConstString]
    site_to_sid: dict[int, int]
    functions: list[FunctionInfo]
    class_names: list[str]
    method_names: dict[int, list[str]]
    native_names: list[str]
    decoded: list[DecodedFunction] = field(default_factory=list)
    regions: list[Region] = field(default_factory=list)
    texts: list[TextEntry] = field(default_factory=list)
    image_section: Section | None = None
    tier_blocked: list[dict] = field(default_factory=list)
    name_bindings: list[dict] = field(default_factory=list)
    consumers: dict[int, list[tuple[str, int, int]]] | None = None


# --------------------------------------------------------------------------
# primitive readers
# --------------------------------------------------------------------------

class Reader:
    """Bounds-checked cursor over the source bytes."""

    __slots__ = ("data", "pos", "limit")

    def __init__(self, data: bytes, pos: int = 0, limit: int | None = None):
        self.data = data
        self.pos = pos
        self.limit = len(data) if limit is None else limit

    def need(self, count: int) -> int:
        start = self.pos
        end = start + count
        if end > self.limit:
            raise CsxError(f"read of {count} bytes at 0x{start:X} passes region end 0x{self.limit:X}")
        self.pos = end
        return start

    # The four scalar readers are on the decode hot path, so each does its own
    # bound check and cursor bump rather than calling need().
    def u8(self) -> int:
        pos = self.pos
        if pos >= self.limit:
            raise CsxError(f"read of 1 byte at 0x{pos:X} passes region end 0x{self.limit:X}")
        self.pos = pos + 1
        return self.data[pos]

    def u32(self) -> int:
        pos = self.pos
        end = pos + 4
        if end > self.limit:
            raise CsxError(f"read of 4 bytes at 0x{pos:X} passes region end 0x{self.limit:X}")
        self.pos = end
        return U32.unpack_from(self.data, pos)[0]

    def i32(self) -> int:
        pos = self.pos
        end = pos + 4
        if end > self.limit:
            raise CsxError(f"read of 4 bytes at 0x{pos:X} passes region end 0x{self.limit:X}")
        self.pos = end
        return I32.unpack_from(self.data, pos)[0]

    def u64(self) -> int:
        return U64.unpack_from(self.data, self.need(8))[0]

    def f64(self) -> float:
        return F64.unpack_from(self.data, self.need(8))[0]

    def skip(self, count: int) -> None:
        self.need(count)

    def wide_string(self) -> str:
        units = self.u32()
        start = self.need(units * 2)
        return self.data[start:start + units * 2].decode(TEXT_ENCODING)


def sha256_range(data: bytes, start: int, end: int) -> str:
    digest = hashlib.sha256()
    digest.update(data[start:end])
    return digest.hexdigest()


# --------------------------------------------------------------------------
# container and section parsing
# --------------------------------------------------------------------------

def parse_sections(data: bytes) -> tuple[list[Section], int]:
    container = DIALECT["container"]
    if not data.startswith(container["file_magic"]):
        raise CsxError("file does not start with the Entis container magic")
    image_type = container["image_type"]
    type_at = container["image_type_offset"]
    if data[type_at:type_at + len(image_type)] != image_type:
        raise CsxError("container image type is not 'Cotopha Image file'")

    sections: list[Section] = []
    pos = container["header_size"]
    head = container["record_header_size"]
    while pos + head <= len(data):
        raw_tag = data[pos:pos + container["record_tag_width"]]
        try:
            tag = raw_tag.decode("ascii")
        except UnicodeDecodeError:
            break
        if tag not in SECTION_TAGS:
            break
        length = U64.unpack_from(data, pos + container["record_tag_width"])[0]
        body = pos + head
        if length > len(data) - body:
            raise CsxError(f"section '{tag}' at 0x{pos:X} claims {length} bytes past end of file")
        sections.append(Section(tag, SECTION_TAGS[tag], pos, body, body + length))
        pos = body + length
    if not sections:
        raise CsxError("no container sections could be read")
    return sections, pos


def parse_const_strings(data: bytes, section: Section) -> tuple[list[ConstString], dict[int, int]]:
    reader = Reader(data, section.start, section.end)
    count = reader.u32()
    strings: list[ConstString] = []
    sites: dict[int, int] = {}
    for sid in range(count):
        record_start = reader.pos
        text = reader.wide_string()
        site_count = reader.u32()
        entries = []
        for _ in range(site_count):
            offset = reader.u32()
            entries.append(offset)
            if offset in sites:
                raise CsxError(f"image offset 0x{offset:X} claimed by strings {sites[offset]} and {sid}")
            sites[offset] = sid
        strings.append(ConstString(sid, text, tuple(entries), record_start, reader.pos))
    if reader.pos != section.end:
        raise CsxError(
            f"conststr parsed to 0x{reader.pos:X} but the section ends at 0x{section.end:X}"
        )
    return strings, sites


def parse_function_info(data: bytes, section: Section) -> list[FunctionInfo]:
    reader = Reader(data, section.start, section.end)
    count = reader.u32()
    out: list[FunctionInfo] = []
    for _ in range(count):
        start = reader.pos
        flags = reader.u32()
        address = reader.u32()
        size = reader.u32()
        reserved = reader.u32()
        name = reader.wide_string()
        if reserved:
            reader.skip(reserved)
        out.append(FunctionInfo(flags, address, size, reserved, name, start, reader.pos))
    if reader.pos != section.end:
        raise CsxError(
            f"funcinfo parsed to 0x{reader.pos:X} but the section ends at 0x{section.end:X}"
        )
    return out




def parse_native_names(data: bytes, section: Section) -> list[str]:
    """impnativ holds nested 'nativfnc' / 'nakedfnc' records."""
    container = DIALECT["container"]
    head = container["record_header_size"]
    pos = section.start
    names: list[str] = []
    while pos + head <= section.end:
        tag = data[pos:pos + container["record_tag_width"]]
        length = U64.unpack_from(data, pos + container["record_tag_width"])[0]
        body = pos + head
        if length > section.end - body:
            raise CsxError(f"impnativ sub-record at 0x{pos:X} overruns the section")
        if tag == NATIVE_FUNC_RECORD:
            reader = Reader(data, body, body + length)
            for _ in range(reader.u32()):
                names.append(reader.wide_string())
        pos = body + length
    return names


# --------------------------------------------------------------------------
# instruction decoding
# --------------------------------------------------------------------------

class InstructionDecoder:
    """Decodes one instruction per call, following the declared dialect."""

    def __init__(self, image: Image):
        self.image = image
        self.base = image.image_section.start
        self.strings = image.strings
        self.class_names = image.class_names
        self.method_names = image.method_names
        self.native_names = image.native_names
        self.func_by_address = {f.address: f for f in image.functions if f.has_bounds}
        # Bind opcode -> (mnemonic, bound handler) once, so the hot loop is a
        # single list index instead of a dict lookup plus getattr per
        # instruction.  This sample decodes over a million instructions.
        self._dispatch: list[tuple[str, object] | None] = [None] * 256
        for opcode, spec in INSTRUCTIONS.items():
            self._dispatch[opcode] = (spec["mnemonic"],
                                      getattr(self, f"_op_{spec['handler']}"))

    # -- operand helpers ---------------------------------------------------
    def _literal(self, reader: Reader) -> tuple[str, int | None, int | None]:
        """Interned conststr reference, or an inline wide string (v1 style)."""
        probe = reader.u32()
        if probe != INTERNED:
            reader.pos -= 4
            return reader.wide_string(), None, None
        site = reader.pos - self.base
        sid = reader.u32()
        if not 0 <= sid < len(self.strings):
            raise CsxError(f"string index {sid} at image offset 0x{site:X} is out of range")
        return self.strings[sid].text, sid, site

    def _class_or_object_name(self, reader: Reader, var_type: int) -> tuple[str, list[int]]:
        sites: list[int] = []
        if var_type == 9:
            index = reader.i32()
            if not 0 <= index < len(self.class_names):
                raise CsxError(f"class index {index} is out of range")
            return self.class_names[index], sites
        if var_type == 0:
            name, sid, site = self._literal(reader)
            if site is not None:
                sites.append(site)
            return name, sites
        return "", sites

    def _member_name(self, class_index: int, func_index: int) -> str:
        members = self.method_names.get(class_index)
        if members is None or not 0 <= func_index < len(members):
            return f"class#{class_index}::method#{func_index}"
        return members[func_index]

    # -- per-opcode handlers ----------------------------------------------
    def decode(self, reader: Reader) -> Instruction:
        data = reader.data
        offset = reader.pos - self.base
        opcode = data[reader.pos]
        reader.pos += 1
        entry = self._dispatch[opcode]
        if entry is None:
            raise UnknownOpcode(opcode, offset)
        mnemonic, handler = entry
        sites: list[int] = []
        text, operands, target = handler(reader, sites)
        return Instruction(
            offset=offset,
            size=reader.pos - self.base - offset,
            opcode=opcode,
            mnemonic=mnemonic,
            operands=operands,
            text=text,
            string_sites=tuple(sites),
            target=target,
        )

    def _op_new(self, reader: Reader, sites: list[int]):
        mode = reader.u8()
        var_type = reader.u8()
        class_name, extra = self._class_or_object_name(reader, var_type)
        sites.extend(extra)
        var_name, sid, site = self._literal(reader)
        if site is not None:
            sites.append(site)
        mode_name = OBJECT_MODES.get(mode, f"mode#{mode}")
        if class_name:
            return f'New {mode_name} "{class_name}" "{var_name}"', (mode, var_type, class_name, var_name), None
        return f'New {mode_name} "{var_name}"', (mode, var_type, var_name), None

    def _op_free(self, reader: Reader, sites: list[int]):
        return "Free", (), None

    def _op_load(self, reader: Reader, sites: list[int]):
        mode = reader.u8()
        var_type = reader.u8()
        type_name = VARIABLE_TYPES.get(var_type, f"type#{var_type}")
        if mode == 0:
            if var_type == 0:
                name, sid, site = self._literal(reader)
                if site is not None:
                    sites.append(site)
                return f'Load New "{name}"', (mode, var_type, name), None
            if var_type in (1, 2, 3):
                return f"Load New {type_name}", (mode, var_type), None
            if var_type == 4:
                return f"Load Integer {reader.u32()}", (mode, var_type), None
            if var_type == 5:
                return f"Load Real {reader.f64()!r}", (mode, var_type), None
            if var_type == 6:
                value, sid, site = self._literal(reader)
                if site is not None:
                    sites.append(site)
                    return f"Load String sid={sid}", (mode, var_type, sid), None
                return f'Load String "{escape_text(value)}"', (mode, var_type, value), None
            if var_type == 7:
                return f"Load Integer64 {reader.u64()}", (mode, var_type), None
            if var_type == 8:
                return f"Load Pointer {reader.u32()}", (mode, var_type), None
            if var_type == 9:
                index = reader.i32()
                if not 0 <= index < len(self.class_names):
                    raise CsxError(f"class index {index} is out of range")
                return f'Load New "{self.class_names[index]}"', (mode, var_type, index), None
            if var_type == 10:
                return f"Load Boolean {reader.u8()}", (mode, var_type), None
            raise CsxError(f"Load immediate has unexpected variable type {var_type}")
        mode_name = OBJECT_MODES.get(mode, f"mode#{mode}")
        if var_type == 1:
            return f"Load {mode_name}", (mode, var_type), None
        if var_type == 4:
            return f"Load {mode_name} [{reader.i32()}]", (mode, var_type), None
        if var_type == 6:
            name, sid, site = self._literal(reader)
            if site is not None:
                sites.append(site)
            return f'Load {mode_name} ["{name}"]', (mode, var_type, name), None
        raise CsxError(f"Load {mode_name} has unexpected variable type {var_type}")

    def _op_store(self, reader: Reader, sites: list[int]):
        return f"Store.{reader.u8()}", (), None

    def _op_enter(self, reader: Reader, sites: list[int]):
        name, sid, site = self._literal(reader)
        if site is not None:
            sites.append(site)
        num_args = reader.i32()
        if num_args == -1:
            flag = reader.u8()
            if flag != 0:
                raise CsxError("extended namespace instruction is not defined")
            rel = reader.i32()
            catch = reader.pos - self.base + rel
            return f'Enter "{name}" Try-Catch {catch:08X}', (name, -1), catch
        args: list[str] = []
        for _ in range(num_args):
            var_type = reader.u8()
            class_name, extra = self._class_or_object_name(reader, var_type)
            sites.extend(extra)
            var_name, sid2, site2 = self._literal(reader)
            if site2 is not None:
                sites.append(site2)
            args.append(f"{{{class_name}:{var_name}}}" if class_name else var_name)
        return f'Enter "{name}" ({", ".join(args)})', (name, num_args, tuple(args)), None

    def _op_leave(self, reader: Reader, sites: list[int]):
        return "Leave", (), None

    def _op_jump(self, reader: Reader, sites: list[int]):
        rel = reader.i32()
        target = reader.pos - self.base + rel
        return "Jump", (target,), target

    def _op_cjump(self, reader: Reader, sites: list[int]):
        cond = reader.u8()
        rel = reader.i32()
        target = reader.pos - self.base + rel
        return f"CJump {cond}", (cond, target), target

    def _op_call(self, reader: Reader, sites: list[int]):
        mode = reader.u8()
        num_args = reader.i32()
        name, sid, site = self._literal(reader)
        if site is not None:
            sites.append(site)
        mode_name = OBJECT_MODES.get(mode, f"mode#{mode}")
        return f'Call {mode_name} "{name}" <{num_args}>', (mode, num_args, name), None

    def _op_return(self, reader: Reader, sites: list[int]):
        return "Return Void" if reader.u8() == 1 else "Return", (), None

    def _op_element(self, reader: Reader, sites: list[int]):
        var_type = reader.u8()
        if var_type == 4:
            return f"Element [{reader.i32()}]", (var_type,), None
        if var_type == 6:
            name, sid, site = self._literal(reader)
            if site is not None:
                sites.append(site)
            return f'Element ["{name}"]', (var_type, name), None
        raise CsxError(f"Element has unexpected variable type {var_type}")

    def _op_element_indirect(self, reader: Reader, sites: list[int]):
        return "ElementIndirect", (), None

    def _op_operate(self, reader: Reader, sites: list[int]):
        return f"Operate.{reader.u8()}", (), None

    def _op_uni_operate(self, reader: Reader, sites: list[int]):
        return f"UnaryOperate.{reader.u8()}", (), None

    def _op_compare(self, reader: Reader, sites: list[int]):
        code = reader.u8()
        name = DIALECT["compare_ops"].get(code)
        if name is None:
            raise CsxError(f"undeclared compare sub-code {code}")
        return f"Compare.{name}", (code,), None

    def _op_ex_operate(self, reader: Reader, sites: list[int]):
        code = reader.u8()
        name = DIALECT["extra_ops"].get(code)
        if name is None:
            raise CsxError(f"undeclared extra operator {code}")
        if code == 0:
            dims = [reader.i32() for _ in range(reader.i32())]
            return f"ExOperate.array_dimension {{{', '.join(map(str, dims))}}}", (code, tuple(dims)), None
        return f"ExOperate.{name}", (code,), None

    def _op_ex_uni_operate(self, reader: Reader, sites: list[int]):
        code = reader.u8()
        name = DIALECT["extra_uni_ops"].get(code)
        if name is None:
            raise CsxError(f"undeclared extra unary operator {code}")
        if code == 4:
            values = (reader.i32(), reader.i32(), reader.i32())
            return f"ExUniOperate.static_cast {values[0]}, {values[1]}, {values[2]}", (code, values), None
        if code == 5:
            cast, sid, site = self._literal(reader)
            if site is not None:
                sites.append(site)
            return f'ExUniOperate.dynamic_cast "{cast}"', (code, cast), None
        return f"ExUniOperate.{name}", (code,), None

    def _op_ex_call(self, reader: Reader, sites: list[int]):
        num_args = reader.i32()
        mode = reader.u8()
        var_type = reader.u8()
        if mode != 0:
            raise CsxError(f"ExCall has unexpected object mode {mode}")
        if var_type == 6:
            name, sid, site = self._literal(reader)
            if site is not None:
                sites.append(site)
            return f'ExCall "{name}" <{num_args}>', (num_args, name), None
        if var_type == 4:
            address = reader.u32()
            func = self.func_by_address.get(address)
            label = func.name if func else f"{address:08X}"
            return f'ExCall "{label}" <{num_args}>', (num_args, address), None
        raise CsxError(f"ExCall has unexpected variable type {var_type}")

    def _op_ex_return(self, reader: Reader, sites: list[int]):
        return "ExReturn Void" if reader.u8() == 1 else "ExReturn", (), None

    def _op_call_member(self, reader: Reader, sites: list[int]):
        num_args = reader.i32()
        class_index = reader.i32()
        func_index = reader.i32()
        name = self._member_name(class_index, func_index)
        return f'CallMember "{name}" <{num_args}>', (num_args, name), None

    def _op_call_native_member(self, reader: Reader, sites: list[int]):
        num_args = reader.i32()
        class_index = reader.i32()
        func_index = reader.i32()
        name = self._member_name(class_index, func_index)
        return f'CallNativeMember "{name}" <{num_args}>', (num_args, name), None

    def _op_swap(self, reader: Reader, sites: list[int]):
        reader.u8()
        first = reader.i32()
        second = reader.i32()
        return f"Swap #{first}, #{second}", (first, second), None

    def _op_create_buffer_vsize(self, reader: Reader, sites: list[int]):
        return "CreateBufferVSize", (), None

    def _op_pointer_to_object(self, reader: Reader, sites: list[int]):
        return f"PointerToObject {reader.i32()}", (), None

    def _op_reference_for_pointer(self, reader: Reader, sites: list[int]):
        code = reader.u8()
        if code not in VARIABLE_TYPES:
            raise CsxError(f"ReferenceForPointer has unexpected variable type {code}")
        return f"ReferenceForPointer {VARIABLE_TYPES[code]}", (code,), None

    def _op_call_native_function(self, reader: Reader, sites: list[int]):
        num_args = reader.i32()
        index = reader.i32()
        if not 0 <= index < len(self.native_names):
            raise CsxError(f"native function index {index} is out of range")
        name = self.native_names[index]
        return f'CallNativeFunction "{name}" <{num_args}>', (num_args, name), None


def needs_placeholder(code: int) -> bool:
    """Whether a code point must be rendered as raw byte placeholders (§4.5)."""
    low, high = PLACEHOLDER_POLICY["private_use"]
    return (code < PLACEHOLDER_POLICY["control_below"]
            or code == PLACEHOLDER_POLICY["delete"]
            or low <= code <= high)


def as_placeholder(ch: str) -> str:
    encoded = ch.encode(TEXT_ENCODING)
    return "{{" + ":".join(f"{b:02X}" for b in encoded) + "}}"


def escape_text(value: str) -> str:
    out = []
    for ch in value:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif needs_placeholder(ord(ch)):
            out.append(as_placeholder(ch))
        else:
            out.append(ch)
    return "".join(out)


def escape_line(value: str) -> str:
    """Escape for the two-line text file: placeholders, no quote escaping."""
    breaks = set(PLACEHOLDER_POLICY["line_breaks"])
    out = []
    for ch in value:
        code = ord(ch)
        if code in breaks or needs_placeholder(code):
            out.append(as_placeholder(ch))
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------
# decode driver
# --------------------------------------------------------------------------

def decode_functions(image: Image) -> None:
    """Decode each function within the bounds funcinfo declares for it."""
    section = image.image_section
    decoder = InstructionDecoder(image)
    bounded = sorted((f for f in image.functions if f.has_bounds), key=lambda f: f.address)
    for info in bounded:
        start = section.start + info.address
        end = start + info.size
        if end > section.end:
            raise CsxError(f"function '{info.name}' extends past the image section")
        reader = Reader(image.data, start, end)
        instructions: list[Instruction] = []
        status = "decoded"
        blocked = None
        try:
            while reader.pos < end:
                instructions.append(decoder.decode(reader))
            if reader.pos != end:
                raise CsxError("decode overran the declared function size")
        except (CsxError, UnicodeDecodeError) as exc:
            status = "unknown_opaque_block"
            last = instructions[-1].offset if instructions else info.address
            blocked = {
                "attempted": "T3",
                "settled": "T2",
                "function": info.name,
                "offset": reader.pos - section.start,
                "last_verified_instruction_offset": last,
                "reason": type(exc).__name__.upper(),
                "detail": str(exc),
            }
            image.tier_blocked.append(blocked)
        image.decoded.append(DecodedFunction(info, instructions, status, blocked))


def build_regions(image: Image, trailer_start: int) -> None:
    """One region per accounted byte range; gaps and overlaps are failures."""
    data = image.data
    container = DIALECT["container"]
    regions: list[Region] = [
        Region("R_HEADER", 0, container["header_size"], "decoded", "container-header",
               "T2", "container", sha256_range(data, 0, container["header_size"]),
               ("EV_CONTAINER",))
    ]
    for index, section in enumerate(image.sections):
        regions.append(Region(
            f"R_SECHDR_{index:03d}", section.header_offset, section.start,
            "decoded", "section-header", "T2", section.name,
            sha256_range(data, section.header_offset, section.start), ("EV_CONTAINER",),
        ))
        if section.size == 0:
            continue
        if section.name == "image":
            regions.extend(build_image_regions(image, section))
            continue
        status = "decoded" if section.name in {
            "const_string", "function_info", "class_info", "import_native", "header"
        } else "opaque-preserved"
        regions.append(Region(
            f"R_SEC_{index:03d}", section.start, section.end, status, f"section:{section.name}",
            "T2", section.name, sha256_range(data, section.start, section.end),
            ("EV_CONTAINER",),
        ))
    if trailer_start < len(data):
        regions.append(Region(
            "R_TRAILER", trailer_start, len(data), "opaque-preserved", "container-trailer",
            "T0", "container", sha256_range(data, trailer_start, len(data)), ("EV_CONTAINER",),
        ))
    regions.sort(key=lambda r: r.start)
    cursor = 0
    for region in regions:
        if region.start < cursor:
            raise CsxError(f"regions overlap at 0x{region.start:X}")
        if region.start > cursor:
            raise CsxError(f"unaccounted bytes at 0x{cursor:X}..0x{region.start:X}")
        cursor = region.end
    if cursor != len(data):
        raise CsxError(f"regions cover {cursor} of {len(data)} bytes")
    image.regions = regions


def build_image_regions(image: Image, section: Section) -> list[Region]:
    """Sub-regions inside the image section: decoded functions and the rest."""
    data = image.data
    out: list[Region] = []
    for func in image.decoded:
        if not func.instructions and func.status != "decoded":
            continue
        start = section.start + func.info.address
        end = start + func.info.size
        tier = "T3" if func.status == "decoded" else "T2"
        out.append(Region(
            f"R_FUNC_{func.info.address:08X}", start, end, func.status,
            "instruction-stream" if func.status == "decoded" else "partial-instruction-stream",
            tier, func.info.name, sha256_range(data, start, end),
            ("EV_FUNCINFO", "EV_REFERENCE_DECODER"),
        ))
    out.sort(key=lambda r: r.start)
    filled: list[Region] = []
    cursor = section.start
    for region in out:
        if region.start > cursor:
            filled.append(Region(
                f"R_IMG_GAP_{cursor - section.start:08X}", cursor, region.start,
                "opaque-preserved", "image-unclaimed", "T0", "image",
                sha256_range(data, cursor, region.start), ("EV_FUNCINFO",),
            ))
        filled.append(region)
        cursor = region.end
    if cursor < section.end:
        filled.append(Region(
            f"R_IMG_GAP_{cursor - section.start:08X}", cursor, section.end,
            "opaque-preserved", "image-unclaimed", "T0", "image",
            sha256_range(data, cursor, section.end), ("EV_FUNCINFO",),
        ))
    return filled


# --------------------------------------------------------------------------
# text discovery through proven reference joins
# --------------------------------------------------------------------------

# 文本角色来自调用参数槽位的声明，声明本身放在 profiles/*.json，代码不含任何
# 作品专属字面量。槽位角色为 None 表示该槽已证明承载不可翻译的资源标识。
CALL_SLOT_ROLES: dict[str, dict] = profile.call_slot_roles()


def slot_role(callee: str, slot: int) -> tuple[bool, str | None]:
    """返回 (该槽位是否已声明, 角色)。未声明的调用一律不产生角色。"""
    layout = CALL_SLOT_ROLES.get(callee)
    if layout is None:
        return False, None
    slots = layout["slots"]
    if slot in slots:
        return True, slots[slot]
    rest_from = layout.get("rest_from")
    if rest_from is not None and slot >= rest_from:
        return True, layout["rest"]
    return False, None


def collect_argument_sites(image: Image) -> dict[int, list[tuple[str, int, int]]]:
    """Map each string-value site to the calls that consume it.

    A site is recorded as ``(callee, slot_ordinal, argument_count)``.  Only
    ``Load Immediate String`` pushes are tracked: identifier operands of
    ``New`` / ``Enter`` / ``Element`` name variables and members, not script text.
    """
    func_by_address = {f.address: f.name for f in image.functions if f.has_bounds}
    consumers: dict[int, list[tuple[str, int, int]]] = {}
    call_ops = ("CALL", "EX_CALL", "CALL_MEMBER",
                "CALL_NATIVE_MEMBER", "CALL_NATIVE_FUNCTION")
    barriers = ("ENTER", "LEAVE", "RETURN", "EX_RETURN", "JUMP", "CJUMP")

    for func in image.decoded:
        pending: list[int] = []
        for inst in func.instructions:
            if (inst.mnemonic == "LOAD" and inst.string_sites
                    and len(inst.operands) > 1
                    and inst.operands[0] == 0 and inst.operands[1] == 6):
                pending.append(inst.string_sites[0])
                continue
            if inst.mnemonic in call_ops:
                target = inst.operands[-1] if inst.operands else None
                if isinstance(target, int):
                    callee = func_by_address.get(target, f"func_{target:08X}")
                elif isinstance(target, str):
                    callee = target
                else:
                    callee = ""
                if callee and pending:
                    total = len(pending)
                    for slot, site in enumerate(pending):
                        consumers.setdefault(site, []).append((callee, slot, total))
                pending = []
                continue
            if inst.mnemonic in barriers:
                pending = []
    return consumers


def build_texts(image: Image) -> None:
    """Emit one entry per *reference site*, in bytecode order.

    A site is the unit of discovery and of export.  Grouping by storage instead
    would collapse every occurrence of a reused line into a single entry and
    delete the speaker line that precedes each one: this sample stores ``母親``
    once but references it from 12,996 call sites, so storage-level export
    yields 31 name entries instead of 30,045.

    Roles come from the argument slot of a proven call (``CALL_SLOT_ROLES``).
    Sites sharing one storage record an ``alias_count`` so an editor can see
    that changing one changes all of them.
    """
    consumers = collect_argument_sites(image)
    # Cache it: shapes_report needs the same map, and rebuilding it means a
    # second full pass over a million instructions.
    image.consumers = consumers
    string_value_sites = set(consumers)
    for func in image.decoded:
        for inst in func.instructions:
            if (inst.mnemonic == "LOAD" and inst.string_sites
                    and len(inst.operands) > 1
                    and inst.operands[0] == 0 and inst.operands[1] == 6):
                string_value_sites.add(inst.string_sites[0])

    # A site no call consumes can never be dialogue: msg/name/choice roles all
    # come from a *proven* call argument slot (§3.4).  Such sites are hash keys
    # (``ルート判定フラグ``), comparison operands and stored properties
    # (``xpos``, ``trans``, ``mask_u``) — counted as no_consumer and kept in the
    # IR as frozen references so the number stays visible in the report instead
    # of being folded into unresolved.
    no_consumer = string_value_sites - set(consumers)

    entries: list[TextEntry] = []
    for site in sorted(string_value_sites):
        sid = image.site_to_sid[site]
        uses = consumers.get(site, ())
        roles: set[str] = set()
        callees: set[str] = set()
        frozen_asset = False
        for callee, slot, total in uses:
            callees.add(callee)
            declared, role = slot_role(callee, slot)
            if not declared:
                continue
            if role is None:
                frozen_asset = True
            else:
                roles.add(role)

        # An empty stored string carries nothing to translate, and §4.9 rule 13
        # requires every target line to be non-empty, so such a site cannot be a
        # valid text entry.  It stays in the IR as an unexported reference.
        if not image.strings[sid].text:
            continue

        if not uses:
            tag, tag_source = "misc", "structural"
        elif len(roles) == 1:
            tag, tag_source = next(iter(roles)), "anchor"
        elif roles:
            tag, tag_source = "misc", "unresolved"
        elif frozen_asset:
            tag, tag_source = "misc", "structural"
        else:
            tag, tag_source = "misc", "unresolved"

        if tag_source == "structural":
            policy = "frozen"
        elif tag == "misc":
            policy = "review-required"
        else:
            policy = "translatable"

        entries.append(TextEntry(
            idx=0, sid=sid, text=image.strings[sid].text, tag=tag,
            tag_source=tag_source, translate_policy=policy, sites=(site,),
            callees=tuple(sorted(callees)),
        ))

    for number, item in enumerate(entries, start=1):
        item.idx = number
    image.texts = entries

    # Entries backed by the same storage form an alias group.  Record only the
    # group size per entry: the group itself is identified by `sid`, so the full
    # membership is recoverable from the IR by grouping on that key.  Storing an
    # explicit per-entry list would be quadratic — one string here is referenced
    # 16,060 times.
    group_size: dict[int, int] = {}
    for item in entries:
        group_size[item.sid] = group_size.get(item.sid, 0) + 1
    for item in entries:
        item.alias_count = group_size[item.sid] - 1

    image.name_bindings = build_name_bindings(image, consumers)


def build_name_bindings(image: Image,
                        consumers: dict[int, list[tuple[str, int, int]]]) -> list[dict]:
    """Bind speaker to message by argument slot ordinal, never by adjacency.

    Only calls whose slot layout declares both a ``name`` and a ``msg`` slot can
    produce a binding, and the two slots must belong to the same call site.
    """
    slot_pairs = {
        callee: (
            next((s for s, r in layout["slots"].items() if r == "name"), None),
            next((s for s, r in layout["slots"].items() if r == "msg"), None),
        )
        for callee, layout in CALL_SLOT_ROLES.items()
    }
    func_by_address = {f.address: f.name for f in image.functions if f.has_bounds}
    call_ops = ("CALL", "EX_CALL", "CALL_MEMBER",
                "CALL_NATIVE_MEMBER", "CALL_NATIVE_FUNCTION")
    barriers = ("ENTER", "LEAVE", "RETURN", "EX_RETURN", "JUMP", "CJUMP")

    # Entries are per site, so a binding pairs the two sites of one call.  This
    # is unambiguous by construction: both operands belong to the same call.
    by_site = {e.sites[0]: e for e in image.texts}
    out: list[dict] = []
    for func in image.decoded:
        pending: list[int] = []
        for inst in func.instructions:
            if (inst.mnemonic == "LOAD" and inst.string_sites
                    and len(inst.operands) > 1
                    and inst.operands[0] == 0 and inst.operands[1] == 6):
                pending.append(inst.string_sites[0])
                continue
            if inst.mnemonic in call_ops:
                target = inst.operands[-1] if inst.operands else None
                callee = (func_by_address.get(target, "") if isinstance(target, int)
                          else target if isinstance(target, str) else "")
                slots = slot_pairs.get(callee)
                if slots and None not in slots:
                    name_slot, msg_slot = slots
                    if max(name_slot, msg_slot) < len(pending):
                        name_entry = by_site.get(pending[name_slot])
                        msg_entry = by_site.get(pending[msg_slot])
                        if name_entry and msg_entry and name_entry.text:
                            msg_entry.speaker = name_entry.text
                            out.append({
                                "binding_id": f"B{len(out):06d}",
                                "msg_entry_idx": msg_entry.idx,
                                "name_entry_idx": name_entry.idx,
                                "name_kind": "entry",
                                "method": "slot-ordinal",
                                "confidence": "derived",
                                "candidates": [name_entry.idx],
                                "evidence_refs": ["EV_CALL_SLOTS"],
                            })
                pending = []
                continue
            if inst.mnemonic in barriers:
                pending = []
    return out


def parse_source(path: Path, decode: bool = True) -> Image:
    """Parse the container, the string table and, unless ``decode`` is false,
    the instruction stream.

    ``decode=False`` is for callers that only need the string table and its
    reference sites — repacking, for instance, copies the image bytes verbatim,
    so decoding a million instructions would prove nothing about the output.
    """
    data = Path(path).read_bytes()
    sections, trailer_start = parse_sections(data)
    by_name = {s.name: s for s in sections}
    for required in ("image", "const_string", "function_info"):
        if required not in by_name:
            raise CsxError(f"required section '{required}' is missing")

    strings, sites = parse_const_strings(data, by_name["const_string"])
    functions = parse_function_info(data, by_name["function_info"])
    # This sample's classinf names use a v2/v3 name table form that must be
    # resolved against conststr.  It is not needed to establish any text JoinSite;
    # retain it as a bounded opaque section and use numeric class/member labels
    # until the class metadata reader has an independent round-trip proof.
    class_names, method_names = ([f"class#{i}" for i in range(128)], {})
    native_names = parse_native_names(data, by_name["import_native"]) if "import_native" in by_name else []

    image = Image(
        path=Path(path), data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),
        sections=sections, strings=strings, site_to_sid=sites,
        functions=functions, class_names=class_names,
        method_names=method_names, native_names=native_names,
        image_section=by_name["image"],
    )

    image_base = image.image_section.start
    for offset, sid in sites.items():
        absolute = image_base + offset
        if absolute + 4 > image.image_section.end:
            raise CsxError(f"reference site 0x{offset:X} lies outside the image section")
        if U32.unpack_from(data, absolute)[0] != sid:
            raise CsxError(f"reference site 0x{offset:X} does not hold string index {sid}")

    if decode:
        decode_functions(image)
        build_regions(image, trailer_start)
        build_texts(image)
    return image


# --------------------------------------------------------------------------
# projections
# --------------------------------------------------------------------------

def render_asm(image: Image) -> str:
    """Deterministic structural view.  No raw hex dumps, jumps use labels."""
    targets = {
        inst.target
        for func in image.decoded for inst in func.instructions
        if inst.target is not None
    }
    out: list[str] = [
        f'; source {image.path.name}',
        f'.dialect  "{DIALECT["engine_id"]}" version "{DIALECT["schema_version"]}"',
        f'.tool     "{TOOL_VERSION}"',
        '.encoding "utf-16-le"',
        f'.tier     "{"T3" if not image.tier_blocked else "T2"}"',
        f'.source_sha256 {image.sha256}',
        "",
        "; ---- container sections ----",
    ]
    for section in image.sections:
        out.append(f'.section "{section.tag}" name={section.name} '
                   f'start=0x{section.start:08X} size={section.size}')
    out.append("")
    out.append("; ---- image ----")
    for func in image.decoded:
        out.append("")
        out.append(f"func_{func.info.address:08X}:")
        out.append(f'    .function "{func.info.name}" size={func.info.size} '
                   f'flags=0x{func.info.flags:X} status={func.status}')
        for inst in func.instructions:
            label = f"loc_{inst.offset:08X}"
            if inst.offset in targets:
                out.append("")
                out.append(f"{label}:")
            sid = None
            if inst.string_sites:
                sid = image.site_to_sid.get(inst.string_sites[0])
            body = inst.text
            if inst.target is not None:
                body = f"{body} loc_{inst.target:08X}"
            prefix = f"    0x{inst.offset:08X}  {body}"
            if sid is not None:
                prefix += f'  ; sid={sid} "{escape_text(image.strings[sid].text)}"'
            out.append(prefix)
        if func.blocked:
            out.append(f"    .tier_blocked offset=0x{func.blocked['offset']:08X} "
                       f"reason={func.blocked['reason']}")
    out.append("")
    return "\n".join(out)


def render_texts(image: Image) -> str:
    """TEXT/2 two-line file.  Target line is pre-filled with the source line."""
    total = len(image.texts)
    lines = [
        f"# TEXT/2 ir={IR_VERSION} tool={TOOL_VERSION} src_sha256={image.sha256}",
        "# encoding source=utf-16-le target=utf-16-le file=utf-8",
        f"# scope kind=all range=ALL part=1/1 entries={total}",
        "# tags name msg choice label ui system ruby misc",
        "#",
    ]
    for entry in image.texts:
        body = escape_line(entry.text)
        head = (f"# idx={entry.idx:08d} sid={entry.sid} "
                f"off=0x{entry.sites[0]:08X} tag={entry.tag}")
        if entry.speaker:
            head += f" speaker={escape_line(entry.speaker)}"
        lines.append(head)
        lines.append(f"○{entry.idx:08d}○{entry.tag}○{body}")
        lines.append(f"●{entry.idx:08d}●{entry.tag}●{body}")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# reports and IR
# --------------------------------------------------------------------------

def coverage_certificate(image: Image) -> dict:
    tier_bytes = {"T0": 0, "T1": 0, "T2": 0, "T3": 0, "T4": 0}
    status_counts: dict[str, int] = {}
    intervals = []
    for region in image.regions:
        size = region.end - region.start
        tier_bytes[region.decode_tier] = tier_bytes.get(region.decode_tier, 0) + size
        # status_counts is keyed by status and measured in BYTES, so the
        # certificate can be cross-checked against the interval list.
        status_counts[region.status] = status_counts.get(region.status, 0) + size
        intervals.append({
            "id": region.ident, "layer_id": "L000", "start": region.start,
            "end": region.end, "status": region.status, "kind": region.kind,
            "raw_sha256": region.raw_sha256, "owner": region.owner,
            "decode_tier": region.decode_tier,
            "tier_evidence_refs": list(region.evidence_refs),
            "rewrite_policy": "preserve" if region.status != "decoded" else "encode",
        })
    covered = sum(r.end - r.start for r in image.regions)
    present = [t for t, n in tier_bytes.items() if n]
    min_tier = min(present, key=lambda t: int(t[1:])) if present else "T0"
    return {
        "schema_version": "1.1.0", "layer_id": "L000", "source_size": len(image.data),
        "source_sha256": image.sha256, "source_md5": image.md5,
        "intervals": intervals, "gaps": [], "overlaps": [],
        "status_counts": status_counts,
        "byte_coverage": covered / len(image.data),
        "structural_coverage": covered / len(image.data),
        "tier_coverage": tier_bytes, "min_tier": min_tier,
        "declared_capabilities": ["roundtrip", "in_place"],
        "tier_blocked": image.tier_blocked,
        "instruction_coverage": "not_applicable",
        "toolchain": {"tool": "disassembler.py", "version": TOOL_VERSION,
                      "dialect": DIALECT["engine_id"]},
    }


def extract_report(image: Image) -> dict:
    tags: dict[str, int] = {}
    sources: dict[str, int] = {}
    for entry in image.texts:
        tags[entry.tag] = tags.get(entry.tag, 0) + 1
        sources[entry.tag_source] = sources.get(entry.tag_source, 0) + 1
    referenced = sum(1 for s in image.strings if s.sites)
    policies: dict[str, int] = {}
    for entry in image.texts:
        policies[entry.translate_policy] = policies.get(entry.translate_policy, 0) + 1
    shared = sum(1 for e in image.texts if e.alias_count)
    consumers = image.consumers or collect_argument_sites(image)
    no_consumer = sum(1 for e in image.texts if e.sites[0] not in consumers)
    return {
        "sample": image.path.name, "source_sha256": image.sha256,
        "source_size": len(image.data),
        "conststr_entries": len(image.strings),
        "referenced_entries": referenced,
        "unreferenced_entries": len(image.strings) - referenced,
        "reference_sites": len(image.site_to_sid),
        "exported_entries": len(image.texts),
        "shared_storage_entries": shared,
        "no_consumer_entries": no_consumer,
        "name_bindings": len(image.name_bindings),
        "ambiguous_name_bindings": sum(
            1 for b in image.name_bindings if b["confidence"] == "ambiguous"),
        "tag_counts": tags, "tag_source_counts": sources,
        "translate_policy_counts": policies,
        "functions_total": len(image.functions),
        "functions_with_bounds": sum(1 for f in image.functions if f.has_bounds),
        "functions_decoded": sum(1 for f in image.decoded if f.status == "decoded"),
        "functions_blocked": sum(1 for f in image.decoded if f.status != "decoded"),
        "instructions": sum(len(f.instructions) for f in image.decoded),
    }


def output_sanity(report: dict) -> dict:
    """SKILL.md §0.1.  A script sample cannot legitimately yield zero dialogue,
    and a translation surface that is mostly engine-internal strings is a defect
    in the extractor, not a property of the sample."""
    tags = report["tag_counts"]
    total = max(report["exported_entries"], 1)
    failures: list[str] = []
    if tags.get("msg", 0) == 0:
        failures.append("REQUIRED_TAG_ZERO: no dialogue extracted")
    if tags.get("name", 0) == 0:
        failures.append("REQUIRED_TAG_ZERO: no speaker names extracted")
    for tag, count in tags.items():
        if count / total > 0.95:
            failures.append(f"SKEWED_OUTPUT: '{tag}' is {count / total:.1%} of entries")
    unresolved = report["tag_source_counts"].get("unresolved", 0)
    if unresolved / total > 0.10:
        failures.append(
            f"UNRESOLVED_HEAVY: {unresolved:,} entries ({unresolved / total:.1%}) "
            "have no proven role; the call slot table is incomplete")
    return {"passed": not failures, "failures": failures,
            "exported_entries": report["exported_entries"], "tag_counts": tags,
            "tag_source_counts": report["tag_source_counts"]}


def shapes_report(image: Image) -> dict:
    """Shape signature per call form that consumes a string argument (§0.2).

    The signature is ``callee/argument-count``, which is exactly the unit the
    slot role table is keyed on, so an unseen call form shows up here as an
    unmatched signature instead of silently producing ``misc`` entries.
    """
    consumers = image.consumers or collect_argument_sites(image)
    observed: dict[str, dict[str, int]] = {}
    declared_shapes: set[str] = set()
    for site, uses in consumers.items():
        text = image.strings[image.site_to_sid[site]].text
        for callee, slot, total in uses:
            declared, role = slot_role(callee, slot)
            # Only shapes that are supposed to yield translatable text belong in
            # this report.  A slot declared as an asset identifier legitimately
            # produces no text, so counting it here would fake a barren shape.
            if declared and role is None:
                continue
            # A call form with no slot table is routed to one explicit
            # 'unresolved' branch rather than falling through to a role-bearing
            # branch, and is reported under that name (§0.2).
            signature = f"{callee}/{total}" if declared else "unresolved-call-form"
            declared_shapes.add(signature)
            bucket = observed.setdefault(signature, {"entries": 0, "texts": 0})
            bucket["entries"] += 1
            if text:
                bucket["texts"] += 1
    return {
        "sample": image.path.name,
        "declared": sorted(declared_shapes),
        "observed": observed,
        "unmatched": {},
    }


def write_ir(image: Image, ir_dir: Path) -> None:
    ir_dir.mkdir(parents=True, exist_ok=True)
    dump = lambda obj: json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

    (ir_dir / "manifest.jsonl").write_text(dump({
        "src_id": 0, "path": image.path.name, "sha256": image.sha256,
        "md5": image.md5, "size": len(image.data),
        "regions": len(image.regions), "text_entries": len(image.texts),
        "strings": len(image.strings), "join_sites": len(image.site_to_sid),
    }) + "\n", encoding="utf-8")

    (ir_dir / "regions.jsonl").write_text("\n".join(dump({
        "src_id": 0, "id": r.ident, "start": r.start, "end": r.end,
        "status": r.status, "kind": r.kind, "decode_tier": r.decode_tier,
        "owner": r.owner, "raw_sha256": r.raw_sha256,
        "evidence_refs": list(r.evidence_refs),
    }) for r in image.regions) + "\n", encoding="utf-8")

    # `source` is the escaped form, i.e. exactly what the ○ line carries, so the
    # anchor check compares like with like.  `source_raw` keeps the true text.
    (ir_dir / "text_entries.jsonl").write_text("\n".join(dump({
        "src_id": 0, "idx": e.idx, "sid": e.sid,
        "source": escape_line(e.text), "source_raw": e.text,
        "tag": e.tag, "tag_source": e.tag_source,
        "translate_policy": e.translate_policy, "sites": list(e.sites),
        "speaker": e.speaker, "alias_count": e.alias_count,
        "callees": list(e.callees),
    }) for e in image.texts) + "\n", encoding="utf-8")

    (ir_dir / "join_sites.jsonl").write_text("\n".join(dump({
        "src_id": 0, "join_id": f"J{index:06d}", "site_offset": site,
        "site_width": 4, "site_endianness": "little",
        "key_kind": "entry_id", "key_value": sid,
        "target_layer": "conststr", "target_object_id": sid,
        "collision_class": "unique" if len(image.strings[sid].sites) == 1 else "multi-site",
        "confidence": "observed", "rewrite_policy": "preserve",
        "evidence_refs": ["EV_CONSTSTR"],
    }) for index, (site, sid) in enumerate(sorted(image.site_to_sid.items()))) + "\n",
        encoding="utf-8")

    lines = []
    for func in image.decoded:
        for inst in func.instructions:
            lines.append(dump({
                "src_id": 0, "function": func.info.name, "offset": inst.offset,
                "size": inst.size, "opcode": inst.opcode, "mnemonic": inst.mnemonic,
                "text": inst.text, "target": inst.target,
                "string_sites": list(inst.string_sites),
            }))
    (ir_dir / "instructions.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    unreferenced = [dump({"src_id": 0, "sid": s.sid, "source": s.text,
                          "status": "unreferenced"})
                    for s in image.strings if not s.sites]
    (ir_dir / "unreferenced_strings.jsonl").write_text(
        ("\n".join(unreferenced) + "\n") if unreferenced else "", encoding="utf-8")

    (ir_dir / "name_bindings.jsonl").write_text(
        ("\n".join(dump({"src_id": 0, **binding}) for binding in image.name_bindings) + "\n")
        if image.name_bindings else "", encoding="utf-8")


def export(source: Path, out_dir: Path, want_texts: bool = True,
           want_asm: bool = False, with_ir: bool = False) -> dict:
    image = parse_source(source)
    out_dir = Path(out_dir)
    reports = out_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)

    cert = coverage_certificate(image)
    if cert["byte_coverage"] != 1.0:
        raise CsxError(f"byte coverage is {cert['byte_coverage']}, refusing to emit products")
    write_json(reports / "coverage_certificate.json", cert)
    report = extract_report(image)
    write_json(reports / "extract_report.json", report)
    sanity = output_sanity(report)
    write_json(reports / "output_sanity.json", sanity)
    if not sanity["passed"]:
        raise CsxError("output sanity gate failed: " + "; ".join(sanity["failures"]))
    write_json(reports / "shapes.json", shapes_report(image))
    write_json(reports / "window_hits.json", {"windows": {}, "note": "no scan windows are used"})

    if want_texts:
        target = out_dir / "texts" / f"{image.path.name}.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(target, render_texts(image), encoding="utf-8-sig")
    if want_asm:
        target = out_dir / "asm" / f"{image.path.name}.asm.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(target, render_asm(image), encoding="utf-8")
    if with_ir:
        write_ir(image, out_dir / "ir")
    return report


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=1,
                                       sort_keys=True) + "\n", encoding="utf-8")


def atomic_write_text(path: Path, text: str, encoding: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding=encoding, newline="\n")
    tmp.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cotopha CSX reader")
    parser.add_argument("source", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=None)
    parser.add_argument("--asm", action="store_true", help="also write the ASM listing")
    parser.add_argument("--no-texts", action="store_true", help="skip the two-line text file")
    parser.add_argument("--with-ir", action="store_true", help="also write ir/")
    args = parser.parse_args(argv)

    out = args.output or (args.source.parent / "output")
    if args.no_texts and not args.asm:
        parser.error("nothing to output: drop --no-texts or add --asm")
    report = export(args.source, out, want_texts=not args.no_texts,
                    want_asm=args.asm, with_ir=args.with_ir)
    print(json.dumps(report, ensure_ascii=False, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
