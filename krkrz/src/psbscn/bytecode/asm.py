"""ASM 投影：带偏移标注、可读的值图转储。

ASM 视图只是审计产物。它由 IR 投影生成，绝不被反向解析，因此可以尽量详细。
共享节点在首次出现处发射一次，之后以 `-> @0xXXXX (共享)` 引用，从而如实反映
磁盘上的 DAG，而不是静默复制子树。
"""
from __future__ import annotations

import struct
from typing import Iterator

from ..formats import psb_spec as S

INDENT = "  "


def _fmt_scalar(doc, node) -> str:
    t = node.type
    if t in (S.T_NONE, S.T_NULL):
        return "null"
    if t == S.T_TRUE:
        return "true"
    if t == S.T_FALSE:
        return "false"
    if S.T_INT_BASE <= t <= S.T_INT_MAX:
        width = t - S.T_INT_BASE
        return f"int:{width} {node.int_value()}"
    if S.T_STRING_BASE <= t <= S.T_STRING_MAX:
        sid = node.string_id()
        return f"str #{sid} {_quote(doc.string_text(sid))}"
    if S.T_RESOURCE_BASE <= t <= S.T_RESOURCE_MAX:
        return f"res #{node.string_id()}"
    if t == S.T_FLOAT0:
        return "float0 0.0"
    if t == S.T_FLOAT32:
        return f"f32 {struct.unpack('<f', node.payload)[0]!r}"
    if t == S.T_FLOAT64:
        return f"f64 {struct.unpack('<d', node.payload)[0]!r}"
    if node.inline_table is not None:
        tbl = node.inline_table
        values = ", ".join(str(v) for v in tbl.values[:12])
        more = f", ...(+{len(tbl.values) - 12})" if len(tbl.values) > 12 else ""
        return (f"intarray[{len(tbl.values)}] cw={tbl.count_width} "
                f"ew={tbl.element_width} [{values}{more}]")
    return f"type{t}"


def _quote(text: str) -> str:
    escaped = (text.replace("\\", "\\\\").replace("\n", "\\n")
               .replace("\r", "\\r").replace("\t", "\\t").replace('"', '\\"'))
    return f'"{escaped}"'


def iter_asm_lines(doc, *, max_depth: int = 512) -> Iterator[str]:
    """逐行产出某个文档的完整 ASM 清单。"""
    h = doc.header
    yield f"; PSB v{h.version} 剧本反汇编"
    yield f"; 源文件    : {doc.source_name or '<内存>'}"
    yield f"; 长度      : {doc.size} (0x{doc.size:X}) 字节"
    yield f"; 编码      : {doc.strings.encoding}"
    yield (f"; 校验和    : 0x{h.checksum:08X} "
           f"(header[0x08:0x28] 的 adler32)")
    yield "; 分区："
    for name, start, end in doc.section_map():
        yield f";   {name:<14} 0x{start:06X}..0x{end:06X}  {end - start} 字节"
    yield (f"; 名称键    : {len(doc.names)} "
           f"(trie 节点 {len(doc.names.charset.values)}，"
           f"不可达 {doc.names.unreachable_node_count})")
    yield f"; 字符串    : {len(doc.strings)}"
    yield (f"; 值节点    : {len(doc.graph)} "
           f"(共享引用 {doc.graph.shared_hits})")
    yield ""
    yield ".names"
    for key_id, raw in enumerate(doc.names.names):
        yield f"  {key_id:5d}  {_quote(raw.decode(doc.strings.encoding, 'surrogateescape'))}"
    yield ""
    yield ".strings"
    for sid, rel in enumerate(doc.strings.offsets.values):
        yield f"  {sid:5d}  +0x{rel:06X}  {_quote(doc.strings.text(sid))}"
    yield ""
    yield ".entries"
    emitted: set[int] = set()
    nodes = doc.graph.nodes
    name_text = doc.names.text
    # 缩进串按深度缓存：这个循环跑十万级，每层重算同一个字符串没有意义。
    pads: list[str] = [""]
    stack: list[tuple[int, int, str]] = [(doc.graph.root, 0, "$")]
    push = stack.append
    while stack:
        offset, depth, label = stack.pop()
        node = nodes[offset]
        d = depth if depth < max_depth else max_depth
        while len(pads) <= d:
            pads.append(INDENT * len(pads))
        head = f"  0x{offset:06X}  {pads[d]}{label}"
        if offset in emitted:
            yield f"{head} -> @0x{offset:06X} (共享)"
            continue
        emitted.add(offset)
        ntype = node.type
        if ntype == S.T_COLLECTION:
            tbl = node.offset_table
            children = node.children
            yield (f"{head} collection[{len(children)}] "
                   f"cw={tbl.count_width} ew={tbl.element_width}")
            child_depth = depth + 1
            for i in range(len(children) - 1, -1, -1):
                push((children[i], child_depth, f"[{i}]"))
        elif ntype == S.T_OBJECT:
            tbl = node.offset_table
            children, keys = node.children, node.keys
            yield (f"{head} object[{len(children)}] "
                   f"cw={tbl.count_width} ew={tbl.element_width}")
            child_depth = depth + 1
            for i in range(len(children) - 1, -1, -1):
                push((children[i], child_depth, f".{name_text(keys[i])}"))
        else:
            yield f"{head} {_fmt_scalar(doc, node)}"


def render_asm(doc) -> str:
    return "\n".join(iter_asm_lines(doc)) + "\n"
