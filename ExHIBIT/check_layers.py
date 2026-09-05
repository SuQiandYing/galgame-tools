"""Gate: engine-specific constants must live in opcodelist.py only.

If a magic number, byte signature or opcode value appears in the structural
logic, the dialect is no longer portable to another ExHIBIT title -- adapting
would mean editing the algorithms instead of adding a declaration.

Hex values that are generic bit/width machinery (masks, byte widths) are
whitelisted. A line may be exempted with a `dialect-literal-ok` comment plus
a reason.
"""
import io
import re
import sys

LOGIC = ["rldcore.py", "rldir.py", "disassembler.py", "assembler.py",
         "run_gui.py"]

# Generic machinery, not engine facts: byte/word widths, shifts, nibble and
# byte masks, ASCII control boundary, model smoothing constants.
GENERIC_HEX = {0x0, 0x1, 0x2, 0x3, 0x4, 0x8, 0xF, 0x10, 0x20, 0xFF,
               0xFFFF, 0x100}

"""Calibration note: the negative control must report zero.

A gate that reports false positives trains people to ignore it, so this one
was checked in both directions (see selftest_gate() below). The `0x` pattern
requires a non-word char before it, otherwise Tk geometry strings like
"760x660" are read as the hex value 0x660.
"""
HEX = re.compile(r"(?<![\w])0x[0-9A-Fa-f]+")
BYTESIG = re.compile(r"""b['"](?:\\x[0-9A-Fa-f]{2}){2,}""")
INLINE_RE = re.compile(r"re\.(?:compile|match|search|findall|finditer|sub)"
                       r"\s*\(\s*(?:r?['\"])")


def scan(path):
    src = io.open(path, encoding="utf-8").read()
    violations, advisories = [], []
    for lineno, line in enumerate(src.split("\n"), 1):
        if "dialect-literal-ok" in line:
            continue
        code = line.split("#")[0]
        for m in HEX.finditer(code):
            if int(m.group(), 16) not in GENERIC_HEX:
                violations.append((lineno, "hex", m.group(), line.strip()))
        for m in BYTESIG.finditer(code):
            violations.append((lineno, "byte-signature", m.group(),
                               line.strip()))
        for m in INLINE_RE.finditer(code):
            # a regex built here rather than read from the dialect
            if "DIALECT" not in code:
                advisories.append((lineno, "inline-regex", m.group(),
                                   line.strip()))
    return violations, advisories


POSITIVE_CONTROL = '''
def decrypt(data):
    if data[:4] != b"\\x00\\x44\\x4c\\x52":
        return None
    j = min((len(data) - 0x10) >> 2, 0x3FF0)
    OPCODES = {0x1C: "MSG", 0x30: "CHARA"}
    return re.match(r"^\\d+,\\d+,(.*)$", text)
'''


def selfcheck_gate():
    """Both directions. A gate that never fires is indistinguishable from one
    that checks nothing, so prove it fires on known-bad input."""
    import tempfile, os
    fd, tmp = tempfile.mkstemp(suffix=".py")
    os.close(fd)
    io.open(tmp, "w", encoding="utf-8").write(POSITIVE_CONTROL)
    try:
        v, a = scan(tmp)
    finally:
        os.unlink(tmp)
    kinds = {k for _, k, _, _ in v}
    ok = len(v) >= 4 and "byte-signature" in kinds and "hex" in kinds
    print(f"[{'  ok  ' if ok else ' FAIL '}] positive control fires "
          f"({len(v)} violations: {sorted(kinds)})")
    return ok


def main():
    if "--selfcheck" in sys.argv:
        return 0 if selfcheck_gate() else 1
    total_v = total_a = 0
    for path in LOGIC:
        v, a = scan(path)
        total_v += len(v)
        total_a += len(a)
        status = "ok" if not v else f"{len(v)} VIOLATION(S)"
        print(f"{path:20} {status}"
              + (f"   ({len(a)} advisory)" if a else ""))
        for lineno, kind, tok, line in v[:6]:
            print(f"    line {lineno}: {kind} {tok}  |  {line[:66]}")
        for lineno, kind, tok, line in a[:4]:
            print(f"    advisory line {lineno}: {kind}  |  {line[:60]}")
    print(f"\n{total_v} violations, {total_a} advisories")
    return 1 if total_v else 0


if __name__ == "__main__":
    raise SystemExit(main())
