# SILKY'S ENGINE .MES — VM analysis and evidence ledger

Single source of truth for `opcodelist.py`, `disassembler.py`, `assembler.py`
and `run_gui.py`. Every dialect value in `opcodelist.py` traces to an `EV_*`
entry here.

Corpus: 59 files (58 `.MES` + `LIBLARY.LIB`), 9.6 MB, from
`E:\fuyukuru_dl\SILKYSIMAGE\新建文件夹` (ORCSOFT『冬のフクロウ』/ fuyukuru).

## Declared capability

```
analysis_mode   bytecode-disasm
declared_tier   T3  instruction-stream
unpack_mode     not-required        code and text are directly visible
text_source     embedded
byte_coverage   1.0   (59/59 files)
roundtrip       byte-identical (59/59 files)
repack          identity / in_place / pointer-rewrite
not claimed     T4 semantic-cfg — no basic-block or stack-effect model
```

T3 is claimed because every byte of every file is assigned to an instruction
with a known length and operand schema, with no `unknown_opaque_block` and no
`tier_blocked`. T4 is **not** claimed: jump targets are resolved and relocated,
but no control-flow graph or stack-effect analysis exists, so structural editing
(`full-layout`) is refused rather than attempted.

## Architecture

Stack VM. Values are pushed by explicit `PUSH` instructions and consumed by a
single dispatching `SYSCALL` opcode whose id is the immediately preceding
immediate. Linear instruction stream, no separate data or string section:
string literals are inline operands.

**Endianness is mixed and this is the most common way to get the format wrong:**

| Region | Endianness |
|---|---|
| header integers and offset tables | little |
| instruction operands (`PUSH`, `JMP`, `CALL`) | big |

### EV_HEADER_LAYOUT — header
- Evidence level: `derived`
- Layout: `u32 n_labels, u32 n_entries, u32 labels[n_labels], u32 entries[n_entries]`.
  Code begins at `8 + 4*n_labels + 4*n_entries`.
- Cross-check: computed code start lands on a valid first instruction in all 59
  files. In the 51 files whose `n_entries` is 0, the first code byte is `0x32`
  (`PUSH`) in 50 cases; the exception is `_SAMPLE.MES`, a debug build.
- `n_labels` ranges 0..1866; `n_entries` is 0 or 1 except `_SAMPLE.MES` (2).

### EV_HEADER_LABELS / EV_HEADER_ENTRIES — offset tables
- Evidence level: `observed`
- Values are byte offsets **relative to code start**, not absolute.
- This is the decisive constraint in the whole analysis: across the corpus,
  **every one of the ~24,000 label values lands exactly on an instruction
  boundary** under the operand-width table below. A wrong table desynchronises
  the linear decode and misses thousands of them, so `parse()` raises
  `LabelMisaligned` rather than continuing.

### EV_OPERAND_ENDIAN — operand byte order
- Evidence level: `derived`
- Jump operands interpreted big-endian resolve to in-range instruction
  boundaries; little-endian interpretation yields values far beyond file size.

## Instruction encoding

One-byte opcode. Three length classes:

### EV_PUSH_IMM / EV_JUMP_TARGETS / EV_OP19_WIDTH — 5-byte instructions
- `0x32 PUSH imm32`, `0x14 JMP`, `0x15 CALL`, `0x19`
- Evidence level: `observed` for `0x32`, `derived` for the rest
- `EV_OP19_WIDTH` is worth stating explicitly because it is easy to miss and
  its absence is silent: treating `0x19` as a 1-byte opcode still produces a
  decoder that reaches EOF cleanly and still satisfies every label target, but
  the observed distinct-opcode count inflates from **51 to all 256** and 154
  dialogue strings fail the oracle. The inflated opcode count is the signal.

### EV_STR_OPCODES — NUL-terminated string operands
- Evidence level: `observed`
- `0x33 PUSHS` — identifiers: filenames, config paths, speaker names (77,890)
- `0x0A PUSHM` — message text (47,929)
- Two separate string opcodes, not one. `0x0A` is the dialogue carrier.

### Single-byte opcodes
Every other value, no operand. Only **51 distinct opcodes** occur across 9.6 MB
once `0x19` is handled correctly. Their individual semantics are not modelled
(that would be T4) and are rendered as `.op 0xNN`; they are preserved verbatim,
which is sufficient for byte-exact rebuild.

### EV_SYSCALL_DISPATCH — syscall
- Evidence level: `derived`
- Opcode `0x18`; the id is the operand of the immediately preceding `0x32`
  (98.1% of 166,134 sites). 21 distinct ids observed.

## Syscall roles

### EV_MSG_SYSCALL — id 0x16 is message display
- Evidence level: `derived`
- Message groups are terminated by syscall `0x16` in 14,143 of 14,145 sampled
  cases. Near-total exclusivity in both directions. See EV_MESSAGE_JOIN for how
  a group spans several strings.

### EV_NAME_SYSCALL / EV_NAME_BRACKET — speaker names
- Evidence level: `observed`
- Names are `0x33` strings delimited `【...】`, pushed for syscall `0x1D`, and
  bind to the next `0x0A` message. Verified by reading the resulting
  name/dialogue alternation as coherent conversation across several files.
- Binding method is structural (bracket + syscall group), not adjacency-only, so
  it does not depend on argument order. Syscall `0x1D` also carries `.akb`
  image filenames, so the bracket predicate is required to separate them; the
  rule that matches names is declared *before* the filename rules so it cannot
  be shadowed.

### EV_ASSET_SYSCALLS / EV_CONFIG_SYSCALL — non-text strings
- Evidence level: `derived`
- `0x12` voice `.ogg`, `0x1B`/`0x13` image `.akb`, `0x10` sound `.wav`,
  `0x17` video `.vsd`, `0x15` script `.mes`, `0x19`/`0x0F` `/Config/...` keys.
- All are tagged `label` / `frozen`: exported so a translator can see them, but
  rejected if modified.

### EV_ASSET_EXTENSIONS / EV_TRANSITION_CODES / EV_ASCII_TOKENS
- Evidence level: `inferred` (`tag_source=heuristic`)
- Some asset strings are pushed with no syscall inside the window. They are
  classified by appearance: known extension, the 4 transition codes
  (`fi` `fo` `wi` `wo`), or pure ASCII. Appearance rules are used **only** to
  subdivide strings already proven to be string operands, never to discover
  text, and their verdicts are marked `inferred`.

### EV_SHAPE_MSG_IN_0X33 — shape variant
- Evidence level: `inferred`, individually confirmed against the oracle
- 9 dialogue lines are stored uncompressed in `0x33` with no consuming syscall
  in the window. Confirmed as real dialogue because their bytes hash-match the
  oracle. Handled as an explicit declared shape rather than by widening the
  window, so the other 125,828 entries keep their existing classification.

## EV_KANA_TABLE — the substitution table

The non-obvious part of the format, and the reason a naive cp932 decode yields
garbage.

Inside string operands, bytes `0x01..0x53` are **not** cp932. They are
single-byte codes for hiragana:

```
char = chr(0x3040 + code)        # 0x02 -> あ, 0x04 -> い, 0x0B -> か, 0x53 -> ん
```

Tokenisation: cp932 lead bytes (`0x81-0x9F`, `0xE0-0xEF`) consume two bytes and
are literal; `0x01..0x53` expand via the rule above; everything else is literal.

**How it was derived, not guessed.** `chs.json` (sibling of the script folder) is
a pre-existing third-party Chinese translation whose 33,231 keys are
`sha1(original_japanese_cp932_bytes)`. That is an oracle: a candidate decoding
is provably correct when its hash is a key.

1. 407 dialogue strings contain exactly one substitution code. For each, all
   7,336 valid two-byte cp932 characters were substituted and hashed.
2. 25 codes resolved uniquely this way (`0x02→あ`, `0x04→い`, `0x0B→か`,
   `0x14→ご`, `0x2F→は`, `0x53→ん`, ...).
3. All 25 fit `chr(0x3040 + code)` with **zero** exceptions. The fit was tested
   against 14 candidate offsets; only `+0x3040` matched, and it matched 25/25.

Full-corpus result: **48,086 of 48,093** extracted engine lines hash-match the
oracle (99.985%), across 30,146 merged messages. All 6 non-matching are repeated-filler test strings in
`_SAMPLE.MES` (`あああ…`, `２２２…`), a developer file absent from the shipped
translation; they decode correctly and were simply never translated.

## EV_MESSAGE_JOIN — one sentence is stored as 1–3 strings

- Evidence level: `observed`
- A single spoken line is emitted as up to three consecutive `0x0A` strings
  joined by the opcode pair `1C 00` (the engine's line-break instruction), with
  one `0x16` syscall for the whole group.
- All **17,947** separators in the corpus are exactly `1C 00`, with no variants,
  and group sizes are only 1 (17,527), 2 (7,271) or 3 (5,338).
- Consequence: the 48,093 raw dialogue strings are really **30,146 messages**.
  Extracting them as separate entries splits sentences mid-clause — an opening
  `「` in one entry and its closing `」` two entries later — which makes the text
  unusable for a translator who needs to see the whole utterance.

The parts are therefore merged into one editable entry, with `\n` marking each
engine line break and `lines=N` in the comment. Two measured properties make
this safe:

| Property | Measurement | Why it matters |
|---|---|---|
| No jump targets a non-first part | 0 of 12,609 groups | merging cannot break control flow |
| No dialogue contains a literal `\` | 0 of 48,083 strings | the `\n` escape is unambiguous |

On repack the entry is split back on `\n` and **each part is written to its own
original site**, so the stored layout is unchanged. The line count is fixed by
the engine (each line is a separate string operand), so changing the number of
`\n` is rejected in both directions rather than silently reflowed — adding or
removing a line would mean inserting or deleting instructions, a full-layout
operation.

Note the oracle keys each engine line **separately** (12,609 of 12,609 groups
match per part; only 1 matches in joined form). That is why merging is a
presentation decision at the text-file layer only, and the oracle gate checks
part by part.

## EV_CHOICE_BLOCK — player choices, opcode 0x1B

- Evidence level: `observed`
- A player-visible choice is registered as:

```
1B <u32 BE code offset>   <message string>   00
```

  The operand is the branch taken when that option is picked; the option text
  immediately follows as a message string.

- **0x1B is context-dependent.** In library files (`LIBLARY.LIB`) the same value
  occurs as a genuine no-operand opcode. It is read as 5 bytes only when the
  operand resolves inside the file — a decidable test, not a preference. With
  that rule: 10 choices in fuyukuru and 52 in title "1", with **zero misaligned
  targets**; the 2 candidates in `LIBLARY.LIB` are rejected because their
  operands (0x3C320008) exceed the file size by orders of magnitude.

- Treating `0x1B` as 1 byte inflates the distinct-opcode count (84 → 90 in
  fuyukuru, 80 → 126 in title "1") because the swallowed target bytes are then
  decoded as instructions.

### Why this was missed at first

The choice text still appeared in the output, but tagged `msg` by the
`message-unanchored` fallback rule, with `choice` count **zero**. Every byte
gate passed. This is the §0.1 failure mode a second time: a fallback rule that
absorbs unrecognised structure hides the fact that the structure is
unrecognised. The fix was to identify the real anchor; the guard is
`EXPECTED_TAG_ZERO` in `check_output_sanity.py`, which now fails when a corpus
this size yields no choices at all.

Cross-checks:
- The 10 fuyukuru choices match the published walkthrough exactly (5 save points
  × 2 options), including `我慢なんかしてません。` and `気持ち悪くなんかないよ。`
- All 10 hash-match the independent translation database, confirming they are
  real translatable strings and not misparsed bytes.
- Choice targets are relocated on variable-length repack and verified to point at
  the same *logical instruction* (by ordinal), not merely at some valid
  boundary. Missing this would silently reroute a branch in a still-loadable
  file.

### EV_KANA_SCOPE — the table applies only to 0x0A
- Evidence level: `observed`
- Measured, not assumed: **0** of 77,689 `0x33` strings need expansion to match
  the oracle (the 17,371 that match, match identically either way), while
  46,107 of 47,928 `0x0A` strings contain codes.
- Expanding `0x33` corrupts filenames: `black.akb` becomes `black<の>akb`,
  because `0x2E` there is a literal `.`, not a code for `の`. This was an actual
  bug in the first draft, caught by inspecting output rather than by any hash or
  coverage check — neither of which can see it.

## Repack

No stored offset points at a string body; string operands are positional in the
instruction stream. So a length change requires relocating exactly three classes
of stored offset, all code-relative:

1. header label table
2. header entry table
3. `JMP` / `CALL` operands

`apply_edits()` builds one old→new offset map from the re-emitted stream and
applies it **by site**. Values are never matched: a `PUSH` constant that happens
to equal an old code offset must remain untouched. `FK029.MES` contains exactly
one such collision (`PUSH 0x80` at `0x72FF`); after a +230-byte repack it is
unchanged while 216 genuine jump sites relocated. `scripts/check_sites.py`
enforces this and fails on a forged value-matched rewrite.

Strategy is chosen by probe, minimum capability first, and a failed `run` never
falls back to another strategy.

| Situation | Strategy | Verified |
|---|---|---|
| no edits | `identity` | 59/59 byte-identical |
| edits fit original slots | `in_place` | −92 bytes, reparses |
| edits exceed slots | `pointer-rewrite` | +230 bytes, reparses, all edits present |
| instruction/data edited in asm | refused, needs T4 | refusal verified, no output written |

## EV_VARIANT_0B — second title, second dialogue opcode

- Evidence level: `observed`
- A second corpus (`E:uyukuru_dl\SILKYSIMAGE`, 241 files) is the same
  engine: identical header layout, identical code-start computation, identical
  prologue bytes, identical 5-byte operand set. It is an **L2 variant** in the
  sense of SKILL.md 7.5, not a new profile.
- What differs: dialogue is carried by opcode **`0x0B`**, and the strings are
  **plain cp932 with no kana substitution** (10 distinct stray single bytes,
  versus 80 in the compressed variant).
- Getting this wrong is silent in the byte gates. Parsing that corpus under the
  fuyukuru variant gives `byte_coverage=1.0`, byte-identical roundtrip for all
  241 files, and **114 dialogue lines against 25,064 names** — the exact
  signature described in SKILL.md 0. `check_output_sanity.py` and
  `check_variants.py` both catch it; nothing else does.

### Variant selection

By structural probe only, never by file or folder name (7.5.2). Each candidate
decodes the whole file; the winner is the one with the **fewest distinct
opcodes**, because a desynchronised decode walks through text and invents
opcodes that are not in the real instruction set. Measured separation:

| Corpus | correct variant | wrong variant |
|---|---|---|
| fuyukuru (59 files) | 51 opcodes | fails to decode |
| title "1" (241 files) | 65 opcodes | 249 opcodes |
| S04-30.MES alone | 33 opcodes | 207 opcodes |

The cp932-lead-byte ratio was tried as a *selector* first and rejected a valid
file at 0.1212 against a 0.12 cut, while the opcode counts for the same file were
33 versus 207. It is therefore demoted to a sanity bound on the winner only
(`MAX_LEAD_BYTE_RATIO_ABSOLUTE`), catching the case where every candidate is
desynchronised. **A signal that decides a knife-edge should not be the primary
discriminator when a far wider one is available.**

Files with no dialogue at all (`LIBLARY.LIB`, `MAIN.MES`, `FLAGINI.MES` and
friends) score identically under both variants, since the variants differ only in
how dialogue is stored. Those ties are harmless and recorded in
`variant_scores`; 7 such files in title "1" resolve to the fuyukuru variant.

Two residual artefacts, both in `LIBLARY.LIB` and both marked
`tag_source=heuristic` rather than presented as confirmed dialogue: the message
opcode value also occurs there as a genuine no-operand opcode, yielding a 1-2
character fragment (`ひ`, `そひ`). 2 spurious entries out of 70,190.

### Target encoding for title "1"

Its text is Chinese but stored **inside cp932 codepoints** — a font-hack
translation, which is what `chs.ttf` and `FontHook.ini` are for. So
`target_encoding=cp932` is correct for it too; only characters with no cp932
codepoint are rejected, and the importer names the offending character.

## Known limits and open questions

- The 51 single-byte opcodes are preserved but not individually named. Naming
  them requires host disassembly of `fuyukuru.exe` and would be a T4 claim.
- `0x19`'s semantics are unknown; only its 4-byte operand width is established.
- The high 16 bits of some syscall ids are unexplained.
- `full-layout` (inserting/deleting instructions) is not implemented.
- Inline control bytes inside dialogue (`0x05` etc., ~31 distinct values) are
  preserved byte-exactly as `{{XX}}` placeholders but their display semantics
  (ruby, wait, colour) are not decoded.
- Cross-sample validation now covers **two titles** (59 + 241 files, 300 total)
  with different variants, plus one independent translation database for the
  first. Both variants are exercised. There is no oracle for title "1" (it is
  already a translated release), so its dialogue is validated structurally and
  by reading, not by hash.
- The `0x0B` variant's single-byte opcodes are unnamed, same as the other
  variant's.
