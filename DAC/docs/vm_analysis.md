# VM / Script Layer Analysis

Target: DAC Hyper Net Media Player script resources in `script.dpk`.

## Container layer

- Archive magic: `DPK\0`.
- DPK index is protected by a rolling XOR envelope.
- Index entries contain payload offset, payload size, an unknown/reserved field, and a CP932 file name.
- Payloads are stored contiguously after the index. Repacking recalculates offsets and sizes in index order.

## Script layer

The `.dacz` / `.iniz` payload is not a compressed archive. It is a DAC text script / INI stream encrypted by the engine loader.

- Encrypted resource suffix: `.dacz`, `.iniz`.
- Decoded suffix: `.dac`, `.ini`.
- Key derivation: CP932 filename bytes, DBCS-aware ASCII lowercase, strip final `z`, fold each byte with file size and constant `0x713E66EB`, final key is low byte.
- Byte stream transform:
  - state starts at `(start_offset * 0x713E66EB + 0x71BD) & 0xFFFFFFFF`.
  - stream byte is `((state >> 8) + state) & 0xFF`.
  - decode byte is `((cipher ^ stream) - key) & 0xFF`.
  - encode byte is `((plain + key) & 0xFF) ^ stream`.

## VM form

After layer decoding, the resources are source-level DAC scripts, not a dense binary opcode stream. The tool therefore models each physical script line as an instruction-like IR node with:

- raw byte hash and byte span,
- source line number and physical offset,
- semantic opcode class such as `CALL.SPEAKER`, `TEXT.MSG`, `CALL.CHOICE`, `CALL.SUBTITLE`, `COMMAND`, `EXPRESSION`, `LABEL`, or `COMMENT`.

This is intentionally conservative: unknown/non-text bytes remain covered by the decoded script stream region and are not discarded.

## Rebuild strategy

- Zero-edit: decoded scripts are re-encoded and DPK is reserialized. Expected result is byte-exact identical to the original archive.
- Lengthened translation: whole decoded script files are rebuilt as CP932 text streams, then re-encrypted. DPK file offsets and sizes are dynamically recalculated.
- In-place mode: available through CLI flag `--in-place`; rejects longer target text entries.
