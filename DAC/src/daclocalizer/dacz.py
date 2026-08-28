# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

DEFAULT_ENCODING = "cp932"


@dataclass
class CryptoProfile:
    profile_id: str
    display_name: str
    algorithm: str
    encrypted_exts: list[str]
    decoded_ext_map: dict[str, str]
    filename_encoding: str
    params: dict[str, Any]
    probe: dict[str, Any]
    raw: dict[str, Any]


@dataclass
class DecodeResult:
    decoded: bytes
    profile_id: str
    profile_name: str
    key: int | None
    score: int
    status: str
    decoded_name: str
    params: dict[str, Any]
    reason: str = ""


def _tool_root() -> Path:
    # src/daclocalizer/dacz.py -> project root
    return Path(__file__).resolve().parents[2]


def _parse_int(v: Any) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 0)
    raise TypeError(f"invalid integer value in profile: {v!r}")


def load_profiles(extra_dirs: list[Path] | None = None) -> list[CryptoProfile]:
    """Load script crypto profiles.

    This is intentionally profile-driven: the tool does not store a fixed game key.
    It tries enabled profile JSON files, scores the decoded stream, and records the
    selected profile/key in IR. Add a new JSON file under profiles/ for another game.
    """
    roots = [_tool_root() / "profiles", Path.cwd() / "profiles"]
    if extra_dirs:
        roots.extend(extra_dirs)
    seen_files: set[Path] = set()
    profiles: list[CryptoProfile] = []
    for root in roots:
        if not root.exists():
            continue
        for fp in sorted(root.glob("*.json")):
            real = fp.resolve()
            if real in seen_files:
                continue
            seen_files.add(real)
            data = json.loads(fp.read_text(encoding="utf-8"))
            if not data.get("enabled", True):
                continue
            profiles.append(CryptoProfile(
                profile_id=data["profile_id"],
                display_name=data.get("display_name", data["profile_id"]),
                algorithm=data.get("algorithm", ""),
                encrypted_exts=[x.lower() for x in data.get("encrypted_exts", [])],
                decoded_ext_map={k.lower(): v for k, v in data.get("decoded_ext_map", {}).items()},
                filename_encoding=data.get("filename_encoding", DEFAULT_ENCODING),
                params=data.get("params", {}),
                probe=data.get("probe", {}),
                raw=data,
            ))
    return profiles


def is_cp932_lead(c: int) -> bool:
    return (0x81 <= c <= 0x9F) or (0xE0 <= c <= 0xFC)


def lower_cp932_path_bytes(bs: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(bs):
        c = bs[i]
        if is_cp932_lead(c):
            out.append(c)
            if i + 1 < len(bs):
                out.append(bs[i + 1])
                i += 2
            else:
                i += 1
        else:
            out.append(c + 0x20 if 0x41 <= c <= 0x5A else c)
            i += 1
    return bytes(out)


def normalize_name_bytes(name: str, profile: CryptoProfile, encoding: str | None = None) -> bytes:
    enc = encoding or profile.filename_encoding or DEFAULT_ENCODING
    bs = name.encode(enc, errors="strict")
    if profile.params.get("use_basename", True):
        for sep in (b"/", b"\\"):
            if sep in bs:
                bs = bs.rsplit(sep, 1)[1]
    if b"?" in bs:
        bs = bs.split(b"?", 1)[0]
    if profile.params.get("lowercase_ascii_preserve_cp932", True):
        bs = lower_cp932_path_bytes(bs)
    if profile.params.get("strip_final_z", True) and bs.endswith(b"z"):
        bs = bs[:-1]
    return bs


def derive_key_with_profile(name: str, byte_size: int, profile: CryptoProfile, encoding: str | None = None) -> int:
    if profile.algorithm != "filename_size_lcg":
        raise ValueError(f"unsupported script crypto algorithm: {profile.algorithm}")
    const = _parse_int(profile.params.get("const"))
    add = _parse_int(profile.params.get("add", 0))
    bs = normalize_name_bytes(name, profile, encoding)
    acc = 0
    for c in reversed(bs):
        signed_c = c if c < 0x80 else c - 0x100
        term = (((signed_c + byte_size) & 0xFFFFFFFF) * const) & 0xFFFFFFFF
        acc = (acc + term + add) & 0xFFFFFFFF
    return acc & 0xFF


def _crypt_lcg(data: bytes, key: int, profile: CryptoProfile, decrypt: bool, start_offset: int | None = None) -> bytes:
    const = _parse_int(profile.params.get("const"))
    add = _parse_int(profile.params.get("add", 0))
    if start_offset is None:
        start_offset = int(profile.params.get("start_offset", 0))
    out = bytearray(len(data))
    state = (((start_offset & 0xFFFFFFFF) * const) + add) & 0xFFFFFFFF
    for i, b in enumerate(data):
        stream = (((state >> 8) & 0xFF) + (state & 0xFF)) & 0xFF
        if decrypt:
            out[i] = ((b ^ stream) - key) & 0xFF
        else:
            out[i] = ((b + key) & 0xFF) ^ stream
        state = (state + const) & 0xFFFFFFFF
    return bytes(out)


def decrypt_with_profile(data: bytes, key: int, profile: CryptoProfile, start_offset: int | None = None) -> bytes:
    return _crypt_lcg(data, key, profile, True, start_offset)


def encrypt_with_profile(decoded: bytes, key: int, profile: CryptoProfile, start_offset: int | None = None) -> bytes:
    return _crypt_lcg(decoded, key, profile, False, start_offset)


def decoded_name_for_profile(src_name: str, profile: CryptoProfile) -> str:
    lower = Path(src_name).suffix.lower()
    mapped = profile.decoded_ext_map.get(lower)
    if mapped is not None:
        return src_name[: -len(Path(src_name).suffix)] + mapped
    if src_name.lower().endswith("z"):
        return src_name[:-1]
    return src_name + ".decoded"


def is_candidate_script_name(name: str, profiles: list[CryptoProfile] | None = None) -> bool:
    profiles = profiles or load_profiles()
    ext = Path(name).suffix.lower()
    if ext in {".dacz", ".iniz", ".dac", ".ini"}:
        return True
    return any(ext in p.encrypted_exts for p in profiles)


def score_decoded_stream(decoded: bytes, encoding: str, profile: CryptoProfile | None = None) -> tuple[int, str]:
    # Score is heuristic, used only to choose among known profiles. It is not a
    # regex text extractor; real text export still reads decoded IR/source lines.
    if not decoded:
        return 0, "empty"
    nul_ratio = decoded.count(0) / max(1, len(decoded))
    if nul_ratio > (profile.probe.get("negative_nul_ratio", 0.02) if profile else 0.02):
        return 0, f"too many NUL bytes: {nul_ratio:.3f}"
    try:
        text = decoded.decode(encoding)
        decode_bonus = 25
    except UnicodeDecodeError as e:
        # Many valid source files may be large; tolerate a small tail/fragment issue
        # but penalize it heavily.
        text = decoded.decode(encoding, errors="ignore")
        decode_bonus = 5 if len(text) > len(decoded) * 0.50 else 0
    sample = text[:8192]
    printable = sum(1 for ch in sample if ch in "\r\n\t" or ord(ch) >= 0x20)
    printable_ratio = printable / max(1, len(sample))
    score = int(printable_ratio * 25) + decode_bonus
    markers = (profile.probe.get("positive_markers") if profile else None) or [".call", ".include", "set_subtitle", "台詞", "選択肢", "//", "$."]
    hits = [m for m in markers if m in sample]
    score += min(40, len(hits) * 8)
    line_count = sample.count("\n") + sample.count("\r")
    if line_count >= 3:
        score += 10
    if sample.startswith("\ufeff"):
        score += 2
    reason = f"printable={printable_ratio:.2f}; markers={hits[:8]}; lines={line_count}"
    return score, reason


def auto_decode_script(data: bytes, src_name: str, encoding: str = DEFAULT_ENCODING, profiles: list[CryptoProfile] | None = None) -> DecodeResult:
    profiles = profiles or load_profiles()
    ext = Path(src_name).suffix.lower()
    # Plain decoded source fallback.
    if ext in {".dac", ".ini"}:
        score, reason = score_decoded_stream(data, encoding, None)
        return DecodeResult(data, "plain", "Plain text script", None, score, "plain", src_name, {}, reason)

    candidates = [p for p in profiles if (not p.encrypted_exts or ext in p.encrypted_exts)]
    best: DecodeResult | None = None
    for profile in candidates:
        try:
            key = derive_key_with_profile(src_name, len(data), profile, encoding=profile.filename_encoding or encoding)
            dec = decrypt_with_profile(data, key, profile)
            score, reason = score_decoded_stream(dec, encoding, profile)
            res = DecodeResult(dec, profile.profile_id, profile.display_name, key, score, "decoded", decoded_name_for_profile(src_name, profile), profile.raw, reason)
        except Exception as e:
            res = DecodeResult(data, profile.profile_id, profile.display_name, None, 0, "failed", src_name + ".raw", profile.raw, str(e))
        if best is None or res.score > best.score:
            best = res
    if best is None:
        return DecodeResult(data, "none", "No matching profile", None, 0, "preserve_exact", src_name + ".raw", {}, "no profile candidate")
    min_score = int(best.params.get("probe", {}).get("min_score", 35)) if isinstance(best.params.get("probe"), dict) else 35
    # raw params is full profile JSON; fetch from profile object if available by id.
    for p in profiles:
        if p.profile_id == best.profile_id:
            min_score = int(p.probe.get("min_score", min_score))
            break
    if best.score < min_score:
        return DecodeResult(data, "none", "No profile passed probe", None, best.score, "preserve_exact", src_name + ".raw", {}, f"best={best.profile_id}; {best.reason}")
    return best


def get_profile(profile_id: str, profiles: list[CryptoProfile] | None = None) -> CryptoProfile:
    for p in profiles or load_profiles():
        if p.profile_id == profile_id:
            return p
    raise KeyError(f"script crypto profile not found: {profile_id}")


def encode_with_profile_id(decoded: bytes, src_encrypted_name: str, profile_id: str, encoding: str = DEFAULT_ENCODING) -> tuple[bytes, int]:
    profile = get_profile(profile_id)
    key = derive_key_with_profile(src_encrypted_name, len(decoded), profile, encoding=profile.filename_encoding or encoding)
    return encrypt_with_profile(decoded, key, profile), key


# Backward-compatible wrappers. They use the default profile file rather than a
# fixed per-game key; callers should prefer auto_decode_script/encode_with_profile_id.
def _default_profile() -> CryptoProfile:
    profiles = load_profiles()
    for p in profiles:
        if p.profile_id == "dac_filename_size_lcg":
            return p
    if not profiles:
        raise RuntimeError("no crypto profiles loaded")
    return profiles[0]


def derive_dacz_key(name: str, byte_size: int, encoding: str = DEFAULT_ENCODING) -> int:
    return derive_key_with_profile(name, byte_size, _default_profile(), encoding)


def decrypt_dacz(data: bytes, key: int, start_offset: int = 0) -> bytes:
    return decrypt_with_profile(data, key, _default_profile(), start_offset)


def encrypt_dacz(decoded: bytes, key: int, start_offset: int = 0) -> bytes:
    return encrypt_with_profile(decoded, key, _default_profile(), start_offset)


def decoded_name_for(src_name: str) -> str:
    return decoded_name_for_profile(src_name, _default_profile())


def encoded_name_for(decoded_name: str) -> str:
    lower = decoded_name.lower()
    if lower.endswith(".dac") or lower.endswith(".ini"):
        return decoded_name + "z"
    return decoded_name


def decode_file(path: Path, out_path: Path | None = None, encoding: str = DEFAULT_ENCODING) -> bytes:
    res = auto_decode_script(path.read_bytes(), path.name, encoding)
    if res.status != "decoded" and res.status != "plain":
        raise ValueError(f"no script crypto profile passed probe for {path.name}: {res.reason}")
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(res.decoded)
    return res.decoded


def encode_file(decoded_path: Path, output_path: Path, source_encrypted_name: str | None = None, encoding: str = DEFAULT_ENCODING) -> bytes:
    dec = decoded_path.read_bytes()
    name = source_encrypted_name or output_path.name
    profile = _default_profile()
    key = derive_key_with_profile(name, len(dec), profile, encoding)
    enc = encrypt_with_profile(dec, key, profile)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(enc)
    return enc
