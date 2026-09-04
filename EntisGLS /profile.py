"""数据档加载：把作品专属的事实与代码分开。

代码不含任何作品字面量——封包密码、调用参数槽位角色这类东西全部来自
``profiles/*.json``。适配新作品只需追加或修改一份数据档，不改代码。
"""

from __future__ import annotations

import json
from pathlib import Path

PROFILE_DIR = Path(__file__).resolve().parent / "profiles"


def _load_all() -> list[dict]:
    if not PROFILE_DIR.is_dir():
        return []
    out = []
    for path in sorted(PROFILE_DIR.glob("*.json")):
        try:
            out.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    return out


_PROFILES = _load_all()


def reload() -> None:
    """重新读取数据档，便于外部改动后立即生效。"""
    global _PROFILES
    _PROFILES = _load_all()


def archive_password(archive_name: str) -> str | None:
    """按封包文件名查密码；没有记录就返回 None，由调用方决定如何处理。"""
    name = Path(archive_name).name.lower()
    for profile in _PROFILES:
        keys = profile.get("archive_keys", {}).get("keys", {})
        if name in keys:
            return keys[name]
    return None


def call_slot_roles() -> dict[str, dict]:
    """合并各数据档的调用槽位声明，槽位键从 JSON 字符串转回整数。"""
    merged: dict[str, dict] = {}
    for profile in _PROFILES:
        calls = profile.get("call_slot_roles", {}).get("calls", {})
        for callee, layout in calls.items():
            merged[callee] = {
                "slots": {int(k): v for k, v in layout.get("slots", {}).items()},
                "rest_from": layout.get("rest_from"),
                "rest": layout.get("rest"),
            }
    return merged
