from __future__ import annotations

import json
from pathlib import Path


def get_config_path() -> Path:
    return Path(__file__).resolve().parents[2] / "gui_config.json"


def load_config() -> dict:
    path = get_config_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(payload: dict) -> None:
    try:
        get_config_path().write_text(
            json.dumps(payload, ensure_ascii=False, indent=4),
            encoding="utf-8",
        )
    except Exception:
        pass


def reset_config() -> None:
    try:
        path = get_config_path()
        if path.exists():
            path.unlink()
    except Exception:
        pass
