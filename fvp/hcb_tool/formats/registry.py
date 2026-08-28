from __future__ import annotations

from pathlib import Path
from .base import FormatPlugin
from .hcb import HCBPlugin


_PLUGINS: list[FormatPlugin] = [HCBPlugin()]


def iter_plugins() -> list[FormatPlugin]:
    return list(_PLUGINS)


def find_best_plugin(path: str | Path, data: bytes) -> tuple[FormatPlugin, float]:
    path = Path(path)
    scored = sorted(((p.probe(path, data), p) for p in _PLUGINS), key=lambda x: x[0], reverse=True)
    score, plugin = scored[0]
    if score <= 0:
        raise ValueError(f"no format plugin recognized {path}")
    return plugin, score
