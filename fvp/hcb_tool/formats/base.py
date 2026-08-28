from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class FormatPlugin(ABC):
    plugin_id: str = "base"
    display_name: str = "Base format"
    version: str = "0.0.0"

    @abstractmethod
    def probe(self, path: Path, data: bytes) -> float:
        """Return confidence 0.0..1.0."""

    def decode_layers(self, data: bytes, options: Any | None = None) -> tuple[bytes, dict]:
        return data, {"layers": [{"kind": "raw", "lossless": True}]}

    @abstractmethod
    def disassemble(self, path: Path, decoded: bytes, options: Any | None = None) -> dict:
        """Return full IR dictionary."""

    @abstractmethod
    def build_doubleline_entries(self, ir: dict, options: Any | None = None) -> list[dict]:
        """Build editable text entries from IR, not by regex scanning."""

    @abstractmethod
    def apply_doubleline_entries(self, ir: dict, entries: list[dict], options: Any | None = None) -> tuple[list[dict], list[dict]]:
        """Return patches and report entries."""

    def repack(self, ir: dict, layer_info: dict, options: Any | None = None) -> bytes:
        source_path = Path(ir["source_path"])
        return source_path.read_bytes()
