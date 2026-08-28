from __future__ import annotations

import json
from pathlib import Path

from ..io.json_io import load_jsonl
from ..io.translation_workflow_support import export_tag_for_row


def summary_command(dump_dir: Path) -> dict:
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    text_rows = load_jsonl(dump_dir / "text_entries.jsonl")
    message_rows = load_jsonl(dump_dir / "messages.jsonl")
    role_counts: dict[str, int] = {}
    tag_counts: dict[str, int] = {}
    for row in text_rows:
        for role in row["roles"]:
            role_counts[role] = role_counts.get(role, 0) + 1
        tag = export_tag_for_row(row)
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
    return {
        "script_sha256": manifest["script_sha256"],
        "text_sha256": manifest["text_sha256"],
        "text_entry_count": manifest["text_entry_count"],
        "message_event_count": manifest["message_event_count"],
        "role_counts": role_counts,
        "tag_counts": tag_counts,
        "sample_messages": message_rows[:10],
    }
