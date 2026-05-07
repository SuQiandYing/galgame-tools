from __future__ import annotations

from .compat_text import TRANSLATE_MARK


def first_message_context_map(message_rows: list[dict]) -> dict[int, dict]:
    ctx: dict[int, dict] = {}
    for row in message_rows:
        text_idx = int(row["text_idx"])
        if text_idx not in ctx:
            ctx[text_idx] = {
                "role": "message_text",
                "call_offset_hex": row["call_offset_hex"],
                "line_id_hex": row["line_id_hex"],
                "pair_idx": row["name_idx"],
                "pair_text": row["name"],
                "kind": row["kind"],
            }
        name_idx = row["name_idx"]
        if name_idx is not None:
            name_idx = int(name_idx)
            if name_idx not in ctx:
                ctx[name_idx] = {
                    "role": "speaker_name",
                    "call_offset_hex": row["call_offset_hex"],
                    "line_id_hex": row["line_id_hex"],
                    "pair_idx": row["text_idx"],
                    "pair_text": row["text"],
                    "kind": row["kind"],
                }
    return ctx


def export_tag_for_row(row: dict) -> str:
    return row["export_tag"]


def build_translate_blocks(text_rows: list[dict], message_rows: list[dict]) -> list[str]:
    ctx_map = first_message_context_map(message_rows)
    blocks: list[str] = []
    for row in text_rows:
        idx = int(row["idx"])
        tag = export_tag_for_row(row)
        comment_parts = [
            f"idx={idx}",
            f"off={row['entry_offset_hex']}",
            f"tag={tag}",
            f"refs={row['ref_count']}",
        ]
        if row.get("scenario_role"):
            comment_parts.append(f"scenario_role={row['scenario_role']}")
        if row.get("scenario_boundary_source"):
            comment_parts.append(f"scenario_src={row['scenario_boundary_source']}")
        if row.get("direct_call_ids_hex"):
            comment_parts.append("calls=" + ",".join(row["direct_call_ids_hex"]))
        ctx = ctx_map.get(idx)
        if ctx is not None:
            comment_parts.append(f"kind={ctx['kind']}")
            comment_parts.append(f"call={ctx['call_offset_hex']}")
            comment_parts.append(f"line={ctx['line_id_hex']}")
            comment_parts.append("pair=NONE" if ctx["pair_idx"] is None else f"pair={ctx['pair_idx']}")
        original_text = row["original_text"]
        line = f"{TRANSLATE_MARK}{idx:08d}{TRANSLATE_MARK}{tag}{TRANSLATE_MARK}{original_text}"
        blocks.append("\n".join(["# " + " ".join(comment_parts), line, line, ""]))
    return blocks


def build_translation_header(idx_start: int | None, idx_end: int | None) -> list[str]:
    return [
        "# SOFTPAL_TRANSLATE_V1",
        "# Supplemental tags: `title`=作品标题, `chapter_title`=章节标题, `route_title`=路线/分支标题, `replay_title`=回想标题。",
        "# 规则：每组只改第二行；第一行保持原文作对照；不要改动 `○编号○标签○` 这一段。",
        "# 标签说明：`name`=人名, `text`=正文/旁白, `choice`=可见选项文本, `label`=机器脚本标签, `label_text`=文本型分支锚点, `label_internal`=内部锚点/标签, `ui`=可见 UI 文本, `display`=可见的独立展示文本, `system`=系统提示, `font`=字体名, `kana`=假名索引, `symbol`=分隔符/符号文本, `asset`=资源名或路径, `config`=配置/内部 ID, `scenario`=场景 ID, `debug`=调试/格式串, `misc`=未识别的其他文本, `unused`=当前未被引用。",
        (
            "# 提取范围：ALL"
            if idx_start is None and idx_end is None
            else f"# 提取范围：idx {idx_start if idx_start is not None else '-inf'} .. {idx_end if idx_end is not None else '+inf'}"
        ),
        "#",
        "",
    ]
