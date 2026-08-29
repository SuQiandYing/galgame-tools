"""M2 kirikiri `*.txt.scn` 剧本的语义层定义。

结构由遍历全语料确认。根对象键为 `hash`、`name`、`outlines`、`scenes`。
每个场景带有 `firstLine`、`label`、`lines`、`nexts`、`spCount`、`title`，
以及可选的 `texts`、`jumplabels`、`postevals`、`selectInfo`、`selects`。

`texts[]` 条目是位置数组，长度为 6 或 9：

    [0] 说话人显示名（字符串或 null）
    [1] 次要说话人 / 注音式标注（通常为 null）
    [2] 正文——可见的台词，可能含 "\\n"
    [3] 语音描述列表（含 `name`/`pan` 的对象列表）或 null
    [4] 整数消息 ID
    [5] 舞台状态对象（`data`、`env`，可选 `meswintype`）
    [6] null                      （仅 9 槽形态）
    [7] 回想日志行 1               （仅 9 槽形态）
    [8] 回想日志行 2               （仅 9 槽形态）

槽位 7 与 8 保存的是与槽位 2 相同的句子、只是去掉了换行，因此翻译必须同时应用到
三处，才能保持回想记录一致。工具通过把它们归入同一个逻辑文本单元来处理。

`selects[]` 条目是含 `exp`、`render`、`selidx`、`text` 的对象；`text` 是可见的
选项标签。
"""
from __future__ import annotations

from dataclasses import dataclass, field

K_SCENES = "scenes"
K_TEXTS = "texts"
K_SELECTS = "selects"
K_TITLE = "title"
K_LABEL = "label"
K_NAME = "name"
K_TEXT = "text"
K_OUTLINES = "outlines"

SLOT_SPEAKER = 0
SLOT_SPEAKER_ALT = 1
SLOT_MESSAGE = 2
SLOT_VOICE = 3
SLOT_MESSAGE_ID = 4
SLOT_STATE = 5
SLOT_BACKLOG_A = 7
SLOT_BACKLOG_B = 8

TEXT_SLOT_TAGS = {
    SLOT_SPEAKER: "name",
    SLOT_SPEAKER_ALT: "name",
    SLOT_MESSAGE: "msg",
    SLOT_BACKLOG_A: "msg",
    SLOT_BACKLOG_B: "msg",
}

# --- 多语言嵌套形态 -----------------------------------------------------
# 另一类 M2 剧本（如 `*.ks.scn`）把正文放在**语言列表**里而不是平铺槽位：
#
#     texts[] = [说话人, [语言项, ...], 语音列表, 消息ID, 舞台状态]
#     语言项  = [显示名, 正文, 消息ID]                        （3 槽）
#             | [显示名, 正文, 消息ID, 回想行, 检索行]          （5 槽）
#
# 槽位 3/4 与正文同句、只去掉了控制码，作用等同于 9 槽形态的槽位 7/8，因此归入同一
# 逻辑文本单元。语言下标固定取 0：这是引擎的主语言位，与 VNTextPatch 的
# `LanguageIndex` 一致。
LANGUAGE_INDEX = 0
LANG_SLOT_NAME = 0
LANG_SLOT_TEXT = 1
LANG_SLOT_BACKLOG_A = 3
LANG_SLOT_BACKLOG_B = 4

LANG_SLOT_TAGS = {
    LANG_SLOT_NAME: "name",
    LANG_SLOT_TEXT: "msg",
    LANG_SLOT_BACKLOG_A: "msg",
    LANG_SLOT_BACKLOG_B: "msg",
}

K_LANGUAGE = "language"


@dataclass(slots=True)
class TextSite:
    """通过已证明的剧本路径可达的字符串值节点。"""

    node_offset: int
    string_id: int
    tag: str
    path: str
    scene_index: int
    entry_index: int
    slot: int
    speaker: str | None = None
    speaker_confidence: str = "derived"
    group_key: str = ""
    evidence: str = "derived"
    siblings: list[int] = field(default_factory=list)


def _is_string(doc, offset: int) -> bool:
    from ..formats import psb_spec as S
    node = doc.graph.nodes[offset]
    return S.T_STRING_BASE <= node.type <= S.T_STRING_MAX


def _child_by_key(doc, offset: int, key: str) -> int | None:
    """对象节点中 `key` 对应的子节点偏移，不存在则返回 None。"""
    from ..formats import psb_spec as S
    node = doc.graph.nodes[offset]
    if node.type != S.T_OBJECT:
        return None
    for key_id, child in zip(node.keys, node.children):
        if doc.names.text(key_id) == key:
            return child
    return None


def _children(doc, offset: int) -> tuple[int, ...]:
    from ..formats import psb_spec as S
    node = doc.graph.nodes[offset]
    return node.children if node.type == S.T_COLLECTION else ()


def _language_item(doc, offset: int) -> tuple[int, ...] | None:
    """若 `offset` 是语言列表，返回主语言项的槽位；否则返回 None。

    形态为 `[[显示名, 正文, ...], ...]`：外层按语言下标，内层是该语言的各字段。
    只有内层至少有名字与正文两槽时才认；否则视为普通集合，交回平铺路径处理。
    """
    outer = _children(doc, offset)
    if len(outer) <= LANGUAGE_INDEX:
        return None
    inner = _children(doc, outer[LANGUAGE_INDEX])
    if len(inner) < 2:
        return None
    return inner


def collect_text_sites(doc) -> list[TextSite]:
    """遍历 root.scenes[] 并返回每一个可翻译的字符串位点。

    只返回结构上已证明的位置：`texts[]` 的消息槽位、`selects[].text`、场景
    `title` 以及根 `outlines` 的标签。不做原始二进制扫描，不按外观猜测。
    """
    sites: list[TextSite] = []
    root = doc.graph.root
    scenes_off = _child_by_key(doc, root, K_SCENES)
    if scenes_off is None:
        return sites

    for scene_i, scene_off in enumerate(_children(doc, scenes_off)):
        title_off = _child_by_key(doc, scene_off, K_TITLE)
        scene_label = ""
        label_off = _child_by_key(doc, scene_off, K_LABEL)
        if label_off is not None and _is_string(doc, label_off):
            scene_label = doc.string_text(
                doc.graph.nodes[label_off].string_id())
        if title_off is not None and _is_string(doc, title_off):
            sites.append(TextSite(
                node_offset=title_off,
                string_id=doc.graph.nodes[title_off].string_id(),
                tag="ui", path=f"scenes[{scene_i}].title",
                scene_index=scene_i, entry_index=-1, slot=-1,
                group_key=f"s{scene_i}:title", evidence="derived"))

        texts_off = _child_by_key(doc, scene_off, K_TEXTS)
        for entry_i, entry_off in enumerate(_children(doc, texts_off or -1)
                                            if texts_off is not None else ()):
            slots = _children(doc, entry_off)
            speaker, speaker_conf = None, "unresolved"
            if len(slots) > SLOT_SPEAKER and _is_string(doc, slots[SLOT_SPEAKER]):
                speaker = doc.string_text(
                    doc.graph.nodes[slots[SLOT_SPEAKER]].string_id())
                speaker_conf = "observed"
            elif slots:
                speaker_conf = "narration"
            body_group = f"s{scene_i}:t{entry_i}:msg"
            for slot, tag in TEXT_SLOT_TAGS.items():
                if slot >= len(slots):
                    continue
                child = slots[slot]
                if not _is_string(doc, child):
                    continue
                group = (body_group if slot in
                         (SLOT_MESSAGE, SLOT_BACKLOG_A, SLOT_BACKLOG_B)
                         else f"s{scene_i}:t{entry_i}:name{slot}")
                sites.append(TextSite(
                    node_offset=child,
                    string_id=doc.graph.nodes[child].string_id(),
                    tag=tag,
                    path=f"scenes[{scene_i}].texts[{entry_i}][{slot}]",
                    scene_index=scene_i, entry_index=entry_i, slot=slot,
                    speaker=speaker, speaker_confidence=speaker_conf,
                    group_key=group, evidence="observed"))

            # 多语言嵌套形态：正文在语言列表里，平铺槽位是 null。槽位 1 与 2 都可能
            # 承载它，取决于该作把说话人放在哪一槽。
            for host in (SLOT_SPEAKER_ALT, SLOT_MESSAGE):
                if host >= len(slots):
                    continue
                lang = _language_item(doc, slots[host])
                if lang is None:
                    continue
                for lslot, tag in LANG_SLOT_TAGS.items():
                    if lslot >= len(lang):
                        continue
                    child = lang[lslot]
                    if not _is_string(doc, child):
                        continue
                    if lslot == LANG_SLOT_NAME:
                        group = f"s{scene_i}:t{entry_i}:langname"
                    else:
                        group = body_group
                    sites.append(TextSite(
                        node_offset=child,
                        string_id=doc.graph.nodes[child].string_id(),
                        tag=tag,
                        path=(f"scenes[{scene_i}].texts[{entry_i}][{host}]"
                              f"[{LANGUAGE_INDEX}][{lslot}]"),
                        scene_index=scene_i, entry_index=entry_i, slot=lslot,
                        speaker=speaker, speaker_confidence=speaker_conf,
                        group_key=group, evidence="observed"))
                break

        selects_off = _child_by_key(doc, scene_off, K_SELECTS)
        for sel_i, sel_off in enumerate(_children(doc, selects_off)
                                        if selects_off is not None else ()):
            # 选项同样可能带语言层：`selects[].language[LANGUAGE_INDEX].text`
            # 优先于平铺的 `selects[].text`；两者都存在时前者才是显示用的。
            text_off = None
            path = f"scenes[{scene_i}].selects[{sel_i}].text"
            lang_off = _child_by_key(doc, sel_off, K_LANGUAGE)
            if lang_off is not None:
                langs = _children(doc, lang_off)
                if len(langs) > LANGUAGE_INDEX:
                    cand = _child_by_key(doc, langs[LANGUAGE_INDEX], K_TEXT)
                    if cand is not None and _is_string(doc, cand):
                        text_off = cand
                        path = (f"scenes[{scene_i}].selects[{sel_i}]"
                                f".language[{LANGUAGE_INDEX}].text")
            if text_off is None:
                cand = _child_by_key(doc, sel_off, K_TEXT)
                if cand is not None and _is_string(doc, cand):
                    text_off = cand
            if text_off is not None:
                sites.append(TextSite(
                    node_offset=text_off,
                    string_id=doc.graph.nodes[text_off].string_id(),
                    tag="choice", path=path,
                    scene_index=scene_i, entry_index=sel_i, slot=-1,
                    speaker=scene_label or None,
                    speaker_confidence="derived",
                    group_key=f"s{scene_i}:sel{sel_i}", evidence="observed"))

    outlines_off = _child_by_key(doc, root, K_OUTLINES)
    for out_i, out_off in enumerate(_children(doc, outlines_off)
                                    if outlines_off is not None else ()):
        for key in (K_TITLE, K_LABEL, K_NAME):
            child = _child_by_key(doc, out_off, key)
            if child is not None and _is_string(doc, child):
                sites.append(TextSite(
                    node_offset=child,
                    string_id=doc.graph.nodes[child].string_id(),
                    tag="ui", path=f"outlines[{out_i}].{key}",
                    scene_index=-1, entry_index=out_i, slot=-1,
                    group_key=f"outline{out_i}:{key}", evidence="derived"))
    return sites
