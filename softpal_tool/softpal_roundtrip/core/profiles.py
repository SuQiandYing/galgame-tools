from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping, Sequence

from .models import (
    InstructionSet,
    MessageEvent,
    NameTextContext,
    ScenarioBoundary,
    TextClassificationContext,
    TextEntry,
)
from ..crypto.softpal import SoftPalCipherConfig

if False:
    from ..engine.script_parser import ParsedScript


class AbstractGameProfile(ABC):
    name = "abstract"

    def get_text_codec(self) -> str:
        return "cp932"

    def get_instruction_set(self) -> InstructionSet:
        return InstructionSet()

    def get_text_header_size(self) -> int:
        return 0x10

    def get_no_name_sentinel(self) -> int:
        return 0x0FFFFFFF

    def get_text_cipher_config(self) -> SoftPalCipherConfig | None:
        return SoftPalCipherConfig(header_size=self.get_text_header_size())

    @abstractmethod
    def get_message_call_ids(self) -> set[int]:
        raise NotImplementedError

    @abstractmethod
    def get_font_call_ids(self) -> set[int]:
        raise NotImplementedError

    @abstractmethod
    def get_system_call_ids(self) -> set[int]:
        raise NotImplementedError

    def get_visible_ui_call_ids(self) -> set[int]:
        return set()

    def get_title_display_call_ids(self) -> set[int]:
        return set()

    def get_debug_call_ids(self) -> set[int]:
        return set()

    @abstractmethod
    def extract_message_events(
        self,
        script: "ParsedScript",
        text_map: Mapping[int, TextEntry],
    ) -> list[MessageEvent]:
        raise NotImplementedError

    @abstractmethod
    def detect_choice_text_offsets(
        self,
        script: "ParsedScript",
        text_map: Mapping[int, TextEntry],
    ) -> set[int]:
        raise NotImplementedError

    @abstractmethod
    def detect_label_text_offsets(
        self,
        script: "ParsedScript",
        text_map: Mapping[int, TextEntry],
    ) -> set[int]:
        raise NotImplementedError

    @abstractmethod
    def is_name_text(self, text: str, context: NameTextContext) -> bool:
        raise NotImplementedError

    @abstractmethod
    def is_choice_text(self, text: str, context: TextClassificationContext) -> bool:
        raise NotImplementedError

    @abstractmethod
    def classify_display_tag(self, text: str, context: TextClassificationContext) -> str:
        raise NotImplementedError

    @abstractmethod
    def classify_script_label_tag(self, text: str, context: TextClassificationContext) -> str:
        raise NotImplementedError

    @abstractmethod
    def classify_reference_tag(self, text: str, context: TextClassificationContext) -> str:
        raise NotImplementedError

    @abstractmethod
    def detect_scenario_split_boundaries(
        self,
        rows: Sequence[dict[str, Any]],
        messages: Sequence[dict[str, Any]],
    ) -> list[ScenarioBoundary]:
        raise NotImplementedError

    def primary_role_from_roles(self, roles: Sequence[str]) -> str:
        context = TextClassificationContext(
            entry=TextEntry(order=-1, idx=-1, entry_offset=-1, raw_text=b"", original_text=""),
            roles=tuple(roles),
            reference_offsets=(),
            direct_call_ids=(),
        )
        return context.primary_role

    def classify_entry_tag(self, context: TextClassificationContext) -> str:
        role = context.primary_role
        if role == "speaker_name":
            return "name"
        if role == "choice_text":
            return "choice"
        if role == "message_text":
            return "text"
        if role == "script_label":
            return self.classify_script_label_tag(context.entry.original_text, context)
        if role == "unreferenced":
            return self.classify_unreferenced_tag(context.entry.original_text, context)
        return self.classify_reference_tag(context.entry.original_text, context)

    def classify_unreferenced_tag(
        self,
        text: str,
        context: TextClassificationContext,
    ) -> str:
        return "unused"

    def build_manifest_extras(self) -> dict[str, Any]:
        return {}
