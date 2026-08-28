from __future__ import annotations

from .chapter_detector import ChapterDetectorMixin
from .choice_detector import ChoiceDetectorMixin
from .parser_base import HCBParserBase
from .semantic_helpers import SemanticHelpersMixin
from .name_mapping import NameMappingMixin
from .semantics import SemanticsMixin
from .views import ViewsMixin


class _HCBParser(
    ChapterDetectorMixin,
    ChoiceDetectorMixin,
    SemanticsMixin,
    ViewsMixin,
    NameMappingMixin,
    SemanticHelpersMixin,
    HCBParserBase,
):
    """Opcode parser assembled from small mixins.

    The public behaviour is intentionally kept compatible with the previous
    single-file implementation; only the file/module layout changed here.
    """

    pass
