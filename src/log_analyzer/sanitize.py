import re
import unicodedata

DEFAULT_MAX_LENGTH = 1000
PLACEHOLDER = "?"
ELLIPSIS = "..."
LINE_SEPARATOR_CATEGORIES = frozenset({"Zl", "Zp"})

ANSI_PATTERN = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"
    r"|\x1b[ -/]+[0-~]"
    r"|\x1b[@-Z\\-~]"
)


def is_unsafe(char: str) -> bool:
    category = unicodedata.category(char)
    return category.startswith("C") or category in LINE_SEPARATOR_CATEGORIES


def replace_unsafe(text: str) -> str:
    return "".join(PLACEHOLDER if is_unsafe(char) else char for char in text)


def clean(text: str, max_length: int = DEFAULT_MAX_LENGTH) -> str:
    if max_length < 1:
        raise ValueError("max_length must be at least 1")
    stripped = ANSI_PATTERN.sub("", text)
    if len(stripped) <= max_length:
        return replace_unsafe(stripped)
    if max_length <= len(ELLIPSIS):
        return replace_unsafe(stripped[:max_length])
    return replace_unsafe(stripped[: max_length - len(ELLIPSIS)]) + ELLIPSIS
