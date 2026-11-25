"""Text normalisation and injection signals. Rules: README.md, "What to build", part 1."""
from __future__ import annotations

import re
import unicodedata

# Hidden characters: zero-width space/joiners, word joiner, BOM, soft hyphen.
INVISIBLE = {"​", "‌", "‍", "⁠", "﻿", "­"}
# Bidi controls: ALM, LRM/RLM, LRE/RLE/PDF/LRO/RLO, LRI/RLI/FSI/PDI.
BIDI = {"؜", "‎", "‏", *map(chr, range(0x202A, 0x202F)), *map(chr, range(0x2066, 0x206A))}
# Arabic tatweel (U+0640) and the harakat/other marks U+064B-U+065F and U+0670.
ARABIC_MARKS = re.compile(r"[ـً-ٰٟ]")


def _is_tag(ch: str) -> bool:
    """True for a character in the Unicode Tags block (U+E0000-U+E007F)."""
    return 0xE0000 <= ord(ch) <= 0xE007F


def has_hidden_characters(text: str) -> bool:
    """True if `text` contains any invisible, bidi-control or Tags-block character."""
    raise NotImplementedError


def normalize(text: str) -> str:
    """Remove hidden characters, NFKC, strip Arabic tatweel/marks, casefold, collapse whitespace."""
    raise NotImplementedError


# The exact patterns from README.md, "What to build", part 1. Do not add your own: the grader's
# false-positive test is private, and extra patterns tend to fail it.
PATTERNS: dict[str, list[str]] = {
    "override": [
        r"\b(ignore|disregard|forget)\b (all |any )?(the )?(previous|prior|above|earlier|your) (instructions|rules|prompts?)",
        r"تجاهل (كل |جميع )?التعليمات",
        r"\byou are now\b",
    ],
    "role_tag": [
        r"(^|\s)(system|assistant|developer)\s*:",
        r"<\|im_start\|>|<\|im_end\|>|\[inst\]|\[/inst\]|</?system>",
    ],
    "action_request": [
        r"\bclose_alert\b",
        r"\b(close|resolve|suppress) (this|the|all) (alert|alerts|incident)s?\b",
        r"\bmark (it |this |them )?as (a )?false positive\b",
        r"\bset severity to (low|informational)\b",
    ],
    "exfil_markup": [
        r"!\[[^\]]*\]\(",
        r"<img\b",
    ],
}


def detect_injection(text: str) -> list[str]:
    """A sorted list of signal codes found in `text` (see README.md for the exact rules)."""
    raise NotImplementedError
