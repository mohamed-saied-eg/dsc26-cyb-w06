"""Checking the model's reply before an analyst sees it. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .normalize import detect_injection

SEVERITIES = ["informational", "low", "medium", "high", "critical"]
NEXT_STEPS = {"escalate_to_analyst", "request_more_context", "monitor", "open_incident"}
ALLOWED_LINK_HOSTS = {"attack.mitre.org", "hisn.local"}

_FORBIDDEN_KEYS = {"action", "actions", "tool_call", "tool_calls", "function_call"}
_TENANT_REF_RE = re.compile(r"TEN-[0-9]{3}")
_BARE_PATTERN = r"https?://[^\s<>]+"
_BARE_RE = re.compile(_BARE_PATTERN, re.IGNORECASE)
_MARKUP_RE = re.compile(
    r"(?P<image>!\[[^\]]*\]\([^)]*\))"
    r"|(?P<link>\[(?P<text>[^\]]*)\]\((?P<url>[^)\s]*)\))"
    r"|(?P<bare>" + _BARE_PATTERN + r")",
    re.IGNORECASE,
)
_TRAILING = ".,;:!?)'\""


class Rejected(Exception):
    """Raised by parse_model_output / triage when the reply cannot be accepted. Keeps .reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class TriageResult:
    severity: str
    summary_html: str
    next_step: str
    related_alert_ids: list[str]
    flags: list[str] = field(default_factory=list)


def _host_allowed(url: str) -> bool:
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and host in ALLOWED_LINK_HOSTS


def _clean_summary(summary: str) -> tuple[str, set[str]]:
    flags: set[str] = set()

    def fix_bare(m: re.Match) -> str:
        url = m.group(0)
        core = url.rstrip(_TRAILING)
        tail = url[len(core):]
        if _host_allowed(core):
            return url
        flags.add("link_removed")
        return "[link removed]" + tail

    def repl(m: re.Match) -> str:
        if m.group("image") is not None:
            flags.add("image_removed")
            return "[image removed]"
        if m.group("link") is not None:
            if _host_allowed(m.group("url")):
                return m.group("link")
            flags.add("link_removed")
            return _BARE_RE.sub(fix_bare, m.group("text"))
        return fix_bare(m)

    return _MARKUP_RE.sub(repl, summary), flags


def _extract_json_text(raw: str) -> str:
    text = raw.strip()
    lines = text.split("\n")
    if len(lines) >= 2 and lines[0].strip() in ("```json", "```") and lines[-1].strip() == "```":
        text = "\n".join(lines[1:-1])
    return text


def parse_model_output(raw: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult:
    """Parse, validate and clean one model reply."""
    # 1. JSON object or nothing
    try:
        data = json.loads(_extract_json_text(raw))
    except (ValueError, RecursionError):
        raise Rejected("not_json")
    if not isinstance(data, dict):
        raise Rejected("not_json")

    # 2. forbidden actions
    if _FORBIDDEN_KEYS & set(data.keys()):
        raise Rejected("forbidden_action")
    next_step = data.get("next_step")
    if isinstance(next_step, str) and "close" in next_step:
        raise Rejected("forbidden_action")

    # 3. field rules
    severity = data.get("severity")
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise Rejected("bad_severity")
    if not isinstance(next_step, str) or next_step not in NEXT_STEPS:
        raise Rejected("bad_next_step")
    summary = data.get("summary")
    if not isinstance(summary, str):
        raise Rejected("bad_summary")
    summary = summary.strip()
    if not summary or len(summary) > 600:
        raise Rejected("bad_summary")
    related = data.get("related_alert_ids", [])
    if not isinstance(related, list) or not all(isinstance(x, str) for x in related):
        raise Rejected("bad_related_alert_ids")

    # 4. other tenants
    if any(ref != tenant_id for ref in _TENANT_REF_RE.findall(summary)):
        raise Rejected("cross_tenant_reference")

    flags: set[str] = set()

    # 5. related ids: unique, in order, only known ones
    unique = list(dict.fromkeys(related))
    kept = [x for x in unique if x in known_alert_ids]
    if len(kept) != len(unique):
        flags.add("unknown_alert_id")

    # 6. summary clean-up, then escape
    summary, summary_flags = _clean_summary(summary)
    flags |= summary_flags
    summary_html = html.escape(summary, quote=True)

    return TriageResult(
        severity=severity,
        summary_html=summary_html,
        next_step=next_step,
        related_alert_ids=kept,
        flags=sorted(flags),
    )


def _strings_in(obj):
    """Every string inside obj: keys and values, nested."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield from _strings_in(key)
            yield from _strings_in(value)
    elif isinstance(obj, (list, tuple, set)):
        for item in obj:
            yield from _strings_in(item)


def triage(alert: dict, raw_output: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult:
    """Run detect_injection over every string in `alert`, then parse_model_output."""
    codes: set[str] = set()
    for text in _strings_in(alert):
        codes.update(detect_injection(text))

    result = parse_model_output(raw_output, tenant_id=tenant_id, known_alert_ids=known_alert_ids)

    if codes:
        flags = set(result.flags)
        flags.add("possible_injection")
        flags.update(f"signal:{code}" for code in codes)
        result.flags = sorted(flags)
        result.severity = max(result.severity, "high", key=SEVERITIES.index)
        if result.next_step == "monitor":
            result.next_step = "escalate_to_analyst"
    return result