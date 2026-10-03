from __future__ import annotations

import re
from typing import Any

_LEVEL_START_RE = re.compile(
    r"^\[(?P<time>\d{2}:\d{2})\]\s+\[\d+/\d+\]\s+(?P<level>[NS]\d{2}[A-Z]?)\s+.+?\s+-\s+START\s*$"
)
_LEVEL_END_RE = re.compile(
    r"^\[(?P<time>\d{2}:\d{2})\]\s+\[\d+/\d+\]\s+(?P<level>[NS]\d{2}[A-Z]?)\s+-\s+(?P<verdict>PASS|WARN|FAIL|SKIP|BLOCKED|ERROR|INFRA_ERROR|CONFIG_ERROR)\b"
)
_LEVEL_BLOCKED_RE = re.compile(
    r"^\[(?P<time>\d{2}:\d{2})\]\s+\[\d+/\d+\]\s+(?P<level>[NS]\d{2}[A-Z]?)\s+.+?\s+-\s+(?P<verdict>BLOCKED)\b"
)


def split_levels(levels: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    functional = [x for x in levels if str(x.get("id", "")).startswith("N")]
    security = [x for x in levels if str(x.get("id", "")).startswith("S")]
    return functional, security


def campaign_names_for_profile(campaigns: dict[str, dict[str, Any]], profile: str) -> list[str]:
    names=[]
    for name, meta in campaigns.items():
        p=str(meta.get("profile", ""))
        if p == profile:
            names.append(name)
    return names


def parse_level_event(line: str) -> tuple[str, str] | None:
    text=line.strip()
    match=_LEVEL_END_RE.match(text) or _LEVEL_BLOCKED_RE.match(text)
    if match:
        return match.group("level"),match.group("verdict")
    match=_LEVEL_START_RE.match(text)
    if match:
        return match.group("level"),"RUNNING"
    return None
