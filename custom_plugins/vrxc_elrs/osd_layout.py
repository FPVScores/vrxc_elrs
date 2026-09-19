"""Parse FPV Scores Race OSD layouts stored on RotorHazard pilots."""

from __future__ import annotations

import html
import json
from typing import Any

ROWS = 18
COLS = 50
HOLD_CHOICES = frozenset((-1, 3, 5, 10, 15, 30))
ITEM_IDS = (
    "heat_name",
    "class_name",
    "event_name",
    "announcement",
    "race_status",
    "lap_position",
    "lap_result",
    "gap_result",
    "gap_behind",
    "recent_laps",
    "results",
)
ALWAYS_HOLD = frozenset(
    (
        "heat_name",
        "class_name",
        "event_name",
        "lap_position",
        "recent_laps",
        "results",
    )
)


def default_hold(item_id: str) -> int:
    return -1 if item_id in ALWAYS_HOLD else 5


def _as_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def clamp_hold(value: Any, fallback: int) -> int:
    n = _as_int(value, fallback)
    if n == 0:
        return fallback
    return n if n in HOLD_CHOICES else fallback


def parse_comm_osd(raw: Any) -> dict | None:
    if raw is None:
        return None
    data = raw
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="ignore")
    if isinstance(raw, str):
        text = html.unescape(raw).strip()
        if text == "":
            return None
        if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
            text = text[1:-1]
        try:
            data = json.loads(text)
        except (TypeError, ValueError):
            try:
                data = json.loads(html.unescape(text))
            except (TypeError, ValueError):
                return None
    if not isinstance(data, dict):
        return None
    incoming = data.get("elements") if isinstance(data.get("elements"), dict) else data
    if not isinstance(incoming, dict):
        incoming = {}
    elements: dict[str, dict] = {}
    for item_id in ITEM_IDS:
        row = incoming.get(item_id) if isinstance(incoming.get(item_id), dict) else {}
        hold_fb = default_hold(item_id)
        item = {
            "enabled": bool(row.get("enabled")),
            "row": max(0, min(ROWS - 1, _as_int(row.get("row"), 0))),
            "col": max(0, min(COLS - 1, _as_int(row.get("col"), 0))),
            "center": bool(row["center"]) if "center" in row else True,
            "hold_secs": clamp_hold(row.get("hold_secs", hold_fb), hold_fb),
        }
        if item_id == "recent_laps":
            item["num_laps"] = max(1, min(5, _as_int(row.get("num_laps"), 3)))
        elements[item_id] = item
    enabled = True
    if "enabled" in data:
        enabled = bool(data.get("enabled"))
    return {"version": 1, "enabled": enabled, "elements": elements}


def layout_has_items(layout: dict | None) -> bool:
    return bool(layout) and bool(layout.get("enabled", True))


def element(layout: dict | None, item_id: str) -> dict | None:
    if not layout_has_items(layout):
        return None
    item = (layout.get("elements") or {}).get(item_id)
    if not item or not item.get("enabled"):
        return None
    return item
