from __future__ import annotations

import json
import math
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_BUCKETS = 20
RECONNECT_GRACE_SECONDS = 30


@dataclass(frozen=True)
class IncidentTimeline:
    run: str
    final: dict[str, Any]
    history: list[dict[str, Any]]
    activity: list[tuple[float, int]]
    reconnects: int


def load_records(path: str | Path) -> Iterator[dict[str, Any]]:
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{number}: invalid JSON ({error.msg})") from error


def activity_buckets(deauth_times: list[float], start: float, end: float) -> list[tuple[float, int]]:
    if not deauth_times:
        return []
    bucket_seconds = max(1, math.ceil(max(end - start, 1.0) / MAX_BUCKETS))
    counts: Counter[int] = Counter(int((stamp - start) // bucket_seconds) for stamp in deauth_times)
    return [(start + index * bucket_seconds, counts.get(index, 0)) for index in range(max(counts) + 1)]


def build_timelines(records: list[dict[str, Any]], bssid: str | None = None) -> list[IncidentTimeline]:
    alerts_by_incident: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for record in records:
        if record["type"] == "alert" and (bssid is None or record["bssid"] == bssid):
            key = (record.get("run", ""), record["incident"]["incident_id"])
            alerts_by_incident.setdefault(key, []).append(record)

    deauths = [record for record in records if record["type"] == "deauth"]
    reconnects = [record for record in records if record["type"] == "reconnect"]
    timelines = []

    for run, incident_id in sorted(alerts_by_incident):
        history = sorted(alerts_by_incident[(run, incident_id)], key=lambda item: item["timestamp"])
        final = history[-1]["incident"]
        start, end = final["started"], final["last_seen"]
        deauth_times = [
            item["timestamp"]
            for item in deauths
            if item.get("run", "") == run and item["bssid"] == final["bssid"] and start <= item["timestamp"] <= end
        ]
        reconnect_count = sum(
            1
            for item in reconnects
            if item.get("run", "") == run and item["bssid"] == final["bssid"]
            and start <= item["timestamp"] <= end + RECONNECT_GRACE_SECONDS
        )
        timelines.append(
            IncidentTimeline(run, final, history, activity_buckets(deauth_times, start, end), reconnect_count)
        )
    return timelines
