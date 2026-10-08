from __future__ import annotations

import tomllib
from dataclasses import dataclass, fields
from pathlib import Path


@dataclass(frozen=True)
class DetectorConfig:
    window_seconds: float = 10.0
    warning_frames: int = 10
    critical_frames: int = 100
    client_repeat_frames: int = 5
    multi_source_min: int = 3
    spoof_min_frames: int = 3
    suspicious_reasons: frozenset[int] = frozenset({2, 7})
    incident_quiet_seconds: float = 30.0
    reconnect_window_seconds: float = 30.0
    rssi_deviation_db: float = 15.0
    sequence_gap: int = 512
    beacon_max_age_seconds: float = 10.0
    reference_rssi_dbm: float = -40.0
    path_loss_exponent: float = 3.0
    known_aps: frozenset[str] = frozenset()


def load_config(path: str | Path) -> DetectorConfig:
    with open(path, "rb") as handle:
        section = tomllib.load(handle).get("detector", {})

    valid_names = {item.name for item in fields(DetectorConfig)}
    unknown = sorted(set(section) - valid_names)
    if unknown:
        raise ValueError(f"unknown config keys: {', '.join(unknown)}")

    values = dict(section)
    if "known_aps" in values:
        values["known_aps"] = frozenset(mac.lower() for mac in values["known_aps"])
    if "suspicious_reasons" in values:
        values["suspicious_reasons"] = frozenset(int(code) for code in values["suspicious_reasons"])
    return DetectorConfig(**values)
