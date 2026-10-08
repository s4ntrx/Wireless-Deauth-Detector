from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any

BROADCAST = "ff:ff:ff:ff:ff:ff"

REASON_NAMES = {
    1: "unspecified",
    2: "previous authentication no longer valid",
    3: "station is leaving",
    4: "inactivity",
    5: "AP cannot handle all stations",
    6: "class 2 frame from non-authenticated station",
    7: "class 3 frame from non-associated station",
    8: "station left the BSS",
}


class Severity(IntEnum):
    INFO = 0
    WARNING = 1
    CRITICAL = 2


@dataclass(frozen=True)
class DeauthEvent:
    timestamp: float
    source: str
    destination: str
    bssid: str
    reason: int
    kind: str = "deauth"
    rssi: int | None = None
    channel: int | None = None
    sequence: int | None = None
    protected: bool = False

    @property
    def client(self) -> str:
        return self.source if self.destination == self.bssid else self.destination


@dataclass(frozen=True)
class BeaconInfo:
    timestamp: float
    bssid: str
    ssid: str
    channel: int | None
    rssi: int | None
    sequence: int | None
    pmf_capable: bool
    pmf_required: bool


@dataclass(frozen=True)
class ReconnectEvent:
    timestamp: float
    client: str
    bssid: str


@dataclass(frozen=True)
class Alert:
    timestamp: float
    severity: Severity
    kind: str
    bssid: str
    summary: str
    incident: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        record = asdict(self)
        record["severity"] = self.severity.name
        return record
