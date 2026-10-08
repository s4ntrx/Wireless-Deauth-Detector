from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from .models import BeaconInfo, DeauthEvent, ReconnectEvent

RATE_WINDOW_SECONDS = 10.0


@dataclass
class CaptureStats:
    started: float = field(default_factory=time.monotonic)
    deauths: int = 0
    beacons: int = 0
    reconnects: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    last_alert_summary: str = ""
    _recent_deauths: deque[float] = field(default_factory=deque)

    def observe(self, item: DeauthEvent | BeaconInfo | ReconnectEvent) -> None:
        if self.first_timestamp is None:
            self.first_timestamp = item.timestamp
        self.last_timestamp = item.timestamp
        if isinstance(item, DeauthEvent):
            self.deauths += 1
            self._recent_deauths.append(time.monotonic())
        elif isinstance(item, BeaconInfo):
            self.beacons += 1
        else:
            self.reconnects += 1

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started

    @property
    def capture_span_seconds(self) -> float:
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0
        return self.last_timestamp - self.first_timestamp

    def deauth_rate(self) -> float:
        cutoff = time.monotonic() - RATE_WINDOW_SECONDS
        while self._recent_deauths and self._recent_deauths[0] < cutoff:
            self._recent_deauths.popleft()
        return len(self._recent_deauths) / RATE_WINDOW_SECONDS
