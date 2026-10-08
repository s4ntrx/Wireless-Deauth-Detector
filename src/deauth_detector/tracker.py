from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .models import BROADCAST, DeauthEvent, ReconnectEvent


@dataclass
class ClientProfile:
    mac: str
    first_seen: float
    last_seen: float
    last_deauth: float
    deauths: int = 0
    reconnects: int = 0
    bssids: set[str] = field(default_factory=set)
    reasons: Counter = field(default_factory=Counter)


class ClientTracker:
    def __init__(self, reconnect_window_seconds: float = 30.0):
        self.reconnect_window_seconds = reconnect_window_seconds
        self.profiles: dict[str, ClientProfile] = {}
        self._last_broadcast_deauth: dict[str, float] = {}

    def record_deauth(self, event: DeauthEvent) -> None:
        client = event.client
        if client == BROADCAST:
            self._last_broadcast_deauth[event.bssid] = event.timestamp
            return
        profile = self.profiles.get(client)
        if profile is None:
            profile = ClientProfile(client, event.timestamp, event.timestamp, event.timestamp)
            self.profiles[client] = profile
        profile.deauths += 1
        profile.last_seen = profile.last_deauth = event.timestamp
        profile.bssids.add(event.bssid)
        profile.reasons[event.reason] += 1

    def record_reconnect(self, event: ReconnectEvent) -> bool:
        profile = self.profiles.get(event.client)
        last_targeted = max(
            profile.last_deauth if profile else 0.0,
            self._last_broadcast_deauth.get(event.bssid, 0.0),
        )
        if last_targeted == 0.0 or event.timestamp - last_targeted > self.reconnect_window_seconds:
            return False
        if profile is None:
            profile = ClientProfile(event.client, event.timestamp, event.timestamp, last_targeted)
            self.profiles[event.client] = profile
        profile.reconnects += 1
        profile.last_seen = event.timestamp
        profile.bssids.add(event.bssid)
        return True

    def victims(self, min_deauths: int = 3, min_reconnects: int = 1) -> list[ClientProfile]:
        matches = [
            profile
            for profile in self.profiles.values()
            if profile.deauths >= min_deauths and profile.reconnects >= min_reconnects
        ]
        return sorted(matches, key=lambda profile: profile.deauths, reverse=True)
