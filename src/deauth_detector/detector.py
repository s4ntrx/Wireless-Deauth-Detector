from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .config import DetectorConfig
from .models import Alert, BeaconInfo, DeauthEvent, ReconnectEvent, Severity
from .tracker import ClientTracker
from .vendors import lookup_vendor
from .window import SlidingWindow

TOP_ENTRIES = 10
SEQUENCE_SPACE = 4096


@dataclass
class AccessPointProfile:
    bssid: str
    ssid: str = ""
    channel: int | None = None
    mean_rssi: float | None = None
    last_sequence: int | None = None
    last_beacon: float = 0.0
    pmf_capable: bool = False
    pmf_required: bool = False

    def update(self, beacon: BeaconInfo) -> None:
        self.ssid = beacon.ssid or self.ssid
        self.channel = beacon.channel or self.channel
        self.last_sequence = beacon.sequence
        self.last_beacon = beacon.timestamp
        self.pmf_capable = beacon.pmf_capable
        self.pmf_required = beacon.pmf_required
        if beacon.rssi is not None:
            smoothed = self.mean_rssi if self.mean_rssi is not None else beacon.rssi
            self.mean_rssi = 0.9 * smoothed + 0.1 * beacon.rssi


@dataclass
class Incident:
    incident_id: int
    bssid: str
    started: float
    last_seen: float
    severity: Severity = Severity.WARNING
    frames: int = 0
    peak_window_frames: int = 0
    spoofed_frames: int = 0
    spoofed_rssi_total: float = 0.0
    spoofed_rssi_samples: int = 0
    rules: set[str] = field(default_factory=set)
    clients: Counter = field(default_factory=Counter)
    sources: Counter = field(default_factory=Counter)
    reasons: Counter = field(default_factory=Counter)


class DeauthDetector:
    def __init__(
        self,
        config: DetectorConfig | None = None,
        observer: Callable[[DeauthEvent | ReconnectEvent], None] | None = None,
    ):
        self.config = config or DetectorConfig()
        self.observer = observer
        self.clients = ClientTracker(self.config.reconnect_window_seconds)
        self.access_points: dict[str, AccessPointProfile] = {
            bssid: AccessPointProfile(bssid) for bssid in self.config.known_aps
        }
        self.closed_incidents: list[Incident] = []
        self._windows: dict[str, SlidingWindow] = {}
        self._open: dict[str, Incident] = {}
        self._next_incident_id = 1

    def process(self, item: DeauthEvent | BeaconInfo | ReconnectEvent) -> list[Alert]:
        alerts = self.tick(item.timestamp)
        if isinstance(item, BeaconInfo):
            self._learn_beacon(item)
        elif isinstance(item, ReconnectEvent):
            if self.clients.record_reconnect(item) and self.observer:
                self.observer(item)
        elif isinstance(item, DeauthEvent):
            alerts.extend(self._handle_deauth(item))
        return alerts

    @property
    def open_incidents(self) -> list[Incident]:
        return list(self._open.values())

    def tick(self, now: float) -> list[Alert]:
        quiet = self.config.incident_quiet_seconds
        stale = [bssid for bssid, incident in self._open.items() if now - incident.last_seen > quiet]
        return [self._close(bssid) for bssid in stale]

    def finalize(self) -> list[Alert]:
        return [self._close(bssid) for bssid in list(self._open)]

    def _learn_beacon(self, beacon: BeaconInfo) -> None:
        known = self.config.known_aps
        if known and beacon.bssid not in known:
            return
        profile = self.access_points.setdefault(beacon.bssid, AccessPointProfile(beacon.bssid))
        profile.update(beacon)

    def _handle_deauth(self, event: DeauthEvent) -> list[Alert]:
        known = self.config.known_aps
        if known and event.bssid not in known:
            return []
        if self.observer:
            self.observer(event)
        self.clients.record_deauth(event)

        flags = self._spoof_flags(event)
        window = self._windows.setdefault(event.bssid, SlidingWindow(self.config.window_seconds))
        window.add(event, flags)

        rules, severity = self._evaluate(event, window, flags)
        incident = self._open.get(event.bssid)
        if incident is None and not rules:
            return []

        opened = incident is None
        if opened:
            incident = self._open_incident(window, severity)
        escalated = not opened and severity > incident.severity
        if escalated:
            incident.severity = severity

        incident.rules |= rules
        if not opened:
            self._absorb(incident, event, flags, len(window))

        if opened:
            return [self._alert("incident_opened", incident)]
        if escalated:
            return [self._alert("incident_escalated", incident)]
        return []

    def _evaluate(
        self, event: DeauthEvent, window: SlidingWindow, flags: frozenset[str]
    ) -> tuple[set[str], Severity]:
        config = self.config
        rules: set[str] = set()
        severity = Severity.INFO

        if len(window) >= config.critical_frames:
            rules.add("flood")
            severity = Severity.CRITICAL
        elif len(window) >= config.warning_frames:
            rules.add("flood")
            severity = Severity.WARNING

        if window.frames_for(event.client) >= config.client_repeat_frames:
            rules.add("client_repeat")
            severity = max(severity, Severity.WARNING)

        if window.distinct_sources_for(event.client) >= config.multi_source_min:
            rules.add("multi_source")
            severity = max(severity, Severity.WARNING)

        if window.flagged_frames >= config.spoof_min_frames:
            rules |= window.active_flags
            severity = Severity.CRITICAL if "flood" in rules else max(severity, Severity.WARNING)

        if rules and event.reason in config.suspicious_reasons:
            rules.add("suspicious_reason")
        return rules, severity

    def _spoof_flags(self, event: DeauthEvent) -> frozenset[str]:
        profile = self.access_points.get(event.bssid)
        if profile is None:
            return frozenset()

        flags: set[str] = set()
        if event.source != event.bssid and event.destination != event.bssid:
            flags.add("foreign_source")
        if event.source == event.bssid:
            if self._rssi_deviates(event, profile):
                flags.add("rssi_mismatch")
            if self._sequence_deviates(event, profile):
                flags.add("sequence_anomaly")
            if profile.pmf_required and not event.protected:
                flags.add("pmf_violation")
        return frozenset(flags)

    def _rssi_deviates(self, event: DeauthEvent, profile: AccessPointProfile) -> bool:
        if event.rssi is None or profile.mean_rssi is None:
            return False
        return abs(event.rssi - profile.mean_rssi) >= self.config.rssi_deviation_db

    def _sequence_deviates(self, event: DeauthEvent, profile: AccessPointProfile) -> bool:
        if event.sequence is None or profile.last_sequence is None:
            return False
        if event.timestamp - profile.last_beacon > self.config.beacon_max_age_seconds:
            return False
        half = SEQUENCE_SPACE // 2
        delta = (event.sequence - profile.last_sequence + half) % SEQUENCE_SPACE - half
        return abs(delta) > self.config.sequence_gap

    def _open_incident(self, window: SlidingWindow, severity: Severity) -> Incident:
        first = window.entries[0].event
        incident = Incident(
            incident_id=self._next_incident_id,
            bssid=first.bssid,
            started=first.timestamp,
            last_seen=first.timestamp,
            severity=severity,
        )
        self._next_incident_id += 1
        self._open[first.bssid] = incident
        for entry in window.entries:
            self._absorb(incident, entry.event, entry.flags, len(window))
        return incident

    @staticmethod
    def _absorb(incident: Incident, event: DeauthEvent, flags: frozenset[str], window_size: int) -> None:
        incident.last_seen = event.timestamp
        incident.frames += 1
        incident.peak_window_frames = max(incident.peak_window_frames, window_size)
        incident.clients[event.client] += 1
        incident.sources[event.source] += 1
        incident.reasons[event.reason] += 1
        if flags:
            incident.spoofed_frames += 1
            if event.rssi is not None:
                incident.spoofed_rssi_total += event.rssi
                incident.spoofed_rssi_samples += 1

    def _close(self, bssid: str) -> Alert:
        incident = self._open.pop(bssid)
        self.closed_incidents.append(incident)
        return self._alert("incident_closed", incident)

    def _alert(self, kind: str, incident: Incident) -> Alert:
        details = self.describe(incident)
        summary = (
            f"{incident.severity.name} {kind.removeprefix('incident_')} bssid={incident.bssid} "
            f"rules={','.join(sorted(incident.rules)) or 'pending'} frames={incident.frames} "
            f"clients={len(incident.clients)}"
        )
        return Alert(incident.last_seen, incident.severity, kind, incident.bssid, summary, details)

    def describe(self, incident: Incident) -> dict[str, Any]:
        profile = self.access_points.get(incident.bssid)
        return {
            "incident_id": incident.incident_id,
            "bssid": incident.bssid,
            "ssid": profile.ssid if profile else "",
            "channel": profile.channel if profile else None,
            "pmf_required": profile.pmf_required if profile else None,
            "severity": incident.severity.name,
            "started": incident.started,
            "last_seen": incident.last_seen,
            "duration_seconds": round(incident.last_seen - incident.started, 3),
            "frames": incident.frames,
            "peak_window_frames": incident.peak_window_frames,
            "spoofed_frames": incident.spoofed_frames,
            "rules": sorted(incident.rules),
            "clients": incident.clients.most_common(TOP_ENTRIES),
            "sources": incident.sources.most_common(TOP_ENTRIES),
            "reasons": {str(code): count for code, count in incident.reasons.most_common()},
            "attacker_estimate": self._attacker_estimate(incident),
            "vendors": self._vendor_labels(incident),
        }

    @staticmethod
    def _vendor_labels(incident: Incident) -> dict[str, str]:
        addresses = {incident.bssid, *incident.clients, *incident.sources}
        return {
            mac: lookup_vendor(mac, virtual_interface=mac == incident.bssid).label
            for mac in sorted(addresses)
        }

    def _attacker_estimate(self, incident: Incident) -> dict[str, Any] | None:
        if not incident.spoofed_rssi_samples:
            return None
        mean_rssi = incident.spoofed_rssi_total / incident.spoofed_rssi_samples
        exponent = 10 * self.config.path_loss_exponent
        distance = 10 ** ((self.config.reference_rssi_dbm - mean_rssi) / exponent)
        return {
            "mean_rssi_dbm": round(mean_rssi, 1),
            "approx_distance_m": round(distance, 1),
            "samples": incident.spoofed_rssi_samples,
        }
