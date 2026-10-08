from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass

from .models import DeauthEvent


@dataclass(frozen=True)
class WindowEntry:
    event: DeauthEvent
    flags: frozenset[str]


class SlidingWindow:
    def __init__(self, span_seconds: float):
        self.span_seconds = span_seconds
        self._entries: deque[WindowEntry] = deque()
        self._frames_by_client: Counter[str] = Counter()
        self._sources_by_client: dict[str, Counter[str]] = {}
        self._flag_counts: Counter[str] = Counter()
        self._flagged_frames = 0

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> tuple[WindowEntry, ...]:
        return tuple(self._entries)

    @property
    def flagged_frames(self) -> int:
        return self._flagged_frames

    @property
    def active_flags(self) -> set[str]:
        return set(self._flag_counts)

    def frames_for(self, client: str) -> int:
        return self._frames_by_client[client]

    def distinct_sources_for(self, client: str) -> int:
        return len(self._sources_by_client.get(client, ()))

    def add(self, event: DeauthEvent, flags: frozenset[str]) -> None:
        entry = WindowEntry(event, flags)
        self._entries.append(entry)
        self._apply(entry, 1)
        cutoff = event.timestamp - self.span_seconds
        while self._entries and self._entries[0].event.timestamp < cutoff:
            self._apply(self._entries.popleft(), -1)

    def _apply(self, entry: WindowEntry, step: int) -> None:
        client, source = entry.event.client, entry.event.source

        self._frames_by_client[client] += step
        if self._frames_by_client[client] <= 0:
            del self._frames_by_client[client]

        sources = self._sources_by_client.setdefault(client, Counter())
        sources[source] += step
        if sources[source] <= 0:
            del sources[source]
        if not sources:
            del self._sources_by_client[client]

        for flag in entry.flags:
            self._flag_counts[flag] += step
            if self._flag_counts[flag] <= 0:
                del self._flag_counts[flag]
        if entry.flags:
            self._flagged_frames += step
