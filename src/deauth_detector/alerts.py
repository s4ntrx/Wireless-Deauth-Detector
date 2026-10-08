from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import Alert, DeauthEvent, ReconnectEvent

WEBHOOK_TIMEOUT_SECONDS = 5


def record_from(item: DeauthEvent | ReconnectEvent | Alert) -> dict[str, Any]:
    if isinstance(item, Alert):
        return {"type": "alert", **item.to_dict()}
    kind = "deauth" if isinstance(item, DeauthEvent) else "reconnect"
    return {"type": kind, **asdict(item)}


class JsonlLog:
    def __init__(self, path: str | Path):
        self._handle = open(path, "a", encoding="utf-8")
        self.run_id = time.strftime("%Y%m%d-%H%M%S")

    def write(self, record: dict[str, Any]) -> None:
        self._handle.write(json.dumps({**record, "run": self.run_id}, sort_keys=True) + "\n")
        self._handle.flush()

    def close(self) -> None:
        self._handle.close()


class WebhookSink:
    def __init__(self, url: str):
        if not url.startswith(("http://", "https://")):
            raise ValueError("webhook URL must start with http:// or https://")
        self.url = url

    def __call__(self, alert: Alert) -> None:
        threading.Thread(target=self._post, args=(alert,), daemon=True).start()

    def _post(self, alert: Alert) -> None:
        request = urllib.request.Request(
            self.url,
            data=json.dumps(alert.to_dict()).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(request, timeout=WEBHOOK_TIMEOUT_SECONDS).close()
        except (urllib.error.URLError, OSError) as error:
            print(f"webhook delivery failed: {error}", file=sys.stderr)
