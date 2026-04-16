"""
Alert data structures and persistence helpers for the SOC pipeline.
"""

from __future__ import annotations

import json
import os
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib import error, request


@dataclass(slots=True)
class ThreatAlert:
    timestamp: str
    ip: str
    threat_type: str
    explanation: str
    severity: str
    user: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AlertManager:
    """Handle alert output to both console and persistent storage."""

    def __init__(
        self,
        alert_file: str = "logs/alerts.log",
        webhook_url: str | None = None,
        webhook_timeout_seconds: int = 5,
    ) -> None:
        self.alert_file = Path(alert_file)
        self.alert_file.parent.mkdir(parents=True, exist_ok=True)
        self.webhook_url = webhook_url or os.getenv("SOC_ALERT_WEBHOOK_URL")
        self.webhook_timeout_seconds = webhook_timeout_seconds

    def emit(self, alert: ThreatAlert) -> None:
        self._print_to_console(alert)
        self._append_to_file(alert)
        self._send_to_webhook(alert)

    def emit_many(self, alerts: list[ThreatAlert]) -> None:
        for alert in alerts:
            self.emit(alert)

    def _append_to_file(self, alert: ThreatAlert) -> None:
        with self.alert_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert.to_dict()) + "\n")

    def _print_to_console(self, alert: ThreatAlert) -> None:
        print(
            "[ALERT] "
            f"{alert.timestamp} "
            f"| severity={alert.severity.upper()} "
            f"| ip={alert.ip} "
            f"| type={alert.threat_type} "
            f"| explanation={alert.explanation}"
        )

    def _send_to_webhook(self, alert: ThreatAlert) -> None:
        if not self.webhook_url:
            return

        payload = json.dumps(alert.to_dict()).encode("utf-8")
        webhook_request = request.Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with request.urlopen(webhook_request, timeout=self.webhook_timeout_seconds):
                pass
        except (error.URLError, TimeoutError) as exc:
            print(f"[ALERT][webhook] failed to deliver alert to {self.webhook_url}: {exc}")

    def reset(self) -> None:
        with suppress(FileNotFoundError):
            self.alert_file.unlink()
