"""
Analyze authentication logs and apply modular detection rules.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from alerts import AlertManager, ThreatAlert
from detector_rules import DetectionContext, RuleConfig, default_rules, parse_timestamp, update_context


@dataclass(slots=True)
class AnalysisSummary:
    total_events: int = 0
    alert_count: int = 0
    alerts_by_type: Counter[str] = field(default_factory=Counter)
    top_talkers: Counter[str] = field(default_factory=Counter)
    top_suspicious_ips: Counter[str] = field(default_factory=Counter)


class LogAnalyzer:
    """Read a JSONL log stream, apply detection rules, and emit alerts."""

    def __init__(
        self,
        *,
        alert_manager: AlertManager | None = None,
        rule_config: RuleConfig | None = None,
    ) -> None:
        self.alert_manager = alert_manager or AlertManager()
        self.rule_config = rule_config or RuleConfig()
        self.rules = default_rules(self.rule_config)
        self.context = DetectionContext()
        self.summary = AnalysisSummary()

    def analyze_file(self, log_file: str) -> tuple[list[ThreatAlert], AnalysisSummary]:
        path = Path(log_file)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        alerts: list[ThreatAlert] = []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue

                event = self._parse_event_line(line, line_number, path)
                event_alerts = self._process_event(event)
                if event_alerts:
                    self.alert_manager.emit_many(event_alerts)
                    alerts.extend(event_alerts)

        self.summary.total_events = self.context.events_processed
        self.summary.alert_count = len(alerts)
        self.summary.top_talkers = self.context.events_by_ip
        self.summary.top_suspicious_ips = self.context.alerts_by_ip
        return alerts, self.summary

    def _parse_event_line(self, line: str, line_number: int, path: Path) -> dict[str, Any]:
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path} at line {line_number}: {exc}") from exc

        required_fields = {"timestamp", "ip", "user", "action"}
        missing = required_fields.difference(event)
        if missing:
            raise ValueError(
                f"Event in {path} at line {line_number} is missing required fields: {sorted(missing)}"
            )
        return event

    def _process_event(self, event: dict[str, Any]) -> list[ThreatAlert]:
        event_time = parse_timestamp(event["timestamp"])
        update_context(self.context, event, event_time)

        alerts: list[ThreatAlert] = []
        for rule in self.rules:
            generated = rule.evaluate(event, event_time, self.context)
            for alert in generated:
                alerts.append(alert)
                self.context.alerts_generated += 1
                self.context.alerts_by_ip[alert.ip] += 1
                self.summary.alerts_by_type[alert.threat_type] += 1

        return alerts


def render_dashboard(summary: AnalysisSummary) -> str:
    """Return a CLI-friendly dashboard view."""
    top_talkers = summary.top_talkers.most_common(5)
    top_suspicious = summary.top_suspicious_ips.most_common(5)
    alert_types = summary.alerts_by_type.most_common()

    lines = [
        "",
        "SOC PIPELINE DASHBOARD",
        "======================",
        f"Total events processed : {summary.total_events}",
        f"Alerts generated      : {summary.alert_count}",
        "",
        "Top active IPs:",
    ]

    if top_talkers:
        for ip, count in top_talkers:
            lines.append(f"  - {ip}: {count} events")
    else:
        lines.append("  - No events processed")

    lines.append("")
    lines.append("Top suspicious IPs:")
    if top_suspicious:
        for ip, count in top_suspicious:
            lines.append(f"  - {ip}: {count} alerts")
    else:
        lines.append("  - No suspicious IPs detected")

    lines.append("")
    lines.append("Alert types:")
    if alert_types:
        for alert_type, count in alert_types:
            lines.append(f"  - {alert_type}: {count}")
    else:
        lines.append("  - No alerts generated")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze SOC authentication logs.")
    parser.add_argument("--input", default="logs/events.jsonl", help="Input JSONL log file.")
    parser.add_argument("--alerts-output", default="logs/alerts.log", help="Alert output JSONL file.")
    parser.add_argument(
        "--webhook-url",
        default=None,
        help="Optional webhook URL for forwarding alerts as JSON payloads.",
    )
    parser.add_argument("--failed-threshold", type=int, default=5, help="Failed login threshold.")
    parser.add_argument(
        "--failed-window",
        type=int,
        default=120,
        help="Time window in seconds for failed login detection.",
    )
    parser.add_argument(
        "--repeated-threshold",
        type=int,
        default=10,
        help="Repeated access threshold for a single IP.",
    )
    parser.add_argument(
        "--repeated-window",
        type=int,
        default=60,
        help="Time window in seconds for repeated access detection.",
    )
    parser.add_argument(
        "--spike-threshold",
        type=int,
        default=15,
        help="Event threshold for unusual activity spikes.",
    )
    parser.add_argument(
        "--spike-window",
        type=int,
        default=90,
        help="Time window in seconds for unusual activity spike detection.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress dashboard output after analysis.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    alert_manager = AlertManager(args.alerts_output, webhook_url=args.webhook_url)
    alert_manager.reset()

    analyzer = LogAnalyzer(
        alert_manager=alert_manager,
        rule_config=RuleConfig(
            failed_login_threshold=args.failed_threshold,
            failed_login_window_seconds=args.failed_window,
            repeated_access_threshold=args.repeated_threshold,
            repeated_access_window_seconds=args.repeated_window,
            activity_spike_threshold=args.spike_threshold,
            activity_spike_window_seconds=args.spike_window,
        ),
    )
    _, summary = analyzer.analyze_file(args.input)
    if not args.quiet:
        print(render_dashboard(summary))


if __name__ == "__main__":
    main()
