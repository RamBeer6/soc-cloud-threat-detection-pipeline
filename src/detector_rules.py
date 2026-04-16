"""
Detection rules for the SOC-oriented threat detection pipeline.

Each rule is evaluated independently against a shared analysis context so the
system can be extended with new detections without rewriting the analyzer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from alerts import ThreatAlert


DEFAULT_KNOWN_BAD_IPS = {
    "185.220.101.12",
    "45.95.147.27",
    "103.246.187.44",
}


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value)


@dataclass(slots=True)
class RuleConfig:
    failed_login_threshold: int = 5
    failed_login_window_seconds: int = 120
    repeated_access_threshold: int = 10
    repeated_access_window_seconds: int = 60
    activity_spike_threshold: int = 15
    activity_spike_window_seconds: int = 90
    per_rule_cooldown_seconds: int = 300


@dataclass(slots=True)
class DetectionContext:
    events_processed: int = 0
    alerts_generated: int = 0
    events_by_ip: Counter[str] = field(default_factory=Counter)
    alerts_by_ip: Counter[str] = field(default_factory=Counter)
    failed_logins_by_ip: dict[str, deque[datetime]] = field(default_factory=lambda: defaultdict(deque))
    successes_by_ip: dict[str, deque[datetime]] = field(default_factory=lambda: defaultdict(deque))
    all_activity_by_ip: dict[str, deque[datetime]] = field(default_factory=lambda: defaultdict(deque))
    last_alert_by_rule_and_ip: dict[tuple[str, str], datetime] = field(default_factory=dict)


class DetectionRule(ABC):
    """Base class for all detection rules."""

    def __init__(self, config: RuleConfig) -> None:
        self.config = config

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable rule name."""

    @abstractmethod
    def evaluate(
        self,
        event: dict[str, Any],
        event_time: datetime,
        context: DetectionContext,
    ) -> list[ThreatAlert]:
        """Return zero or more alerts for the supplied event."""

    def _cooldown_active(self, ip: str, event_time: datetime, context: DetectionContext) -> bool:
        last_alert = context.last_alert_by_rule_and_ip.get((self.name, ip))
        if last_alert is None:
            return False

        cooldown = timedelta(seconds=self.config.per_rule_cooldown_seconds)
        return event_time - last_alert < cooldown

    def _mark_alerted(self, ip: str, event_time: datetime, context: DetectionContext) -> None:
        context.last_alert_by_rule_and_ip[(self.name, ip)] = event_time

    def _create_alert(
        self,
        *,
        ip: str,
        timestamp: str,
        threat_type: str,
        explanation: str,
        severity: str,
        user: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ThreatAlert:
        return ThreatAlert(
            timestamp=timestamp,
            ip=ip,
            threat_type=threat_type,
            explanation=explanation,
            severity=severity,
            user=user,
            metadata=metadata or {},
        )


class FailedLoginBurstRule(DetectionRule):
    @property
    def name(self) -> str:
        return "failed_login_burst"

    def evaluate(
        self,
        event: dict[str, Any],
        event_time: datetime,
        context: DetectionContext,
    ) -> list[ThreatAlert]:
        if event.get("action") != "login_failed":
            return []

        ip = event["ip"]
        failed_events = context.failed_logins_by_ip[ip]
        window = timedelta(seconds=self.config.failed_login_window_seconds)
        cutoff = event_time - window
        while failed_events and failed_events[0] < cutoff:
            failed_events.popleft()

        if len(failed_events) < self.config.failed_login_threshold:
            return []

        if self._cooldown_active(ip, event_time, context):
            return []

        self._mark_alerted(ip, event_time, context)
        return [
            self._create_alert(
                ip=ip,
                timestamp=event["timestamp"],
                user=event.get("user"),
                threat_type="brute_force_suspected",
                severity="high",
                explanation=(
                    f"Detected {len(failed_events)} failed login attempts from {ip} "
                    f"within {self.config.failed_login_window_seconds} seconds."
                ),
                metadata={
                    "failed_attempts": len(failed_events),
                    "window_seconds": self.config.failed_login_window_seconds,
                    "rule": self.name,
                },
            )
        ]


class RepeatedAccessRule(DetectionRule):
    @property
    def name(self) -> str:
        return "repeated_access"

    def evaluate(
        self,
        event: dict[str, Any],
        event_time: datetime,
        context: DetectionContext,
    ) -> list[ThreatAlert]:
        ip = event["ip"]
        access_events = context.all_activity_by_ip[ip]
        window = timedelta(seconds=self.config.repeated_access_window_seconds)
        cutoff = event_time - window
        while access_events and access_events[0] < cutoff:
            access_events.popleft()

        if len(access_events) < self.config.repeated_access_threshold:
            return []

        if self._cooldown_active(ip, event_time, context):
            return []

        self._mark_alerted(ip, event_time, context)
        return [
            self._create_alert(
                ip=ip,
                timestamp=event["timestamp"],
                user=event.get("user"),
                threat_type="repeated_access_pattern",
                severity="medium",
                explanation=(
                    f"Observed {len(access_events)} authentication events from {ip} "
                    f"within {self.config.repeated_access_window_seconds} seconds."
                ),
                metadata={
                    "event_count": len(access_events),
                    "window_seconds": self.config.repeated_access_window_seconds,
                    "rule": self.name,
                },
            )
        ]


class ActivitySpikeRule(DetectionRule):
    @property
    def name(self) -> str:
        return "activity_spike"

    def evaluate(
        self,
        event: dict[str, Any],
        event_time: datetime,
        context: DetectionContext,
    ) -> list[ThreatAlert]:
        ip = event["ip"]
        activity_events = context.all_activity_by_ip[ip]
        window = timedelta(seconds=self.config.activity_spike_window_seconds)
        cutoff = event_time - window
        while activity_events and activity_events[0] < cutoff:
            activity_events.popleft()

        if len(activity_events) < self.config.activity_spike_threshold:
            return []

        if self._cooldown_active(ip, event_time, context):
            return []

        self._mark_alerted(ip, event_time, context)
        return [
            self._create_alert(
                ip=ip,
                timestamp=event["timestamp"],
                user=event.get("user"),
                threat_type="unusual_activity_spike",
                severity="medium",
                explanation=(
                    f"Traffic from {ip} spiked to {len(activity_events)} events "
                    f"in {self.config.activity_spike_window_seconds} seconds."
                ),
                metadata={
                    "event_count": len(activity_events),
                    "window_seconds": self.config.activity_spike_window_seconds,
                    "rule": self.name,
                },
            )
        ]


class SuspiciousIPRule(DetectionRule):
    def __init__(self, config: RuleConfig, known_bad_ips: set[str] | None = None) -> None:
        super().__init__(config)
        self.known_bad_ips = known_bad_ips or DEFAULT_KNOWN_BAD_IPS

    @property
    def name(self) -> str:
        return "suspicious_ip"

    def evaluate(
        self,
        event: dict[str, Any],
        event_time: datetime,
        context: DetectionContext,
    ) -> list[ThreatAlert]:
        ip = event["ip"]
        if ip not in self.known_bad_ips and event.get("threat_context") != "known_bad_ip":
            return []

        if self._cooldown_active(ip, event_time, context):
            return []

        self._mark_alerted(ip, event_time, context)
        return [
            self._create_alert(
                ip=ip,
                timestamp=event["timestamp"],
                user=event.get("user"),
                threat_type="known_suspicious_ip_activity",
                severity="high",
                explanation=(
                    f"Authentication activity detected from IP {ip}, which is flagged "
                    "as suspicious in the simulated threat intel set."
                ),
                metadata={
                    "action": event.get("action"),
                    "rule": self.name,
                },
            )
        ]


def update_context(context: DetectionContext, event: dict[str, Any], event_time: datetime) -> None:
    """Update rolling counters before rule evaluation."""
    ip = event["ip"]
    context.events_processed += 1
    context.events_by_ip[ip] += 1

    context.all_activity_by_ip[ip].append(event_time)
    if event.get("action") == "login_failed":
        context.failed_logins_by_ip[ip].append(event_time)
    if event.get("action") == "login_success":
        context.successes_by_ip[ip].append(event_time)


def default_rules(config: RuleConfig | None = None) -> list[DetectionRule]:
    active_config = config or RuleConfig()
    return [
        SuspiciousIPRule(active_config),
        FailedLoginBurstRule(active_config),
        RepeatedAccessRule(active_config),
        ActivitySpikeRule(active_config),
    ]
