"""
Generate realistic authentication-style logs for a SOC-oriented detection pipeline.

The generator intentionally mixes benign events with suspicious patterns so the
analyzer can exercise rule-based detections against repeatable sample data.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


USERS = [
    "alice",
    "bob",
    "charlie",
    "diana",
    "eve",
    "frank",
    "grace",
    "heidi",
    "ivan",
    "judy",
]

COUNTRIES = [
    "US",
    "DE",
    "GB",
    "IL",
    "IN",
    "BR",
    "CA",
    "NL",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3)",
    "curl/8.5.0",
    "python-requests/2.32.3",
]

KNOWN_BAD_IPS = [
    "185.220.101.12",
    "45.95.147.27",
    "103.246.187.44",
]

TRUSTED_IPS = [
    "10.0.10.15",
    "10.0.10.21",
    "10.0.10.35",
    "172.16.4.18",
    "192.168.1.52",
]


@dataclass(slots=True)
class GeneratorConfig:
    event_count: int = 200
    output_file: str = "logs/events.jsonl"
    seed: int | None = 42
    failed_burst_size: int = 7
    repeated_access_size: int = 16
    suspicious_ip_event_size: int = 8


class LogGenerator:
    """Create SOC-friendly authentication logs as newline-delimited JSON."""

    def __init__(self, config: GeneratorConfig) -> None:
        self.config = config
        self.random = random.Random(config.seed)
        self.current_time = datetime.now(timezone.utc) - timedelta(minutes=30)

    def generate(self) -> list[dict[str, Any]]:
        """Build a mixed stream of normal and suspicious events."""
        events: list[dict[str, Any]] = []

        # Guarantee core suspicious patterns in every dataset so the analyzer
        # always has realistic detections to surface during demos and reviews.
        guaranteed_sequences = [
            self._generate_failed_login_burst(self.config.failed_burst_size),
            self._generate_repeated_access_sequence(self.config.repeated_access_size),
            self._generate_suspicious_ip_sequence(self.config.suspicious_ip_event_size),
        ]
        for sequence in guaranteed_sequences:
            if len(events) >= self.config.event_count:
                break
            remaining = self.config.event_count - len(events)
            events.extend(sequence[:remaining])

        while len(events) < self.config.event_count:
            remaining = self.config.event_count - len(events)
            profile = self.random.choices(
                population=["normal", "failed_burst", "repeated_access", "suspicious_ip"],
                weights=[72, 10, 10, 8],
                k=1,
            )[0]

            if profile == "failed_burst":
                events.extend(self._generate_failed_login_burst(min(remaining, self.config.failed_burst_size)))
            elif profile == "repeated_access":
                events.extend(self._generate_repeated_access_sequence(min(remaining, self.config.repeated_access_size)))
            elif profile == "suspicious_ip":
                events.extend(
                    self._generate_suspicious_ip_sequence(
                        min(remaining, self.config.suspicious_ip_event_size)
                    )
                )
            else:
                events.append(self._generate_normal_event())

        return events[: self.config.event_count]

    def save(self, events: list[dict[str, Any]]) -> Path:
        """Persist events as JSONL."""
        output_path = Path(self.config.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(event) + "\n")

        return output_path

    def _generate_normal_event(self) -> dict[str, Any]:
        action = self.random.choices(
            population=["login_success", "login_failed"],
            weights=[84, 16],
            k=1,
        )[0]
        ip = self.random.choice(TRUSTED_IPS + [self._random_public_ip() for _ in range(3)])
        user = self.random.choice(USERS)
        advance_seconds = self.random.randint(15, 180)
        self.current_time += timedelta(seconds=advance_seconds)

        explanation = "Routine authentication attempt"
        if action == "login_failed":
            explanation = "User provided invalid credentials"

        event = self._build_event(
            timestamp=self.current_time,
            ip=ip,
            user=user,
            action=action,
            country=self.random.choice(COUNTRIES),
            user_agent=self.random.choice(USER_AGENTS),
            outcome="success" if action == "login_success" else "failure",
            explanation=explanation,
            threat_context="none",
        )
        return self._serialize_event(event)

    def _generate_failed_login_burst(self, size: int) -> list[dict[str, Any]]:
        ip = self._random_public_ip()
        user = self.random.choice(USERS)
        base_time = self.current_time + timedelta(seconds=self.random.randint(5, 30))
        events: list[dict[str, Any]] = []
        current_time = base_time

        for index in range(size):
            if index > 0:
                current_time += timedelta(seconds=self.random.randint(8, 20))
            events.append(
                self._build_event(
                    timestamp=current_time,
                    ip=ip,
                    user=user,
                    action="login_failed",
                    country=self.random.choice(COUNTRIES),
                    user_agent=self.random.choice(USER_AGENTS),
                    outcome="failure",
                    explanation="Repeated failed login attempt from a single source",
                    threat_context="possible_bruteforce",
                )
            )

        self.current_time = events[-1]["timestamp_dt"]
        return [self._serialize_event(event) for event in events]

    def _generate_repeated_access_sequence(self, size: int) -> list[dict[str, Any]]:
        ip = self.random.choice(TRUSTED_IPS + [self._random_public_ip()])
        user = self.random.choice(USERS)
        base_time = self.current_time + timedelta(seconds=self.random.randint(10, 40))
        events: list[dict[str, Any]] = []
        current_time = base_time

        for index in range(size):
            if index > 0:
                current_time += timedelta(seconds=self.random.randint(3, 5))
            events.append(
                self._build_event(
                    timestamp=current_time,
                    ip=ip,
                    user=user,
                    action="login_success",
                    country=self.random.choice(COUNTRIES),
                    user_agent=self.random.choice(USER_AGENTS),
                    outcome="success",
                    explanation="Repeated successful access from same IP in a short interval",
                    threat_context="activity_spike",
                )
            )

        self.current_time = events[-1]["timestamp_dt"]
        return [self._serialize_event(event) for event in events]

    def _generate_suspicious_ip_sequence(self, size: int) -> list[dict[str, Any]]:
        ip = self.random.choice(KNOWN_BAD_IPS)
        base_time = self.current_time + timedelta(seconds=self.random.randint(10, 45))
        events: list[dict[str, Any]] = []
        current_time = base_time

        for index in range(size):
            action = self.random.choices(
                population=["login_failed", "login_success"],
                weights=[70, 30],
                k=1,
            )[0]
            if index > 0:
                current_time += timedelta(seconds=self.random.randint(5, 15))
            events.append(
                self._build_event(
                    timestamp=current_time,
                    ip=ip,
                    user=self.random.choice(USERS),
                    action=action,
                    country=self.random.choice(["RU", "CN", "US", "NL"]),
                    user_agent=self.random.choice(USER_AGENTS),
                    outcome="success" if action == "login_success" else "failure",
                    explanation="Authentication attempt from an IP marked as suspicious",
                    threat_context="known_bad_ip",
                )
            )

        self.current_time = events[-1]["timestamp_dt"]
        return [self._serialize_event(event) for event in events]

    def _build_event(
        self,
        *,
        timestamp: datetime,
        ip: str,
        user: str,
        action: str,
        country: str,
        user_agent: str,
        outcome: str,
        explanation: str,
        threat_context: str,
    ) -> dict[str, Any]:
        return {
            "timestamp_dt": timestamp,
            "timestamp": timestamp.isoformat(),
            "ip": ip,
            "user": user,
            "action": action,
            "country": country,
            "source": "auth-service",
            "user_agent": user_agent,
            "outcome": outcome,
            "explanation": explanation,
            "threat_context": threat_context,
        }

    def _serialize_event(self, event: dict[str, Any]) -> dict[str, Any]:
        serialized = dict(event)
        serialized.pop("timestamp_dt", None)
        return serialized

    def _random_public_ip(self) -> str:
        return ".".join(str(self.random.randint(1, 254)) for _ in range(4))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate sample SOC log data.")
    parser.add_argument("--count", type=int, default=200, help="Number of events to generate.")
    parser.add_argument(
        "--output",
        default="logs/events.jsonl",
        help="Destination JSONL file for generated events.",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducible runs.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = GeneratorConfig(
        event_count=args.count,
        output_file=args.output,
        seed=args.seed,
    )
    generator = LogGenerator(config)
    events = generator.generate()
    path = generator.save(events)

    print(f"[generator] wrote {len(events)} events to {path}")
    print("[generator] sample event:")
    print(json.dumps(events[0], indent=2))


if __name__ == "__main__":
    main()
