"""
Flask web dashboard for the SOC-oriented threat detection pipeline.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request

from alerts import AlertManager
from analyzer import AnalysisSummary, LogAnalyzer
from detector_rules import RuleConfig


class SilentAlertManager(AlertManager):
    """Persist alerts without printing them during dashboard refreshes."""

    def _print_to_console(self, alert) -> None:
        return None


def build_rule_config(args: argparse.Namespace) -> RuleConfig:
    return RuleConfig(
        failed_login_threshold=args.failed_threshold,
        failed_login_window_seconds=args.failed_window,
        repeated_access_threshold=args.repeated_threshold,
        repeated_access_window_seconds=args.repeated_window,
        activity_spike_threshold=args.spike_threshold,
        activity_spike_window_seconds=args.spike_window,
    )


def load_alert_records(alert_file: str, limit: int = 25) -> list[dict[str, Any]]:
    path = Path(alert_file)
    if not path.exists():
        return []

    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))

    return list(reversed(records[-limit:]))


def serialize_summary(summary: AnalysisSummary) -> dict[str, Any]:
    return {
        "total_events": summary.total_events,
        "alert_count": summary.alert_count,
        "alerts_by_type": dict(summary.alerts_by_type.most_common()),
        "top_talkers": summary.top_talkers.most_common(5),
        "top_suspicious_ips": summary.top_suspicious_ips.most_common(5),
    }


def build_dashboard_context(
    *,
    log_file: str,
    alert_file: str,
    rule_config: RuleConfig,
    alert_limit: int = 25,
) -> dict[str, Any]:
    log_path = Path(log_file)
    if not log_path.exists():
        return {
            "status": "missing_logs",
            "message": f"No log file found at {log_path}. Run the pipeline first.",
            "summary": serialize_summary(AnalysisSummary()),
            "recent_alerts": [],
            "log_file": str(log_path),
            "alert_file": str(Path(alert_file)),
        }

    alert_manager = SilentAlertManager(alert_file)
    alert_manager.reset()
    analyzer = LogAnalyzer(alert_manager=alert_manager, rule_config=rule_config)
    alerts, summary = analyzer.analyze_file(log_file)

    return {
        "status": "ready",
        "message": f"Loaded {summary.total_events} events and {len(alerts)} alerts from the current dataset.",
        "summary": serialize_summary(summary),
        "recent_alerts": load_alert_records(alert_file, limit=alert_limit),
        "log_file": str(log_path),
        "alert_file": str(Path(alert_file)),
    }


def create_app(args: argparse.Namespace | None = None) -> Flask:
    runtime_args = args or parse_args([])
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).resolve().parents[1] / "templates"),
        static_folder=str(Path(__file__).resolve().parents[1] / "static"),
    )
    rule_config = build_rule_config(runtime_args)

    @app.get("/")
    def dashboard() -> str:
        context = build_dashboard_context(
            log_file=runtime_args.input,
            alert_file=runtime_args.alerts_output,
            rule_config=rule_config,
        )
        return render_template("dashboard.html", **context)

    @app.get("/api/summary")
    def api_summary():
        context = build_dashboard_context(
            log_file=runtime_args.input,
            alert_file=runtime_args.alerts_output,
            rule_config=rule_config,
        )
        return jsonify(context)

    @app.post("/api/reload")
    def api_reload():
        requested_log = request.form.get("log_file", runtime_args.input)
        context = build_dashboard_context(
            log_file=requested_log,
            alert_file=runtime_args.alerts_output,
            rule_config=rule_config,
        )
        return jsonify(context)

    return app


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the SOC pipeline web dashboard.")
    parser.add_argument("--input", default="logs/events.jsonl", help="Input JSONL log file.")
    parser.add_argument("--alerts-output", default="logs/alerts.log", help="Alert output JSONL file.")
    parser.add_argument("--host", default="127.0.0.1", help="Flask host.")
    parser.add_argument("--port", type=int, default=5000, help="Flask port.")
    parser.add_argument("--debug", action="store_true", help="Run Flask in debug mode.")
    parser.add_argument("--failed-threshold", type=int, default=5)
    parser.add_argument("--failed-window", type=int, default=120)
    parser.add_argument("--repeated-threshold", type=int, default=10)
    parser.add_argument("--repeated-window", type=int, default=60)
    parser.add_argument("--spike-threshold", type=int, default=15)
    parser.add_argument("--spike-window", type=int, default=90)
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    app = create_app(args)
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
