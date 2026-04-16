"""
Unified project entrypoint for generating logs, analyzing events, and rendering
SOC-style operational summaries.
"""

from __future__ import annotations

import argparse
import json

from alerts import AlertManager
from analyzer import LogAnalyzer, render_dashboard
from detector_rules import RuleConfig
from log_generator import GeneratorConfig, LogGenerator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cloud Threat Detection Pipeline (SOC-Oriented System)"
    )
    subparsers = parser.add_subparsers(dest="command")

    generate_parser = subparsers.add_parser("generate", help="Generate sample SOC logs.")
    generate_parser.add_argument("--count", type=int, default=200, help="Number of events to generate.")
    generate_parser.add_argument("--output", default="logs/events.jsonl", help="Generated JSONL file.")
    generate_parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducible output.")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze existing logs and generate alerts.")
    analyze_parser.add_argument("--input", default="logs/events.jsonl", help="Input JSONL log file.")
    analyze_parser.add_argument("--alerts-output", default="logs/alerts.log", help="Output alert log file.")
    analyze_parser.add_argument("--webhook-url", default=None, help="Optional webhook for forwarding alerts.")
    analyze_parser.add_argument("--failed-threshold", type=int, default=5)
    analyze_parser.add_argument("--failed-window", type=int, default=120)
    analyze_parser.add_argument("--repeated-threshold", type=int, default=10)
    analyze_parser.add_argument("--repeated-window", type=int, default=60)
    analyze_parser.add_argument("--spike-threshold", type=int, default=15)
    analyze_parser.add_argument("--spike-window", type=int, default=90)

    run_parser = subparsers.add_parser(
        "run",
        help="Generate sample logs, analyze them, emit alerts, and print a dashboard.",
    )
    run_parser.add_argument("--count", type=int, default=200, help="Number of events to generate.")
    run_parser.add_argument("--output", default="logs/events.jsonl", help="Generated JSONL file.")
    run_parser.add_argument("--alerts-output", default="logs/alerts.log", help="Output alert log file.")
    run_parser.add_argument("--webhook-url", default=None, help="Optional webhook for forwarding alerts.")
    run_parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducible output.")
    run_parser.add_argument("--failed-threshold", type=int, default=5)
    run_parser.add_argument("--failed-window", type=int, default=120)
    run_parser.add_argument("--repeated-threshold", type=int, default=10)
    run_parser.add_argument("--repeated-window", type=int, default=60)
    run_parser.add_argument("--spike-threshold", type=int, default=15)
    run_parser.add_argument("--spike-window", type=int, default=90)

    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="Launch a Flask dashboard for reviewing current SOC telemetry and alerts.",
    )
    dashboard_parser.add_argument("--input", default="logs/events.jsonl", help="Input JSONL log file.")
    dashboard_parser.add_argument("--alerts-output", default="logs/alerts.log", help="Output alert log file.")
    dashboard_parser.add_argument("--host", default="127.0.0.1")
    dashboard_parser.add_argument("--port", type=int, default=5000)
    dashboard_parser.add_argument("--debug", action="store_true")
    dashboard_parser.add_argument("--failed-threshold", type=int, default=5)
    dashboard_parser.add_argument("--failed-window", type=int, default=120)
    dashboard_parser.add_argument("--repeated-threshold", type=int, default=10)
    dashboard_parser.add_argument("--repeated-window", type=int, default=60)
    dashboard_parser.add_argument("--spike-threshold", type=int, default=15)
    dashboard_parser.add_argument("--spike-window", type=int, default=90)

    return parser


def run_generate(args: argparse.Namespace) -> None:
    generator = LogGenerator(
        GeneratorConfig(
            event_count=args.count,
            output_file=args.output,
            seed=args.seed,
        )
    )
    events = generator.generate()
    path = generator.save(events)
    print(f"[generator] wrote {len(events)} events to {path}")
    print("[generator] sample event:")
    print(json.dumps(events[0], indent=2))


def run_analyze(args: argparse.Namespace) -> None:
    input_path = getattr(args, "input", args.output)
    alert_manager = AlertManager(args.alerts_output, webhook_url=getattr(args, "webhook_url", None))
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
    alerts, summary = analyzer.analyze_file(input_path)
    print(f"[analyzer] processed {summary.total_events} events and generated {len(alerts)} alerts")
    print(render_dashboard(summary))


def run_pipeline(args: argparse.Namespace) -> None:
    run_generate(args)
    print("")
    run_analyze(args)


def run_dashboard(args: argparse.Namespace) -> None:
    from web_dashboard import create_app

    app = create_app(args)
    app.run(host=args.host, port=args.port, debug=args.debug)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "generate":
        run_generate(args)
        return
    if args.command == "analyze":
        run_analyze(args)
        return
    if args.command == "dashboard":
        run_dashboard(args)
        return

    if args.command in {None, "run"}:
        if args.command is None:
            args = parser.parse_args(["run"])
        run_pipeline(args)
        return

    parser.error(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    main()
