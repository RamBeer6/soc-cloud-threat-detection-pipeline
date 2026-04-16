import argparse
import json
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from alerts import AlertManager
from analyzer import LogAnalyzer
from detector_rules import RuleConfig
from log_generator import GeneratorConfig, LogGenerator
from web_dashboard import create_app


TEST_ARTIFACTS_DIR = PROJECT_ROOT / "logs" / "test_artifacts"


def reset_test_dir(name: str) -> Path:
    test_dir = TEST_ARTIFACTS_DIR / name
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)
    return test_dir


class SilentAlertManager(AlertManager):
    def _print_to_console(self, alert) -> None:
        return None


class LogGeneratorTests(unittest.TestCase):
    def test_generator_outputs_expected_count_and_fields(self) -> None:
        test_dir = reset_test_dir("generator")
        output_file = test_dir / "events.jsonl"
        generator = LogGenerator(
            GeneratorConfig(
                event_count=50,
                output_file=str(output_file),
                seed=42,
            )
        )

        events = generator.generate()
        saved_path = generator.save(events)

        self.assertEqual(len(events), 50)
        self.assertEqual(saved_path, output_file)
        self.assertTrue(output_file.exists())

        required_fields = {
            "timestamp",
            "ip",
            "user",
            "action",
            "country",
            "source",
            "user_agent",
            "outcome",
            "explanation",
            "threat_context",
        }
        self.assertTrue(required_fields.issubset(events[0].keys()))
        self.assertIn("possible_bruteforce", {event["threat_context"] for event in events})
        self.assertIn("known_bad_ip", {event["threat_context"] for event in events})


class AnalyzerPipelineTests(unittest.TestCase):
    def test_pipeline_generates_all_core_alert_types(self) -> None:
        test_dir = reset_test_dir("pipeline_core_alerts")
        events_file = test_dir / "events.jsonl"
        alerts_file = test_dir / "alerts.log"

        generator = LogGenerator(
            GeneratorConfig(
                event_count=200,
                output_file=str(events_file),
                seed=42,
            )
        )
        generator.save(generator.generate())

        analyzer = LogAnalyzer(
            alert_manager=SilentAlertManager(str(alerts_file)),
            rule_config=RuleConfig(),
        )
        alerts, summary = analyzer.analyze_file(str(events_file))

        alert_types = {alert.threat_type for alert in alerts}
        self.assertGreater(summary.total_events, 0)
        self.assertEqual(summary.alert_count, len(alerts))
        self.assertTrue(alerts_file.exists())
        self.assertIn("brute_force_suspected", alert_types)
        self.assertIn("repeated_access_pattern", alert_types)
        self.assertIn("unusual_activity_spike", alert_types)
        self.assertIn("known_suspicious_ip_activity", alert_types)

    def test_alert_log_contains_valid_json_records(self) -> None:
        test_dir = reset_test_dir("alert_log_json")
        events_file = test_dir / "events.jsonl"
        alerts_file = test_dir / "alerts.log"

        generator = LogGenerator(
            GeneratorConfig(
                event_count=120,
                output_file=str(events_file),
                seed=7,
            )
        )
        generator.save(generator.generate())

        analyzer = LogAnalyzer(
            alert_manager=SilentAlertManager(str(alerts_file)),
            rule_config=RuleConfig(),
        )
        alerts, _ = analyzer.analyze_file(str(events_file))

        alert_lines = alerts_file.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(alert_lines), len(alerts))

        first_alert = json.loads(alert_lines[0])
        self.assertIn("timestamp", first_alert)
        self.assertIn("ip", first_alert)
        self.assertIn("threat_type", first_alert)
        self.assertIn("explanation", first_alert)
        self.assertIn("severity", first_alert)

    def test_analyzer_rejects_invalid_event_records(self) -> None:
        test_dir = reset_test_dir("invalid_input")
        invalid_events_file = test_dir / "invalid_events.jsonl"
        invalid_events_file.write_text(
            json.dumps(
                {
                    "timestamp": "2026-04-16T10:00:00+00:00",
                    "ip": "1.2.3.4",
                    "action": "login_failed",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        analyzer = LogAnalyzer(alert_manager=SilentAlertManager(str(test_dir / "alerts.log")))
        with self.assertRaises(ValueError):
            analyzer.analyze_file(str(invalid_events_file))


class AlertIntegrationTests(unittest.TestCase):
    def test_alert_manager_posts_json_to_webhook(self) -> None:
        test_dir = reset_test_dir("webhook_delivery")
        alerts_file = test_dir / "alerts.log"
        manager = AlertManager(str(alerts_file), webhook_url="https://example.test/webhook")
        sample_alert = {
            "timestamp": "2026-04-16T10:00:00+00:00",
            "ip": "10.10.10.10",
            "threat_type": "brute_force_suspected",
            "explanation": "Repeated failed logins detected.",
            "severity": "high",
            "user": "alice",
            "metadata": {"rule": "failed_login_burst"},
        }

        with patch("alerts.request.urlopen") as mocked_urlopen:
            from alerts import ThreatAlert
            with patch.object(manager, "_print_to_console"):
                manager.emit(ThreatAlert(**sample_alert))

        self.assertTrue(alerts_file.exists())
        sent_request = mocked_urlopen.call_args.args[0]
        self.assertEqual(sent_request.full_url, "https://example.test/webhook")
        self.assertEqual(sent_request.method, "POST")
        self.assertEqual(json.loads(sent_request.data.decode("utf-8")), sample_alert)


class WebDashboardTests(unittest.TestCase):
    def test_dashboard_homepage_renders_summary(self) -> None:
        test_dir = reset_test_dir("dashboard_render")
        events_file = test_dir / "events.jsonl"
        alerts_file = test_dir / "alerts.log"

        generator = LogGenerator(
            GeneratorConfig(
                event_count=120,
                output_file=str(events_file),
                seed=42,
            )
        )
        generator.save(generator.generate())

        app = create_app(
            argparse.Namespace(
                input=str(events_file),
                alerts_output=str(alerts_file),
                host="127.0.0.1",
                port=5000,
                debug=False,
                failed_threshold=5,
                failed_window=120,
                repeated_threshold=10,
                repeated_window=60,
                spike_threshold=15,
                spike_window=90,
            )
        )
        client = app.test_client()
        response = client.get("/")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Cloud Threat Detection Dashboard", body)
        self.assertIn("Recent Alerts", body)
        self.assertIn("Top Active IPs", body)


if __name__ == "__main__":
    unittest.main()
