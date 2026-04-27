# Operations Runbook

This runbook provides quick operational steps for running, validating, and troubleshooting the SOC pipeline.

## Quick Validation

Run the automated tests:

```bash
python -m unittest discover -s tests -v
```

Expected result:

```text
OK
```

## Generate Fresh Telemetry

```bash
python src/main.py generate --count 200 --output logs/events.jsonl --seed 42
```

This creates synthetic authentication events in `logs/events.jsonl`.

## Analyze Logs

```bash
python src/main.py analyze --input logs/events.jsonl --alerts-output logs/alerts.log
```

Expected outputs:

- alert messages printed to the console
- persisted JSON alert records in `logs/alerts.log`
- a CLI summary of total events, alerts, top active IPs, and alert types

## Run the Full Pipeline

```bash
python src/main.py run --count 200 --output logs/events.jsonl --alerts-output logs/alerts.log --seed 42
```

Use this for the fastest end-to-end demo.

## Start the Dashboard

```bash
python src/main.py dashboard --input logs/events.jsonl --alerts-output logs/alerts.log
```

Open:

```text
http://127.0.0.1:5000
```

## Webhook Delivery Check

Use `SOC_ALERT_WEBHOOK_URL` or `--webhook-url` to forward alerts as JSON payloads.

```bash
python src/main.py run --webhook-url https://example.com/security-alerts
```

## Troubleshooting

| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| `ModuleNotFoundError: flask` | Dependencies are not installed | Run `python -m pip install -r requirements.txt` |
| No alerts generated | Dataset is too small or thresholds are too high | Run with `--count 200` or lower thresholds |
| Dashboard shows missing logs | `logs/events.jsonl` does not exist | Run the pipeline before starting the dashboard |
| Webhook delivery fails | Endpoint unreachable or invalid URL | Verify URL and test endpoint availability |

## Analyst Review Flow

1. Run the full pipeline.
2. Review the CLI summary for alert volume and top suspicious IPs.
3. Open the dashboard and inspect recent alerts.
4. Open `docs/sample-incident-report.md` and map one alert into the investigation format.
5. Tune thresholds if alert volume is too noisy or too quiet.
