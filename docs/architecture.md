# Architecture Overview

This document explains the main components of the Cloud Threat Detection Pipeline and how data moves through the system.

## System Flow

```text
+-------------------+
|   Log Generator   |
|  JSONL auth logs  |
+---------+---------+
          |
          v
+-------------------+
|    Log Analyzer   |
| validation + flow |
+---------+---------+
          |
          v
+-------------------+
| Detection Rules   |
| rolling windows   |
+---------+---------+
          |
          v
+-------------------+       +-------------------+
|   Alert Manager   | ----> | Webhook Endpoint  |
| console + JSONL   |       | optional delivery |
+---------+---------+       +-------------------+
          |
          v
+-------------------+
| Flask Dashboard   |
| SOC visibility    |
+-------------------+
```

## Component Responsibilities

| Component | File | Responsibility |
| --- | --- | --- |
| Log Generator | `src/log_generator.py` | Creates synthetic authentication events with normal and suspicious activity patterns. |
| Analyzer | `src/analyzer.py` | Reads JSONL logs, validates event records, applies detection rules, emits alerts, and builds summary metrics. |
| Detection Rules | `src/detector_rules.py` | Contains modular rule classes for brute-force, repeated access, activity spikes, and suspicious IP detections. |
| Alert Manager | `src/alerts.py` | Prints alerts, writes JSONL alert records, and optionally forwards alerts to a webhook. |
| CLI Entrypoint | `src/main.py` | Provides `generate`, `analyze`, `run`, and `dashboard` commands. |
| Web Dashboard | `src/web_dashboard.py` | Serves a Flask dashboard and JSON summary endpoint for reviewing detections. |
| Tests | `tests/test_pipeline.py` | Validates generator output, analyzer behavior, alert persistence, webhook delivery, and dashboard rendering. |

## Data Model

Generated events are stored as newline-delimited JSON records.

Core event fields:

- `timestamp`
- `ip`
- `user`
- `action`
- `country`
- `source`
- `user_agent`
- `outcome`
- `explanation`
- `threat_context`

Alert records are also stored as JSONL and include:

- `timestamp`
- `ip`
- `threat_type`
- `explanation`
- `severity`
- `user`
- `metadata`

## Detection Design

Rules operate over a shared `DetectionContext` that tracks rolling event windows and counters.

This design keeps rule logic isolated while allowing rules to share state such as:

- failed logins by IP
- successful logins by IP
- total activity by IP
- alert counts by IP
- per-rule cooldown state

## Operational Modes

The CLI supports four primary modes:

```bash
python src/main.py generate
python src/main.py analyze
python src/main.py run
python src/main.py dashboard
```

Use `run` for a full local demo and `dashboard` for analyst-facing review.

## Extension Points

Good next additions include:

- file-based rule configuration
- external threat-intelligence feed ingestion
- Slack or SOAR webhook formatting
- storage backend such as SQLite, PostgreSQL, or Elasticsearch
- cloud-style log ingestion from S3, CloudWatch, or syslog

## Security Notes

- The dataset is synthetic and safe for portfolio demonstration.
- Webhook forwarding is optional and should be tested before connecting to real systems.
- The dashboard is intended for local demonstration and should not be exposed publicly without authentication and hardening.
