# Changelog

## 1.0.0 - Portfolio Release

### Added

- Synthetic authentication log generation in JSONL format.
- Modular rule-based detections for brute force, repeated access, activity spikes, and suspicious IP activity.
- Alert persistence to `logs/alerts.log`.
- Optional webhook forwarding for alert payloads.
- CLI summary view for SOC-style operational output.
- Flask dashboard for event, alert, and suspicious IP visibility.
- Docker and Docker Compose support.
- Automated tests for generator, analyzer, alert persistence, webhook behavior, and dashboard rendering.
- GitHub Actions CI workflow.
- Detection rule reference, sample incident report, operations runbook, and GitHub launch kit documentation.

### Notes

- This release is designed as a cybersecurity and DevSecOps portfolio project.
- The project uses synthetic data and should be hardened before any real production usage.
