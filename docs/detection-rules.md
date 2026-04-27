# Detection Rules Reference

This document describes the core detections implemented in the SOC pipeline and explains why each one matters from an analyst perspective.

| Rule | Severity | Logic | Why It Matters | MITRE ATT&CK |
| --- | --- | --- | --- | --- |
| `brute_force_suspected` | High | 5 failed logins from the same IP within 120 seconds | Indicates possible credential guessing or password spraying | T1110 |
| `repeated_access_pattern` | Medium | 10 authentication events from the same IP within 60 seconds | Highlights rapid repeated access that may indicate automation or scripted probing | T1078 / T1110.001 |
| `unusual_activity_spike` | Medium | 15 total events from the same IP within 90 seconds | Surfaces short-window spikes that can point to abuse, recon, or scripted account activity | T1059 / T1087 |
| `known_suspicious_ip_activity` | High | IP is present in the simulated suspicious IP set or marked by threat context | Simulates threat-intel hits that should be escalated quickly | T1071 / T1583 |

## Rule Design Notes

- The thresholds are intentionally simple and readable so the project is easy to discuss in interviews.
- Detection logic is isolated inside `src/detector_rules.py` to make future rule additions straightforward.
- Each alert includes explanation text and metadata so an analyst can quickly understand why the alert fired.

## Tuning Guidance

- Increase thresholds if the simulated environment produces too many alerts.
- Lower thresholds if you want a more sensitive demo for screenshots or walkthroughs.
- Replace the static suspicious IP list with a file-based or API-backed threat feed for a more advanced version.
