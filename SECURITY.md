# Security Policy

## Project Scope

This repository is a portfolio-oriented SOC simulation project. It generates synthetic authentication logs, applies rule-based detections, and demonstrates alerting workflows.

It is not intended to be deployed as-is in production environments without additional hardening, authentication, monitoring, and secure configuration review.

## Supported Version

The `main` branch is the actively maintained version of this project.

## Reporting Security Issues

If you find a security issue in this project, open a GitHub issue with:

- a clear description of the issue
- affected file or component
- steps to reproduce
- expected and actual behavior
- suggested remediation, if available

Do not include real secrets, real credentials, or sensitive production logs in reports.

## Safe Usage Notes

- Use synthetic or sanitized logs only.
- Do not point webhook forwarding at production incident systems without testing.
- Treat generated IP addresses as simulated data unless explicitly configured otherwise.
- Review thresholds before adapting this project to real telemetry.
