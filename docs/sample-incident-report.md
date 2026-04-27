# Incident Report: Brute Force Attempt

## Executive Summary

The pipeline detected repeated failed authentication attempts from a single source IP within a short time window. The activity pattern is consistent with credential guessing or automated brute-force behavior.

## Evidence

- Source IP: `164.29.7.190`
- Failed attempts detected: `5`
- Time window: `120 seconds`
- Affected user: `eve`
- Detection rule: `brute_force_suspected`

## Severity

High

## Analyst Notes

The event sequence suggests deliberate account access attempts rather than normal user error. In a production SOC environment, this would warrant immediate review of adjacent activity, including successful authentications from the same source or username after the failure burst.

## Recommended Response

1. Block or rate-limit the offending source IP at the edge or identity layer.
2. Enforce MFA for the targeted account if not already required.
3. Review authentication logs for successful logins following the failure sequence.
4. Check whether the source IP appears in threat-intelligence or firewall deny lists.
5. Monitor the user account for password reset attempts or follow-on abuse.

## Lessons Learned

- Short-window failed-login detections provide strong early-warning value for credential attacks.
- Alert context should always include the time window, source IP, username, and failed attempt count.
- Pairing detections with a concise investigation template makes the project feel more like a real SOC workflow than a standalone parser.
