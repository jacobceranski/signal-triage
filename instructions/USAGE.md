# Signal Triage Usage Instructions

This guide explains how to download, run, test, and understand Signal Triage.

Signal Triage is a Python-based SOC-style authentication log analyzer. It reads SSO/VPN-style login events, detects suspicious authentication activity, and creates a report plus JSON and CSV alert exports.

---

# What Signal Triage Does

Signal Triage looks for suspicious login patterns that a SOC analyst might investigate.

It detects:

- **Brute force attempts** — many failed logins for one user from one IP address
- **Password spraying** — one IP address trying to log in to many different users
- **Success-after-failure** — a successful login after several failed login attempts
- **New IP for user** — a user logs in from a new IP address in the dataset
- **Impossible travel** — a user logs in from different countries within a short time window
- **Suspicious geography** — a successful login from a higher-risk country configured in the profile

---

# What Signal Triage Creates

When you run Signal Triage, it creates these files:

- `report.md` — a human-readable SOC-style report
- `alerts.json` — structured alert data
- `alerts.csv` — spreadsheet-friendly alert data

It also prints a summary in the terminal.

Example output:
