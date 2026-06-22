# Signal Triage

Signal Triage is a simple SOC-style authentication log analyzer built in Python.

It analyzes SSO/VPN-style login events, flags suspicious authentication patterns, and produces an incident-style Markdown report plus readable JSON and CSV alert exports.

Built by **Jacob Ceranski**.

---

## What it does

Signal Triage detects common authentication attack patterns, including:

- **Brute force**: many failures for one user from one IP
- **Password spraying**: one IP attempting many users
- **Success-after-failure**: many failures followed by a successful login
- **New IP for user**: first time a user is seen from an IP in the dataset
- **Impossible travel**: successful logins from different countries within a short time window
- **Suspicious geography**: successful login from higher-risk countries configured in the profile

---

## Outputs

The tool generates:

- Console summary
- `report.md` — incident-style Markdown report
- `alerts.json` — structured alert export
- `alerts.csv` — spreadsheet-friendly alert export

---

## Requirements

- Windows, macOS, or Linux
- Python 3.10+
- Git, if cloning from GitHub

This project currently uses only the Python standard library, so no package install is required.

---

## Refer to instructions

For full beginner-friendly setup and usage directions, open the instructions file here:

[View the Signal Triage instructions](instructions/USAGE.md)

The instructions explain how to:

- Install Python
- Download the project from GitHub
- Run Signal Triage
- Open the generated report
- View the JSON and CSV alert files
- Test different detection profiles
- Use your own authentication logs
- Troubleshoot common beginner errors

---

## Input formats

Signal Triage supports:

- JSON Lines: `.jsonl` or `.ndjson`
- JSON: `.json`
- CSV: `.csv`

Common field names are normalized automatically, including:

- Timestamp: `timestamp`, `time`, `ts`, `@timestamp`, `event_time`, `created_at`, `datetime`
- User: `user`, `username`, `user_name`, `email`, `principal`, `actor`
- Source IP: `source_ip`, `src_ip`, `ip`, `client_ip`, `remote_ip`, `sourceAddress`
- Outcome: `outcome`, `result`, `status`, `decision`, `success`
- App: `app`, `application`, `service`, `target`, `resource`, `provider`
- Geo: `country`, `src_country`, `geo_country`, `country_code`, `city`, `src_city`, `geo_city`

---

## Example JSONL event

Each line in a `.jsonl` file should contain one authentication event:
