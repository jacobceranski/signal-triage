<<<<<<< HEAD
Signal Triage

Simple SOC-style authentication log analyzer built in Python. It utilizes SSO/VPN-style login events and flags suspicious patterns, then produces an incident-style markdown report and readable alert exports.

Built by Jacob Ceranski

---

 What it does

Detections included:
- Brute force (many failures for one user from one IP)
- Password spraying (one IP attempting many users)
- Success-after-failure (many fails then a success)
- New IP for user (first time a user is seen from an IP in the dataset)
- Impossible travel (country-based) (successful logins from different countries within a short window)

Outputs:
- Console summary
- `report.md` (incident report style)
- `alerts.json`
- `alerts.csv`

---

 Requirements

- Windows / macOS / Linux
- Python 3.10+ 
- pip


---

 Input formats

 JSONL (one JSON object per line)
Each line is JSON.
=======
# Signal Triage

Simple SOC-style authentication log analyzer built in Python. It utilizes SSO/VPN-style login events and flags suspicious patterns, then produces an incident-style markdown report and readable alert exports.

Built by Jacob Ceranski.

## What it does

Detections included:

- Brute force: many failures for one user from one IP
- Password spraying: one IP attempting many users
- Success-after-failure: many failures followed by a success
- New IP for user: first time a user is seen from an IP in the dataset
- Impossible travel: country-based successful logins from different countries within a short window
- Suspicious geography: successful login from higher-risk countries configured in the profile

Outputs:

- Console summary
- `report.md` incident report style markdown
- `alerts.json`
- `alerts.csv`

## Requirements

- Windows, macOS, or Linux
- Python 3.10+
- pip

This project currently uses only the Python standard library, so no package install is required.

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

Example JSONL event:

```json
{"timestamp":"2026-06-22T09:00:00Z","user":"alice@example.com","source_ip":"198.51.100.10","action":"vpn.login","outcome":"failure","app":"VPN","country":"US","city":"Chicago"}
```

## Quick start

From the project folder:

```powershell
python -m src.cli sample_data/auth_sample.jsonl --profile balanced --out report.md --json alerts.json --csv alerts.csv
```

On macOS/Linux, use the same command:

```bash
python -m src.cli sample_data/auth_sample.jsonl --profile balanced --out report.md --json alerts.json --csv alerts.csv
```

## Profiles

Available profiles:

- `strict`: lower thresholds, more sensitive
- `balanced`: default SOC-style thresholds
- `loose`: higher thresholds, fewer alerts

## Project structure

```text
signal-triage/
├── README.md
├── sample_data/
│   └── auth_sample.jsonl
└── src/
    ├── __init__.py
    ├── cli.py
    ├── detections.py
    ├── parser.py
    ├── report.py
    └── scoring.py
```

## GitHub setup

```powershell
cd C:\Users\jacob\Projects\signal-triage
git init
git add .
git commit -m "Initial Signal Triage analyzer"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/signal-triage.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username.
>>>>>>> 5be87b0 (Build Signal Triage auth log analyzer)
