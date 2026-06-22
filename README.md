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
