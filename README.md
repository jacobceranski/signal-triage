   _____ _                   _   _______     _                   
  / ____(_)                 | | |__   __|   (_)                  
 | (___  _  __ _ _ __   __ _| |    | |_ __   _  __ _  __ _  ___  
  \___ \| |/ _` | '_ \ / _` | |    | | '__| | |/ _` |/ _` |/ _ \ 
  ____) | | (_| | | | | (_| | |    | | |    | | (_| | (_| |  __/ 
 |_____/|_|\__, |_| |_|\__,_|_|    |_|_|    |_|\__,_|\__, |\___| 
            __/ |                                      __/ |     
           |___/                                      |___/      

           
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
