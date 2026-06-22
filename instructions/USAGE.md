# Signal Triage — Usage Instructions (Beginner-Friendly)

This guide explains how to download, run, test, and understand **Signal Triage**.

Signal Triage is a Python SOC-style authentication log analyzer. It reads SSO/VPN-style login events, detects suspicious authentication activity, and creates:

- `report.md` — a SOC-style incident report (Markdown)
- `alerts.json` — structured alert export
- `alerts.csv` — spreadsheet-friendly alert export

---

## What Signal Triage detects

Signal Triage looks for suspicious authentication patterns that a SOC analyst might investigate:

- **Brute force** — many failures for one user from one IP
- **Password spraying** — one IP attempting many users
- **Success-after-failure** — multiple failures followed by a successful login
- **New IP for user** — first time a user is seen from an IP in the dataset
- **Impossible travel** — successful logins from different countries within a short window
- **Suspicious geography** — successful login from higher-risk countries (profile-based)

---

## Part 1 — Install Python (first-time setup)

You need **Python 3.10+**.

### Windows (recommended: python.org)
1. Go to: https://www.python.org/downloads/windows/
2. Download the latest Python 3 release.
3. Run the installer.
4. **IMPORTANT:** Check the box **“Add python.exe to PATH”** (or “Add Python to PATH”).
5. Finish installation.

### macOS
- Go to: https://www.python.org/downloads/macos/ and install Python, **or**
- If you already use Homebrew, you can install Python with Homebrew.

### Linux
Most distros have Python available via the package manager.

### Quick check (optional)
Open Terminal (macOS/Linux) or Command Prompt (Windows) and run:

python --version

Windows fallback:
py --version

---

## Part 2 — Download the project from GitHub (browser-first)

Go to the repository:
https://github.com/jacobceranski/signal-triage

### Option A: Download ZIP (easiest)
1. Click the green **Code** button.
2. Click **Download ZIP**.
3. Unzip the file somewhere easy (Desktop or Downloads).

You should end up with a folder like:
- `signal-triage-main/` (or similar)

### Option B: Clone (for Git users)
If you already use Git, you can clone the repo, but the ZIP method above is totally fine.

---

## Part 3 — Open the project folder

You want to open a terminal **in the repo folder**.

### Windows
1. Open the folder in File Explorer.
2. Click the address bar and type `cmd` then press Enter.
   - This opens Command Prompt in that folder.

### macOS
1. Open Terminal.
2. Drag the repo folder into Terminal to paste the path.
3. Press Enter.

### Linux
Open a terminal and `cd` into the repo folder.

---

## Part 4 — Run Signal Triage (sample data)

Signal Triage includes sample data you can use immediately.

From the project folder, run:

python -m src.cli sample_data/auth_sample.jsonl --profile balanced --out report.md --json alerts.json --csv alerts.csv

If that doesn’t work on Windows, try:

py -m src.cli sample_data/auth_sample.jsonl --profile balanced --out report.md --json alerts.json --csv alerts.csv

### What you should see
You should see a short console summary like:

- Events loaded: ...
- Alerts generated: ...

And these files will appear in the same folder:

- report.md
- alerts.json
- alerts.csv

---

## Part 5 — Open the output files

### Open report.md
`report.md` is a Markdown file. You can open it with:
- VS Code (recommended)
- Any text editor (Notepad, TextEdit)
- Some Markdown viewers

Tip: If you open it in a plain text editor, it will still be readable.

### Open alerts.json
`alerts.json` is structured data. You can open it with:
- VS Code (recommended)
- Any text editor

You’ll see an array/list of alert objects.

### Open alerts.csv
`alerts.csv` is spreadsheet-friendly. Open it with:
- Excel
- Google Sheets (File → Import)
- LibreOffice Calc

---

## Part 6 — Try different detection profiles (strict / balanced / loose)

Signal Triage supports multiple detection “profiles” that tune sensitivity.

Run the same command but change `--profile`:

Strict (fewer alerts, higher confidence)
python -m src.cli sample_data/auth_sample.jsonl --profile strict --out report.md --json alerts.json --csv alerts.csv

Balanced (recommended starting point)
python -m src.cli sample_data/auth_sample.jsonl --profile balanced --out report.md --json alerts.json --csv alerts.csv

Loose (more alerts, more sensitive)
python -m src.cli sample_data/auth_sample.jsonl --profile loose --out report.md --json alerts.json --csv alerts.csv

Windows fallback:
If `python` doesn’t work, replace `python` with `py`:
py -m src.cli sample_data/auth_sample.jsonl --profile balanced --out report.md --json alerts.json --csv alerts.csv

---

## Part 7 — Use your own authentication logs (JSONL / JSON / CSV)

You can analyze your own logs by replacing the input path.

Supported file types:
- JSON Lines: .jsonl or .ndjson (recommended)
- JSON: .json
- CSV: .csv

Run (example):
python -m src.cli path/to/your_auth_logs.jsonl --profile balanced --out report.md --json alerts.json --csv alerts.csv

Windows fallback:
py -m src.cli path/to/your_auth_logs.jsonl --profile balanced --out report.md --json alerts.json --csv alerts.csv

### What your log data should contain
Signal Triage works best when each event includes:
- Timestamp
- Username / user identity
- Source IP
- Outcome (success/failure)
- Optional: geo fields (country/city) and app/provider fields

Signal Triage normalizes common field names automatically, for example:

- Timestamp: `timestamp`, `time`, `ts`, `@timestamp`, `event_time`, `created_at`, `datetime`
- User: `user`, `username`, `user_name`, `email`, `principal`, `actor`
- Source IP: `source_ip`, `src_ip`, `ip`, `client_ip`, `remote_ip`, `sourceAddress`
- Outcome: `outcome`, `result`, `status`, `decision`, `success`
- App: `app`, `application`, `service`, `target`, `resource`, `provider`
- Geo: `country`, `src_country`, `geo_country`, `country_code`, `city`, `src_city`, `geo_city`

If your logs use different field names, you may need to rename columns/keys to match (or update the parser).

---

## Part 8 — Troubleshooting (common beginner issues)

### 1) “python is not recognized” (Windows)
Cause: Python installed but not added to PATH.

Fix:
- Re-run the Python installer and check “Add Python to PATH”, or
- Use `py` instead of `python`:

py -m src.cli sample_data/auth_sample.jsonl --profile balanced --out report.md --json alerts.json --csv alerts.csv

### 2) “No module named src” / import errors
Cause: You are not running the command from the project root folder.

Fix:
- Make sure your terminal is open in the folder that contains `src/`.
- Then run the command again.

### 3) “File not found” for your input logs
Cause: The file path is wrong.

Fix:
- Double-check the path.
- If the file is in the repo folder, use a simple relative path like:
  - `my_logs.jsonl`
  - `data/my_logs.csv`

### 4) “0 alerts generated”
This can be normal.

Possible reasons:
- Your dataset is small
- Your logins look normal
- The profile is too strict for your data

Fix:
- Try `--profile loose`
- Confirm your log file actually contains failures/successes and IPs

### 5) Report/alerts files didn’t appear
Cause: The command failed before writing outputs, or you’re looking in the wrong folder.

Fix:
- Re-run the command and watch for errors.
- Confirm you’re in the repo folder when you run it.
