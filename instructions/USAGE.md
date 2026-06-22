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
If you want to verify Python is installed, open Terminal (macOS/Linux) or Command Prompt (Windows) and run:

- `python --version`

If `python` doesn’t work on Windows, try:

- `py --version`

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
