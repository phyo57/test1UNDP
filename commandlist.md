### 1\. Create and Enter the Python Environment

Run these commands in your terminal inside your project folder:

```sh
# Create a virtual environment named .venv
python3 -m venv .venv

# Activate the virtual environment
# On Linux / WSL / macOS:
source .venv/bin/activate

# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
```

* *Verification:* Your terminal prompt will display `(.venv)` on the left side.

---

### 2\. Install and Use Bandit

Bandit is a Python AST-based security scanner.

```sh
# Install Bandit inside your active environment
pip install bandit

# Run Bandit on a python file or directory recursively (-r)
bandit -r .
python -m bandit -r app.py
```

* *Verification:* The terminal outputs a scan summary table flagging any hardcoded credentials or insecure function calls.

---

### 3\. Install and Use Snyk

Snyk scans your dependency files for known CVEs and supply chain vulnerabilities.

```sh
# Install Snyk CLI (or use the standalone snyk binary/extension)
pip install snyk

# Authenticate your free Snyk account (first-time setup only)
snyk auth

# Test your project dependencies (e.g., requirements.txt)
snyk test

```

* *Verification:* Snyk scans your `requirements.txt` and prints a list of detected vulnerabilities with upgrade recommendations.

---

### 4\. Install and Use TruffleHog

TruffleHog scans your files and git history for hardcoded API keys and secrets.

```sh
# Install TruffleHog globally (Linux / WSL)
https://github.com/trufflesecurity/trufflehog/releases/tag/v3.99.8

curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin

# Run TruffleHog on a local folder without git
trufflehog filesystem . --no-update --results=verified,unknown

```

* *Verification:* TruffleHog prints out discovered secret patterns or confirms no secrets were found.

---

### 5\. Install and Use Semgrep

Semgrep is a language-agnostic static analysis tool for catching logic and data-flow flaws.

```sh
# Install Semgrep inside your active environment
pip install semgrep

# Run Semgrep using auto-configured security rules
semgrep scan --config=auto .

```

* *Verification:* Semgrep scans your codebase and highlights code vulnerabilities directly in the terminal output.

---

### 06\. Local Version Control & Static Analysis

```sh
# Turns your current folder into a tracked project
git init

# Selects all files in the folder to be saved
git add .

# Takes a snapshot of the files
git commit -m "initial commit"

# If You haven't committed the accidental deletion yet
git checkout . # (Or in newer Git versions: git restore .) 

# Ensure your local branch is named 'main' 
git branch -M main 

# Link your local folder to it
git remote add origin <your-repo-url> 

# Explicitly upload it
git push -u origin main

# Delete the hidden .git directory 
Remove-Item -Recurse -Force .git
```
