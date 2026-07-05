# HybridSec Agent

**A context-aware Linux server security platform built for small and medium-sized enterprises (SMEs)**

HybridSec Agent automatically scans your Linux server for vulnerabilities, scores each risk based on your business context, and provides one-click automated fixes — all through a clean web dashboard. It combines rule-based analysis, machine learning, and language model reasoning into a single hybrid scoring engine to deliver the most accurate risk picture possible.

---

## What Problem Does It Solve?

Small and medium businesses running Linux servers face real security threats but often lack:
- Dedicated security staff to interpret vulnerability reports
- Tools that understand their specific business context
- Safe and automated ways to fix common misconfigurations
- Real-time threat monitoring without enterprise budgets

HybridSec Agent addresses all of this in one self-hosted, open-source platform.

---

## What It Does

| Capability | Description |
|---|---|
| **Vulnerability Scanning** | Detects SSH misconfigurations, firewall gaps, Apache/MySQL issues, weak passwords, SUID anomalies, and more |
| **Hybrid Risk Scoring** | Combines rule-based, ML, and LLM scoring weighted by your business type and size |
| **Auto-Fix Engine** | One-click fixes for supported vulnerabilities with automatic config backup and rollback |
| **Live Threat Guard** | Real-time detection of SSH brute force, port scans, SQLi/XSS attempts, and DDoS |
| **Remediation Guidance** | Step-by-step manual fix instructions for every detected vulnerability |
| **Report Generation** | Exportable PDF and HTML security reports |
| **Alert System** | Telegram and Email notifications for critical threats |

---

## Key Benefits

- **No security expertise required** — the dashboard explains every risk in plain language with clear fix steps
- **Business-aware scoring** — the same vulnerability scores higher on a customer-facing e-commerce server than an internal development machine
- **Safe auto-fixing** — every fix creates a timestamped backup first; one-click rollback if anything goes wrong
- **Self-hosted and private** — your scan data never leaves your server
- **Always-on protection** — Live Guard daemon monitors threats 24/7 in the background
- **Dark and light mode UI** — clean, modern dashboard that works on any screen

---

## Supported Environments

| Category | Supported |
|---|---|
| **Operating System** | Ubuntu 20.04, 22.04, 24.04 · Debian 11, 12 · CentOS 8+ · RHEL 8+ · Amazon Linux 2 |
| **Python** | 3.10 or higher |
| **Architecture** | x86_64 (AMD64) |
| **Browser** | Chrome, Firefox, Edge, Safari (any modern browser) |
| **Services Scanned** | SSH, Apache, MySQL, UFW/iptables, system users, cron jobs, SUID binaries |

---

## Features

### Module 1 — Vulnerability Collection
- Nmap-based port and service discovery
- System-level security checks (SSH config, firewall rules, password policy, SUID files)
- Apache and MySQL configuration auditing
- Lynis hardening score integration for deep audits
- NVD CVE enrichment via public API
- Quick scan mode (2–3 minutes) and Deep scan mode (full Lynis audit)

### Module 2 — SME Context Manager
- Business profile setup (business type, employee count, data sensitivity level)
- Context stored and applied to every vulnerability score automatically
- Profile validation with guided setup wizard
- Context modifier adjusts risk scores to your real-world exposure

### Module 3 — Hybrid Scoring Engine
- **Rule-based scorer** (30% weight) — deterministic CVSS-style scoring rules
- **ML scorer** (35% weight) — Random Forest model trained on vulnerability data
- **LLM scorer** (35% weight) — language model reasoning with full SME business context
- Score combiner produces final `hybrid_score` and priority label
- Each engine individually toggleable from the dashboard
- Triple Hybrid mode delivers highest accuracy; falls back gracefully if an engine is unavailable

| Priority | Score Range | Recommended Action |
|---|---|---|
| CRITICAL | 9.0 – 10.0 | Fix immediately |
| HIGH | 7.0 – 8.9 | Fix within 24 hours |
| MEDIUM | 4.0 – 6.9 | Fix within the week |
| LOW | 0.0 – 3.9 | Fix when convenient |

### Module 4 — Remediation and Auto-Fix
- Fix templates covering SSH, firewall, Apache, MySQL, and password policy
- Auto-fix with pre-fix config backup and one-click rollback
- Manual step-by-step instructions for every vulnerability type
- Risk level and estimated fix time shown per vulnerability
- Verification step after each auto-fix confirms the fix was applied correctly

**Auto-Fix Coverage:**

| Service | Supported Fixes |
|---|---|
| SSH | Disable root login, disable password auth, enforce key-based auth |
| Firewall | Enable UFW, set default deny policy, open required ports only |
| Apache | Disable directory listing, hide server version, set security headers |
| MySQL | Remove anonymous users, disable remote root login, remove test database |
| Passwords | Enforce minimum length, complexity rules, and expiry policy |

### Module 5 — Web Dashboard
- Secure login with Two-Factor Authentication (2FA via TOTP/Google Authenticator)
- Live server resource gauges — CPU, RAM, and disk usage updated every 5 seconds
- Security stat cards showing Critical, High, Medium, Low vulnerability counts
- Lynis hardening score ring with Good/Fair/Poor rating
- Top risks feed with hybrid scores and priority badges
- Full audit log of every action taken in the system
- Dark and light mode toggle with preference saved per browser
- CSRF-protected API endpoints throughout

### Module 6 — Live Guard (Real-Time Threat Detection)
- SSH brute force detection by monitoring `/var/log/auth.log`
- Port scan detection via UFW and syslog analysis
- Web attack detection (SQLi, XSS, DDoS) via Apache access log monitoring
- Automatic IP blocking via UFW/iptables when attack threshold is exceeded
- Telegram and Email alerts for critical incidents
- Scheduled background scans (quick scan every 6 hours, deep scan daily at 03:00)
- Incident feed on Live Guard page with timestamp, source IP, and severity

### Module 7 — Report Generator
- Full PDF security reports including vulnerability list, scores, and fix recommendations
- HTML reports for sharing in browser or attaching to emails
- Covers all scan findings, remediation status, and hardening score

---

## Project Structure

```
hybridsec-agent/
│
├── run.py                          # Application entry point
├── config.py                       # Central configuration
├── install.sh                      # One-command installer
├── requirements.txt                # Python dependencies
│
├── modules/
│   ├── module1_collection/         # Vulnerability scanning
│   │   ├── scanner.py              # Main scan orchestrator
│   │   ├── system_scanner.py       # OS-level security checks
│   │   ├── nmap_scanner.py         # Port and service scanning
│   │   ├── lynis_scanner.py        # Lynis hardening audit
│   │   └── nvd_api.py              # NVD CVE enrichment
│   │
│   ├── module2_context/            # SME business profile
│   │   ├── context_manager.py      # Profile storage and retrieval
│   │   └── profile_validator.py    # Input validation
│   │
│   ├── module3_scoring/            # Hybrid scoring engine
│   │   ├── hybrid_engine.py        # Master score orchestrator
│   │   ├── rule_based_scorer.py    # Rule engine (30% weight)
│   │   ├── ml_scorer.py            # Random Forest scorer (35% weight)
│   │   ├── llm_scorer.py           # LLM scorer (35% weight)
│   │   ├── score_combiner.py       # Weighted score combiner
│   │   └── models/train_model.py   # ML model training script
│   │
│   ├── module4_remediation/        # Remediation and auto-fix engine
│   │   ├── autofix_agent.py        # Auto-fix orchestrator
│   │   ├── backup_manager.py       # Config backup and rollback
│   │   ├── remediation_generator.py# Fix advice generator
│   │   └── fix_templates/          # Per-service fix templates
│   │       ├── ssh_fixes.py
│   │       ├── firewall_fixes.py
│   │       ├── apache_fixes.py
│   │       ├── mysql_fixes.py
│   │       └── password_fixes.py
│   │
│   ├── module5_web/                # Web dashboard
│   │   ├── app.py                  # Flask application factory
│   │   ├── routes.py               # Page routes
│   │   ├── api.py                  # REST API endpoints
│   │   └── auth.py                 # Login, 2FA, session management
│   │
│   ├── module6_liveguard/          # Real-time threat detection
│   │   ├── live_guard.py           # Daemon orchestrator
│   │   ├── ssh_monitor.py          # SSH brute force monitor
│   │   ├── web_monitor.py          # Web attack monitor
│   │   ├── port_scan_monitor.py    # Port scan monitor
│   │   ├── ip_blocker.py           # Firewall auto-block
│   │   └── alert_system.py         # Telegram and Email alerts
│   │
│   └── module7_reports/            # Report generation
│       ├── report_generator.py     # Report orchestrator
│       ├── pdf_generator.py        # PDF output
│       └── html_generator.py       # HTML output
│
├── templates/                      # Jinja2 HTML templates
├── static/                         # CSS, JavaScript, fonts
├── data/                           # Scan results and config backups
├── database/                       # SQLite database
├── logs/                           # Application logs
└── tests/                          # Unit and integration tests
```

---

## Installation

### Option 1 — One-Command Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/Rangana666/HybridsecAgent/main/install.sh | sudo bash
```

This automatically installs all system dependencies, Python packages, configures the systemd service, and starts the dashboard.

> **Already installed?** Running the same command again will automatically stop the old service, remove the old installation (your `.env` config is preserved), and install fresh — no manual cleanup needed.

---

### Option 2 — Manual Installation

**1. Clone the repository**
```bash
git clone https://github.com/Rangana666/HybridsecAgent.git
cd HybridsecAgent
```

**2. Create a virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Install Python dependencies**
```bash
pip install -r requirements.txt
```

**4. Install system tools**
```bash
sudo apt update
sudo apt install -y nmap lynis ufw
```

**5. Configure environment**
```bash
cp .env.example .env
nano .env
```

**6. Run the application**
```bash
python3 run.py
```

**7. Open the dashboard**

Go to `http://localhost:5443` in your browser and complete the first-time setup.

---

## Configuration

Edit `.env` in the project root:

```env
# Required
SECRET_KEY=your-random-secret-key-here

# LLM Scoring — enables the third scoring engine (choose one)
OPENAI_API_KEY=sk-...
OPENROUTER_API_KEY=sk-or-...
GEMINI_API_KEY=AIza...

# Telegram Alerts
TELEGRAM_BOT_TOKEN=your-bot-token
TELEGRAM_CHAT_ID=your-chat-id

# Email Alerts
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASS=your-app-password
ALERT_EMAIL_TO=admin@yourdomain.com
```

---

## How to Use

1. **Login** at `https://your-server:5443` (or `http://your-server:5000` as fallback)
2. **Set up your SME profile** — enter your business type, size, and data sensitivity level
3. **Run a scan** — choose Quick (2–3 min) or Deep (includes full Lynis audit)
4. **Review risks** — all vulnerabilities are ranked by hybrid score with full explanations
5. **Fix issues** — click Auto-Fix for supported types, or follow the provided manual steps
6. **Monitor threats** — the Live Guard tab shows real-time security incidents
7. **Generate a report** — export PDF or HTML for management review or compliance records

---

## Python Dependencies

| Package | Purpose |
|---|---|
| `flask` | Web framework |
| `scikit-learn`, `pandas`, `numpy` | ML scoring engine |
| `python-nmap` | Port and service scanning |
| `reportlab` | PDF report generation |
| `psutil` | Live server resource monitoring |
| `apscheduler` | Scheduled background scans |
| `pyotp`, `qrcode` | Two-factor authentication |
| `openai`, `google-generativeai` | LLM scoring engine |
| `python-dotenv` | Environment configuration |

---

## System Requirements

- Python 3.10 or higher
- Linux-based operating system (Ubuntu, Debian, CentOS, RHEL, Amazon Linux)
- `nmap` for port and service scanning
- `ufw` or `iptables` for firewall checks and Live Guard auto-blocking
- `lynis` for deep scan hardening score (optional but recommended)
- Root or sudo access for auto-fix commands and Live Guard IP blocking

---

## License

This project is released for research and educational purposes.

---

## Author

**Ravindu Rangana Gunasinghe**
BSc (Hons) Computer Science — Final Year Research Project
