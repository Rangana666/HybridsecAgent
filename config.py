"""
config.py — HybridSec Agent Global Configuration
All thresholds, file paths, schedules, and tunable parameters live here.
Override any value by setting the corresponding environment variable in .env
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# ── Load .env file ────────────────────────────────────────────
load_dotenv()

# ── Base Paths ────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
DATABASE_PATH = BASE_DIR / os.getenv("DATABASE_PATH", "database/hybridsec.db")
LOGS_DIR = BASE_DIR / "logs"
DATA_DIR = BASE_DIR / "data"
BACKUPS_DIR = DATA_DIR / "backups"
TRAINING_DIR = DATA_DIR / "training"
RULES_DIR = DATA_DIR / "rules"
MODELS_DIR = BASE_DIR / "modules" / "module3_scoring" / "models"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# ── Log File Paths ─────────────────────────────────────────────
APP_LOG = LOGS_DIR / "hybridsec.log"
SECURITY_LOG = LOGS_DIR / "security.log"
INCIDENTS_FILE = LOGS_DIR / "incidents.json"

# ── Rules & Model Files ────────────────────────────────────────
SECURITY_RULES_FILE = RULES_DIR / "security_rules.json"
ML_MODEL_FILE = MODELS_DIR / "risk_model.pkl"
LABEL_ENCODER_FILE = MODELS_DIR / "label_encoder.pkl"
TRAINING_DATASET = TRAINING_DIR / "vulnerability_dataset.csv"

# ── Flask Web Server ──────────────────────────────────────────
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE-THIS-IN-PRODUCTION")

# ── Session ───────────────────────────────────────────────────
SESSION_LIFETIME_HOURS = 8          # Session expires after 8 hours
MAX_LOGIN_ATTEMPTS = 10             # Account locked after this many failures
LOGIN_RATE_LIMIT = "5 per minute"   # Flask-Limiter rate limit string

# ── Admin Access ──────────────────────────────────────────────
ADMIN_WHITELIST_IPS = [
    ip.strip()
    for ip in os.getenv("ADMIN_WHITELIST_IPS", "127.0.0.1").split(",")
    if ip.strip()
]

# ── LLM Configuration ─────────────────────────────────────────
LLM_PROVIDER    = os.getenv("LLM_PROVIDER", "openai")   # openai | openrouter | gemini | local
OPENAI_API_KEY  = os.getenv("OPENAI_API_KEY", "")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL   = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
GEMINI_API_KEY  = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL    = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
USE_LOCAL_LLM   = os.getenv("USE_LOCAL_LLM", "false").lower() == "true"
LOCAL_LLM_URL   = os.getenv("LOCAL_LLM_URL", "http://localhost:11434/api/generate")
LOCAL_LLM_MODEL = os.getenv("LOCAL_LLM_MODEL", "llama3")
LLM_MODEL_NAME  = "gpt-4o-mini"    # OpenAI model used for scoring & remediation
LLM_MAX_TOKENS  = 500
LLM_TEMPERATURE = 0.2               # Low temperature = more deterministic output

# ── NVD CVE API ───────────────────────────────────────────────
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_REQUEST_TIMEOUT = 30            # seconds
NVD_RATE_LIMIT_DELAY = 0.6          # seconds between requests (NVD limit: ~50/30s)

# ── Scoring Engine Enable/Disable Toggles ────────────────────
ENGINE_RULE_ENABLED = os.getenv("ENGINE_RULE_ENABLED", "true").lower() == "true"
ENGINE_ML_ENABLED   = os.getenv("ENGINE_ML_ENABLED",   "true").lower() == "true"
ENGINE_LLM_ENABLED  = os.getenv("ENGINE_LLM_ENABLED",  "true").lower() == "true"

# ── Triple Hybrid Scoring Weights ─────────────────────────────
RULE_BASED_WEIGHT = 0.30
ML_WEIGHT = 0.35
LLM_WEIGHT = 0.35

# ── Priority Score Thresholds ─────────────────────────────────
PRIORITY_CRITICAL_MIN = 8.5         # 8.5 – 10.0 → CRITICAL (fix immediately)
PRIORITY_HIGH_MIN = 7.0             # 7.0 – 8.4  → HIGH     (fix within 24h)
PRIORITY_MEDIUM_MIN = 5.0           # 5.0 – 6.9  → MEDIUM   (fix this week)
PRIORITY_LOW_MIN = 0.0              # 0.0 – 4.9  → LOW      (fix this month)

# ── SME Context Multipliers (Module 2) ────────────────────────
BUSINESS_TYPE_MULTIPLIERS = {
    "E-commerce":   1.8,
    "Healthcare":   1.8,
    "Finance":      1.8,
    "IT Services":  1.4,
    "Restaurant":   1.0,
    "Other":        1.0,
}

EMPLOYEE_COUNT_ADDITIONS = {
    "1-10":   0.3,
    "11-50":  0.1,
    "51-300": 0.0,
}

SERVER_PURPOSE_ADDITIONS = {
    "Database":     0.4,
    "App Server":   0.3,
    "Web Server":   0.2,
    "Email Server": 0.1,
    "File Storage": 0.0,
}

SENSITIVE_DATA_ADDITION = {
    "Yes": 0.4,
    "No":  0.0,
}

IT_STAFF_ADDITION = {
    "No":  0.3,
    "Yes": 0.0,
}

BUDGET_ADDITION = {
    "Under $50":  0.2,
    "$50-200":    0.1,
    "$200+":      0.0,
}

# ── Scanning Schedule ─────────────────────────────────────────
DEEP_SCAN_TIME = os.getenv("DEEP_SCAN_TIME", "03:00")           # Daily deep scan
QUICK_SCAN_INTERVAL_HOURS = int(
    os.getenv("QUICK_SCAN_INTERVAL_HOURS", 6)
)

# ── Live Guard Detection Thresholds (Module 6) ─────────────────
SSH_BRUTE_FORCE_THRESHOLD = 5       # Failed logins that trigger a block
SSH_BRUTE_FORCE_WINDOW_SECONDS = 60 # Time window for counting failures

PORT_SCAN_THRESHOLD = 10            # Different ports scanned to trigger a block
PORT_SCAN_WINDOW_SECONDS = 30

DDOS_REQUEST_THRESHOLD = 100        # HTTP requests from one IP to trigger a block
DDOS_WINDOW_SECONDS = 60

# ── Linux Log File Paths (Module 6 monitors these) ────────────
AUTH_LOG_PATH = "/var/log/auth.log"             # SSH auth events
SYSLOG_PATH = "/var/log/syslog"                 # General system log
APACHE_ACCESS_LOG = "/var/log/apache2/access.log"
NGINX_ACCESS_LOG = "/var/log/nginx/access.log"

# ── Auto-Fix Safety ───────────────────────────────────────────
AUTOFIX_REQUIRE_CONFIRMATION = True  # Require admin to type YES before executing
AUTOFIX_CREATE_BACKUP = True         # Always backup config file before modifying
BACKUP_RETENTION_DAYS = 30           # Delete backups older than this

# ── Telegram Alerts ───────────────────────────────────────────
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
TELEGRAM_ENABLED = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)

# ── Email Alerts ──────────────────────────────────────────────
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
EMAIL_ALERTS_ENABLED = bool(ALERT_EMAIL and SMTP_PASSWORD)

# ── Logging ───────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_MAX_BYTES = 10 * 1024 * 1024    # 10 MB per log file
LOG_BACKUP_COUNT = 5                # Keep 5 rotated log files
