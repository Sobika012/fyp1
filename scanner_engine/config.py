"""
Central configuration for the vulnerability scanner engine.
All timeouts, wordlists, and tunables are defined here.
"""

import os

# ==============================
# RUNTIME
# ==============================

BASIC_MAX_RUNTIME_SEC = 240
DEEP_MAX_RUNTIME_SEC = 600

# ==============================
# WORDLISTS
# ==============================

BASIC_WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/quick.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

DEEP_WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]

# ==============================
# ALLOWED FFUF STATUS CODES
# ==============================

FFUF_VALID_STATUS_CODES = (200, 301, 302, 403)
FFUF_MATCH_CODES_STR = "200,301,302,403"

# ==============================
# RISK SCORING (risk_scoring.py)
# ==============================

SENSITIVE_KEYWORDS = [
    "admin", "login", "auth", "dashboard", "panel",
    "config", "backup", "db", "sql", "manage",
    "portal", "account", "user", "upload", "api",
]

STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".map", ".min.js", ".min.css",
)

SCORE_PARAMETERIZED = 60
SCORE_SENSITIVE_KEYWORD = 40
SCORE_STATIC_FILE = -50

# ==============================
# BASIC MODE
# ==============================

BASIC_WHATWEB_TIMEOUT = 30
BASIC_FFUF_MAXTIME = 60
BASIC_NUCLEI_BUDGET = 180
BASIC_NUCLEI_SEVERITY = ["critical", "high"]
BASIC_NUCLEI_TAGS = ["sqli", "xss", "lfi", "rce"]
BASIC_NUCLEI_EXCLUDE_TAGS = ["slow", "dos", "bruteforce", "fuzz", "network"]
BASIC_NUCLEI_CONCURRENCY = 15
BASIC_NUCLEI_RATE_LIMIT = 50
BASIC_MAX_NUCLEI_TARGETS = 3

# ==============================
# DEEP MODE
# ==============================

DEEP_WHATWEB_TIMEOUT = 60
DEEP_FFUF_MAXTIME = 180
DEEP_NUCLEI_BUDGET = 300
DEEP_NUCLEI_SEVERITY = ["critical", "high", "medium", "low", "info"]
DEEP_NUCLEI_CONCURRENCY = 10
DEEP_NUCLEI_RATE_LIMIT = 40
DEEP_MAX_SQLMAP_TARGETS = 4
DEEP_SQLMAP_TIMEOUT_EACH = 120
DEEP_CRAWLER_MIN_REMAINING = 30

# ==============================
# OUTPUT
# ==============================

OUTPUT_BASE_DIR = os.path.join("scans", "output")
COMBINED_REPORT_FILENAME = "combined_report.json"

# ==============================
# HELPERS
# ==============================

def pick_wordlist(candidates):
    for path in candidates:
        if os.path.exists(path):
            return path
    return None
