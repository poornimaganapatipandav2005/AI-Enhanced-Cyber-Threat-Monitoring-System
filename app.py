# ============================================================
#   CYBER THREAT DASHBOARD  –  app.py
#   Full-featured Flask backend with:
#     • Password hashing (werkzeug)
#     • 3-attempt login lockout + OpenCV intruder capture
#     • Forgot-password flow
#     • Session management & timeout
#     • Admin panel
#     • Real-time threat monitoring
# ============================================================

from flask import (Flask, request, render_template, redirect,
                   url_for, session, jsonify, flash)
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from datetime import datetime, timedelta
import os, subprocess, requests, uuid, re
import ipaddress, socket
import smtplib
from email.message import EmailMessage
from concurrent.futures import ThreadPoolExecutor
from db import get_engine, table_exists, init_email_alerts_table

# ── OpenCV (graceful fallback if not installed) ──────────────
try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

# ── Wireshark helper ─────────────────────────────────────────
try:
    from wireshark_integrate import get_connected_ips
    WIRESHARK_AVAILABLE = True
except Exception:
    WIRESHARK_AVAILABLE = False
    def get_connected_ips():
        return set()

# ============================================================
#   APP CONFIG
# ============================================================
app = Flask(__name__)
app.secret_key = "cyber_ultra_secret_2024_key"
app.permanent_session_lifetime = timedelta(minutes=30)   # session timeout

app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", "587"))
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "")
app.config["MAIL_SENDER"] = os.environ.get("MAIL_SENDER", app.config["MAIL_USERNAME"])
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}
app.config["ADMIN_ALERT_RECIPIENT"] = os.environ.get("ADMIN_ALERT_RECIPIENT", app.config["MAIL_USERNAME"])

# ── File paths ───────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
LOG_FILE        = os.path.join(BASE_DIR, "logs.xlsx")
USER_FILE       = os.path.join(BASE_DIR, "users.xlsx")
BLOCK_FILE      = os.path.join(BASE_DIR, "blocked_ips.xlsx")
INTRUDER_FILE   = os.path.join(BASE_DIR, "intruders.xlsx")
LOGIN_HIST_FILE = os.path.join(BASE_DIR, "login_history.xlsx")
INTRUDER_DIR    = os.path.join(BASE_DIR, "static", "intruders")

os.makedirs(INTRUDER_DIR, exist_ok=True)

# SQL engine (SQLite)
ENGINE = get_engine()

# ── Column schemas ───────────────────────────────────────────
LOG_COLUMNS        = ["Time","IP Address","Endpoint","Method","User Agent","Risk Score","Threat Type"]
USER_COLUMNS       = ["First Name","Last Name","Email","Mobile","Gender","Username","Password"]
BLOCK_COLUMNS      = ["IP Address","Blocked Time"]
INTRUDER_COLUMNS   = ["Username Attempted","IP Address","Date Time","Device Info","Image Name"]
LOGIN_HIST_COLUMNS = ["Username","IP Address","Date Time","Status","Device Info"]
EMAIL_ALERT_COLUMNS = [
    "id","alert_type","attack_type","severity","source_ip","recipient","subject",
    "description","recommended_action","event_key","timestamp","status"
]

ALERT_ATTACK_TYPES = {
    "Malware": {
        "severity": "High",
        "description": "Malware-like tooling or payload activity was detected.",
        "recommended_action": "Isolate the source, review downloaded files and processes, and block the IP if malicious.",
    },
    "SQL Injection": {
        "severity": "High",
        "description": "A request contained SQL injection patterns.",
        "recommended_action": "Review query handling, validate inputs, and inspect related authentication or database activity.",
    },
    "DDoS": {
        "severity": "Critical",
        "description": "Traffic patterns indicate possible denial-of-service activity.",
        "recommended_action": "Enable rate limiting, check traffic volume, and block or throttle abusive sources.",
    },
    "XSS": {
        "severity": "Medium",
        "description": "A request contained cross-site scripting payload indicators.",
        "recommended_action": "Verify output encoding, sanitize inputs, and review affected pages.",
    },
    "Port Scan": {
        "severity": "Low",
        "description": "Network reconnaissance or port scanning activity was detected.",
        "recommended_action": "Review exposed services, firewall rules, and repeated probes from the same source.",
    },
    "Intruder": {
        "severity": "Critical",
        "description": "An intruder capture or unauthorized access attempt was recorded.",
        "recommended_action": "Review the captured evidence, login history, and block the source if suspicious.",
    },
    "Multiple Failed Login Attempts": {
        "severity": "Critical",
        "description": "Multiple failed login attempts indicate a possible brute-force attack.",
        "recommended_action": "Review login history, verify the targeted account, and keep the source blocked until cleared.",
    },
}

NAME_PATTERN = re.compile(r"^[A-Za-z]+$")

# ── Runtime state ────────────────────────────────────────────
MONITORING_ENABLED = False
# Per-IP failed-login counter  {ip: count}
login_attempts: dict = {}

CHATBOT_RESPONSES = [
    {
        "keywords": ("blocked", "block", "ip"),
        "answer": "You can review blocked IP addresses in the blocked IP section. If an IP looks suspicious, keep it blocked and check the login history for matching failed attempts.",
    },
    {
        "keywords": ("login", "failed", "attempt", "intruder"),
        "answer": "Failed login attempts are tracked by IP address. After repeated failures, the dashboard records the event and can capture intruder details when camera support is available.",
    },
    {
        "keywords": ("email", "alert", "mail", "smtp"),
        "answer": "Email alerts need SMTP settings configured with MAIL_USERNAME and MAIL_PASSWORD. Check the email alert history to confirm whether alerts were sent or failed.",
    },
    {
        "keywords": ("risk", "score", "threat"),
        "answer": "Risk scores help prioritize suspicious requests. Higher scores should be investigated first, especially when paired with unknown endpoints, repeated access, or unusual user agents.",
    },
    {
        "keywords": ("wireshark", "network", "monitor", "traffic"),
        "answer": "Network monitoring uses the Wireshark helper when available. If it is unavailable, the app falls back gracefully and still keeps the dashboard usable.",
    },
    {
        "keywords": ("password", "forgot", "reset"),
        "answer": "Use the forgot-password flow to reset a user password. For security, make sure the account email and SMTP settings are configured correctly.",
    },
]


def get_chatbot_reply(message: str):
    clean_message = (message or "").strip().lower()
    if not clean_message:
        return "Please type a question about threats, blocked IPs, alerts, logins, or dashboard security."

    for item in CHATBOT_RESPONSES:
        if any(keyword in clean_message for keyword in item["keywords"]):
            return item["answer"]

    return "I can help with blocked IPs, failed logins, threat scores, email alerts, password reset, and network monitoring. Ask me about one of those dashboard topics."

# ============================================================
#   HELPER – INIT EXCEL FILES
# ============================================================
def init_files():
    init_email_alerts_table(ENGINE)

    # Ensure SQL tables exist. Prefer importing from existing Excel files
    specs = [
        ("logs",        LOG_FILE,        LOG_COLUMNS),
        ("users",       USER_FILE,       USER_COLUMNS),
        ("blocked_ips", BLOCK_FILE,      BLOCK_COLUMNS),
        ("intruders",   INTRUDER_FILE,   INTRUDER_COLUMNS),
        ("login_history", LOGIN_HIST_FILE, LOGIN_HIST_COLUMNS),
    ]
    for table_name, path, cols in specs:
        try:
            if table_exists(ENGINE, table_name):
                continue
            # If Excel file exists, import it; otherwise create empty table with columns
            if os.path.exists(path):
                df = pd.read_excel(path)
                # ensure columns
                for c in cols:
                    if c not in df.columns:
                        df[c] = ""
            else:
                df = pd.DataFrame(columns=cols)
            df.to_sql(table_name, ENGINE, if_exists="replace", index=False)
        except Exception:
            # on any failure, create an empty table
            pd.DataFrame(columns=cols).to_sql(table_name, ENGINE, if_exists="replace", index=False)


def read_table(table_name: str, cols: list, excel_path: str):
    try:
        return pd.read_sql_query(f"SELECT * FROM {table_name}", ENGINE)
    except Exception:
        # fallback: try to read excel and write to table, then return
        try:
            if os.path.exists(excel_path):
                df = pd.read_excel(excel_path)
                for c in cols:
                    if c not in df.columns:
                        df[c] = ""
            else:
                df = pd.DataFrame(columns=cols)
            df.to_sql(table_name, ENGINE, if_exists="replace", index=False)
            return df
        except Exception:
            return pd.DataFrame(columns=cols)


def write_table(table_name: str, df: pd.DataFrame, mode: str = "replace"):
    if mode == "append":
        df.to_sql(table_name, ENGINE, if_exists="append", index=False)
    else:
        df.to_sql(table_name, ENGINE, if_exists="replace", index=False)


def split_recipient_list(value: str):
    cleaned = re.split(r"[,;\n]+", value or "")
    return [email.strip() for email in cleaned if email.strip()]


def get_email_alert_settings():
    init_email_alerts_table(ENGINE)
    default_types = list(ALERT_ATTACK_TYPES.keys())
    try:
        df = pd.read_sql_query(
            "SELECT enabled, recipients, attack_types, dedupe_minutes FROM email_alert_settings WHERE id = 1",
            ENGINE,
        ).fillna("")
        row = df.iloc[0].to_dict() if not df.empty else {}
    except Exception:
        row = {}

    attack_types = split_recipient_list(row.get("attack_types", "")) or default_types
    recipients = split_recipient_list(row.get("recipients", "")) or split_recipient_list(app.config.get("ADMIN_ALERT_RECIPIENT", ""))
    try:
        dedupe_minutes = max(0, int(row.get("dedupe_minutes", 10)))
    except Exception:
        dedupe_minutes = 10

    return {
        "enabled": bool(int(row.get("enabled", 1) or 0)),
        "recipients": recipients,
        "attack_types": attack_types,
        "dedupe_minutes": dedupe_minutes,
    }


def save_email_alert_settings(enabled: bool, recipients: list, attack_types: list, dedupe_minutes: int):
    init_email_alerts_table(ENGINE)
    clean_recipients = ", ".join(split_recipient_list(",".join(recipients)))
    clean_types = ", ".join([t for t in attack_types if t in ALERT_ATTACK_TYPES])
    try:
        dedupe_minutes = max(0, int(dedupe_minutes))
    except Exception:
        dedupe_minutes = 10
    ENGINE.execute(
        """
        UPDATE email_alert_settings
        SET enabled = ?, recipients = ?, attack_types = ?, dedupe_minutes = ?, updated_at = ?
        WHERE id = 1
        """,
        (
            1 if enabled else 0,
            clean_recipients,
            clean_types,
            dedupe_minutes,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    ENGINE.commit()


def severity_for_risk(risk_score):
    try:
        risk = int(float(risk_score or 0))
    except Exception:
        risk = 0
    if risk >= 90:
        return "Critical"
    if risk >= 70:
        return "High"
    if risk >= 40:
        return "Medium"
    return "Low"


def normalize_attack_type(alert_type="", threat_type=""):
    text = f"{alert_type or ''} {threat_type or ''}".lower()
    for attack_type in ALERT_ATTACK_TYPES:
        if attack_type.lower() in text:
            return attack_type
    if "failed login" in text or "brute" in text:
        return "Multiple Failed Login Attempts"
    if "intruder" in text:
        return "Intruder"
    return threat_type or alert_type or "Security Alert"


def is_duplicate_alert(event_key: str, recipient: str, window_minutes: int):
    if not event_key or window_minutes <= 0:
        return False
    since = (datetime.now() - timedelta(minutes=window_minutes)).strftime("%Y-%m-%d %H:%M:%S")
    try:
        df = pd.read_sql_query(
            """
            SELECT id FROM email_alerts
            WHERE event_key = ? AND recipient = ? AND timestamp >= ? AND status = 'SENT'
            LIMIT 1
            """,
            ENGINE,
            params=[event_key, recipient, since],
        )
        return not df.empty
    except Exception:
        return False


def record_email_alert(alert_type: str, recipient: str, subject: str, status: str,
                       attack_type: str = "", severity: str = "", source_ip: str = "",
                       description: str = "", recommended_action: str = "", event_key: str = ""):
    init_email_alerts_table(ENGINE)
    row = {
        "alert_type": alert_type or "Security Alert",
        "attack_type": attack_type or alert_type or "Security Alert",
        "severity": severity or "Medium",
        "source_ip": source_ip or "",
        "recipient": recipient or "",
        "subject": subject or "",
        "description": description or "",
        "recommended_action": recommended_action or "",
        "event_key": event_key or "",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": status or "UNKNOWN",
    }
    try:
        pd.DataFrame([row]).to_sql("email_alerts", ENGINE, if_exists="append", index=False)
    except Exception:
        pass


def extract_alert_type(subject: str):
    clean = (subject or "Security Alert").strip()
    if ":" in clean:
        return clean.split(":", 1)[0].strip()
    return clean


def send_alert_email(subject, recipient, message, alert_type="", attack_type="", severity="",
                     source_ip="", description="", recommended_action="", event_key=""):
    alert_type = alert_type or extract_alert_type(subject)
    if not recipient:
        record_email_alert(alert_type, recipient, subject, "FAILED: missing recipient",
                           attack_type, severity, source_ip, description, recommended_action, event_key)
        return False
    if not app.config["MAIL_USERNAME"] or not app.config["MAIL_PASSWORD"]:
        record_email_alert(alert_type, recipient, subject, "FAILED: SMTP credentials not configured",
                           attack_type, severity, source_ip, description, recommended_action, event_key)
        return False

    email = EmailMessage()
    email["Subject"] = subject
    email["From"] = app.config.get("MAIL_SENDER") or app.config["MAIL_USERNAME"]
    email["To"] = recipient
    email.set_content(message)

    try:
        with smtplib.SMTP(app.config["MAIL_SERVER"], app.config["MAIL_PORT"], timeout=15) as smtp:
            if app.config["MAIL_USE_TLS"]:
                smtp.starttls()
            smtp.login(app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])
            smtp.send_message(email)
        record_email_alert(alert_type, recipient, subject, "SENT",
                           attack_type, severity, source_ip, description, recommended_action, event_key)
        return True
    except smtplib.SMTPException as exc:
        record_email_alert(alert_type, recipient, subject, f"FAILED: {exc}",
                           attack_type, severity, source_ip, description, recommended_action, event_key)
    except OSError as exc:
        record_email_alert(alert_type, recipient, subject, f"FAILED: {exc}",
                           attack_type, severity, source_ip, description, recommended_action, event_key)
    return False


def build_alert_message(alert_type, severity="", username="", ip_address="", threat_details="", recommended_action=""):
    return "\n".join([
        f"Attack Type: {alert_type}",
        f"Severity Level: {severity or 'Medium'}",
        f"Source IP: {ip_address or 'N/A'}",
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Username: {username or 'N/A'}",
        f"Description: {threat_details or 'N/A'}",
        f"Recommended Action: {recommended_action or 'Review the security dashboard and investigate this event.'}",
    ])


def admin_alert_recipient():
    return app.config.get("ADMIN_ALERT_RECIPIENT") or app.config.get("MAIL_USERNAME")


def get_user_email(username: str):
    try:
        users_df = read_table("users", USER_COLUMNS, USER_FILE).fillna("")
        users_df["Username"] = users_df["Username"].astype(str).str.strip()
        row = users_df[users_df["Username"].str.lower() == (username or "").strip().lower()]
        if not row.empty:
            return str(row.iloc[0].get("Email", "")).strip()
    except Exception:
        pass
    return ""


def send_security_alert(alert_type, subject, username="", ip_address="", threat_details="",
                        recommended_action="", recipient=None, threat_type="", risk_score=0,
                        event_key=None, force=False):
    settings = get_email_alert_settings()
    attack_type = normalize_attack_type(alert_type, threat_type or subject)
    if not force:
        if not settings["enabled"]:
            return False
        if attack_type in ALERT_ATTACK_TYPES and attack_type not in settings["attack_types"]:
            return False

    profile = ALERT_ATTACK_TYPES.get(attack_type, {})
    severity = profile.get("severity") or severity_for_risk(risk_score)
    description = threat_details or profile.get("description") or f"{attack_type} detected."
    action = recommended_action or profile.get("recommended_action") or "Review the security dashboard and investigate this event."
    event_key = event_key or f"{attack_type}|{ip_address}|{description[:80]}"
    recipients = [recipient] if recipient else settings["recipients"]
    if not recipients:
        recipients = [admin_alert_recipient()]

    message = build_alert_message(
        alert_type=attack_type,
        severity=severity,
        username=username,
        ip_address=ip_address,
        threat_details=description,
        recommended_action=action,
    )
    sent_any = False
    for to_addr in recipients:
        if not force and is_duplicate_alert(event_key, to_addr, settings["dedupe_minutes"]):
            record_email_alert(alert_type, to_addr, subject, "SKIPPED: duplicate suppressed",
                               attack_type, severity, ip_address, description, action, event_key)
            continue
        sent_any = send_alert_email(
            subject, to_addr, message,
            alert_type=alert_type,
            attack_type=attack_type,
            severity=severity,
            source_ip=ip_address,
            description=description,
            recommended_action=action,
            event_key=event_key,
        ) or sent_any
    return sent_any


def get_email_alert_metrics(limit=5):
    init_email_alerts_table(ENGINE)
    try:
        alerts_df = pd.read_sql_query(
            """
            SELECT id, alert_type, attack_type, severity, source_ip, recipient, subject,
                   description, recommended_action, timestamp, status
            FROM email_alerts
            ORDER BY datetime(timestamp) DESC, id DESC
            """,
            ENGINE,
        ).fillna("")
    except Exception:
        alerts_df = pd.DataFrame(columns=EMAIL_ALERT_COLUMNS)
    total_sent = int((alerts_df.get("status", pd.Series(dtype=str)).astype(str) == "SENT").sum()) if not alerts_df.empty else 0
    failed = int(alerts_df.get("status", pd.Series(dtype=str)).astype(str).str.startswith("FAILED").sum()) if not alerts_df.empty else 0
    return {
        "recent": alerts_df.head(limit).to_dict(orient="records"),
        "total_sent": total_sent,
        "failed": failed,
        "total": int(alerts_df.shape[0]),
    }


def is_valid_name(name: str):
    return 2 <= len(name) <= 30 and bool(NAME_PATTERN.fullmatch(name))


def get_local_ipv4_networks():
    networks = set()
    try:
        output = subprocess.check_output(["ipconfig"], stderr=subprocess.DEVNULL).decode(errors="ignore")
        current_ip = None
        for line in output.splitlines():
            clean = line.strip()
            if "IPv4 Address" in clean:
                current_ip = clean.split(":")[-1].strip().split("(")[0].strip()
            elif "Subnet Mask" in clean and current_ip:
                mask = clean.split(":")[-1].strip()
                try:
                    ip = ipaddress.ip_address(current_ip)
                    network = ipaddress.ip_network(f"{current_ip}/{mask}", strict=False)
                    if ip.version == 4 and not ip.is_loopback and not ip.is_link_local:
                        networks.add(network)
                except ValueError:
                    pass
                current_ip = None
    except Exception:
        pass
    return networks


def get_connected_wifi_ipv4_networks():
    wifi_networks = set()
    try:
        output = subprocess.check_output(["ipconfig"], stderr=subprocess.DEVNULL).decode(errors="ignore")
        adapter_name = ""
        current_ip = None
        active_adapter = False
        wifi_keywords = ("wireless", "wi-fi", "wifi", "wlan")

        for line in output.splitlines():
            clean = line.strip()
            if line and not line.startswith(" ") and clean.endswith(":"):
                adapter_name = clean[:-1].lower()
                current_ip = None
                active_adapter = not clean.lower().endswith("media disconnected:")
                continue
            if "Media disconnected" in clean:
                active_adapter = False
            if "IPv4 Address" in clean:
                current_ip = clean.split(":")[-1].strip().split("(")[0].strip()
            elif "Subnet Mask" in clean and current_ip:
                mask = clean.split(":")[-1].strip()
                try:
                    network = ipaddress.ip_network(f"{current_ip}/{mask}", strict=False)
                    ip_obj = ipaddress.ip_address(current_ip)
                    is_wifi_adapter = any(keyword in adapter_name for keyword in wifi_keywords)
                    if ip_obj.version == 4 and not ip_obj.is_loopback and active_adapter and is_wifi_adapter:
                        wifi_networks.add(network)
                except ValueError:
                    pass
                current_ip = None
    except Exception:
        pass
    if not wifi_networks:
        wifi_networks = get_local_ipv4_networks()
    return wifi_networks


def get_local_ipv4_addresses():
    addresses = set()
    try:
        output = subprocess.check_output(["ipconfig"], stderr=subprocess.DEVNULL).decode(errors="ignore")
        for line in output.splitlines():
            clean = line.strip()
            if "IPv4 Address" in clean:
                addresses.add(clean.split(":")[-1].strip().split("(")[0].strip())
    except Exception:
        pass
    return addresses


def warm_arp_cache():
    targets = []
    for network in get_connected_wifi_ipv4_networks():
        # Keep scans quick on large networks by probing a /24 around this host.
        if network.num_addresses > 256:
            continue
        targets.extend(str(ip) for ip in network.hosts())

    def ping(ip_addr):
        try:
            subprocess.run(
                ["ping", "-n", "1", "-w", "250", ip_addr],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1
            )
        except Exception:
            pass

    if targets:
        with ThreadPoolExecutor(max_workers=64) as pool:
            list(pool.map(ping, targets))


def is_local_network_ip(ip_addr, networks=None):
    try:
        ip_obj = ipaddress.ip_address(str(ip_addr))
    except ValueError:
        return False
    if networks is None:
        networks = get_local_ipv4_networks()
    return any(ip_obj in network for network in networks)


def scan_network_devices():
    seen = {}
    local_networks = get_connected_wifi_ipv4_networks()
    local_addresses = get_local_ipv4_addresses()

    try:
        for ip_addr in get_connected_ips():
            if str(ip_addr) not in local_addresses and is_local_network_ip(ip_addr, local_networks):
                seen[str(ip_addr)] = {"mac": "N/A", "host": "Unknown"}
    except Exception:
        pass

    warm_arp_cache()

    try:
        arp_out = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL).decode(errors="ignore")
        for line in arp_out.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            ip_addr, mac_addr, row_type = parts[0].strip(), parts[1].strip(), parts[2].strip().lower()
            try:
                ip_obj = ipaddress.ip_address(ip_addr)
            except ValueError:
                continue
            if (
                ip_obj.is_multicast
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_unspecified
                or not is_local_network_ip(ip_addr, local_networks)
                or ip_addr in local_addresses
                or ip_addr.endswith(".255")
                or mac_addr.lower() == "ff-ff-ff-ff-ff-ff"
            ):
                continue
            if row_type not in {"dynamic", "static"}:
                continue
            seen[ip_addr] = {"mac": mac_addr, "host": seen.get(ip_addr, {}).get("host", "Unknown")}
    except Exception:
        pass

    for ip_addr in list(seen.keys()):
        try:
            seen[ip_addr]["host"] = socket.gethostbyaddr(ip_addr)[0]
        except Exception:
            pass

    return [
        {
            "ip": ip_addr,
            "mac": info.get("mac", "N/A"),
            "host": info.get("host", "Unknown"),
            "status": "Connected",
        }
        for ip_addr, info in sorted(seen.items(), key=lambda item: tuple(int(part) for part in item[0].split(".")))
    ]

# ============================================================
#   HELPER – RISK SCORING
# ============================================================
def calculate_risk(endpoint: str, user_agent: str):
    ep = (endpoint or "").lower()
    ua = (user_agent or "").lower()
    if any(k in ep for k in ["select ", "union ", "' or ", "1=1"]):
        return 85, "SQL Injection"
    if "<script" in ep or "javascript:" in ep:
        return 70, "XSS"
    if "../" in ep or "..%2f" in ep:
        return 60, "Directory Traversal"
    if "sqlmap" in ua:
        return 75, "Malware"
    if "botnet" in ua or "ddos" in ua:
        return 90, "DDoS"
    if "nmap" in ua or "masscan" in ua:
        return 40, "Port Scan"
    if "nikto" in ua or "dirbuster" in ua:
        return 55, "Web Scanner"
    return 5, "Normal"


def _safe_datetime(value):
    try:
        return pd.to_datetime(value, errors="coerce")
    except Exception:
        return pd.NaT


def explain_security_alert(alert_type="", endpoint="", user_agent="", status="", risk_score=0):
    """Convert a technical alert/log row into a short message that non-technical users can read."""
    text = " ".join(str(value or "").lower() for value in [alert_type, endpoint, user_agent, status])
    risk = int(float(risk_score or 0))

    if any(word in text for word in ["failed", "locked", "login", "intruder", "brute"]):
        return "Possible brute-force attack detected."
    if any(word in text for word in ["email", "mail", "smtp", "phishing", "recipient"]):
        return "Possible phishing attempt detected."
    if any(word in text for word in ["ddos", "botnet"]) or risk >= 90:
        return "Possible DDoS activity detected."
    if any(word in text for word in ["sql", "select ", "union ", "1=1"]):
        return "Possible SQL injection attempt detected."
    if any(word in text for word in ["xss", "<script", "javascript:"]):
        return "Possible cross-site scripting attempt detected."
    if any(word in text for word in ["port scan", "nmap", "masscan"]):
        return "Possible port scanning activity detected."
    if risk >= 70:
        return "High-risk security activity detected."
    if risk >= 40:
        return "Suspicious activity detected and should be reviewed."
    return "No active security alert summary is available."


def build_ai_alert_summary():
    """Build the latest AI Alert Summary from logs, login history, and email alert records."""
    init_files()

    try:
        logs_df = read_table("logs", LOG_COLUMNS, LOG_FILE).fillna("")
    except Exception:
        logs_df = pd.DataFrame(columns=LOG_COLUMNS)
    logs_df["Risk Score"] = pd.to_numeric(logs_df.get("Risk Score", 0), errors="coerce").fillna(0)
    logs_df["Time Parsed"] = pd.to_datetime(logs_df.get("Time", ""), errors="coerce")

    try:
        login_df = read_table("login_history", LOGIN_HIST_COLUMNS, LOGIN_HIST_FILE).fillna("")
    except Exception:
        login_df = pd.DataFrame(columns=LOGIN_HIST_COLUMNS)
    login_df["Date Parsed"] = pd.to_datetime(login_df.get("Date Time", ""), errors="coerce")

    try:
        email_df = pd.read_sql_query(
            "SELECT alert_type, recipient, subject, timestamp, status FROM email_alerts",
            ENGINE
        ).fillna("")
    except Exception:
        email_df = pd.DataFrame(columns=["alert_type", "recipient", "subject", "timestamp", "status"])
    email_df["Date Parsed"] = pd.to_datetime(email_df.get("timestamp", ""), errors="coerce")

    candidates = []

    # Include recent high-risk logs so technical rows become plain-language explanations.
    for _, row in logs_df[logs_df["Risk Score"] >= 40].tail(5).iterrows():
        candidates.append({
            "time": row.get("Time Parsed"),
            "summary": explain_security_alert(
                alert_type=row.get("Threat Type", ""),
                endpoint=row.get("Endpoint", ""),
                user_agent=row.get("User Agent", ""),
                risk_score=row.get("Risk Score", 0),
            ),
            "source": row.get("Threat Type", "Security Log") or "Security Log",
            "details": f"IP {row.get('IP Address', 'Unknown')} reached {row.get('Endpoint', 'Unknown endpoint')}",
            "risk": int(row.get("Risk Score", 0) or 0),
        })

    # Include failed-login rows so lockout/brute-force alerts are summarized even if they are not web request logs.
    failed_logins = login_df[login_df.get("Status", "").astype(str).str.contains("fail|locked", case=False, na=False)]
    for _, row in failed_logins.tail(5).iterrows():
        candidates.append({
            "time": row.get("Date Parsed"),
            "summary": explain_security_alert(alert_type="failed login"),
            "source": "Login History",
            "details": f"User {row.get('Username', 'Unknown')} from IP {row.get('IP Address', 'Unknown')}",
            "risk": 75,
        })

    # Include email alerts so mail/SMPP failures or suspicious email activity become a phishing-style summary.
    for _, row in email_df.tail(5).iterrows():
        subject = row.get("subject", "")
        candidates.append({
            "time": row.get("Date Parsed"),
            "summary": explain_security_alert(
                alert_type=row.get("alert_type", ""),
                endpoint=subject,
                status=row.get("status", ""),
            ),
            "source": row.get("alert_type", "Email Alert") or "Email Alert",
            "details": subject or row.get("status", "Email alert generated"),
            "risk": 60,
        })

    candidates = [item for item in candidates if not pd.isna(item.get("time"))]
    candidates.sort(key=lambda item: item["time"], reverse=True)

    if not candidates:
        return {
            "summary": "No active security alert summary is available.",
            "source": "System",
            "details": "The dashboard has not detected a recent alert.",
            "risk": 0,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "recent": [],
        }

    latest = candidates[0]
    return {
        "summary": latest["summary"],
        "source": latest["source"],
        "details": latest["details"],
        "risk": latest["risk"],
        "time": latest["time"].strftime("%Y-%m-%d %H:%M:%S"),
        "recent": [
            {
                "summary": item["summary"],
                "source": item["source"],
                "details": item["details"],
                "risk": item["risk"],
                "time": item["time"].strftime("%Y-%m-%d %H:%M:%S"),
            }
            for item in candidates[:4]
        ],
    }


def build_copilot_context():
    init_files()
    now = datetime.now()
    today = now.date()
    week_start = today - timedelta(days=6)

    try:
        logs_df = read_table("logs", LOG_COLUMNS, LOG_FILE).fillna("")
    except Exception:
        logs_df = pd.DataFrame(columns=LOG_COLUMNS)
    logs_df["Risk Score"] = pd.to_numeric(logs_df.get("Risk Score", 0), errors="coerce").fillna(0)
    logs_df["Time Parsed"] = pd.to_datetime(logs_df.get("Time", ""), errors="coerce")
    today_logs = logs_df[logs_df["Time Parsed"].dt.date == today].copy()
    week_logs = logs_df[logs_df["Time Parsed"].dt.date >= week_start].copy()
    threat_logs = today_logs[today_logs["Risk Score"] >= 40].copy()

    try:
        blocked_df = read_table("blocked_ips", BLOCK_COLUMNS, BLOCK_FILE).fillna("")
    except Exception:
        blocked_df = pd.DataFrame(columns=BLOCK_COLUMNS)

    try:
        intruder_df = read_table("intruders", INTRUDER_COLUMNS, INTRUDER_FILE).fillna("")
    except Exception:
        intruder_df = pd.DataFrame(columns=INTRUDER_COLUMNS)
    intruder_df["Date Parsed"] = pd.to_datetime(intruder_df.get("Date Time", ""), errors="coerce")
    today_intruders = intruder_df[intruder_df["Date Parsed"].dt.date == today].copy()

    try:
        login_df = read_table("login_history", LOGIN_HIST_COLUMNS, LOGIN_HIST_FILE).fillna("")
    except Exception:
        login_df = pd.DataFrame(columns=LOGIN_HIST_COLUMNS)
    login_df["Date Parsed"] = pd.to_datetime(login_df.get("Date Time", ""), errors="coerce")
    today_logins = login_df[login_df["Date Parsed"].dt.date == today].copy()

    threat_types = {}
    if not threat_logs.empty:
        threat_types = threat_logs["Threat Type"].astype(str).replace("", "Unknown").value_counts().to_dict()

    top_ips = []
    if not threat_logs.empty:
        grouped = threat_logs.groupby("IP Address").agg(
            events=("IP Address", "size"),
            max_risk=("Risk Score", "max"),
            last_seen=("Time Parsed", "max"),
        ).reset_index().sort_values(["max_risk", "events"], ascending=[False, False])
        top_ips = grouped.head(5).fillna("").to_dict(orient="records")

    failed_logins = today_logins[today_logins["Status"].astype(str).str.upper().str.contains("FAILED|LOCKED", na=False)]

    return {
        "today": today,
        "logs": logs_df,
        "today_logs": today_logs,
        "week_logs": week_logs,
        "threat_logs": threat_logs,
        "blocked": blocked_df,
        "intruders": intruder_df,
        "today_intruders": today_intruders,
        "login_history": login_df,
        "today_logins": today_logins,
        "failed_logins": failed_logins,
        "threat_types": threat_types,
        "top_ips": top_ips,
    }


def _format_top_items(items):
    if not items:
        return "No high-priority source IPs were found today."
    lines = []
    for item in items:
        last_seen = item.get("last_seen", "")
        if hasattr(last_seen, "strftime") and not pd.isna(last_seen):
            last_seen = last_seen.strftime("%H:%M:%S")
        lines.append(
            f"- {item.get('IP Address', 'Unknown')}: {int(item.get('events', 0))} event(s), "
            f"max risk {int(item.get('max_risk', 0))}, last seen {last_seen or 'unknown'}"
        )
    return "\n".join(lines)


def generate_copilot_answer(question):
    ctx = build_copilot_context()
    q = (question or "").strip()
    q_lower = q.lower()

    if not q:
        return "Ask a security question such as 'Summarize today's incidents' or 'What should I investigate first?'"

    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", q)
    if ip_match:
        ip = ip_match.group(0)
        related_logs = ctx["logs"][ctx["logs"]["IP Address"].astype(str) == ip].copy()
        related_blocks = ctx["blocked"][ctx["blocked"]["IP Address"].astype(str) == ip].copy()
        if related_logs.empty and related_blocks.empty:
            return f"I do not see activity for {ip} in the current logs or blocked IP list."
        answer = [f"IP review for {ip}:"]
        if not related_blocks.empty:
            blocked_time = related_blocks.iloc[-1].get("Blocked Time", "unknown time")
            answer.append(f"- Block status: currently blocked since {blocked_time}.")
        if not related_logs.empty:
            related_logs["Risk Score"] = pd.to_numeric(related_logs["Risk Score"], errors="coerce").fillna(0)
            max_risk = int(related_logs["Risk Score"].max())
            threats = ", ".join(related_logs["Threat Type"].astype(str).replace("", "Unknown").value_counts().head(3).index)
            last = related_logs.tail(1).iloc[0]
            answer.append(f"- Activity: {len(related_logs)} logged event(s), highest risk {max_risk}, main threat(s): {threats}.")
            answer.append(f"- Latest event: {last.get('Time', '')} on {last.get('Endpoint', '')} using {last.get('Method', '')}.")
            if max_risk >= 70:
                answer.append("- Recommendation: keep it blocked, inspect matching endpoints, and check whether any account activity occurred near this timestamp.")
            elif max_risk >= 40:
                answer.append("- Recommendation: review recent requests from this source and block it if the behavior repeats.")
            else:
                answer.append("- Recommendation: monitor only; current risk is low.")
        return "\n".join(answer)

    if any(term in q_lower for term in ["today", "summary", "summarize", "incidents"]):
        threat_count = int(ctx["threat_logs"].shape[0])
        total_count = int(ctx["today_logs"].shape[0])
        blocked_count = int(ctx["blocked"].shape[0])
        intruder_count = int(ctx["today_intruders"].shape[0])
        failed_count = int(ctx["failed_logins"].shape[0])
        type_summary = ", ".join(f"{name}: {count}" for name, count in list(ctx["threat_types"].items())[:5]) or "no high-risk threat types"
        return "\n".join([
            f"Today's security summary for {ctx['today'].strftime('%Y-%m-%d')}:",
            f"- {threat_count} threat event(s) out of {total_count} total logged request(s).",
            f"- Threat mix: {type_summary}.",
            f"- {blocked_count} IP address(es) are currently blocked.",
            f"- {intruder_count} intruder capture(s) and {failed_count} failed/locked login event(s) today.",
            "Recommended next step: start with the highest-risk IP and correlate it with login failures or intruder captures."
        ])

    if any(term in q_lower for term in ["top threat", "this week", "week"]):
        week_logs = ctx["week_logs"][ctx["week_logs"]["Risk Score"] >= 40]
        if week_logs.empty:
            return "No high-risk threats were logged in the last 7 days."
        top_types = week_logs["Threat Type"].astype(str).replace("", "Unknown").value_counts().head(5)
        lines = ["Top threats in the last 7 days:"]
        lines.extend(f"- {name}: {int(count)} event(s)" for name, count in top_types.items())
        lines.append("Recommended action: focus controls and validation around the highest-volume category first.")
        return "\n".join(lines)

    if any(term in q_lower for term in ["suspicious ip", "suspicious ips", "top ip", "top ips"]):
        if not ctx["top_ips"]:
            return "No suspicious source IPs were found in today's high-risk request logs."
        return "\n".join([
            "Top suspicious IPs today:",
            _format_top_items(ctx["top_ips"]),
            "Recommended action: review each source, check matching login failures, and block repeated high-risk activity.",
        ])

    if any(term in q_lower for term in ["investigate", "first", "priority", "recommended action", "recommend"]):
        if ctx["top_ips"]:
            first = ctx["top_ips"][0]
            return "\n".join([
                "Investigation priority:",
                f"- Start with {first.get('IP Address', 'Unknown')} because it has the highest current risk signal: "
                f"{int(first.get('events', 0))} event(s), max risk {int(first.get('max_risk', 0))}.",
                "- Then review blocked IPs, failed logins, and intruder captures around the same timestamps.",
                "- If the endpoint was login/admin/API related, reset affected credentials and preserve logs for evidence.",
                "",
                "Top source IPs:",
                _format_top_items(ctx["top_ips"]),
            ])
        if not ctx["failed_logins"].empty:
            return "Investigate failed or locked login attempts first. There are no high-risk request logs today, so account access anomalies are the strongest signal."
        return "No urgent investigation target is visible right now. Keep monitoring active and review any new high-risk events as they arrive."

    if any(term in q_lower for term in ["abnormal", "users", "user behaved"]):
        failed = ctx["failed_logins"]
        if failed.empty:
            return "I do not see abnormal user behavior today based on failed or locked login history."
        grouped = failed.groupby("Username").size().sort_values(ascending=False).head(5)
        lines = ["Users with abnormal login behavior today:"]
        lines.extend(f"- {user or 'Unknown'}: {int(count)} failed/locked event(s)" for user, count in grouped.items())
        lines.append("Recommended action: verify these users, check source IPs, and enforce a password reset if the attempts were unexpected.")
        return "\n".join(lines)

    if any(term in q_lower for term in ["report", "executive", "daily", "weekly"]):
        threat_count = int(ctx["threat_logs"].shape[0])
        blocked_count = int(ctx["blocked"].shape[0])
        top = ctx["top_ips"][0].get("IP Address") if ctx["top_ips"] else "none"
        return "\n".join([
            "Executive security report:",
            f"- Threat posture: {'Elevated' if threat_count else 'Stable'}",
            f"- Threat events today: {threat_count}",
            f"- Blocked IPs: {blocked_count}",
            f"- Primary source to watch: {top}",
            "- Management note: continue monitoring and review high-risk sources before closing the day."
        ])

    return "\n".join([
        "Here is the best current read:",
        f"- Threat events today: {int(ctx['threat_logs'].shape[0])}",
        f"- Blocked IPs: {int(ctx['blocked'].shape[0])}",
        f"- Intruder captures today: {int(ctx['today_intruders'].shape[0])}",
        "",
        "Try asking: 'Summarize today's incidents', 'What should I investigate first?', or 'Why was 203.0.113.42 blocked?'"
    ])

# ============================================================
#   HELPER – CAPTURE INTRUDER PHOTO
# ============================================================
def capture_intruder(username_attempted: str):
    """Activate webcam, capture one frame, save to static/intruders/."""
    img_name = f"intruder_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}.jpg"
    img_path = os.path.join(INTRUDER_DIR, img_name)

    if CV2_AVAILABLE:
        try:
            cam = cv2.VideoCapture(0)
            if cam.isOpened():
                ret, frame = cam.read()
                if ret:
                    cv2.imwrite(img_path, frame)
                cam.release()
            else:
                img_name = "no_camera.jpg"
        except Exception:
            img_name = "no_camera.jpg"
    else:
        img_name = "no_camera.jpg"

    # Save intruder record to Excel
    ip          = request.remote_addr
    device_info = request.headers.get("User-Agent", "Unknown")[:200]
    df = read_table("intruders", INTRUDER_COLUMNS, INTRUDER_FILE)
    df.loc[len(df)] = [
        username_attempted,
        ip,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        device_info,
        img_name
    ]
    write_table("intruders", df, mode="replace")
    return img_name

# ============================================================
#   HELPER – LOG LOGIN HISTORY
# ============================================================
def log_login_history(username: str, status: str):
    # Append a single row to login_history table
    row = {
        "Username": username,
        "IP Address": request.remote_addr,
        "Date Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Status": status,
        "Device Info": request.headers.get("User-Agent", "")[:200]
    }
    try:
        pd.DataFrame([row]).to_sql("login_history", ENGINE, if_exists="append", index=False)
    except Exception:
        # fallback: read full table, append and replace
        df = read_table("login_history", LOGIN_HIST_COLUMNS, LOGIN_HIST_FILE)
        df.loc[len(df)] = [row[c] for c in LOGIN_HIST_COLUMNS]
        write_table("login_history", df, mode="replace")


def build_weekly_login_graph(hist_df=None):
    if hist_df is None:
        hist_df = read_table("login_history", LOGIN_HIST_COLUMNS, LOGIN_HIST_FILE).fillna("")
    else:
        hist_df = hist_df.fillna("")

    today = datetime.now().date()
    days = [today - timedelta(days=offset) for offset in range(6, -1, -1)]
    labels = [day.strftime("%a %d") for day in days]
    day_keys = [day.strftime("%Y-%m-%d") for day in days]

    graph = {
        "labels": labels,
        "success": [0] * 7,
        "failed": [0] * 7,
        "locked": [0] * 7,
        "totals": [0] * 7,
        "users": [],
    }

    if hist_df.empty or "Date Time" not in hist_df.columns:
        return graph

    data = hist_df.copy()
    data["Date Time"] = pd.to_datetime(data["Date Time"], errors="coerce")
    data = data.dropna(subset=["Date Time"])
    data["Day"] = data["Date Time"].dt.strftime("%Y-%m-%d")
    data["Status"] = data["Status"].astype(str).str.upper().str.strip()
    data["Username"] = data["Username"].astype(str).str.strip()
    data = data[data["Day"].isin(day_keys)]

    for index, day_key in enumerate(day_keys):
        day_rows = data[data["Day"] == day_key]
        graph["success"][index] = int((day_rows["Status"] == "SUCCESS").sum())
        graph["failed"][index] = int((day_rows["Status"] == "FAILED").sum())
        graph["locked"][index] = int((day_rows["Status"] == "LOCKED").sum())
        graph["totals"][index] = int(len(day_rows))

    success_rows = data[data["Status"] == "SUCCESS"]
    if not success_rows.empty:
        user_counts = success_rows.groupby("Username").size().sort_values(ascending=False).head(5)
        graph["users"] = [
            {"username": username or "Unknown", "count": int(count)}
            for username, count in user_counts.items()
        ]

    return graph


def is_new_device_login(username: str, ip_address: str, device_info: str):
    try:
        hist_df = read_table("login_history", LOGIN_HIST_COLUMNS, LOGIN_HIST_FILE).fillna("")
        hist_df["Username"] = hist_df["Username"].astype(str).str.strip()
        prior = hist_df[
            (hist_df["Username"].str.lower() == (username or "").strip().lower())
            & (hist_df["Status"].astype(str).str.upper() == "SUCCESS")
        ]
        if prior.empty:
            return False
        same_device = (
            (prior["IP Address"].astype(str) == str(ip_address))
            & (prior["Device Info"].astype(str) == str(device_info))
        )
        return not bool(same_device.any())
    except Exception:
        return False


def auto_block_ip(ip_address: str, username: str = "", reason: str = ""):
    block_df = read_table("blocked_ips", BLOCK_COLUMNS, BLOCK_FILE)
    already_blocked = ip_address in block_df["IP Address"].astype(str).values
    if not already_blocked:
        block_df.loc[len(block_df)] = [ip_address, datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        write_table("blocked_ips", block_df, mode="replace")
        send_security_alert(
            alert_type="IP Automatically Blocked",
            subject=f"IP Automatically Blocked: {ip_address}",
            username=username,
            ip_address=ip_address,
            threat_details=reason or "The IP address exceeded the configured security threshold.",
            recommended_action="Review login history and blocked IP records before unblocking this address.",
        )
    return not already_blocked

# ============================================================
#   BEFORE REQUEST – MONITORING + IP BLOCK CHECK
# ============================================================
@app.before_request
def monitor():
    session.permanent = True   # enforce session timeout

    if not MONITORING_ENABLED:
        return

    skip = ["static", "login", "register", "logout",
            "forgot_password", "reset_password", "admin_login"]
    if request.endpoint in skip or request.endpoint is None:
        return

    init_files()
    ip = request.remote_addr

    block_df = read_table("blocked_ips", BLOCK_COLUMNS, BLOCK_FILE)
    if ip in block_df["IP Address"].astype(str).values:
        return render_template("blocked.html", ip=ip), 403

    ep  = request.path
    ua  = request.headers.get("User-Agent", "")
    risk, threat = calculate_risk(ep, ua)

    df = read_table("logs", LOG_COLUMNS, LOG_FILE)
    df.loc[len(df)] = [
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip, ep, request.method, ua[:200], int(risk), threat
    ]
    write_table("logs", df, mode="replace")

    attack_type = normalize_attack_type(threat_type=threat)
    if int(risk) >= 40 and attack_type in ALERT_ATTACK_TYPES:
        send_security_alert(
            alert_type=attack_type,
            subject=f"{attack_type} Detected: {ip}",
            username=session.get("user", ""),
            ip_address=ip,
            threat_details=f"{threat} detected on {request.method} {ep} with risk score {int(risk)}.",
            recommended_action="Investigate the request, review related logs, and block the IP if the activity is malicious.",
            threat_type=threat,
            risk_score=risk,
            event_key=f"{attack_type}|{ip}|{request.method}|{ep}",
        )


# ============================================================
#   REGISTER
# ============================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    init_files()
    msg = ""
    success = ""
    form = {}

    if request.method == "POST":
        fname    = request.form.get("fname", "").strip()
        lname    = request.form.get("lname", "").strip()
        email    = request.form.get("email", "").strip().lower()
        mobile   = request.form.get("mobile", "").strip()
        gender   = request.form.get("gender", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm  = request.form.get("confirm_password", "").strip()
        form = {
            "fname": fname,
            "lname": lname,
            "email": email,
            "mobile": mobile,
            "gender": gender,
            "username": username,
        }

        # ── Validation ──────────────────────────────────────
        if not is_valid_name(fname):
            msg = "First name must contain only alphabets and be 2-30 characters long."
        elif not is_valid_name(lname):
            msg = "Last name must contain only alphabets and be 2-30 characters long."
        elif len(password) < 8:
            msg = "Password must be at least 8 characters."
        elif not any(c.isupper() for c in password):
            msg = "Password must contain at least one uppercase letter."
        elif not any(c.isdigit() for c in password):
            msg = "Password must contain at least one digit."
        elif password != confirm:
            msg = "Passwords do not match."
        else:
            df = read_table("users", USER_COLUMNS, USER_FILE)
            if (df["Username"].astype(str).str.strip().str.lower() == username.lower()).any():
                msg = "Username already exists. Please choose another."
            elif (df["Email"].astype(str).str.strip().str.lower() == email).any():
                msg = "Email already registered."
            else:
                hashed_pw = generate_password_hash(password)
                new_row = {
                    "First Name": fname,
                    "Last Name":  lname,
                    "Email":      email,
                    "Mobile":     mobile,
                    "Gender":     gender,
                    "Username":   username,
                    "Password":   hashed_pw
                }
                df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
                write_table("users", df, mode="replace")
                success = "Account created successfully! Please login."
                return render_template("register.html", msg=msg, success=success, form={})

    return render_template("register.html", msg=msg, success=success, form=form)


# ============================================================
#   LOGIN  (3-attempt lockout + intruder capture)
# ============================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    init_files()
    msg      = ""
    attempts = 0      # always an int so Jinja comparisons work
    locked   = False

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        ip       = request.remote_addr

        # ── Check IP block ───────────────────────────────────
        block_df = read_table("blocked_ips", BLOCK_COLUMNS, BLOCK_FILE)
        if ip in block_df["IP Address"].astype(str).values:
            return render_template("login.html",
                                   msg="⛔ Your IP is blocked due to suspicious activity.",
                                   attempts="", locked=True)

        # ── Initialise attempt counter ───────────────────────
        if ip not in login_attempts:
            login_attempts[ip] = 0

        # ── Already locked out? ──────────────────────────────
        if login_attempts[ip] >= 3:
            locked = True
            msg = "🔒 Too many failed attempts. Webcam capture triggered."
            log_login_history(username, "LOCKED")
            return render_template("login.html", msg=msg,
                                   attempts=login_attempts[ip], locked=locked)

        # ── Verify credentials ───────────────────────────────
        df = read_table("users", USER_COLUMNS, USER_FILE)
        df["Username"] = df["Username"].astype(str).str.strip()
        user_row = df[df["Username"].str.lower() == username.lower()]

        login_ok = False
        if not user_row.empty:
            stored_pw = str(user_row.iloc[0]["Password"]).strip()
            # Support both hashed and legacy plain-text passwords
            try:
                login_ok = check_password_hash(stored_pw, password)
            except Exception:
                login_ok = (stored_pw == password)

        if login_ok:
            # ── SUCCESS ──────────────────────────────────────
            device_info = request.headers.get("User-Agent", "")[:200]
            new_device = is_new_device_login(username, ip, device_info)
            login_attempts[ip] = 0          # reset counter
            session.permanent  = True
            session["user"]    = username
            log_login_history(username, "SUCCESS")
            if new_device:
                send_security_alert(
                    alert_type="New Device Login",
                    subject=f"New Device Login: {username}",
                    username=username,
                    ip_address=ip,
                    threat_details=f"A login succeeded from a new IP/device combination. Device: {device_info or 'Unknown'}",
                    recommended_action="If this login was not expected, reset the account password and review recent login history.",
                    recipient=get_user_email(username) or admin_alert_recipient(),
                )
            return redirect(url_for("dashboard"))
        else:
            # ── FAILURE ──────────────────────────────────────
            login_attempts[ip] += 1
            remaining = 3 - login_attempts[ip]
            log_login_history(username, "FAILED")

            if login_attempts[ip] >= 3:
                # Trigger intruder capture
                img = capture_intruder(username)
                send_security_alert(
                    alert_type="Multiple Failed Login Attempts",
                    subject=f"Multiple Failed Login Attempts: {ip}",
                    username=username,
                    ip_address=ip,
                    threat_details=f"{login_attempts[ip]} failed login attempts were recorded. Intruder image: {img}.",
                    recommended_action="Review the intruder capture and login history, then verify whether the username was targeted.",
                    threat_type="Multiple Failed Login Attempts",
                    risk_score=95,
                    event_key=f"Multiple Failed Login Attempts|{ip}|{username}",
                )
                send_security_alert(
                    alert_type="Intruder",
                    subject=f"Intruder Detected: {ip}",
                    username=username,
                    ip_address=ip,
                    threat_details=f"Intruder capture was triggered after repeated failed login attempts. Image: {img}.",
                    recommended_action="Review the intruder photo and login history before restoring access.",
                    threat_type="Intruder",
                    risk_score=95,
                    event_key=f"Intruder|{ip}|{username}",
                )
                auto_block_ip(
                    ip,
                    username=username,
                    reason=f"{login_attempts[ip]} failed login attempts from this IP address.",
                )
                locked  = True
                msg     = (f"🚨 3 failed attempts detected! "
                           f"Intruder photo captured: {img}. "
                           f"Incident logged.")
            else:
                msg      = f"❌ Invalid username or password. {remaining} attempt(s) remaining."
                attempts = int(login_attempts[ip])

    return render_template("login.html", msg=msg,
                           attempts=attempts, locked=locked)


# ============================================================
#   FORGOT PASSWORD
# ============================================================
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    init_files()
    msg     = ""
    success = ""
    step    = request.args.get("step", "1")   # step 1 = verify, step 2 = reset

    if request.method == "POST":
        step = request.form.get("step", "1")

        # ── STEP 1: Verify identity ──────────────────────────
        if step == "1":
            identifier = request.form.get("identifier", "").strip().lower()
            df = read_table("users", USER_COLUMNS, USER_FILE)
            df["Username"] = df["Username"].astype(str).str.strip().str.lower()
            df["Email"]    = df["Email"].astype(str).str.strip().str.lower()

            match = df[(df["Username"] == identifier) | (df["Email"] == identifier)]
            if match.empty:
                msg = "❌ No account found with that username or email."
                step = "1"
            else:
                # Store verified username in session temporarily
                session["reset_user"] = str(match.iloc[0]["Username"])
                step    = "2"
                success = f"✅ Account verified for: {match.iloc[0]['Username']}. Set your new password below."

        # ── STEP 2: Reset password ───────────────────────────
        elif step == "2":
            new_pw  = request.form.get("new_password", "").strip()
            confirm = request.form.get("confirm_password", "").strip()
            reset_user = session.get("reset_user", "")

            if not reset_user:
                msg  = "Session expired. Please start again."
                step = "1"
            elif len(new_pw) < 8:
                msg  = "Password must be at least 8 characters."
                step = "2"
            elif not any(c.isupper() for c in new_pw):
                msg  = "Password must contain at least one uppercase letter."
                step = "2"
            elif not any(c.isdigit() for c in new_pw):
                msg  = "Password must contain at least one digit."
                step = "2"
            elif new_pw != confirm:
                msg  = "Passwords do not match."
                step = "2"
            else:
                df = read_table("users", USER_COLUMNS, USER_FILE)
                df["Username"] = df["Username"].astype(str).str.strip()
                hashed = generate_password_hash(new_pw)
                df.loc[df["Username"].str.lower() == reset_user.lower(), "Password"] = hashed
                write_table("users", df, mode="replace")
                session.pop("reset_user", None)
                success = "✅ Password reset successfully! You can now login."
                step    = "done"

    return render_template("forgot_password.html",
                           msg=msg, success=success, step=step)


# ============================================================
#   LOGOUT
# ============================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================
#   DASHBOARD
# ============================================================
@app.route("/")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    init_files()

    try:
        df = read_table("logs", LOG_COLUMNS, LOG_FILE)
    except Exception:
        df = pd.DataFrame(columns=LOG_COLUMNS)

    df["Risk Score"] = pd.to_numeric(df["Risk Score"], errors="coerce").fillna(0)
    df["Time"]       = pd.to_datetime(df["Time"], errors="coerce")

    today    = datetime.now().date()
    today_df = df[df["Time"].dt.date == today]

    total_threats = int(today_df[today_df["Risk Score"] >= 40].shape[0])
    malware_count = int(today_df[today_df["Threat Type"].str.contains("Malware",    case=False, na=False)].shape[0])
    sql_count     = int(today_df[today_df["Threat Type"].str.contains("SQL",        case=False, na=False)].shape[0])
    ddos_count    = int(today_df[today_df["Threat Type"].str.contains("DDoS",       case=False, na=False)].shape[0])
    xss_count     = int(today_df[today_df["Threat Type"].str.contains("XSS",        case=False, na=False)].shape[0])
    traversal_count = int(today_df[today_df["Threat Type"].str.contains("Traversal",case=False, na=False)].shape[0])

    avg_risk = float(today_df["Risk Score"].mean()) if not today_df.empty else 0.0

    if avg_risk >= 70:
        threat_level = "HIGH"
        threat_color = "danger"
    elif avg_risk >= 40:
        threat_level = "MEDIUM"
        threat_color = "warning"
    else:
        threat_level = "LOW"
        threat_color = "success"

    low_count    = int(today_df[today_df["Risk Score"] < 40].shape[0])
    medium_count = int(today_df[(today_df["Risk Score"] >= 40) & (today_df["Risk Score"] < 70)].shape[0])
    high_count   = int(today_df[today_df["Risk Score"] >= 70].shape[0])

    # Hourly trend for today
    hourly = {str(i): 0 for i in range(24)}
    if not today_df.empty:
        today_df = today_df.copy()
        today_df["Hour"] = today_df["Time"].dt.hour
        for h, cnt in today_df.groupby("Hour").size().items():
            hourly[str(h)] = int(cnt)

    # Recent logs
    logs_df = df.tail(15).copy()
    logs_df["Status"] = logs_df["Risk Score"].apply(
        lambda x: "ATTACK" if int(x) >= 40 else "SAFE")
    logs = logs_df.fillna("").to_dict(orient="records")

    # Intruder count
    try:
        intruder_count = read_table("intruders", INTRUDER_COLUMNS, INTRUDER_FILE).shape[0]
    except Exception:
        intruder_count = 0

    # Blocked IPs
    try:
        blocked_df = read_table("blocked_ips", BLOCK_COLUMNS, BLOCK_FILE).fillna("")
        blocked_count = blocked_df.shape[0]
        blocked = blocked_df.to_dict(orient="records")
    except Exception:
        blocked_count = 0
        blocked = []

    email_metrics = get_email_alert_metrics(limit=5)

    return render_template(
        "dashboard.html",
        logs=logs,
        total_threats=total_threats,
        malware_count=malware_count,
        sql_count=sql_count,
        ddos_count=ddos_count,
        xss_count=xss_count,
        traversal_count=traversal_count,
        threat_level=threat_level,
        threat_color=threat_color,
        low_count=low_count,
        medium_count=medium_count,
        high_count=high_count,
        hourly=hourly,
        intruder_count=intruder_count,
        blocked_count=blocked_count,
        blocked=blocked,
        recent_email_alerts=email_metrics["recent"],
        total_emails_sent=email_metrics["total_sent"],
        failed_email_deliveries=email_metrics["failed"],
        monitoring=MONITORING_ENABLED,
        username=session.get("user")
    )


# ============================================================
#   AI SECURITY COPILOT
# ============================================================
@app.route("/ai_assistant", methods=["GET", "POST"])
def ai_assistant():
    if "user" not in session:
        return redirect(url_for("login"))

    question = ""
    answer = ""
    if request.method == "POST":
        question = request.form.get("question", "").strip()
        answer = generate_copilot_answer(question)
        history = session.get("copilot_history", [])
        history.insert(0, {
            "question": question,
            "answer": answer,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        session["copilot_history"] = history[:10]

    context = build_copilot_context()
    return render_template(
        "ai_assistant.html",
        question=question,
        answer=answer,
        history=session.get("copilot_history", []),
        suggested_questions=[
            "Show today's attacks",
            "Top suspicious IPs",
            "Generate executive summary",
        ],
        copilot_stats={
            "threats": int(context["threat_logs"].shape[0]),
            "blocked": int(context["blocked"].shape[0]),
            "intruders": int(context["today_intruders"].shape[0]),
            "failed_logins": int(context["failed_logins"].shape[0]),
        },
    )


@app.route("/api/copilot", methods=["POST"])
def api_copilot():
    if "user" not in session:
        return jsonify(error="Unauthorized"), 401
    data = request.get_json(silent=True) or {}
    question = str(data.get("question", "")).strip()
    return jsonify(answer=generate_copilot_answer(question))


# ============================================================
#   MONITORING TOGGLE
# ============================================================
@app.route("/start_monitoring")
def start_monitoring():
    global MONITORING_ENABLED
    MONITORING_ENABLED = True
    return redirect(url_for("dashboard"))

@app.route("/stop_monitoring")
def stop_monitoring():
    global MONITORING_ENABLED
    MONITORING_ENABLED = False
    return redirect(url_for("dashboard"))


# ============================================================
#   BLOCK / UNBLOCK IP
# ============================================================
@app.route("/block_ip/<path:ip>")
def block_ip(ip):
    if "user" not in session and "admin" not in session:
        return redirect(url_for("login"))
    df = read_table("blocked_ips", BLOCK_COLUMNS, BLOCK_FILE)
    if ip not in df["IP Address"].astype(str).values:
        df.loc[len(df)] = [ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        write_table("blocked_ips", df, mode="replace")
    ref = request.referrer or url_for("dashboard")
    return redirect(ref)

@app.route("/unblock_ip/<path:ip>")
def unblock_ip(ip):
    if "admin" not in session:
        return redirect(url_for("admin_login"))
    df = read_table("blocked_ips", BLOCK_COLUMNS, BLOCK_FILE)
    df = df[df["IP Address"].astype(str) != ip]
    write_table("blocked_ips", df, mode="replace")
    return redirect(url_for("admin_dashboard"))


# ============================================================
#   CLEAR LOGS
# ============================================================
@app.route("/clear_logs", methods=["POST"])
def clear_logs():
    if "user" not in session:
        return redirect(url_for("login"))
    write_table("logs", pd.DataFrame(columns=LOG_COLUMNS), mode="replace")
    return redirect(url_for("dashboard"))


# ============================================================
#   ATTACK SIMULATIONS
# ============================================================
@app.route("/simulate_malware")
def simulate_malware():
    init_files()
    event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = "10.0.0.5"
    threat = "Malware"
    risk = 80
    df = read_table("logs", LOG_COLUMNS, LOG_FILE)
    df.loc[len(df)] = [event_time, ip, "/admin", "POST",
                       "sqlmap malware scanner", risk, threat]
    write_table("logs", df, mode="replace")
    send_security_alert(
        alert_type=threat,
        subject=f"{threat} Detected: {ip}",
        username=session.get("user", ""),
        ip_address=ip,
        threat_details=f"Simulated {threat} event detected with risk score {risk}.",
        recommended_action="Validate the event source, inspect related logs, and block the IP if this was not a simulation.",
        threat_type=threat,
        risk_score=risk,
        event_key=f"{threat}|{ip}|simulate",
    )
    return redirect(url_for("dashboard"))

@app.route("/simulate_sql")
def simulate_sql():
    init_files()
    event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = "45.23.11.90"
    threat = "SQL Injection"
    risk = 85
    df = read_table("logs", LOG_COLUMNS, LOG_FILE)
    df.loc[len(df)] = [event_time, ip, "/login?user=admin' OR '1'='1",
                       "GET", "sqlmap scanner", risk, threat]
    write_table("logs", df, mode="replace")
    send_security_alert(
        alert_type=threat,
        subject=f"{threat} Detected: {ip}",
        username=session.get("user", ""),
        ip_address=ip,
        threat_details=f"Simulated {threat} event detected with risk score {risk}.",
        recommended_action="Review input validation, query parameter logs, and block repeat sources.",
        threat_type=threat,
        risk_score=risk,
        event_key=f"{threat}|{ip}|simulate",
    )
    return redirect(url_for("dashboard"))

@app.route("/simulate_ddos")
def simulate_ddos():
    init_files()
    event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = "192.168.0.1"
    threat = "DDoS"
    risk = 90
    df = read_table("logs", LOG_COLUMNS, LOG_FILE)
    df.loc[len(df)] = [event_time, ip, "/api/data", "GET",
                       "botnet ddos tool", risk, threat]
    write_table("logs", df, mode="replace")
    send_security_alert(
        alert_type=threat,
        subject=f"{threat} Detected: {ip}",
        username=session.get("user", ""),
        ip_address=ip,
        threat_details=f"Simulated {threat} event detected with risk score {risk}.",
        recommended_action="Check traffic volume, enable rate limiting, and block abusive sources.",
        threat_type=threat,
        risk_score=risk,
        event_key=f"{threat}|{ip}|simulate",
    )
    return redirect(url_for("dashboard"))

@app.route("/simulate_xss")
def simulate_xss():
    init_files()
    event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = "77.88.55.60"
    threat = "XSS"
    risk = 70
    df = read_table("logs", LOG_COLUMNS, LOG_FILE)
    df.loc[len(df)] = [event_time, ip, "/search?q=<script>alert(1)</script>",
                       "GET", "Mozilla/5.0", risk, threat]
    write_table("logs", df, mode="replace")
    send_security_alert(
        alert_type=threat,
        subject=f"{threat} Detected: {ip}",
        username=session.get("user", ""),
        ip_address=ip,
        threat_details=f"Simulated {threat} event detected with risk score {risk}.",
        recommended_action="Review output encoding, sanitize inputs, and investigate repeated attempts.",
        threat_type=threat,
        risk_score=risk,
        event_key=f"{threat}|{ip}|simulate",
    )
    return redirect(url_for("dashboard"))

@app.route("/simulate_portscan")
def simulate_portscan():
    init_files()
    ip = "203.0.113.42"
    threat = "Port Scan"
    risk = 40
    df = read_table("logs", LOG_COLUMNS, LOG_FILE)
    df.loc[len(df)] = [datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                       ip, "/", "GET",
                       "nmap -sS scanner", risk, threat]
    write_table("logs", df, mode="replace")
    send_security_alert(
        alert_type=threat,
        subject=f"{threat} Detected: {ip}",
        username=session.get("user", ""),
        ip_address=ip,
        threat_details=f"Simulated {threat} event detected with risk score {risk}.",
        recommended_action="Review exposed services and firewall rules, then watch for repeated scans.",
        threat_type=threat,
        risk_score=risk,
        event_key=f"{threat}|{ip}|simulate",
    )
    return redirect(url_for("dashboard"))


# ============================================================
#   DETAILS PAGE
# ============================================================
@app.route("/details/<attack_type>")
def details(attack_type):
    if "user" not in session:
        return redirect(url_for("login"))

    try:
        df = read_table("logs", LOG_COLUMNS, LOG_FILE)
    except Exception:
        df = pd.DataFrame(columns=LOG_COLUMNS)

    df["Risk Score"] = pd.to_numeric(df["Risk Score"], errors="coerce").fillna(0)
    df["Time"]       = pd.to_datetime(df["Time"], errors="coerce")

    today = datetime.now().date()
    df    = df[df["Time"].dt.date == today]

    filters = {
        "malware":   lambda d: d[d["Threat Type"].str.contains("Malware",    case=False, na=False)],
        "sql":       lambda d: d[d["Threat Type"].str.contains("SQL",        case=False, na=False)],
        "ddos":      lambda d: d[d["Threat Type"].str.contains("DDoS",       case=False, na=False)],
        "xss":       lambda d: d[d["Threat Type"].str.contains("XSS",        case=False, na=False)],
        "traversal": lambda d: d[d["Threat Type"].str.contains("Traversal",  case=False, na=False)],
        "total":     lambda d: d[d["Risk Score"] >= 40],
    }
    filtered = filters.get(attack_type, lambda d: d)(df)

    records    = filtered.fillna("").to_dict(orient="records")
    graph_data = {str(i): 0 for i in range(24)}
    try:
        tmp = filtered.copy()
        tmp["Hour"] = tmp["Time"].dt.hour
        for h, cnt in tmp.groupby("Hour").size().items():
            graph_data[str(h)] = int(cnt)
    except Exception:
        pass

    return render_template("details.html",
                           records=records,
                           graph_data=graph_data,
                           attack_type=attack_type)


# ============================================================
#   API – LIVE CHART DATA
# ============================================================
@app.route("/api/chart-data")
def chart_data():
    try:
        df = read_table("logs", LOG_COLUMNS, LOG_FILE)
        df["Risk Score"] = pd.to_numeric(df["Risk Score"], errors="coerce").fillna(0)
        low    = int(df[df["Risk Score"] < 40].shape[0])
        medium = int(df[(df["Risk Score"] >= 40) & (df["Risk Score"] < 70)].shape[0])
        high   = int(df[df["Risk Score"] >= 70].shape[0])
    except Exception:
        low = medium = high = 0
    return jsonify(low=low, medium=medium, high=high)

@app.route("/api/hourly-data")
def hourly_data():
    try:
        df = read_table("logs", LOG_COLUMNS, LOG_FILE)
        df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
        today = datetime.now().date()
        df    = df[df["Time"].dt.date == today].copy()
        df["Hour"] = df["Time"].dt.hour
        hourly = {str(i): 0 for i in range(24)}
        for h, cnt in df.groupby("Hour").size().items():
            hourly[str(h)] = int(cnt)
    except Exception:
        hourly = {str(i): 0 for i in range(24)}
    return jsonify(hourly)


def build_map_events():
    def ip_is_local(ip_addr: str):
        try:
            ip_obj = ipaddress.ip_address(str(ip_addr))
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return True

    def fallback_location(ip_addr: str, index: int):
        # Keep local/private events visible on the world map.
        return {
            "lat": 20.5937 + ((index % 7) - 3) * 0.55,
            "lon": 78.9629 + ((index % 5) - 2) * 0.55,
            "country": "Local Network",
            "city": "Private IP",
        }

    geo_cache = {}
    markers = []

    def resolve_location(ip_addr: str, index: int):
        ip_addr = str(ip_addr or "").strip()
        if not ip_addr or ip_is_local(ip_addr):
            return fallback_location(ip_addr, index)
        if ip_addr in geo_cache:
            return geo_cache[ip_addr]
        try:
            res = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=3).json()
            if res.get("status") == "success":
                geo_cache[ip_addr] = {
                    "lat": float(res.get("lat", 0)),
                    "lon": float(res.get("lon", 0)),
                    "country": res.get("country", "Unknown"),
                    "city": res.get("city", ""),
                }
                return geo_cache[ip_addr]
        except Exception:
            pass
        geo_cache[ip_addr] = fallback_location(ip_addr, index)
        return geo_cache[ip_addr]

    def add_marker(ip_addr, category, title, detail="", event_time="", username="", threat="", risk=0):
        ip_addr = str(ip_addr or "").strip()
        if not ip_addr:
            return
        loc = resolve_location(ip_addr, len(markers))
        markers.append({
            "ip": ip_addr,
            "lat": loc["lat"],
            "lon": loc["lon"],
            "country": loc["country"],
            "city": loc.get("city", ""),
            "category": category,
            "title": title,
            "detail": detail,
            "time": str(event_time or ""),
            "username": str(username or ""),
            "threat": str(threat or ""),
            "risk": int(float(risk or 0)),
        })

    try:
        logs_df = read_table("logs", LOG_COLUMNS, LOG_FILE).fillna("")
        logs_df["Risk Score"] = pd.to_numeric(logs_df["Risk Score"], errors="coerce").fillna(0)
        for _, row in logs_df[logs_df["Risk Score"] >= 40].tail(100).iterrows():
            add_marker(
                row.get("IP Address", ""),
                "attack",
                "Attack Detected",
                row.get("Endpoint", ""),
                row.get("Time", ""),
                threat=row.get("Threat Type", "Unknown"),
                risk=row.get("Risk Score", 0),
            )
    except Exception:
        pass

    try:
        hist_df = read_table("login_history", LOGIN_HIST_COLUMNS, LOGIN_HIST_FILE).fillna("")
        for _, row in hist_df[hist_df["Status"].astype(str).str.upper() == "SUCCESS"].tail(100).iterrows():
            add_marker(
                row.get("IP Address", ""),
                "login",
                "User Login",
                row.get("Device Info", ""),
                row.get("Date Time", ""),
                username=row.get("Username", ""),
            )
    except Exception:
        pass

    try:
        block_df = read_table("blocked_ips", BLOCK_COLUMNS, BLOCK_FILE).fillna("")
        for _, row in block_df.tail(100).iterrows():
            add_marker(
                row.get("IP Address", ""),
                "blocked",
                "Blocked IP",
                "Blocked by security system",
                row.get("Blocked Time", ""),
            )
    except Exception:
        pass

    try:
        intruder_df = read_table("intruders", INTRUDER_COLUMNS, INTRUDER_FILE).fillna("")
        for _, row in intruder_df.tail(100).iterrows():
            add_marker(
                row.get("IP Address", ""),
                "intruder",
                "Intruder Capture",
                row.get("Image Name", ""),
                row.get("Date Time", ""),
                username=row.get("Username Attempted", ""),
            )
    except Exception:
        pass

    stats = {
        "attacks": sum(1 for m in markers if m["category"] == "attack"),
        "logins": sum(1 for m in markers if m["category"] == "login"),
        "blocked": sum(1 for m in markers if m["category"] == "blocked"),
        "intruders": sum(1 for m in markers if m["category"] == "intruder"),
    }

    return markers, stats


# ============================================================
#   ATTACK MAP
# ============================================================
@app.route("/map")
def attack_map():
    if "user" not in session:
        return redirect(url_for("login"))

    markers, stats = build_map_events()
    return render_template("map.html", locations=markers, stats=stats)


@app.route("/api/map-events")
def map_events():
    if "user" not in session:
        return jsonify(error="Unauthorized"), 401

    markers, stats = build_map_events()
    return jsonify(locations=markers, stats=stats)


# ============================================================
#   INTRUDER MONITORING PAGE
# ============================================================
@app.route("/intruders")
def intruders():
    if "user" not in session and "admin" not in session:
        return redirect(url_for("login"))
    try:
        df = read_table("intruders", INTRUDER_COLUMNS, INTRUDER_FILE).fillna("")
        records = df.to_dict(orient="records")
    except Exception:
        records = []
    return render_template("intruders.html", records=records)

@app.route("/delete_intruder/<int:idx>")
def delete_intruder(idx):
    if "admin" not in session:
        return redirect(url_for("admin_login"))
    df = read_table("intruders", INTRUDER_COLUMNS, INTRUDER_FILE)
    if idx < len(df):
        # Remove image file
        img_name = str(df.iloc[idx].get("Image Name", ""))
        img_path = os.path.join(INTRUDER_DIR, img_name)
        if os.path.exists(img_path):
            os.remove(img_path)
        df = df.drop(index=idx).reset_index(drop=True)
        write_table("intruders", df, mode="replace")
    return redirect(url_for("intruders"))


# ============================================================
#   CONNECTED DEVICES  (ARP + Wireshark + hostname lookup)
# ============================================================
@app.route("/connected_devices")
def connected_devices():
    if "user" not in session:
        return redirect(url_for("login"))

    devices = scan_network_devices() if request.args.get("scan") == "true" else []

    return render_template("connected_devices.html", devices=devices)


@app.route("/api/connected-devices")
def api_connected_devices():
    if "user" not in session:
        return jsonify(error="Unauthorized"), 401
    return jsonify(devices=scan_network_devices())


# ============================================================
#   EDIT PROFILE (user)
# ============================================================
@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "user" not in session:
        return redirect(url_for("login"))

    df = read_table("users", USER_COLUMNS, USER_FILE).fillna("")
    df["Username"] = df["Username"].astype(str).str.strip()
    username = session["user"].strip()
    user_row = df[df["Username"].str.lower() == username.lower()]

    if user_row.empty:
        return "User not found", 404

    msg = success = ""

    if request.method == "POST":
        fname = request.form.get("fname", "").strip()
        lname = request.form.get("lname", "").strip()
        email = request.form.get("email", "").strip()
        mobile = request.form.get("mobile", "").strip()
        new_pw = request.form.get("new_password", "").strip()

        if not is_valid_name(fname):
            msg = "First name must contain only alphabets and be 2-30 characters long."
        elif not is_valid_name(lname):
            msg = "Last name must contain only alphabets and be 2-30 characters long."
        elif new_pw and len(new_pw) < 8:
            msg = "New password must be at least 8 characters."
        else:
            user_mask = df["Username"].str.lower() == username.lower()
            df.loc[user_mask, "First Name"] = fname
            df.loc[user_mask, "Last Name"]  = lname
            df.loc[user_mask, "Email"]      = email
            df.loc[user_mask, "Mobile"]     = mobile
            if new_pw:
                df.loc[user_mask, "Password"] = generate_password_hash(new_pw)
            write_table("users", df, mode="replace")
            success = "Profile updated successfully."

    user = df[df["Username"].str.lower() == username.lower()].iloc[0].to_dict()
    return render_template("edit_profile.html", user=user, msg=msg, success=success)


# ============================================================
#   STATIC PAGES
# ============================================================
@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/information")
def information():
    return render_template("information.html", username=session.get("user"))


# ============================================================
#   ADMIN LOGIN
# ============================================================
@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    msg = ""
    if request.method == "GET":
        session.pop("admin", None)
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "").strip()
        if u == "admin" and p == "admin123":
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        else:
            msg = "❌ Invalid admin credentials."
    return render_template("admin_login.html", msg=msg)

@app.route("/admin_logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))


# ============================================================
#   ADMIN DASHBOARD
# ============================================================
@app.route("/admin_dashboard")
def admin_dashboard():
    if "admin" not in session:
        return redirect(url_for("admin_login"))

    init_files()

    users_df    = read_table("users", USER_COLUMNS, USER_FILE).fillna("")
    logs_df     = read_table("logs", LOG_COLUMNS, LOG_FILE).fillna("")
    block_df    = read_table("blocked_ips", BLOCK_COLUMNS, BLOCK_FILE).fillna("")
    intruder_df = read_table("intruders", INTRUDER_COLUMNS, INTRUDER_FILE).fillna("")
    hist_df     = read_table("login_history", LOGIN_HIST_COLUMNS, LOGIN_HIST_FILE).fillna("")
    email_metrics = get_email_alert_metrics(limit=8)

    logs_df["Risk Score"] = pd.to_numeric(logs_df["Risk Score"], errors="coerce").fillna(0)

    stats = {
        "total_users":    len(users_df),
        "total_attacks":  int(logs_df[logs_df["Risk Score"] >= 40].shape[0]),
        "blocked_ips":    len(block_df),
        "intruders":      len(intruder_df),
        "emails_sent":    email_metrics["total_sent"],
        "email_failures": email_metrics["failed"],
    }
    weekly_login_graph = build_weekly_login_graph(hist_df)

    return render_template(
        "admin_dashboard.html",
        users       = users_df.to_dict(orient="records"),
        logs        = logs_df.tail(20).to_dict(orient="records"),
        blocked     = block_df.to_dict(orient="records"),
        intruders   = intruder_df.to_dict(orient="records"),
        login_hist  = hist_df.tail(20).to_dict(orient="records"),
        email_alerts = email_metrics["recent"],
        stats       = stats,
        weekly_login_graph = weekly_login_graph
    )


# ============================================================
#   ADMIN – USER MANAGEMENT
# ============================================================
@app.route("/admin_email_alerts", methods=["GET", "POST"])
def admin_email_alerts():
    if "admin" not in session:
        return redirect(url_for("admin_login"))

    init_files()
    message = ""
    message_type = "success"
    if request.method == "POST":
        action = request.form.get("action", "save")
        if action == "test":
            ok = send_security_alert(
                alert_type="Malware",
                subject="Test Security Alert: Malware",
                username=session.get("admin", "admin"),
                ip_address=request.remote_addr,
                threat_details="This is a sample security alert generated from the admin Email Alerts page.",
                recommended_action="No action is required if this was an authorized test.",
                threat_type="Malware",
                risk_score=80,
                event_key=f"test-email|{request.remote_addr}|{datetime.now().strftime('%Y%m%d%H%M%S')}",
                force=True,
            )
            message = "Test alert was sent or recorded in history." if ok else "Test alert could not be delivered. Check SMTP environment variables and history status."
            message_type = "success" if ok else "danger"
        else:
            save_email_alert_settings(
                enabled=request.form.get("enabled") == "on",
                recipients=request.form.getlist("attack_recipients") or split_recipient_list(request.form.get("recipients", "")),
                attack_types=request.form.getlist("attack_types"),
                dedupe_minutes=request.form.get("dedupe_minutes", 10),
            )
            message = "Email alert settings saved."

    selected_date = request.args.get("date", "").strip()
    email_query = request.args.get("email", "").strip()

    sql = """
        SELECT id, alert_type, attack_type, severity, source_ip, recipient, subject,
               description, recommended_action, timestamp, status
        FROM email_alerts WHERE 1=1
    """
    params = []
    if selected_date:
        sql += " AND date(timestamp) = ?"
        params.append(selected_date)
    if email_query:
        sql += " AND lower(recipient) LIKE ?"
        params.append(f"%{email_query.lower()}%")
    sql += " ORDER BY datetime(timestamp) DESC, id DESC"

    try:
        alerts_df = pd.read_sql_query(sql, ENGINE, params=params).fillna("")
    except Exception:
        alerts_df = pd.DataFrame(columns=EMAIL_ALERT_COLUMNS)

    return render_template(
        "admin_email_alerts.html",
        alerts=alerts_df.to_dict(orient="records"),
        selected_date=selected_date,
        email_query=email_query,
        settings=get_email_alert_settings(),
        attack_types=ALERT_ATTACK_TYPES,
        smtp_config={
            "server": app.config.get("MAIL_SERVER", ""),
            "port": app.config.get("MAIL_PORT", ""),
            "sender": app.config.get("MAIL_SENDER") or app.config.get("MAIL_USERNAME", ""),
            "username_set": bool(app.config.get("MAIL_USERNAME")),
            "password_set": bool(app.config.get("MAIL_PASSWORD")),
            "tls": app.config.get("MAIL_USE_TLS", True),
        },
        message=message,
        message_type=message_type,
    )


@app.route("/test_email_alert")
def test_email_alert():
    if "admin" not in session:
        return redirect(url_for("admin_login"))
    send_security_alert(
        alert_type="Malware",
        subject="Test Security Alert: Malware",
        username=session.get("admin", "admin"),
        ip_address=request.remote_addr,
        threat_details="This is a sample security alert generated from the test route.",
        recommended_action="No action is required if this was an authorized test.",
        threat_type="Malware",
        risk_score=80,
        event_key=f"test-route|{request.remote_addr}|{datetime.now().strftime('%Y%m%d%H%M%S')}",
        force=True,
    )
    return redirect(url_for("admin_email_alerts"))


@app.route("/api/weekly-logins")
def weekly_logins():
    if "admin" not in session:
        return jsonify(error="Unauthorized"), 401

    init_files()
    try:
        return jsonify(build_weekly_login_graph())
    except Exception as e:
        return jsonify({
            "labels": [],
            "success": [],
            "failed": [],
            "locked": [],
            "totals": [],
            "users": [],
            "error": str(e),
        })


@app.route("/delete_user/<username>")
def delete_user(username):
    if "admin" not in session:
        return redirect(url_for("admin_login"))
    df = read_table("users", USER_COLUMNS, USER_FILE)
    df["Username"] = df["Username"].astype(str).str.strip()
    df = df[df["Username"] != username]
    write_table("users", df, mode="replace")
    return redirect(url_for("admin_dashboard"))

@app.route("/edit_user/<username>", methods=["GET", "POST"])
def edit_user(username):
    if "admin" not in session:
        return redirect(url_for("admin_login"))

    df = read_table("users", USER_COLUMNS, USER_FILE).fillna("")
    df["Username"] = df["Username"].astype(str).str.strip()
    user_row = df[df["Username"] == username]

    if user_row.empty:
        return "User not found", 404

    if request.method == "POST":
        for col, key in [("First Name","fname"),("Last Name","lname"),
                         ("Email","email"),("Mobile","mobile"),("Gender","gender")]:
            df.loc[df["Username"] == username, col] = request.form.get(key, "")
        write_table("users", df, mode="replace")
        return redirect(url_for("admin_dashboard"))

    return render_template("edit_user.html", user=user_row.iloc[0].to_dict())

@app.route("/weekly_attacks")
def weekly_attacks():

    try:
        query = """
        SELECT
            DATE(timestamp) as day,
            COUNT(*) as total
        FROM email_alerts
        WHERE DATE(timestamp) >= DATE('now', '-6 days')
        GROUP BY DATE(timestamp)
        ORDER BY DATE(timestamp)
        """

        df = pd.read_sql_query(query, ENGINE)

        labels = df["day"].tolist()
        values = df["total"].tolist()

        return jsonify({
            "labels": labels,
            "values": values
        })

    except Exception as e:
        return jsonify({
            "labels": [],
            "values": [],
            "error": str(e)
        })


@app.route("/api/chatbot", methods=["POST"])
def chatbot():
    if "admin" not in session:
        return jsonify(error="Unauthorized"), 401

    data = request.get_json(silent=True) or {}
    message = data.get("message", "")
    return jsonify(reply=get_chatbot_reply(message))


@app.route("/api/alert-summary")
def alert_summary():
    """Return the newest plain-language AI Alert Summary for real-time dashboard polling."""
    if "user" not in session and "admin" not in session:
        return jsonify(error="Unauthorized"), 401
    return jsonify(build_ai_alert_summary())



# ============================================================
#   RUN
# ============================================================
if __name__ == "__main__":
    init_files()
    app.run(debug=True)
