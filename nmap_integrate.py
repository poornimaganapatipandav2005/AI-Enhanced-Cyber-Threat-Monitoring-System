import pandas as pd
import random
import os
from datetime import datetime
from db import get_engine

LOG_FILE = "logs.xlsx"
ENGINE = get_engine()

COLUMNS = [
    "Time",
    "IP Address",
    "Endpoint",
    "Method",
    "User Agent",
    "Risk Score",
    "Threat Type"
]

ATTACKS = [
    ("/login?user=admin' OR '1'='1", "GET", "sqlmap", 85, "SQL Injection"),
    ("/search?<script>alert(1)</script>", "GET", "curl", 70, "XSS"),
    ("/../../etc/passwd", "GET", "nmap", 65, "Traversal"),
    ("/", "GET", "nmap -sS", 40, "Port Scan"),
    ("/api", "POST", "botnet", 90, "DDoS Simulation")
]

def random_ip():
    return f"192.168.1.{random.randint(2,254)}"

def init_excel():
    if not os.path.exists(LOG_FILE):
        pd.DataFrame(columns=COLUMNS).to_excel(LOG_FILE, index=False)

def simulate_attack():
    init_excel()
    try:
        df = pd.read_sql_query("SELECT * FROM logs", ENGINE)
    except Exception:
        df = pd.read_excel(LOG_FILE)

    for _ in range(random.randint(5, 15)):
        endpoint, method, ua, risk, threat = random.choice(ATTACKS)

        df.loc[len(df)] = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            random_ip(),
            endpoint,
            method,
            ua,
            risk,
            threat
        ]

    df.to_sql("logs", ENGINE, if_exists="replace", index=False)
    print("✅ NMAP attack simulation complete")

if __name__ == "__main__":
    simulate_attack()
