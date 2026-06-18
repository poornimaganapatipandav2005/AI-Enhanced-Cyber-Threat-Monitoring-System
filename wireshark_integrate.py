# Wireshark integration now writes to SQLite `logs` table (fallback to Excel)
import subprocess
import pandas as pd
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

def init_excel():
    if not os.path.exists(LOG_FILE):
        pd.DataFrame(columns=COLUMNS).to_excel(LOG_FILE, index=False)

def get_connected_ips():
    command = [
        "tshark",
        "-i", "Wi-Fi",
        "-a", "duration:10",
        "-T", "fields",
        "-e", "ip.src"
    ]

    try:
        output = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        ips = set(output.decode().split())
        return ips
    except Exception:
        return set()

def log_devices():
    init_excel()
    try:
        df = pd.read_sql_query("SELECT * FROM logs", ENGINE)
    except Exception:
        df = pd.read_excel(LOG_FILE)

    ips = get_connected_ips()

    for ip in ips:
        df.loc[len(df)] = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            "/network",
            "PASSIVE",
            "Wireshark",
            5,
            "Connected Device"
        ]

    df.to_sql("logs", ENGINE, if_exists="replace", index=False)
    print("✅ Wireshark device scan complete")

if __name__ == "__main__":
    log_devices()
