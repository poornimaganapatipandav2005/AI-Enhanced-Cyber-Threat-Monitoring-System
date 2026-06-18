"""
Import existing Excel files into a new SQLite database `cyber_threat.db`.
Run from the project root:

    python import_excel.py

It will read the Excel files used by `app.py` and write them to SQLite tables:
 - logs
 - users
 - blocked_ips
 - intruders
 - login_history

If an Excel file is missing, an empty table with the expected columns will be created.
"""
import os
import pandas as pd
from db import get_engine, DB_PATH

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Excel file paths (match names used in app.py)
FILES = {
    "logs": {
        "path": os.path.join(BASE_DIR, "logs.xlsx"),
        "columns": ["Time","IP Address","Endpoint","Method",
                    "User Agent","Risk Score","Threat Type"]
    },
    "users": {
        "path": os.path.join(BASE_DIR, "users.xlsx"),
        "columns": ["First Name","Last Name","Email","Mobile",
                    "Gender","Username","Password"]
    },
    "blocked_ips": {
        "path": os.path.join(BASE_DIR, "blocked_ips.xlsx"),
        "columns": ["IP Address","Blocked Time"]
    },
    "intruders": {
        "path": os.path.join(BASE_DIR, "intruders.xlsx"),
        "columns": ["Username Attempted","IP Address","Date Time",
                    "Device Info","Image Name"]
    },
    "login_history": {
        "path": os.path.join(BASE_DIR, "login_history.xlsx"),
        "columns": ["Username","IP Address","Date Time","Status","Device Info"]
    }
}


def ensure_table_from_excel(engine, table_name, spec):
    path = spec["path"]
    cols = spec["columns"]
    try:
        if os.path.exists(path):
            print(f"Reading {path} -> table `{table_name}`")
            df = pd.read_excel(path)
            # Ensure expected columns exist (fill missing with empty values)
            for c in cols:
                if c not in df.columns:
                    df[c] = ""
            df = df[cols]
        else:
            print(f"File missing: {path}. Creating empty table `{table_name}` with columns: {cols}")
            df = pd.DataFrame(columns=cols)
        # Write to SQLite
        df.to_sql(table_name, get_engine(), if_exists="replace", index=False)
        print(f"Wrote table `{table_name}` ({len(df)} rows) to {DB_PATH}")
    except Exception as e:
        print(f"Failed to import {path} -> {e}")


def main():
    print("Importing Excel files into SQLite database:", DB_PATH)
    eng = get_engine()
    for table, spec in FILES.items():
        ensure_table_from_excel(eng, table, spec)
    print("Import complete.")

if __name__ == "__main__":
    main()
