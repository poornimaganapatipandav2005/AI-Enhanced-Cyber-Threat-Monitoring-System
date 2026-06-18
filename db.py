"""
Lightweight DB helper using sqlite3 (no external dependencies).
Provides `get_engine()` which returns a sqlite3.Connection and
`table_exists(conn, table_name)` to check for tables.
"""
import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "cyber_threat.db")


def get_engine():
    # returns a sqlite3.Connection
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    # use row factory for convenience
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(conn, table_name: str) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    res = cur.fetchone()
    return res is not None


def _table_columns(conn, table_name: str) -> set:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table_name})")
    return {row[1] for row in cur.fetchall()}


def _add_column_if_missing(conn, table_name: str, column_name: str, definition: str):
    if column_name not in _table_columns(conn, table_name):
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def init_email_alerts_table(conn):
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS email_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            attack_type TEXT,
            severity TEXT,
            source_ip TEXT,
            recipient TEXT NOT NULL,
            subject TEXT NOT NULL,
            description TEXT,
            recommended_action TEXT,
            event_key TEXT,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL
        )
        """
    )
    for name, definition in [
        ("attack_type", "TEXT"),
        ("severity", "TEXT"),
        ("source_ip", "TEXT"),
        ("description", "TEXT"),
        ("recommended_action", "TEXT"),
        ("event_key", "TEXT"),
    ]:
        _add_column_if_missing(conn, "email_alerts", name, definition)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS email_alert_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL DEFAULT 1,
            recipients TEXT NOT NULL DEFAULT '',
            attack_types TEXT NOT NULL DEFAULT '',
            dedupe_minutes INTEGER NOT NULL DEFAULT 10,
            updated_at TEXT NOT NULL
        )
        """
    )
    cur.execute("SELECT COUNT(*) FROM email_alert_settings WHERE id = 1")
    if cur.fetchone()[0] == 0:
        cur.execute(
            """
            INSERT INTO email_alert_settings
                (id, enabled, recipients, attack_types, dedupe_minutes, updated_at)
            VALUES (1, 1, '', '', 10, datetime('now', 'localtime'))
            """
        )
    conn.commit()


if __name__ == "__main__":
    print("DB file:", DB_PATH)
    conn = get_engine()
    print("Connected. Tables present:")
    cur = conn.cursor()
    for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        print(" -", row[0])
    conn.close()
