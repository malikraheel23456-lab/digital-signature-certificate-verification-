"""SQLite storage for non-sensitive application activity (never stores keys/signatures)."""
from pathlib import Path
import sqlite3
from datetime import datetime, timezone

DB_PATH = Path(__file__).with_name("verification_history.db")


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            filename TEXT NOT NULL,
            signature_status TEXT,
            trust_status TEXT,
            fingerprint TEXT,
            details TEXT
        )""")


def add_activity(action, filename, signature_status=None, trust_status=None,
                 fingerprint=None, details=None):
    init_db()
    with connect() as conn:
        conn.execute(
            "INSERT INTO activity(timestamp, action, filename, signature_status, trust_status, fingerprint, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
             action, filename, signature_status, trust_status, fingerprint, details)
        )


def get_activities(limit=500):
    init_db()
    with connect() as conn:
        rows = conn.execute("SELECT * FROM activity ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def clear_activities():
    init_db()
    with connect() as conn:
        conn.execute("DELETE FROM activity")
