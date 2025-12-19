"""
db.py – SQLite database setup and helper functions for IdentityGuard.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Any, Iterable

# Event types that should generate critical alerts
CRITICAL_EVENT_TYPES = (
    "password_change",
    "2fa_disabled",
    "suspicious_login",
    "new_device_login",
)

DB_PATH = Path("identityguard.db")


def init_db() -> None:
    """Create tables if they don't exist."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                service TEXT NOT NULL,
                event_type TEXT NOT NULL,
                account_email TEXT,
                ip TEXT,
                location TEXT,
                device TEXT,
                time_utc TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                raw_subject TEXT,
                raw_snippet TEXT,
                message_uid TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            )
            """

        )
        cur.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    time_utc TEXT NOT NULL,
                    delivered INTEGER DEFAULT 0,
                    FOREIGN KEY(event_id) REFERENCES events(id)
    );
    """
)
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


def save_events(events: Iterable[Dict[str, Any]]) -> int:
    """Insert a batch of events; skips ones with duplicate (provider,message_uid)."""
    count = 0
    with get_conn() as conn:
        cur = conn.cursor()
        for ev in events:
            try:
                cur.execute(
                    """
                    INSERT INTO events (
                        provider, service, event_type, account_email,
                        ip, location, device, time_utc,
                        risk_level, raw_subject, raw_snippet, message_uid
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ev.get("provider"),
                        ev.get("service"),
                        ev.get("event_type"),
                        ev.get("account_email"),
                        ev.get("ip"),
                        ev.get("location"),
                        ev.get("device"),
                        ev.get("time_utc"),
                        ev.get("risk_level"),
                        ev.get("raw_subject"),
                        ev.get("raw_snippet"),
                        ev.get("message_uid"),
                    ),
                )
                ev_id = cur.lastrowid
                event_type = ev.get("event_type") or ""
                time_utc = ev.get("time_utc") or ""
                
                if event_type in CRITICAL_EVENT_TYPES:
                    insert_alert(ev_id, event_type, time_utc)
                count += 1
            except sqlite3.IntegrityError:
                # Duplicate (provider, message_uid) – skip
                continue
        conn.commit()
    return count
def insert_alert(event_id: int, event_type: str, time_utc: str) -> None:
    """Insert a new alert triggered by a critical event."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO alerts (event_id, event_type, time_utc, delivered)
            VALUES (?, ?, ?, 0)
            """,
            (event_id, event_type, time_utc),
        )
        conn.commit()
