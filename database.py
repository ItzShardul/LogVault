"""
database.py
------------
SQLite persistence layer for LogVault.

Two tables:
  - logs        : the "actual" security log entries (the thing an attacker
                   who compromises the machine could edit or delete)
  - blockchain  : the append-only chain of blocks that fingerprints each
                   log at the moment it was written (the thing an attacker
                   should NOT be able to silently rewrite)

Keeping these as two separate tables (rather than one) is intentional and
mirrors the architecture described in the project brief: local storage vs.
blockchain-backed integrity record are conceptually different things that
happen to both live in the same SQLite file for this simulation.
"""

import sqlite3
import os
import threading

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logvault.db")

_lock = threading.Lock()


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(reset=False):
    """Create tables. If reset=True, drop and recreate everything."""
    with _lock:
        conn = get_connection()
        cur = conn.cursor()

        if reset:
            cur.execute("DROP TABLE IF EXISTS logs")
            cur.execute("DROP TABLE IF EXISTS blockchain")
            cur.execute("DROP TABLE IF EXISTS activity_feed")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                username TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                log_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE'
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS blockchain (
                block_index INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                log_id TEXT NOT NULL,
                log_hash TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                block_hash TEXT NOT NULL
            )
        """)

        # A rolling feed of "what just happened" for the dashboard,
        # used mainly to narrate the demo mode step by step.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS activity_feed (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                message TEXT NOT NULL,
                level TEXT NOT NULL DEFAULT 'info'
            )
        """)

        conn.commit()
        conn.close()


def add_activity(message, level="info"):
    from datetime import datetime, timezone
    with _lock:
        conn = get_connection()
        conn.execute(
            "INSERT INTO activity_feed (timestamp, message, level) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), message, level),
        )
        conn.commit()
        conn.close()


def get_activity(limit=50):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM activity_feed ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

def insert_log(event_id, timestamp, source_ip, username, event_type,
                severity, description, log_hash):
    with _lock:
        conn = get_connection()
        conn.execute("""
            INSERT INTO logs
                (event_id, timestamp, source_ip, username, event_type,
                 severity, description, log_hash, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
        """, (event_id, timestamp, source_ip, username, event_type,
              severity, description, log_hash))
        conn.commit()
        conn.close()


def get_all_logs():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM logs ORDER BY id ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_log_by_event_id(event_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM logs WHERE event_id = ?", (event_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_log_field(event_id, field, value):
    allowed = {"severity", "timestamp", "username", "description", "source_ip"}
    if field not in allowed:
        raise ValueError(f"Field '{field}' cannot be modified")
    with _lock:
        conn = get_connection()
        conn.execute(f"UPDATE logs SET {field} = ? WHERE event_id = ?", (value, event_id))
        conn.commit()
        conn.close()


def delete_log(event_id):
    with _lock:
        conn = get_connection()
        conn.execute("DELETE FROM logs WHERE event_id = ?", (event_id,))
        conn.commit()
        conn.close()


def count_logs():
    conn = get_connection()
    n = conn.execute("SELECT COUNT(*) AS c FROM logs").fetchone()["c"]
    conn.close()
    return n


# ---------------------------------------------------------------------------
# Blockchain
# ---------------------------------------------------------------------------

def insert_block(index, timestamp, log_id, log_hash, previous_hash, block_hash):
    with _lock:
        conn = get_connection()
        conn.execute("""
            INSERT INTO blockchain
                (block_index, timestamp, log_id, log_hash, previous_hash, block_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (index, timestamp, log_id, log_hash, previous_hash, block_hash))
        conn.commit()
        conn.close()


def get_all_blocks():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM blockchain ORDER BY block_index ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_block_by_log_id(log_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM blockchain WHERE log_id = ? ORDER BY block_index DESC LIMIT 1",
        (log_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_latest_block():
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM blockchain ORDER BY block_index DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def update_block_field(index, field, value):
    """Used ONLY by the attacker simulation to demonstrate blockchain tampering."""
    allowed = {"previous_hash", "log_hash", "timestamp", "block_hash"}
    if field not in allowed:
        raise ValueError(f"Field '{field}' cannot be modified")
    with _lock:
        conn = get_connection()
        conn.execute(f"UPDATE blockchain SET {field} = ? WHERE block_index = ?", (value, index))
        conn.commit()
        conn.close()


def count_blocks():
    conn = get_connection()
    n = conn.execute("SELECT COUNT(*) AS c FROM blockchain").fetchone()["c"]
    conn.close()
    return n
