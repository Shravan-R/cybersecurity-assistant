# responders/db_logger.py
import sqlite3
import threading
from datetime import datetime
from typing import Optional, List, Dict
import os
import re
import logging
import json

logger = logging.getLogger("cybersec-assistant.dblogger")

class DBLogger:
    def __init__(self, db_path: str):
        """
        db_path can be:
          - "./data/events.db"
          - "sqlite:///./data/events.db"
        """
        if not db_path:
            db_path = "./events.db"

        # allow sqlite:///./path and sqlite:///{abs}
        match = re.match(r"sqlite:(?:///?)(.+)", db_path)
        if match:
            sqlite_file = match.group(1)
        else:
            sqlite_file = db_path

        # make absolute
        sqlite_file = os.path.abspath(sqlite_file)

        # ensure directory exists
        dirpath = os.path.dirname(sqlite_file)
        if dirpath and not os.path.exists(dirpath):
            try:
                os.makedirs(dirpath, exist_ok=True)
            except Exception as e:
                logger.warning("Could not create DB directory %s: %s", dirpath, e)

        self.db_path = sqlite_file
        self._lock = threading.Lock()
        self._ensure_tables()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_tables(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT,
                    action TEXT,
                    score REAL,
                    reason TEXT,
                    data TEXT,
                    created_at TEXT
                )
            """)
            conn.commit()

    # ------------------ SAVE EVENT ------------------
    def log_event(self, decision: dict) -> int:
        """
        Insert a decision dict into events table.
        Expected keys in decision: type, action, combined_score, reason.
        Stores JSON dump of decision in data column.
        Returns inserted row id.
        """
        with self._lock:
            with self._connect() as conn:
                now = datetime.utcnow().isoformat() + "Z"
                data_json = None
                try:
                    data_json = json.dumps(decision, default=str)
                except Exception:
                    # fallback to str
                    data_json = json.dumps({"raw": str(decision)})
                cur = conn.execute("""
                    INSERT INTO events (type, action, score, reason, data, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    decision.get("type"),
                    decision.get("action"),
                    decision.get("combined_score") or decision.get("score") or 0,
                    decision.get("reason"),
                    data_json,
                    now
                ))
                conn.commit()
                rowid = cur.lastrowid
                logger.debug("Logged event id=%s type=%s action=%s", rowid, decision.get("type"), decision.get("action"))
                return rowid

    # ------------------ GET LAST EVENTS ------------------
    def get_last_events(self, limit: int = 20) -> List[Dict]:
        if limit <= 0:
            limit = 20
        with self._connect() as conn:
            cur = conn.execute("""
                SELECT id, type, action, score, reason, data, created_at
                FROM events
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = cur.fetchall()

            out = []
            for r in rows:
                data_field = r["data"]
                parsed = None
                if data_field:
                    try:
                        parsed = json.loads(data_field)
                    except Exception:
                        parsed = data_field
                out.append({
                    "id": int(r["id"]),
                    "type": r["type"],
                    "action": r["action"],
                    "score": r["score"],
                    "reason": r["reason"],
                    "data": parsed,
                    "created_at": r["created_at"]
                })
            return out

    # ------------------ GET SINGLE EVENT ------------------
    def get_event(self, event_id: int) -> Optional[Dict]:
        with self._connect() as conn:
            cur = conn.execute("""
                SELECT id, type, action, score, reason, data, created_at
                FROM events
                WHERE id = ?
            """, (event_id,))
            r = cur.fetchone()
            if not r:
                return None
            data_field = r["data"]
            parsed = None
            if data_field:
                try:
                    parsed = json.loads(data_field)
                except Exception:
                    parsed = data_field
            return {
                "id": int(r["id"]),
                "type": r["type"],
                "action": r["action"],
                "score": r["score"],
                "reason": r["reason"],
                "data": parsed,
                "created_at": r["created_at"]
            }

    # ------------------ DELETE EVENT ------------------
    def delete_event(self, event_id: int) -> bool:
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
                conn.commit()
                return cur.rowcount > 0
