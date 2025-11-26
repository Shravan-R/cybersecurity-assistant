# responders/db_logger.py
import sqlite3
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

class DBLogger:
    """
    Simple SQLite logger for events.
    'database_url' expected like 'sqlite:///./events.db' or path './events.db' or ':memory:'.
    """

    def __init__(self, database_url: str):
        # Accept sqlite:///./path or direct path
        if database_url.startswith("sqlite:///"):
            path = database_url.split("sqlite:///")[-1]
        else:
            path = database_url
        self.path = path or "./events.db"
        self._init_db()

    def _init_db(self):
        con = sqlite3.connect(self.path, check_same_thread=False)
        cur = con.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                type TEXT,
                combined_score INTEGER,
                action TEXT,
                reason TEXT,
                payload TEXT
            )
        """
        )
        con.commit()
        con.close()

    def log_event(self, event: Dict[str, Any]) -> None:
        con = sqlite3.connect(self.path)
        cur = con.cursor()
        cur.execute(
            """
            INSERT INTO events(ts,type,combined_score,action,reason,payload)
            VALUES (?,?,?,?,?,?)
        """,
            (
                datetime.utcnow().isoformat(),
                event.get("type"),
                int(event.get("combined_score") or 0),
                event.get("action"),
                (event.get("reason") or "")[:1000],
                json.dumps(event),
            ),
        )
        con.commit()
        con.close()

    def last_events(self, limit: int = 5) -> List[Dict[str, Any]]:
        con = sqlite3.connect(self.path)
        cur = con.cursor()
        cur.execute(
            "SELECT id, ts, type, combined_score, action, reason FROM events ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = cur.fetchall()
        con.close()
        return [
            {"id": r[0], "ts": r[1], "type": r[2], "score": r[3], "action": r[4], "reason": r[5]} for r in rows
        ]

    def query_all(self, limit: int = 100) -> List[Dict[str, Any]]:
        con = sqlite3.connect(self.path)
        cur = con.cursor()
        cur.execute("SELECT id, ts, type, combined_score, action, reason, payload FROM events ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        con.close()
        out = []
        for r in rows:
            payload = {}
            try:
                payload = json.loads(r[6])
            except Exception:
                payload = {}
            out.append({"id": r[0], "ts": r[1], "type": r[2], "score": r[3], "action": r[4], "reason": r[5], "payload": payload})
        return out
