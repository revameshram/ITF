"""SQLite persistence layer.

One small database file (data/generated/aegis.db) holds everything:
audit chain, inference records, model registry, findings, evidence,
the evidence graph, cases and audit runs. JSON documents are stored as
text so the schema stays simple for a student team to maintain.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);

CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    asset TEXT,
    details TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS inference_records (
    record_id TEXT PRIMARY KEY,
    stream TEXT NOT NULL,
    seq INTEGER NOT NULL,
    body TEXT NOT NULL,
    received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    record_id TEXT NOT NULL,
    first_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    record_id TEXT,
    accepted INTEGER NOT NULL,
    reason TEXT
);

CREATE TABLE IF NOT EXISTS model_registry (
    model_id TEXT PRIMARY KEY,
    doc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started TEXT NOT NULL,
    doc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    doc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    doc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS graph_nodes (
    run_id TEXT NOT NULL,
    id TEXT NOT NULL,
    type TEXT NOT NULL,
    label TEXT NOT NULL,
    props TEXT,
    PRIMARY KEY (run_id, id)
);

CREATE TABLE IF NOT EXISTS graph_edges (
    run_id TEXT NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    rel TEXT NOT NULL,
    props TEXT
);

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    doc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
"""


class Store:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else config.DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---- low level -------------------------------------------------
    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self.conn.execute(sql, tuple(params))
            self.conn.commit()
            return cur

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.conn.execute(sql, tuple(params)).fetchall())

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # ---- key/value -------------------------------------------------
    def kv_get(self, k: str, default: Any = None) -> Any:
        rows = self.query("SELECT v FROM kv WHERE k=?", (k,))
        return json.loads(rows[0]["v"]) if rows else default

    def kv_set(self, k: str, v: Any) -> None:
        self.execute("INSERT OR REPLACE INTO kv(k, v) VALUES(?, ?)", (k, json.dumps(v)))

    # ---- counters for human-friendly IDs (F-001, E-001, CASE-0001) --
    def next_id(self, name: str, prefix: str, width: int = 3) -> str:
        with self._lock:
            row = self.conn.execute("SELECT value FROM counters WHERE name=?", (name,)).fetchone()
            value = (row["value"] if row else 0) + 1
            self.conn.execute("INSERT OR REPLACE INTO counters(name, value) VALUES(?, ?)", (name, value))
            self.conn.commit()
        return f"{prefix}{value:0{width}d}"

    # ---- JSON document helpers --------------------------------------
    def put_doc(self, table: str, doc_id: str, doc: dict, **cols: Any) -> None:
        names = ["id" if table != "model_registry" else "model_id", "doc", *cols.keys()]
        placeholders = ",".join("?" for _ in names)
        self.execute(
            f"INSERT OR REPLACE INTO {table}({','.join(names)}) VALUES({placeholders})",
            (doc_id, json.dumps(doc), *cols.values()),
        )

    def get_doc(self, table: str, doc_id: str) -> dict | None:
        key = "model_id" if table == "model_registry" else "id"
        rows = self.query(f"SELECT doc FROM {table} WHERE {key}=?", (doc_id,))
        return json.loads(rows[0]["doc"]) if rows else None

    def list_docs(self, table: str, where: str = "", params: Iterable[Any] = ()) -> list[dict]:
        sql = f"SELECT doc FROM {table} {('WHERE ' + where) if where else ''}"
        return [json.loads(r["doc"]) for r in self.query(sql, params)]

    def reset_all(self) -> None:
        """Drop every row (used by 'Reset demo'). Schema is kept."""
        with self._lock:
            for (name,) in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                if name.startswith("sqlite_"):
                    continue
                self.conn.execute(f"DELETE FROM {name}")
            self.conn.commit()
