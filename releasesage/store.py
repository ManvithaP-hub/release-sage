"""SQLite persistence: items, briefings, runs, angles.

History is what makes novelty, threading, corroboration, and the angle
uniqueness check possible. Single file, zero infra; swap for Postgres by
reimplementing this module's five functions.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .models import Briefing

_SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
  uid TEXT PRIMARY KEY, source_id TEXT, title TEXT, url TEXT, summary TEXT,
  published TEXT, tier TEXT, thread_id TEXT, thread_position INTEGER,
  corroboration TEXT, admitted INTEGER, rejection_reasons TEXT,
  cls_category TEXT, cls_signal_label TEXT, cls_audiences TEXT,
  cls_substance INTEGER, cls_novelty INTEGER, cls_hype_risk INTEGER,
  cls_urgency INTEGER, cls_overall INTEGER,
  cls_what_happened TEXT, cls_why_it_matters TEXT, cls_builder_takeaway TEXT,
  cls_uncertainty TEXT, cls_vendor_framed INTEGER,
  briefing_number INTEGER, created_at REAL
);
CREATE TABLE IF NOT EXISTS briefings (
  number INTEGER PRIMARY KEY, window_start TEXT, window_end TEXT,
  published INTEGER, gate_reasons TEXT, admitted INTEGER, rejected INTEGER,
  total_information INTEGER, run_stats TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS angles (
  id INTEGER PRIMARY KEY AUTOINCREMENT, briefing_number INTEGER,
  item_uid TEXT, hook TEXT, body TEXT, created_at REAL
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def next_briefing_number(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(number) AS n FROM briefings").fetchone()
    return (row["n"] or 0) + 1


def recent_item_history(conn: sqlite3.Connection, days: int) -> list[dict]:
    cutoff = time.time() - days * 86400
    rows = conn.execute(
        "SELECT uid, title, summary, thread_id, tier FROM items WHERE created_at > ?",
        (cutoff,)).fetchall()
    return [dict(r) for r in rows]


def angle_history(conn: sqlite3.Connection, limit: int = 200) -> list[str]:
    rows = conn.execute(
        "SELECT hook FROM angles ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [r["hook"] for r in rows]


def save_briefing(conn: sqlite3.Connection, b: Briefing) -> None:
    now = time.time()
    conn.execute(
        "INSERT OR REPLACE INTO briefings VALUES (?,?,?,?,?,?,?,?,?,?)",
        (b.number, b.window_start, b.window_end, int(b.gate.published),
         json.dumps(b.gate.reasons), b.gate.admitted, b.gate.rejected,
         b.gate.total_information, json.dumps(b.run_stats), now))
    for item in b.items:
        rec = item.to_record()
        rec["briefing_number"] = b.number
        rec["created_at"] = now
        cols = ",".join(rec)
        conn.execute(f"INSERT OR REPLACE INTO items ({cols}) VALUES "
                     f"({','.join('?' * len(rec))})", tuple(rec.values()))
    for a in b.angles:
        conn.execute("INSERT INTO angles (briefing_number, item_uid, hook, body, created_at) "
                     "VALUES (?,?,?,?,?)", (b.number, a.item_uid, a.hook, a.body, now))
    conn.commit()
