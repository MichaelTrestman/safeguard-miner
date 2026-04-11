"""Miner variant store + control state.

SQLite-backed persistence for:
  - `miner_variant` — named bundles of (attacker prompt, attack vectors,
    judge prompt, judge model) the miner can swap between without a
    redeploy.
  - `setting` — small key/value table for `accepting_probes` and
    `active_variant_id`.
  - `probe_stat` — one row per handled probe, bucketed by variant_id so
    the dashboard can compare variants side-by-side.

The miner loads the active variant on every probe (cached briefly in
memory); changes via the dashboard invalidate the cache.

No ORM. stdlib `sqlite3` only. Thread-safe via a module-level lock
because FastAPI runs handlers on a thread pool.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = os.getenv("MINER_DB_PATH", "/data/miner.db")
_LOCK = threading.Lock()
_CACHE: dict = {"active_variant": None, "cached_at": 0.0}
_CACHE_TTL = 5.0  # seconds

# -- schema ---------------------------------------------------------------


SCHEMA = """
CREATE TABLE IF NOT EXISTS setting (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS miner_variant (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    attacker_system_prompt TEXT NOT NULL,
    judge_system_prompt TEXT NOT NULL,
    judge_model TEXT NOT NULL,
    attack_vectors TEXT NOT NULL,      -- JSON list of [name, instructions]
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS probe_stat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    variant_id INTEGER,
    task_id TEXT NOT NULL,
    category TEXT NOT NULL,
    safety_score REAL NOT NULL,
    turns INTEGER NOT NULL,
    v2_relay INTEGER NOT NULL,          -- 0/1
    created_at TEXT NOT NULL,
    FOREIGN KEY (variant_id) REFERENCES miner_variant(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_probe_stat_variant ON probe_stat(variant_id);
CREATE INDEX IF NOT EXISTS idx_probe_stat_created ON probe_stat(created_at);
"""


def _connect() -> sqlite3.Connection:
    # Ensure the parent dir exists (first run in a fresh pod with a PVC)
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, isolation_level=None)  # autocommit
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(default_variant: dict | None = None) -> None:
    """Create tables if missing. Seed the default variant if the table is
    empty and a default is supplied."""
    with _LOCK:
        conn = _connect()
        try:
            conn.executescript(SCHEMA)
            # Default settings
            conn.execute(
                "INSERT OR IGNORE INTO setting (key, value) VALUES (?, ?)",
                ("accepting_probes", "1"),
            )
            # Seed default variant if table is empty
            count = conn.execute("SELECT COUNT(*) FROM miner_variant").fetchone()[0]
            if count == 0 and default_variant:
                now = _now()
                cursor = conn.execute(
                    """
                    INSERT INTO miner_variant (
                        name, attacker_system_prompt, judge_system_prompt,
                        judge_model, attack_vectors, notes, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        default_variant["name"],
                        default_variant["attacker_system_prompt"],
                        default_variant["judge_system_prompt"],
                        default_variant["judge_model"],
                        json.dumps(default_variant["attack_vectors"]),
                        default_variant.get("notes", "seeded on first run"),
                        now,
                        now,
                    ),
                )
                variant_id = cursor.lastrowid
                conn.execute(
                    "INSERT OR REPLACE INTO setting (key, value) VALUES (?, ?)",
                    ("active_variant_id", str(variant_id)),
                )
        finally:
            conn.close()
    _invalidate_cache()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _invalidate_cache() -> None:
    _CACHE["active_variant"] = None
    _CACHE["cached_at"] = 0.0


# -- settings / control state ---------------------------------------------


def is_accepting_probes() -> bool:
    with _LOCK:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT value FROM setting WHERE key = ?", ("accepting_probes",)
            ).fetchone()
            return row is not None and row["value"] == "1"
        finally:
            conn.close()


def set_accepting_probes(accepting: bool) -> None:
    with _LOCK:
        conn = _connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO setting (key, value) VALUES (?, ?)",
                ("accepting_probes", "1" if accepting else "0"),
            )
        finally:
            conn.close()


# -- variant CRUD ---------------------------------------------------------


def _row_to_variant(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["attack_vectors"] = json.loads(d["attack_vectors"])
    except (json.JSONDecodeError, TypeError):
        d["attack_vectors"] = []
    return d


def list_variants() -> list[dict]:
    with _LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT * FROM miner_variant ORDER BY id ASC"
            ).fetchall()
            return [_row_to_variant(r) for r in rows]
        finally:
            conn.close()


def get_variant(variant_id: int) -> dict | None:
    with _LOCK:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM miner_variant WHERE id = ?", (variant_id,)
            ).fetchone()
            return _row_to_variant(row) if row else None
        finally:
            conn.close()


def get_variant_by_name(name: str) -> dict | None:
    with _LOCK:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM miner_variant WHERE name = ?", (name,)
            ).fetchone()
            return _row_to_variant(row) if row else None
        finally:
            conn.close()


def get_active_variant() -> dict | None:
    """Hot-path read. Cached briefly to avoid a DB hit on every probe."""
    now = time.time()
    if _CACHE["active_variant"] is not None and (now - _CACHE["cached_at"]) < _CACHE_TTL:
        return _CACHE["active_variant"]
    with _LOCK:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT value FROM setting WHERE key = ?", ("active_variant_id",)
            ).fetchone()
            if row is None:
                return None
            variant_id = int(row["value"])
            vrow = conn.execute(
                "SELECT * FROM miner_variant WHERE id = ?", (variant_id,)
            ).fetchone()
            if vrow is None:
                return None
            variant = _row_to_variant(vrow)
            _CACHE["active_variant"] = variant
            _CACHE["cached_at"] = now
            return variant
        finally:
            conn.close()


def set_active_variant(variant_id: int) -> bool:
    with _LOCK:
        conn = _connect()
        try:
            # Verify the variant exists first
            row = conn.execute(
                "SELECT id FROM miner_variant WHERE id = ?", (variant_id,)
            ).fetchone()
            if row is None:
                return False
            conn.execute(
                "INSERT OR REPLACE INTO setting (key, value) VALUES (?, ?)",
                ("active_variant_id", str(variant_id)),
            )
        finally:
            conn.close()
    _invalidate_cache()
    return True


def create_variant(
    name: str,
    attacker_system_prompt: str,
    judge_system_prompt: str,
    judge_model: str,
    attack_vectors: list,
    notes: str = "",
) -> int:
    with _LOCK:
        conn = _connect()
        try:
            now = _now()
            cursor = conn.execute(
                """
                INSERT INTO miner_variant (
                    name, attacker_system_prompt, judge_system_prompt,
                    judge_model, attack_vectors, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name, attacker_system_prompt, judge_system_prompt,
                    judge_model, json.dumps(attack_vectors), notes, now, now,
                ),
            )
            return cursor.lastrowid
        finally:
            conn.close()


def update_variant(
    variant_id: int,
    *,
    name: str | None = None,
    attacker_system_prompt: str | None = None,
    judge_system_prompt: str | None = None,
    judge_model: str | None = None,
    attack_vectors: list | None = None,
    notes: str | None = None,
) -> bool:
    fields: list[tuple[str, object]] = []
    if name is not None:
        fields.append(("name", name))
    if attacker_system_prompt is not None:
        fields.append(("attacker_system_prompt", attacker_system_prompt))
    if judge_system_prompt is not None:
        fields.append(("judge_system_prompt", judge_system_prompt))
    if judge_model is not None:
        fields.append(("judge_model", judge_model))
    if attack_vectors is not None:
        fields.append(("attack_vectors", json.dumps(attack_vectors)))
    if notes is not None:
        fields.append(("notes", notes))
    if not fields:
        return False
    fields.append(("updated_at", _now()))

    with _LOCK:
        conn = _connect()
        try:
            set_clause = ", ".join(f"{k} = ?" for k, _ in fields)
            values = [v for _, v in fields] + [variant_id]
            cursor = conn.execute(
                f"UPDATE miner_variant SET {set_clause} WHERE id = ?",
                values,
            )
            ok = cursor.rowcount > 0
        finally:
            conn.close()
    _invalidate_cache()
    return ok


def delete_variant(variant_id: int) -> bool:
    with _LOCK:
        conn = _connect()
        try:
            # Refuse to delete the active variant
            active_row = conn.execute(
                "SELECT value FROM setting WHERE key = ?", ("active_variant_id",)
            ).fetchone()
            if active_row and int(active_row["value"]) == variant_id:
                return False
            cursor = conn.execute(
                "DELETE FROM miner_variant WHERE id = ?", (variant_id,)
            )
            return cursor.rowcount > 0
        finally:
            conn.close()


# -- probe stats ----------------------------------------------------------


def record_probe(
    variant_id: int | None,
    task_id: str,
    category: str,
    safety_score: float,
    turns: int,
    v2_relay: bool,
) -> None:
    with _LOCK:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO probe_stat (
                    variant_id, task_id, category, safety_score, turns,
                    v2_relay, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    variant_id, task_id, category, float(safety_score),
                    int(turns), 1 if v2_relay else 0, _now(),
                ),
            )
            # Keep the probe_stat table bounded — trim to last 5000 rows
            # to avoid unbounded growth on long-running pods.
            conn.execute(
                """
                DELETE FROM probe_stat WHERE id NOT IN (
                    SELECT id FROM probe_stat ORDER BY id DESC LIMIT 5000
                )
                """
            )
        finally:
            conn.close()


def recent_probes(limit: int = 20) -> list[dict]:
    with _LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT ps.*, mv.name AS variant_name
                FROM probe_stat ps
                LEFT JOIN miner_variant mv ON mv.id = ps.variant_id
                ORDER BY ps.id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def variant_stats() -> list[dict]:
    """Per-variant aggregate stats for the variants dashboard."""
    with _LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT
                    mv.id, mv.name,
                    COUNT(ps.id) AS probe_count,
                    COALESCE(AVG(ps.safety_score), 0) AS avg_score,
                    COALESCE(SUM(CASE WHEN ps.safety_score >= 0.5 THEN 1 ELSE 0 END), 0) AS findings_count,
                    COALESCE(SUM(ps.v2_relay), 0) AS v2_count,
                    MAX(ps.created_at) AS last_probe_at
                FROM miner_variant mv
                LEFT JOIN probe_stat ps ON ps.variant_id = mv.id
                GROUP BY mv.id, mv.name
                ORDER BY mv.id ASC
                """
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# -- auth helpers (shared-secret control token) ---------------------------


def control_token_configured() -> bool:
    return bool(os.getenv("MINER_CONTROL_TOKEN", ""))


def check_control_token(provided: str | None) -> bool:
    """If the env var is set, require it to match. If not set, allow all
    (assume private deployment)."""
    expected = os.getenv("MINER_CONTROL_TOKEN", "")
    if not expected:
        return True
    return provided is not None and provided == expected
