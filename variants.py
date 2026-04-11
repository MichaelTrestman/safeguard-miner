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
    concern_id_slug TEXT,               -- Concerns v2: which concern seeded this probe (nullable; NULL = v1 fallback / empty catalog)
    trigger_id INTEGER,                 -- Concerns v2 precise attribution: UserTrigger row id on the validator (nullable; NULL = no trigger used)
    FOREIGN KEY (variant_id) REFERENCES miner_variant(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_probe_stat_variant ON probe_stat(variant_id);
CREATE INDEX IF NOT EXISTS idx_probe_stat_created ON probe_stat(created_at);

CREATE TABLE IF NOT EXISTS hitl_case (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT UNIQUE NOT NULL,
    transcript TEXT NOT NULL,           -- JSON list of {role, content}
    miner_claim TEXT NOT NULL,          -- JSON of miner-reported claim/score
    validator_audit TEXT NOT NULL,      -- JSON of validator audit context
    status TEXT NOT NULL CHECK (status IN ('pending','in_review','labeled','timed_out')),
    received_at TEXT NOT NULL,
    labeled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_hitl_case_status ON hitl_case(status);
CREATE INDEX IF NOT EXISTS idx_hitl_case_received ON hitl_case(received_at);

CREATE TABLE IF NOT EXISTS hitl_label (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    severity REAL NOT NULL,
    categories TEXT NOT NULL,           -- JSON list of strings
    reasoning TEXT NOT NULL DEFAULT '',
    submitted_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES hitl_case(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hitl_label_case ON hitl_label(case_id);
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
            # Concerns v2 migration: add probe_stat.concern_id_slug on
            # existing DBs where the column didn't exist before. SQLite
            # doesn't support IF NOT EXISTS on ALTER TABLE ADD COLUMN,
            # so we introspect PRAGMA table_info first.
            existing_cols = {
                r["name"]
                for r in conn.execute("PRAGMA table_info(probe_stat)").fetchall()
            }
            if "concern_id_slug" not in existing_cols:
                conn.execute("ALTER TABLE probe_stat ADD COLUMN concern_id_slug TEXT")
            # Concerns v2 precise attribution: add probe_stat.trigger_id
            # on existing DBs in place (same PRAGMA table_info pattern as
            # concern_id_slug above).
            if "trigger_id" not in existing_cols:
                conn.execute("ALTER TABLE probe_stat ADD COLUMN trigger_id INTEGER")
            # Default settings
            conn.execute(
                "INSERT OR IGNORE INTO setting (key, value) VALUES (?, ?)",
                ("accepting_probes", "1"),
            )
            conn.execute(
                "INSERT OR IGNORE INTO setting (key, value) VALUES (?, ?)",
                ("accepting_hitl_cases", "1"),
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
    concern_id_slug: str | None = None,
    trigger_id: int | None = None,
) -> None:
    with _LOCK:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO probe_stat (
                    variant_id, task_id, category, safety_score, turns,
                    v2_relay, created_at, concern_id_slug, trigger_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    variant_id, task_id, category, float(safety_score),
                    int(turns), 1 if v2_relay else 0, _now(),
                    concern_id_slug,
                    int(trigger_id) if trigger_id is not None else None,
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


# -- HITL case store ------------------------------------------------------


def is_accepting_hitl_cases() -> bool:
    with _LOCK:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT value FROM setting WHERE key = ?",
                ("accepting_hitl_cases",),
            ).fetchone()
            return row is not None and row["value"] == "1"
        finally:
            conn.close()


def set_accepting_hitl_cases(accepting: bool) -> None:
    with _LOCK:
        conn = _connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO setting (key, value) VALUES (?, ?)",
                ("accepting_hitl_cases", "1" if accepting else "0"),
            )
        finally:
            conn.close()


def _row_to_hitl_case(row: sqlite3.Row) -> dict:
    d = dict(row)
    for field in ("transcript", "miner_claim", "validator_audit"):
        try:
            d[field] = json.loads(d[field]) if d.get(field) else None
        except (json.JSONDecodeError, TypeError):
            d[field] = None
    return d


def insert_hitl_case(
    task_id: str,
    transcript: list | dict,
    miner_claim: dict,
    validator_audit: dict,
) -> int | None:
    """Insert a new hitl_case. Returns the row id, or None if a row with
    this task_id already exists (idempotent on re-delivery)."""
    with _LOCK:
        conn = _connect()
        try:
            now = _now()
            try:
                cursor = conn.execute(
                    """
                    INSERT INTO hitl_case (
                        task_id, transcript, miner_claim, validator_audit,
                        status, received_at
                    ) VALUES (?, ?, ?, ?, 'pending', ?)
                    """,
                    (
                        task_id,
                        json.dumps(transcript) if transcript is not None else "null",
                        json.dumps(miner_claim) if miner_claim is not None else "null",
                        json.dumps(validator_audit) if validator_audit is not None else "null",
                        now,
                    ),
                )
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                return None
        finally:
            conn.close()


def get_hitl_case_by_task_id(task_id: str) -> dict | None:
    with _LOCK:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM hitl_case WHERE task_id = ?", (task_id,)
            ).fetchone()
            return _row_to_hitl_case(row) if row else None
        finally:
            conn.close()


def get_pending_hitl_cases(limit: int = 50) -> list[dict]:
    with _LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT * FROM hitl_case
                WHERE status IN ('pending','in_review')
                ORDER BY received_at ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [_row_to_hitl_case(r) for r in rows]
        finally:
            conn.close()


def set_hitl_case_status(task_id: str, status: str) -> bool:
    if status not in ("pending", "in_review", "labeled", "timed_out"):
        return False
    with _LOCK:
        conn = _connect()
        try:
            if status == "labeled":
                cursor = conn.execute(
                    "UPDATE hitl_case SET status = ?, labeled_at = ? WHERE task_id = ?",
                    (status, _now(), task_id),
                )
            else:
                cursor = conn.execute(
                    "UPDATE hitl_case SET status = ? WHERE task_id = ?",
                    (status, task_id),
                )
            return cursor.rowcount > 0
        finally:
            conn.close()


def record_hitl_label(
    case_id: int,
    severity: float,
    categories: list,
    reasoning: str,
) -> int:
    """Insert a hitl_label row and flip the parent case to 'labeled'.
    Returns the label row id."""
    with _LOCK:
        conn = _connect()
        try:
            now = _now()
            cursor = conn.execute(
                """
                INSERT INTO hitl_label (
                    case_id, severity, categories, reasoning, submitted_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    float(severity),
                    json.dumps(list(categories)),
                    reasoning or "",
                    now,
                ),
            )
            label_id = cursor.lastrowid
            conn.execute(
                "UPDATE hitl_case SET status = 'labeled', labeled_at = ? WHERE id = ?",
                (now, case_id),
            )
            return label_id
        finally:
            conn.close()


def recent_hitl_labels(limit: int = 20) -> list[dict]:
    """Recent labels joined with their case for the history table."""
    with _LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT
                    hl.id, hl.case_id, hl.severity, hl.categories, hl.reasoning,
                    hl.submitted_at,
                    hc.task_id, hc.received_at
                FROM hitl_label hl
                JOIN hitl_case hc ON hc.id = hl.case_id
                ORDER BY hl.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["categories"] = json.loads(d["categories"])
                except (json.JSONDecodeError, TypeError):
                    d["categories"] = []
                out.append(d)
            return out
        finally:
            conn.close()


def get_label_by_task_id(task_id: str) -> dict | None:
    """Fetch the most recent hitl_label for a task_id, joining through
    hitl_case. Returns None if no label has been recorded.

    This is the source of truth for a labeled case — `handle_hitl_task`
    reads it on wake instead of a volatile in-memory payload dict, so
    duplicate dispatches of the same task_id all converge to the same
    persisted answer without racing on who-pops-the-dict-first."""
    with _LOCK:
        conn = _connect()
        try:
            row = conn.execute(
                """
                SELECT
                    hl.id, hl.case_id, hl.severity, hl.categories, hl.reasoning,
                    hl.submitted_at,
                    hc.task_id
                FROM hitl_label hl
                JOIN hitl_case hc ON hc.id = hl.case_id
                WHERE hc.task_id = ?
                ORDER BY hl.id DESC
                LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            if row is None:
                return None
            d = dict(row)
            try:
                d["categories"] = json.loads(d["categories"])
            except (json.JSONDecodeError, TypeError):
                d["categories"] = []
            return d
        finally:
            conn.close()


def hitl_stats() -> dict:
    """Aggregate counters for the dashboard stats card."""
    with _LOCK:
        conn = _connect()
        try:
            row = conn.execute(
                """
                SELECT
                    COALESCE(SUM(CASE WHEN status='pending'   THEN 1 ELSE 0 END), 0) AS pending,
                    COALESCE(SUM(CASE WHEN status='in_review' THEN 1 ELSE 0 END), 0) AS in_review,
                    COALESCE(SUM(CASE WHEN status='labeled'   THEN 1 ELSE 0 END), 0) AS labeled,
                    COALESCE(SUM(CASE WHEN status='timed_out' THEN 1 ELSE 0 END), 0) AS timed_out,
                    COUNT(*) AS total
                FROM hitl_case
                """
            ).fetchone()
            return dict(row) if row else {
                "pending": 0, "in_review": 0, "labeled": 0,
                "timed_out": 0, "total": 0,
            }
        finally:
            conn.close()
