"""HITL role for safeguard-miner.

Exposes:
  - POST /hitl_task           (Epistula-authed receive from the validator;
                               blocks until a human operator labels the case
                               via /hitl/submit-label, or HITL_TASK_TIMEOUT)
  - POST /hitl/submit-label   (dashboard form POST; wakes the waiter)

Ported from safeguard/safeguard-hitl-miner/main.py (read-only reference).
This module adds no new threads, no new ports, no new wallets — it just
registers a FastAPI APIRouter that miner.py mounts on the main app.

Coordination points with the validator-side agent (A2). These are the
places I had to guess the wire contract because the legacy reference
predates the current validator-side HitlCase model; A2 must confirm:

  * Inbound /hitl_task request body shape. Legacy reference used:
        {task_id, transcript, category, miner_safety_score, validator_score}
    This module accepts that superset and also reads top-level
    'miner_claim' and 'validator_audit' objects if present so the
    validator can pass richer context. If A2 standardizes on either
    shape, fine — we preserve whatever arrives into `hitl_case`.

  * Outbound response shape on a successful label.
        {task_id, status: "labeled", severity, categories, reasoning}
    `severity` is a float 0.0–1.0 (the slider value). The legacy
    reference also carried a string `severity` enum ("LOW"/"HIGH"/…).
    We drop the enum — the float is the ground truth per DESIGN.md
    §"HITL as the primary value layer". A2 must accept float severity.

  * Timeout response: HTTP 504 with {task_id, status: "timed_out"}.
    Legacy reference returned 200 with status="timeout". We use 504
    so the validator's dispatch loop can retry via its normal HTTP
    failure path. A2 must treat 504 as a retryable miner cooldown.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse
from bittensor_wallet.keypair import Keypair

import variants

logger = logging.getLogger(__name__)

# Seconds the /hitl_task handler will block waiting for a human label
# before responding 504. Configurable via env for deployments with
# slower operators or faster validator retry loops.
HITL_TASK_TIMEOUT = int(os.getenv("HITL_TASK_TIMEOUT", "600"))
MAX_REQUEST_AGE = 60

router = APIRouter()

# task_id -> asyncio.Event. Created when a case arrives, set when the
# dashboard form submits a label, awaited by the /hitl_task handler.
#
# The label payload itself is NOT held in memory. Once
# `submit_hitl_label` writes the `hitl_label` row via
# `variants.record_hitl_label` and flips the case to `labeled`, the DB
# is the single source of truth. Waiters read the label back via
# `variants.get_label_by_task_id` on wake. This design is deliberate:
# a validator may retry /hitl_task for the same task_id, parking two
# waiters on the same Event; when the human labels once, both waiters
# wake, both read the same persisted label, both return 200 with the
# same body. No in-memory pop-once dict, no 500 on the second waiter.
_pending_events: dict[str, asyncio.Event] = {}
_pending_lock = asyncio.Lock()


def _label_response(task_id: str, label_row: dict) -> dict:
    """Shape a persisted hitl_label row into the outbound response body."""
    return {
        "task_id": task_id,
        "status": "labeled",
        "severity": label_row["severity"],
        "categories": label_row["categories"],
        "reasoning": label_row.get("reasoning", ""),
    }


# miner.py sets this at import-time wiring so we can reuse the same
# Metagraph instance for validator-permit checks. Using a module-level
# accessor (not a direct import) avoids a circular import with miner.py.
_metagraph_accessor = None


def set_metagraph_accessor(fn):
    """miner.py calls this with a zero-arg callable that returns the
    current metagraph. We cannot import metagraph directly from miner.py
    because miner.py imports this module."""
    global _metagraph_accessor
    _metagraph_accessor = fn


def _verify_epistula(timestamp: str, signature: str, hotkey: str, body: bytes) -> str:
    request_time = int(timestamp) / 1e9
    if abs(time.time() - request_time) > MAX_REQUEST_AGE:
        raise ValueError("Request timestamp too old")
    body_hash = hashlib.sha256(body).hexdigest()
    message = f"{timestamp}.{body_hash}"
    keypair = Keypair(ss58_address=hotkey)
    if not keypair.verify(message.encode(), bytes.fromhex(signature)):
        raise ValueError("Invalid signature")
    return hotkey


async def _get_body(request: Request) -> bytes:
    return await request.body()


async def _verify_validator(
    request: Request, body: bytes = Depends(_get_body)
) -> str:
    """Validator-permit gated Epistula verify — mirrors prober/miner.py."""
    try:
        hotkey = _verify_epistula(
            timestamp=request.headers["X-Epistula-Timestamp"],
            signature=request.headers["X-Epistula-Signature"],
            hotkey=request.headers["X-Epistula-Hotkey"],
            body=body,
        )
    except KeyError as e:
        raise HTTPException(400, f"Missing header: {e}")
    except ValueError as e:
        raise HTTPException(401, str(e))

    if _metagraph_accessor is None:
        # Startup hasn't wired us yet — reject rather than crash.
        raise HTTPException(503, "HITL role not ready (metagraph unwired)")
    metagraph = _metagraph_accessor()
    if metagraph is None:
        raise HTTPException(503, "Metagraph unavailable")

    if hotkey not in metagraph.hotkeys:
        raise HTTPException(403, "Caller not on subnet")
    uid = metagraph.hotkeys.index(hotkey)
    if not metagraph.validator_permit[uid]:
        raise HTTPException(403, "Caller not a validator")
    return hotkey


@router.post("/hitl_task")
async def handle_hitl_task(
    request: Request, validator_hotkey: str = Depends(_verify_validator)
):
    """Receive a HITL case from the validator. Block until a human
    labels it via /hitl/submit-label, or HITL_TASK_TIMEOUT fires."""
    if not variants.is_accepting_hitl_cases():
        logger.info(
            f"Rejecting HITL task from {validator_hotkey[:8]}... — role paused"
        )
        return JSONResponse(
            {"error": "hitl role paused", "accepting_hitl_cases": False},
            status_code=503,
        )

    body = await request.json()
    task_id = body.get("task_id")
    if not task_id:
        raise HTTPException(400, "Missing task_id")

    transcript = body.get("transcript", [])
    # Accept either the legacy flat fields (miner_safety_score,
    # validator_score, category) OR new structured fields
    # (miner_claim, validator_audit). We preserve whichever the
    # validator sends; see the coordination note at the top of the file.
    miner_claim = body.get("miner_claim")
    if miner_claim is None:
        miner_claim = {
            "miner_safety_score": body.get("miner_safety_score"),
            "category": body.get("category"),
        }
    validator_audit = body.get("validator_audit")
    if validator_audit is None:
        validator_audit = {
            "validator_score": body.get("validator_score"),
        }

    row_id = variants.insert_hitl_case(
        task_id=task_id,
        transcript=transcript,
        miner_claim=miner_claim,
        validator_audit=validator_audit,
    )
    if row_id is None:
        # Idempotent re-delivery of a case we already have. Look it up
        # and decide based on current status.
        existing = variants.get_hitl_case_by_task_id(task_id)
        if existing is None:
            # Insert returned None (IntegrityError on task_id) but no
            # row visible now — transient DB inconsistency. Surface a
            # conflict so the validator retries rather than crashing.
            logger.warning(
                f"HITL task {task_id[:12]}... insert returned None but row not found"
            )
            return JSONResponse(
                {
                    "task_id": task_id,
                    "status": "conflict",
                    "error": "case insert reported duplicate but row not visible",
                },
                status_code=409,
            )
        if existing["status"] == "labeled":
            # Already labeled — return the persisted label directly so
            # the validator converges without re-blocking.
            label_row = variants.get_label_by_task_id(task_id)
            if label_row is None:
                logger.error(
                    f"HITL task {task_id[:12]}... case marked labeled but no hitl_label row"
                )
                return JSONResponse(
                    {
                        "task_id": task_id,
                        "status": "conflict",
                        "error": "case marked labeled but no label row persisted",
                    },
                    status_code=409,
                )
            return _label_response(task_id, label_row)
        if existing["status"] == "timed_out":
            # A previous dispatch for this task_id already hit the
            # local wait timeout. The validator (A2 contract) treats
            # a 504 as a retryable cooldown and may redispatch the
            # same task_id later. That's a legitimate second chance
            # to label — re-queue the case so the dashboard shows it,
            # then fall through to the block path below.
            variants.set_hitl_case_status(task_id, "pending")
            logger.info(
                f"HITL task {task_id[:12]}... was timed_out; "
                f"re-queued on validator retry"
            )
        # else: existing status is 'pending' or 'in_review' — already
        # in the queue. Fall through and park on the shared Event
        # below. A second waiter on the same task_id is fine: the
        # DB-backed read on wake means both waiters return the same
        # label.

    logger.info(
        f"HITL task {task_id[:12]}... received from validator "
        f"{validator_hotkey[:8]}... — blocking on human label"
    )

    # Create (or reuse) the Event keyed by task_id.
    async with _pending_lock:
        event = _pending_events.get(task_id)
        if event is None:
            event = asyncio.Event()
            _pending_events[task_id] = event

    try:
        await asyncio.wait_for(event.wait(), timeout=HITL_TASK_TIMEOUT)
    except asyncio.TimeoutError:
        logger.info(
            f"HITL task {task_id[:12]}... timed out after {HITL_TASK_TIMEOUT}s"
        )
        variants.set_hitl_case_status(task_id, "timed_out")
        async with _pending_lock:
            # Only drop the event if it's still this one — a later
            # dispatch may have parked its own Event on the same key.
            if _pending_events.get(task_id) is event:
                _pending_events.pop(task_id, None)
        return JSONResponse(
            {"task_id": task_id, "status": "timed_out"},
            status_code=504,
        )

    # Event fired. Read the persisted label from the DB — this is
    # idempotent across concurrent waiters on the same task_id.
    label_row = variants.get_label_by_task_id(task_id)
    if label_row is None:
        # Event set but no label row exists. Only way this happens is
        # a code bug in submit_hitl_label (set event before writing DB)
        # or a DB-level failure in record_hitl_label. Surface a 409
        # with the specific failure so the validator logs something
        # actionable — NOT a 500.
        logger.error(
            f"HITL task {task_id[:12]}... event set but no hitl_label row found"
        )
        return JSONResponse(
            {
                "task_id": task_id,
                "status": "conflict",
                "error": "label event fired but no persisted label row",
            },
            status_code=409,
        )

    # Best-effort cleanup. Multiple waiters may race here; the last
    # one to pop wins, the rest are no-ops. We do NOT require this
    # cleanup for correctness — a stale Event in the dict just makes
    # the next dispatch for that task_id return from the "already
    # labeled" fast path above.
    async with _pending_lock:
        if _pending_events.get(task_id) is event:
            _pending_events.pop(task_id, None)

    logger.info(
        f"HITL task {task_id[:12]}... labeled: severity={label_row['severity']} "
        f"categories={label_row['categories']}"
    )
    return _label_response(task_id, label_row)


@router.post("/hitl/submit-label")
async def submit_hitl_label(
    request: Request,
    task_id: str = Form(...),
    severity: float = Form(...),
    categories: str = Form(""),        # comma-separated
    reasoning: str = Form(""),
):
    """Dashboard form target. Records the label and wakes the /hitl_task
    waiter keyed by task_id."""
    # Control-token gate — mirrors the variant CRUD endpoints. The
    # function is imported here (not at module top) to avoid pulling
    # miner.py at import time.
    from miner import _require_control_token
    _require_control_token(request)

    try:
        severity_f = float(severity)
    except (TypeError, ValueError):
        raise HTTPException(400, "severity must be a float")
    if not (0.0 <= severity_f <= 1.0):
        raise HTTPException(400, "severity must be between 0.0 and 1.0")

    cat_list = [c.strip() for c in categories.split(",") if c.strip()]

    case = variants.get_hitl_case_by_task_id(task_id)
    if case is None:
        raise HTTPException(404, f"No hitl_case for task_id={task_id}")
    if case["status"] == "timed_out":
        raise HTTPException(409, "Case already timed out; label rejected")
    if case["status"] == "labeled":
        raise HTTPException(409, "Case already labeled")

    # Persist the label FIRST, then signal the waiter. Order matters:
    # the /hitl_task waiter reads the DB on wake, so the row must exist
    # before the event fires.
    variants.record_hitl_label(
        case_id=case["id"],
        severity=severity_f,
        categories=cat_list,
        reasoning=reasoning,
    )

    async with _pending_lock:
        event = _pending_events.get(task_id)
        if event is not None:
            event.set()

    logger.info(
        f"HITL label submitted for task_id={task_id[:12]}... "
        f"severity={severity_f} by dashboard"
    )

    # If the form submission came from a browser, redirect back to the
    # HITL tab; otherwise return JSON. FastAPI's Form(...) dependency
    # suggests browser, so bias toward HTML redirect on Accept: text/html.
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/ui/hitl", status_code=303)
    return {"task_id": task_id, "status": "labeled"}


@router.post("/control/hitl/pause")
async def control_hitl_pause(request: Request):
    from miner import _require_control_token
    _require_control_token(request)
    variants.set_accepting_hitl_cases(False)
    logger.info("HITL role paused via dashboard")
    return {"status": "paused", "accepting_hitl_cases": False}


@router.post("/control/hitl/resume")
async def control_hitl_resume(request: Request):
    from miner import _require_control_token
    _require_control_token(request)
    variants.set_accepting_hitl_cases(True)
    logger.info("HITL role resumed via dashboard")
    return {"status": "resumed", "accepting_hitl_cases": True}
