"""safeguard-miner — FastAPI server exposing /probe to the Safeguard validator.

Drop-in protocol-compatible with safeguard/safeguard-example-miner/main.py:
- POST /probe, Epistula-authenticated, expects ProbingTask, returns ProbeResult
- Commits {"endpoint": "http://host:port"} to chain at startup so the
  Safeguard validator can discover us via get_all_commitments(netuid).

Roleplay wallet (see safeguard-miner/README.md):
  coldkey: miner
  hotkey:  default
"""

from dotenv import load_dotenv
load_dotenv()

import os
import sys
import json
import time
import hashlib
import logging
import asyncio
from collections import deque
from datetime import datetime, timezone

import html as html_mod

import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from bittensor_wallet.keypair import Keypair
from bittensor_wallet import Wallet
import bittensor as bt

from prober import (
    probe_via_relay, ATTACKER_SYSTEM_PROMPT, ATTACK_VECTORS, ATTACK_MODEL,
)
from score import JUDGE_SYSTEM_PROMPT, JUDGE_MODEL
import variants
import hitl
import concerns as concerns_mod

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | SG-MINER | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

NETWORK = os.getenv("NETWORK", "test")
NETUID = int(os.getenv("NETUID", "444"))
WALLET_NAME = os.getenv("WALLET_NAME", "miner")
HOTKEY_NAME = os.getenv("HOTKEY_NAME", "default")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8090"))
MAX_REQUEST_AGE = 60
HITL_ENABLED = os.getenv("HITL_ENABLED", "true").lower() in ("1", "true", "yes", "on")

app = FastAPI(title="safeguard-miner (miner)")

# Register the HITL role router on the same app/process/port as probe
# mining. The router is always mounted when HITL_ENABLED is true;
# operators can still pause the role from the dashboard independently
# of probe mining via variants.set_accepting_hitl_cases().
if HITL_ENABLED:
    app.include_router(hitl.router)

wallet: Wallet = None
subtensor: bt.Subtensor = None
metagraph: bt.Metagraph = None

_probes_received = 0
_started_at = time.time()
_probe_history: deque = deque(maxlen=100)
_chutes_ok: bool | None = None  # None = unknown, True/False = last call result
_relay_ok: bool | None = None


def verify_epistula(timestamp: str, signature: str, hotkey: str, body: bytes) -> str:
    request_time = int(timestamp) / 1e9
    if abs(time.time() - request_time) > MAX_REQUEST_AGE:
        raise ValueError("Request timestamp too old")
    body_hash = hashlib.sha256(body).hexdigest()
    message = f"{timestamp}.{body_hash}"
    keypair = Keypair(ss58_address=hotkey)
    if not keypair.verify(message.encode(), bytes.fromhex(signature)):
        raise ValueError("Invalid signature")
    return hotkey


async def get_body(request: Request) -> bytes:
    return await request.body()


async def verify_validator(request: Request, body: bytes = Depends(get_body)) -> str:
    """Verify caller is a registered validator on Safeguard."""
    try:
        hotkey = verify_epistula(
            timestamp=request.headers["X-Epistula-Timestamp"],
            signature=request.headers["X-Epistula-Signature"],
            hotkey=request.headers["X-Epistula-Hotkey"],
            body=body,
        )
    except KeyError as e:
        raise HTTPException(400, f"Missing header: {e}")
    except ValueError as e:
        raise HTTPException(401, str(e))

    if hotkey not in metagraph.hotkeys:
        raise HTTPException(403, "Caller not on subnet")
    uid = metagraph.hotkeys.index(hotkey)
    if not metagraph.validator_permit[uid]:
        raise HTTPException(403, "Caller not a validator")
    return hotkey


@app.post("/probe")
async def handle_probe(request: Request, validator_hotkey: str = Depends(verify_validator)):
    global _probes_received

    # Pause gate — operator can pause/resume probing from the dashboard.
    # When paused, return 503 so the validator can log the miner as
    # cooled-down rather than broken.
    if not variants.is_accepting_probes():
        logger.info(f"Rejecting probe from {validator_hotkey[:8]}... — miner paused")
        return JSONResponse(
            {"error": "miner paused", "accepting_probes": False},
            status_code=503,
        )

    _probes_received += 1
    body = await request.json()

    task_id = body.get("task_id", "unknown")
    target_validator_endpoint = body.get("target_validator_endpoint", "")
    scenario_category = body.get("scenario_category", "")
    # v2 provenance fields (RELAY_PROTOCOL_V2). When the Safeguard
    # validator sends these, we route per-turn calls through
    # /probe/relay on the validator instead of directly to the client
    # v1 /relay, and echo the response_commitment into each transcript
    # entry. If absent, fall back to v1 path unchanged.
    safeguard_relay_endpoint = body.get("safeguard_relay_endpoint", "")
    target_descriptor = body.get("target_descriptor")

    if not target_validator_endpoint and not safeguard_relay_endpoint:
        raise HTTPException(400, "Missing target_validator_endpoint")

    # Load the currently active variant. If none exists (shouldn't happen
    # post-seed) fall back to the module-level constants so probes still work.
    active_variant = variants.get_active_variant()
    variant_id = active_variant["id"] if active_variant else None
    variant_name = active_variant["name"] if active_variant else "default(fallback)"

    logger.info(
        f"Task {task_id} from validator {validator_hotkey[:8]}... "
        f"category={scenario_category}"
        + (f" [v2 relay]" if safeguard_relay_endpoint else " [v1]")
        + f" variant={variant_name}"
    )

    global _chutes_ok, _relay_ok
    try:
        result = await probe_via_relay(
            wallet=wallet,
            target_validator_endpoint=target_validator_endpoint,
            scenario_category=scenario_category,
            safeguard_relay_endpoint=safeguard_relay_endpoint,
            target_descriptor=target_descriptor,
            attacker_system_prompt=(
                active_variant["attacker_system_prompt"]
                if active_variant else ATTACKER_SYSTEM_PROMPT
            ),
            attack_vectors=(
                active_variant["attack_vectors"] if active_variant else None
            ),
            judge_system_prompt=(
                active_variant["judge_system_prompt"] if active_variant else None
            ),
            judge_model=(
                active_variant["judge_model"] if active_variant else None
            ),
        )
        # If we got a transcript with assistant replies, relay worked
        _relay_ok = True
        # If we got a nonzero score, Chutes (judge) worked
        if result.get("miner_safety_score") is not None:
            _chutes_ok = True
    except Exception as e:
        logger.error(f"Probe failed: {e}")
        _relay_ok = False
        raise

    result["task_id"] = task_id

    turns = len(result.get("transcript", [])) // 2
    safety_score = result.get("miner_safety_score", 0.0)
    concern_id_slug = result.get("concern_id_slug")

    # Record in-memory (existing behavior, feeds live dashboard)
    _probe_history.append({
        "task_id": task_id,
        "category": scenario_category,
        "safety_score": safety_score,
        "turns": turns,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "v2_relay": bool(safeguard_relay_endpoint),
        "variant_name": variant_name,
        "concern_id_slug": concern_id_slug,
    })
    # Record in SQLite (bucketed by variant, survives pod restart,
    # feeds per-variant stats page)
    try:
        variants.record_probe(
            variant_id=variant_id,
            task_id=task_id,
            category=scenario_category,
            safety_score=safety_score,
            turns=turns,
            v2_relay=bool(safeguard_relay_endpoint),
            concern_id_slug=concern_id_slug,
        )
    except Exception as e:
        logger.warning(f"Failed to record probe stat: {e}")

    logger.info(
        f"Task {task_id} done: self_score={safety_score:.2f} turns={turns}"
    )
    return result


# --- Control endpoint auth (shared-secret token) ------------------------


def _require_control_token(request: Request) -> None:
    """Gate mutation endpoints on MINER_CONTROL_TOKEN if set.
    Accepts the token via the X-Control-Token header or a `token` form field.
    If the env var is unset, allows all (private deployment assumption).
    """
    if not variants.control_token_configured():
        return
    provided = request.headers.get("X-Control-Token", "")
    if not variants.check_control_token(provided):
        raise HTTPException(401, "Invalid or missing control token")


# --- Control endpoints ---------------------------------------------------


@app.post("/control/pause")
async def control_pause(request: Request):
    _require_control_token(request)
    variants.set_accepting_probes(False)
    logger.info("Miner paused via dashboard")
    return {"status": "paused", "accepting_probes": False}


@app.post("/control/resume")
async def control_resume(request: Request):
    _require_control_token(request)
    variants.set_accepting_probes(True)
    logger.info("Miner resumed via dashboard")
    return {"status": "resumed", "accepting_probes": True}


@app.post("/control/concerns/refresh")
async def control_concerns_refresh(request: Request):
    """Drop the in-memory concerns cache. The next probe will re-fetch
    from the validator's /api/concerns. Read-only with respect to the
    validator — this is purely a local cache invalidation."""
    _require_control_token(request)
    concerns_mod.invalidate_cache()
    logger.info("Concerns cache invalidated via dashboard")
    return {"status": "ok", "cache": "invalidated"}


# --- Variant endpoints ---------------------------------------------------


@app.get("/variants")
async def list_variants_api(request: Request):
    return {
        "active_variant_id": (
            variants.get_active_variant()["id"]
            if variants.get_active_variant() else None
        ),
        "variants": variants.list_variants(),
        "stats": variants.variant_stats(),
    }


@app.get("/variants/{variant_id}")
async def get_variant_api(variant_id: int):
    v = variants.get_variant(variant_id)
    if v is None:
        raise HTTPException(404, "Variant not found")
    return v


@app.post("/variants")
async def create_variant_api(request: Request):
    _require_control_token(request)
    body = await request.json()
    try:
        new_id = variants.create_variant(
            name=body["name"],
            attacker_system_prompt=body["attacker_system_prompt"],
            judge_system_prompt=body["judge_system_prompt"],
            judge_model=body["judge_model"],
            attack_vectors=body.get("attack_vectors", []),
            notes=body.get("notes", ""),
        )
    except KeyError as e:
        raise HTTPException(400, f"Missing field: {e}")
    except sqlite_err() as e:
        raise HTTPException(400, f"DB error: {e}")
    return {"id": new_id}


@app.put("/variants/{variant_id}")
async def update_variant_api(variant_id: int, request: Request):
    _require_control_token(request)
    body = await request.json()
    ok = variants.update_variant(variant_id, **{
        k: v for k, v in body.items() if k in {
            "name", "attacker_system_prompt", "judge_system_prompt",
            "judge_model", "attack_vectors", "notes",
        }
    })
    if not ok:
        raise HTTPException(404, "Variant not found or no fields to update")
    return {"id": variant_id, "status": "updated"}


@app.post("/variants/{variant_id}/activate")
async def activate_variant_api(variant_id: int, request: Request):
    _require_control_token(request)
    ok = variants.set_active_variant(variant_id)
    if not ok:
        raise HTTPException(404, "Variant not found")
    logger.info(f"Activated variant id={variant_id}")
    return {"active_variant_id": variant_id}


@app.delete("/variants/{variant_id}")
async def delete_variant_api(variant_id: int, request: Request):
    _require_control_token(request)
    ok = variants.delete_variant(variant_id)
    if not ok:
        raise HTTPException(400, "Variant not found or is currently active")
    return {"id": variant_id, "status": "deleted"}


def sqlite_err():
    import sqlite3 as _s
    return _s.IntegrityError


def _fmt_uptime(seconds: int) -> str:
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    uptime_s = int(time.time() - _started_at)
    uptime_str = _fmt_uptime(uptime_s)
    probes_per_hour = (_probes_received / max(uptime_s, 1)) * 3600

    my_hotkey = wallet.hotkey.ss58_address if wallet else "n/a"
    hotkey_trunc = f"{my_hotkey[:8]}...{my_hotkey[-6:]}" if len(my_hotkey) > 16 else my_hotkey
    my_uid = "n/a"
    if wallet and metagraph and my_hotkey in metagraph.hotkeys:
        my_uid = metagraph.hotkeys.index(my_hotkey)

    def _health_dot(state):
        if state is True:
            return '<span style="color:#22c55e;">&#9679; OK</span>'
        elif state is False:
            return '<span style="color:#ef4444;">&#9679; FAIL</span>'
        return '<span style="color:#a3a3a3;">&#9679; unknown</span>'

    chutes_dot = _health_dot(_chutes_ok)
    relay_dot = _health_dot(_relay_ok)

    accepting = variants.is_accepting_probes()
    status_pill = (
        '<span style="color:#22c55e;font-weight:600;">&#9679; ACCEPTING</span>'
        if accepting else
        '<span style="color:#eab308;font-weight:600;">&#9679; PAUSED</span>'
    )
    accepting_hitl = variants.is_accepting_hitl_cases()
    hitl_status_pill = (
        '<span style="color:#22c55e;font-weight:600;">&#9679; ACCEPTING</span>'
        if accepting_hitl else
        '<span style="color:#eab308;font-weight:600;">&#9679; PAUSED</span>'
    )
    hitl_stats_row = variants.hitl_stats()
    active_variant = variants.get_active_variant()
    active_variant_name = (
        html_mod.escape(active_variant["name"]) if active_variant else "none"
    )

    # Concerns v2: render the cached concern catalog as a read-only
    # table on the dashboard. Detection cues are NEVER surfaced here —
    # the serializer should omit them, but we also strip them in
    # concerns._sanitize_concern(). See Workstream 4 design notes.
    concerns_snap = concerns_mod.cache_snapshot()
    concerns_catalog = concerns_snap["catalog"]
    concerns_version = concerns_snap["catalog_version"]
    concerns_served_at = concerns_snap["served_at"]
    concerns_fetched_at = concerns_snap["fetched_at"]
    concerns_fetched_str = (
        datetime.fromtimestamp(concerns_fetched_at, tz=timezone.utc).isoformat(timespec="seconds")
        if concerns_fetched_at else "—"
    )
    if concerns_catalog:
        concerns_rows = ""
        for c in concerns_catalog:
            title = html_mod.escape(str(c.get("title", "—")))
            category = html_mod.escape(str(c.get("category", "—")))
            sev_prior = c.get("severity_prior")
            sev_str = f"{float(sev_prior):.2f}" if isinstance(sev_prior, (int, float)) else "—"
            n_triggers = len(c.get("triggers") or [])
            concerns_rows += f"""<tr>
                <td>{title}</td>
                <td style="color:#a3a3a3;">{category}</td>
                <td style="color:#a3a3a3;">{sev_str}</td>
                <td style="color:#a3a3a3;">{n_triggers}</td>
            </tr>"""
        concerns_table = (
            "<table><thead><tr><th>Title</th><th>Category</th>"
            "<th>Severity prior</th><th># triggers</th></tr></thead>"
            f"<tbody>{concerns_rows}</tbody></table>"
        )
    else:
        concerns_table = (
            '<div class="empty">No concerns cached. '
            'The catalog may be empty during the v2 migration window, '
            'or the validator has not been contacted yet.</div>'
        )
    auth_required_hint = (
        '<div style="font-size:0.75em;color:#eab308;margin-top:8px;">Control token required for mutations.</div>'
        if variants.control_token_configured() else
        '<div style="font-size:0.75em;color:#737373;margin-top:8px;">No control token configured — mutations are open.</div>'
    )

    # Build recent probes table rows (newest first, show last 20)
    # _probe_history stores up to 100 but we display 20
    display_rows = ""
    for i, entry in enumerate(reversed(_probe_history)):
        if i >= 20:
            break
        tid = entry["task_id"]
        tid_trunc = f"{tid[:8]}..." if len(tid) > 10 else tid
        score = entry["safety_score"]
        if score >= 0.7:
            score_color = "#ef4444"
        elif score >= 0.4:
            score_color = "#eab308"
        else:
            score_color = "#22c55e"
        v2_badge = '<span style="color:#38bdf8;">v2</span>' if entry["v2_relay"] else '<span style="color:#a3a3a3;">v1</span>'
        variant_label = html_mod.escape(entry.get("variant_name", "—"))
        display_rows += f"""<tr>
            <td style="font-family:monospace;color:#d4d4d4;">{tid_trunc}</td>
            <td>{html_mod.escape(entry["category"])}</td>
            <td style="color:{score_color};font-weight:600;">{score:.2f}</td>
            <td>{entry["turns"]}</td>
            <td>{v2_badge}</td>
            <td style="color:#a3a3a3;">{variant_label}</td>
            <td style="color:#a3a3a3;font-size:0.85em;">{entry["timestamp"]}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Safeguard Miner Dashboard</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: #0a0a0a;
    color: #e5e5e5;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
    padding: 24px;
  }}
  h1 {{
    font-size: 1.5rem;
    color: #f5f5f5;
    margin-bottom: 20px;
    border-bottom: 1px solid #333;
    padding-bottom: 12px;
  }}
  .cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }}
  .card {{
    background: #1a1a1a;
    border: 1px solid #2a2a2a;
    border-radius: 8px;
    padding: 20px;
  }}
  .card h2 {{
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #737373;
    margin-bottom: 12px;
  }}
  .card .row {{
    display: flex;
    justify-content: space-between;
    padding: 4px 0;
    border-bottom: 1px solid #1f1f1f;
  }}
  .card .row:last-child {{ border-bottom: none; }}
  .card .label {{ color: #a3a3a3; }}
  .card .value {{ color: #f5f5f5; font-weight: 500; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: #1a1a1a;
    border: 1px solid #2a2a2a;
    border-radius: 8px;
    overflow: hidden;
  }}
  th {{
    text-align: left;
    padding: 10px 12px;
    background: #151515;
    color: #737373;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }}
  td {{
    padding: 8px 12px;
    border-top: 1px solid #1f1f1f;
    font-size: 0.9rem;
  }}
  tr:hover {{ background: #222; }}
  .empty {{ color: #525252; text-align: center; padding: 32px; }}
  .refresh {{ color: #525252; font-size: 0.8rem; margin-top: 16px; }}
  .btn {{
    display: inline-block; padding: 8px 16px; margin-right: 8px;
    background: #1a1a1a; border: 1px solid #444; border-radius: 4px;
    color: #e5e5e5; cursor: pointer; font-family: inherit; font-size: 0.9rem;
  }}
  .btn:hover {{ background: #222; }}
  .btn-primary {{ background: #1e3a5f; border-color: #3b82f6; }}
  .btn-warn {{ background: #3f2a1a; border-color: #eab308; }}
  .btn-danger {{ background: #3a1a1a; border-color: #ef4444; }}
  a {{ color: #60a5fa; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .navbar {{ margin-bottom: 16px; color: #a3a3a3; font-size: 0.85rem; }}
  input[type="text"], input[type="password"] {{
    background: #0a0a0a; border: 1px solid #333; color: #e5e5e5;
    padding: 6px 10px; border-radius: 3px; font-family: inherit;
  }}
</style>
</head>
<body>
<h1>Safeguard Miner</h1>
<div class="navbar"><a href="/">Dashboard</a> · <a href="/ui/variants">Variants</a> · <a href="/ui/hitl">HITL</a> · <a href="/health">/health</a></div>

<div class="cards">
  <div class="card">
    <h2>Status</h2>
    <div class="row"><span class="label">Wallet</span><span class="value">{WALLET_NAME}</span></div>
    <div class="row"><span class="label">Hotkey</span><span class="value" style="font-family:monospace;font-size:0.85em;">{hotkey_trunc}</span></div>
    <div class="row"><span class="label">UID</span><span class="value">{my_uid}</span></div>
    <div class="row"><span class="label">Netuid</span><span class="value">{NETUID}</span></div>
    <div class="row"><span class="label">Network</span><span class="value">{NETWORK}</span></div>
    <div class="row"><span class="label">Uptime</span><span class="value">{uptime_str}</span></div>
  </div>

  <div class="card">
    <h2>Control</h2>
    <div class="row"><span class="label">Probe gate</span><span class="value">{status_pill}</span></div>
    <div class="row"><span class="label">Active variant</span><span class="value">{active_variant_name}</span></div>
    <div style="margin-top:12px;">
      <input type="password" id="control-token" placeholder="control token (if required)" style="width:100%;box-sizing:border-box;margin-bottom:8px;" />
      <button class="btn btn-warn" onclick="postControl('/control/pause')">Pause</button>
      <button class="btn btn-primary" onclick="postControl('/control/resume')">Resume</button>
    </div>
    {auth_required_hint}
  </div>

  <div class="card">
    <h2>Probes</h2>
    <div class="row"><span class="label">Total received</span><span class="value">{_probes_received}</span></div>
    <div class="row"><span class="label">Per hour</span><span class="value">{probes_per_hour:.1f}</span></div>
  </div>

  <div class="card">
    <h2>Health</h2>
    <div class="row"><span class="label">Chutes API</span><span class="value">{chutes_dot}</span></div>
    <div class="row"><span class="label">Relay endpoint</span><span class="value">{relay_dot}</span></div>
  </div>

  <div class="card">
    <h2>HITL</h2>
    <div class="row"><span class="label">Role gate</span><span class="value">{hitl_status_pill}</span></div>
    <div class="row"><span class="label">Pending</span><span class="value">{hitl_stats_row['pending']}</span></div>
    <div class="row"><span class="label">In review</span><span class="value">{hitl_stats_row['in_review']}</span></div>
    <div class="row"><span class="label">Labeled</span><span class="value">{hitl_stats_row['labeled']}</span></div>
    <div class="row"><span class="label">Timed out</span><span class="value">{hitl_stats_row['timed_out']}</span></div>
    <div style="margin-top:12px;">
      <a href="/ui/hitl" class="btn btn-primary">Open HITL queue</a>
    </div>
  </div>
</div>

<h2 style="font-size:1rem;color:#a3a3a3;margin-bottom:12px;">Recent Probes (last 20)</h2>
{"<table><thead><tr><th>Task ID</th><th>Category</th><th>Score</th><th>Turns</th><th>Relay</th><th>Variant</th><th>Time</th></tr></thead><tbody>" + display_rows + "</tbody></table>" if display_rows else '<div class="empty">No probes recorded yet.</div>'}

<h2 style="font-size:1rem;color:#a3a3a3;margin:24px 0 12px 0;">Concern catalog (cached)</h2>
<div style="display:flex;gap:16px;align-items:center;margin-bottom:12px;color:#a3a3a3;font-size:0.85rem;">
  <span>Entries: <span style="color:#f5f5f5;">{len(concerns_catalog)}</span></span>
  <span>Catalog version: <span style="color:#f5f5f5;">{html_mod.escape(str(concerns_version) if concerns_version is not None else '—')}</span></span>
  <span>Served at: <span style="color:#f5f5f5;">{html_mod.escape(str(concerns_served_at) if concerns_served_at else '—')}</span></span>
  <span>Fetched at: <span style="color:#f5f5f5;">{concerns_fetched_str}</span></span>
  <button class="btn btn-primary" onclick="postControl('/control/concerns/refresh')">Refresh</button>
</div>
{concerns_table}

<p class="refresh">Page does not auto-refresh. Reload to update.</p>

<script>
function getToken() {{
  const el = document.getElementById('control-token');
  const token = el ? el.value : '';
  if (token) sessionStorage.setItem('miner_control_token', token);
  return token || sessionStorage.getItem('miner_control_token') || '';
}}
async function postControl(path) {{
  const token = getToken();
  const headers = {{'Content-Type': 'application/json'}};
  if (token) headers['X-Control-Token'] = token;
  const r = await fetch(path, {{method: 'POST', headers}});
  if (r.ok) {{
    location.reload();
  }} else {{
    const body = await r.text();
    alert('Failed: ' + r.status + ' ' + body);
  }}
}}
// Prefill from sessionStorage on load
window.addEventListener('DOMContentLoaded', () => {{
  const saved = sessionStorage.getItem('miner_control_token');
  const el = document.getElementById('control-token');
  if (saved && el) el.value = saved;
}});
</script>
</body>
</html>"""
    return HTMLResponse(content=html)


# --- Variants management UI ---------------------------------------------


@app.get("/ui/variants", response_class=HTMLResponse)
async def variants_dashboard():
    all_variants = variants.list_variants()
    stats = {s["id"]: s for s in variants.variant_stats()}
    active = variants.get_active_variant()
    active_id = active["id"] if active else None

    rows_html = ""
    for v in all_variants:
        s = stats.get(v["id"], {})
        is_active = v["id"] == active_id
        active_badge = (
            '<span style="color:#22c55e;font-weight:600;">&#9679; ACTIVE</span>'
            if is_active else
            f'<button class="btn" onclick="activate({v["id"]})">Activate</button>'
        )
        delete_btn = (
            '<span style="color:#525252;font-size:0.8em;">(active)</span>'
            if is_active else
            f'<button class="btn btn-danger" onclick="deleteVariant({v["id"]})">Delete</button>'
        )
        rows_html += f"""<tr>
            <td><a href="/ui/variants/{v['id']}">{html_mod.escape(v['name'])}</a></td>
            <td>{html_mod.escape(v['judge_model'])}</td>
            <td>{len(v['attack_vectors'])} vectors</td>
            <td>{s.get('probe_count', 0)}</td>
            <td>{s.get('findings_count', 0)}</td>
            <td>{s.get('avg_score') or 0:.2f}</td>
            <td style="color:#a3a3a3;font-size:0.8em;">{s.get('last_probe_at') or '—'}</td>
            <td>{active_badge}</td>
            <td>{delete_btn}</td>
        </tr>"""

    auth_hint = (
        '<div style="color:#eab308;font-size:0.85em;margin-bottom:16px;">Control token required for activate/create/edit/delete.</div>'
        if variants.control_token_configured() else
        '<div style="color:#737373;font-size:0.85em;margin-bottom:16px;">No control token configured — mutations are open.</div>'
    )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Miner Variants</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0a0a0a; color: #e5e5e5;
         font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
         padding: 24px; }}
  h1 {{ font-size: 1.5rem; color: #f5f5f5; margin-bottom: 12px;
        border-bottom: 1px solid #333; padding-bottom: 12px; }}
  .navbar {{ margin-bottom: 16px; color: #a3a3a3; font-size: 0.85rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1a1a;
           border: 1px solid #2a2a2a; border-radius: 8px; overflow: hidden; }}
  th {{ text-align: left; padding: 10px 12px; background: #151515;
        color: #737373; font-size: 0.8rem; text-transform: uppercase; }}
  td {{ padding: 10px 12px; border-top: 1px solid #1f1f1f; font-size: 0.9rem; }}
  tr:hover {{ background: #222; }}
  .btn {{ display: inline-block; padding: 6px 12px;
          background: #1a1a1a; border: 1px solid #444; border-radius: 4px;
          color: #e5e5e5; cursor: pointer; font-family: inherit; font-size: 0.85rem; }}
  .btn:hover {{ background: #222; }}
  .btn-primary {{ background: #1e3a5f; border-color: #3b82f6; }}
  .btn-danger {{ background: #3a1a1a; border-color: #ef4444; }}
  a {{ color: #60a5fa; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  input[type="password"] {{
    background: #0a0a0a; border: 1px solid #333; color: #e5e5e5;
    padding: 6px 10px; border-radius: 3px; font-family: inherit;
    width: 260px;
  }}
</style></head>
<body>
<h1>Variants</h1>
<div class="navbar"><a href="/">Dashboard</a> · <a href="/ui/variants">Variants</a></div>
<div style="margin-bottom:16px;">
  <input type="password" id="control-token" placeholder="control token (if required)" />
  <a href="/ui/variants/new" class="btn btn-primary">+ New variant</a>
</div>
{auth_hint}
<table>
  <thead><tr>
    <th>Name</th><th>Judge model</th><th>Vectors</th>
    <th>Probes</th><th>Findings</th><th>Avg score</th><th>Last probe</th>
    <th></th><th></th>
  </tr></thead>
  <tbody>{rows_html}</tbody>
</table>

<script>
function getToken() {{
  const el = document.getElementById('control-token');
  const token = el ? el.value : '';
  if (token) sessionStorage.setItem('miner_control_token', token);
  return token || sessionStorage.getItem('miner_control_token') || '';
}}
async function activate(id) {{
  const headers = {{'Content-Type': 'application/json'}};
  const token = getToken();
  if (token) headers['X-Control-Token'] = token;
  const r = await fetch('/variants/' + id + '/activate', {{method: 'POST', headers}});
  if (r.ok) location.reload();
  else alert('Failed: ' + r.status + ' ' + await r.text());
}}
async function deleteVariant(id) {{
  if (!confirm('Delete this variant?')) return;
  const headers = {{}};
  const token = getToken();
  if (token) headers['X-Control-Token'] = token;
  const r = await fetch('/variants/' + id, {{method: 'DELETE', headers}});
  if (r.ok) location.reload();
  else alert('Failed: ' + r.status + ' ' + await r.text());
}}
window.addEventListener('DOMContentLoaded', () => {{
  const saved = sessionStorage.getItem('miner_control_token');
  const el = document.getElementById('control-token');
  if (saved && el) el.value = saved;
}});
</script>
</body></html>"""
    return HTMLResponse(content=html)


@app.get("/ui/variants/new", response_class=HTMLResponse)
async def variant_new_page():
    return HTMLResponse(content=_render_variant_form(variant=None))


@app.get("/ui/variants/{variant_id}", response_class=HTMLResponse)
async def variant_edit_page(variant_id: int):
    v = variants.get_variant(variant_id)
    if v is None:
        raise HTTPException(404, "Variant not found")
    return HTMLResponse(content=_render_variant_form(variant=v))


def _render_variant_form(variant: dict | None) -> str:
    is_new = variant is None
    title = "New variant" if is_new else f"Edit: {html_mod.escape(variant['name'])}"
    name_val = "" if is_new else html_mod.escape(variant["name"])
    name_readonly = "" if is_new else 'readonly'
    attacker_val = "" if is_new else html_mod.escape(variant["attacker_system_prompt"])
    judge_val = "" if is_new else html_mod.escape(variant["judge_system_prompt"])
    judge_model_val = "deepseek-ai/DeepSeek-V3" if is_new else html_mod.escape(variant["judge_model"])
    vectors_val = (
        "[]" if is_new else
        html_mod.escape(json.dumps(variant["attack_vectors"], indent=2))
    )
    notes_val = "" if is_new else html_mod.escape(variant.get("notes", ""))
    variant_id = "" if is_new else str(variant["id"])
    submit_label = "Create" if is_new else "Save"

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0a0a0a; color: #e5e5e5;
         font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
         padding: 24px; max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 1.5rem; color: #f5f5f5; margin-bottom: 12px;
        border-bottom: 1px solid #333; padding-bottom: 12px; }}
  .navbar {{ margin-bottom: 16px; color: #a3a3a3; font-size: 0.85rem; }}
  label {{ display: block; margin-top: 16px; color: #a3a3a3;
           font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }}
  input, textarea {{
    width: 100%; background: #0a0a0a; border: 1px solid #333;
    color: #e5e5e5; padding: 10px; border-radius: 4px;
    font-family: ui-monospace, SFMono-Regular, monospace;
    font-size: 0.85rem; margin-top: 4px;
  }}
  textarea {{ resize: vertical; }}
  .btn {{ display: inline-block; padding: 10px 20px; margin-top: 16px;
          background: #1e3a5f; border: 1px solid #3b82f6; border-radius: 4px;
          color: #e5e5e5; cursor: pointer; font-family: inherit; font-size: 0.9rem; }}
  .btn:hover {{ background: #2a4a75; }}
  a {{ color: #60a5fa; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .hint {{ color: #737373; font-size: 0.8rem; margin-top: 4px; }}
  .token-row {{ margin-top: 16px; }}
</style></head>
<body>
<h1>{title}</h1>
<div class="navbar"><a href="/">Dashboard</a> · <a href="/ui/variants">Variants</a> · {title}</div>

<form id="variant-form" onsubmit="return submitForm(event)">
  <label for="v-name">Name</label>
  <input type="text" id="v-name" value="{name_val}" {name_readonly} required />

  <label for="v-judge-model">Judge model</label>
  <input type="text" id="v-judge-model" value="{judge_model_val}" required />
  <div class="hint">e.g. deepseek-ai/DeepSeek-V3, Qwen/Qwen3-32B-TEE</div>

  <label for="v-attacker">Attacker system prompt</label>
  <textarea id="v-attacker" rows="12" required>{attacker_val}</textarea>

  <label for="v-judge">Judge system prompt</label>
  <textarea id="v-judge" rows="12" required>{judge_val}</textarea>

  <label for="v-vectors">Attack vectors (JSON list of [name, instructions] pairs)</label>
  <textarea id="v-vectors" rows="14" required>{vectors_val}</textarea>

  <label for="v-notes">Notes</label>
  <textarea id="v-notes" rows="3">{notes_val}</textarea>

  <div class="token-row">
    <input type="password" id="control-token" placeholder="control token (if required)" />
  </div>
  <button type="submit" class="btn">{submit_label}</button>
</form>

<script>
const VARIANT_ID = "{variant_id}";
const IS_NEW = {str(is_new).lower()};

function getToken() {{
  const el = document.getElementById('control-token');
  const token = el ? el.value : '';
  if (token) sessionStorage.setItem('miner_control_token', token);
  return token || sessionStorage.getItem('miner_control_token') || '';
}}

async function submitForm(e) {{
  e.preventDefault();
  let vectors;
  try {{
    vectors = JSON.parse(document.getElementById('v-vectors').value);
  }} catch (err) {{
    alert('Attack vectors must be valid JSON: ' + err);
    return false;
  }}
  const body = {{
    name: document.getElementById('v-name').value,
    judge_model: document.getElementById('v-judge-model').value,
    attacker_system_prompt: document.getElementById('v-attacker').value,
    judge_system_prompt: document.getElementById('v-judge').value,
    attack_vectors: vectors,
    notes: document.getElementById('v-notes').value,
  }};
  const headers = {{'Content-Type': 'application/json'}};
  const token = getToken();
  if (token) headers['X-Control-Token'] = token;
  const url = IS_NEW ? '/variants' : '/variants/' + VARIANT_ID;
  const method = IS_NEW ? 'POST' : 'PUT';
  const r = await fetch(url, {{method, headers, body: JSON.stringify(body)}});
  if (r.ok) {{
    window.location = '/ui/variants';
  }} else {{
    alert('Failed: ' + r.status + ' ' + await r.text());
  }}
  return false;
}}
window.addEventListener('DOMContentLoaded', () => {{
  const saved = sessionStorage.getItem('miner_control_token');
  const el = document.getElementById('control-token');
  if (saved && el) el.value = saved;
}});
</script>
</body></html>"""


@app.get("/ui/hitl", response_class=HTMLResponse)
async def hitl_dashboard():
    pending = variants.get_pending_hitl_cases(limit=50)
    history = variants.recent_hitl_labels(limit=20)
    stats = variants.hitl_stats()
    accepting = variants.is_accepting_hitl_cases()
    status_pill = (
        '<span style="color:#22c55e;font-weight:600;">&#9679; ACCEPTING</span>'
        if accepting else
        '<span style="color:#eab308;font-weight:600;">&#9679; PAUSED</span>'
    )

    auth_hint = (
        '<div style="color:#eab308;font-size:0.85em;margin-bottom:16px;">Control token required for label submission and pause/resume.</div>'
        if variants.control_token_configured() else
        '<div style="color:#737373;font-size:0.85em;margin-bottom:16px;">No control token configured — submissions are open.</div>'
    )

    category_options = [
        "self-harm", "fraud", "harassment", "illegal-activity",
        "pii-generation", "unauthorized-access", "csam-grooming",
        "stalking", "animal-cruelty", "illegal-substances",
        "identity-theft", "jailbreak", "operational-safety",
    ]
    category_checkboxes = "".join(
        f'<label style="display:inline-block;margin:4px 12px 4px 0;font-size:0.85em;text-transform:none;letter-spacing:0;color:#e5e5e5;">'
        f'<input type="checkbox" name="cat" value="{html_mod.escape(c)}" style="width:auto;margin-right:4px;" />{html_mod.escape(c)}</label>'
        for c in category_options
    )

    # Pending cases table with expandable transcript previews
    if pending:
        pending_rows = ""
        for case in pending:
            tid = case["task_id"]
            tid_trunc = f"{tid[:12]}..." if len(tid) > 14 else tid
            claim = case.get("miner_claim") or {}
            cat = claim.get("category", "—") if isinstance(claim, dict) else "—"
            received = case.get("received_at", "—")
            transcript = case.get("transcript") or []
            preview_lines = []
            for turn in transcript[:6]:
                if not isinstance(turn, dict):
                    continue
                role = str(turn.get("role", "?")).upper()
                content = str(turn.get("content", ""))[:600]
                preview_lines.append(
                    f'<div style="margin:4px 0;"><span style="color:#737373;font-size:0.75em;">[{html_mod.escape(role)}]</span> '
                    f'<span style="white-space:pre-wrap;">{html_mod.escape(content)}</span></div>'
                )
            preview_html = "".join(preview_lines) or '<div style="color:#737373;">(empty transcript)</div>'

            pending_rows += f"""<tr>
                <td style="font-family:monospace;color:#d4d4d4;vertical-align:top;">{html_mod.escape(tid_trunc)}</td>
                <td style="vertical-align:top;">{html_mod.escape(str(cat))}</td>
                <td style="color:#a3a3a3;font-size:0.85em;vertical-align:top;">{html_mod.escape(str(received))}</td>
                <td style="vertical-align:top;">
                  <details>
                    <summary style="cursor:pointer;color:#60a5fa;">view transcript</summary>
                    <div style="margin-top:8px;padding:8px;background:#0a0a0a;border:1px solid #2a2a2a;border-radius:4px;max-height:300px;overflow:auto;">{preview_html}</div>
                  </details>
                  <button class="btn" style="margin-top:8px;" onclick="loadIntoForm('{html_mod.escape(tid)}')">Label this case</button>
                </td>
            </tr>"""
        pending_table = f"""<table>
          <thead><tr>
            <th>Task ID</th><th>Category</th><th>Received</th><th>Action</th>
          </tr></thead>
          <tbody>{pending_rows}</tbody>
        </table>"""
    else:
        pending_table = '<div class="empty">No pending HITL cases.</div>'

    # Label history table
    if history:
        history_rows = ""
        for lbl in history:
            tid = lbl.get("task_id", "")
            tid_trunc = f"{tid[:12]}..." if len(tid) > 14 else tid
            sev = lbl.get("severity", 0.0)
            if sev >= 0.7:
                sev_color = "#ef4444"
            elif sev >= 0.4:
                sev_color = "#eab308"
            else:
                sev_color = "#22c55e"
            cats = lbl.get("categories") or []
            cats_str = ", ".join(cats) if cats else "—"
            reasoning = (lbl.get("reasoning") or "")[:120]
            submitted = lbl.get("submitted_at", "—")
            history_rows += f"""<tr>
                <td style="font-family:monospace;color:#d4d4d4;">{html_mod.escape(tid_trunc)}</td>
                <td style="color:{sev_color};font-weight:600;">{float(sev):.2f}</td>
                <td>{html_mod.escape(cats_str)}</td>
                <td style="color:#a3a3a3;font-size:0.85em;">{html_mod.escape(reasoning)}</td>
                <td style="color:#a3a3a3;font-size:0.85em;">{html_mod.escape(str(submitted))}</td>
            </tr>"""
        history_table = f"""<table>
          <thead><tr>
            <th>Task ID</th><th>Severity</th><th>Categories</th><th>Reasoning</th><th>Submitted</th>
          </tr></thead>
          <tbody>{history_rows}</tbody>
        </table>"""
    else:
        history_table = '<div class="empty">No labels submitted yet.</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Safeguard Miner — HITL Queue</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0a0a0a; color: #e5e5e5;
         font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
         padding: 24px; }}
  h1 {{ font-size: 1.5rem; color: #f5f5f5; margin-bottom: 12px;
        border-bottom: 1px solid #333; padding-bottom: 12px; }}
  h2 {{ font-size: 1rem; color: #a3a3a3; margin: 24px 0 12px 0; }}
  .navbar {{ margin-bottom: 16px; color: #a3a3a3; font-size: 0.85rem; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px; margin-bottom: 24px; }}
  .card {{ background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 8px; padding: 16px; }}
  .card h3 {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;
              color: #737373; margin-bottom: 10px; }}
  .card .row {{ display: flex; justify-content: space-between; padding: 3px 0;
                border-bottom: 1px solid #1f1f1f; font-size: 0.85rem; }}
  .card .row:last-child {{ border-bottom: none; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1a1a;
           border: 1px solid #2a2a2a; border-radius: 8px; overflow: hidden; }}
  th {{ text-align: left; padding: 10px 12px; background: #151515;
        color: #737373; font-size: 0.8rem; text-transform: uppercase; }}
  td {{ padding: 10px 12px; border-top: 1px solid #1f1f1f; font-size: 0.9rem; }}
  tr:hover {{ background: #222; }}
  .empty {{ color: #525252; text-align: center; padding: 32px;
            background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 8px; }}
  .btn {{ display: inline-block; padding: 6px 12px; background: #1a1a1a;
          border: 1px solid #444; border-radius: 4px; color: #e5e5e5;
          cursor: pointer; font-family: inherit; font-size: 0.85rem; }}
  .btn:hover {{ background: #222; }}
  .btn-primary {{ background: #1e3a5f; border-color: #3b82f6; }}
  .btn-warn {{ background: #3f2a1a; border-color: #eab308; }}
  a {{ color: #60a5fa; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  form.label-form {{ background: #1a1a1a; border: 1px solid #2a2a2a;
                     border-radius: 8px; padding: 16px; margin-bottom: 24px; }}
  form.label-form label {{ display: block; margin-top: 12px; color: #a3a3a3;
                           font-size: 0.8rem; text-transform: uppercase;
                           letter-spacing: 0.04em; }}
  form.label-form input[type="text"],
  form.label-form textarea,
  form.label-form input[type="password"] {{
    width: 100%; background: #0a0a0a; border: 1px solid #333; color: #e5e5e5;
    padding: 8px 10px; border-radius: 4px; font-family: inherit; font-size: 0.85rem;
    margin-top: 4px;
  }}
  form.label-form input[type="range"] {{ width: 100%; margin-top: 8px; }}
  form.label-form button[type="submit"] {{
    margin-top: 16px; padding: 10px 20px; background: #1e3a5f;
    border: 1px solid #3b82f6; border-radius: 4px; color: #e5e5e5;
    cursor: pointer; font-family: inherit; font-size: 0.9rem;
  }}
  .sev-display {{ display: inline-block; margin-left: 8px; color: #f5f5f5;
                  font-weight: 600; font-family: ui-monospace, monospace; }}
</style>
</head>
<body>
<h1>HITL Queue</h1>
<div class="navbar"><a href="/">Dashboard</a> · <a href="/ui/variants">Variants</a> · <a href="/ui/hitl">HITL</a></div>

<div class="cards">
  <div class="card">
    <h3>Role status</h3>
    <div class="row"><span>Gate</span><span>{status_pill}</span></div>
    <div style="margin-top:12px;">
      <input type="password" id="control-token" placeholder="control token" style="width:100%;background:#0a0a0a;border:1px solid #333;color:#e5e5e5;padding:6px 8px;border-radius:3px;font-family:inherit;margin-bottom:8px;" />
      <button class="btn btn-warn" onclick="postControl('/control/hitl/pause')">Pause HITL</button>
      <button class="btn btn-primary" onclick="postControl('/control/hitl/resume')">Resume HITL</button>
    </div>
  </div>
  <div class="card">
    <h3>Counters</h3>
    <div class="row"><span>Pending</span><span>{stats['pending']}</span></div>
    <div class="row"><span>In review</span><span>{stats['in_review']}</span></div>
    <div class="row"><span>Labeled</span><span>{stats['labeled']}</span></div>
    <div class="row"><span>Timed out</span><span>{stats['timed_out']}</span></div>
    <div class="row"><span>Total</span><span>{stats['total']}</span></div>
  </div>
</div>

{auth_hint}

<h2>Label form</h2>
<form class="label-form" id="label-form" method="post" action="/hitl/submit-label">
  <label for="f-task-id">Task ID</label>
  <input type="text" id="f-task-id" name="task_id" required placeholder="paste task_id from pending table" />

  <label for="f-severity">Severity (0.0 safe — 1.0 critical) <span class="sev-display" id="sev-display">0.00</span></label>
  <input type="range" id="f-severity" name="severity" min="0" max="1" step="0.05" value="0" oninput="document.getElementById('sev-display').textContent=parseFloat(this.value).toFixed(2)" />

  <label>Categories</label>
  <div>{category_checkboxes}</div>
  <input type="hidden" id="f-categories" name="categories" value="" />

  <label for="f-reasoning">Reasoning</label>
  <textarea id="f-reasoning" name="reasoning" rows="4" placeholder="one-line explanation of why this severity"></textarea>

  <button type="submit">Submit label</button>
</form>

<h2>Pending cases ({len(pending)})</h2>
{pending_table}

<h2>Label history (last 20)</h2>
{history_table}

<script>
function getToken() {{
  const el = document.getElementById('control-token');
  const token = el ? el.value : '';
  if (token) sessionStorage.setItem('miner_control_token', token);
  return token || sessionStorage.getItem('miner_control_token') || '';
}}
function loadIntoForm(taskId) {{
  const el = document.getElementById('f-task-id');
  if (el) el.value = taskId;
  el.scrollIntoView({{behavior: 'smooth', block: 'center'}});
  el.focus();
}}
async function postControl(path) {{
  const token = getToken();
  const headers = {{'Content-Type': 'application/json'}};
  if (token) headers['X-Control-Token'] = token;
  const r = await fetch(path, {{method: 'POST', headers}});
  if (r.ok) {{ location.reload(); }}
  else {{ alert('Failed: ' + r.status + ' ' + await r.text()); }}
}}
// Submit the label form via fetch so we can attach the control token header
document.getElementById('label-form').addEventListener('submit', async (e) => {{
  e.preventDefault();
  const form = e.target;
  const cats = Array.from(form.querySelectorAll('input[name="cat"]:checked')).map(c => c.value).join(',');
  document.getElementById('f-categories').value = cats;
  const body = new URLSearchParams();
  body.set('task_id', form.task_id.value);
  body.set('severity', form.severity.value);
  body.set('categories', cats);
  body.set('reasoning', form.reasoning.value);
  const headers = {{'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}};
  const token = getToken();
  if (token) headers['X-Control-Token'] = token;
  const r = await fetch('/hitl/submit-label', {{method: 'POST', headers, body: body.toString()}});
  if (r.ok) {{
    alert('Label submitted for ' + form.task_id.value);
    location.reload();
  }} else {{
    alert('Failed: ' + r.status + ' ' + await r.text());
  }}
}});
window.addEventListener('DOMContentLoaded', () => {{
  const saved = sessionStorage.getItem('miner_control_token');
  const el = document.getElementById('control-token');
  if (saved && el) el.value = saved;
}});
</script>
</body>
</html>"""
    return HTMLResponse(content=html)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "wallet": WALLET_NAME,
        "hotkey_name": HOTKEY_NAME,
        "netuid": NETUID,
        "network": NETWORK,
        "uptime_seconds": int(time.time() - _started_at),
        "probes_received": _probes_received,
    }


@app.on_event("startup")
async def startup():
    global wallet, subtensor, metagraph

    # Initialize the variant DB and seed a default variant from the
    # current module-level constants if the DB is fresh. The default
    # variant is just "the behavior the miner had before variants
    # existed" — operators can create experimental variants alongside
    # it and A/B test.
    variants.init_db(default_variant={
        "name": "baseline",
        "attacker_system_prompt": ATTACKER_SYSTEM_PROMPT,
        "judge_system_prompt": JUDGE_SYSTEM_PROMPT,
        "judge_model": JUDGE_MODEL,
        # Convert the tuple list to a list-of-lists so it round-trips
        # through JSON cleanly.
        "attack_vectors": [list(v) for v in ATTACK_VECTORS],
        "notes": "Seeded from module constants on first run.",
    })
    logger.info(f"Variant DB ready at {variants.DB_PATH}")

    wallet = Wallet(name=WALLET_NAME, hotkey=HOTKEY_NAME)
    subtensor = bt.Subtensor(network=NETWORK)
    metagraph = bt.Metagraph(netuid=NETUID, network=NETWORK)
    metagraph.sync(subtensor=subtensor)

    my_hotkey = wallet.hotkey.ss58_address
    if my_hotkey not in metagraph.hotkeys:
        logger.error(
            f"Hotkey {my_hotkey} ({WALLET_NAME}/{HOTKEY_NAME}) not registered "
            f"on netuid {NETUID}. Run: btcli subnets register --netuid {NETUID} "
            f"--wallet.name {WALLET_NAME} --wallet.hotkey {HOTKEY_NAME} --network {NETWORK}"
        )
        sys.exit(1)

    my_uid = metagraph.hotkeys.index(my_hotkey)
    logger.info(f"safeguard-miner UID={my_uid} hotkey={my_hotkey} on netuid {NETUID} ({NETWORK})")

    # Wire the metagraph accessor for the HITL router so it can
    # validator-permit-check incoming /hitl_task callers against the
    # same metagraph instance we sync here.
    if HITL_ENABLED:
        hitl.set_metagraph_accessor(lambda: metagraph)

    external_endpoint = os.getenv("MINER_EXTERNAL_ENDPOINT", "")
    if not external_endpoint:
        commit_host = "127.0.0.1" if HOST == "0.0.0.0" else HOST
        external_endpoint = f"http://{commit_host}:{PORT}"

    # Chain-commitment schema choice (coordination point with
    # validator-side agent A2):
    #
    # The legacy safeguard/safeguard-hitl-miner/main.py used a single-
    # role commitment {"type": "hitl", "endpoint": "..."}. The original
    # safeguard-miner commitment was {"endpoint": "..."} with no type
    # field (probe was the only role). A hotkey can only hold one
    # commitment at a time, so we cannot ship both shapes in parallel.
    #
    # We use an extensible single-entry form:
    #     {"types": [...], "endpoint": "..."}
    # This advertises every role the process runs today. A validator
    # that only reads the legacy `type` field will not see this as a
    # hitl miner — A2 must update validator-side discovery to read the
    # `types` list (or fall back to legacy `type` if present) so a
    # single wallet can advertise probe + hitl at once.
    role_types = ["probe"]
    if HITL_ENABLED:
        role_types.append("hitl")
    endpoint_data = json.dumps({
        "types": role_types,
        "endpoint": external_endpoint,
    })
    try:
        subtensor.set_commitment(wallet=wallet, netuid=NETUID, data=endpoint_data)
        logger.info(f"Committed endpoint to chain: {endpoint_data}")
    except Exception as e:
        logger.warning(f"set_commitment failed (may already be committed): {e}")


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)
