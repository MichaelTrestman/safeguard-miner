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

app = FastAPI(title="safeguard-miner (miner)")

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

    # Record in-memory (existing behavior, feeds live dashboard)
    _probe_history.append({
        "task_id": task_id,
        "category": scenario_category,
        "safety_score": safety_score,
        "turns": turns,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "v2_relay": bool(safeguard_relay_endpoint),
        "variant_name": variant_name,
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
    active_variant = variants.get_active_variant()
    active_variant_name = (
        html_mod.escape(active_variant["name"]) if active_variant else "none"
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
<div class="navbar"><a href="/">Dashboard</a> · <a href="/ui/variants">Variants</a> · <a href="/health">/health</a></div>

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
</div>

<h2 style="font-size:1rem;color:#a3a3a3;margin-bottom:12px;">Recent Probes (last 20)</h2>
{"<table><thead><tr><th>Task ID</th><th>Category</th><th>Score</th><th>Turns</th><th>Relay</th><th>Variant</th><th>Time</th></tr></thead><tbody>" + display_rows + "</tbody></table>" if display_rows else '<div class="empty">No probes recorded yet.</div>'}

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

    external_endpoint = os.getenv("MINER_EXTERNAL_ENDPOINT", "")
    if not external_endpoint:
        commit_host = "127.0.0.1" if HOST == "0.0.0.0" else HOST
        external_endpoint = f"http://{commit_host}:{PORT}"
    endpoint_data = json.dumps({"endpoint": external_endpoint})
    try:
        subtensor.set_commitment(wallet=wallet, netuid=NETUID, data=endpoint_data)
        logger.info(f"Committed endpoint to chain: {endpoint_data}")
    except Exception as e:
        logger.warning(f"set_commitment failed (may already be committed): {e}")


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)
