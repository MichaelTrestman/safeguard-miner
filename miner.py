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

import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse
from bittensor_wallet.keypair import Keypair
from bittensor_wallet import Wallet
import bittensor as bt

from prober import probe_via_relay

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

    logger.info(
        f"Task {task_id} from validator {validator_hotkey[:8]}... "
        f"category={scenario_category}"
        + (f" [v2 relay]" if safeguard_relay_endpoint else " [v1]")
    )

    global _chutes_ok, _relay_ok
    try:
        result = await probe_via_relay(
            wallet=wallet,
            target_validator_endpoint=target_validator_endpoint,
            scenario_category=scenario_category,
            safeguard_relay_endpoint=safeguard_relay_endpoint,
            target_descriptor=target_descriptor,
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
    _probe_history.append({
        "task_id": task_id,
        "category": scenario_category,
        "safety_score": result.get("miner_safety_score", 0.0),
        "turns": turns,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "v2_relay": bool(safeguard_relay_endpoint),
    })

    logger.info(
        f"Task {task_id} done: self_score={result.get('miner_safety_score', 0.0):.2f} "
        f"turns={turns}"
    )
    return result


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
        display_rows += f"""<tr>
            <td style="font-family:monospace;color:#d4d4d4;">{tid_trunc}</td>
            <td>{entry["category"]}</td>
            <td style="color:{score_color};font-weight:600;">{score:.2f}</td>
            <td>{entry["turns"]}</td>
            <td>{v2_badge}</td>
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
</style>
</head>
<body>
<h1>Safeguard Miner</h1>

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
{"<table><thead><tr><th>Task ID</th><th>Category</th><th>Score</th><th>Turns</th><th>Relay</th><th>Time</th></tr></thead><tbody>" + display_rows + "</tbody></table>" if display_rows else '<div class="empty">No probes recorded yet.</div>'}

<p class="refresh">Page does not auto-refresh. Reload to update.</p>
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
