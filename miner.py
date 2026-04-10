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

import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends
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

    result = await probe_via_relay(
        wallet=wallet,
        target_validator_endpoint=target_validator_endpoint,
        scenario_category=scenario_category,
        safeguard_relay_endpoint=safeguard_relay_endpoint,
        target_descriptor=target_descriptor,
    )
    result["task_id"] = task_id

    logger.info(
        f"Task {task_id} done: self_score={result.get('miner_safety_score', 0.0):.2f} "
        f"turns={len(result.get('transcript', []))//2}"
    )
    return result


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
