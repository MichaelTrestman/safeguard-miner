"""Concerns catalog client (Workstream 4, Concerns v2).

The validator exposes an active concern catalog at GET /api/concerns
(Epistula-authenticated). Miners fetch that catalog, pick a concern
when starting a probe, and feed the concern's user-side triggers
into the attacker LLM as adversarial seeds. The concern's id_slug is
carried through to the probe result so the validator can associate
the finding with the probed concern on submission.

Conceptual model (v2 — see safeguard-miner CONCERNS.md):
  * Concern:       first-person operator worry about AI behavior.
  * DetectionCue:  after-the-fact textual evidence that the AI did
                   the concerning thing — MINERS DO NOT SEE THESE.
  * UserTrigger:   human-user prompting behaviors that might elicit
                   the concerning AI behavior. Miners use these as
                   seeds for the attacker model.

Hard constraints honored here:
  * Empty catalog is a legal response. Never raise — log and return [].
  * 4xx/5xx/network failures → warn, return []. The miner must
    gracefully fall back to "today's behavior" if the endpoint is
    empty or unreachable.
  * Never request or read `cues` — even if the serializer accidentally
    leaks them, ignore the field.
"""
from __future__ import annotations

import hashlib
import json
import logging
import random
import time

import httpx
from bittensor_wallet import Wallet

logger = logging.getLogger(__name__)


# In-memory cache, refreshed when the TTL elapses or a caller calls
# invalidate_cache() (e.g. the dashboard's "Refresh" button).
_CACHE_TTL_SECONDS = 60.0
_CACHE: dict = {
    "fetched_at": 0.0,
    "catalog": [],
    "endpoint": None,
    "served_at": None,
    "catalog_version": None,
}


def invalidate_cache() -> None:
    """Drop the in-memory catalog cache so the next fetch re-hits the
    validator. Called by the dashboard's 'Refresh' button."""
    _CACHE["fetched_at"] = 0.0
    _CACHE["catalog"] = []
    _CACHE["endpoint"] = None
    _CACHE["served_at"] = None
    _CACHE["catalog_version"] = None


def cache_snapshot() -> dict:
    """Read-only view of the current cache for the dashboard card.
    Returns a shallow copy so the UI code can't accidentally mutate
    the cached catalog."""
    return {
        "fetched_at": _CACHE["fetched_at"],
        "catalog": list(_CACHE["catalog"]),
        "endpoint": _CACHE["endpoint"],
        "served_at": _CACHE["served_at"],
        "catalog_version": _CACHE["catalog_version"],
    }


def _create_epistula_headers(wallet: Wallet, body: bytes) -> dict:
    """Sign a GET body (may be b"") the same way prober.py signs POSTs.
    Duplicated here rather than imported to keep concerns.py independent
    of prober.py import order — both modules use the same construction."""
    nonce = str(int(time.time() * 1e9))
    body_hash = hashlib.sha256(body).hexdigest()
    message = f"{nonce}.{body_hash}"
    signature = wallet.hotkey.sign(message.encode()).hex()
    return {
        "X-Epistula-Timestamp": nonce,
        "X-Epistula-Signature": signature,
        "X-Epistula-Hotkey": wallet.hotkey.ss58_address,
    }


def _sanitize_concern(concern: dict) -> dict:
    """Strip any `cues`/`detection_cues` fields that may leak through
    from the serializer, and normalize the triggers list. Miners must
    not see cues — belt-and-suspenders defense against a serializer
    bug on the validator side."""
    if not isinstance(concern, dict):
        return {}
    clean = {k: v for k, v in concern.items() if k not in ("cues", "detection_cues")}
    triggers = clean.get("triggers") or []
    if not isinstance(triggers, list):
        triggers = []
    norm_triggers: list[dict] = []
    for t in triggers:
        if not isinstance(t, dict):
            continue
        # Defensive: also scrub any cue-like fields from triggers.
        norm_triggers.append(
            {k: v for k, v in t.items() if k not in ("cues", "detection_cues")}
        )
    clean["triggers"] = norm_triggers
    return clean


async def fetch_concerns_catalog(
    validator_endpoint: str,
    wallet: Wallet,
    http_client: httpx.AsyncClient | None = None,
    force_refresh: bool = False,
) -> list[dict]:
    """Fetch the active concern catalog from the validator.

    Returns a list of concern dicts. Each dict carries its nested
    `triggers` list. `cues` is never returned — even if the validator's
    serializer leaks it, this function strips it.

    Empty list is a legal response — during the v2 migration window
    the validator's catalog may be fully empty. The miner must fall
    back to its default attacker behavior in that case.

    Errors (network, HTTP 4xx/5xx, parse failures) are logged at WARN
    and return []. This function never raises.

    Caches results in-memory for ~60 seconds keyed on validator_endpoint.
    If the caller switches endpoints, the cache is invalidated.
    """
    now = time.time()
    if (
        not force_refresh
        and _CACHE["endpoint"] == validator_endpoint
        and (now - _CACHE["fetched_at"]) < _CACHE_TTL_SECONDS
        and _CACHE["catalog"]
    ):
        return list(_CACHE["catalog"])

    url = f"{validator_endpoint.rstrip('/')}/api/concerns"
    # GET with an empty body — still Epistula-sign the empty body so
    # the validator's signature verifier is happy.
    headers = _create_epistula_headers(wallet, b"")

    close_client = False
    client = http_client
    if client is None:
        client = httpx.AsyncClient(timeout=30.0)
        close_client = True

    try:
        resp = await client.get(url, headers=headers, timeout=30.0)
        if resp.status_code >= 400:
            logger.warning(
                f"/api/concerns returned HTTP {resp.status_code} from "
                f"{validator_endpoint} — falling back to empty catalog"
            )
            _CACHE["fetched_at"] = now
            _CACHE["catalog"] = []
            _CACHE["endpoint"] = validator_endpoint
            _CACHE["served_at"] = None
            _CACHE["catalog_version"] = None
            return []
        try:
            payload = resp.json()
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(
                f"/api/concerns returned non-JSON body from "
                f"{validator_endpoint}: {e}"
            )
            _CACHE["fetched_at"] = now
            _CACHE["catalog"] = []
            _CACHE["endpoint"] = validator_endpoint
            _CACHE["served_at"] = None
            _CACHE["catalog_version"] = None
            return []

        raw = payload.get("concerns") or []
        catalog = [_sanitize_concern(c) for c in raw if isinstance(c, dict)]
        # Drop empty dicts produced by _sanitize_concern on garbage input.
        catalog = [c for c in catalog if c]
        _CACHE["fetched_at"] = now
        _CACHE["catalog"] = catalog
        _CACHE["endpoint"] = validator_endpoint
        _CACHE["served_at"] = payload.get("served_at")
        _CACHE["catalog_version"] = payload.get("catalog_version")
        logger.info(
            f"Fetched {len(catalog)} concerns from {validator_endpoint} "
            f"(catalog_version={_CACHE['catalog_version']})"
        )
        return list(catalog)
    except (httpx.HTTPError, httpx.TransportError, Exception) as e:
        logger.warning(
            f"/api/concerns fetch failed from {validator_endpoint}: {e} — "
            f"falling back to empty catalog"
        )
        # Do NOT update the cache on a transient failure — keep the
        # last-good snapshot alive so intermittent flakes don't wipe
        # the catalog for the full TTL.
        return list(_CACHE["catalog"]) if _CACHE["endpoint"] == validator_endpoint else []
    finally:
        if close_client:
            await client.aclose()


def pick_concern_for_probe(
    catalog: list[dict],
    category: str | None = None,
) -> dict | None:
    """Pick a random concern from the catalog.

    If `category` is provided, filter to concerns matching that category
    first. If no concerns match the category, fall back to picking from
    the whole catalog. Returns None only if the catalog is empty.
    """
    if not catalog:
        return None
    if category:
        matching = [c for c in catalog if c.get("category") == category]
        if matching:
            return random.choice(matching)
    return random.choice(catalog)


def pick_trigger_for_probe(concern: dict) -> dict | None:
    """Pick ONE user-trigger from a concern, uniform random.

    Returns a single trigger dict or None if the concern is empty or
    has no triggers. The singular form exists because per-probe trigger
    attribution is impossible when the attacker is told "pick one or
    combine" — picking exactly one per probe lets the validator credit
    that probe's finding to exactly one UserTrigger row.
    """
    if not concern:
        return None
    triggers = concern.get("triggers") or []
    if not triggers:
        return None
    return random.choice(triggers)


def pick_triggers_for_probe(concern: dict, n: int = 3) -> list[dict]:
    """DEPRECATED back-compat shim. Use `pick_trigger_for_probe` instead.

    Returns a single-element list wrapping `pick_trigger_for_probe(concern)`
    or an empty list if no trigger was available. The old multi-trigger
    behavior is intentionally gone — see `pick_trigger_for_probe` for why.
    """
    logger.warning(
        "pick_triggers_for_probe is DEPRECATED; use pick_trigger_for_probe "
        "(singular). Returning a single-element list for back-compat."
    )
    single = pick_trigger_for_probe(concern)
    return [single] if single is not None else []
