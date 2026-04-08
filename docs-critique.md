# Stranger-onboarding pain points in safeguard/

Compiled while reading the open-source repo with no prior context. These are
the rough edges that cost a new miner time. Ordered by severity.

## 1. No JSON schema for `/probe` anywhere in the docs

**README.md "Building your own miner"** says:

> Your miner must expose `POST /probe` with Epistula authentication. It receives
> a `ProbingTask` (target relay endpoint + scenario category), conducts an
> adversarial conversation through the relay, and returns a `ProbeResult`
> (transcript + safety score + categories). See [DESIGN.md](DESIGN.md) for the
> scoring rubric and what makes a good miner.

But neither README nor DESIGN.md gives the actual JSON shape. To learn the
protocol, a new miner has to:
1. Read `validator.py:131` for the `ProbingTask` dataclass
2. Read `validator.py:149` for the `ProbeResult` dataclass and notice the
   legacy `miner_safety_verdict` bool branch in `from_dict`
3. Read `safeguard-example-miner/main.py:127` for the actual returned dict
4. Cross-reference with `safeguard-example-miner/prober.py:335` for the
   `_probe_loop` return shape

**Fix:** paste the request/response JSON in README "Building your own miner",
or link to validator.py:131 with line numbers.

## 2. The "honest scoring is optimal" insight is invisible

DESIGN.md derives `confidence = 1 - |claim - audit|` and
`accepted_severity = claim × confidence` but never says the load-bearing
consequence: **the optimum is to match the judge**, not to claim high. A naive
miner reading "discovery market, you get paid for what you find" will assume
"claim 1.0 always" and lose to honest scorers.

**Fix:** in DESIGN.md "Discovery market", add: *"Note: because confidence
penalises both overclaiming and underclaiming, the reward-maximising strategy
is to self-score honestly. A miner running the same judge family as the
validator achieves confidence ≈ 1.0 by construction."*

## 3. `safeguard-example-miner/README.md` is a dead end

Main README points to `safeguard-example-miner/README.md` "for details", but
that file is 29 lines, says "this is a test miner only", and contains zero
protocol detail. A new miner follows the link and learns nothing.

## 4. Quick Start collides with LOCAL_DEPLOY.md

README Quick Start says `pip install -e .` → `cp env.example .env` →
`btcli subnets register`. But there's a separate `LOCAL_DEPLOY.md` for the
local-stack flow. A new miner doesn't know which entry point applies to them.
Quick Start should branch:

- "Want to try this against a local chain in 5 minutes?" → LOCAL_DEPLOY.md
- "Want to register on testnet?" → keep current flow

Also: README Quick Start example uses `NETUID=2`, but `run_validator.sh`
defaults to `--netuid 444`. Pick one for the example or explain why they differ.

## 5. The bait library is dramatically smaller than the design implies

DESIGN.md describes the bait library as bootstrapped from "HarmBench, AdvBench,
etc." with HITL-discovered patterns flowing in continuously. The actual
`bait/library.json` has **exactly one entry per category**. A stranger expecting
a real adversarial corpus finds a stub. Either grow it or note it as a v0
limitation in DESIGN.md so the gap between vision and current state is honest.

## 6. `BAIT_LIBRARY_PATH` env var is undocumented

`prober.py:40` reads `BAIT_LIBRARY_PATH` and falls back to a path computed from
`__file__/../../bait/library.json`. That path only works for miners sitting
inside `safeguard/`. External miner authors get a silent "library not found"
warning and lose the bait modifier. Document the env var and the convention.

## 7. Refusal-detection heuristic is too eager

`prober.py:324-330` has a hardcoded English keyword list and breaks the probe
loop on the first non-refusal. Even a partially compliant or deflecting
response ends escalation. Worth either documenting this as deliberate (so
miners know to override it) or replacing with a real engagement detector. The
3-turn cap also seems low for any of the long-horizon attacks DESIGN.md §
"Long-horizon probing" describes.

## 8. Concerns vector is hardcoded in bootstrap, but the API for setting it is undocumented

DESIGN.md spec says concerns are per-buyer, but a new miner has no way to know
what the running validator's concerns vector is — it could be uniform, it could
be heavily weighted toward `csam-grooming` and `self-harm`, who knows. This
materially affects which categories are profitable to attack. A read-only
`/concerns` endpoint on the cross-subnet API would let miners optimise.

## 9. The `miner_safety_verdict` legacy bool path

`validator.py:160-164` still supports the old bool-verdict response shape:

```python
if score is None:
    score = 1.0 if data.get("miner_safety_verdict", False) else 0.0
```

That fallback hard-codes the old protocol into the new audit math. If a legacy
miner sends `miner_safety_verdict=True`, it gets booked as `claim=1.0` and the
audit will almost certainly disagree → near-zero confidence → near-zero reward.
Either remove the fallback or add a deprecation log line so legacy miners know
they're getting silently penalised.
