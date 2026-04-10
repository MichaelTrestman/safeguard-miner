# safeguard-miner — GKE Deployment

Independent deployment. Not part of the validator stack.

## Setup

```bash
cd safeguard-miner/
bash k8s/create-secrets.sh   # first time
bash k8s/deploy.sh           # build, push, deploy
```

The deploy script prints the LoadBalancer external IP. Update
`MINER_EXTERNAL_ENDPOINT` in `k8s/deployment.yaml` with `http://<IP>:8090`,
then reapply + restart so the miner commits the correct public endpoint
to chain.

## Logs

```bash
kubectl logs -f deploy/safeguard-miner -n safeguard-miner
```

## How it connects

The miner commits its public endpoint to chain at startup. Validators
anywhere discover it via `get_all_commitments(netuid)` and POST probes
to it. No direct network link to the validator cluster needed.
