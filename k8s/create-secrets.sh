#!/bin/bash
set -euo pipefail

# Create k8s secrets for the safeguard-miner deployment.
# Run once before deploying.

WALLETS_DIR="${HOME}/.bittensor/wallets"

echo "=== Creating namespace ==="
kubectl apply -f k8s/namespace.yaml

echo "=== Creating miner secrets ==="
kubectl create secret generic miner-secrets \
  --namespace=safeguard-miner \
  --from-literal=chutes-api-key="$(grep CHUTES_API_KEY .env | cut -d= -f2 | tr -d '\"')" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "=== Creating wallet secret ==="
kubectl create secret generic wallet-miner2 \
  --namespace=safeguard-miner \
  --from-file=hotkey="${WALLETS_DIR}/miner2/hotkeys/default" \
  --from-file=coldkeypub.txt="${WALLETS_DIR}/miner2/coldkeypub.txt" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "=== Done ==="
kubectl get secrets -n safeguard-miner
