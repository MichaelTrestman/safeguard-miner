#!/bin/bash
set -euo pipefail

# Deploy safeguard-miner to GKE.
# Separate from the validator — this is an independent project.

REGISTRY="us-central1-docker.pkg.dev/safeguard-testnet/safeguard"
REGION="us-central1"
PROJECT="safeguard-testnet"

echo "=== Building and pushing image ==="
gcloud auth configure-docker ${REGION}-docker.pkg.dev --quiet
docker buildx build --platform linux/amd64 -t ${REGISTRY}/safeguard-miner:latest --push .

echo "=== Getting cluster credentials ==="
gcloud container clusters get-credentials safeguard-cluster \
  --region=${REGION} --project=${PROJECT}

echo "=== Creating namespace + secrets ==="
kubectl apply -f k8s/namespace.yaml
kubectl get secret miner-secrets -n safeguard-miner 2>/dev/null || {
  echo "ERROR: secrets not found. Run: bash k8s/create-secrets.sh"
  exit 1
}

echo "=== Deploying ==="
kubectl apply -f k8s/deployment.yaml

echo "=== Waiting for rollout ==="
kubectl rollout status deployment/safeguard-miner -n safeguard-miner --timeout=120s

echo "=== Getting external IP ==="
echo "Waiting for LoadBalancer IP..."
for i in $(seq 1 30); do
  IP=$(kubectl get svc safeguard-miner -n safeguard-miner -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)
  if [ -n "$IP" ]; then
    echo ""
    echo "External IP: $IP"
    echo "Miner endpoint: http://$IP:8090"
    echo ""
    echo "IMPORTANT: Update k8s/deployment.yaml MINER_EXTERNAL_ENDPOINT to:"
    echo "  http://$IP:8090"
    echo "Then: kubectl apply -f k8s/deployment.yaml && kubectl rollout restart deployment/safeguard-miner -n safeguard-miner"
    break
  fi
  printf "."
  sleep 5
done

echo ""
echo "=== Status ==="
kubectl get pods -n safeguard-miner
echo ""
echo "Logs: kubectl logs -f deploy/safeguard-miner -n safeguard-miner"
