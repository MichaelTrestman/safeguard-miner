#!/bin/bash
set -euo pipefail

# Deploy the test miner (experiments branch) to GKE.
# Uses SuperPractice wallet, :experiments image tag.
# Prod miner (safeguard-miner namespace, miner2 wallet, :latest) untouched.

REGISTRY="us-central1-docker.pkg.dev/safeguard-testnet/safeguard"
REGION="us-central1"
PROJECT="safeguard-testnet"
NAMESPACE="safeguard-miner-test"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MINER_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=== Authenticating Docker ==="
gcloud auth configure-docker ${REGION}-docker.pkg.dev --quiet

echo "=== Building safeguard-miner:experiments ==="
docker buildx build --platform linux/amd64 \
  -t ${REGISTRY}/safeguard-miner:experiments \
  --push \
  ${MINER_DIR}

echo "=== Getting cluster credentials ==="
gcloud container clusters get-credentials safeguard-cluster \
  --region=${REGION} --project=${PROJECT}

echo "=== Syncing secrets ==="
kubectl create namespace ${NAMESPACE} 2>/dev/null || true

kubectl create secret generic miner-test-secrets \
  --namespace=${NAMESPACE} \
  --from-literal=chutes-api-key="$(gcloud secrets versions access latest --secret=chutes-api-key --project=$PROJECT)" \
  --from-literal=dashboard-admin-user="$(gcloud secrets versions access latest --secret=admin-user --project=$PROJECT)" \
  --from-literal=dashboard-admin-password="$(gcloud secrets versions access latest --secret=admin-pass --project=$PROJECT)" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic wallet-superpractice \
  --namespace=${NAMESPACE} \
  --from-literal=hotkey="$(gcloud secrets versions access latest --secret=wallet-superpractice-hotkey --project=$PROJECT)" \
  --from-literal=coldkeypub.txt="$(gcloud secrets versions access latest --secret=wallet-superpractice-coldkeypub --project=$PROJECT)" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "=== Deploying test miner ==="
kubectl apply -f "${SCRIPT_DIR}/deployment.yaml"

echo "=== Waiting for rollout ==="
kubectl rollout status deployment/safeguard-miner-test -n ${NAMESPACE} --timeout=120s

echo "=== Waiting for LoadBalancer IP ==="
for i in $(seq 1 30); do
  IP=$(kubectl get svc safeguard-miner-test -n ${NAMESPACE} -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
  if [ -n "$IP" ]; then
    echo ""
    echo "=== LoadBalancer IP: ${IP} ==="
    echo ""
    echo "IMPORTANT: Update MINER_EXTERNAL_ENDPOINT in deployment.yaml to:"
    echo "  http://${IP}:8090"
    echo "Then re-apply: kubectl apply -f ${SCRIPT_DIR}/deployment.yaml"
    echo ""
    break
  fi
  echo -n "."
  sleep 5
done

echo "=== Status ==="
kubectl get pods -n ${NAMESPACE}
kubectl get svc -n ${NAMESPACE}
echo ""
echo "Dashboard: kubectl port-forward svc/safeguard-miner-test 8091:8090 -n ${NAMESPACE}"
