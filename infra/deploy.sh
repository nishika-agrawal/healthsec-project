#!/bin/bash
# Executed on the EC2 server BY THE CI/CD PIPELINE over SSH (see the
# "deploy" job in .github/workflows/devsecops-pipeline.yml). Only ever
# runs after the deployment gate has already decided this build may
# proceed - this script does not make any policy decisions itself, it
# only pulls and (re)starts the already-approved images.

set -euo pipefail

cd /opt/healthsec

echo "=== Pulling latest approved images ==="
docker compose -f docker-compose.prod.yml pull

echo "=== Starting/updating containers ==="
docker compose -f docker-compose.prod.yml up -d

echo "=== Cleaning up old, unused images ==="
docker image prune -f

echo "=== Waiting for the backend to become healthy ==="
sleep 5
for attempt in 1 2 3 4 5; do
  if curl -sf http://localhost:8000/health > /dev/null; then
    echo "Backend is healthy."
    exit 0
  fi
  echo "Attempt $attempt: backend not ready yet, retrying in 5s..."
  sleep 5
done

echo "ERROR: backend did not become healthy after deployment."
docker compose -f docker-compose.prod.yml logs backend --tail=50
exit 1
