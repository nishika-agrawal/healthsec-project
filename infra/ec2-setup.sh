#!/bin/bash
# Run ONCE, manually, on a fresh Ubuntu 22.04/24.04 EC2 instance to
# prepare it for deployment. Not run by CI - this is a one-time setup
# step a human performs over SSH (see AWS_DEPLOYMENT.md).
#
# Usage:
#   scp infra/ec2-setup.sh ubuntu@<EC2_PUBLIC_IP>:~/
#   ssh ubuntu@<EC2_PUBLIC_IP>
#   chmod +x ec2-setup.sh && ./ec2-setup.sh

set -euo pipefail

echo "=== Updating packages ==="
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg

echo "=== Installing Docker Engine + Compose plugin ==="
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

echo "=== Allowing the current user to run docker without sudo ==="
sudo usermod -aG docker "$USER"

echo "=== Creating the deployment directory ==="
sudo mkdir -p /opt/healthsec
sudo chown "$USER":"$USER" /opt/healthsec

echo ""
echo "=== Setup complete ==="
echo "1. Log out and back in (or run 'newgrp docker') for the docker group change to take effect."
echo "2. Copy docker-compose.prod.yml from this repo to /opt/healthsec/ on this server."
echo "3. Copy .env.prod.example to /opt/healthsec/.env.prod and fill in real values (see AWS_DEPLOYMENT.md)."
echo "4. Verify with: docker compose -f /opt/healthsec/docker-compose.prod.yml config"
