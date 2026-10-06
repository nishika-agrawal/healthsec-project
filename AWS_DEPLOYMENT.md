# AWS Deployment Guide (Phase 10)

This guide walks through deploying the Healthcare DevSecOps Risk Assessment Framework to a single AWS EC2 instance, with deployments automated (and gated) by the GitHub Actions pipeline from Phases 4 and 8.

**The project remains fully usable locally without any of this.** Everything below is optional and only needed if you want to demonstrate the live cloud deployment.

## What Runs Where

| Component | Runs locally (Phases 1-9) | Runs on AWS (Phase 10) |
|---|---|---|
| Backend (FastAPI) | ✅ via `docker compose up` or `uvicorn` | ✅ as a Docker container on EC2 |
| Frontend (React) | ✅ via `npm run dev` (dev server) | ✅ as a static build served by nginx in a Docker container |
| PostgreSQL | ✅ Docker container, bound to `127.0.0.1` only | ✅ Docker container, bound to `127.0.0.1` only - **never exposed publicly**, on either environment |
| GitHub Actions CI/CD | ✅ runs on GitHub's servers regardless | Same pipeline additionally builds/pushes images and deploys to EC2 |
| SonarQube | Optional: SonarCloud or local Docker container | Not deployed to AWS - it's a CI-time tool, not part of the running application |

Only the backend, frontend, and database containers actually run on the EC2 instance. Everything else (the pipeline itself, SonarQube analysis, Trivy/OWASP scanning) happens on GitHub's own runners before anything is deployed.

## Step 1: Launch an EC2 Instance

1. AWS Console → EC2 → **Launch Instance**.
2. **AMI:** Ubuntu Server 22.04 LTS (or 24.04 LTS).
3. **Instance type:** `t2.micro` or `t3.micro` (both free-tier eligible).
4. **Key pair:** create a new one, download the `.pem` file, keep it safe - you'll need it for the `EC2_SSH_PRIVATE_KEY` GitHub secret later.
5. **Network settings → Security group:** create a new one with these inbound rules:

   | Type | Port | Source | Purpose |
   |---|---|---|---|
   | SSH | 22 | **Your IP only** (not 0.0.0.0/0) | Admin access |
   | Custom TCP | 8000 | 0.0.0.0/0 | Backend API |
   | HTTP | 80 | 0.0.0.0/0 | Frontend |

   **Do not add a rule for port 5432 (PostgreSQL).** The database is never meant to be reachable from outside the server - `docker-compose.prod.yml` already binds it to `127.0.0.1` only, and the security group should not open it either. This is defense in depth.

6. Launch the instance.

## Step 2: Allocate an Elastic IP

A plain EC2 public IP changes if the instance restarts, which would break `CORS_ORIGINS` and the frontend's baked-in `VITE_API_URL`.

1. EC2 Console → **Elastic IPs** → Allocate.
2. Associate it with your new instance.
3. Use this IP (or a domain pointed at it) everywhere below as `<EC2_PUBLIC_IP>`.

## Step 3: IAM Setup

### IAM user (for your own console/CLI access)

Create an IAM user for yourself (not for GitHub Actions - this deployment uses SSH, not the AWS API, so GitHub Actions never needs AWS credentials at all). Attach a least-privilege policy, for example:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:RebootInstances"
      ],
      "Resource": "arn:aws:ec2:*:*:instance/YOUR_INSTANCE_ID"
    }
  ]
}
```

### IAM role for the EC2 instance (optional, for S3 report archival)

If you'd like the deployed server to archive scan reports to S3 for long-term storage (optional - not required for the app to function):

1. Create an S3 bucket (e.g. `healthsec-scan-archives`).
2. IAM → Roles → Create role → AWS service → EC2.
3. Attach a policy scoped to only that bucket:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject"],
      "Resource": "arn:aws:s3:::healthsec-scan-archives/*"
    }
  ]
}
```

4. Attach this role to the EC2 instance (Instance settings → Attach/Replace IAM role).

This project does not require this step - it's included to demonstrate least-privilege IAM role usage for the optional S3 integration, per the Phase 1 architecture.

## Step 4: Prepare the Server

```bash
scp -i your-key.pem infra/ec2-setup.sh ubuntu@<EC2_PUBLIC_IP>:~/
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>
chmod +x ec2-setup.sh
./ec2-setup.sh
```

This installs Docker and Docker Compose, and creates `/opt/healthsec/`. Log out and back in afterward (or run `newgrp docker`) so your user can run `docker` without `sudo`.

## Step 5: Create the Production Environment File

On the server:

```bash
nano /opt/healthsec/.env.prod
```

Paste the contents of this repo's `.env.prod.example`, and replace every `REPLACE_WITH_...` placeholder with a real, randomly-generated value. Generate secrets with:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Set `CORS_ORIGINS=http://<EC2_PUBLIC_IP>` and `BACKEND_IMAGE`/`FRONTEND_IMAGE` to match your actual GitHub repository (see Step 7).

**Never commit this file.** It only ever lives on the server. `chmod 600 /opt/healthsec/.env.prod` is good practice.

## Step 6: Make GHCR Images Pullable

The CI pipeline pushes images to `ghcr.io/<owner>/<repo>-backend` and `ghcr.io/<owner>/<repo>-frontend`. The simplest option for a demo project is to make these packages public (no registry login needed on the server):

1. After the first successful pipeline run, go to your GitHub profile/org → **Packages**.
2. Open each package (`<repo>-backend`, `<repo>-frontend`) → **Package settings** → **Change visibility** → **Public**.

(If you'd rather keep them private, you'd instead `docker login ghcr.io` on the EC2 server using a GitHub Personal Access Token with `read:packages` scope - out of scope for this guide, but straightforward if needed.)

## Step 7: Configure GitHub Secrets and Variables

Repo → **Settings → Secrets and variables → Actions**:

| Type | Name | Value |
|---|---|---|
| Secret | `EC2_HOST` | Your Elastic IP |
| Secret | `EC2_SSH_USER` | `ubuntu` |
| Secret | `EC2_SSH_PRIVATE_KEY` | The full contents of your `.pem` file |
| Variable | `VITE_API_URL` | `http://<EC2_PUBLIC_IP>:8000` |

(`SONAR_TOKEN`/`SONAR_HOST_URL` from Phase 4 are unrelated to deployment but should already be set if you're using SonarCloud.)

## Step 8: Configure GitHub Environments (the manual-approval gate)

Repo → **Settings → Environments**:

1. Create an environment named **`production`** - leave it with no protection rules. Builds the policy engine marks **Low risk / approved** deploy here instantly.
2. Create a second environment named **`production-review`** - add a **required reviewer** (yourself, or a teammate). Builds marked **Medium risk / review_required** will pause here until someone clicks "Approve" in the Actions tab.

**High risk / blocked** builds never reach either environment - the `deployment-gate` job fails outright and the `deploy` job is skipped automatically (see the workflow file for how this works).

## Step 9: Deploy

Push to `main`. In the **Actions** tab you'll see, in order:
1. `build-test-scan` - tests, SonarQube/Trivy/OWASP scans
2. `build-and-push-images` and `deployment-gate` run in parallel
3. `deploy` - waits for approval if the environment requires it, then SSHs into EC2 and runs `infra/deploy.sh`

## Step 10: Verify the Deployment

```bash
curl http://<EC2_PUBLIC_IP>:8000/health
# {"status": "ok"}

curl http://<EC2_PUBLIC_IP>:8000/health/db
# {"status": "ok", "database": "connected"}
```

Open `http://<EC2_PUBLIC_IP>` in a browser - you should see the login page. Open `http://<EC2_PUBLIC_IP>:8000/docs` for the live API documentation.

On the server, you can also check container status directly:

```bash
docker compose -f /opt/healthsec/docker-compose.prod.yml ps
docker compose -f /opt/healthsec/docker-compose.prod.yml logs backend --tail=50
```

## Deployment History and Status

The deployment **policy decision** (approved / review_required / blocked, and why) for every scan is already recorded in the database and queryable via `GET /deployments` (Phase 8) - this is the project's permanent deployment history record, and is what the Phase 9 dashboard's "Deployment History" section displays.

The **infrastructure-level** record of each deploy attempt (which commit, whether the SSH deploy step succeeded, when) lives in the GitHub Actions run history itself (the Actions tab) - a standard, complete audit trail that doesn't need to be duplicated into the application database.

## Troubleshooting

- **`deploy` job never appears in the Actions tab:** check that `deployment-gate` didn't fail (a "blocked" decision fails it on purpose) and that you pushed to `main`, not a feature branch.
- **SSH step fails with a permission error:** confirm the EC2 security group allows port 22 from GitHub's runners, or (more securely) keep it restricted to your IP and use a self-hosted runner - a public 0.0.0.0/0 rule on port 22 is not recommended.
- **Backend container starts but `/health/db` returns an error:** check `/opt/healthsec/.env.prod`'s `DATABASE_URL` matches the `POSTGRES_*` values in the same file.
- **Frontend loads but API calls fail (CORS errors in the browser console):** confirm `CORS_ORIGINS` in `.env.prod` matches the exact URL you're loading the frontend from, and that `VITE_API_URL` was correct at image build time (changing it requires rebuilding the frontend image, not just restarting the container - see the note in `frontend/Dockerfile.prod`).
