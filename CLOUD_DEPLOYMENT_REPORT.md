# Cloud Deployment on AWS

*Report section. Replace the screenshot placeholders with your own captures.*

## 1. Objective

The HealthSec application (a React frontend, a FastAPI backend with machine-learning risk scoring and explanations, and a PostgreSQL database) originally ran locally in Docker. The course requires the project to be hosted on AWS. This section describes how the application was moved to AWS, which services were used and why, how it is secured and monitored, and what decisions and constraints shaped the design.

## 2. Architecture

The application runs in the **Asia Pacific (Sydney) region, ap-southeast-2**.

```
User browser
   |  HTTP :80 / :8000
   v
Application Load Balancer  (healthsec-alb)
   |-- :80   --> ECS Fargate task: frontend (nginx + React build)
   |-- :8000 --> ECS Fargate task: backend  (FastAPI + ML model)
                       |
                       v
               Amazon RDS for PostgreSQL (private, no public access)

Supporting services: ECR (images), Secrets Manager (credentials), IAM (roles),
CloudWatch (logs and alarms), SNS (email alerts), CloudTrail (audit),
S3 (log and backup storage), AWS Budgets (cost control).
```

*[Insert screenshot: the application running at the load balancer address.]*

## 3. AWS services used and why

| Service | Role in the project | Why it was chosen |
|---|---|---|
| **Amazon ECS on Fargate** | Runs the backend and frontend containers | Containers run without managing servers; ECS restarts failed containers automatically |
| **Amazon ECR** | Stores the Docker images | Private registry integrated with ECS and IAM |
| **Application Load Balancer** | Single public entry point; routes by port to the frontend or backend; health-checks the containers | Removes direct exposure of containers and gives automatic health monitoring |
| **Amazon RDS (PostgreSQL)** | Hosts the application database | Managed service with automated backups, patching and no database server to maintain |
| **Amazon VPC and security groups** | Network isolation and firewalling | Allows only internet to load balancer, load balancer to containers, containers to database |
| **AWS Secrets Manager** | Holds the database URL, JWT signing key and demo password | Keeps credentials out of source code and images |
| **AWS IAM** | Roles for ECS and for the build server | Gives each component only the permissions it needs, with no stored access keys |
| **Amazon CloudWatch** | Container logs, plus alarms for unhealthy targets, database CPU and server status | Central logging and proactive failure detection |
| **Amazon SNS** | Sends alarm notifications by email | Immediate notice of failures |
| **AWS CloudTrail** | Records account activity | Audit trail, which is important for a security-focused healthcare project |
| **Amazon S3** | Stores CloudTrail logs and database backups | Durable, low-cost storage |
| **Amazon EC2, EBS and Elastic IP** | Build server for container images, database administration host, and a complete fallback deployment | The first working deployment, kept as a backup; the EBS snapshot is a restore point |
| **AWS Budgets** | Cost alerts | Protects the account's credits |

*[Insert screenshots: ECS services running; RDS instance details; load balancer listeners and healthy targets; ECR repositories.]*

## 4. Security design

- **Defence in depth through network layers.** The load balancer accepts public traffic; the container security group accepts traffic only from the load balancer; the database security group accepts traffic only from the containers (and from the administration server). The database is not publicly accessible and has no internet route.
- **No credentials in code.** Secrets are stored in Secrets Manager and injected into the backend at start-up. The ECS execution role may read only secrets whose names begin with `healthsec/`.
- **Least-privilege roles.** ECS tasks use an execution role; the build server's role can push images, read the project's secrets and write to one backup bucket.
- **Auditability.** CloudTrail captures account activity; application logs go to CloudWatch with a 14-day retention period.
- **Application-level security.** Authentication uses signed JWT tokens, and the project's DevSecOps gate (Trivy, OWASP Dependency-Check, SonarQube and an ML-based risk score) decides whether a build is approved, as described in earlier sections.

*[Insert screenshot: security groups and their inbound rules.]*

## 5. Deployment process

1. Created three security groups (load balancer, containers, database).
2. Created the RDS PostgreSQL instance in private mode and stored its connection string and the other credentials in Secrets Manager.
3. Created the load balancer with two target groups (frontend on port 80, backend on port 8000) and two listeners.
4. Created the IAM roles and the ECR repositories.
5. Built the backend and frontend images on the EC2 build server and pushed them to ECR. The frontend image is built with the load balancer address so the browser can find the API.
6. Migrated the existing database content into RDS using `pg_dump` and `psql`, and verified the row counts (users, scans, predictions, findings).
7. Registered the ECS task definitions and started the two services.
8. Verified health endpoints through the load balancer and used the application end to end.

The full commands are in `AWS_DEPLOYMENT.md`.

## 6. Reliability, monitoring and backups

- ECS replaces a failed container automatically; the load balancer routes traffic only to healthy targets.
- CloudWatch alarms notify by email when the backend becomes unhealthy, when database CPU stays high, or when the fallback server fails its status checks. A test alarm was triggered to confirm that email delivery works.
- RDS takes automated daily backups; manual `pg_dump` backups were copied to S3; an EBS snapshot protects the fallback server.
- A fallback deployment on a single EC2 instance (Docker Compose) was kept running while the ECS deployment was verified.

## 7. Cost control

The application is hosted using the account's AWS credits. A monthly budget with email alerts monitors spending, log retention is capped at 14 days, and the estimated running cost of the full stack is about $3 to $4 per day. Resources are deleted after the project is finished (the teardown order is documented).

## 8. Challenges and decisions

- **Service availability differed by region.** On this account, attempts to create ECS clusters, load balancers and S3 buckets in us-east-1 were refused by an account-level service control policy, while the same services worked in Sydney. The deployment was therefore built in ap-southeast-2. The first working version used a single EC2 instance with Docker Compose, which was kept as the fallback.
- **Frontend configuration is build-time.** The React build embeds the API address, so the frontend image is rebuilt when the load balancer address changes.
- **Order of data migration.** The data was restored into RDS before the backend service started, because the backend creates its own tables on first run and would otherwise conflict with the restore.
- **Database engine version.** RDS provided PostgreSQL 18, while the original container used version 15. A dump-and-restore migration was used and verified, and the application connected without changes.

## 9. Limitations and future work

- Traffic uses HTTP. A domain, an ACM certificate and an HTTPS listener should be added for production.
- Each service has one task and the database is in one availability zone, so there is no high availability.
- Image builds and deployments to AWS are manual. A pipeline job could build, scan and push to ECR and then update the ECS service.
- No web application firewall or rate limiting protects the public endpoints.
- The application holds only synthetic demo data; real patient data would require encryption at rest and in transit, further access controls and regulatory review.

## 10. Evidence checklist for the demonstration

1. The application at `http://<load balancer address>` with the dashboard showing a risk score and deployment decision.
2. ECS: cluster, both services at 1/1 running, task logs.
3. RDS: instance details showing PostgreSQL, Available, and **Publicly accessible: No**.
4. EC2: load balancer listeners and healthy target groups.
5. ECR: both repositories.
6. Secrets Manager: secret names (never the values).
7. Security groups: inbound rules for the three groups.
8. IAM: the two roles.
9. CloudWatch: alarms and the log group; SNS: the confirmed email subscription; the test alarm email.
10. CloudTrail trail; S3 buckets (including `db/` backups); Budget; EBS snapshot.
