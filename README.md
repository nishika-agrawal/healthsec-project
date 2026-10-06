# Healthcare DevSecOps Risk Assessment Framework

## Phase 3: Healthcare Demo Application

This is a synthetic patient-record management app used later to
demonstrate the DevSecOps security-assessment framework. It has:

- JWT-based login (a single demo user, seeded automatically on startup).
- Full CRUD for patient records (create, view, update, delete).
- Server-side input validation (blank names and malformed emails are rejected).
- A React interface connected to the FastAPI backend.

**This app must only ever be used with synthetic/fake data. Never enter real patient information.**

## Folder Structure

```
healthsec-project/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py          # FastAPI app, router registration, startup seeding
│   │   ├── config.py        # Settings loaded from environment variables
│   │   ├── database.py      # SQLAlchemy engine/session setup
│   │   ├── models.py        # User and Patient SQLAlchemy models
│   │   ├── schemas.py       # Pydantic request/response schemas + validation
│   │   ├── auth_security.py # Password hashing + JWT helpers (renamed in Phase 5)
│   │   ├── auth.py          # get_current_user dependency (route protection)
│   │   ├── crud.py          # Database CRUD helper functions
│   │   ├── security/        # Phase 5: security-scan data processing package
│   │   │   ├── models.py        # Application, Scan, Finding, ScanFeatures tables
│   │   │   ├── normalize.py     # Shared severity scale across scanners
│   │   │   ├── parsers.py       # Trivy / Dependency-Check / SonarQube parsers
│   │   │   ├── dedupe.py        # Duplicate-finding removal
│   │   │   ├── features.py      # Security metric computation
│   │   │   ├── pipeline.py      # Orchestrates parse -> dedupe -> features
│   │   │   ├── repository.py    # Database read/write functions
│   │   │   └── ingest.py        # CLI: report files -> processed -> database
│   │   ├── ml/               # Phase 6: ML risk prediction package
│   │   │   ├── dataset.py        # Synthetic dataset + shared rule-based scorer
│   │   │   ├── train.py          # Trains + evaluates the Random Forest
│   │   │   ├── predictor.py      # predict_risk() with rule-based fallback
│   │   │   ├── models.py         # RiskPrediction table
│   │   │   ├── repository.py     # Save/retrieve predictions
│   │   │   ├── predict_cli.py    # CLI: stored scan features -> prediction -> database
│   │   │   ├── model/            # risk_model.joblib, metadata, evaluation report
│   │   │   └── data/             # synthetic_vulnerability_dataset.csv
│   │   ├── xai/               # Phase 7: explainability + recommendations
│   │   │   ├── explainer.py       # SHAP (real model) + rule breakdown (fallback)
│   │   │   ├── labels.py          # Plain-language feature names
│   │   │   ├── recommendations.py # Findings -> prioritized, linked remediation text
│   │   │   ├── models.py          # Explanation, RecommendationSet tables
│   │   │   ├── repository.py      # Save/retrieve explanations + recommendations
│   │   │   ├── schemas.py         # Pydantic response models
│   │   │   └── explain_cli.py     # CLI: stored scan -> predict -> explain -> recommend
│   │   ├── deployment/         # Phase 8: deployment decision engine
│   │   │   ├── policy.py          # decide_deployment() - configurable policy
│   │   │   ├── models.py          # DeploymentRecord table
│   │   │   ├── repository.py      # Save/retrieve decisions, list history
│   │   │   └── schemas.py         # Pydantic response models
│   │   └── routers/
│   │       ├── __init__.py
│   │       ├── auth.py      # POST /auth/login
│   │       ├── patients.py  # /patients CRUD endpoints
│   │       ├── security.py  # Phase 8: /scans, /applications, /deployments
│   │       └── dashboard.py # Phase 8: /dashboard/stats
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── conftest.py      # Forces tests onto a throwaway SQLite DB
│   │   ├── test_health.py
│   │   ├── test_patients.py # Auth + full CRUD + validation tests
│   │   ├── test_security_normalize.py
│   │   ├── test_security_parsers.py
│   │   ├── test_security_dedupe.py
│   │   ├── test_security_features.py
│   │   ├── test_security_pipeline.py    # Runs the real sample reports through the pipeline
│   │   ├── test_security_repository.py  # Full store + retrieve against a real DB
│   │   ├── test_ml_dataset.py           # Rule-based scoring + synthetic dataset generation
│   │   ├── test_ml_predictor.py         # Trained-model predictions + fallback behavior
│   │   ├── test_ml_integration.py       # Phase 5 features -> Phase 6 prediction -> storage
│   │   ├── test_xai_explainer.py        # SHAP + rule-breakdown correctness
│   │   ├── test_xai_recommendations.py  # Every recommendation category
│   │   ├── test_xai_integration.py      # Full Phase 5 -> 6 -> 7 pipeline
│   │   ├── test_deployment_policy.py    # Every policy branch, incl. mandatory-check blocking
│   │   ├── test_deployment_gate_cli.py  # Phase 10: the CI gate script, run as real subprocesses
│   │   ├── test_api_security.py         # Full HTTP-level API tests
│   │   └── test_e2e_demonstration_scenarios.py  # Phase 11: all 3 scenarios, full stack
│   ├── requirements.txt
│   ├── .env.example
│   ├── API_DOCUMENTATION.md
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── main.jsx
│   │   ├── App.jsx              # Routes: /login, /patients, /dashboard
│   │   ├── api.js                # Axios client, auth token handling, all API calls
│   │   ├── index.css
│   │   ├── pages/
│   │   │   ├── Login.jsx
│   │   │   ├── Patients.jsx      # List, add, edit, delete patients
│   │   │   └── Dashboard.jsx     # Phase 9: security dashboard - owns all state/fetching
│   │   └── components/
│   │       ├── ProtectedRoute.jsx
│   │       ├── PatientForm.jsx
│   │       ├── NavBar.jsx            # Phase 9: shared nav between Patients and Dashboard
│   │       ├── LoadingSpinner.jsx    # Phase 9: reusable loading state
│   │       ├── ErrorMessage.jsx      # Phase 9: reusable error state
│   │       └── dashboard/            # Phase 9: one component per dashboard section
│   │           ├── ApplicationSelector.jsx
│   │           ├── OverviewSection.jsx
│   │           ├── ScanHistoryTable.jsx
│   │           ├── SecurityReportsSection.jsx
│   │           ├── RiskAssessmentSection.jsx
│   │           ├── ExplainableAISection.jsx
│   │           ├── RecommendationsSection.jsx
│   │           ├── DeploymentDecisionCard.jsx
│   │           └── DeploymentHistoryTable.jsx
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   ├── .env.example
│   ├── Dockerfile             # Dev server (local docker-compose.yml)
│   ├── Dockerfile.prod        # Phase 10: production build, served by nginx
│   └── nginx.conf             # Phase 10: SPA routing for the production image
├── docker-compose.yml
├── docker-compose.prod.yml        # Phase 10: production compose (pulls GHCR images)
├── docker-compose.sonarqube.yml   # Optional local SonarQube server
├── sonar-project.properties       # SonarQube/SonarCloud project config
├── .env.prod.example               # Phase 10: template for the server's real secrets file
├── infra/                          # Phase 10: deployment scripts
│   ├── ec2-setup.sh                    # One-time: install Docker on a fresh EC2 instance
│   └── deploy.sh                       # Run by CI over SSH: pull + restart containers
├── AWS_DEPLOYMENT.md               # Phase 10: full AWS setup guide
├── .github/
│   └── workflows/
│       └── devsecops-pipeline.yml # CI/CD: build, test, scan, report, gate, deploy
├── scripts/
│   ├── requirements.txt
│   ├── fetch_sonarqube_report.py  # Pulls issues + quality gate from SonarQube API
│   ├── record_missing_sonar.py    # Placeholder report when Sonar isn't configured
│   ├── validate_reports.py        # Checks all 3 reports exist/are valid JSON
│   └── tests/
│       ├── test_fetch_sonarqube_report.py
│       └── test_validate_reports.py
├── reports/
│   ├── samples/                   # Illustrative sample reports (see samples/README.md)
│   └── fixtures/                  # Phase 11: controlled demonstration scenario reports
│       ├── scenario-1-low-risk/
│       ├── scenario-2-high-risk/
│       ├── scenario-3-remediated/
│       └── demonstration-transcript.txt   # Real captured output of all 3 scenarios
├── TESTING_AND_DEMONSTRATION.md    # Phase 11: test breakdown, scenarios, limitations
├── PROJECT_REPORT.md                # Phase 12: complete final academic report
├── PRESENTATION_OUTLINE.md          # Phase 12: slide-by-slide presentation structure
├── DEMONSTRATION_SCRIPT.md          # Phase 12: live demonstration script
├── .gitignore
└── README.md
```

## Required Software (install these first)

- Python 3.10+ (`python3 --version`)
- Node.js 18+ and npm (`node --version`, `npm --version`)
- Docker Desktop / Docker Engine + Docker Compose
- Git
- PostgreSQL 15 (only needed if you run the database without Docker — Docker Compose already includes it)

## Option A: Run Everything with Docker Compose (recommended)

1. Copy the environment templates:
   ```bash
   cp backend/.env.example backend/.env
   cp frontend/.env.example frontend/.env
   ```
2. From the project root, start everything:
   ```bash
   docker compose up --build
   ```
3. Once it's running:
   - Backend API: http://localhost:8000
   - Backend docs (Swagger UI): http://localhost:8000/docs
   - Frontend: http://localhost:5173
4. Open the frontend in your browser — you should see "Backend status: ok".
5. To stop everything: `docker compose down` (add `-v` to also delete the database volume).

## Option B: Run Backend and Frontend Locally (without Docker)

### Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Make sure PostgreSQL is running locally and matches the credentials in
`.env` (or edit `.env` to match your local database). Then start the API:

```bash
uvicorn app.main:app --reload
```

- API: http://localhost:8000
- Interactive docs: http://localhost:8000/docs
- Health check: http://localhost:8000/health
- Database check: http://localhost:8000/health/db

### Frontend

In a separate terminal:

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

- Frontend: http://localhost:5173

## Running the Backend Tests

The test suite runs against a temporary SQLite database, so you do **not**
need PostgreSQL running just to run tests.

```bash
cd backend
source venv/bin/activate   # if not already active
pytest tests/ -v
```

You should see 9 tests pass, covering:
- The basic health checks (from Phase 2).
- Successful and failed login.
- That `/patients` endpoints reject unauthenticated requests.
- The full create → list → get → update → delete flow for a patient record.
- Validation: blank names and invalid emails are rejected with a 422 error.

## Using the Application

1. Start the app (Docker Compose or the two local dev servers - see above).
2. Open http://localhost:5173 - you'll land on the login page.
3. Log in with the demo credentials: **demo_doctor / ChangeMe123!**
   (This user is created automatically the first time the backend starts, from the `DEMO_USERNAME`/`DEMO_PASSWORD` values in `backend/.env`.)
4. You'll be redirected to the Patients page, where you can:
   - Click **"+ Add Patient"** to create a synthetic patient record.
   - Click **"Edit"** on any row to update a record.
   - Click **"Delete"** to remove a record (with a confirmation prompt).
5. All data is stored in PostgreSQL (or SQLite for automated tests) - refresh the page and the data will still be there.

You can also explore and test every endpoint directly at
http://localhost:8000/docs (FastAPI's interactive Swagger UI). Click
**Authorize**, log in with the demo credentials, and try the endpoints live.

## What to Expect at the End of Phase 3

- Logging in with the demo credentials succeeds; wrong credentials are rejected.
- `/patients` endpoints return `401 Unauthorized` without a valid token.
- Patient records can be created, listed, viewed, updated, and deleted from both the API docs and the React UI.
- Invalid input (blank name, malformed email) is rejected with a clear validation error rather than silently accepted or crashing the server.
- No real patient data is used anywhere - only synthetic/fake values.

Security scanning, ML risk prediction, explainability, and the full dashboard are not part of this phase - those come in Phases 4 onward, per the Phase 1 roadmap.

## Manual Steps You Need to Perform

1. Install the required software listed above if not already installed.
2. Copy `.env.example` → `.env` in both `backend/` and `frontend/` (these are gitignored and must be created locally by each team member).
3. **Change `DEMO_USERNAME`/`DEMO_PASSWORD`** in `backend/.env` if you don't want to use the default demo login shown in this README.
4. If using Option B, make sure a local PostgreSQL server is running with a database matching your `.env` settings (or simplest: use Option A with Docker Compose, which creates the database automatically).

---

## Phase 4: DevSecOps Pipeline and Security Scanning

The GitHub Actions workflow at `.github/workflows/devsecops-pipeline.yml` runs automatically on every push and pull request. It:

1. Installs backend dependencies and runs the pytest suite.
2. Installs frontend dependencies and runs `npm run build`.
3. Builds the backend Docker image.
4. Runs a **SonarQube** static-analysis scan (skipped gracefully if not configured yet - see below).
5. Runs **Trivy** against the built Docker image.
6. Runs **OWASP Dependency-Check** against the project's dependencies.
7. Validates that each scanner produced a real report (`scripts/validate_reports.py`) and writes `reports/report-manifest.json`.
8. Uploads everything under `reports/` as a downloadable pipeline artifact named `security-reports-<commit-sha>`.

### Required GitHub Secrets (for SonarQube/SonarCloud)

Go to your GitHub repo → **Settings → Secrets and variables → Actions** and add:

| Secret | Value |
|---|---|
| `SONAR_TOKEN` | A token generated from SonarCloud or your self-hosted SonarQube instance |
| `SONAR_HOST_URL` | `https://sonarcloud.io`, or your self-hosted URL |

**If these secrets are not set, the pipeline still runs successfully** - the SonarQube step is skipped and a placeholder report (`"status": "unavailable"`) is written instead, so Phase 5 always has a report file to read, even if it says a scanner didn't run.

Trivy and OWASP Dependency-Check require no secrets - they run automatically.

### Setting Up SonarQube

**Option A - SonarCloud (recommended, free for public repos):**
1. Sign up at https://sonarcloud.io and import this GitHub repository.
2. Edit `sonar-project.properties` and replace `your-sonarcloud-org` with your real organization key.
3. Generate a token in SonarCloud and add it as the `SONAR_TOKEN` GitHub secret; add `SONAR_HOST_URL = https://sonarcloud.io`.

**Option B - Self-hosted, for local testing before pushing:**
```bash
docker compose -f docker-compose.sonarqube.yml up -d
```
Then open http://localhost:9000 (default login `admin`/`admin`), create a project with key `healthsec-devsecops-framework`, and generate a token.

### Testing the Report-Handling Scripts Locally

You don't need a real pipeline run to test the Python scripts that process scan output:

```bash
cd scripts
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest tests/ -v
```

You should see 10 tests pass, covering: a missing SonarQube token/host, a simulated network failure, a successful mocked SonarQube response, missing report files, empty report files, invalid JSON, and valid JSON.

### Sample Reports

`reports/samples/` contains **hand-written, clearly-labeled illustrative examples** of what each tool's real report looks like (matching Trivy's and OWASP Dependency-Check's actual JSON schemas, and this project's own SonarQube summary format). These are **not** real scan results - see `reports/samples/README.md` for details. They exist purely so Phase 5's data-processing code can be built and tested before your first real pipeline run produces real reports.

### What to Expect at the End of Phase 4

- Pushing a commit (or opening a pull request) triggers the workflow automatically under the **Actions** tab on GitHub.
- The workflow builds and tests both apps, then runs all three scanners.
- Whether or not SonarQube is configured, and regardless of whether any vulnerabilities are found, the pipeline **completes successfully** and produces a `security-reports-<sha>` artifact you can download containing `reports/sonarqube/`, `reports/trivy/`, `reports/dependency-check/`, and `reports/report-manifest.json`.
- The pipeline only fails outright if there's a genuine problem (e.g., backend tests fail, the Docker image doesn't build, or literally none of the three reports were produced at all).

Turning these raw reports into structured features for the ML model is Phase 5's job - this phase only produces and validates the raw scan data.

### Manual Steps You Need to Perform

1. Push this project to a GitHub repository if you haven't already (`git init`, `git add`, `git commit`, `git remote add origin ...`, `git push`).
2. (Optional but recommended) Set up SonarCloud or local SonarQube and add the `SONAR_TOKEN` / `SONAR_HOST_URL` secrets as described above.
3. Push a commit and check the **Actions** tab to watch the pipeline run, then download the `security-reports-<sha>` artifact to see your real scan results.

---

## Phase 5: Security Data Processing and Database Integration

This phase turns the raw scanner JSON reports into structured, deduplicated findings and computed security metrics, and stores them in new database tables.

### Important note: a filename was renamed

Phase 3's `backend/app/security.py` (password hashing + JWT helpers) has been **renamed to `backend/app/auth_security.py`**. This was necessary because Phase 5 adds a new `backend/app/security/` *package* (for security-scan data processing), and Python cannot have both a `security.py` module and a `security/` package with the same name in the same location. Its contents and behavior are unchanged - only the filename and its imports changed (`app/auth.py` and `app/routers/auth.py` now import from `app.auth_security` instead of `app.security`).

### New module: `backend/app/security/`

| File | Responsibility |
|---|---|
| `models.py` | New database tables: `Application`, `Scan`, `Finding`, `ScanFeatures` |
| `normalize.py` | Maps each scanner's own severity words onto one shared scale (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN) |
| `parsers.py` | Parses Trivy, OWASP Dependency-Check, and SonarQube reports into a common finding format; handles missing/malformed files without crashing |
| `dedupe.py` | Removes duplicate findings (same source + CVE/rule + package), keeping the higher severity if they conflict |
| `features.py` | Computes the security metrics (severity counts, max CVSS, vulnerable dependency count, container vulnerability count, a rule-based A-F security rating, failed-check count, fix-availability count) |
| `pipeline.py` | Orchestrates parse → dedupe → compute-features into one `ProcessedScanResult` |
| `repository.py` | Database read/write functions (store a processed scan; retrieve by UUID, by application, latest scan, findings, features) |
| `ingest.py` | Standalone CLI tool that ties it all together: reads report files and stores the result in the database |

### Database Schema (new tables)

```
applications
├── id (PK)
├── app_uuid (unique)
├── name (unique)
├── repository_url
└── created_at

scans
├── id (PK)
├── scan_uuid (unique)
├── application_id (FK -> applications.id)
├── commit_sha
├── triggered_at
├── scanner_status   (JSON, e.g. {"trivy": "ok", "sonarqube": "tool_unavailable"})
└── scanner_errors   (JSON)

findings
├── id (PK)
├── scan_id (FK -> scans.id)
├── source (trivy | dependency_check | sonarqube)
├── identifier (CVE ID or rule ID)
├── raw_severity / normalized_severity
├── package_name / installed_version / fixed_version / fix_available
├── title / component / cvss_score / finding_class

scan_features   (one row per scan)
├── id (PK)
├── scan_id (FK -> scans.id, unique)
├── critical_count / high_count / medium_count / low_count
├── max_cvss_score
├── vulnerable_dependency_count / container_vulnerability_count
├── security_rating (rule-based A-F label - NOT a model prediction)
├── failed_security_checks / fix_available_count / total_findings / duplicates_removed
└── computed_at
```

These tables are created automatically (alongside the Phase 3 `users`/`patients` tables) the next time the backend starts, since `app/main.py` now imports `app.security.models`.

### Trying It Out Locally

**Run the automated tests** (31 new tests covering normalization, all three parsers, deduplication, feature computation, the full pipeline against the real sample reports, and full database storage/retrieval):

```bash
cd backend
source venv/bin/activate
pytest tests/ -v
```

You should see 40 tests pass in total (9 from Phase 3 + 31 new).

**Process real reports from a pipeline run and store them in the database:**

```bash
cd backend
source venv/bin/activate
python -m app.security.ingest \
  --app-name "healthsec-demo" \
  --repository-url "https://github.com/your-username/your-repo" \
  --commit-sha "$(git rev-parse HEAD)" \
  --trivy-report ../reports/trivy/trivy-report.json \
  --dependency-check-report ../reports/dependency-check/dependency-check-report.json \
  --sonarqube-report ../reports/sonarqube/sonarqube-report.json
```

This prints the stored scan's UUID, each scanner's status, and the computed features. Point the `--*-report` flags at a downloaded `security-reports-<sha>` artifact from Phase 4 to process real scan data, or at `reports/samples/` to try it with the illustrative sample data (see below).

### Sample Processed Dataset

`reports/samples/sample-processed-dataset.json` was generated by **actually running** `app/security/pipeline.py` against the illustrative sample reports from Phase 4 - it is not hand-written. It shows exactly what the pipeline output looks like: per-scanner status, deduplicated findings, and computed features (in this sample: 2 critical, 3 high, 3 medium, 1 low finding, security rating "F").

### What to Expect at the End of Phase 5

- Running the ingest CLI against any combination of present/missing/malformed report files always completes without crashing - missing scanners are recorded as `"missing"`, not silently ignored.
- Two identical findings within the combined report set are merged into one, keeping the higher severity if they disagreed.
- `security_rating` is a simple, transparent rule (highest severity present), clearly documented as not being a model prediction - Phase 6 adds the actual ML-based risk score as a separate, clearly-labeled field.
- The `applications`, `scans`, `findings`, and `scan_features` tables are queryable directly in PostgreSQL (or SQLite for tests) after running the ingest CLI.

### Manual Steps You Need to Perform

1. If you already had a real Phase 4 pipeline run, download its `security-reports-<sha>` artifact and unzip it somewhere so you can point `app.security.ingest` at real report files instead of the samples.
2. Make sure your `backend/.env` `DATABASE_URL` points at a running PostgreSQL instance (or use Docker Compose) before running the ingest CLI against real data - it will create the new tables automatically on first run.

---

## Phase 6: Machine Learning-Based Risk Prediction

### Where the training data comes from (please read)

There is no public dataset that maps security-scan feature vectors directly onto a real deployment-risk outcome - that would require sensitive, proprietary incident data that organizations don't publish. So this phase **generates a synthetic dataset** instead (`backend/app/ml/dataset.py`):

- Feature values (vulnerability counts, CVSS scores, etc.) are drawn from distributions shaped like real scan output.
- The "ground truth" risk label for each synthetic row comes from a documented, transparent scoring rule (`rule_based_risk_score`), not from any real observed outcome.
- A small amount of random label noise (8%) is added so the dataset isn't trivially perfect.

**This means the model learns to approximate that rule, not real-world deployment risk.** This project does not claim real-world predictive accuracy from this synthetic data - see the full explanation in `app/ml/dataset.py`'s docstring. Using real, outcome-labeled historical scan data is listed as a future enhancement in the Phase 12 documentation.

That same rule (`rule_based_risk_score`) is reused as the **rule-based fallback** whenever the trained model isn't available - so the two aren't unrelated: the model is trained to approximate a rule that's also directly usable on its own.

### New module: `backend/app/ml/`

| File | Responsibility |
|---|---|
| `dataset.py` | Generates the synthetic training dataset; defines `rule_based_risk_score` (shared by training-label generation and the fallback predictor) |
| `train.py` | Trains the Random Forest, evaluates it, saves the model + metadata + evaluation report |
| `predictor.py` | `predict_risk(features)` - the single entry point the rest of the app uses; falls back to the rule-based score if the model is missing/corrupted/unloadable |
| `models.py` | New database table: `RiskPrediction` (one row per scan) |
| `repository.py` | Save/retrieve a scan's risk prediction |
| `predict_cli.py` | CLI that connects Phase 5's stored features to Phase 6's predictor - loads a scan's features from the database, predicts, stores the result |

### Risk Categories and Scores - what each number means

- **`risk_category`**: `"Low"`, `"Medium"`, or `"High"` - the Random Forest's classification (or the rule's, in fallback mode).
- **`predicted_probability`**: a number between **0 and 1** - the Random Forest's confidence in its predicted category. Only present when `model_used` is `"random_forest"`.
- **`risk_score`**: a number between **0 and 100** - the deterministic, rule-based score. **Always** available, even in fallback mode. This is **not** a probability and must never be read as one - it's a transparent, weighted-sum heuristic.

### Model Training Results (from the model included in this project)

Trained on 2,000 synthetic samples (1,600 train / 400 test), Random Forest with 200 trees, max depth 8, class-balanced:

| Class | Precision | Recall | F1-score | Support |
|---|---|---|---|---|
| Low | 0.85 | 0.85 | 0.85 | 206 |
| Medium | 0.78 | 0.89 | 0.83 | 152 |
| High | 0.80 | 0.38 | 0.52 | 42 |
| **Accuracy** | | | **0.815** | 400 |

**Honest limitation:** recall on the "High" class is noticeably weaker (0.38) than the other two - it's the minority class (only ~10% of samples), and the model misses more true High-risk cases than it should. This is a known limitation of training on an imbalanced synthetic dataset and is documented here rather than hidden. The full confusion matrix is saved in `app/ml/model/evaluation_report.json`.

Top feature importances: `critical_count` (0.24), `total_findings` (0.15), `high_count` (0.14), `max_cvss_score` (0.14) - critical-severity findings dominate the model's decisions, matching how the rule-based labels were constructed.

### Trying It Out Locally

**Run the automated tests** (18 new tests: rule-score behavior, dataset generation/reproducibility, prediction with the real trained model, fallback behavior on a missing/corrupted model file, and full integration with Phase 5's stored features):

```bash
cd backend
source venv/bin/activate
pytest tests/ -v
```

You should see 58 tests pass in total (40 from before + 18 new).

**Retrain the model** (regenerates the dataset, model, metadata, and evaluation report):

```bash
cd backend
source venv/bin/activate
python -m app.ml.train
```

**Run a prediction for an already-ingested scan** (after running `app.security.ingest` from Phase 5):

```bash
python -m app.ml.predict_cli --scan-uuid <uuid-printed-by-ingest>
```

### What to Expect at the End of Phase 6

- `app/ml/model/risk_model.joblib`, `model_metadata.json`, and `evaluation_report.json` exist and reflect a model that was actually trained and evaluated (not hand-written numbers).
- Calling `predict_risk()` with no findings returns `"Low"` risk and a score of `0.0`; calling it with several critical findings returns a meaningfully higher score.
- If the model file is deleted, corrupted, or scikit-learn isn't installed, `predict_risk()` still returns a complete, valid result (via the rule-based fallback) instead of crashing.
- `predicted_probability` and `risk_score` are always reported as clearly distinct fields with distinct ranges - never conflated.
- Running `app.ml.predict_cli` against a real scan-uuid from `app.security.ingest` successfully reads that scan's stored features and writes a prediction back tied to the same scan.

### Manual Steps You Need to Perform

1. (Optional) Re-run `python -m app.ml.train` if you'd like to see the training process yourself or experiment with `n_samples`/`noise_level` in `dataset.py`.
2. When you're ready to connect this to the FastAPI backend and dashboard, that wiring happens in Phase 8, per the roadmap - for now, `predict_cli.py` is the way to exercise the prediction path end-to-end.

---

## Phase 7: Explainable AI and Security Recommendations

### Two clearly-separate explanation methods

Whichever predictor produced a risk prediction (Phase 6), this phase explains it - but the explanation method always matches how the prediction was actually made, and is always labeled accordingly:

- **`shap_tree_explainer`** - used when the trained Random Forest made the prediction. [SHAP](https://shap.readthedocs.io/)'s `TreeExplainer` computes each feature's *exact* mathematical contribution to that specific prediction, straight from the real trained model. These are genuine SHAP values, verified to sum exactly to the model's actual predicted probability (checked directly while building this phase).
- **`rule_based_breakdown`** - used when the rule-based fallback made the prediction (no trained model available). There's no model to run SHAP against, so this decomposes the transparent scoring formula (`app.ml.dataset.rule_based_risk_score`) into its exact additive terms for that specific input. This is a real breakdown of that formula - **never** mislabeled as a SHAP value.

Both produce the same output shape (a ranked list of `{feature, value, contribution, direction}`, plus a plain-language `summary`), so the rest of the app can treat them identically without caring which one ran.

### New module: `backend/app/xai/`

| File | Responsibility |
|---|---|
| `explainer.py` | `explain_prediction()` - dispatches to SHAP or the rule breakdown depending on how the prediction was made |
| `labels.py` | Plain-language names for each feature, used in the generated summary sentences |
| `recommendations.py` | `generate_recommendations()` - turns actual findings into prioritized, linked remediation suggestions |
| `models.py` | New tables: `Explanation`, `RecommendationSet` (one row each per scan) |
| `repository.py` | Save/retrieve explanations and recommendation sets |
| `explain_cli.py` | CLI that ties Phases 5 + 6 + 7 together: loads a scan's stored features/findings, predicts, explains, generates recommendations, stores everything |

### The Recommendation Engine

- Every **CRITICAL** and **HIGH** severity finding gets its own specific, actionable recommendation, explicitly linked back to the finding that produced it (`source`, `identifier`, `component`).
- **MEDIUM** and **LOW** findings are summarized by count rather than listed individually, so the output stays focused - a real scan can have 50+ low-severity findings, and listing every one would bury what actually matters.
- Recommendations are tailored by finding type:
  - Container OS-package vulnerabilities (Trivy) → "rebuild the Docker image"
  - Dependency vulnerabilities (Trivy language packages, OWASP Dependency-Check) → "upgrade the package"
  - Code-quality/security issues (SonarQube) → "review and remediate the code"
  - No fix currently available → an honest "track this for a future release" note, **never** a fabricated version number
- **This module only produces text recommendations.** It never modifies source code, dependency files, or Docker images - all remediation requires a developer to actually read the recommendation and act on it.

### Example: Real Output From This Project

Running the full chain (`app.security.ingest` → `app.xai.explain_cli`) against the sample reports actually produces (captured verbatim from a real run):

> **Predicted category: High** (method: `shap_tree_explainer`)
> "This build was classified as High risk, primarily driven by the number of critical-severity vulnerabilities (2.0), which raised the assessed risk, the total number of findings across all scanners (9.0), which raised the assessed risk, and the number of high-severity vulnerabilities (3.0), which raised the assessed risk (based on the trained model's learned patterns)."
>
> `[CRITICAL] Rebuild the Docker image to update zlib1g from 1:1.2.13.dfsg-1 to 1:1.3.dfsg-3, which fixes CVE-2023-45853.`
> `[HIGH] No fixed version is currently available for CVE-2022-11111 in example-jwt-lib-1.2.0.tar.gz. Track this dependency for a security release.`

The full machine-readable version of this example is saved at `reports/samples/sample-explanation-and-recommendations.json` - generated by actually running the real modules, not hand-written.

### Trying It Out Locally

**Run the automated tests** (18 new tests: SHAP contributions and their sum-to-probability guarantee, the rule-breakdown fallback, direction-of-effect correctness, every recommendation category, and full Phase 5→6→7 integration against a real stored scan):

```bash
cd backend
source venv/bin/activate
pytest tests/ -v
```

You should see 76 tests pass in total (58 from before + 18 new).

**Run the full explain + recommend chain for a stored scan:**

```bash
python -m app.security.ingest --app-name healthsec-demo --trivy-report ../reports/trivy/trivy-report.json --dependency-check-report ../reports/dependency-check/dependency-check-report.json --sonarqube-report ../reports/sonarqube/sonarqube-report.json
# copy the printed scan UUID, then:
python -m app.xai.explain_cli --scan-uuid <uuid>
```

### What to Expect at the End of Phase 7

- Every explanation's `predicted_category` matches the prediction it was generated from - they're computed together in one call, never independently.
- SHAP contributions for a given prediction sum (with the model's base rate) to exactly that prediction's probability - verified directly while building this module.
- The rule-based breakdown's terms sum to exactly the same `risk_score` produced by `rule_based_risk_score` - it's a decomposition of that literal formula.
- Every recommendation names a real, specific finding (CVE ID, SonarQube rule, or dependency name) - nothing generic or fabricated.
- Findings without a known fix get honest "no fix available yet" guidance instead of an invented version number.

### Manual Steps You Need to Perform

None required beyond what earlier phases already asked for - this phase only adds new Python modules and database tables, all exercised by the CLI and test suite above.

---

## Phase 8: FastAPI Backend and Deployment Decision Engine

This phase connects everything from Phases 5-7 into real REST APIs, and adds the deployment decision engine that gates whether a build is allowed to deploy.

### New module: `backend/app/deployment/`

| File | Responsibility |
|---|---|
| `policy.py` | `decide_deployment()` - the configurable policy itself |
| `models.py` | `DeploymentRecord` table (one row per scan) |
| `repository.py` | Save/retrieve deployment decisions, list history |

### The Deployment Policy (configurable)

Default behavior, in the order it's actually evaluated:

1. **Invalid/unrecognized risk category** (e.g. the prediction pipeline failed) → **blocked**. Never defaults to approval just because a category couldn't be determined.
2. **Any mandatory scanner's status isn't exactly `"ok"`** (missing, invalid, or `tool_unavailable`) → **blocked**, *regardless of the predicted risk level*. A scan that didn't actually run is not evidence of safety - this is the core requirement from the Phase 1 policy design, and it's enforced before risk category is even considered.
3. Otherwise, by risk category:
   - **Low** → `approved`
   - **Medium** → `review_required` (a human must approve)
   - **High** → `blocked`

Which scanners are "mandatory" is configurable via the `DEPLOYMENT_MANDATORY_SCANNERS` environment variable (comma-separated; defaults to `trivy,dependency_check,sonarqube`) - see `backend/.env.example`.

### New REST API (Phase 8)

All endpoints require the same JWT bearer authentication as `/patients`. Full reference: **`backend/API_DOCUMENTATION.md`**, or the live interactive docs at `http://localhost:8000/docs`.

| Method | Path | Purpose |
|---|---|---|
| POST | `/scans` | Submit scan reports → runs the full pipeline → returns everything |
| GET | `/scans` | Scan history (filterable by application) |
| GET | `/scans/{uuid}` | Scan summary + features |
| GET | `/scans/{uuid}/findings` | Vulnerability details |
| GET | `/scans/{uuid}/prediction` | Risk prediction |
| POST | `/scans/{uuid}/predict` | Regenerate prediction/explanation/recommendations/decision |
| GET | `/scans/{uuid}/explanation` | AI explanation |
| GET | `/scans/{uuid}/recommendations` | Security recommendations |
| GET | `/scans/{uuid}/deployment-decision` | Deployment decision |
| GET | `/applications` | List applications |
| GET | `/deployments` | Deployment history across all scans |
| GET | `/dashboard/stats?application_name=X` | Overview stats for one application |

A single `POST /scans` call does the work of Phases 5 through 8 in one request: parses whichever reports were submitted (a missing report is recorded as `"missing"`, never silently treated as clean), stores the scan/findings/features, runs risk prediction, generates the SHAP or rule-based explanation, builds recommendations, and applies the deployment policy - then stores and returns all of it together.

### Trying It Out Locally

**Run the automated tests** (27 new tests: the policy engine's every branch - including the two critical rules that mandatory-check failures and invalid predictions always block regardless of risk - plus full HTTP-level API tests covering authentication enforcement, validation, the complete submit → retrieve flow, 404 handling, and dashboard stats edge cases):

```bash
cd backend
source venv/bin/activate
pytest tests/ -v
```

You should see 103 tests pass in total (76 from before + 27 new).

**Try the API directly:**

```bash
# Start the backend (Docker Compose or locally - see Phase 2/3 instructions)
# Then log in:
curl -X POST http://localhost:8000/auth/login \
  -d "username=demo_doctor&password=ChangeMe123!"

# Submit a scan using the sample reports:
curl -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"app_name": "healthsec-demo", "trivy_report": <contents of reports/samples/sample-trivy-report.json>, ...}'
```

Or simply open `http://localhost:8000/docs`, click **Authorize**, log in, and try `POST /scans` interactively - Swagger UI will let you paste the sample report JSON directly into the request body.

### What to Expect at the End of Phase 8

- `POST /scans` with all three sample reports returns a complete result: a "High" risk category, a real SHAP-based explanation, 5 linked recommendations, and a `"blocked"` deployment decision - verified against a real running server over real HTTP, not just through the test client.
- `POST /scans` with **no reports at all** still succeeds (HTTP 201), records every scanner as `"missing"`, and returns a `"blocked"` deployment decision with `mandatory_checks_passed: false` - proving missing data can never slip through as an approval.
- Every `/scans/{uuid}/...` endpoint returns `404` for a nonexistent scan UUID, and `401` for any request without a valid token.
- `/docs` and `/openapi.json` are live and reflect the real API.

### Manual Steps You Need to Perform

1. If you want stricter or looser policy behavior, edit `DEPLOYMENT_MANDATORY_SCANNERS` in `backend/.env` (e.g. to make only Trivy mandatory, set it to `trivy`).
2. When you get to Phase 9, the React dashboard will call these same endpoints - no backend changes should be needed for that phase.

---

## Phase 9: React Dashboard Development

### One small backend addition (explained)

`GET /deployments` previously returned only `scan_id` for each decision, with no way to tell which application or commit it belonged to. The Deployment History dashboard section genuinely needs that context, so the endpoint now also returns `scan_uuid`, `application_name`, and `commit_sha` for each entry. This is purely additive - no existing field, endpoint, or filename changed, and all Phase 8 tests still pass unmodified except one assertion that now also checks the new fields.

### New Frontend Pages and Components

| File | Responsibility |
|---|---|
| `pages/Dashboard.jsx` | The main dashboard page - owns all state, fetches data, composes every section below |
| `components/NavBar.jsx` | Shared navigation between Patients and the Security Dashboard |
| `components/LoadingSpinner.jsx`, `ErrorMessage.jsx` | Reusable loading/error states, used independently by every section |
| `components/dashboard/ApplicationSelector.jsx` | Dropdown populated from `GET /applications` - no hardcoded app names |
| `components/dashboard/OverviewSection.jsx` | Total scans, critical/high counts, latest risk score, deployment status |
| `components/dashboard/ScanHistoryTable.jsx` | Scan history table + a real risk-score trend line chart |
| `components/dashboard/SecurityReportsSection.jsx` | Severity bar chart + full findings table (CVE, component, CVSS, fix availability) |
| `components/dashboard/RiskAssessmentSection.jsx` | Risk score bar, category, model confidence, model used, timestamp |
| `components/dashboard/ExplainableAISection.jsx` | Horizontal bar chart of feature contributions + the plain-language summary |
| `components/dashboard/RecommendationsSection.jsx` | Prioritized, finding-linked recommendation list |
| `components/dashboard/DeploymentDecisionCard.jsx` | This scan's approve/review/block decision and reason |
| `components/dashboard/DeploymentHistoryTable.jsx` | Global deployment history across all applications |

### How Data Flows (no hardcoded values anywhere)

1. On load, the dashboard fetches `GET /applications` and auto-selects the first real application returned - never a hardcoded name.
2. Selecting an application fetches `GET /dashboard/stats` (Overview) and `GET /scans` (scan history) for it, and auto-selects the most recent scan.
3. The risk-score trend chart is built by fetching the real stored prediction (`GET /scans/{uuid}/prediction`) for each of the last 10 scans.
4. Selecting any scan fetches its features, findings, prediction, explanation, recommendations, and deployment decision - five real API calls, rendered as five sections.
5. Deployment History loads once from `GET /deployments` and reflects every decision ever made, across every application.

Every section handles its own loading and error state independently (see `LoadingSpinner`/`ErrorMessage` usage in `Dashboard.jsx`) - a slow or failed request in one section never blocks the others.

### Trying It Out Locally

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Log in, click **Security Dashboard** in the nav bar. If you haven't submitted any scans yet, you'll see "No applications have been scanned yet" - submit one first:

```bash
curl -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer <token-from-login>" \
  -H "Content-Type: application/json" \
  -d @- << 'EOF'
{"app_name": "healthsec-demo", "trivy_report": <paste reports/samples/sample-trivy-report.json here>, ...}
EOF
```

or more simply, use the Swagger UI at `http://localhost:8000/docs` → **POST /scans** → paste the contents of the three `reports/samples/sample-*.json` files into the request body. Refresh the dashboard afterward.

### What to Expect at the End of Phase 9

- The dashboard shows real data pulled from the API - verified directly: I checked the exact JSON shape returned by `/dashboard/stats` and the enriched `/deployments` against what each component destructures, and ran the actual Vite dev server to confirm the app builds and serves without errors.
- With zero scans submitted, the dashboard shows a clear "no applications scanned yet" message instead of breaking or showing fabricated data.
- Charts (severity bar chart, feature-contribution chart, risk-score trend line) render from real numbers - none of the values are hardcoded in the frontend.
- The layout is responsive: stat cards reflow from 4 columns to 2 to 1 as the viewport narrows, and wide tables scroll horizontally rather than breaking the page layout.

### Manual Steps You Need to Perform

1. Submit at least one scan (via `curl` or the Swagger UI, as shown above) so the dashboard has real data to display.
2. `npm install` in `frontend/` to pull in the new `recharts` dependency before running `npm run dev` or `npm run build`.

---

## Phase 10: AWS Deployment and CI/CD Automation

**Full step-by-step instructions live in [`AWS_DEPLOYMENT.md`](./AWS_DEPLOYMENT.md).** This section is a summary of what was built and why.

### What Runs Where

| Component | Local (Phases 1-9) | AWS (Phase 10) |
|---|---|---|
| Backend, Frontend, PostgreSQL | Docker Compose on your machine | Docker Compose on one EC2 instance |
| PostgreSQL exposure | `127.0.0.1` only | `127.0.0.1` only - **never public**, in both environments |
| CI/CD pipeline | Runs on GitHub's servers regardless | Same pipeline additionally builds/pushes images and deploys over SSH |

**The project remains fully usable locally with zero AWS involvement** - none of Phase 10 is required for Phases 1-9 to work.

### New Files

| File | Responsibility |
|---|---|
| `backend/app/deployment/gate_cli.py` | The automated deployment gate - reuses the exact same Phase 5-8 pipeline (parse → predict → decide) the FastAPI backend uses, so CI's decision is guaranteed to match the backend's |
| `docker-compose.prod.yml` | Production compose file - pulls prebuilt images from GHCR instead of building locally |
| `frontend/Dockerfile.prod` + `frontend/nginx.conf` | Production frontend image: real Vite build served by nginx (the existing `frontend/Dockerfile` still runs the dev server, unchanged, for local use) |
| `.env.prod.example` | Template for the server's real secrets file (never committed) |
| `infra/ec2-setup.sh` | One-time script to install Docker on a fresh EC2 instance |
| `infra/deploy.sh` | Pulls the latest approved images and restarts containers - run remotely by CI over SSH |
| `AWS_DEPLOYMENT.md` | Full setup guide: EC2, IAM, security groups, GitHub Secrets/Environments |

### The Automated Deployment Gate

Three new jobs were added to `.github/workflows/devsecops-pipeline.yml` (all restricted to pushes to `main`, never pull requests or other branches):

1. **`build-and-push-images`** - builds and pushes backend/frontend images to GitHub Container Registry (using the automatic `GITHUB_TOKEN` - no AWS or registry credentials needed in GitHub Secrets at all, since deployment itself happens over SSH, not the AWS API).
2. **`deployment-gate`** - downloads this run's real scan reports and runs `gate_cli.py`, which is literally the same decision engine as `POST /scans`. If the decision is **blocked**, this job's step exits non-zero, which fails the job - and because `deploy` requires this job to succeed, deployment is skipped automatically. No extra "was it blocked" check needed anywhere else.
3. **`deploy`** - only reachable if the gate passed. Routes to one of two GitHub Environments based on the decision: `production` (instant, for auto-**approved** Low-risk builds) or `production-review` (requires a human to click "Approve" in the Actions tab, for **review_required** Medium-risk builds) - configured once in the repo's Settings, not in code. It then copies `docker-compose.prod.yml` and `infra/deploy.sh` to the server and runs the deploy script over SSH.

This directly satisfies the core requirement: **only approved (or explicitly human-approved) builds can ever reach the deploy step; blocked builds cannot, structurally, not just by convention.**

### What I Actually Verified

- Ran the real `gate_cli.py` against the real sample reports (`reports/samples/`): correctly blocked (exit code 1) with `risk_category: "High"`, exactly matching Phase 8's API behavior for the same data.
- Ran it again against hand-built clean reports: correctly approved (exit code 0), and confirmed it writes `decision=approved` to a `$GITHUB_OUTPUT`-style file exactly as GitHub Actions expects.
- 4 new automated tests (run as real subprocesses, since the script calls `sys.exit`) cover the blocked, approved, and all-reports-missing cases, and confirm `deployment_decision.json` is written even when the gate fails.
- Validated the full extended workflow YAML parses correctly and has the expected job dependency graph (`deploy` needs both `build-and-push-images` and `deployment-gate`).
- Validated `docker-compose.prod.yml` parses correctly and confirmed PostgreSQL is still bound to `127.0.0.1` only.

**What I could not verify here:** actually provisioning AWS resources, or building/pushing the Docker images - this sandbox has no AWS credentials, no network access to AWS or GHCR, and no Docker daemon available. The workflow and scripts are correctly configured and will work once you follow `AWS_DEPLOYMENT.md` on a real GitHub repo with a real EC2 instance - that real-world verification is a manual step for you.

### Manual Steps You Need to Perform

Everything in `AWS_DEPLOYMENT.md`: launch the EC2 instance, allocate an Elastic IP, set up IAM, run `infra/ec2-setup.sh` once, create `/opt/healthsec/.env.prod` on the server, make the GHCR packages public (or configure a registry login), and add the `EC2_HOST`/`EC2_SSH_USER`/`EC2_SSH_PRIVATE_KEY` secrets and `VITE_API_URL` variable in GitHub, plus the two GitHub Environments (`production`, `production-review`).

---

## Phase 11: Integration, Testing, and Final Demonstration

**Full details live in [`TESTING_AND_DEMONSTRATION.md`](./TESTING_AND_DEMONSTRATION.md).** This section is a summary.

### What Was Added

- **`reports/fixtures/`** - three sets of controlled, synthetic scanner report fixtures (clearly-labeled fake CVE IDs like `TEST-CVE-DEMO-0001`, never real vulnerability data) representing one fictional app, `patient-portal-demo`, at three points in time: low-risk, high-risk, and remediated.
- **`backend/tests/test_e2e_demonstration_scenarios.py`** - 6 new tests that exercise the *entire* system through the real HTTP API (not individual modules) to implement and automatically verify all three demonstration scenarios, plus direct checks that predictions correspond to their source data, explanations correspond to their predictions, and the deployment policy is followed correctly - including the core requirement that a mandatory-scanner failure blocks deployment even for an otherwise Low-risk, zero-findings build.
- **`reports/fixtures/demonstration-transcript.txt`** - the real, captured output of running the actual deployment gate CLI against all three scenarios (not hand-written).

### Test Suite: 113 Tests, All Passing

74 unit tests, 16 integration tests, and 23 end-to-end/API tests - see the full breakdown in `TESTING_AND_DEMONSTRATION.md`.

### The Three Scenarios, Actually Run

| Scenario | Risk Category | Decision | Verified |
|---|---|---|---|
| 1. Low-risk | Low | **approved** | ✅ real gate CLI run + automated test |
| 2. High-risk (controlled synthetic findings) | High | **blocked** | ✅ real gate CLI run + automated test |
| 3. Remediation (same findings fixed) | Low (down from High) | **approved** (up from blocked) | ✅ real gate CLI run + automated test comparing both scans |

### An Honest Note on Screenshots

I cannot generate real screenshots of the running dashboard - this environment has no browser. `TESTING_AND_DEMONSTRATION.md` includes exact steps for you to capture your own, along with a precise description of what each section will show for each scenario (verified via the real API responses, not guessed).

### Manual Steps You Need to Perform

1. Run through the three scenarios yourself (commands in `TESTING_AND_DEMONSTRATION.md`) and capture dashboard screenshots for your presentation.
2. Review the Known Limitations and Future Enhancements sections - these feed directly into Phase 12's final report.

---

## Phase 12: Final Documentation and Academic Presentation

**This is the final phase.** Three new top-level documents complete the project:

| File | Contents |
|---|---|
| **`PROJECT_REPORT.md`** | The complete academic report: introduction, problem statement, objectives, architecture, per-module implementation explanation, ML methodology, real model evaluation results, the Explainable AI component, testing/deployment process, limitations, and future enhancements |
| **`PRESENTATION_OUTLINE.md`** | A 16-slide presentation structure for a 12-15 minute academic presentation |
| **`DEMONSTRATION_SCRIPT.md`** | A minute-by-minute live demonstration script using the three real scenarios from Phase 11, with exact commands, what to say, and a fallback plan if a live run isn't possible |

Every figure in `PROJECT_REPORT.md` - the architecture diagram, the model evaluation table, the confusion matrix, the SHAP example, the test counts, the scenario outcomes - is pulled directly from what was actually built, run, and verified in Phases 1 through 11, not written fresh for the report. The model evaluation numbers, for instance, are copied verbatim from `backend/app/ml/model/evaluation_report.json`, which was generated by actually running `python -m app.ml.train`.

### Project Complete

All 12 phases are now implemented, tested, and documented:

| Phase | Deliverable |
|---|---|
| 1 | Architecture, requirements, roadmap |
| 2 | Runnable backend + frontend skeleton |
| 3 | Working healthcare demo app (patient CRUD) |
| 4 | DevSecOps CI/CD pipeline with 3 real scanners |
| 5 | Security data processing + database schema |
| 6 | Trained Random Forest risk model |
| 7 | SHAP explainability + recommendation engine |
| 8 | Full REST API + deployment decision engine |
| 9 | React dashboard, 6 live-data sections |
| 10 | AWS deployment automation + CI/CD gating |
| 11 | 113 automated tests, 3 verified demonstration scenarios |
| 12 | Final report, presentation outline, demonstration script |

### Manual Steps You Need to Perform

1. Read through `PROJECT_REPORT.md` and adapt the title page (team names, course, institution) for your submission.
2. If your submission requires a Word document or PDF rather than Markdown, ask and it can be converted.
3. Rehearse `DEMONSTRATION_SCRIPT.md` once against your own running instance before presenting live.
