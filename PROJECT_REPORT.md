# Intelligent DevSecOps Risk Assessment Framework for Healthcare Software Delivery using Explainable AI

## Final Project Report

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Problem Statement](#2-problem-statement)
3. [Objectives](#3-objectives)
4. [Proposed System](#4-proposed-system)
5. [System Architecture](#5-system-architecture)
6. [Technology Stack](#6-technology-stack)
7. [Project Workflow](#7-project-workflow)
8. [Module-by-Module Implementation](#8-module-by-module-implementation)
9. [Machine Learning Methodology](#9-machine-learning-methodology)
10. [Model Evaluation Results](#10-model-evaluation-results)
11. [Explainable AI Component](#11-explainable-ai-component)
12. [Testing and Deployment Process](#12-testing-and-deployment-process)
13. [Known Limitations](#13-known-limitations)
14. [Future Enhancements](#14-future-enhancements)
15. [Conclusion](#15-conclusion)
16. [Appendix: Repository Structure](#16-appendix-repository-structure)

---

## 1. Introduction

Healthcare software - patient portals, electronic health record modules, clinical scheduling systems - handles sensitive personal health information, making it both a high-value target for attackers and subject to strict compliance expectations. Modern software delivery relies on CI/CD pipelines to ship code quickly, and DevSecOps practices integrate security scanning directly into that pipeline. In practice, however, security scanners (static analysis, dependency scanners, container scanners) each produce their own large, differently-formatted report full of severity codes and CVE identifiers, with no single place that turns this raw output into a clear, prioritized, and actionable answer to the question every team actually needs answered before deploying: **is this build safe to ship?**

This project builds a complete, working system that answers that question automatically. It integrates three real security scanners, a machine learning risk classifier, an Explainable AI layer, a rule-based recommendation engine, and a policy-driven deployment gate - all wired together end-to-end, from a `git push` through to an actual (or simulated) production deployment on AWS.

## 2. Problem Statement

In most academic and even many industry projects, security scan results are:

- **Manually reviewed**, if reviewed at all, rather than automatically aggregated.
- **Not prioritized** - a report with 200 findings gives no sense of what to fix first.
- **Not connected to a deployment decision** - passing or failing a build is left to human judgment, applied inconsistently.
- **Not explainable**, even when a risk score is produced - a number with no reasoning behind it is hard to trust or act on.

This project addresses all four gaps directly: aggregation, prioritization, automated policy-driven decisions, and explainability.

## 3. Objectives

1. Build a working healthcare demo application (synthetic patient-record CRUD) as the subject of the security assessment.
2. Automate security scanning (SAST, dependency scanning, container scanning) inside a real CI/CD pipeline.
3. Convert raw, heterogeneous scanner output into structured, comparable security features.
4. Train a Machine Learning model (Random Forest) to classify each build's risk as Low / Medium / High, with a supplementary 0-100 risk score.
5. Use Explainable AI (SHAP) so every prediction can be traced back to the specific findings that drove it.
6. Generate actionable, finding-linked remediation recommendations - never invented, always traceable.
7. Enforce a configurable, policy-based deployment gate that blocks unsafe builds automatically, and can never be bypassed by missing or failed data.
8. Visualize the entire pipeline on a React dashboard, backed entirely by live API data.
9. Automate deployment to AWS, gated by the same policy engine that powers the API.

## 4. Proposed System

A developer pushes code to GitHub. GitHub Actions builds the application, runs its test suite, builds a Docker image, and runs three security scanners: SonarQube (static analysis), Trivy (container image vulnerabilities), and OWASP Dependency-Check (third-party dependency vulnerabilities). The raw scanner reports are parsed into a normalized feature vector, stored in PostgreSQL, and fed into a trained Random Forest model, which outputs a risk category and a numeric score. SHAP explains which features drove that specific prediction. A rule-based recommendation engine maps the highest-impact findings to concrete remediation actions. A policy engine decides whether the build may deploy. All of this is exposed through a FastAPI backend and a React dashboard, and approved (or explicitly human-approved) builds are automatically deployed to AWS EC2.

## 5. System Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                              DEVELOPER WORKSTATION                        │
│                    (git push / pull request to GitHub)                   │
└───────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                    GITHUB ACTIONS (CI/CD pipeline)                        │
│  build-test-scan → build-and-push-images ┐                               │
│                   → deployment-gate ──────┴──→ deploy (SSH to EC2)        │
│  Runs: pytest, npm build, Docker build, SonarQube, Trivy, OWASP DC        │
└───────────────────────────────────┬─────────────────────────────────────┘
                                     │ raw JSON reports
                                     ▼
┌───────────────────────────────────────────────────────────────────────────┐
│              SECURITY DATA PROCESSING (Python, app/security/)             │
│  Parse (3 scanners) → normalize severities → deduplicate → compute        │
│  features (severity counts, max CVSS, failed checks, fix availability)    │
└───────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                         POSTGRESQL DATABASE                               │
│  users · patients · applications · scans · findings · scan_features ·     │
│  risk_predictions · explanations · recommendation_sets · deployment_decisions │
└───────────────────────┬───────────────────────────────┬─────────────────┘
                         │                               │
                         ▼                               ▼
┌────────────────────────────────────┐   ┌──────────────────────────────────┐
│   ML RISK PREDICTION (app/ml/)      │   │  EXPLAINABLE AI + RECOMMENDATIONS│
│   Random Forest (trained) or        │──▶│  (app/xai/) SHAP TreeExplainer   │
│   rule-based fallback               │   │  or rule breakdown + linked recs │
└────────────────────────────────────┘   └──────────────────────────────────┘
                         │                               │
                         └───────────────┬───────────────┘
                                          ▼
                     ┌───────────────────────────────────────┐
                     │  DEPLOYMENT DECISION ENGINE (app/deployment/) │
                     │  Low→approved · Medium→review · High→blocked │
                     │  Mandatory-check failure → always blocked     │
                     └───────────────────┬─────────────────────┘
                                          ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                    FASTAPI BACKEND (app/routers/)                         │
│  /scans  /applications  /deployments  /dashboard/stats  /patients         │
└───────────────────────┬───────────────────────────────┬─────────────────┘
                         │                               │
                         ▼                               ▼
┌────────────────────────────────────┐   ┌──────────────────────────────────┐
│      REACT DASHBOARD (frontend)     │   │   AWS EC2 (Docker Compose)       │
│  6 sections, all backed by live API │   │  backend + frontend + PostgreSQL │
│  data - no hardcoded values         │   │  (DB bound to 127.0.0.1 only)    │
└────────────────────────────────────┘   └──────────────────────────────────┘
```

## 6. Technology Stack

| Layer | Technology | Role |
|---|---|---|
| Version control / CI-CD | Git, GitHub, GitHub Actions | Source control and pipeline automation |
| Containerization | Docker, Docker Compose | Consistent packaging across local, CI, and AWS |
| Static analysis | SonarQube / SonarCloud | Code-level security and quality findings |
| Container scanning | Trivy | OS-package vulnerabilities in the built image |
| Dependency scanning | OWASP Dependency-Check | Third-party library vulnerabilities |
| Backend | Python, FastAPI, SQLAlchemy | REST API, ORM, business logic |
| Database | PostgreSQL (SQLite for automated tests) | Persistent storage for every domain table |
| Machine Learning | scikit-learn (Random Forest) | Risk classification |
| Explainable AI | SHAP | Per-prediction feature attribution |
| Frontend | React, Vite, Recharts | Interactive dashboard with real charts |
| Cloud | AWS EC2, IAM, (optional S3) | Hosting the deployed application |

## 7. Project Workflow

1. Developer pushes code → GitHub Actions triggers.
2. Backend tests run (pytest), frontend builds (`npm run build`), Docker image builds.
3. SonarQube, Trivy, and OWASP Dependency-Check scan the code/image; reports are validated and uploaded as artifacts.
4. Reports are parsed, severities normalized, duplicates removed, features computed.
5. Features are stored in PostgreSQL under a unique scan ID, tied to a unique application ID.
6. The trained Random Forest predicts a risk category and score (or the rule-based fallback does, if the model is unavailable).
7. SHAP explains the specific prediction; the recommendation engine builds finding-linked remediation suggestions.
8. The deployment policy engine decides: approved, review_required, or blocked - blocking automatically if any mandatory scanner failed, regardless of the risk score.
9. All of the above is retrievable via REST API and rendered on the React dashboard.
10. On a push to `main`, if the decision isn't "blocked," the pipeline deploys the newly-built images to AWS EC2 over SSH - through a GitHub Environment that pauses for human approval when the decision is "review_required."

## 8. Module-by-Module Implementation

### 8.1 Healthcare Demo Application (Phase 3)
A FastAPI + React application with JWT authentication and full CRUD for synthetic patient records, used purely to give the security framework something realistic to scan. Server-side validation rejects blank names and malformed emails.

### 8.2 DevSecOps Pipeline (Phase 4)
A GitHub Actions workflow (`.github/workflows/devsecops-pipeline.yml`) that installs dependencies, runs tests, builds the Docker image, and runs all three scanners. Missing SonarQube credentials degrade gracefully to a placeholder report rather than failing the whole pipeline. A validation script confirms every report is present and valid JSON before anything downstream trusts it.

### 8.3 Security Data Processing (Phase 5)
`app/security/` parses each scanner's distinct JSON schema into one common finding format, normalizes each tool's own severity vocabulary onto a shared CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN scale, removes duplicate findings (keeping the higher severity if they conflict), and computes eleven structured features per scan. Everything is persisted in four new tables: `applications`, `scans`, `findings`, `scan_features`.

### 8.4 Machine Learning Risk Prediction (Phase 6)
`app/ml/` trains a Random Forest classifier on a clearly-labeled **synthetic** dataset (see Section 9), and exposes a single `predict_risk()` function that transparently falls back to a deterministic, weighted-sum rule whenever the trained model is unavailable - so risk assessment never crashes and never silently returns nothing.

### 8.5 Explainable AI (Phase 7)
`app/xai/explainer.py` uses SHAP's `TreeExplainer` to compute genuine, per-prediction feature contributions when the Random Forest made the prediction, and a transparent decomposition of the fallback formula when it didn't - the two are never conflated, and the method used is always labeled explicitly in the output.

### 8.6 Recommendation Engine (Phase 7)
`app/xai/recommendations.py` turns every CRITICAL/HIGH finding into a specific, finding-linked recommendation (dependency upgrade, Docker image rebuild, or code review, depending on the finding's source), while MEDIUM/LOW findings are only counted, not individually listed. The engine only ever produces text - it never modifies code, dependencies, or images itself.

### 8.7 FastAPI Backend and Deployment Decision Engine (Phase 8)
`app/routers/security.py` and `app/routers/dashboard.py` expose the entire pipeline as REST APIs. `app/deployment/policy.py` implements the configurable policy: Low → approved, Medium → review_required, High → blocked, with mandatory-check failures and invalid predictions always blocking, checked *before* risk category is even considered.

### 8.8 React Dashboard (Phase 9)
Six sections (Overview, Security Reports, Risk Assessment, Explainable AI, Recommendations, Deployment History), each independently loading/erroring, all populated from live API calls - verified field-by-field against the real backend responses, with no hardcoded data anywhere in the final integrated dashboard.

### 8.9 AWS Deployment and CI/CD Automation (Phase 10)
Three additional GitHub Actions jobs build and push Docker images to GHCR, run the deployment gate (the same decision engine as the API, reused directly), and deploy over SSH to an EC2 instance - routed through one of two GitHub Environments depending on whether the decision was "approved" or "review_required." A "blocked" decision fails the gate job outright, which structurally prevents the deploy job from ever running - not merely by convention.

## 9. Machine Learning Methodology

**Dataset.** No public dataset maps security-scan feature vectors directly onto real deployment-risk outcomes - that would require sensitive, proprietary incident data organizations don't publish. This project therefore generates a **synthetic** dataset (`app/ml/dataset.py`): feature values are drawn from distributions shaped like real scan output (most scans have zero or a few critical findings; many low-severity findings are common), and the ground-truth label for each row comes from a documented, transparent scoring rule - not from any observed real-world outcome. 8% random label noise is added so the classification problem isn't trivially perfect.

**This is a stated, deliberate limitation, not an oversight.** A model trained on this data learns to approximate the rule it was labeled with, not real-world risk. The project does not claim otherwise anywhere in its documentation.

**Feature selection.** Eleven features are used: `critical_count`, `high_count`, `medium_count`, `low_count`, `max_cvss_score`, `max_cvss_score_missing` (a flag for when no CVSS data exists at all, rather than silently imputing zero), `vulnerable_dependency_count`, `container_vulnerability_count`, `failed_security_checks`, `fix_available_count`, `total_findings`.

**Target variable.** `risk_category` ∈ {Low, Medium, High}, a three-class classification target.

**Model.** `RandomForestClassifier` (scikit-learn), 200 trees, max depth 8, `class_weight="balanced"` to compensate for High-risk being the rarest class in the generated data, fixed `random_state=42` for full reproducibility.

**Training/evaluation split.** 2,000 samples, stratified 80/20 split (1,600 train / 400 test).

## 10. Model Evaluation Results

These are the actual results from running `python -m app.ml.train`, saved in `backend/app/ml/model/evaluation_report.json` - not hand-written figures.

| Class | Precision | Recall | F1-score | Support |
|---|---|---|---|---|
| Low | 0.850 | 0.850 | 0.850 | 206 |
| Medium | 0.776 | 0.888 | 0.828 | 152 |
| High | 0.800 | 0.381 | 0.516 | 42 |
| **Accuracy** | | | **0.815** | 400 |

**Confusion matrix** (rows = true label, columns = predicted label, order Low/Medium/High):

```
              Predicted
              Low   Medium  High
Actual Low    175     29     2
       Medium  15    135     2
       High    16     10    16
```

**Honest interpretation.** Overall accuracy (81.5%) is respectable for a first-pass model, but recall on the High class is notably weak (0.381) - the model misses more true High-risk builds than it correctly identifies. This is a direct consequence of High being the minority class in the generated data (only 42 of 400 test samples) even with class-balancing applied, and is documented plainly rather than hidden. This was observed directly during Phase 11: an early version of the high-risk demonstration fixture scored 88/100 by the deterministic rule, but the trained model initially classified it "Medium," not "High" - the fixture had to be strengthened with additional findings before the model confidently agreed with the rule. This real discrepancy, not a hypothetical one, is exactly why the system reports `risk_score` (the rule, always available) and `predicted_probability` (the model's own confidence) as two clearly separate values rather than treating them as interchangeable.

**Top feature importances:** `critical_count` (0.237), `total_findings` (0.145), `high_count` (0.142), `max_cvss_score` (0.139) - critical-severity findings dominate the model's decisions, consistent with how the rule-based training labels were constructed.

## 11. Explainable AI Component

Two distinct, never-conflated explanation methods are used, matching exactly how the prediction was made:

- **`shap_tree_explainer`** - used when the Random Forest made the prediction. SHAP's `TreeExplainer` computes each feature's exact mathematical contribution to that specific prediction. This was verified directly during development: for a real test input, the sum of each class's SHAP values plus the explainer's base rate reconstructs the model's actual `predict_proba` output to within floating-point precision.
- **`rule_based_breakdown`** - used when the rule-based fallback made the prediction. Since there's no model to explain, this decomposes the transparent scoring formula into its literal additive terms for that input - a real breakdown of that specific formula, never mislabeled as a SHAP value.

Both produce the same output shape (a ranked list of `{feature, value, contribution, direction}` plus a plain-language summary sentence), so the rest of the system treats them identically regardless of which one ran.

**Real example** (from `reports/fixtures/scenario-2-high-risk/`, captured verbatim):

> "This build was classified as High risk, primarily driven by the number of critical-severity vulnerabilities (4.0), which raised the assessed risk, the total number of findings across all scanners (9.0), which raised the assessed risk, and the number of high-severity vulnerabilities (2.0), which raised the assessed risk (based on the trained model's learned patterns)."

## 12. Testing and Deployment Process

### 12.1 Automated Test Suite

**113 automated tests, all passing**, spanning three levels:

| Level | Count | Example |
|---|---|---|
| Unit | 74 | Every branch of the deployment policy; every scanner parser's handling of missing/malformed input |
| Integration | 16 | The full parse→dedupe→feature pipeline against real sample reports; the CI gate script run as a real subprocess |
| End-to-end / API | 23 | Full HTTP-level submit→retrieve flow; the three demonstration scenarios below, run through the real API |

Full breakdown in `TESTING_AND_DEMONSTRATION.md`.

### 12.2 Demonstration Scenarios

Three controlled, synthetic scenarios (clearly-fake identifiers like `TEST-CVE-DEMO-0001`, never real vulnerability data) demonstrate the complete flow, each actually run and captured (`reports/fixtures/demonstration-transcript.txt`):

| Scenario | Risk Category | Decision |
|---|---|---|
| 1. Low-risk (clean build) | Low | **approved** |
| 2. High-risk (controlled synthetic findings) | High | **blocked** |
| 3. Remediation (same findings fixed) | Low | **approved** |

An automated test (`test_scenario_3_remediation_is_approved_and_improves_on_scenario_2`) numerically confirms the improvement from Scenario 2 to Scenario 3, not just visually.

### 12.3 CI/CD Pipeline

`.github/workflows/devsecops-pipeline.yml` runs on every push: build → test → scan → validate reports → (on `main`) build/push images, run the deployment gate, and deploy. The gate reuses the exact same decision code as the API - there is only one deployment policy implementation in the entire project.

### 12.4 AWS Deployment

Documented fully in `AWS_DEPLOYMENT.md`: a single EC2 instance runs the backend, frontend, and PostgreSQL via Docker Compose, with PostgreSQL bound to `127.0.0.1` only (never publicly exposed, verified by parsing the compose file), fronted by a security group that opens only SSH (restricted to an admin IP), port 80, and port 8000.

## 13. Known Limitations

- The ML model is trained on synthetic, rule-derived data, not real historical outcomes - it demonstrates the pipeline correctly but its accuracy figures reflect how well it approximates a hand-written rule, not real-world predictive power.
- The trained model and the rule-based score can disagree (observed directly during Phase 11 - see Section 10).
- SHAP explainability only covers the Random Forest path; the rule-based fallback has no "model" to explain.
- No database migration tool (e.g. Alembic) - schema changes to an existing database aren't handled gracefully.
- No automated frontend test suite - the dashboard is verified via successful builds and live field-matching against the backend, not automated UI tests.
- Single EC2 instance with no high availability, load balancing, or managed database.
- SonarQube requires manual account/token setup - the one scanner that isn't zero-configuration.
- The deployment policy's mandatory-scanner list is global, not per-application.
- No API rate limiting.

## 14. Future Enhancements

- Replace the synthetic training dataset with real, labeled historical scan/outcome data as it becomes available.
- Add LIME as an alternative explainability method alongside SHAP.
- Move to AWS RDS with Alembic migrations.
- Add a frontend test suite (Vitest + React Testing Library).
- Blue-green or rolling deployments instead of single-instance restarts.
- HTTPS via an Application Load Balancer and AWS Certificate Manager.
- Slack/email notifications when a build is blocked or needs review.
- Per-application deployment policy configuration.
- Role-based access control across applications.

## 15. Conclusion

This project delivers a complete, working, end-to-end DevSecOps risk assessment framework: three real security scanners feeding a real data-processing pipeline, a genuinely trained (and honestly evaluated) machine learning model, real SHAP-based explainability, a finding-linked recommendation engine, a policy engine that structurally cannot approve an unsafe or improperly-scanned build, a live dashboard, and an automated, gated path to AWS deployment - all backed by 113 passing automated tests and three fully-reproducible demonstration scenarios. Every claim in this report is traceable to code that was actually run during development, not just written.

## 16. Appendix: Repository Structure

See the root `README.md` for the complete, annotated folder structure and per-phase setup instructions. Key top-level documents:

| File | Contents |
|---|---|
| `README.md` | Full setup instructions for every phase |
| `API_DOCUMENTATION.md` | Complete REST API reference |
| `AWS_DEPLOYMENT.md` | Full AWS deployment guide |
| `TESTING_AND_DEMONSTRATION.md` | Test suite breakdown, demonstration scenarios, limitations |
| `PRESENTATION_OUTLINE.md` | Slide-by-slide presentation structure |
| `DEMONSTRATION_SCRIPT.md` | Live demonstration script with timing |
