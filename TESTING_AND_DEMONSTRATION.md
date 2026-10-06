# Testing and Demonstration Guide (Phase 11)

This document covers Phase 11's deliverables: the test suite breakdown, the three demonstration scenarios (with exact commands to reproduce them), how to capture dashboard screenshots for your presentation, and an honest account of the project's known limitations and possible future enhancements.

## Test Suite Overview

**113 automated tests, all passing**, run with `cd backend && pytest tests/ -v`. Breakdown by kind:

### Unit tests (pure logic, no database, no HTTP) - 74 tests

Test one function/module in isolation with hand-built inputs:

| File | Tests | Covers |
|---|---|---|
| `test_deployment_policy.py` | 13 | Every branch of the deployment policy, including that mandatory-check failures and invalid risk categories always block, regardless of risk level |
| `test_security_parsers.py` | 13 | All three scanners' report parsers, both file- and data-based, including missing/malformed input |
| `test_ml_dataset.py` | 10 | The rule-based scoring formula and synthetic dataset generation/reproducibility |
| `test_xai_recommendations.py` | 9 | Every recommendation category (container update, dependency upgrade, code review, no-fix-available) |
| `test_security_features.py` | 8 | Feature computation from findings (severity counts, CVSS, ratings) |
| `test_xai_explainer.py` | 7 | SHAP contributions and the rule-based breakdown fallback |
| `test_ml_predictor.py` | 6 | Prediction with the trained model and the rule-based fallback (missing/corrupted model file) |
| `test_security_dedupe.py` | 4 | Duplicate-finding removal |
| `test_security_normalize.py` | 4 | Severity normalization across all three scanners' vocabularies |

### Integration tests (multiple components + real database) - 16 tests

Test that components actually work together correctly, using a real (throwaway SQLite) database:

| File | Tests | Covers |
|---|---|---|
| `test_deployment_gate_cli.py` | 4 | The CI/CD gate script end-to-end, run as real subprocesses |
| `test_security_pipeline.py` | 5 | The full parse → dedupe → feature pipeline against real sample reports |
| `test_ml_integration.py` | 2 | Phase 5's stored features flowing correctly into Phase 6's predictor |
| `test_xai_integration.py` | 2 | Phase 5 → 6 → 7 chained together with real database storage |
| `test_security_repository.py` | 3 | Database storage and retrieval for applications/scans/findings/features |

### End-to-end / API tests (full HTTP stack, real auth) - 23 tests

Exercise the actual running FastAPI application through real HTTP requests, exactly as a browser or `curl` would:

| File | Tests | Covers |
|---|---|---|
| `test_api_security.py` | 8 | Full submit → retrieve flow, authentication enforcement, validation, 404 handling, dashboard stats |
| `test_e2e_demonstration_scenarios.py` | 6 | The three demonstration scenarios below, plus direct verification that predictions/explanations/decisions all correspond correctly to their source data |
| `test_patients.py` | 7 | Patient CRUD, authentication, validation (Phase 3 - part of the same suite) |
| `test_health.py` | 2 | Basic liveness checks |

## The Three Demonstration Scenarios

All three use **controlled, synthetic fixture reports** (`reports/fixtures/`) representing one fictional application, `patient-portal-demo`, at three points in time. The "vulnerabilities" use identifiers like `TEST-CVE-DEMO-0001` - **these are not real CVEs**; they exist only so the demonstration has something concrete to detect, explain, and remediate. See `reports/fixtures/README.md`.

### Scenario 1: Low-Risk Application

**Setup:** a clean build - no findings from any scanner.

**Reproduce it:**
```bash
cd backend
source venv/bin/activate
python -m app.deployment.gate_cli \
  --app-name patient-portal-demo --commit-sha v1.0.0-lowrisk \
  --trivy-report ../reports/fixtures/scenario-1-low-risk/trivy-report.json \
  --dependency-check-report ../reports/fixtures/scenario-1-low-risk/dependency-check-report.json \
  --sonarqube-report ../reports/fixtures/scenario-1-low-risk/sonarqube-report.json
```

**Actual result** (captured verbatim - see `reports/fixtures/demonstration-transcript.txt` for the full output of all three scenarios):
```
risk_category: "Low"
decision: "approved"
reason: "Risk assessed as Low and all mandatory security checks passed."
exit code: 0
```

Or, to see it through the full dashboard: submit the same three files via `POST /scans` (Swagger UI at `/docs`, or `curl` - see `API_DOCUMENTATION.md`), then open the Security Dashboard and select `patient-portal-demo` → the `v1.0.0-lowrisk` scan. You'll see: Overview shows 0 critical/0 high, Risk Assessment shows "Low" with a near-empty score bar, Explainable AI's summary explains there's nothing driving risk up, Recommendations shows "No critical or high-severity findings require action," and the Deployment Decision card shows a green "Approved" badge.

### Scenario 2: High-Risk Application

**Setup:** the same app, now with a controlled critical vulnerability in a container package (`demo-vulnerable-lib`, `TEST-CVE-DEMO-0001`, appearing twice), a critical dependency vulnerability (`TEST-CVE-DEMO-0004`), a high-severity dependency (`TEST-CVE-DEMO-0002`, `TEST-CVE-DEMO-0005`), and a failing SonarQube quality gate with a critical code issue.

**Reproduce it:**
```bash
python -m app.deployment.gate_cli \
  --app-name patient-portal-demo --commit-sha v1.1.0-highrisk \
  --trivy-report ../reports/fixtures/scenario-2-high-risk/trivy-report.json \
  --dependency-check-report ../reports/fixtures/scenario-2-high-risk/dependency-check-report.json \
  --sonarqube-report ../reports/fixtures/scenario-2-high-risk/sonarqube-report.json
```

**Actual result:**
```
critical_count: 4, high_count: 2
risk_category: "High"
decision: "blocked"
reason: "Risk assessed as High. Deployment is blocked until the identified issues are remediated."
exit code: 1
```

On the dashboard: Overview shows 4 critical/2 high, the severity bar chart is dominated by the critical bar, Risk Assessment shows a full red score bar at 100, Explainable AI's chart shows `critical_count` as the largest bar (increasing risk) with a SHAP-based summary sentence, Recommendations lists 6 specific items spanning all three categories (rebuild the Docker image, upgrade two dependencies, review the code issue), and the Deployment Decision card shows a red "Blocked" badge with the reason above.

### Scenario 3: Remediation

**Setup:** the same app, with every finding from Scenario 2 fixed - the vulnerable package upgraded, the dependency upgraded, the code issue resolved.

**Reproduce it:**
```bash
python -m app.deployment.gate_cli \
  --app-name patient-portal-demo --commit-sha v1.2.0-remediated \
  --trivy-report ../reports/fixtures/scenario-3-remediated/trivy-report.json \
  --dependency-check-report ../reports/fixtures/scenario-3-remediated/dependency-check-report.json \
  --sonarqube-report ../reports/fixtures/scenario-3-remediated/sonarqube-report.json
```

**Actual result:**
```
risk_category: "Low" (down from "High")
risk_score: 0.0 (down from 100.0)
decision: "approved" (up from "blocked")
exit code: 0
```

On the dashboard: select `patient-portal-demo`, and the Scan History table's risk-trend line chart visibly drops from 100 back to 0 across the two commits. The Deployment History table (global, across all scans) shows the `v1.1.0-highrisk` row as "Blocked" and the `v1.2.0-remediated` row as "Approved," side by side - a direct before/after comparison.

`backend/tests/test_e2e_demonstration_scenarios.py::test_scenario_3_remediation_is_approved_and_improves_on_scenario_2` automates exactly this comparison and asserts the improvement numerically, not just visually.

## Capturing Dashboard Screenshots

**I can't generate real screenshots of the running dashboard myself** - this environment has no browser or display, only a code sandbox. What I've verified instead is that the dashboard correctly renders this exact data (see Phase 9's verification notes and the real HTTP responses above). To capture screenshots for your own submission:

1. Start the stack: `docker compose up --build` (from the project root).
2. Submit all three scenarios via `POST /scans` (Swagger UI at `http://localhost:8000/docs` is the easiest way - paste each scenario's three JSON files into one request body, with the matching `app_name`/`commit_sha` shown above).
3. Open `http://localhost:5173`, log in, click **Security Dashboard**.
4. For each of the three scans (switch between them in the Scan History table), screenshot：
   - The Overview section
   - The Security Reports section (severity chart + findings table)
   - The Risk Assessment section
   - The Explainable AI section (contribution chart + summary)
   - The Security Recommendations section
   - The Deployment Decision card
5. Screenshot the Deployment History table once, after all three scans are submitted, to show the before/after comparison in one view.

## Known Limitations

Documented honestly, for the final project report (Phase 12):

- **The ML model is trained on synthetic, rule-derived data** (see `app/ml/dataset.py`), not real historical outcomes. It demonstrates the full ML/XAI pipeline correctly, but its accuracy numbers (81.5% overall, notably weaker recall on the minority "High" class) reflect how well it approximates a hand-written rule, not real-world predictive power. This is stated directly in Phase 6's documentation and is not hidden.
- **The trained model and the rule-based score can disagree** (see Scenario 2's original fixture, which the rule scored "High" at 88/100 but the trained model initially classified "Medium"). This is real, observed model behavior, not a hypothetical - and it's exactly why the project reports both a `risk_score` (rule, always available) and a `predicted_probability` (model, when used) as clearly distinct values rather than conflating them.
- **SHAP explainability only covers the Random Forest path.** The rule-based fallback's "explanation" is a literal decomposition of its own formula, not a model explanation technique - there's no model to explain when the fallback is used.
- **No database migration tool (e.g. Alembic).** Tables are created with `Base.metadata.create_all()`, which is fine for a fresh setup but won't handle schema changes to an existing database gracefully.
- **No automated frontend test suite.** The React dashboard is verified via successful builds, live HTTP field-matching against the backend, and manual code review - not automated component/UI tests.
- **Single EC2 instance, no high availability.** If the instance goes down, so does the whole deployed app. There's no load balancer, auto-scaling, or managed database (RDS).
- **SonarQube requires manual setup** (SonarCloud account or self-hosted instance) - it's the one scanner that doesn't work purely out-of-the-box in CI without configuration.
- **The deployment policy's "mandatory scanners" list is global**, not configurable per-application.
- **No rate limiting or request throttling** on the API.

## Future Enhancements

- Replace the synthetic training dataset with real, labeled historical scan/outcome data as it becomes available, and re-evaluate the model's real-world accuracy honestly against it.
- Add LIME as an alternative/comparison explainability method alongside SHAP.
- Move to a managed database (AWS RDS) and add Alembic migrations for schema evolution.
- Add a frontend test suite (e.g. Vitest + React Testing Library).
- Add blue-green or rolling deployment instead of a single-instance restart.
- Add HTTPS via an Application Load Balancer + AWS Certificate Manager, instead of plain HTTP.
- Add Slack/email notifications when a deployment is blocked or needs review.
- Support per-application deployment policy configuration (different mandatory scanners or thresholds per app).
- Add role-based access control (currently every authenticated user has full access to every application's data).
