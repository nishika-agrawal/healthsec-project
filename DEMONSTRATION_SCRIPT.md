# Demonstration Script

A live walkthrough of the three scenarios from `TESTING_AND_DEMONSTRATION.md`, using the real API and dashboard. Every command and expected result below has actually been run during development - nothing here is hypothetical. Total time: roughly 5-7 minutes.

## Before You Present: Setup (do this once, beforehand)

```bash
# From the project root
docker compose up --build -d
```

Wait for it to be healthy:
```bash
curl http://localhost:8000/health
# {"status": "ok"}
```

Open two browser tabs: `http://localhost:8000/docs` (Swagger UI) and `http://localhost:5173` (the dashboard, logged in with `demo_doctor` / `ChangeMe123!`).

## Part 1: Explain the Setup (30 seconds)

Say: *"This is `patient-portal-demo`, a fictional application. I'm going to submit three scans for it - a clean one, one with controlled, synthetic vulnerabilities I've constructed for this demo, and a remediated one - and show the system detect, explain, and clear each one automatically."*

## Part 2: Scenario 1 - Low Risk (1 minute)

In Swagger UI, `POST /scans`, with:
```json
{
  "app_name": "patient-portal-demo",
  "commit_sha": "v1.0.0-lowrisk",
  "trivy_report": /* paste reports/fixtures/scenario-1-low-risk/trivy-report.json */,
  "dependency_check_report": /* paste .../dependency-check-report.json */,
  "sonarqube_report": /* paste .../sonarqube-report.json */
}
```

**Say while it runs:** *"This submits all three scan reports at once. The backend parses them, computes features, runs the ML model, generates an explanation, builds recommendations, and applies the deployment policy - all in this one call."*

**Point out in the response:** `"risk_category": "Low"`, `"decision": "approved"`.

Switch to the dashboard, select `patient-portal-demo`, the `v1.0.0-lowrisk` scan. **Point out:** 0 critical/0 high in Overview, the near-empty risk score bar, the green "Approved" badge.

## Part 3: Scenario 2 - High Risk (2 minutes)

Same `POST /scans`, this time with the `scenario-2-high-risk` fixtures and `commit_sha: "v1.1.0-highrisk"`.

**Say:** *"This scenario has a controlled critical vulnerability I constructed - labeled `TEST-CVE-DEMO-0001`, not a real CVE - plus a couple of other synthetic findings, so we can see the full pipeline react to something serious."*

**Point out in the response:** `"risk_category": "High"`, `"decision": "blocked"`, and the `reason` field explaining why.

Switch to the dashboard:
- **Security Reports:** the severity bar chart, dominated by the critical bar; the findings table showing `TEST-CVE-DEMO-0001` and the others, each with its CVSS score and fix availability.
- **Risk Assessment:** the score bar at 100, red.
- **Explainable AI:** *"This chart shows real SHAP values from the trained Random Forest - each bar is that feature's actual mathematical contribution to this specific prediction, not a hand-picked example."* Point out `critical_count` as the largest bar, increasing risk, and read the plain-language summary sentence.
- **Recommendations:** *"Six recommendations, each linked to a specific finding - a Docker rebuild, two dependency upgrades, and a code review - the system never invents a fix; if none is published yet, it says so honestly instead."*
- **Deployment Decision:** the red "Blocked" badge.

## Part 4: Scenario 3 - Remediation (1.5 minutes)

Same `POST /scans`, with `scenario-3-remediated` fixtures and `commit_sha: "v1.2.0-remediated"`.

**Say:** *"Same application, same findings - now fixed. Watch what changes."*

**Point out in the response:** `"risk_category": "Low"` (down from High), `"decision": "approved"` (up from blocked).

Switch to the dashboard: the Scan History risk-trend line chart visibly drops from 100 back to 0. Scroll to **Deployment History** (bottom of the page) and point out the `v1.1.0-highrisk` row (Blocked) and `v1.2.0-remediated` row (Approved) side by side.

**Say:** *"This entire before/after comparison is also an automated test in the project's test suite - `test_scenario_3_remediation_is_approved_and_improves_on_scenario_2` - so this isn't just a manual demo, it's verified automatically on every test run."*

## Part 5: The Deployment Gate in CI (1 minute, optional if time allows)

If showing the CI/CD pipeline itself:

```bash
cd backend
python -m app.deployment.gate_cli \
  --app-name patient-portal-demo --commit-sha v1.1.0-highrisk \
  --trivy-report ../reports/fixtures/scenario-2-high-risk/trivy-report.json \
  --dependency-check-report ../reports/fixtures/scenario-2-high-risk/dependency-check-report.json \
  --sonarqube-report ../reports/fixtures/scenario-2-high-risk/sonarqube-report.json
echo "Exit code: $?"
```

**Point out:** the script exits with code `1` for the blocked build. **Say:** *"This exact script runs inside the GitHub Actions pipeline. A nonzero exit code here fails that job, and because the actual deployment job depends on this one succeeding, GitHub Actions skips deployment automatically - it's not just application logic saying 'don't deploy,' the CI system itself structurally cannot proceed."*

## Closing (30 seconds)

**Say:** *"To summarize: three real scanners, a real trained model with honestly-reported accuracy, real SHAP explanations, and a deployment policy that's enforced structurally, not just by convention - all backed by 113 automated tests, three of which are this exact demonstration, run automatically on every commit."*

---

## If Something Doesn't Work Live

- **Backend not responding:** `docker compose ps` to check container status; `docker compose logs backend --tail=50`.
- **Dashboard shows "no applications scanned yet":** confirm at least one `POST /scans` succeeded (check Swagger UI's response was `201`, not an error).
- **Fallback plan:** `reports/fixtures/demonstration-transcript.txt` contains the real, captured output of all three scenarios if a live run isn't possible - present that instead and explain it was captured during development.
