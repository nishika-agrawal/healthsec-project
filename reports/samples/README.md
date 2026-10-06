# Sample Security Reports

**These files are illustrative/synthetic examples only.** They were written by hand to match
the real, documented JSON output format of each tool (Trivy, OWASP Dependency-Check, and this
project's own SonarQube report format from `scripts/fetch_sonarqube_report.py`). They were **not**
produced by an actual scan of this project's code or Docker image.

They exist so that:
- Phase 5 (security data processing) can be developed and unit-tested before a real GitHub
  Actions pipeline run has produced real reports.
- You can see what "real" scanner output looks like without needing SonarCloud/Trivy/OWASP
  Dependency-Check installed locally.

Once your GitHub Actions pipeline runs (Phase 4), download the `security-reports-<sha>` artifact
from the Actions tab to get **real** reports for your actual code, and use those going forward.

| File | Represents |
|---|---|
| `sample-trivy-report.json` | Trivy's real JSON schema for a container image scan |
| `sample-dependency-check-report.json` | OWASP Dependency-Check's real JSON report schema |
| `sample-sonarqube-report.json` | The output format of `scripts/fetch_sonarqube_report.py` |
| `sample-report-manifest.json` | The output format of `scripts/validate_reports.py` |
