"""
CI/CD deployment gate (Phase 10).

Run inside the GitHub Actions pipeline, after the security scanners have
produced their reports. Reuses the EXACT same pipeline the FastAPI
backend uses (Phases 5-8: parse reports -> extract features -> predict
risk -> apply the deployment policy), so the gate's decision is
guaranteed to match what the backend would compute for the same data -
there is only one decision engine in this project, not two.

Writes the decision to $GITHUB_OUTPUT (if running in GitHub Actions) so
downstream workflow steps/jobs can branch on it, and always writes
deployment_decision.json as a plain, inspectable artifact.

Uses a throwaway local SQLite database for this run only. This lets the
gate reuse the real repository/pipeline code (which expects a database)
without requiring the CI runner to have network access to the production
database. This is NOT the application's permanent record of the scan -
the deployed backend's own database (on the EC2 instance) holds that,
populated whenever scans are actually submitted to it. This script's job
is only to compute today's yes/no deployment answer.

Exit code:
    0  if the decision is "approved" or "review_required" - the workflow
       itself should proceed. For "review_required", the actual pause
       for human approval happens at the GitHub Environment level (see
       .github/workflows/devsecops-pipeline.yml), not in this script.
    1  if the decision is "blocked" - the workflow must stop here.
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Must be set BEFORE importing any app.* module, since app.database reads
# DATABASE_URL at import time.
os.environ.setdefault("DATABASE_URL", f"sqlite:///{Path.cwd()}/ci_gate.db")
os.environ.setdefault("JWT_SECRET_KEY", "ci-gate-run-not-used-for-authentication")

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.deployment import models as deployment_models  # noqa: E402,F401
from app.deployment import repository as deployment_repository  # noqa: E402
from app.deployment.policy import decide_deployment  # noqa: E402
from app.ml import models as ml_models  # noqa: E402,F401
from app.ml import repository as ml_repository  # noqa: E402
from app.ml.predictor import predict_risk  # noqa: E402
from app.security import models as security_models  # noqa: E402,F401
from app.security import repository as security_repository  # noqa: E402
from app.security.pipeline import process_reports  # noqa: E402


def write_github_output(name: str, value: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a") as f:
        f.write(f"{name}={value}\n")


def parse_args():
    parser = argparse.ArgumentParser(description="CI/CD automated deployment gate")
    parser.add_argument("--app-name", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--trivy-report", required=True)
    parser.add_argument("--dependency-check-report", required=True)
    parser.add_argument("--sonarqube-report", required=True)
    parser.add_argument(
        "--output-path",
        default="deployment_decision.json",
        help="Where to write the machine-readable decision (default: deployment_decision.json)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    Base.metadata.create_all(bind=engine)

    processed = process_reports(
        trivy_path=Path(args.trivy_report),
        dependency_check_path=Path(args.dependency_check_report),
        sonarqube_path=Path(args.sonarqube_report),
    )

    db = SessionLocal()
    try:
        application = security_repository.get_or_create_application(db, name=args.app_name)
        scan = security_repository.create_scan_with_results(
            db, application, commit_sha=args.commit_sha, processed=processed
        )

        prediction = predict_risk(processed.features)
        ml_repository.save_prediction(db, scan.id, prediction)

        decision = decide_deployment(prediction["risk_category"], processed.scanner_statuses)
        deployment_repository.save_deployment_decision(db, scan.id, decision)

        scan_uuid = scan.scan_uuid
    finally:
        db.close()

    result = {
        "scan_uuid": scan_uuid,
        "commit_sha": args.commit_sha,
        "scanner_statuses": processed.scanner_statuses,
        "risk_category": prediction["risk_category"],
        "risk_score": prediction["risk_score"],
        "decision": decision["decision"],
        "reason": decision["reason"],
        "mandatory_checks_passed": decision["mandatory_checks_passed"],
        "failed_checks": decision["failed_checks"],
    }

    Path(args.output_path).write_text(json.dumps(result, indent=2))

    print("=== Deployment Gate Result ===")
    print(json.dumps(result, indent=2))

    write_github_output("decision", decision["decision"])
    write_github_output("risk_category", prediction["risk_category"])

    if decision["decision"] == "blocked":
        print("\nDeployment BLOCKED - see reason above. The pipeline stops here.")
        sys.exit(1)

    print(f"\nDeployment gate passed with decision: {decision['decision']}")
    sys.exit(0)


if __name__ == "__main__":
    main()
