"""
Writes a placeholder SonarQube report explaining that the real scan was
skipped because SONAR_TOKEN / SONAR_HOST_URL GitHub secrets were not
configured. Used only by the CI workflow, as a fallback step.
"""

import json
from pathlib import Path

OUTPUT_PATH = Path("reports/sonarqube/sonarqube-report.json")


def main(output_path: Path = OUTPUT_PATH):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            {
                "scanner": "sonarqube",
                "status": "unavailable",
                "reason": "SONAR_TOKEN or SONAR_HOST_URL GitHub secret not configured.",
                "issues": [],
                "quality_gate_status": None,
            },
            indent=2,
        )
    )
    print(f"Wrote placeholder SonarQube report to {output_path}")


if __name__ == "__main__":
    main()
