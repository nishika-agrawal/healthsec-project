"""
Checks whether each security scanner produced a valid, non-empty JSON
report, and writes a single manifest file summarizing the outcome.

IMPORTANT: this script does NOT decide whether a build is safe to deploy.
That decision belongs to the deployment policy engine (Phase 8). This
script's only job is to make scanner successes/failures visible as
structured data, instead of a missing or broken report silently being
treated as "no vulnerabilities found."
"""

import json
import sys
from pathlib import Path

DEFAULT_REPORTS_DIR = Path("reports")


def build_report_paths(reports_dir: Path) -> dict:
    return {
        "sonarqube": reports_dir / "sonarqube" / "sonarqube-report.json",
        "trivy": reports_dir / "trivy" / "trivy-report.json",
        "dependency_check": reports_dir / "dependency-check" / "dependency-check-report.json",
    }


def check_report(path: Path) -> dict:
    if not path.exists():
        return {
            "path": str(path),
            "found": False,
            "valid_json": False,
            "reason": "file not found",
        }

    content = path.read_text()
    if not content.strip():
        return {
            "path": str(path),
            "found": True,
            "valid_json": False,
            "reason": "file is empty",
        }

    try:
        json.loads(content)
    except json.JSONDecodeError as exc:
        return {
            "path": str(path),
            "found": True,
            "valid_json": False,
            "reason": f"invalid JSON: {exc}",
        }

    return {"path": str(path), "found": True, "valid_json": True, "reason": None}


def build_manifest(reports_dir: Path = DEFAULT_REPORTS_DIR) -> dict:
    paths = build_report_paths(reports_dir)
    return {scanner_name: check_report(path) for scanner_name, path in paths.items()}


def main(reports_dir: Path = DEFAULT_REPORTS_DIR):
    manifest = build_manifest(reports_dir)

    manifest_path = reports_dir / "report-manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print("Security report validation summary:")
    for scanner_name, result in manifest.items():
        status = "OK" if result["valid_json"] else "PROBLEM"
        detail = f" - {result['reason']}" if result["reason"] else ""
        print(f"  - {scanner_name}: {status} ({result['path']}){detail}")

    all_missing = all(not result["found"] for result in manifest.values())
    if all_missing:
        print(
            "ERROR: No security reports were found at all. "
            "The pipeline is likely misconfigured (check earlier steps)."
        )
        sys.exit(1)

    print(f"Manifest written to {manifest_path}")
    sys.exit(0)


if __name__ == "__main__":
    main()
