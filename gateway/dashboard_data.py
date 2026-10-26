import json
from pathlib import Path


def load_tls_benchmark_reports(results_dir: Path) -> list[dict]:
    reports = []
    for report_path in sorted(results_dir.glob("tls-*.json")):
        with report_path.open(encoding="utf-8") as report_file:
            results = json.load(report_file)
        if not isinstance(results, list) or any(
            not isinstance(result, dict) for result in results
        ):
            raise ValueError(
                f"TLS benchmark report {report_path} must contain a JSON array of objects."
            )
        reports.append({"filename": report_path.name, "results": results})
    return reports
