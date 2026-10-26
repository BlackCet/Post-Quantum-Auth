import json
import tempfile
import unittest
from pathlib import Path

from gateway.dashboard_data import load_tls_benchmark_reports


class TlsDashboardDataTests(unittest.TestCase):
    def test_loads_tls_reports_and_ignores_non_tls_json_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            results_dir = Path(temp_dir)
            (results_dir / "tls-pq-hybrid-tls.json").write_text(
                json.dumps([{"mode": "pq-hybrid-tls"}]),
                encoding="utf-8",
            )
            (results_dir / "benchmark_results.json").write_text(
                json.dumps([{"mode": "application-pqc"}]),
                encoding="utf-8",
            )

            self.assertEqual(
                load_tls_benchmark_reports(results_dir),
                [{
                    "filename": "tls-pq-hybrid-tls.json",
                    "results": [{"mode": "pq-hybrid-tls"}],
                }],
            )

    def test_rejects_report_with_invalid_top_level_shape(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "tls-invalid.json"
            report_path.write_text(json.dumps({"mode": "pq-hybrid-tls"}), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "must contain a JSON array"):
                load_tls_benchmark_reports(Path(temp_dir))

    def test_empty_report_directory_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertEqual(load_tls_benchmark_reports(Path(temp_dir)), [])


if __name__ == "__main__":
    unittest.main()
