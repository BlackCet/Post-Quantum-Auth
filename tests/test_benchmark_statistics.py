import unittest

from analysis.benchmark import percentile_summary


class PercentileSummaryTests(unittest.TestCase):
    def test_reports_median_and_nearest_rank_p95(self):
        self.assertEqual(
            percentile_summary([1, 2, 3, 4, 5]),
            {"median": 3, "p95": 5, "min": 1, "max": 5},
        )

    def test_empty_samples_are_explicit(self):
        self.assertEqual(
            percentile_summary([]),
            {"median": None, "p95": None, "min": None, "max": None},
        )


if __name__ == "__main__":
    unittest.main()
