from django.test import TestCase
from apps.simulation.runner import SimulationRunner
from apps.simulation.models import TestRun, TestCaseResult

class SimulationLabTestCase(TestCase):
    def test_run_benchmark_suite(self):
        runner = SimulationRunner()
        test_run = runner.run_suite(suite_name="Unit Test Benchmark")

        self.assertIsNotNone(test_run.run_id)
        self.assertEqual(test_run.total_cases, 16)
        self.assertEqual(test_run.passed_cases, 16)
        self.assertEqual(test_run.failed_cases, 0)

        # Check metrics dict
        m = test_run.metrics
        self.assertEqual(m['accuracy_pct'], 100.0)
        self.assertEqual(m['precision_pct'], 100.0)
        self.assertEqual(m['recall_pct'], 100.0)
        self.assertEqual(m['false_positives'], 0)
        self.assertEqual(m['false_negatives'], 0)

        # Check test case results persisted
        results = test_run.results.all()
        self.assertEqual(results.count(), 16)
