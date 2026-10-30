"""
SentinelShield Safe Simulation Test Runner.
Evaluates pre-configured educational attack scenarios against the DetectionEngine,
records results, and computes confusion matrix accuracy metrics.
"""

import time
import uuid
from typing import Dict, Any, Optional

from apps.detections.engine import DetectionEngine
from apps.detections.models import AttackCategory
from apps.audit.utils import record_audit
from apps.audit.models import AuditAction
from .models import TestRun, TestCaseResult
from .scenarios import EDUCATIONAL_TEST_SCENARIOS

class SimulationRunner:
    """Executes safe local security scenarios without executing code."""

    def __init__(self, engine: Optional[DetectionEngine] = None):
        self.engine = engine or DetectionEngine()

    def run_suite(self, suite_name: str = "OWASP Top Web Signatures Benchmark", user=None) -> TestRun:
        start_time = time.perf_counter()
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"

        test_run = TestRun.objects.create(
            run_id=run_id,
            suite_name=suite_name,
            executed_by=user,
        )

        tp = 0
        tn = 0
        fp = 0
        fn = 0
        passed_count = 0
        failed_count = 0

        for scenario in EDUCATIONAL_TEST_SCENARIOS:
            c_start = time.perf_counter()

            inspection = self.engine.inspect_request(
                path=scenario.get('path', ''),
                query_string=scenario.get('query', ''),
                headers=scenario.get('headers', {}),
                body=scenario.get('body', ''),
                method=scenario.get('http_method', 'GET')
            )
            c_duration = round((time.perf_counter() - c_start) * 1000.0, 3)

            actual_classification = 'BLOCKED' if inspection.is_threat else 'ALLOWED'
            expected_classification = scenario['expected_classification']

            # Test passes if actual matches expected
            case_passed = (actual_classification == expected_classification)
            if case_passed:
                passed_count += 1
            else:
                failed_count += 1

            # Metric accounting
            is_attack_case = (scenario['category'] != AttackCategory.NORMAL)
            if is_attack_case:
                if inspection.is_threat:
                    tp += 1
                else:
                    fn += 1
            else:
                if inspection.is_threat:
                    fp += 1
                else:
                    tn += 1

            TestCaseResult.objects.create(
                test_run=test_run,
                case_id=scenario['case_id'],
                scenario_name=scenario['scenario_name'],
                category=scenario['category'],
                payload_sample=scenario.get('payload_sample', ''),
                target_component=scenario.get('target_component', 'query'),
                expected_classification=expected_classification,
                actual_classification=actual_classification,
                matched_rules=[m.rule_id for m in inspection.matched_rules],
                passed=case_passed,
                duration_ms=c_duration
            )

        total_cases = len(EDUCATIONAL_TEST_SCENARIOS)
        total_duration = round((time.perf_counter() - start_time) * 1000.0, 2)

        # Compute precision, recall, accuracy safely
        precision = round((tp / (tp + fp)) * 100.0, 2) if (tp + fp) > 0 else 0.0
        recall = round((tp / (tp + fn)) * 100.0, 2) if (tp + fn) > 0 else 0.0
        accuracy = round(((tp + tn) / total_cases) * 100.0, 2) if total_cases > 0 else 0.0

        metrics = {
            'true_positives': tp,
            'true_negatives': tn,
            'false_positives': fp,
            'false_negatives': fn,
            'precision_pct': precision,
            'recall_pct': recall,
            'accuracy_pct': accuracy,
            'pass_rate_pct': round((passed_count / total_cases) * 100.0, 2) if total_cases > 0 else 0.0
        }

        test_run.total_cases = total_cases
        test_run.passed_cases = passed_count
        test_run.failed_cases = failed_count
        test_run.duration_ms = total_duration
        test_run.metrics = metrics
        test_run.save()

        record_audit(
            actor=user,
            action=AuditAction.TEST_RUN,
            target_object=f"TestRun:{run_id}",
            metadata={'passed': passed_count, 'total': total_cases, 'accuracy': accuracy}
        )

        return test_run
