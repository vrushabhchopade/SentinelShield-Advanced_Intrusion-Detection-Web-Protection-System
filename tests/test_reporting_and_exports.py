from pathlib import Path
from django.test import TestCase
from django.conf import settings
from apps.reporting.generators import sanitize_csv_cell, export_events_csv, generate_pdf_report
from apps.reporting.models import PracticalReport
from apps.traffic.models import SecurityEvent, SecurityDecision
from apps.detections.models import AttackCategory

class ReportingAndExportsTestCase(TestCase):
    def test_csv_formula_injection_defense(self):
        # Formula indicators must be prepended with a quote to prevent execution in Excel/Calc
        self.assertEqual(sanitize_csv_cell("=1+1"), "'=1+1")
        self.assertEqual(sanitize_csv_cell("@SUM(A1:A10)"), "'@SUM(A1:A10)")
        self.assertEqual(sanitize_csv_cell("+cmd"), "'+cmd")
        self.assertEqual(sanitize_csv_cell("-100"), "'-100")
        self.assertEqual(sanitize_csv_cell("normal text"), "normal text")
        self.assertEqual(sanitize_csv_cell(None), "")

    def test_export_events_csv(self):
        SecurityEvent.objects.create(
            source_ip="192.0.2.1",
            sanitized_path="/test",
            decision=SecurityDecision.BLOCKED,
            category=AttackCategory.SQLI
        )
        csv_buffer = export_events_csv()
        content = csv_buffer.getvalue()
        self.assertIn("Event ID", content)
        self.assertIn("192.0.2.1", content)
        self.assertIn("BLOCKED", content)

    def test_generate_pdf_report(self):
        report = PracticalReport.objects.create(
            title="Test Practical Assessment",
            reporting_period="Test 24h",
            summary="Test summary for verification",
            metrics={'total_requests': 100, 'blocked_requests': 10, 'accuracy_pct': 99.2}
        )
        file_path = generate_pdf_report(report)
        self.assertTrue(file_path.endswith('.pdf'))
        full_path = Path(settings.MEDIA_ROOT) / file_path
        self.assertTrue(full_path.exists())
        self.assertGreater(full_path.stat().st_size, 1000)
