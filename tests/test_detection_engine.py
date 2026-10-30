from django.test import TestCase
from apps.detections.engine import DetectionEngine, safe_normalize_string
from apps.detections.models import AttackCategory, RuleSeverity, DetectionRule
from apps.detections.patterns import DEFAULT_RULES

class DetectionEngineTestCase(TestCase):
    def setUp(self):
        self.engine = DetectionEngine()

    def test_safe_normalize_string(self):
        # Normal string
        self.assertEqual(safe_normalize_string("test"), "test")
        # URL encoded
        self.assertEqual(safe_normalize_string("admin%27%20OR%201%3D1"), "admin' OR 1=1")
        # Plus encoded spaces
        self.assertEqual(safe_normalize_string("UNION+SELECT"), "UNION SELECT")
        # Backslash normalized to forward slash
        self.assertEqual(safe_normalize_string("..\\windows\\system32"), "../windows/system32")

    def test_clean_request_allowed(self):
        res = self.engine.inspect_request(
            path="/api/v1/search",
            query_string="q=python+security&page=1",
            headers={"User-Agent": "Mozilla/5.0"},
            body=""
        )
        self.assertFalse(res.is_threat)
        self.assertEqual(res.primary_category, AttackCategory.NORMAL)
        self.assertEqual(len(res.matched_rules), 0)

    def test_sql_injection_detection(self):
        # Union based
        res = self.engine.inspect_request(query_string="id=1 UNION SELECT username,password FROM auth_user")
        self.assertTrue(res.is_threat)
        self.assertEqual(res.primary_category, AttackCategory.SQLI)
        self.assertIn("SQLI-001", res.matched_rule_ids)

        # Boolean tautology
        res2 = self.engine.inspect_request(body="username=admin' OR '1'='1&password=123")
        self.assertTrue(res2.is_threat)
        self.assertEqual(res2.primary_category, AttackCategory.SQLI)
        self.assertIn("SQLI-002", res2.matched_rule_ids)

    def test_xss_detection(self):
        # Script tag
        res = self.engine.inspect_request(body='{"text": "<script>alert(1)</script>"}')
        self.assertTrue(res.is_threat)
        self.assertEqual(res.primary_category, AttackCategory.XSS)
        self.assertIn("XSS-001", res.matched_rule_ids)

        # Inline event handler
        res2 = self.engine.inspect_request(query_string="img=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")
        self.assertTrue(res2.is_threat)
        self.assertEqual(res2.primary_category, AttackCategory.XSS)
        self.assertIn("XSS-002", res2.matched_rule_ids)

    def test_path_traversal_detection(self):
        # Relative traversal
        res = self.engine.inspect_request(path="/files/../../../../etc/passwd")
        self.assertTrue(res.is_threat)
        self.assertEqual(res.primary_category, AttackCategory.PATH_TRAVERSAL)
        self.assertIn("TRAV-001", res.matched_rule_ids)

    def test_command_injection_detection(self):
        # Semicolon command chain
        res = self.engine.inspect_request(body='{"ip": "127.0.0.1; whoami"}')
        self.assertTrue(res.is_threat)
        self.assertEqual(res.primary_category, AttackCategory.CMD_INJECTION)
        self.assertIn("CMDI-001", res.matched_rule_ids)

    def test_malformed_scanner_header_detection(self):
        # Sqlmap user-agent
        res = self.engine.inspect_request(headers={"User-Agent": "sqlmap/1.5.2#stable"})
        self.assertTrue(res.is_threat)
        self.assertEqual(res.primary_category, AttackCategory.MALFORMED_HEADER)
        self.assertIn("HDR-001", res.matched_rule_ids)

    def test_disabled_rule_behavior(self):
        # Create rule in DB and then disable it
        rule = DetectionRule.objects.create(
            rule_id="CUSTOM-X-01",
            name="Custom Test Rule",
            category=AttackCategory.SQLI,
            pattern=r"SPECIFIC_ATTACK_STRING",
            enabled=False,
            target_components=["query"]
        )
        engine = DetectionEngine()
        res = engine.inspect_request(query_string="payload=SPECIFIC_ATTACK_STRING")
        self.assertNotIn("CUSTOM-X-01", res.matched_rule_ids)
