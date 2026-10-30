import json
from django.test import TestCase, Client
from django.core.cache import cache
from django.conf import settings
from apps.traffic.models import SecurityEvent, SecurityDecision
from apps.alerts.models import SecurityAlert, AlertStatus
from apps.detections.models import AttackCategory

class MiddlewareEnforcementTestCase(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()

    def test_clean_request_allowed_and_logged(self):
        response = self.client.get('/dashboard/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['X-SentinelShield-Status'], 'Inspected')

        # Check clean event logged
        clean_event = SecurityEvent.objects.filter(
            decision=SecurityDecision.ALLOWED,
            category=AttackCategory.NORMAL
        ).first()
        self.assertIsNotNone(clean_event)

    def test_sql_injection_request_blocked_with_403(self):
        response = self.client.get(
            '/dashboard/?probe=1+UNION+SELECT+1,2,3',
            HTTP_ACCEPT='application/json'
        )
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'blocked')
        self.assertEqual(data['status_code'], 403)
        self.assertIn('SQLI-001', data['matched_rules'])

        # Verify event saved in DB
        event = SecurityEvent.objects.filter(decision=SecurityDecision.BLOCKED).first()
        self.assertIsNotNone(event)
        self.assertEqual(event.category, AttackCategory.SQLI)

        # Verify alert created
        alert = SecurityAlert.objects.filter(category=AttackCategory.SQLI).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.status, AlertStatus.OPEN)

    def test_xss_post_body_blocked_with_403(self):
        response = self.client.post(
            '/api/v1/comments/',
            data=json.dumps({"body": "<script>alert('pwned')</script>"}),
            content_type='application/json',
            HTTP_ACCEPT='application/json'
        )
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'blocked')
        self.assertIn('XSS-001', data['matched_rules'])

    def test_request_body_size_limit_enforced(self):
        # Exceed body limit by sending content larger than 256KB
        large_payload = "A" * (settings.SENTINEL_BODY_LIMIT_BYTES + 500)
        response = self.client.post(
            '/api/v1/upload/',
            data=large_payload,
            content_type='text/plain',
            HTTP_ACCEPT='application/json'
        )
        self.assertEqual(response.status_code, 413)

    def test_rate_limiting_enforced_with_429(self):
        # Fire requests to reach threshold
        threshold = settings.SENTINEL_RATE_LIMIT_THRESHOLD
        for _ in range(threshold):
            res = self.client.get('/dashboard/', HTTP_ACCEPT='application/json')
            self.assertEqual(res.status_code, 200)

        # Exceed threshold
        excess_response = self.client.get('/dashboard/', HTTP_ACCEPT='application/json')
        self.assertEqual(excess_response.status_code, 429)
        self.assertIn('Retry-After', excess_response)
        data = json.loads(excess_response.content)
        self.assertEqual(data['status'], 'rate_limited')
