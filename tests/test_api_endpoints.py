import json
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.core.cache import cache
from apps.traffic.models import SecurityEvent, SecurityDecision
from apps.alerts.models import SecurityAlert, AlertStatus
from apps.detections.models import DetectionRule, AttackCategory, RuleSeverity

User = get_user_model()

class APIEndpointsTestCase(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.user = User.objects.create_user(
            username='api_tester',
            password='password123',
            role='ADMIN'
        )
        self.rule = DetectionRule.objects.create(
            rule_id='TEST-RULE-01',
            name='Test Signature',
            category=AttackCategory.SQLI,
            severity=RuleSeverity.HIGH,
            pattern=r'(?i)\bTEST_ATTACK\b',
            target_components=['query']
        )
        self.alert = SecurityAlert.objects.create(
            alert_id='ALT-TEST-001',
            title='Test Alert',
            severity=RuleSeverity.HIGH,
            status=AlertStatus.OPEN,
            category=AttackCategory.SQLI,
            source_ip='192.0.2.1'
        )

    def test_dashboard_summary_api(self):
        response = self.client.get('/api/v1/dashboard/summary/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('summary', data)
        self.assertIn('total_requests', data['summary'])
        self.assertIn('engine_status', data['summary'])

    def test_dashboard_traffic_api(self):
        response = self.client.get('/api/v1/dashboard/traffic/')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('labels', data)
        self.assertIn('datasets', data)

    def test_security_events_list_and_filter(self):
        # Create an event
        SecurityEvent.objects.create(
            source_ip='198.51.100.1',
            sanitized_path='/api/test',
            decision=SecurityDecision.BLOCKED,
            category=AttackCategory.SQLI,
            severity=RuleSeverity.CRITICAL
        )
        response = self.client.get('/api/v1/events/?category=SQLI')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        results = data.get('results', data)
        self.assertGreaterEqual(len(results), 1)

    def test_alert_acknowledge_and_resolve(self):
        # Acknowledge
        res = self.client.patch(f'/api/v1/alerts/{self.alert.id}/acknowledge/')
        self.assertEqual(res.status_code, 200)
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, AlertStatus.ACKNOWLEDGED)

        # Resolve
        res2 = self.client.patch(
            f'/api/v1/alerts/{self.alert.id}/resolve/',
            data=json.dumps({'notes': 'Remediated in test'}),
            content_type='application/json'
        )
        self.assertEqual(res2.status_code, 200)
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, AlertStatus.RESOLVED)

    def test_detection_rule_toggle(self):
        self.assertTrue(self.rule.enabled)
        res = self.client.patch(f'/api/v1/rules/{self.rule.id}/toggle/')
        self.assertEqual(res.status_code, 200)
        self.rule.refresh_from_db()
        self.assertFalse(self.rule.enabled)

    def test_simulation_inspect_sandbox_api(self):
        res = self.client.post(
            '/api/v1/simulation/inspect/',
            data=json.dumps({
                'method': 'GET',
                'path': '/api/v1/search',
                'query': 'q=TEST_ATTACK',
                'headers': {},
                'body': ''
            }),
            content_type='application/json'
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data['is_threat'])
        self.assertEqual(data['primary_category'], AttackCategory.SQLI)

    def test_system_health_api(self):
        res = self.client.get('/api/v1/system/health/')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'HEALTHY')
        self.assertIn('engine', data)
        self.assertIn('database', data)
