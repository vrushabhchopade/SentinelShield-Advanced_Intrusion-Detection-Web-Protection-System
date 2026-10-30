"""
Management command to seed educational demo data into SentinelShield.
Creates demo accounts, base detection rules, and labeled synthetic events.
"""

import uuid
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone

from apps.accounts.models import UserRole
from apps.detections.models import DetectionRule, AttackCategory, RuleSeverity
from apps.detections.patterns import DEFAULT_RULES
from apps.traffic.models import SecurityEvent, SecurityDecision, TrafficEnvironment, AnalystClassification
from apps.alerts.models import SecurityAlert, AlertStatus
from apps.ratelimit.models import RateLimitEvent, RateLimitAction
from apps.simulation.runner import SimulationRunner
from apps.reporting.models import PracticalReport
from apps.reporting.generators import generate_pdf_report
from apps.audit.utils import record_audit
from apps.audit.models import AuditAction

User = get_user_model()

class Command(BaseCommand):
    help = "Seed clearly labeled educational demo data for SentinelShield SOC platform"

    def add_arguments(self, parser):
        parser.add_argument(
            '--no-events',
            action='store_true',
            help='Skip creating synthetic security event telemetry',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE("Initializing SentinelShield Educational Database..."))

        # 1. Create Default Educational Users
        admin_user, created = User.objects.get_or_create(
            username='admin',
            defaults={
                'email': 'admin@sentinelshield.local',
                'first_name': 'Chief Security',
                'last_name': 'Officer',
                'role': UserRole.ADMIN,
                'is_staff': True,
                'is_superuser': True,
                'department': 'SOC Security Leadership',
                'badge_number': 'SOC-ADM-01'
            }
        )
        if created:
            admin_user.set_password('admin123')
            admin_user.save()
            self.stdout.write(self.style.SUCCESS("Created admin user: admin / admin123"))

        analyst_user, created = User.objects.get_or_create(
            username='analyst',
            defaults={
                'email': 'analyst@sentinelshield.local',
                'first_name': 'Dr. Elena',
                'last_name': 'Rostova',
                'role': UserRole.ANALYST,
                'department': 'Threat Triage Unit',
                'badge_number': 'SOC-ANL-42'
            }
        )
        if created:
            analyst_user.set_password('sentinel123')
            analyst_user.save()
            self.stdout.write(self.style.SUCCESS("Created analyst user: analyst / sentinel123"))

        viewer_user, created = User.objects.get_or_create(
            username='viewer',
            defaults={
                'email': 'student@university.edu',
                'first_name': 'Cybersecurity',
                'last_name': 'Student',
                'role': UserRole.VIEWER,
                'department': 'Academic Practical',
                'badge_number': 'STU-9901'
            }
        )
        if created:
            viewer_user.set_password('viewer123')
            viewer_user.save()
            self.stdout.write(self.style.SUCCESS("Created viewer user: viewer / viewer123"))

        # 2. Seed Base Detection Rules
        rules_created = 0
        for r_data in DEFAULT_RULES:
            _, created = DetectionRule.objects.get_or_create(
                rule_id=r_data['rule_id'],
                defaults={
                    'name': r_data['name'],
                    'category': r_data['category'],
                    'severity': r_data['severity'],
                    'description': r_data['description'],
                    'pattern': r_data['pattern'],
                    'target_components': r_data.get('target_components', ['path', 'query', 'body']),
                    'version': r_data.get('version', '1.0'),
                    'enabled': True,
                    'created_by': admin_user
                }
            )
            if created:
                rules_created += 1

        self.stdout.write(self.style.SUCCESS(f"Loaded {rules_created} default detection rules into database."))

        if options.get('no_events'):
            self.stdout.write(self.style.WARNING("Skipping synthetic telemetry as requested."))
            return

        # 3. Seed Realistic Synthetic Telemetry Events (Spanning past 24h)
        now = timezone.now()
        demo_events_data = [
            # SQLi events
            ("198.51.100.23", "POST", "/auth/login/", "username=admin' OR '1'='1", SecurityDecision.BLOCKED, AttackCategory.SQLI, RuleSeverity.HIGH, ["SQLI-002"], "Boolean tautology auth bypass attempt", 1.8),
            ("203.0.113.45", "GET", "/api/v1/telemetry/", "id=1 UNION SELECT 1,username,password FROM users", SecurityDecision.BLOCKED, AttackCategory.SQLI, RuleSeverity.CRITICAL, ["SQLI-001"], "Union-based database exfiltration attempt", 2.1),
            ("198.51.100.23", "POST", "/api/v1/query/", "1; DROP TABLE logs", SecurityDecision.BLOCKED, AttackCategory.SQLI, RuleSeverity.CRITICAL, ["SQLI-003"], "Stacked query DDL tampering", 1.9),

            # XSS events
            ("192.0.2.88", "POST", "/api/v1/comments/", "<script>alert('XSS-TEST')</script>", SecurityDecision.BLOCKED, AttackCategory.XSS, RuleSeverity.HIGH, ["XSS-001"], "HTML <script> tag injection identified", 1.5),
            ("192.0.2.88", "GET", "/search/", "term=<img src=x onerror=alert(document.cookie)>", SecurityDecision.BLOCKED, AttackCategory.XSS, RuleSeverity.HIGH, ["XSS-002"], "Inline DOM onerror handler injection", 1.4),
            ("198.51.100.99", "GET", "/redirect/", "url=javascript:alert(1)", SecurityDecision.BLOCKED, AttackCategory.XSS, RuleSeverity.HIGH, ["XSS-003"], "JavaScript URI pseudo-protocol execution attempt", 1.2),

            # Path Traversal events
            ("203.0.113.12", "GET", "/api/v1/files/download", "file=../../../../etc/passwd", SecurityDecision.BLOCKED, AttackCategory.PATH_TRAVERSAL, RuleSeverity.CRITICAL, ["TRAV-001", "TRAV-002"], "Directory traversal targeting Unix credentials", 1.7),
            ("203.0.113.12", "GET", "/api/v1/download", "file=..\\..\\windows\\system32\\win.ini", SecurityDecision.BLOCKED, AttackCategory.PATH_TRAVERSAL, RuleSeverity.CRITICAL, ["TRAV-001", "TRAV-003"], "Windows directory traversal attempt", 1.6),

            # Command Injection events
            ("198.51.100.77", "POST", "/api/v1/diag/ping", "target=127.0.0.1; whoami", SecurityDecision.BLOCKED, AttackCategory.CMD_INJECTION, RuleSeverity.CRITICAL, ["CMDI-001"], "Shell semicolon metacharacter command chaining", 2.0),
            ("198.51.100.77", "GET", "/api/v1/host", "host=$(id)", SecurityDecision.BLOCKED, AttackCategory.CMD_INJECTION, RuleSeverity.CRITICAL, ["CMDI-002"], "Subshell execution substitution detected", 1.5),

            # Scanner Header event
            ("192.0.2.14", "GET", "/api/v1/meta", "", SecurityDecision.BLOCKED, AttackCategory.MALFORMED_HEADER, RuleSeverity.MEDIUM, ["HDR-001"], "Vulnerability scanner signature: sqlmap probe", 1.1),

            # Rate Limit Event
            ("198.51.100.5", "GET", "/api/v1/auth/session", "", SecurityDecision.RATE_LIMITED, AttackCategory.RATE_LIMIT, RuleSeverity.HIGH, [], "Rate limit threshold exceeded (42 req/min)", 0.8),
        ]

        created_events = []
        for i, ev_tuple in enumerate(demo_events_data):
            ip, method, path, snippet, dec, cat, sev, rules, msg, lat = ev_tuple
            event_time = now - timedelta(hours=(i * 1.5) + 0.2)
            ev = SecurityEvent.objects.create(
                timestamp=event_time,
                source_ip=ip,
                http_method=method,
                sanitized_path=path,
                body_preview=snippet[:256],
                decision=dec,
                category=cat,
                severity=sev,
                matched_rule_ids=rules,
                safe_message=msg,
                processing_time_ms=lat,
                environment=TrafficEnvironment.SIMULATION,
                analyst_reviewed=(i % 2 == 0),
                analyst_classification=AnalystClassification.TRUE_POSITIVE if (i % 2 == 0) else None
            )
            created_events.append(ev)

        # Seed 30 benign normal requests across the timeline to establish realistic base traffic
        for k in range(30):
            event_time = now - timedelta(minutes=(k * 35))
            SecurityEvent.objects.create(
                timestamp=event_time,
                source_ip=f"10.0.0.{10 + (k % 8)}",
                http_method="GET",
                sanitized_path=f"/api/v1/catalog/items?page={(k % 5) + 1}",
                decision=SecurityDecision.ALLOWED,
                category=AttackCategory.NORMAL,
                severity=RuleSeverity.INFO,
                safe_message="Normal traffic signature validated.",
                processing_time_ms=1.3,
                environment=TrafficEnvironment.SIMULATION
            )

        self.stdout.write(self.style.SUCCESS(f"Seeded {len(created_events) + 30} synthetic telemetry security events."))

        # 4. Seed Security Alerts
        alert1 = SecurityAlert.objects.create(
            alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            title="Sustained SQL Injection Probing from 198.51.100.23",
            severity=RuleSeverity.CRITICAL,
            status=AlertStatus.OPEN,
            category=AttackCategory.SQLI,
            source_ip="198.51.100.23",
            occurrence_count=3,
            first_seen=now - timedelta(hours=4),
            last_seen=now - timedelta(minutes=15),
            analyst_notes="Repeated union and boolean tautology patterns detected against auth routes."
        )
        alert1.events.set(created_events[:3])

        alert2 = SecurityAlert.objects.create(
            alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            title="LFI / System File Access Attempts from 203.0.113.12",
            severity=RuleSeverity.HIGH,
            status=AlertStatus.INVESTIGATING,
            category=AttackCategory.PATH_TRAVERSAL,
            source_ip="203.0.113.12",
            occurrence_count=2,
            first_seen=now - timedelta(hours=8),
            last_seen=now - timedelta(hours=2),
            assigned_analyst=analyst_user,
            analyst_notes="Under active triage by Lead SOC Analyst."
        )
        alert2.events.set(created_events[6:8])

        alert3 = SecurityAlert.objects.create(
            alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            title="XSS Script Injection Probe Resolved",
            severity=RuleSeverity.HIGH,
            status=AlertStatus.RESOLVED,
            category=AttackCategory.XSS,
            source_ip="192.0.2.88",
            occurrence_count=2,
            first_seen=now - timedelta(hours=14),
            last_seen=now - timedelta(hours=12),
            assigned_analyst=analyst_user,
            analyst_notes="[Resolution Notes]: Mitigated at WAF boundary; no DOM sinks impacted."
        )
        alert3.events.set(created_events[3:5])

        self.stdout.write(self.style.SUCCESS("Seeded 3 incident security alerts."))

        # 5. Seed Rate Limit Events
        RateLimitEvent.objects.create(
            source_ip="198.51.100.5",
            path="/api/v1/auth/session",
            request_count=42,
            threshold=10,
            window_seconds=60,
            action_taken=RateLimitAction.THROTTLED,
            expiry_time=now + timedelta(minutes=5)
        )

        # 6. Run Initial Simulation Test Run Benchmark
        runner = SimulationRunner()
        test_run = runner.run_suite(suite_name="OWASP Top Web Signatures Benchmark", user=admin_user)
        self.stdout.write(self.style.SUCCESS(f"Executed baseline lab benchmark: {test_run.passed_cases}/{test_run.total_cases} Passed."))

        # 7. Generate a Sample Practical Report
        report = PracticalReport.objects.create(
            title="SentinelShield Academic Defensive Security Assessment",
            reporting_period="Past 24 Hours",
            summary="Formal academic assessment verifying WAF signature heuristics, input normalization, and rate limiting in an isolated sandbox.",
            metrics={
                'total_requests': SecurityEvent.objects.count(),
                'malicious_requests': SecurityEvent.objects.filter(decision__in=[SecurityDecision.BLOCKED, SecurityDecision.FLAGGED]).count(),
                'blocked_requests': SecurityEvent.objects.filter(decision=SecurityDecision.BLOCKED).count(),
                'rate_limited_requests': 1,
                'accuracy_pct': test_run.metrics.get('accuracy_pct', 99.2),
                'avg_latency_ms': 1.8
            },
            report_format='PDF',
            generated_by=analyst_user
        )
        generate_pdf_report(report)
        self.stdout.write(self.style.SUCCESS(f"Generated sample practical PDF report: {report.file_path}"))

        record_audit(admin_user, AuditAction.POLICY_CHANGED, "Database:DemoSeed", metadata={'events': 42, 'rules': len(DEFAULT_RULES)})
        self.stdout.write(self.style.SUCCESS("SentinelShield educational database initialization completed successfully!"))
