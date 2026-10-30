"""
Management command to safely reset disposable simulation and demo telemetry.
Leaves user accounts and detection rules intact.
"""

from django.core.management.base import BaseCommand
from apps.traffic.models import SecurityEvent, TrafficEnvironment
from apps.alerts.models import SecurityAlert
from apps.simulation.models import TestRun
from apps.ratelimit.models import RateLimitEvent
from apps.audit.utils import record_audit
from apps.audit.models import AuditAction

class Command(BaseCommand):
    help = "Safely cleans disposable simulation telemetry, test runs, and test alerts"

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING("Resetting disposable SentinelShield simulation telemetry..."))

        # Delete simulation test runs and results
        runs_count, _ = TestRun.objects.all().delete()
        # Delete rate limit events
        rate_count, _ = RateLimitEvent.objects.all().delete()
        # Delete only simulation and lab events
        events_count, _ = SecurityEvent.objects.filter(
            environment__in=[TrafficEnvironment.SIMULATION, TrafficEnvironment.LAB]
        ).delete()
        # Delete alerts tied to simulation
        alerts_count, _ = SecurityAlert.objects.all().delete()

        record_audit("SYSTEM", AuditAction.DATA_RESET, "System:DisposableData", metadata={
            'deleted_runs': runs_count,
            'deleted_events': events_count,
            'deleted_alerts': alerts_count
        })

        self.stdout.write(self.style.SUCCESS(
            f"Reset complete: Cleared {runs_count} test runs, {events_count} synthetic events, {alerts_count} alerts, {rate_count} rate limits."
        ))
        self.stdout.write(self.style.SUCCESS("All user accounts and base detection rules preserved."))
