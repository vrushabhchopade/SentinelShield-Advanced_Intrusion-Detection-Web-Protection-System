"""
SentinelShield Request Inspection & Decision Enforcement Middleware.
Intercepts requests inside the Django request lifecycle, validates body size,
extracts safe components, performs rate limiting, executes heuristic detection,
logs SecurityEvents, triggers SecurityAlerts, and enforces HTTP 403/429 decisions.
"""

import time
import uuid
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.utils import timezone

from apps.detections.engine import DetectionEngine
from apps.detections.models import AttackCategory, RuleSeverity
from apps.traffic.models import SecurityEvent, SecurityDecision, TrafficEnvironment
from apps.alerts.models import SecurityAlert, AlertStatus
from apps.ratelimit.limiter import RateLimiter, get_client_ip
from .sanitizer import extract_safe_headers, redact_sensitive_body, sanitize_crlf

class SecurityInspectorMiddleware:
    """
    Core defensive middleware implementing real-time request inspection.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.detection_engine = DetectionEngine()
        self.rate_limiter = RateLimiter()
        self.mode = getattr(settings, 'SENTINEL_MODE', 'ENFORCE')
        self.body_limit = getattr(settings, 'SENTINEL_BODY_LIMIT_BYTES', 262144)
        self.excluded_prefixes = tuple(getattr(settings, 'SENTINEL_EXCLUDED_PATH_PREFIXES', (
            '/static/', '/media/', '/favicon.ico', '/api/v1/system/health/'
        )))

    def is_excluded(self, path: str) -> bool:
        return any(path.startswith(prefix) for prefix in self.excluded_prefixes)

    def is_api_request(self, request) -> bool:
        return (
            request.path.startswith('/api/') or
            'application/json' in request.META.get('HTTP_ACCEPT', '')
        )

    def __call__(self, request):
        # 1. Bypass check for excluded paths (static assets, health check)
        if self.is_excluded(request.path):
            return self.get_response(request)

        start_time = time.perf_counter()
        client_ip = get_client_ip(request)
        clean_path = sanitize_crlf(request.path)[:1024]
        query_string = request.META.get('QUERY_STRING', '')

        # 2. Request body size check
        try:
            content_length = int(request.META.get('CONTENT_LENGTH', 0) or 0)
        except (ValueError, TypeError):
            content_length = 0

        if content_length > self.body_limit:
            duration_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
            event = SecurityEvent.objects.create(
                source_ip=client_ip,
                http_method=request.method,
                sanitized_path=clean_path,
                decision=SecurityDecision.BLOCKED,
                category=AttackCategory.MALFORMED_HEADER,
                severity=RuleSeverity.HIGH,
                safe_message=f"Request entity too large: {content_length} bytes exceeds limit of {self.body_limit} bytes",
                processing_time_ms=duration_ms
            )
            return self.render_blocked_response(
                request,
                event_id=event.event_id,
                reason="Payload exceeds maximum configured size limit.",
                status_code=413
            )

        # 3. Rate limiting evaluation
        is_limited, req_count, threshold, retry_after = self.rate_limiter.check_rate_limit(
            client_ip, clean_path
        )
        if is_limited:
            duration_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
            event = SecurityEvent.objects.create(
                source_ip=client_ip,
                http_method=request.method,
                sanitized_path=clean_path,
                decision=SecurityDecision.RATE_LIMITED,
                category=AttackCategory.RATE_LIMIT,
                severity=RuleSeverity.HIGH,
                safe_message=f"Rate limit exceeded: {req_count} requests in window (threshold: {threshold})",
                processing_time_ms=duration_ms
            )
            return self.render_rate_limited_response(request, event.event_id, req_count, threshold, retry_after)

        # 4. Safe body extraction (handling multipart gracefully)
        body_str = ""
        body_preview = ""
        content_type = request.META.get('CONTENT_TYPE', '')
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            if 'multipart/form-data' not in content_type:
                try:
                    raw_body = request.body
                    body_preview = redact_sensitive_body(raw_body)
                    body_str = raw_body.decode('utf-8', errors='replace')
                except Exception:
                    pass

        safe_headers = extract_safe_headers(request)

        # 5. Modular Heuristic Detection Engine
        inspection = self.detection_engine.inspect_request(
            path=clean_path,
            query_string=query_string,
            headers=safe_headers,
            body=body_str,
            method=request.method
        )

        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

        # 6. Policy Decision Enforcement
        if inspection.is_threat:
            if self.mode == 'ENFORCE':
                decision = SecurityDecision.BLOCKED
            else:
                decision = SecurityDecision.FLAGGED

            event = SecurityEvent.objects.create(
                source_ip=client_ip,
                http_method=request.method,
                sanitized_path=clean_path,
                query_params=dict(request.GET.items()) if request.GET else {},
                headers=safe_headers,
                body_preview=body_preview,
                decision=decision,
                category=inspection.primary_category,
                severity=inspection.highest_severity,
                matched_rule_ids=inspection.matched_rule_ids,
                safe_message=inspection.safe_reason,
                processing_time_ms=duration_ms,
                environment=TrafficEnvironment.REAL
            )

            # Trigger or aggregate SecurityAlert for High/Critical or Blocked events
            self.handle_security_alert(event, inspection, client_ip)

            if decision == SecurityDecision.BLOCKED:
                return self.render_blocked_response(
                    request,
                    event_id=event.event_id,
                    reason=inspection.safe_reason,
                    matched_rules=inspection.matched_rule_ids,
                    category=inspection.primary_category,
                    status_code=403
                )
        else:
            # Clean / Allowed request
            # We record clean requests to build authentic SOC operational telemetry
            try:
                SecurityEvent.objects.create(
                    source_ip=client_ip,
                    http_method=request.method,
                    sanitized_path=clean_path,
                    decision=SecurityDecision.ALLOWED,
                    category=AttackCategory.NORMAL,
                    severity=RuleSeverity.INFO,
                    safe_message=inspection.safe_reason,
                    processing_time_ms=duration_ms,
                    environment=TrafficEnvironment.REAL
                )
            except Exception:
                pass

        # 7. Proceed through Django view pipeline
        response = self.get_response(request)

        # Add SentinelShield educational defense header
        response['X-SentinelShield-Engine'] = 'v2.4-Active'
        response['X-SentinelShield-Status'] = 'Inspected'
        return response

    def handle_security_alert(self, event: SecurityEvent, inspection, client_ip: str):
        """Creates or aggregates open security alert for threat events."""
        try:
            # Look for an active open alert for this source_ip and category within the last 2 hours
            cutoff = timezone.now() - timezone.timedelta(hours=2)
            alert = SecurityAlert.objects.filter(
                source_ip=client_ip,
                category=inspection.primary_category,
                status__in=[AlertStatus.OPEN, AlertStatus.INVESTIGATING],
                last_seen__gte=cutoff
            ).first()

            if alert:
                alert.occurrence_count += 1
                alert.last_seen = timezone.now()
                if self.detection_engine.SEVERITY_ORDER.get(inspection.highest_severity, 0) > \
                   self.detection_engine.SEVERITY_ORDER.get(alert.severity, 0):
                    alert.severity = inspection.highest_severity
                alert.save()
                alert.events.add(event)
            else:
                alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
                alert = SecurityAlert.objects.create(
                    alert_id=alert_id,
                    title=f"Suspicious {inspection.primary_category} activity from {client_ip}",
                    severity=inspection.highest_severity,
                    status=AlertStatus.OPEN,
                    category=inspection.primary_category,
                    source_ip=client_ip,
                    occurrence_count=1,
                    first_seen=timezone.now(),
                    last_seen=timezone.now(),
                    analyst_notes="Automatically generated by SentinelShield Inspection Middleware."
                )
                alert.events.add(event)
        except Exception:
            pass

    def render_blocked_response(
        self, request, event_id: str, reason: str, matched_rules: list = None,
        category: str = "MALICIOUS_INGRESS", status_code: int = 403
    ):
        matched_rules = matched_rules or []
        if self.is_api_request(request):
            return JsonResponse({
                'status': 'blocked',
                'status_code': status_code,
                'event_id': str(event_id),
                'error': 'Forbidden - SentinelShield Defense Active',
                'category': category,
                'matched_rules': matched_rules,
                'message': reason,
                'notice': 'Educational WAF Simulator Enforced Localhost Block'
            }, status=status_code)

        html = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="utf-8">
  <title>403 Request Blocked | SentinelShield</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined" rel="stylesheet" />
</head>
<body class="bg-[#0f131d] text-[#dfe2f1] font-sans min-h-screen flex items-center justify-center p-6">
  <div class="max-w-xl w-full bg-[#171b26] border border-[#ffb4ab]/40 rounded-xl p-8 shadow-2xl relative overflow-hidden">
    <div class="absolute top-0 left-0 right-0 h-1 bg-[#ffb4ab]"></div>
    <div class="flex items-center gap-3 mb-6">
      <div class="w-12 h-12 rounded-lg bg-[#93000a]/40 text-[#ffb4ab] flex items-center justify-center">
        <span class="material-symbols-outlined text-2xl">shield_locked</span>
      </div>
      <div>
        <div class="text-[#ffb4ab] text-xs font-mono font-bold tracking-widest uppercase">HTTP 403 FORBIDDEN</div>
        <h1 class="text-xl font-bold text-[#dfe2f1]">SentinelShield Web Application Firewall</h1>
      </div>
    </div>
    <div class="bg-[#0a0e18] p-4 rounded-lg font-mono text-xs text-[#c2c6d6] space-y-2 mb-6 border border-[#424754]">
      <div><span class="text-[#8c909f]">EVENT ID:</span> <span class="text-[#adc6ff]">{event_id}</span></div>
      <div><span class="text-[#8c909f]">VIOLATION:</span> <span class="text-[#ffb4ab]">{reason}</span></div>
      <div><span class="text-[#8c909f]">CATEGORY:</span> <span>{category}</span></div>
      <div><span class="text-[#8c909f]">RULES:</span> <span class="text-[#4edea3]">{', '.join(matched_rules) if matched_rules else 'NONE'}</span></div>
    </div>
    <p class="text-xs text-[#8c909f] leading-relaxed mb-6">
      This request was blocked by the SentinelShield heuristic inspection pipeline. This is an educational defensive security environment.
    </p>
    <div class="flex items-center justify-between pt-4 border-t border-[#424754]">
      <a href="/dashboard/" class="px-4 py-2 bg-[#4d8eff] hover:bg-[#adc6ff] hover:text-[#00285d] text-white text-xs font-bold rounded transition-colors">
        Return to SOC Console
      </a>
      <span class="text-xs font-mono text-[#8c909f]">SENTINELSHIELD v2.4</span>
    </div>
  </div>
</body>
</html>"""
        return HttpResponse(html, status=status_code)

    def render_rate_limited_response(
        self, request, event_id: str, count: int, threshold: int, retry_after: int = 60
    ):
        if self.is_api_request(request):
            response = JsonResponse({
                'status': 'rate_limited',
                'status_code': 429,
                'event_id': str(event_id),
                'error': 'Too Many Requests',
                'threshold': threshold,
                'current_requests': count,
                'retry_after_seconds': retry_after,
                'message': f'Exceeded maximum permitted rate of {threshold} requests per window.'
            }, status=429)
            if retry_after:
                response['Retry-After'] = str(retry_after)
            return response

        html = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="utf-8">
  <title>429 Too Many Requests | SentinelShield</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-[#0f131d] text-[#dfe2f1] font-sans min-h-screen flex items-center justify-center p-6">
  <div class="max-w-md w-full bg-[#171b26] border border-[#adc6ff]/40 rounded-xl p-8 shadow-2xl">
    <div class="text-[#adc6ff] text-xs font-mono font-bold tracking-widest uppercase mb-2">HTTP 429 TOO MANY REQUESTS</div>
    <h1 class="text-xl font-bold text-[#dfe2f1] mb-4">Rate Limit Restriction</h1>
    <p class="text-xs text-[#c2c6d6] mb-4">
      Your client has exceeded the threshold of <strong>{threshold}</strong> requests per window.
      Temporary rate restriction is active for {retry_after} seconds.
    </p>
    <div class="font-mono text-xs text-[#8c909f] mb-6">EVENT ID: {event_id}</div>
    <a href="/dashboard/" class="inline-block px-4 py-2 bg-[#4d8eff] text-white text-xs font-bold rounded hover:bg-[#adc6ff] hover:text-[#00285d] transition-colors">
      Return to SOC Console
    </a>
  </div>
</body>
</html>"""
        response = HttpResponse(html, status=429)
        if retry_after:
            response['Retry-After'] = str(retry_after)
        return response
