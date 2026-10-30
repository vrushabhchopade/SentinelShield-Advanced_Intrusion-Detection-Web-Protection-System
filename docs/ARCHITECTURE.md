# SentinelShield Architecture & Pipeline Specification

## 1. System Overview

SentinelShield is an advanced, educational, defensive cybersecurity Web Application Firewall (WAF) simulator and HTTP intrusion detection platform. It is designed to demonstrate deep-packet inspection, tokenization, regular expression heuristic analysis, sliding-window rate limiting, and Security Operations Center (SOC) incident response inside a modern Django 5.x / Python architecture.

```
+─────────────────────────────────────────────────────────────────────────────+
|                         HTTP CLIENT / ANALYST BROWSER                       |
+──────────────────────────────────────┬──────────────────────────────────────+
                                       │
                                       ▼ HTTP Request (Method, Path, Headers, Body)
+─────────────────────────────────────────────────────────────────────────────+
|                         DJANGO REQUEST LIFECYCLE                            |
|                                                                             |
|  1. SecurityInspectorMiddleware                                             |
|     ├── Path Exclusions Check (/static/, /media/, /api/v1/system/health/)  |
|     ├── Size Validation (Max body <= SENTINEL_BODY_LIMIT_BYTES)             |
|     ├── Safe IP Extraction (Trusted proxies validation)                    |
|     ├── RateLimiter Sliding Window Check (Cache-backed)                    |
|     │    └── Exceeded? ──> Log Event & Return HTTP 429 Too Many Requests   |
|     └── Component Extraction & Normalization                                |
|          ├── Bounded 2-Pass URL Decoding (unquote_plus)                     |
|          ├── Slashes Normalization (\ -> /)                                 |
|          └── Safe Header & Body Filtering (Secrets Redaction)               |
|                                                                             |
|  2. Modular Detection Engine                                                |
|     ├── Compiled Regex Pattern Matching                                     |
|     ├── Multi-Component Sweeping (path, query, headers, body)               |
|     ├── Category & Severity Evaluation (SQLi, XSS, LFI, CMDi, Headers)      |
|     └── Policy Decision Enforcement                                         |
|          ├── ENFORCE: Threat? ──> Log Event + Trigger Alert + Return 403    |
|          ├── FLAG: Threat? ──> Log Event + Flag + Pass to View              |
|          └── MONITOR: Threat? ──> Log Event + Pass to View                  |
|                                                                             |
|  3. Django Core Pipeline (Sessions, CSRF, Authentication, View Routing)     |
+──────────────────────────────────────┬──────────────────────────────────────+
                                       │
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
|                         MODULAR DJANGO APPLICATIONS                         |
|                                                                             |
|  • apps.accounts:    RBAC User Model (Admin, Analyst, Viewer)               |
|  • apps.detections:  Compiled detection rules, pattern repository           |
|  • apps.traffic:     SecurityEvent telemetry logging & querying             |
|  • apps.alerts:      SecurityAlert incident triage lifecycle                |
|  • apps.ratelimit:   Sliding-window counters & RateLimitEvent persistence   |
|  • apps.simulation:  Inert test benchmark runner & Confusion Matrix stats   |
|  • apps.reporting:   ReportLab PDF & CSV telemetry export engine            |
|  • apps.audit:       Administrative audit trail logging                     |
|  • apps.dashboard:   12 Tailwind/Stitch SOC operational screens & REST APIs  |
+──────────────────────────────────────┬──────────────────────────────────────+
                                       │
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
|                         DATA PERSISTENCE & CACHING                          |
|                                                                             |
|  • SQLite3 (Local Development & Academic Labs)                              |
|  • PostgreSQL (Production Target Path)                                      |
|  • LocMemCache / Redis (Sliding-window counters & temporary IP blocklists)  |
+─────────────────────────────────────────────────────────────────────────────+
```

## 2. Request Inspection Pipeline Sequence

1. **Ingress Normalization:**
   Incoming strings are decoded with a strict upper limit of 2 decoding passes. This thwarts multi-encoded evasion tactics without risking infinite recursive loops or denial of service.
2. **Component Sanitization:**
   CRLF control characters (`\r`, `\n`) are stripped from log strings to prevent Log Injection / HTTP Response Splitting. Sensitive field names (`password`, `token`, `secret`) are masked using deterministic regex filters before storage.
3. **Detection Engine Heuristics:**
   Compiled regular expressions inspect candidate components (`path`, `query`, `headers`, `body`). Patterns are bounded to 16 KB inspection buffers to mitigate Regular Expression Denial of Service (ReDoS).
4. **Enforcement Decision:**
   - `BLOCKED`: Request halted immediately with HTTP 403 Forbidden.
   - `RATE_LIMITED`: Request halted with HTTP 429 Too Many Requests and `Retry-After` header.
   - `FLAGGED`: Logged with warning; allowed to pass downstream.
   - `ALLOWED`: Clean request logged to build real-time baseline telemetry.
5. **Incident Aggregation:**
   Confirmed high-severity violations trigger or increment corresponding `SecurityAlert` models to prevent alert fatigue in the SOC dashboard.
