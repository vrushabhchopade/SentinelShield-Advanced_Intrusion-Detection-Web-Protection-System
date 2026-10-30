# SentinelShield Automated Testing & Verification Results

## 1. Test Suite Summary

The automated test suite runs via Django's test framework (`python manage.py test tests`).
All 27 automated tests run against an isolated in-memory test database with full fixture teardown.

```
Creating test database for alias 'default'...
...........................
----------------------------------------------------------------------
Ran 27 tests in 36.419s

OK
Destroying test database for alias 'default'...
Found 27 test(s).
System check identified no issues (0 silenced).
```

## 2. Test Coverage Breakdown

### A. Detection Engine Unit Tests (`tests/test_detection_engine.py`)
- `test_safe_normalize_string`: Verifies multi-pass bounded URL decoding (`unquote_plus`), slash normalization (`\ -> /`), and buffer boundaries.
- `test_clean_request_allowed`: Confirms legitimate requests return `is_threat=False` and zero rule matches.
- `test_sql_injection_detection`: Tests union-based exfiltration and boolean auth tautologies (`SQLI-001`, `SQLI-002`).
- `test_xss_detection`: Validates `<script>` tag detection and inline DOM event attributes (`XSS-001`, `XSS-002`).
- `test_path_traversal_detection`: Confirms detection of relative path stepping (`TRAV-001`).
- `test_command_injection_detection`: Confirms identification of shell metacharacter chaining (`CMDI-001`).
- `test_malformed_scanner_header_detection`: Identifies scanner User-Agents (e.g. `sqlmap`).
- `test_disabled_rule_behavior`: Verifies disabled detection rules do not participate in heuristic matching.

### B. Middleware Enforcement Tests (`tests/test_middleware_enforcement.py`)
- `test_clean_request_allowed_and_logged`: Verifies HTTP 200 and safe telemetry logging.
- `test_sql_injection_request_blocked_with_403`: Verifies HTTP 403 Forbidden on attacks and automatic `SecurityAlert` generation.
- `test_xss_post_body_blocked_with_403`: Verifies POST body scanning and blocking.
- `test_request_body_size_limit_enforced`: Verifies HTTP 413 Payload Too Large when payload exceeds limit.
- `test_rate_limiting_enforced_with_429`: Verifies sliding-window threshold tripping and HTTP 429 Too Many Requests response with `Retry-After`.

### C. REST API Endpoints (`tests/test_api_endpoints.py`)
- `test_dashboard_summary_api`: Verifies `/api/v1/dashboard/summary/`.
- `test_dashboard_traffic_api`: Verifies `/api/v1/dashboard/traffic/`.
- `test_security_events_list_and_filter`: Verifies pagination, category, and severity filtering.
- `test_alert_acknowledge_and_resolve`: Verifies triage workflow (ACKNOWLEDGED -> RESOLVED).
- `test_detection_rule_toggle`: Verifies dynamic rule state changes via API.
- `test_simulation_inspect_sandbox_api`: Verifies in-memory ad-hoc inspection endpoint.
- `test_system_health_api`: Verifies `/api/v1/system/health/`.

### D. Reporting & Export Defenses (`tests/test_reporting_and_exports.py`)
- `test_csv_formula_injection_defense`: Validates formula escaping (CWE-1236).
- `test_export_events_csv`: Confirms valid CSV stream generation.
- `test_generate_pdf_report`: Confirms ReportLab PDF compilation and media storage.

### E. Simulation Benchmark Lab (`tests/test_simulation_lab.py`)
- `test_run_benchmark_suite`: Executes 16 benchmark cases and asserts 100% accuracy, precision, and recall.

### F. Authentication & Role Permissions (`tests/test_auth_and_roles.py`)
- `test_user_role_properties`: Asserts Admin, Analyst, and Viewer role hierarchies.
- `test_login_and_logout_flow`: Asserts session authentication.
- `test_invalid_login_rejected`: Asserts invalid credential denial.
