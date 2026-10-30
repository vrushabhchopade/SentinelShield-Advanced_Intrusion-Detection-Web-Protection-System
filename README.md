# SentinelShield: Advanced Intrusion Detection & Web Protection System

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![Django 5.x](https://img.shields.io/badge/Django-5.x-green.svg)](https://www.djangoproject.com/)
[![REST Framework](https://img.shields.io/badge/DRF-3.15%2B-red.svg)](https://www.django-rest-framework.org/)
[![License: Educational](https://img.shields.io/badge/License-Academic%20Defensive%20Use-blue.svg)](#educational-defensive-scope)
[![Tests Passing](https://img.shields.io/badge/Tests-27%2F27%20Passed-brightgreen.svg)](#testing-and-verification)

SentinelShield is an educational Web Application Firewall (WAF) simulator and HTTP intrusion detection platform designed for academic cybersecurity laboratory work, practical evaluations, and defensive threat analysis.

It inspects incoming HTTP requests inside a controlled application environment, identifies suspicious attack signatures, enforces configurable security decisions (HTTP 403 / 429), monitors request frequency, creates forensic alerts, and provides a Security Operations Center (SOC) dashboard.

---

## 1. Educational Defensive Scope

> [!NOTE]
> SentinelShield is developed exclusively for educational practical work, defensive cybersecurity instruction, and security operations training. It operates inside the application request-response lifecycle as Django middleware. It is not a replacement for enterprise hardware edge firewalls, network tap sensors, or production cloud edge WAFs.

---

## 2. Key Features

- **Deep-Packet Normalization & Sanitization:**
  - Bounded 2-pass URL decoding (`unquote_plus`) to dismantle nested hex evasions.
  - Slashes normalization (`\ -> /`) and control-character CRLF stripping.
  - Automatic masking of sensitive fields (`password`, `token`, `secret`) in stored body previews.
- **Modular Heuristic Detection Engine:**
  - Specialized detectors for:
    - **SQL Injection (SQLi):** Union extraction, boolean tautologies (`' OR '1'='1`), stacked queries (`; DROP`).
    - **Cross-Site Scripting (XSS):** `<script>` tags, inline event handlers (`onerror=`, `onload=`), `javascript:` pseudo-protocols.
    - **Path Traversal & LFI:** Relative directory stepping (`../`, `..\`), sensitive Unix/Windows file paths (`/etc/passwd`, `win.ini`), null bytes.
    - **Command Injection (CMDi):** Shell metacharacters (`;`, `|`, `` ` ``), subshell syntax (`$(...)`), and binary invocations.
    - **Malformed Headers:** Scanner identification (`sqlmap`, `nikto`), Host poisoning, and CRLF header injection.
- **Sliding-Window Rate Limiting:**
  - Cache-backed per-client frequency monitoring.
  - Configurable threshold (60 req/min general, 10 req/min for `/auth/` routes).
  - Enforces HTTP 429 Too Many Requests with `Retry-After` header and temporary restriction cooldowns.
  - Safe handling of forwarded IPs (trusts `X-Forwarded-For` only when behind explicitly configured proxies).
- **Interactive SOC Operations Console (12 Complete Screens):**
  1. **SOC Dashboard:** Live KPI cards, Chart.js traffic ingress timeline, threat taxonomy donut chart, recent event stream, and active alert triage.
  2. **Live Request Inspector:** Interactive payload craft bench, HTTP method selector, safe test presets, and real-time heuristic verdict engine.
  3. **Attack Simulation Lab:** Controlled test bench with 16 OWASP test vectors, confusion matrix scoreboard (TP, TN, FP, FN, Accuracy, Precision, Recall).
  4. **Security Event Logs:** Forensic audit logs with multi-column filtering, search, and CSV export (formula injection defended).
  5. **Alert Management:** Incident queue with Acknowledgement and Resolution workflows with analyst notes.
  6. **Rate Limiting & IP Activity:** Sliding-window counters, flood history, and administrative IP cooldown unblocking.
  7. **Detection Rules:** Signature repository with live rule toggling switch and custom rule creator modal.
  8. **Analytics & Reports:** Visual analytics and on-demand formal academic PDF report generation via ReportLab.
  9. **Practical Journal:** Structured academic workbook for practical experiment submission.
  10. **System Settings:** Operational posture toggle (`ENFORCE` / `FLAG` / `MONITOR`), environmental telemetry, and safe disposable data reset.
  11. **Notifications & Help:** Quick-start guide, heuristic authoring syntax, and REST API documentation.
  12. **Operator Authentication:** Role-based access control (Admin, Analyst, Viewer) with preset credentials.

---

## 3. Technology Stack

- **Backend:** Python 3.12+ (tested on Python 3.13.5), Django 5.x, Django REST Framework.
- **Database:** SQLite3 for local development and academic labs (with a documented path to PostgreSQL).
- **Caching:** Django `LocMemCache` for sliding-window rate limiting.
- **Frontend:** Integrated Stitch Cyber Threat Operations design system, Tailwind CSS, Google Fonts (Inter, JetBrains Mono, Material Symbols), Chart.js.
- **Reporting:** ReportLab 4.x for PDF generation; custom formula-injection-defended CSV streaming.
- **Testing:** Django automated testing framework with isolated test database.

---

## 4. Directory Structure

```
sentinelshield/
├── manage.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── config/
│   ├── settings.py
│   ├── urls.py
│   ├── api_urls.py
│   ├── wsgi.py
│   └── asgi.py
├── apps/
│   ├── accounts/     # User model, roles (Admin, Analyst, Viewer), permissions
│   ├── inspector/    # Request inspection middleware, sanitizers, body validation
│   ├── detections/   # DetectionRule model, patterns, regex engine
│   ├── traffic/      # SecurityEvent model, management commands (seed/reset)
│   ├── alerts/       # SecurityAlert model, triage workflows
│   ├── ratelimit/    # RateLimiter sliding window, RateLimitEvent model
│   ├── simulation/   # TestRun & TestCaseResult models, benchmark runner
│   ├── audit/        # AuditLog model, audit trail recording
│   ├── reporting/    # PracticalReport model, PDF (ReportLab) & CSV generators
│   └── dashboard/    # Context processors, UI view handlers, REST API viewsets
├── templates/
│   ├── base.html
│   ├── auth/login.html
│   └── dashboard/    # 11 operational SOC templates matching Stitch design
├── static/
├── media/            # Generated PDF practical reports
├── tests/            # Automated test suite (27 unit and integration tests)
└── docs/             # Architecture, Security Model, Journal, Deployment
```

---

## 5. Prerequisites

- **Python:** 3.12 or compatible installed version (e.g. 3.13).
- **Shell:** Windows PowerShell, Windows Command Prompt, or Linux/macOS bash.
- **Git** (optional).

---

## 6. Installation & Quick Start (Windows PowerShell)

Open **PowerShell** and navigate to the project directory:

```powershell
cd d:\stitch_sentinelshield_soc_platform
```

### Step 1: Create and Activate Virtual Environment (Optional if globally installed)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 2: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 3: Run Database Migrations
```powershell
python manage.py migrate
```

### Step 4: Seed Educational Demo Data
Populate default detection rules, test accounts, realistic 24-hour event telemetry, and generate a baseline practical PDF report:
```powershell
python manage.py seed_demo_data
```

### Step 5: Start Development Server
```powershell
python manage.py runserver 8000
```

Open your browser and visit: **[http://localhost:8000](http://localhost:8000)**

---

## 7. Educational Default Credentials

| Username | Password | Role | Description |
|---|---|---|---|
| `admin` | `admin123` | **Security Administrator** | Full administrative rights, rule creation, settings policy configuration |
| `analyst` | `sentinel123` | **SOC Threat Analyst** | Incident triage, alert acknowledgement/resolution, event review |
| `viewer` | `viewer123` | **Academic Viewer** | Read-only observation of telemetry, simulation lab, and journal |

---

## 8. Step-by-Step Practical Testing Guide

### Test 1: Verify Legitimate Request Passing
1. Open the **Live Request Inspector** (`/dashboard/inspector/`).
2. Click the preset button **"Safe Request"**.
3. Click **"Transmit & Inspect Request"**.
4. **Result:** The decision card turns **GREEN (ALLOWED 200)** with 0 rule violations and ~1.5ms latency.

### Test 2: Verify SQL Injection Mitigation
1. In the Inspector, click the preset **"SQL Injection"** (`username=admin' OR '1'='1`).
2. Click **"Transmit & Inspect Request"**.
3. **Result:** The decision card turns **RED (BLOCKED 403)**, displaying violation `SQLI-002: Boolean Tautology SQL Injection`.
4. Open the **SOC Dashboard** (`/dashboard/`) to confirm the blocked event is logged and visible in recent events.

### Test 3: Verify Rate Limiting
1. Open PowerShell and send rapid requests exceeding the 60 req/min threshold:
```powershell
1..65 | ForEach-Object { Invoke-RestMethod -Uri "http://localhost:8000/dashboard/" }
```
2. **Result:** Once the threshold is crossed, the server returns **HTTP 429 Too Many Requests** with `Retry-After: 300`.
3. Open **Rate Limiting & IP Activity** (`/dashboard/ratelimit/`) to see the recorded flood event. Click **"Reset IP"** to clear the restriction.

### Test 4: Run Heuristic Validation Benchmark
1. Navigate to the **Attack Simulation Lab** (`/dashboard/simulation/`).
2. Click **"Run Benchmark Suite"**.
3. **Result:** All 16 OWASP test vectors are evaluated in memory. The Confusion Matrix Scorecard updates live to show **100% Accuracy, 100% Precision, 100% Recall (13 TP, 3 TN, 0 FP, 0 FN)**.

### Test 5: Generate Formal Practical PDF Report
1. Go to **Analytics & Reports** (`/dashboard/analytics/`).
2. Click **"Generate Formal Practical Report"**.
3. Click **"Generate & Download"**.
4. **Result:** A formatted PDF report is compiled using ReportLab with telemetry tables and forensic findings, saved to `media/reports/`.

---

## 9. REST API Reference (`/api/v1/`)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/dashboard/summary/` | High-level KPI telemetry (requests, blocked, latency, engine state) |
| `GET` | `/api/v1/dashboard/traffic/` | Chronological time-series ingress data for charts |
| `GET` | `/api/v1/events/` | Paginated security event logs with filtering and search |
| `GET` | `/api/v1/events/export_csv/` | Export event logs to CSV (formula-injection protected) |
| `GET` | `/api/v1/alerts/` | List security incident alerts |
| `PATCH`| `/api/v1/alerts/{id}/acknowledge/`| Acknowledge an alert |
| `PATCH`| `/api/v1/alerts/{id}/resolve/` | Resolve an alert with analyst notes |
| `GET` | `/api/v1/rules/` | List detection rules |
| `PATCH`| `/api/v1/rules/{id}/toggle/` | Enable or disable a detection rule in real time |
| `GET` | `/api/v1/rate-limits/` | List rate limiting history |
| `POST` | `/api/v1/rate-limits/reset_client/`| Administrative unblock of client IP |
| `GET` | `/api/v1/analytics/` | Category breakdown, severity breakdown, and accuracy metrics |
| `GET` | `/api/v1/reports/` | List generated practical assessment reports |
| `POST` | `/api/v1/reports/generate/` | Compile new practical PDF report |
| `GET` | `/api/v1/test-runs/` | List simulation test runs |
| `POST` | `/api/v1/test-runs/` | Execute automated benchmark suite |
| `POST` | `/api/v1/simulation/inspect/` | In-memory safe ad-hoc payload inspection sandbox |
| `GET` | `/api/v1/system/health/` | System health check (RAM, DB, active rules, uptime) |
| `POST` | `/api/v1/system/reset-demo-data/` | Clear disposable simulation telemetry safely |

---

## 10. Testing and Verification

Run the complete 27-test automated verification suite:

```powershell
python manage.py test tests
```

Expected output:
```
Ran 27 tests in 36.419s

OK
Destroying test database for alias 'default'...
```

---

## 11. Troubleshooting

- **`System check identified no issues` but port is in use:**
  Run on an alternate port: `python manage.py runserver 8080`.
- **Resetting Test Data:**
  If you wish to clear disposable test telemetry while keeping accounts and detection rules intact:
  ```powershell
  python manage.py reset_demo_data
  ```
- **Static assets not loading:**
  Run `python manage.py collectstatic --noinput`.

---

## 12. Documentation Index

- [Architecture Specification](file:///d:/stitch_sentinelshield_soc_platform/docs/ARCHITECTURE.md)
- [Security Model & Defensive Posture](file:///d:/stitch_sentinelshield_soc_platform/docs/SECURITY_MODEL.md)
- [Academic Practical Journal Template](file:///d:/stitch_sentinelshield_soc_platform/docs/PRACTICAL_JOURNAL_TEMPLATE.md)
- [Testing & Verification Results](file:///d:/stitch_sentinelshield_soc_platform/docs/TESTING_AND_RESULTS.md)
- [Production & Deployment Guide](file:///d:/stitch_sentinelshield_soc_platform/docs/DEPLOYMENT.md)
