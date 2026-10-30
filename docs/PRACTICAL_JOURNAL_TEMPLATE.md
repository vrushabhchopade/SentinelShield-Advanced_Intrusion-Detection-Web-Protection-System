# Academic Practical Security Journal Template

**Course:** Defensive Web Security & Incident Response  
**Laboratory Practical:** Web Application Firewall (WAF) Simulation & Telemetry Analysis  
**Student / Analyst:** Dr. Elena Rostova / Student  
**System Tested:** SentinelShield v2.4 (Educational SOC Defense Matrix)  

---

## 1. Experiment Overview
- **Title:** Heuristic Intrusion Detection & Rate-Limiting Mitigation Practical
- **Date Executed:** 2026-10-28
- **Laboratory Environment:** Localhost Isolated Sandbox (Python 3.13 / Django 5.x / SQLite3)
- **Objective:** Evaluate the capability of an application-layer inspection middleware to identify and mitigate OWASP Top 10 web injection vectors without disrupting normal application traffic.

---

## 2. Methodology & Test Cases

| Case ID | Scenario Name | Category | Test Vector | Expected Decision | Actual Outcome | Status |
|---|---|---|---|---|---|---|
| **NORM-001** | Benign Search | Normal | `/api/v1/search?q=cybersecurity` | ALLOWED | ALLOWED (200) | PASS |
| **SQLI-01** | Tautology Bypass | SQLi | `username=admin' OR '1'='1` | BLOCKED | BLOCKED (403) | PASS |
| **SQLI-02** | Union Exfiltration | SQLi | `id=1 UNION SELECT 1,username,pass` | BLOCKED | BLOCKED (403) | PASS |
| **XSS-01** | Script Injection | XSS | `<script>alert('XSS')</script>` | BLOCKED | BLOCKED (403) | PASS |
| **TRAV-01** | LFI / Passwd | Traversal | `../../../../etc/passwd` | BLOCKED | BLOCKED (403) | PASS |
| **CMDI-01** | Shell Chain | CMDi | `127.0.0.1; whoami` | BLOCKED | BLOCKED (403) | PASS |
| **RATE-01** | Flood Ingress | RateLimit | Rapid 35 req/10s burst | RATE_LIMITED | RATE_LIMITED (429) | PASS |

---

## 3. Confusion Matrix Accuracy Metrics

Evaluated across the 16 standard educational benchmark cases:
- **True Positives (TP):** 13 attacks correctly blocked.
- **True Negatives (TN):** 3 legitimate requests permitted.
- **False Positives (FP):** 0 legitimate requests blocked.
- **False Negatives (FN):** 0 attacks missed.
- **Accuracy:** `(13 + 3) / 16 = 100.0%`
- **Precision:** `13 / (13 + 0) = 100.0%`
- **Recall / Sensitivity:** `13 / (13 + 0) = 100.0%`

---

## 4. Security Event Log Forensics

1. **Event `EVT-SQLI-01`:** Inspection of query string identified `SQLI-002` pattern (`(?i)\bOR\s+'1'='1`). Decision rendered `BLOCKED` with latency of 1.8 ms.
2. **Alert Triggered:** An incident alert `ALT-SQLI-001` was raised with `CRITICAL` severity and assigned to the SOC queue.

---

## 5. Defensive Recommendations & Conclusions
1. Always pair WAF signatures with parameterization and strict server-side validation.
2. Maintain bounded input normalization to prevent multi-encoded evasion.
3. Utilize distributed caching (Redis) for high-availability rate limiting across multiple worker nodes.
