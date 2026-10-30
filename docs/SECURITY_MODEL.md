# SentinelShield Security Model & Defensive Posture

## 1. Educational Defensive Scope Notice

SentinelShield is engineered specifically for defensive cybersecurity instruction, practical academic exercises, and SOC operator training. It operates inside the application request-response lifecycle as application-level middleware.

### Scope Boundaries:
- **What SentinelShield Is:**
  - An educational Layer 7 Web Application Firewall (WAF) simulator.
  - A signature-based and heuristic HTTP request inspection engine.
  - A training simulator with realistic telemetry, incident queues, and confusion matrix benchmarking.
- **What SentinelShield Is Not:**
  - Not an enterprise replacement for hardware edge firewalls (e.g. Palo Alto, Fortinet).
  - Not an edge CDN WAF (e.g. Cloudflare, AWS WAF, Akamai).
  - Not a Layer 3/4 volumetric DDoS scrubber or raw packet sniffer.

## 2. Threat Modeling & Safeguards

| Threat Vector | Mitigation Strategy Implemented in SentinelShield |
|---|---|
| **SQL Injection (SQLi)** | Bounded normalized token matching on UNION SELECT, boolean tautologies (`' OR '1'='1`), stacked queries (`; DROP`), and sleep functions. |
| **Cross-Site Scripting (XSS)** | Detection of `<script>` tags, inline DOM event handlers (`onerror=`, `onload=`), `javascript:` pseudo-protocols, and unsafe sinks. |
| **Path Traversal / LFI** | Identification of relative path stepping (`../`, `..\`), sensitive Unix files (`/etc/passwd`), Windows files (`win.ini`, `system32`), and null bytes. |
| **Command Injection (CMDi)**| Detection of shell metacharacters (`;`, `|`, `` ` ``), subshell syntax (`$(...)`), and explicit binary invocations (`/bin/sh`, `powershell.exe`). |
| **Protocol Tampering** | Scanner User-Agent identification (`sqlmap`, `nikto`), Host header anomaly detection, and CRLF injection defenses. |
| **Volume Floods / Brute Force**| Cache-backed sliding-window rate limiting (60 req/min general, 10 req/min auth endpoints) triggering HTTP 429 restrictions. |
| **ReDoS (Regex DoS)** | Upper-bounded string buffers (16 KB max per component), non-backtracking regex compilation, and bounded 2-pass URL decoding. |
| **Log Injection (CRLF)** | Control character stripping (`\r`, `\n`) before persisting strings to event logs or audit trails. |
| **CSV Formula Injection** | Prepends single quotes (`'`) to any cell beginning with `=`, `+`, `-`, `@` during CSV telemetry exports (CWE-1236). |
| **Credential Leakage** | Complete suppression of cookies, session tokens, Authorization Bearer headers, and automatic password masking in body previews. |

## 3. Trusted Proxy & IP Extraction Architecture

SentinelShield does **not** blindly trust the incoming `X-Forwarded-For` header.
- If `REMOTE_ADDR` matches an explicitly configured IP in `SENTINEL_TRUSTED_PROXIES`, the middleware inspects the nearest untrusted upstream IP from `X-Forwarded-For`.
- If `REMOTE_ADDR` is not in `SENTINEL_TRUSTED_PROXIES`, SentinelShield strictly enforces `REMOTE_ADDR` as the client IP, preventing header spoofing attacks.
