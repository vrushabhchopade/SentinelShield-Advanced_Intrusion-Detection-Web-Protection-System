"""
Sanitization and safe extraction utilities for SentinelShield inspection pipeline.
Protects against log injection, secrets leakage, and unbounded buffer consumption.
"""

import re
import json
from typing import Dict, Any

SENSITIVE_KEY_PATTERN = re.compile(
    r'(?i)(password|passwd|token|secret|api_?key|auth|bearer|cookie|credit_?card|ssn)'
)

SAFE_HEADER_WHITELIST = {
    'HTTP_USER_AGENT',
    'HTTP_ACCEPT',
    'HTTP_ACCEPT_LANGUAGE',
    'HTTP_ACCEPT_ENCODING',
    'HTTP_REFERER',
    'HTTP_ORIGIN',
    'HTTP_HOST',
    'CONTENT_TYPE',
    'CONTENT_LENGTH',
}

def sanitize_crlf(val: Any) -> str:
    """Removes CRLF and control characters to prevent log injection."""
    if val is None:
        return ""
    s = str(val)
    return re.sub(r'[\r\n\x00-\x1f\x7f]', ' ', s).strip()


def extract_safe_headers(request) -> Dict[str, str]:
    """
    Extracts only non-sensitive operational headers from request.META.
    Never inspects or persists cookies, auth bearer tokens, or session tokens.
    """
    safe_headers = {}
    for meta_key, meta_val in request.META.items():
        if meta_key in SAFE_HEADER_WHITELIST and isinstance(meta_val, str):
            clean_name = meta_key.replace('HTTP_', '').replace('_', '-').title()
            safe_headers[clean_name] = sanitize_crlf(meta_val)[:256]
    return safe_headers


def redact_sensitive_body(body_bytes: bytes, max_len: int = 512) -> str:
    """
    Attempts to parse body safely and mask sensitive fields (password, token, etc.).
    Falls back to safe truncated UTF-8 string with CRLF sanitization.
    """
    if not body_bytes:
        return ""

    try:
        raw_text = body_bytes.decode('utf-8', errors='replace')
    except Exception:
        raw_text = body_bytes.decode('latin-1', errors='replace')

    # Try JSON redaction
    try:
        data = json.loads(raw_text)
        if isinstance(data, dict):
            redacted = {}
            for k, v in data.items():
                if SENSITIVE_KEY_PATTERN.search(str(k)):
                    redacted[k] = "[REDACTED_SECRET]"
                else:
                    redacted[k] = v
            return sanitize_crlf(json.dumps(redacted))[:max_len]
    except Exception:
        pass

    # Regex masking for common key=value format (e.g. password=secret)
    masked = SENSITIVE_KEY_PATTERN.sub(r'\1=[REDACTED]', raw_text)
    return sanitize_crlf(masked)[:max_len]
