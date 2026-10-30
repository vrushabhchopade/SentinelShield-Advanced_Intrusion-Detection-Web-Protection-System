"""
SentinelShield Modular Detection Engine.
Performs input normalization, recursive-decode bounding, component extraction,
and safe multi-pattern regex matching.
"""

import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from .models import AttackCategory, RuleSeverity, DetectionRule
from .patterns import DEFAULT_RULES

MAX_DECODE_PASSES = 2
MAX_INSPECTION_BUFFER_LEN = 16384  # Max 16KB per single component for regex safety

# Compile-time cache for compiled regex patterns
_COMPILED_PATTERN_CACHE: Dict[str, re.Pattern] = {}

@dataclass
class RuleMatch:
    rule_id: str
    name: str
    category: str
    severity: str
    target_component: str
    snippet: str
    reason: str

@dataclass
class InspectionResult:
    is_threat: bool
    matched_rules: List[RuleMatch] = field(default_factory=list)
    primary_category: str = AttackCategory.NORMAL
    highest_severity: str = RuleSeverity.INFO
    safe_reason: str = "Request passed heuristic inspection."
    execution_time_ms: float = 0.0

    @property
    def matched_rule_ids(self) -> List[str]:
        return [m.rule_id for m in self.matched_rules]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_threat': self.is_threat,
            'primary_category': self.primary_category,
            'highest_severity': self.highest_severity,
            'safe_reason': self.safe_reason,
            'execution_time_ms': self.execution_time_ms,
            'matched_rules': [
                {
                    'rule_id': m.rule_id,
                    'name': m.name,
                    'category': m.category,
                    'severity': m.severity,
                    'target_component': m.target_component,
                    'snippet': m.snippet,
                    'reason': m.reason,
                }
                for m in self.matched_rules
            ]
        }


def safe_normalize_string(val: Optional[str]) -> str:
    """
    Normalizes input by URL-decoding safely with a bounded number of passes,
    normalizing slashes, and handling null characters safely.
    """
    if not val or not isinstance(val, str):
        return ""

    s = val[:MAX_INSPECTION_BUFFER_LEN]

    # Bounded URL decode to prevent recursive decode bypasses or infinite loops
    for _ in range(MAX_DECODE_PASSES):
        try:
            decoded = urllib.parse.unquote_plus(s)
            if decoded == s:
                break
            s = decoded
        except Exception:
            break

    # Normalize backslashes to forward slashes for unified traversal detection
    s_norm = s.replace('\\', '/')
    return s_norm


def get_compiled_pattern(pattern_str: str) -> Optional[re.Pattern]:
    """Retrieves compiled pattern from cache or compiles it safely."""
    if pattern_str in _COMPILED_PATTERN_CACHE:
        return _COMPILED_PATTERN_CACHE[pattern_str]

    try:
        compiled = re.compile(pattern_str, re.IGNORECASE)
        _COMPILED_PATTERN_CACHE[pattern_str] = compiled
        return compiled
    except re.error:
        return None


def get_active_rules() -> List[Dict[str, Any]]:
    """
    Loads active detection rules from the database if available;
    otherwise falls back to default in-memory rules.
    """
    try:
        db_rules = DetectionRule.objects.filter(enabled=True).values(
            'rule_id', 'name', 'category', 'severity', 'pattern', 'target_components', 'description'
        )
        if db_rules.exists():
            return list(db_rules)
    except Exception:
        # DB may not be ready during migrations or initial checks
        pass
    return DEFAULT_RULES


class DetectionEngine:
    """
    Modular Rule-Based Detection Engine.
    Executes signatures against specified request components.
    """

    SEVERITY_ORDER = {
        RuleSeverity.INFO: 1,
        RuleSeverity.LOW: 2,
        RuleSeverity.MEDIUM: 3,
        RuleSeverity.HIGH: 4,
        RuleSeverity.CRITICAL: 5,
    }

    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None):
        self._rules = rules

    def get_rules(self) -> List[Dict[str, Any]]:
        if self._rules is not None:
            return self._rules
        return get_active_rules()

    def inspect_request(
        self,
        path: str = "",
        query_string: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        method: str = "GET"
    ) -> InspectionResult:
        """
        Inspects all candidate components against configured detection rules.
        """
        start_time = time.perf_counter()
        headers = headers or {}
        matches: List[RuleMatch] = []

        # Safe component normalization
        normalized_path = safe_normalize_string(path)
        normalized_query = safe_normalize_string(query_string)
        normalized_body = safe_normalize_string(body)

        # Inspect headers: construct header string representation safely
        header_snippets = []
        for h_key, h_val in headers.items():
            if h_val:
                header_snippets.append(f"{h_key}: {h_val}")
        normalized_headers = safe_normalize_string("\n".join(header_snippets))

        components_map = {
            'path': normalized_path,
            'query': normalized_query,
            'body': normalized_body,
            'headers': normalized_headers,
        }

        rules = self.get_rules()

        for rule in rules:
            pattern_str = rule.get('pattern', '')
            if not pattern_str:
                continue

            compiled = get_compiled_pattern(pattern_str)
            if not compiled:
                continue

            target_components = rule.get('target_components', ['path', 'query', 'body', 'headers'])

            for comp_name in target_components:
                comp_text = components_map.get(comp_name, "")
                if not comp_text:
                    continue

                try:
                    match_obj = compiled.search(comp_text)
                    if match_obj:
                        # Extract bounded snippet for safe reporting
                        matched_span = match_obj.group(0)
                        safe_snippet = (matched_span[:60] + "...") if len(matched_span) > 60 else matched_span

                        matches.append(RuleMatch(
                            rule_id=rule['rule_id'],
                            name=rule['name'],
                            category=rule['category'],
                            severity=rule.get('severity', RuleSeverity.MEDIUM),
                            target_component=comp_name,
                            snippet=safe_snippet,
                            reason=f"Matched pattern {rule['rule_id']} ({rule['name']}) in {comp_name}"
                        ))
                        # Move to next rule once matched in this rule to avoid duplicates for same rule
                        break
                except Exception:
                    # Ignore single rule execution error safely
                    continue

        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

        if not matches:
            return InspectionResult(
                is_threat=False,
                matched_rules=[],
                primary_category=AttackCategory.NORMAL,
                highest_severity=RuleSeverity.INFO,
                safe_reason="Normal traffic signature validated.",
                execution_time_ms=duration_ms
            )

        # Determine highest severity and primary category
        highest_sev = max(
            matches,
            key=lambda m: self.SEVERITY_ORDER.get(m.severity, 0)
        ).severity

        # Determine dominant attack category (from highest severity match)
        primary_match = max(
            matches,
            key=lambda m: self.SEVERITY_ORDER.get(m.severity, 0)
        )
        primary_category = primary_match.category

        matched_names = ", ".join(f"{m.rule_id} [{m.name}]" for m in matches[:3])
        safe_reason = f"Security heuristic violation: {matched_names}"
        if len(matches) > 3:
            safe_reason += f" (+{len(matches)-3} more)"

        return InspectionResult(
            is_threat=True,
            matched_rules=matches,
            primary_category=primary_category,
            highest_severity=highest_sev,
            safe_reason=safe_reason,
            execution_time_ms=duration_ms
        )
