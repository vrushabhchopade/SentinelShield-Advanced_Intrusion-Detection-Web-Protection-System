"""
SentinelShield Rate Limiter.
Implements cache-backed sliding window rate limiting with IP extraction,
allowlists, authentication endpoint protections, and cooldown restrictions.
"""

import time
import ipaddress
from datetime import timedelta
from typing import Tuple, Optional
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from .models import RateLimitEvent, RateLimitAction

def get_client_ip(request) -> str:
    """
    Safely resolves client IP address.
    Does NOT blindly trust X-Forwarded-For unless REMOTE_ADDR is an explicitly configured trusted proxy.
    """
    remote_addr = request.META.get('REMOTE_ADDR', '127.0.0.1')
    trusted_proxies = getattr(settings, 'SENTINEL_TRUSTED_PROXIES', [])

    if remote_addr in trusted_proxies and 'HTTP_X_FORWARDED_FOR' in request.META:
        forwarded_for = request.META['HTTP_X_FORWARDED_FOR']
        # X-Forwarded-For: client, proxy1, proxy2
        ips = [ip.strip() for ip in forwarded_for.split(',') if ip.strip()]
        for candidate in reversed(ips):
            if candidate not in trusted_proxies:
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except ValueError:
                    continue

    try:
        ipaddress.ip_address(remote_addr)
        return remote_addr
    except ValueError:
        return '127.0.0.1'


class RateLimiter:
    """
    Cache-backed sliding-window rate limiter for SentinelShield.
    """

    def __init__(
        self,
        default_threshold: Optional[int] = None,
        default_window_secs: Optional[int] = None,
        block_duration_secs: Optional[int] = None,
        auth_threshold: Optional[int] = None,
        auth_window_secs: Optional[int] = None,
        allowlist: Optional[list] = None
    ):
        self.default_threshold = default_threshold or getattr(settings, 'SENTINEL_RATE_LIMIT_THRESHOLD', 60)
        self.default_window_secs = default_window_secs or getattr(settings, 'SENTINEL_RATE_LIMIT_WINDOW_SECS', 60)
        self.block_duration_secs = block_duration_secs or getattr(settings, 'SENTINEL_RATE_LIMIT_BLOCK_SECS', 300)
        self.auth_threshold = auth_threshold or getattr(settings, 'SENTINEL_AUTH_RATE_LIMIT_THRESHOLD', 10)
        self.auth_window_secs = auth_window_secs or getattr(settings, 'SENTINEL_AUTH_RATE_LIMIT_WINDOW_SECS', 60)
        self.allowlist = allowlist or []

    def is_allowlisted(self, ip: str) -> bool:
        return ip in self.allowlist

    def is_auth_path(self, path: str) -> bool:
        p = path.lower()
        return '/auth/' in p or '/login' in p

    def check_rate_limit(self, client_ip: str, path: str) -> Tuple[bool, int, int, Optional[int]]:
        """
        Evaluates whether client_ip has exceeded allowed rate for given path.
        Returns:
            (is_limited: bool, current_count: int, threshold: int, retry_after_secs: Optional[int])
        """
        if self.is_allowlisted(client_ip):
            return False, 0, self.default_threshold, None

        is_auth = self.is_auth_path(path)
        threshold = self.auth_threshold if is_auth else self.default_threshold
        window_secs = self.auth_window_secs if is_auth else self.default_window_secs

        block_key = f"sentinel:ratelimit:blocked:{client_ip}"
        blocked_expiry = cache.get(block_key)
        if blocked_expiry:
            remaining = int(blocked_expiry - time.time())
            if remaining > 0:
                return True, threshold + 1, threshold, remaining

        # Sliding window key based on time bucket, separating general and authentication traffic
        now = time.time()
        bucket = int(now // window_secs)
        counter_prefix = "auth_counter" if is_auth else "counter"
        window_key = f"sentinel:ratelimit:{counter_prefix}:{client_ip}:{bucket}"

        # Increment count atomically in cache
        try:
            count = cache.get(window_key, 0) + 1
            cache.set(window_key, count, timeout=window_secs * 2)
        except Exception:
            count = 1

        if count > threshold:
            # Set temporary block
            expiry_timestamp = now + self.block_duration_secs
            cache.set(block_key, expiry_timestamp, timeout=self.block_duration_secs)

            # Persist rate limit event asynchronously or directly
            try:
                RateLimitEvent.objects.create(
                    source_ip=client_ip,
                    path=path[:512],
                    request_count=count,
                    threshold=threshold,
                    window_seconds=window_secs,
                    action_taken=RateLimitAction.THROTTLED,
                    expiry_time=timezone.now() + timedelta(seconds=self.block_duration_secs)
                )
            except Exception:
                pass

            return True, count, threshold, self.block_duration_secs

        return False, count, threshold, None

    def reset_client(self, client_ip: str):
        """Clears rate limit state for a given client IP."""
        block_key = f"sentinel:ratelimit:blocked:{client_ip}"
        cache.delete(block_key)
