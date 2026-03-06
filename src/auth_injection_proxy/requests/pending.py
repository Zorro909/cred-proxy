"""In-memory pending credential request store with TTL and rate limiting."""

from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum

import httpx

logger = logging.getLogger(__name__)


class RequestStatus(Enum):
    PENDING = "pending"
    FULFILLED = "fulfilled"
    EXPIRED = "expired"


@dataclass
class PendingRequest:
    token: str
    domain: str
    reason: str
    auth_type: str | None
    created_at: float
    ttl: int
    status: RequestStatus = RequestStatus.PENDING
    credential_id: str | None = None
    webhook_url: str | None = None


@dataclass
class SlidingWindowRateLimiter:
    """Simple sliding window rate limiter."""

    max_requests: int = 10
    window_seconds: int = 60
    _timestamps: list[float] = field(default_factory=list)

    def allow(self) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        if len(self._timestamps) >= self.max_requests:
            return False
        self._timestamps.append(now)
        return True


def _fire_webhook(webhook_url: str, payload: dict) -> None:
    """Fire-and-forget webhook notification. 5s timeout, single attempt."""
    try:
        httpx.post(webhook_url, json=payload, timeout=5.0)
        logger.info("Webhook fired: url=%s", webhook_url)
    except Exception as e:
        logger.warning("Webhook failed: url=%s error=%s", webhook_url, e)


class PendingRequestStore:
    def __init__(self, default_ttl: int = 900) -> None:
        self._requests: dict[str, PendingRequest] = {}
        self._lock = threading.Lock()
        self._default_ttl = default_ttl
        self._rate_limiter = SlidingWindowRateLimiter()

    def create(
        self,
        domain: str,
        reason: str,
        auth_type: str | None = None,
        ttl: int | None = None,
        webhook_url: str | None = None,
    ) -> PendingRequest:
        """Create a new pending credential request. Returns the request with token."""
        token = secrets.token_urlsafe(32)
        req = PendingRequest(
            token=token,
            domain=domain,
            reason=reason,
            auth_type=auth_type,
            created_at=time.monotonic(),
            ttl=ttl if ttl is not None else self._default_ttl,
            webhook_url=webhook_url,
        )
        with self._lock:
            self._requests[token] = req
        return req

    def get(self, token: str) -> PendingRequest | None:
        with self._lock:
            req = self._requests.get(token)
            if req is None:
                return None
            # Check expiry
            if req.status == RequestStatus.PENDING:
                if time.monotonic() - req.created_at > req.ttl:
                    req.status = RequestStatus.EXPIRED
                    self._notify_webhook(req)
            return req

    def get_status(self, token: str) -> RequestStatus | None:
        req = self.get(token)
        if req is None:
            return None
        return req.status

    def fulfill(self, token: str, credential_id: str) -> bool:
        """Mark a request as fulfilled. Returns True on success, False if not pending."""
        with self._lock:
            req = self._requests.get(token)
            if req is None:
                return False
            # Check expiry
            if time.monotonic() - req.created_at > req.ttl:
                req.status = RequestStatus.EXPIRED
                return False
            if req.status != RequestStatus.PENDING:
                return False
            req.status = RequestStatus.FULFILLED
            req.credential_id = credential_id
        self._notify_webhook(req)
        return True

    def _notify_webhook(self, req: PendingRequest) -> None:
        """Fire webhook notification if webhook_url is set."""
        if not req.webhook_url:
            return
        payload = {
            "token": req.token,
            "status": req.status.value,
            "domain": req.domain,
        }
        thread = threading.Thread(
            target=_fire_webhook,
            args=(req.webhook_url, payload),
            daemon=True,
        )
        thread.start()

    def check_rate_limit(self) -> bool:
        """Returns True if the request is allowed, False if rate-limited."""
        return self._rate_limiter.allow()

    def cleanup_expired(self) -> int:
        """Remove expired requests from memory. Returns count removed."""
        now = time.monotonic()
        removed = 0
        with self._lock:
            expired_tokens = [
                t
                for t, r in self._requests.items()
                if r.status == RequestStatus.EXPIRED
                or (r.status == RequestStatus.PENDING and now - r.created_at > r.ttl)
            ]
            for t in expired_tokens:
                req = self._requests[t]
                if req.status == RequestStatus.PENDING:
                    req.status = RequestStatus.EXPIRED
                    self._notify_webhook(req)
                del self._requests[t]
                removed += 1
        return removed
