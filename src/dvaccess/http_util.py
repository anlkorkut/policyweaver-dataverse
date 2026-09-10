"""Shared HTTP plumbing: bearer auth, 429/5xx retry with Retry-After, 401 refresh
including Continuous Access Evaluation (CAE) claims challenges."""

from __future__ import annotations

import base64
import logging
import re
import time

import httpx

from .auth import TokenProvider

logger = logging.getLogger(__name__)


def _cae_claims_challenge(response: httpx.Response) -> str | None:
    """Extract and decode the CAE claims challenge from WWW-Authenticate, if any."""
    for challenge in response.headers.get_list("WWW-Authenticate"):
        if "insufficient_claims" not in challenge:
            continue
        match = re.search(r'claims="([^"]+)"', challenge)
        if match:
            value = match.group(1)
            value += "=" * (-len(value) % 4)
            try:
                return base64.b64decode(value).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return None
    return None

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 6
_MAX_AUTH_REFRESHES = 3  # long extracts cross token expiry; refresh more than once
_DEFAULT_BACKOFF_SECONDS = 5.0


class ApiError(RuntimeError):
    def __init__(self, message: str, response: httpx.Response | None = None):
        super().__init__(message)
        self.response = response
        self.status_code = response.status_code if response is not None else None


def authorized_request(
    http: httpx.Client,
    method: str,
    url: str,
    *,
    token_provider: TokenProvider,
    scope: str,
    headers: dict | None = None,
    params: dict | None = None,
    json: object | None = None,
) -> httpx.Response:
    """Issue a request with bearer auth; retry on throttling/transient errors and
    refresh the token once on 401. Raises ApiError on non-success."""
    attempt = 0
    refreshes = 0
    while True:
        request_headers = {"Authorization": f"Bearer {token_provider.token(scope)}"}
        if headers:
            request_headers.update(headers)
        try:
            response = http.request(method, url, headers=request_headers, params=params, json=json)
        except httpx.TransportError as exc:
            # Stale keep-alive connections, resets, timeouts: safe to retry GETs;
            # PUT/PATCH retries are bounded and idempotent in this app (full-state
            # replacement with ETag concurrency).
            if attempt >= _MAX_RETRIES:
                raise ApiError(f"{method} {url} failed after retries: {exc}") from exc
            delay = _DEFAULT_BACKOFF_SECONDS * (attempt + 1)
            logger.warning(
                "Transport error on %s %s (%s); retrying in %.0fs (attempt %d/%d)",
                method, url, exc, delay, attempt + 1, _MAX_RETRIES,
            )
            time.sleep(delay)
            attempt += 1
            continue
        if response.status_code < 300:
            return response
        if response.status_code == 401 and refreshes < _MAX_AUTH_REFRESHES:
            refreshes += 1
            claims = _cae_claims_challenge(response)
            logger.warning(
                "HTTP 401 on %s %s; %s (attempt %d/%d)",
                method, url,
                "answering CAE claims challenge" if claims else "refreshing token",
                refreshes, _MAX_AUTH_REFRESHES,
            )
            token_provider.invalidate(scope)
            if claims:
                token_provider.token(scope, claims=claims)  # caches the challenge-satisfying token
            time.sleep(2.0 * refreshes)  # tolerate token clock skew / CLI refresh lag
            continue
        if response.status_code in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
            retry_after = response.headers.get("Retry-After")
            try:
                delay = float(retry_after) if retry_after else _DEFAULT_BACKOFF_SECONDS * (attempt + 1)
            except ValueError:
                delay = _DEFAULT_BACKOFF_SECONDS * (attempt + 1)
            logger.warning(
                "HTTP %s on %s %s; retrying in %.0fs (attempt %d/%d)",
                response.status_code, method, url, delay, attempt + 1, _MAX_RETRIES,
            )
            time.sleep(delay)
            attempt += 1
            continue
        raise ApiError(
            f"{method} {url} failed with HTTP {response.status_code}: {response.text[:2000]}",
            response,
        )
