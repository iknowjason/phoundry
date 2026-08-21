"""VirusTotal API v3 client — lookup only, rate-limited, cached.

Two constraints drive this design:

1. The public API allows 4 requests/minute and 500/day. A single phishing email
   can contain 20+ indicators, so the agent must *choose* what to look up. The
   throttle here is a backstop, not the plan.
2. Submitting content to VirusTotal publishes it to every VT enterprise
   subscriber. Uploading a customer's attachment is a data leak, so submission
   endpoints are not implemented at all — lookup by hash is safe, upload is not.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

import httpx

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Public tier: 4 requests per minute.
PUBLIC_RATE = 4
PUBLIC_WINDOW_SECONDS = 60.0


class VirusTotalError(RuntimeError):
    pass


class QuotaExhausted(VirusTotalError):
    """VT returned 429. Callers should degrade gracefully, not crash the triage."""


class _RateLimiter:
    """Sliding-window limiter, shared across threads."""

    def __init__(self, max_calls: int, window: float) -> None:
        self._max_calls = max_calls
        self._window = window
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Block until a slot is free. Returns seconds waited."""
        waited = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self._window:
                    self._calls.popleft()
                if len(self._calls) < self._max_calls:
                    self._calls.append(now)
                    return waited
                sleep_for = self._window - (now - self._calls[0]) + 0.05
            time.sleep(sleep_for)
            waited += sleep_for


class VirusTotalClient:
    """Read-only VirusTotal v3 client with an on-disk cache."""

    def __init__(
        self,
        api_key: str,
        *,
        tier: str = "public",
        cache_dir: Path | None = None,
        cache_ttl_seconds: int = 24 * 3600,
        timeout: float = 30.0,
    ) -> None:
        self._client = httpx.Client(
            base_url=VT_BASE_URL,
            headers={"x-apikey": api_key, "Accept": "application/json"},
            timeout=timeout,
        )
        self._tier = tier
        self._limiter = _RateLimiter(PUBLIC_RATE, PUBLIC_WINDOW_SECONDS) if tier == "public" else None
        self._cache_dir = cache_dir
        self._cache_ttl = cache_ttl_seconds
        self._lookups = 0
        self._cache_hits = 0
        if self._cache_dir:
            self._cache_dir.mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> VirusTotalClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def stats(self) -> dict[str, int]:
        """Quota accounting, so the notebook can show what was spent."""
        return {"api_lookups": self._lookups, "cache_hits": self._cache_hits}

    # ── cache ────────────────────────────────────────────────────────────────

    def _cache_path(self, key: str) -> Path | None:
        if not self._cache_dir:
            return None
        safe = base64.urlsafe_b64encode(key.encode()).decode().rstrip("=")
        return self._cache_dir / f"vt_{safe}.json"

    def _cache_read(self, key: str) -> dict[str, Any] | None:
        path = self._cache_path(key)
        if not path or not path.exists():
            return None
        if time.time() - path.stat().st_mtime > self._cache_ttl:
            return None
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return None

    def _cache_write(self, key: str, value: dict[str, Any]) -> None:
        path = self._cache_path(key)
        if path:
            try:
                path.write_text(json.dumps(value))
            except OSError:
                pass  # A failed cache write must never break triage.

    # ── core ─────────────────────────────────────────────────────────────────

    def _lookup(self, path: str) -> dict[str, Any]:
        cached = self._cache_read(path)
        if cached is not None:
            self._cache_hits += 1
            return cached

        if self._limiter:
            self._limiter.acquire()

        response = self._client.get(path)
        self._lookups += 1

        if response.status_code == 404:
            result = {"found": False, "reason": "not_present_in_virustotal"}
            self._cache_write(path, result)
            return result
        if response.status_code == 429:
            raise QuotaExhausted(
                "VirusTotal quota exhausted (429). Public keys allow 4/min and 500/day."
            )
        if response.status_code >= 400:
            raise VirusTotalError(f"GET {path} → HTTP {response.status_code}: {response.text[:300]}")

        result = _summarize(response.json())
        self._cache_write(path, result)
        return result

    # ── public lookups ───────────────────────────────────────────────────────

    def lookup_file_hash(self, file_hash: str) -> dict[str, Any]:
        """Look up an existing report by MD5/SHA-1/SHA-256. Never uploads."""
        return self._lookup(f"/files/{file_hash.strip().lower()}")

    def lookup_url(self, url: str) -> dict[str, Any]:
        """Look up a URL by its VT id (unpadded base64 of the URL). Never submits."""
        url_id = base64.urlsafe_b64encode(url.strip().encode()).decode().rstrip("=")
        return self._lookup(f"/urls/{url_id}")

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        return self._lookup(f"/domains/{domain.strip().lower()}")

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        return self._lookup(f"/ip_addresses/{ip.strip()}")


def _summarize(payload: dict[str, Any]) -> dict[str, Any]:
    """Reduce a VT response to the fields that matter for triage.

    Raw VT objects run to hundreds of keys. Feeding them verbatim to the model
    wastes context and buries the signal, so this keeps the verdict-relevant
    subset plus the few reputation fields analysts actually cite.
    """
    attributes = (payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values()) or 0

    engines = {
        name: result.get("result")
        for name, result in (attributes.get("last_analysis_results") or {}).items()
        if result.get("category") in {"malicious", "suspicious"} and result.get("result")
    }

    summary: dict[str, Any] = {
        "found": True,
        "detections": f"{malicious + suspicious}/{total}" if total else "0/0",
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total,
        "reputation": attributes.get("reputation"),
        "flagging_engines": dict(list(engines.items())[:15]),
    }

    for key in (
        "meaningful_name",
        "type_description",
        "creation_date",
        "first_submission_date",
        "last_analysis_date",
        "times_submitted",
        "registrar",
        "as_owner",
        "country",
        "categories",
        "title",
        "final_url",
    ):
        if key in attributes:
            summary[key] = attributes[key]

    return summary
