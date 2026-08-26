"""Sublime Security Platform API client.

Endpoint paths and parameter names were taken from the published OpenAPI spec
(https://docs.sublime.security/openapi/sublime-platform-api.json) rather than
the prose docs, which lag the spec in places.
"""

from __future__ import annotations

import base64
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential


class SublimeError(RuntimeError):
    """A Sublime API call failed."""


class SublimeClient:
    """Thin, typed wrapper over the endpoints this agent actually uses."""

    def __init__(self, base_url: str, api_key: str, *, timeout: float = 60.0) -> None:
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            },
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SublimeClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ── plumbing ─────────────────────────────────────────────────────────────

    @retry(
        retry=retry_if_exception_type(httpx.TransportError),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        response = self._client.request(method, path, **kwargs)
        if response.status_code >= 400:
            # X-Request-ID is on every Sublime response and is what support asks for.
            request_id = response.headers.get("X-Request-ID", "unknown")
            raise SublimeError(
                f"{method} {path} → HTTP {response.status_code} "
                f"(X-Request-ID: {request_id}): {response.text[:500]}"
            )
        return response

    def _get_json(self, path: str, **kwargs: Any) -> dict[str, Any]:
        return self._request("GET", path, **kwargs).json()

    def _post_json(self, path: str, **kwargs: Any) -> dict[str, Any]:
        response = self._request("POST", path, **kwargs)
        return response.json() if response.content else {}

    # ── ingestion ────────────────────────────────────────────────────────────

    def search_message_groups(
        self,
        *,
        start: datetime,
        end: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
        message_types: list[str] | None = None,
        states: list[str] | None = None,
    ) -> dict[str, Any]:
        """GET /v0/message-groups/search over a created_at window.

        `start` is inclusive, `end` is exclusive — matching the API's own semantics
        so a message never lands in two consecutive polling windows.
        """
        end = end or datetime.now(UTC)
        params: dict[str, Any] = {
            "created_at[gte]": _iso(start),
            "created_at[lt]": _iso(end),
            "limit": min(limit, 500),
            "offset": offset,
        }
        if message_types:
            # Bare enum values: inbound | outbound | internal. Note these are NOT
            # the MQL attribute names (`type.inbound`) used in detection rules —
            # the API rejects those with a 400.
            params["type"] = message_types
        if states:
            params["states"] = states
        return self._get_json("/v0/message-groups/search", params=params)

    def recent_messages(
        self,
        *,
        lookback_minutes: int = 5,
        inbound_only: bool = True,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Flatten the last N minutes of message groups into a list of messages.

        Each returned dict carries the group context alongside the message preview,
        because the group is where the campaign signal lives (flagged rules, link
        clicks, how many mailboxes were hit).
        """
        end = datetime.now(UTC)
        start = end - timedelta(minutes=lookback_minutes)
        result = self.search_message_groups(
            start=start,
            end=end,
            limit=limit,
            message_types=["inbound"] if inbound_only else None,
        )

        return _flatten_groups(result)

    # ── identity lookup ──────────────────────────────────────────────────────

    def find_messages(
        self,
        identifier: str,
        *,
        days: int = 7,
        poll_interval: float = 2.0,
        max_polls: int = 30,
    ) -> list[dict[str, Any]]:
        """Find messages involving a person, by email address or display name.

        `search_message_groups` filters on a time window only, so an analyst-supplied
        identifier has to go through a hunt: `POST /v0/hunt-jobs` takes arbitrary MQL.
        Hunt jobs are asynchronous, so this blocks while polling — bounded by
        `poll_interval * max_polls` (default 60s).

        Returns the same row shape as `recent_messages()`, so anything that renders
        one renders the other.
        """
        end = datetime.now(UTC)
        start = end - timedelta(days=max(1, days))
        mql = build_identity_mql(identifier)

        job_id = self.start_hunt(
            mql_source=mql,
            start=start,
            end=end,
            name=f"analyst-lookup-{identifier[:40]}",
        )

        for _ in range(max_polls):
            time.sleep(poll_interval)
            status = self.get_hunt_status(job_id)
            state = str(status.get("state") or status.get("status") or "").lower()
            if state in {"completed", "complete", "finished", "done"}:
                return _flatten_groups(self.get_hunt_results(job_id))
            if state in {"failed", "error"}:
                raise SublimeError(f"Hunt job {job_id} failed: {status}")

        raise SublimeError(
            f"Hunt job {job_id} did not finish within "
            f"{poll_interval * max_polls:.0f}s. Query it later with "
            f"get_hunt_status({job_id!r}) / get_hunt_results({job_id!r})."
        )

    # ── per-message detail ───────────────────────────────────────────────────

    def set_access_justification(self, message_id: str, justification: str) -> None:
        """POST a justification, required before the MDM returns unredacted content.

        Sublime records this against the API key's user — which is exactly why the
        notebook authenticates as the analyst rather than a shared service principal.
        """
        self._post_json(
            f"/v0/messages/{message_id}/justification",
            json={"justification": justification},
        )

    def get_message_data_model(self, message_id: str) -> dict[str, Any]:
        """GET the normalized Message Data Model (MDM)."""
        return self._get_json(f"/v0/messages/{message_id}/message_data_model")

    def get_message(self, message_id: str, *, drop_large_text: bool = True) -> dict[str, Any]:
        return self._get_json(
            f"/v0/messages/{message_id}",
            params={"remove_large_text_fields": drop_large_text},
        )

    def get_raw_eml(self, message_id: str) -> str:
        """GET the raw EML. This is the ground truth for header analysis."""
        response = self._request(
            "GET", f"/v0/messages/{message_id}/eml", headers={"Accept": "*/*"}
        )
        return response.text

    def get_attack_score(self, message_id: str) -> dict[str, Any]:
        return self._get_json(f"/v0/messages/{message_id}/attack_score")

    def get_asa_verdict(self, message_id: str) -> dict[str, Any]:
        """Sublime's own automated security analysis verdict, if one exists."""
        return self._get_json(f"/v0/messages/{message_id}/asa_verdict")

    def get_message_screenshot(self, message_id: str) -> bytes:
        """Rendered image of the message — what the recipient actually saw."""
        response = self._request(
            "GET", f"/v0/messages/{message_id}/image", headers={"Accept": "image/*"}
        )
        return response.content

    def get_message_screenshot_b64(self, message_id: str) -> str:
        return base64.b64encode(self.get_message_screenshot(message_id)).decode("ascii")

    # ── enrichment ───────────────────────────────────────────────────────────

    def link_analysis(self, url: str) -> dict[str, Any]:
        """ML link analysis. Costs no VirusTotal quota, so try it first."""
        return self._post_json("/v0/enrichment/link_analysis/evaluate", json={"url": url})

    # ── campaign scoping ─────────────────────────────────────────────────────

    def start_hunt(
        self,
        *,
        mql_source: str,
        start: datetime,
        end: datetime,
        name: str | None = None,
        flagged_only: bool = False,
    ) -> str:
        """POST /v0/hunt-jobs — returns the hunt job id."""
        body: dict[str, Any] = {
            "source": mql_source,
            "range_start_time": _iso(start),
            "range_end_time": _iso(end),
            "private": False,
        }
        if name:
            body["name"] = name
        if flagged_only:
            body["triage_flagged"] = True
        result = self._post_json("/v0/hunt-jobs", json=body)
        # The API returns `hunt_job_id`; the other two are accepted defensively
        # because older responses and the prose docs both use them.
        job_id = result.get("hunt_job_id") or result.get("id") or result.get("job_id")
        if not job_id:
            raise SublimeError(f"Hunt job did not return an id: {result}")
        return str(job_id)

    def get_hunt_results(self, job_id: str) -> dict[str, Any]:
        return self._get_json(f"/v0/hunt-jobs/{job_id}/results")

    def get_hunt_status(self, job_id: str) -> dict[str, Any]:
        return self._get_json(f"/v0/hunt-jobs/{job_id}")

    # ── detection engineering ────────────────────────────────────────────────

    def validate_rule(self, rule_yaml: str) -> dict[str, Any]:
        """POST /v0/rules/validate — checks MQL and YAML without creating anything."""
        return self._post_json("/v0/rules/validate", json={"source": rule_yaml})

    # ── response actions (gated) ─────────────────────────────────────────────

    def action_message(self, message_id: str, action: str) -> dict[str, Any]:
        """Perform trash / restore / quarantine / warning_banner / move_to_spam.

        Deliberately not wrapped in a convenience helper and never wired to the
        agent unless ALLOW_MAILBOX_ACTIONS is true.
        """
        return self._post_json(f"/v0/messages/{message_id}/actions", json={"action": action})


def _mql_literal(value: str) -> str:
    """Quote a value for use as an MQL string literal.

    The identifier comes from an analyst typing into a notebook cell, so it is
    untrusted with respect to the query it lands in. Escaping backslashes before
    quotes keeps a value containing `"` from terminating the literal early.
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_identity_mql(identifier: str) -> str:
    """Build the MQL for "show me mail involving this person".

    An identifier containing `@` is treated as an address and matched exactly against
    sender and recipient addresses. Anything else is treated as a display name and
    matched case-insensitively as a substring, because analysts type "Jane Doe" when
    the header carries "Jane Doe (Finance)".
    """
    identifier = identifier.strip()
    if not identifier:
        raise ValueError("identifier must not be empty")

    lit = _mql_literal(identifier)
    if "@" in identifier:
        return (
            f"sender.email.email == {lit}"
            f" or any(recipients.to, .email.email == {lit})"
            f" or any(recipients.cc, .email.email == {lit})"
        )
    return (
        f"strings.icontains(sender.display_name, {lit})"
        f" or any(recipients.to, strings.icontains(.display_name, {lit}))"
    )


def _flatten_groups(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten a message-groups payload into one row per message, newest first.

    Both `/v0/message-groups/search` and `/v0/hunt-jobs/{id}/results` return this
    shape, which is what lets the time-window and identity entry points share it.
    """
    messages: list[dict[str, Any]] = []
    for group in result.get("message_groups") or result.get("results") or []:
        flagged = [r.get("name") for r in group.get("flagged_rules", []) or []]
        clicked = group.get("message_links_clicked", []) or []
        for preview in group.get("messages", []) or []:
            messages.append(
                {
                    "message_id": preview.get("id"),
                    "canonical_id": group.get("id"),
                    "subject": preview.get("subject"),
                    "sender": (preview.get("sender") or {}).get("email"),
                    "sender_display_name": (preview.get("sender") or {}).get("display_name"),
                    "mailbox": (preview.get("mailbox") or {}).get("email_address"),
                    "created_at": preview.get("created_at"),
                    "delivered": preview.get("delivered"),
                    "read_at": preview.get("read_at"),
                    "group_state": group.get("state"),
                    "group_classification": group.get("classification"),
                    "flagged_rules": [name for name in flagged if name],
                    "group_size": len(group.get("messages", []) or []),
                    "links_clicked": clicked,
                    "user_reports": len(group.get("user_reports", []) or []),
                }
            )
    messages.sort(key=lambda m: m.get("created_at") or "", reverse=True)
    return messages


def _iso(value: datetime) -> str:
    """Format as the API expects: UTC, ISO 8601, 'Z' suffix, no microseconds."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
