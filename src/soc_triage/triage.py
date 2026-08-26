"""Triage orchestration.

This is the layer the notebook calls. It owns client lifecycle, the escalation
decision, and the mapping from a message id to a finished verdict.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from agent_framework import Agent

from soc_triage.agent import build_agent, run_options
from soc_triage.config import Settings, load_settings
from soc_triage.models import Severity, TriageResult, TriageVerdict
from soc_triage.sublime import SublimeClient
from soc_triage.tools import TriageContext
from soc_triage.virustotal import VirusTotalClient

# Escalate to the larger model when the first pass lands here.
ESCALATE_AT = Severity.MALICIOUS
LOW_CONFIDENCE = 0.65

# Re-exported: TriageResult is defined in models.py but has always been
# importable from here, and the notebook imports it from here.
__all__ = ["TriageSession", "TriageResult", "ESCALATE_AT", "LOW_CONFIDENCE"]


class TriageSession:
    """Holds clients for the duration of an analyst's notebook session."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or load_settings()
        self.sublime = SublimeClient(
            self.settings.sublime_base_url, self.settings.sublime_api_key
        )
        self.virustotal = (
            VirusTotalClient(
                self.settings.vt_api_key,
                tier=self.settings.vt_tier,
                cache_dir=self.settings.cache_dir,
            )
            if self.settings.vt_api_key
            else None
        )

    def close(self) -> None:
        self.sublime.close()
        if self.virustotal:
            self.virustotal.close()

    def __enter__(self) -> TriageSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ── ingestion ────────────────────────────────────────────────────────────

    def recent_messages(
        self,
        *,
        lookback_minutes: int = 5,
        inbound_only: bool = True,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List messages Sublime ingested in the last N minutes.

        Defaults to 5 minutes to match the original monitoring requirement. Widen
        it in a quiet test tenant — a five-minute window is frequently empty, which
        makes for a poor demo but a correct implementation.
        """
        return self.sublime.recent_messages(
            lookback_minutes=lookback_minutes,
            inbound_only=inbound_only,
            limit=limit,
        )

    def find_messages(
        self,
        identifier: str,
        *,
        days: int = 7,
    ) -> list[dict[str, Any]]:
        """Find messages involving a person, by email address or display name.

        The analyst-driven counterpart to `recent_messages()`: instead of "what
        arrived recently", this answers "what has this person sent or received".
        Runs as a Sublime hunt, so it blocks for a few seconds while the job
        completes. Returns the same row shape as `recent_messages()`.
        """
        return self.sublime.find_messages(identifier, days=days)

    # ── triage ───────────────────────────────────────────────────────────────

    async def triage(
        self,
        message_id: str,
        *,
        justification: str = "Automated SOC triage review (analyst-initiated)",
        allow_escalation: bool = True,
        effort: str = "high",
    ) -> TriageResult:
        """Triage a single message, escalating to the larger model when warranted."""
        started = datetime.now(UTC)
        ctx = TriageContext(
            settings=self.settings,
            sublime=self.sublime,
            virustotal=self.virustotal,
            message_id=message_id,
            justification=justification,
        )

        try:
            agent = build_agent(self.settings, ctx, model=self.settings.triage_model)
            verdict = await self._run(agent, message_id, effort=effort)
            verdict.model_used = self.settings.triage_model

            if allow_escalation and self._should_escalate(verdict):
                escalated_agent = build_agent(
                    self.settings,
                    ctx,
                    model=self.settings.escalation_model,
                    name="SOCTriageAgentEscalated",
                )
                verdict = await self._run(
                    escalated_agent,
                    message_id,
                    effort="max",
                    prior=verdict,
                )
                verdict.model_used = self.settings.escalation_model
                verdict.escalated = True

            verdict.triaged_at = datetime.now(UTC)
            return TriageResult(
                verdict=verdict,
                tool_calls=list(ctx.tool_log),
                vt_stats=self.virustotal.stats if self.virustotal else {},
                elapsed_seconds=(datetime.now(UTC) - started).total_seconds(),
            )

        except Exception as exc:  # noqa: BLE001 - a failed triage must not kill a batch
            placeholder = TriageVerdict(
                message_id=message_id,
                subject="(triage failed)",
                sender="(unknown)",
                severity=Severity.SUSPICIOUS,
                confidence=0.0,
                recommended_disposition="escalate_to_ir",  # type: ignore[arg-type]
                summary=f"Triage did not complete: {exc}. Review this message manually.",
                triaged_at=datetime.now(UTC),
            )
            return TriageResult(
                verdict=placeholder,
                tool_calls=list(ctx.tool_log),
                elapsed_seconds=(datetime.now(UTC) - started).total_seconds(),
                error=str(exc),
            )

    async def _run(
        self,
        agent: Agent,
        message_id: str,
        *,
        effort: str,
        prior: TriageVerdict | None = None,
    ) -> TriageVerdict:
        prompt = (
            f"Triage the message with id `{message_id}`. Follow your method, gather "
            f"evidence with your tools, and return the structured verdict."
        )
        if prior is not None:
            prompt += (
                "\n\nA first-pass triage already ran and reached "
                f"severity={prior.severity} with confidence={prior.confidence:.2f}. "
                "Its summary was:\n"
                f"{prior.summary}\n\n"
                "You are the escalation reviewer. Re-examine the evidence independently. "
                "Confirm, correct or overturn that assessment, and say which you did in "
                "analyst_notes. Do not simply agree — a second identical opinion adds nothing."
            )

        response = await agent.run(prompt, options=run_options(effort=effort))
        verdict = response.value
        if not isinstance(verdict, TriageVerdict):
            raise TypeError(
                f"Agent returned {type(verdict).__name__}, expected TriageVerdict. "
                f"Raw text: {str(response.text)[:400]}"
            )
        return verdict

    @staticmethod
    def _should_escalate(verdict: TriageVerdict) -> bool:
        """Escalate on high severity, low confidence, or a Sublime disagreement.

        Low confidence matters as much as high severity here: an uncertain call on
        a benign-looking message is exactly where a second, stronger pass pays off.
        """
        return (
            verdict.severity.rank >= ESCALATE_AT.rank
            or verdict.confidence < LOW_CONFIDENCE
            or verdict.disagrees_with_sublime
            or verdict.prompt_injection_detected
        )

    async def triage_many(
        self,
        message_ids: list[str],
        *,
        concurrency: int = 3,
        **kwargs: Any,
    ) -> list[TriageResult]:
        """Triage several messages with bounded concurrency.

        Concurrency is capped low on purpose: pay-as-you-go Foundry quota for
        Claude models is 40 RPM / 40K input tokens per minute, and each triage
        makes many tool-augmented calls.
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def _one(message_id: str) -> TriageResult:
            async with semaphore:
                return await self.triage(message_id, **kwargs)

        return await asyncio.gather(*(_one(mid) for mid in message_ids))
