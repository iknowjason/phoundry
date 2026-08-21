"""Report rendering — inline HTML for the notebook, Markdown for tickets."""

from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path

from soc_triage.models import Severity, TriageResult, TriageVerdict

SEVERITY_COLORS = {
    Severity.BENIGN: ("#0b6e3f", "#e7f6ee"),
    Severity.SUSPICIOUS: ("#8a6100", "#fdf3e0"),
    Severity.MALICIOUS: ("#a32020", "#fdeaea"),
    Severity.CRITICAL: ("#ffffff", "#8b0000"),
}


def render_html(result: TriageResult) -> str:
    """Render a verdict as self-contained HTML for display in a notebook cell."""
    v = result.verdict
    fg, bg = SEVERITY_COLORS.get(v.severity, ("#333", "#eee"))
    esc = html.escape

    banners = []
    if v.prompt_injection_detected:
        banners.append(
            _banner(
                "⚠ PROMPT INJECTION ATTEMPT IN MESSAGE BODY",
                f"The message contains text targeting AI analysis tooling. "
                f"It was reported, not obeyed.<br><code>{esc((v.prompt_injection_excerpt or '')[:400])}</code>",
                "#5b21b6",
                "#f3e8ff",
            )
        )
    if v.users_who_clicked:
        banners.append(
            _banner(
                "🚨 CONFIRMED INTERACTION — THIS IS AN INCIDENT",
                "These mailboxes clicked a link in this message: "
                + esc(", ".join(v.users_who_clicked)),
                "#ffffff",
                "#8b0000",
            )
        )
    if v.disagrees_with_sublime:
        banners.append(
            _banner(
                "⚑ DISAGREES WITH SUBLIME'S VERDICT — REVIEW FIRST",
                esc(v.disagreement_note or "The agent's assessment differs from Sublime's attack score."),
                "#0c4a6e",
                "#e0f2fe",
            )
        )

    indicator_rows = "".join(
        f"<tr>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #eee'><code>{esc(i.value)}</code></td>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>{esc(i.type.value)}</td>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>"
        f"<strong style='color:{SEVERITY_COLORS.get(i.severity, ('#333',''))[0]}'>{esc(i.severity.value)}</strong></td>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>{esc(i.vt_detections or '—')}</td>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #eee'>{esc(i.rationale)}"
        f"<br><span style='color:#777;font-size:11px'>source: {esc(i.source)}</span></td>"
        f"</tr>"
        for i in v.indicators
    ) or "<tr><td colspan='5' style='padding:10px;color:#777'>No indicators extracted.</td></tr>"

    auth_block = ""
    if v.authentication:
        a = v.authentication
        auth_block = (
            "<h4 style='margin:16px 0 6px'>Email authentication</h4>"
            f"<p style='margin:0'><code>SPF={esc(a.spf)}</code> "
            f"<code>DKIM={esc(a.dkim)}</code> <code>DMARC={esc(a.dmarc)}</code></p>"
            f"<p style='margin:6px 0;color:#444'>{esc(a.alignment_notes)}</p>"
        )

    rule_block = ""
    if v.proposed_detection_rule:
        rule_block = (
            "<h4 style='margin:16px 0 6px'>Proposed detection rule "
            "<span style='font-weight:400;color:#777;font-size:12px'>(validate and review before deploying)</span></h4>"
            f"<pre style='background:#f6f8fa;padding:10px;border-radius:6px;overflow-x:auto;"
            f"font-size:12px'>{esc(v.proposed_detection_rule)}</pre>"
            f"<p style='color:#555;font-size:12px'>Validation: {esc(v.rule_validation_result or 'not validated')}</p>"
        )

    meta = (
        f"model: {esc(v.model_used or '—')}"
        f"{' → escalated' if v.escalated else ''} · "
        f"{result.elapsed_seconds:.1f}s · "
        f"{len(result.tool_calls)} tool calls · "
        f"VT: {result.vt_stats.get('api_lookups', 0)} lookups, "
        f"{result.vt_stats.get('cache_hits', 0)} cached"
    )

    return f"""
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
            border:1px solid #ddd;border-radius:10px;overflow:hidden;margin:12px 0;max-width:1000px">
  <div style="background:{bg};color:{fg};padding:14px 18px">
    <div style="font-size:12px;letter-spacing:.08em;opacity:.85">TRIAGE VERDICT</div>
    <div style="font-size:22px;font-weight:700;margin-top:2px">
      {esc(v.severity.value.upper())}
      <span style="font-size:14px;font-weight:400;opacity:.85">
        · confidence {v.confidence:.0%} · recommend: {esc(v.recommended_disposition.value.replace('_', ' '))}
      </span>
    </div>
  </div>
  <div style="padding:16px 18px">
    {''.join(banners)}
    <table style="width:100%;font-size:13px;margin-bottom:12px">
      <tr><td style="color:#777;width:90px;padding:2px 0">Subject</td><td><strong>{esc(v.subject)}</strong></td></tr>
      <tr><td style="color:#777;padding:2px 0">From</td><td><code>{esc(v.sender)}</code></td></tr>
      <tr><td style="color:#777;padding:2px 0">To</td><td>{esc(', '.join(v.recipients) or '—')}</td></tr>
    </table>

    <p style="font-size:14px;line-height:1.55;margin:0 0 4px">{esc(v.summary)}</p>

    {auth_block}

    <h4 style="margin:16px 0 6px">Indicators ({len(v.indicators)})</h4>
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr style="text-align:left;background:#fafafa">
        <th style="padding:6px 10px">Indicator</th><th style="padding:6px 10px">Type</th>
        <th style="padding:6px 10px">Severity</th><th style="padding:6px 10px">VT</th>
        <th style="padding:6px 10px">Rationale</th>
      </tr></thead>
      <tbody>{indicator_rows}</tbody>
    </table>

    {_chips("Attack types", v.attack_types)}
    {_chips("MITRE ATT&CK", v.mitre_techniques)}
    {f'<p style="font-size:13px;margin:12px 0 0"><strong>Campaign scope:</strong> {esc(v.campaign_scope)}</p>' if v.campaign_scope else ''}
    {rule_block}
    {f'<p style="font-size:13px;margin:12px 0 0"><strong>Analyst notes:</strong> {esc(v.analyst_notes)}</p>' if v.analyst_notes else ''}

    <p style="color:#999;font-size:11px;margin:16px 0 0;border-top:1px solid #eee;padding-top:8px">{esc(meta)}</p>
  </div>
</div>
"""


def _banner(title: str, body: str, fg: str, bg: str) -> str:
    return (
        f"<div style='background:{bg};color:{fg};padding:10px 12px;border-radius:6px;"
        f"margin-bottom:12px;font-size:13px'>"
        f"<strong>{title}</strong><br>{body}</div>"
    )


def _chips(label: str, values: list[str]) -> str:
    if not values:
        return ""
    chips = "".join(
        f"<span style='display:inline-block;background:#eef2f7;border-radius:4px;"
        f"padding:2px 8px;margin:2px 4px 2px 0;font-size:12px'>{html.escape(v)}</span>"
        for v in values
    )
    return f"<p style='margin:10px 0 0;font-size:12px'><span style='color:#777'>{label}:</span> {chips}</p>"


def render_markdown(result: TriageResult) -> str:
    """Render a verdict as Markdown, suitable for pasting into a ticket."""
    v = result.verdict
    lines = [
        f"# Email triage — {v.severity.value.upper()} ({v.confidence:.0%} confidence)",
        "",
        f"- **Message ID:** `{v.message_id}`",
        f"- **Subject:** {v.subject}",
        f"- **From:** `{v.sender}`",
        f"- **To:** {', '.join(v.recipients) or '—'}",
        f"- **Recommended disposition:** {v.recommended_disposition.value.replace('_', ' ')}",
        f"- **Triaged:** {v.triaged_at.isoformat() if v.triaged_at else '—'} "
        f"using `{v.model_used}`{' (escalated)' if v.escalated else ''}",
        "",
        "## Summary",
        "",
        v.summary,
        "",
    ]

    if v.prompt_injection_detected:
        lines += [
            "> **⚠ Prompt injection attempt detected in message body.** "
            "The message contains text targeting AI analysis tooling; it was reported, not obeyed.",
            "",
            f"> `{(v.prompt_injection_excerpt or '')[:500]}`",
            "",
        ]
    if v.users_who_clicked:
        lines += [
            f"> **🚨 Confirmed interaction — treat as an incident.** "
            f"Mailboxes that clicked: {', '.join(v.users_who_clicked)}",
            "",
        ]
    if v.disagrees_with_sublime:
        lines += [
            f"> **⚑ Disagrees with Sublime's verdict.** {v.disagreement_note or ''}",
            "",
        ]

    if v.authentication:
        a = v.authentication
        lines += [
            "## Email authentication",
            "",
            f"`SPF={a.spf}` `DKIM={a.dkim}` `DMARC={a.dmarc}`",
            "",
            a.alignment_notes,
            "",
        ]

    lines += ["## Indicators", ""]
    if v.indicators:
        lines += [
            "| Indicator | Type | Severity | VT | Rationale | Source |",
            "|---|---|---|---|---|---|",
        ]
        lines += [
            f"| `{i.value}` | {i.type.value} | {i.severity.value} | {i.vt_detections or '—'} "
            f"| {i.rationale} | {i.source} |"
            for i in v.indicators
        ]
    else:
        lines.append("_No indicators extracted._")
    lines.append("")

    if v.attack_types:
        lines += [f"**Attack types:** {', '.join(v.attack_types)}", ""]
    if v.mitre_techniques:
        lines += [f"**MITRE ATT&CK:** {', '.join(v.mitre_techniques)}", ""]
    if v.campaign_scope:
        lines += ["## Campaign scope", "", v.campaign_scope, ""]
    if v.proposed_detection_rule:
        lines += [
            "## Proposed detection rule",
            "",
            "_Review before deploying. Generated by the agent, not a human detection engineer._",
            "",
            "```yaml",
            v.proposed_detection_rule,
            "```",
            "",
            f"Validation: {v.rule_validation_result or 'not validated'}",
            "",
        ]
    if v.analyst_notes:
        lines += ["## Analyst notes", "", v.analyst_notes, ""]

    lines += [
        "---",
        "",
        "<details><summary>Tool calls made during triage</summary>",
        "",
        *[f"{n}. `{call}`" for n, call in enumerate(result.tool_calls, 1)],
        "",
        "</details>",
    ]
    return "\n".join(lines)


def save_report(result: TriageResult, report_dir: Path) -> Path:
    """Write the Markdown report to disk and return its path."""
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = (result.verdict.triaged_at or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    safe_id = "".join(c for c in result.verdict.message_id if c.isalnum() or c in "-_")[:40]
    path = report_dir / f"{stamp}_{result.verdict.severity.value}_{safe_id}.md"
    path.write_text(render_markdown(result), encoding="utf-8")
    return path


def render_queue(results: list[TriageResult]) -> str:
    """Render a triage queue summary — worst first, because that's what gets worked."""
    ordered = sorted(
        results,
        key=lambda r: (-r.verdict.severity.rank, -r.verdict.confidence),
    )
    rows = "".join(
        f"<tr style='border-bottom:1px solid #eee'>"
        f"<td style='padding:8px 10px'>"
        f"<span style='background:{SEVERITY_COLORS.get(r.verdict.severity, ('', '#eee'))[1]};"
        f"color:{SEVERITY_COLORS.get(r.verdict.severity, ('#333', ''))[0]};"
        f"padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700'>"
        f"{r.verdict.severity.value.upper()}</span></td>"
        f"<td style='padding:8px 10px;font-size:13px'>{html.escape(r.verdict.subject[:70])}</td>"
        f"<td style='padding:8px 10px;font-size:12px'><code>{html.escape(r.verdict.sender)}</code></td>"
        f"<td style='padding:8px 10px;font-size:12px'>{r.verdict.confidence:.0%}</td>"
        f"<td style='padding:8px 10px;font-size:12px'>"
        f"{'🚩' if r.verdict.disagrees_with_sublime else ''}"
        f"{'💉' if r.verdict.prompt_injection_detected else ''}"
        f"{'🚨' if r.verdict.users_who_clicked else ''}"
        f"{'⏫' if r.verdict.escalated else ''}</td>"
        f"<td style='padding:8px 10px;font-size:12px;color:#555'>"
        f"{html.escape(r.verdict.recommended_disposition.value.replace('_', ' '))}</td>"
        f"</tr>"
        for r in ordered
    )
    return f"""
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:1000px">
  <h3 style="margin:0 0 8px">Triage queue — {len(ordered)} message(s)</h3>
  <p style="color:#777;font-size:12px;margin:0 0 8px">
    🚩 disagrees with Sublime · 💉 prompt injection · 🚨 user clicked · ⏫ escalated
  </p>
  <table style="width:100%;border-collapse:collapse">
    <thead><tr style="text-align:left;background:#fafafa;font-size:12px">
      <th style="padding:8px 10px">Severity</th><th style="padding:8px 10px">Subject</th>
      <th style="padding:8px 10px">Sender</th><th style="padding:8px 10px">Conf.</th>
      <th style="padding:8px 10px">Flags</th><th style="padding:8px 10px">Recommend</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
"""
