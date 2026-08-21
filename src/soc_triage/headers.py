"""Deterministic email header forensics.

Everything here is computed in Python, not inferred by the model. Authentication
results, Received-chain reconstruction and homoglyph detection are exactly the
kind of mechanical checks a language model will *usually* get right and
occasionally hallucinate — so they are done in code and handed to the model as
established fact.
"""

from __future__ import annotations

import email
import re
import unicodedata
from dataclasses import dataclass, field
from email.message import Message
from email.utils import parseaddr

AUTH_RESULT_RE = re.compile(
    r"\b(spf|dkim|dmarc|compauth)=(\w+)", re.IGNORECASE
)

# Latin characters with common lookalikes in other scripts.
CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "FULLWIDTH")


@dataclass(slots=True)
class ReceivedHop:
    index: int
    from_host: str | None
    by_host: str | None
    raw: str


@dataclass(slots=True)
class HeaderAnalysis:
    """Structured result of mechanical header inspection."""

    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"
    compauth: str = "unknown"

    header_from: str = ""
    header_from_display: str = ""
    envelope_from: str = ""
    reply_to: str = ""
    return_path: str = ""

    subject: str = ""
    message_id: str = ""
    date: str = ""

    received_chain: list[ReceivedHop] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "authentication": {
                "spf": self.spf,
                "dkim": self.dkim,
                "dmarc": self.dmarc,
                "compauth": self.compauth,
            },
            "addresses": {
                "header_from": self.header_from,
                "header_from_display_name": self.header_from_display,
                "envelope_from": self.envelope_from,
                "return_path": self.return_path,
                "reply_to": self.reply_to,
            },
            "subject": self.subject,
            "message_id": self.message_id,
            "date": self.date,
            "received_hop_count": len(self.received_chain),
            "received_chain": [
                {"hop": h.index, "from": h.from_host, "by": h.by_host}
                for h in self.received_chain
            ],
            "findings": self.findings,
        }


def analyze_eml(raw_eml: str) -> HeaderAnalysis:
    """Parse a raw EML and run mechanical authentication and spoofing checks."""
    msg: Message = email.message_from_string(raw_eml)
    analysis = HeaderAnalysis()

    analysis.subject = str(msg.get("Subject") or "")
    analysis.message_id = str(msg.get("Message-ID") or "")
    analysis.date = str(msg.get("Date") or "")

    display, addr = parseaddr(str(msg.get("From") or ""))
    analysis.header_from = addr.lower()
    analysis.header_from_display = display

    analysis.return_path = parseaddr(str(msg.get("Return-Path") or ""))[1].lower()
    analysis.reply_to = parseaddr(str(msg.get("Reply-To") or ""))[1].lower()
    analysis.envelope_from = analysis.return_path

    _parse_auth_results(msg, analysis)
    analysis.received_chain = _parse_received_chain(msg)
    _run_checks(analysis)
    return analysis


def _parse_auth_results(msg: Message, analysis: HeaderAnalysis) -> None:
    """Read Authentication-Results / Received-SPF headers.

    Takes the *first* occurrence of each mechanism, which corresponds to the
    receiving boundary closest to the mailbox. Attacker-supplied headers appear
    lower in the stack and must not win.
    """
    blobs: list[str] = []
    for header in ("Authentication-Results", "ARC-Authentication-Results", "Received-SPF"):
        blobs.extend(str(v) for v in msg.get_all(header, []))

    seen: dict[str, str] = {}
    for blob in blobs:
        for mechanism, result in AUTH_RESULT_RE.findall(blob):
            key = mechanism.lower()
            if key not in seen:
                seen[key] = result.lower()

    analysis.spf = seen.get("spf", "unknown")
    analysis.dkim = seen.get("dkim", "unknown")
    analysis.dmarc = seen.get("dmarc", "unknown")
    analysis.compauth = seen.get("compauth", "unknown")


def _parse_received_chain(msg: Message) -> list[ReceivedHop]:
    """Reconstruct the delivery path. Received headers are prepended, so reverse."""
    hops: list[ReceivedHop] = []
    received = [str(v) for v in msg.get_all("Received", [])]
    for index, raw in enumerate(reversed(received), start=1):
        collapsed = " ".join(raw.split())
        from_match = re.search(r"from\s+([^\s;]+)", collapsed, re.IGNORECASE)
        by_match = re.search(r"by\s+([^\s;]+)", collapsed, re.IGNORECASE)
        hops.append(
            ReceivedHop(
                index=index,
                from_host=from_match.group(1) if from_match else None,
                by_host=by_match.group(1) if by_match else None,
                raw=collapsed[:300],
            )
        )
    return hops


def _run_checks(analysis: HeaderAnalysis) -> None:
    """Populate findings with the classic spoofing tells."""
    findings = analysis.findings

    if analysis.spf in {"fail", "softfail"}:
        findings.append(f"SPF {analysis.spf}: sending IP is not authorized for the From domain.")
    if analysis.dkim == "fail":
        findings.append("DKIM signature failed to verify — content or sender may be forged.")
    if analysis.dmarc == "fail":
        findings.append("DMARC failed: neither SPF nor DKIM aligned with the header From domain.")
    if analysis.spf in {"none", "unknown"} and analysis.dkim in {"none", "unknown"}:
        findings.append("No SPF or DKIM present — sender domain publishes no email authentication.")

    header_domain = _domain_of(analysis.header_from)
    envelope_domain = _domain_of(analysis.envelope_from)
    if header_domain and envelope_domain and header_domain != envelope_domain:
        findings.append(
            f"Envelope/header mismatch: Return-Path is {envelope_domain} "
            f"but From displays as {header_domain}."
        )

    reply_domain = _domain_of(analysis.reply_to)
    if reply_domain and header_domain and reply_domain != header_domain:
        findings.append(
            f"Reply-To redirects to {reply_domain}, different from the From domain "
            f"{header_domain} — a common BEC pattern."
        )

    # Display name containing an address that isn't the real one.
    display = analysis.header_from_display or ""
    embedded = re.search(r"[\w.+-]+@[\w.-]+\.\w+", display)
    if embedded and embedded.group(0).lower() != analysis.header_from:
        findings.append(
            f"Display name embeds address {embedded.group(0)} but the real sender is "
            f"{analysis.header_from} — display-name spoofing."
        )

    if header_domain:
        if _is_punycode(header_domain):
            findings.append(f"Sender domain {header_domain} uses punycode (IDN homograph risk).")
        confusables = _confusable_scripts(analysis.header_from + display)
        if confusables:
            findings.append(
                f"Non-Latin lookalike characters detected ({', '.join(sorted(confusables))}) "
                "in the sender address or display name."
            )

    if not analysis.received_chain:
        findings.append("No Received headers present — message may have been injected directly.")


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def _is_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in domain.split("."))


def _confusable_scripts(text: str) -> set[str]:
    """Detect characters from scripts commonly used for Latin lookalikes."""
    found: set[str] = set()
    for char in text:
        if char.isascii():
            continue
        try:
            name = unicodedata.name(char)
        except ValueError:
            continue
        for script in CONFUSABLE_SCRIPTS:
            if name.startswith(script):
                found.add(script.title())
    return found
