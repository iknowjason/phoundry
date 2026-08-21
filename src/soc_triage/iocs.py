"""Indicator extraction and defanging.

Uses MSTICpy's IoCExtract when available — this is the appropriate role for
MSTICpy in an agent system: a threat-intel *analysis library* called as a tool,
not an orchestration framework. A regex fallback keeps the demo runnable when
MSTICpy isn't installed.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

try:  # pragma: no cover - exercised by environment, not tests
    from msticpy.transform.iocextract import IoCExtract

    _MSTICPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    IoCExtract = None  # type: ignore[assignment]
    _MSTICPY_AVAILABLE = False


URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")

# Hosts that add noise without adding signal.
BENIGN_HOSTS = {
    "schemas.microsoft.com",
    "www.w3.org",
    "purl.org",
    "schema.org",
    "fonts.googleapis.com",
    "gstatic.com",
}

# URL-shortener and redirect services worth calling out on their own.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "lnkd.in", "tiny.cc",
}


@dataclass(slots=True)
class IOCSet:
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)

    def total(self) -> int:
        return len(self.urls) + len(self.domains) + len(self.ips) + len(self.hashes)

    def as_dict(self, *, defanged: bool = True) -> dict[str, list[str]]:
        transform = defang if defanged else (lambda v: v)
        return {
            "urls": [transform(u) for u in self.urls],
            "domains": [transform(d) for d in self.domains],
            "ips": [transform(i) for i in self.ips],
            "file_hashes": list(self.hashes),
            "emails": [transform(e) for e in self.emails],
        }


def defang(indicator: str) -> str:
    """Render an indicator unclickable for safe display in reports and notebooks."""
    return (
        indicator.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace("ftp://", "fxp://")
        .replace(".", "[.]")
        .replace("@", "[@]")
    )


def refang(indicator: str) -> str:
    """Reverse defanging — needed before an API lookup."""
    return (
        indicator.replace("hxxp://", "http://")
        .replace("hxxps://", "https://")
        .replace("fxp://", "ftp://")
        .replace("[.]", ".")
        .replace("[@]", "@")
        .replace("[:]", ":")
    )


def extract(text: str, *, max_per_type: int = 40) -> IOCSet:
    """Extract indicators from message text."""
    if not text:
        return IOCSet()
    raw = _extract_msticpy(text) if _MSTICPY_AVAILABLE else _extract_regex(text)
    return _clean(raw, max_per_type=max_per_type)


def _extract_msticpy(text: str) -> dict[str, set[str]]:  # pragma: no cover
    extractor = IoCExtract()
    results = extractor.extract(src=text)
    mapping = {
        "urls": {"url"},
        "ips": {"ipv4", "ipv6"},
        "hashes": {"md5_hash", "sha1_hash", "sha256_hash"},
        "domains": {"dns"},
        "emails": {"email"},
    }
    out: dict[str, set[str]] = {key: set() for key in mapping}
    for target, source_keys in mapping.items():
        for source_key in source_keys:
            values = results.get(source_key) or set()
            out[target].update(str(v) for v in values)
    # MSTICpy's extractor does not always return an email set; backfill.
    if not out["emails"]:
        out["emails"] = set(EMAIL_RE.findall(text))
    return out


def _extract_regex(text: str) -> dict[str, set[str]]:
    return {
        "urls": set(URL_RE.findall(text)),
        "ips": set(IPV4_RE.findall(text)),
        "hashes": set(HASH_RE.findall(text)),
        "domains": set(),
        "emails": set(EMAIL_RE.findall(text)),
    }


def _clean(raw: dict[str, set[str]], *, max_per_type: int) -> IOCSet:
    urls = sorted({u.rstrip(".,;)>\"'") for u in raw.get("urls", set())})

    domains = {d.lower().strip(".") for d in raw.get("domains", set())}
    for url in urls:
        host = urlparse(url).hostname
        if host:
            domains.add(host.lower())

    domains = {
        d for d in domains
        if d and "." in d and not _is_ip(d) and d not in BENIGN_HOSTS
        and not any(d.endswith(f".{b}") for b in BENIGN_HOSTS)
    }

    ips = {ip for ip in raw.get("ips", set()) if _is_public_ip(ip)}

    urls = [u for u in urls if not _host_is_benign(u)]

    return IOCSet(
        urls=urls[:max_per_type],
        domains=sorted(domains)[:max_per_type],
        ips=sorted(ips)[:max_per_type],
        hashes=sorted({h.lower() for h in raw.get("hashes", set())})[:max_per_type],
        emails=sorted({e.lower() for e in raw.get("emails", set())})[:max_per_type],
    )


def _host_is_benign(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in BENIGN_HOSTS or any(host.endswith(f".{b}") for b in BENIGN_HOSTS)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_public_ip(value: str) -> bool:
    """Filter out private/loopback space — internal relays aren't indicators."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast)


def is_shortener(url_or_domain: str) -> bool:
    host = (urlparse(url_or_domain).hostname or url_or_domain).lower()
    return host in SHORTENERS


def prioritize(iocs: IOCSet, *, budget: int = 10) -> list[tuple[str, str]]:
    """Rank indicators for enrichment under a hard VirusTotal quota.

    Public VT keys allow 4 lookups/minute, so the agent cannot enumerate every
    indicator in a message. File hashes rank highest (a known-bad hash is decisive),
    then shortened links (which hide their destination), then everything else.
    """
    ranked: list[tuple[int, str, str]] = []
    for file_hash in iocs.hashes:
        ranked.append((0, "file_hash", file_hash))
    for url in iocs.urls:
        ranked.append((1 if is_shortener(url) else 2, "url", url))
    for domain in iocs.domains:
        ranked.append((3, "domain", domain))
    for ip in iocs.ips:
        ranked.append((4, "ip", ip))

    ranked.sort(key=lambda item: item[0])
    return [(kind, value) for _, kind, value in ranked[:budget]]
