"""Tests for indicator extraction, defanging and quota-aware prioritization."""

from soc_triage.iocs import IOCSet, defang, extract, is_shortener, prioritize, refang


def test_defang_and_refang_roundtrip():
    url = "https://evil.example.com/login?x=1"
    assert defang(url) == "hxxps://evil[.]example[.]com/login?x=1"
    assert refang(defang(url)) == url


def test_extract_finds_urls_and_hashes():
    text = (
        "Click https://phish.example.tld/login now. "
        "Attachment hash d41d8cd98f00b204e9800998ecf8427e. "
        "Contact billing@attacker.tld"
    )
    found = extract(text)
    assert any("phish.example.tld" in u for u in found.urls)
    assert "d41d8cd98f00b204e9800998ecf8427e" in found.hashes
    assert "billing@attacker.tld" in found.emails


def test_extract_filters_private_ips():
    # 93.184.216.34 is genuinely routable; the RFC 5737 documentation ranges
    # (192.0.2/24, 198.51.100/24, 203.0.113/24) are classified private by
    # Python's ipaddress module and are correctly filtered out too.
    found = extract("relay 10.0.0.5 and 192.168.1.1 then 93.184.216.34")
    assert "93.184.216.34" in found.ips
    assert "10.0.0.5" not in found.ips
    assert "192.168.1.1" not in found.ips


def test_extract_drops_boilerplate_hosts():
    found = extract('xmlns="http://schemas.microsoft.com/office" and https://real-phish.tld/a')
    assert not any("schemas.microsoft.com" in d for d in found.domains)
    assert any("real-phish.tld" in u for u in found.urls)


def test_shortener_detection():
    assert is_shortener("https://bit.ly/abc123")
    assert not is_shortener("https://example.com/abc")


def test_prioritize_ranks_hashes_first_then_shorteners():
    iocs = IOCSet(
        urls=["https://example.com/a", "https://bit.ly/x"],
        domains=["example.com"],
        ips=["198.51.100.7"],
        hashes=["d41d8cd98f00b204e9800998ecf8427e"],
    )
    ranked = prioritize(iocs, budget=10)
    assert ranked[0] == ("file_hash", "d41d8cd98f00b204e9800998ecf8427e")
    assert ranked[1] == ("url", "https://bit.ly/x")


def test_prioritize_respects_budget():
    iocs = IOCSet(urls=[f"https://a{i}.tld/x" for i in range(50)])
    assert len(prioritize(iocs, budget=10)) == 10
