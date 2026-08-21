"""Tests for deterministic header forensics.

These checks are the ones the agent is told to treat as fact, so they need to be
right independently of any model behavior.
"""

from soc_triage.headers import analyze_eml

CLEAN_EML = """\
Received: from mail.example.com (mail.example.com [203.0.113.10]) by mx.corp.com
Authentication-Results: mx.corp.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass
Return-Path: <alerts@example.com>
From: Example Alerts <alerts@example.com>
To: analyst@corp.com
Subject: Your monthly report
Message-ID: <abc123@example.com>
Date: Mon, 18 Aug 2026 10:00:00 +0000

Your report is ready.
"""

SPOOFED_EML = """\
Received: from evil-relay.attacker.tld (evil-relay.attacker.tld [198.51.100.7]) by mx.corp.com
Authentication-Results: mx.corp.com; spf=fail smtp.mailfrom=attacker.tld; dkim=none; dmarc=fail
Return-Path: <payroll@attacker.tld>
From: "IT Helpdesk <helpdesk@corp.com>" <no-reply@attacker.tld>
Reply-To: collect@another-domain.tld
To: analyst@corp.com
Subject: Urgent: password expires today
Message-ID: <xyz@attacker.tld>
Date: Mon, 18 Aug 2026 10:00:00 +0000

Click here immediately.
"""


def test_clean_message_has_no_findings():
    result = analyze_eml(CLEAN_EML)
    assert result.spf == "pass"
    assert result.dkim == "pass"
    assert result.dmarc == "pass"
    assert result.findings == []
    assert result.header_from == "alerts@example.com"


def test_spoofed_message_detects_auth_failures():
    result = analyze_eml(SPOOFED_EML)
    assert result.spf == "fail"
    assert result.dmarc == "fail"
    joined = " ".join(result.findings)
    assert "SPF fail" in joined
    assert "DMARC failed" in joined


def test_detects_display_name_spoofing():
    result = analyze_eml(SPOOFED_EML)
    joined = " ".join(result.findings)
    assert "Display name embeds address" in joined
    assert "helpdesk@corp.com" in joined


def test_detects_reply_to_redirect():
    result = analyze_eml(SPOOFED_EML)
    joined = " ".join(result.findings)
    assert "Reply-To redirects to another-domain.tld" in joined


def test_received_chain_is_ordered_oldest_first():
    eml = (
        "Received: from second.example.com by mx.corp.com\n"
        "Received: from first.example.com by second.example.com\n"
        "From: a@example.com\n\nbody\n"
    )
    result = analyze_eml(eml)
    assert [hop.index for hop in result.received_chain] == [1, 2]
    assert result.received_chain[0].from_host == "first.example.com"


def test_detects_punycode_sender_domain():
    eml = "From: support@xn--pple-43d.com\nTo: a@corp.com\n\nbody\n"
    result = analyze_eml(eml)
    assert any("punycode" in f for f in result.findings)


def test_detects_cyrillic_lookalike_characters():
    # 'а' here is U+0430 CYRILLIC SMALL LETTER A, not ASCII 'a'.
    eml = "From: Microsоft Support <support@microsоft-billing.com>\nTo: a@corp.com\n\nbody\n"
    result = analyze_eml(eml)
    assert any("lookalike" in f for f in result.findings)


def test_missing_authentication_is_reported():
    eml = "From: a@nowhere.tld\nTo: b@corp.com\nSubject: hi\n\nbody\n"
    result = analyze_eml(eml)
    joined = " ".join(result.findings)
    assert "No SPF or DKIM present" in joined
