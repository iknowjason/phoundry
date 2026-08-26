"""Tests for identity-lookup MQL construction and message-group flattening.

The MQL field names in build_identity_mql were verified against the live
`POST /v0/hunt-jobs` endpoint, which rejects unknown attributes. These tests
cover the parts that must hold regardless of the API: escaping of the
analyst-supplied identifier, address-versus-name routing, and the row shape
shared by the search and hunt entry points.
"""

import pytest

from soc_triage.sublime import _flatten_groups, _mql_literal, build_identity_mql


def test_address_identifier_matches_sender_and_recipients():
    mql = build_identity_mql("alice@corp.com")
    assert 'sender.email.email == "alice@corp.com"' in mql
    assert 'any(recipients.to, .email.email == "alice@corp.com")' in mql
    assert 'any(recipients.cc, .email.email == "alice@corp.com")' in mql


def test_name_identifier_uses_case_insensitive_substring():
    mql = build_identity_mql("Jane Doe")
    assert 'strings.icontains(sender.display_name, "Jane Doe")' in mql
    # A name must never be matched against an address field.
    assert "email.email" not in mql


def test_quotes_in_identifier_cannot_terminate_the_literal():
    # An unescaped `"` here would end the MQL string and let the rest of the
    # identifier be parsed as query syntax.
    assert _mql_literal('a"b') == '"a\\"b"'
    assert _mql_literal("a\\b") == '"a\\\\b"'
    # Backslash escaping must happen before quote escaping, or `\"` becomes `\\"`.
    assert _mql_literal('a\\"b') == '"a\\\\\\"b"'


def test_identifier_is_stripped_and_empty_is_rejected():
    assert build_identity_mql("  alice@corp.com  ") == build_identity_mql("alice@corp.com")
    with pytest.raises(ValueError):
        build_identity_mql("   ")


def test_flatten_handles_both_payload_shapes_and_missing_fields():
    group = {
        "id": "grp-1",
        "state": "active",
        "messages": [
            {"id": "msg-1", "subject": "Invoice", "created_at": "2026-08-25T10:00:00Z"},
            {"id": "msg-2", "subject": "Later", "created_at": "2026-08-25T12:00:00Z"},
        ],
    }
    # `message_groups` is the search shape; `results` is the hunt shape.
    for key in ("message_groups", "results"):
        rows = _flatten_groups({key: [group]})
        assert [r["message_id"] for r in rows] == ["msg-2", "msg-1"]  # newest first
        assert rows[0]["canonical_id"] == "grp-1"
        assert rows[0]["sender"] is None  # absent nested dict must not raise
        assert rows[0]["group_size"] == 2


def test_flatten_empty_payload():
    assert _flatten_groups({}) == []
