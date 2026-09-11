"""Parser tests. Nothing here touches the network."""

from __future__ import annotations

import pytest

from app.services.eml_parser import extract_ip, is_public_ip, parse_eml

from .conftest import build_message


def test_parses_core_identities():
    raw = build_message(
        from_header='"Priya Sharma" <priya@example-sender.test>',
        extra_headers="Return-Path: <bounces@relay.example-sender.test>\nReply-To: other@elsewhere.test",
    )
    parsed = parse_eml(raw)

    assert parsed.from_address == "priya@example-sender.test"
    assert parsed.from_display_name == "Priya Sharma"
    assert parsed.from_domain == "example-sender.test"
    assert parsed.envelope_from == "bounces@relay.example-sender.test"
    assert parsed.envelope_from_domain == "relay.example-sender.test"
    assert parsed.reply_to_address == "other@elsewhere.test"
    assert parsed.subject == "Quarterly report"


def test_missing_return_path_falls_back_to_from_and_warns():
    parsed = parse_eml(build_message())

    assert parsed.return_path is None
    assert parsed.envelope_from == "hello@example-sender.test"
    assert any("No Return-Path" in w for w in parsed.parse_warnings)


def test_decodes_rfc2047_encoded_subject():
    raw = build_message(
        subject="=?utf-8?B?W0FjdGlvbiBSZXF1aXJlZF0gQWNjb3VudCBsaW1pdGVk?="
    )
    parsed = parse_eml(raw)

    assert parsed.subject == "[Action Required] Account limited"


def test_received_chain_is_parsed_in_order():
    raw = build_message(
        extra_headers=(
            "Received: from mx01.recipient.test (localhost [127.0.0.1])\n"
            "\tby mx01.recipient.test (Postfix) with ESMTP id AAA111\n"
            "\tfor <analyst@recipient.test>; Tue, 9 Sep 2026 14:22:31 +0530\n"
            "Received: from relay.sender.test (relay.sender.test [45.33.32.156])\n"
            "\tby mx01.recipient.test (Postfix) with ESMTPS id BBB222\n"
            "\tfor <analyst@recipient.test>; Tue, 9 Sep 2026 14:22:29 +0530"
        )
    )
    parsed = parse_eml(raw)

    assert len(parsed.received_chain) == 2
    first, second = parsed.received_chain

    assert first.index == 0
    assert first.from_ip == "127.0.0.1"
    assert first.by_host == "mx01.recipient.test"
    assert first.queue_id == "AAA111"
    assert first.recipient == "analyst@recipient.test"
    assert first.timestamp is not None

    assert second.from_host == "relay.sender.test"
    assert second.from_ip == "45.33.32.156"
    assert second.protocol == "ESMTPS"


def test_client_ip_skips_internal_relay_hops():
    """The first *public* hop is the edge; hops above it are internal."""
    raw = build_message(
        extra_headers=(
            "Received: from internal-2.recipient.test (internal-2 [10.0.0.8])\n"
            "\tby mx01.recipient.test with ESMTP id CCC333; Tue, 9 Sep 2026 14:22:33 +0530\n"
            "Received: from internal-1.recipient.test (internal-1 [127.0.0.1])\n"
            "\tby internal-2.recipient.test with ESMTP id BBB222; Tue, 9 Sep 2026 14:22:31 +0530\n"
            "Received: from evil.sender.test (evil.sender.test [91.198.174.192])\n"
            "\tby internal-1.recipient.test with ESMTP id AAA111; Tue, 9 Sep 2026 14:22:29 +0530"
        )
    )
    parsed = parse_eml(raw)

    assert parsed.client_ip == "91.198.174.192"
    assert parsed.helo == "evil.sender.test"
    assert "hop 2" in parsed.client_ip_source


def test_falls_back_to_x_originating_ip_when_no_public_hop():
    raw = build_message(
        extra_headers=(
            "X-Originating-IP: [104.26.10.5]\n"
            "Received: from local.test (local.test [10.1.1.1])\n"
            "\tby mx01.recipient.test with ESMTP id AAA111; Tue, 9 Sep 2026 14:22:29 +0530"
        )
    )
    parsed = parse_eml(raw)

    assert parsed.client_ip == "104.26.10.5"
    assert "X-Originating-IP" in parsed.client_ip_source


def test_no_received_headers_reports_no_client_ip():
    parsed = parse_eml(build_message())

    assert parsed.received_chain == []
    assert parsed.client_ip is None
    assert any("No usable client IP" in w for w in parsed.parse_warnings)


def test_ignores_receiving_server_ip_after_the_by_clause():
    """The IP in the ``by`` clause belongs to us, not to the sender."""
    raw = build_message(
        extra_headers=(
            "Received: from sender.test (sender.test [45.33.32.5])\n"
            "\tby mx01.recipient.test (mx01 [104.18.32.7]) with ESMTP id AAA111;"
            " Tue, 9 Sep 2026 14:22:29 +0530"
        )
    )
    parsed = parse_eml(raw)

    assert parsed.client_ip == "45.33.32.5"


def test_survives_malformed_headers():
    raw = (
        b"From: not-an-address\r\n"
        b"Received: garbage without any structure\r\n"
        b"Date: definitely not a date\r\n"
        b"\r\n"
        b"body\r\n"
    )
    parsed = parse_eml(raw)

    assert parsed.date is None
    assert len(parsed.received_chain) == 1
    assert parsed.received_chain[0].from_ip is None
    assert any("Date header" in w for w in parsed.parse_warnings)


def test_counts_attachments():
    raw = (
        b'Content-Type: multipart/mixed; boundary="BOUND"\r\n'
        b"From: a@example-sender.test\r\n"
        b"Subject: with attachment\r\n"
        b"\r\n"
        b"--BOUND\r\n"
        b"Content-Type: text/plain\r\n\r\nhello\r\n"
        b"--BOUND\r\n"
        b"Content-Type: application/pdf\r\n"
        b'Content-Disposition: attachment; filename="invoice.pdf"\r\n\r\n'
        b"%PDF-1.4\r\n"
        b"--BOUND--\r\n"
    )
    parsed = parse_eml(raw)

    assert parsed.attachment_count == 1
    assert parsed.attachment_names == ["invoice.pdf"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("from host (host [45.33.32.156])", "45.33.32.156"),
        ("from host ([198.51.100.1])", "198.51.100.1"),
        ("from host (IPv6:2001:db8::1)", "2001:db8::1"),
        ("from host (localhost [127.0.0.1])", "127.0.0.1"),
        ("from host with no address", None),
        ("from host ([999.1.1.1])", None),
    ],
)
def test_extract_ip(text: str, expected: str | None):
    assert extract_ip(text) == expected


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("8.8.8.8", True),
        ("45.33.32.156", True),
        ("10.0.0.1", False),
        ("127.0.0.1", False),
        ("192.168.1.1", False),
        ("not-an-ip", False),
        (None, False),
    ],
)
def test_is_public_ip(ip: str | None, expected: bool):
    assert is_public_ip(ip) is expected


def test_captures_authentication_results_stamped_by_the_receiving_mta():
    raw = build_message(
        extra_headers=(
            "Authentication-Results: mx01.recipient.test; spf=pass smtp.mailfrom=x.test"
        )
    )
    parsed = parse_eml(raw)

    assert len(parsed.authentication_results) == 1
    assert "spf=pass" in parsed.authentication_results[0]
