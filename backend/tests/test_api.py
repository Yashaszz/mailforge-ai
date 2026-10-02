"""End-to-end API tests.

``conftest`` puts the app in offline mode, so these exercise upload handling,
parsing and the response contract without any DNS traffic.
"""

from __future__ import annotations

import io
import pathlib

import pytest
from fastapi.testclient import TestClient

from app.main import app

from .conftest import build_message

client = TestClient(app)


def _upload(raw: bytes, filename: str = "message.eml"):
    return client.post(
        "/analyze",
        files={"file": (filename, io.BytesIO(raw), "message/rfc822")},
    )


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["offline_mode"] is True


def test_analyze_returns_the_full_contract():
    raw = build_message(
        extra_headers=(
            "Return-Path: <bounce@relay.sender.test>\n"
            "Received: from relay.sender.test (relay.sender.test [45.33.32.44])\n"
            "\tby mx01.recipient.test with ESMTPS id AAA111;"
            " Tue, 9 Sep 2026 14:22:29 +0530"
        )
    )
    response = _upload(raw, "inbound.eml")

    assert response.status_code == 200
    body = response.json()

    assert body["filename"] == "inbound.eml"
    assert body["size_bytes"] == len(raw)

    assert body["message"]["from_address"] == "hello@example-sender.test"
    assert body["message"]["envelope_from"] == "bounce@relay.sender.test"
    assert body["message"]["subject"] == "Quarterly report"

    assert body["origin"]["client_ip"] == "45.33.32.44"
    assert body["origin"]["client_ip_is_public"] is True
    assert body["origin"]["helo"] == "relay.sender.test"

    auth = body["authentication"]
    assert set(auth) >= {"spf", "dkim", "dmarc", "dns_available", "notes"}
    for check in ("spf", "dkim", "dmarc"):
        assert auth[check]["result"] == "not_checked"  # offline mode

    assert len(body["received_chain"]) == 1
    assert body["received_chain"][0]["from_ip"] == "45.33.32.44"
    assert body["received_chain"][0]["from_ip_is_public"] is True

    assert body["headers"]["From"]
    assert any(h["name"] == "Message-ID" for h in body["all_headers"])


@pytest.mark.parametrize("name", ["01_legitimate_gmail.eml", "02_spoofed_paypal_phish.eml", "03_bec_ceo_wire_fraud.eml"])
def test_analyze_accepts_every_bundled_sample(name: str, sample_paths: dict[str, pathlib.Path]):
    assert name in sample_paths, f"missing sample {name}"
    response = _upload(sample_paths[name].read_bytes(), name)

    assert response.status_code == 200
    body = response.json()
    assert body["message"]["from_address"]
    assert body["origin"]["client_ip"]
    assert body["received_chain"]


def test_analyze_reports_the_receiving_mta_verdict():
    path = pathlib.Path(__file__).parent.parent.parent / "samples" / "01_legitimate_gmail.eml"
    body = _upload(path.read_bytes()).json()

    assert body["reported_authentication_results"]
    assert "spf=pass" in body["reported_authentication_results"][0]


def test_analyze_rejects_an_empty_file():
    response = _upload(b"   \r\n  ")

    assert response.status_code == 422
    assert "empty" in response.json()["detail"].lower()


def test_analyze_rejects_something_that_is_not_an_email():
    response = _upload(b"%PDF-1.4\r\nnot an email at all\r\n", "invoice.pdf")

    assert response.status_code == 422
    assert "raw .eml" in response.json()["detail"]


def test_analyze_requires_a_file():
    assert client.post("/analyze").status_code == 422


def test_analyze_rejects_an_oversized_upload(monkeypatch):
    from app import main

    monkeypatch.setattr(main.settings, "max_upload_bytes", 128)
    response = _upload(build_message(body="x" * 4096))

    assert response.status_code == 413


def test_analyze_survives_a_malformed_message():
    """Garbage in still has to produce a verdict, not a 500."""
    response = _upload(b"From: broken\r\nReceived: nonsense\r\n\r\nbody\r\n")

    assert response.status_code == 200
    assert response.json()["origin"]["client_ip"] is None
    assert response.json()["warnings"]


def test_authenticate_returns_only_the_authentication_block():
    raw = build_message(
        extra_headers=(
            "Received: from relay.sender.test (relay.sender.test [45.33.32.44])\n"
            "\tby mx01.recipient.test with ESMTPS id AAA111;"
            " Tue, 9 Sep 2026 14:22:29 +0530"
        )
    )
    response = client.post(
        "/authenticate", files={"file": ("m.eml", io.BytesIO(raw), "message/rfc822")}
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body) >= {"spf", "dkim", "dmarc", "dns_available"}
    # No scoring and no reputation: this endpoint must stay a pure re-verification.
    assert "assessment" not in body and "origin" not in body


def test_authenticate_rejects_empty_upload():
    response = client.post(
        "/authenticate", files={"file": ("m.eml", io.BytesIO(b"  "), "message/rfc822")}
    )
    assert response.status_code == 422
