"""Shared test fixtures.

Every test in this suite runs without network access:

* DKIM is verified against a keypair generated for this repository, served
  through a stub resolver, so a real signature is really verified.
* DMARC and SPF record lookups go through :class:`FakeResolver`.
* API tests run the app in offline mode.
"""

from __future__ import annotations

import os
import pathlib
from types import SimpleNamespace

# Must be set before app.config is imported anywhere, so the API tests never
# touch DNS. Individual auth tests inject their own stub resolvers instead.
os.environ.setdefault("MAILFORGE_OFFLINE", "true")

import dns.resolver  # noqa: E402
import dkim  # noqa: E402
import pytest  # noqa: E402

TESTS_DIR = pathlib.Path(__file__).parent
KEYS_DIR = TESTS_DIR / "keys"
SAMPLES_DIR = TESTS_DIR.parent.parent / "samples"

DKIM_SELECTOR = b"mailforgetest"
DKIM_DOMAIN = b"example-sender.test"


class FakeResolver:
    """Minimal stand-in for :class:`dns.resolver.Resolver`.

    Only implements the TXT path that :mod:`app.services.email_auth` uses.
    """

    def __init__(self, records: dict[str, list[str]]):
        self.records = records
        self.queries: list[str] = []

    def resolve(self, name, rdtype, lifetime=None, **kwargs):  # noqa: ARG002
        key = str(name).rstrip(".").lower()
        self.queries.append(key)
        if key not in self.records:
            raise dns.resolver.NXDOMAIN(qnames=[key])
        return [
            SimpleNamespace(strings=[value.encode()])
            for value in self.records[key]
        ]


@pytest.fixture(scope="session")
def dkim_private_key() -> bytes:
    return (KEYS_DIR / "dkim_test_private.pem").read_bytes()


@pytest.fixture(scope="session")
def dkim_public_b64() -> str:
    return (KEYS_DIR / "dkim_test_public.b64").read_text().strip()


@pytest.fixture(scope="session")
def dkim_dnsfunc(dkim_public_b64: str):
    """A ``dnsfunc`` serving the test public key for our selector only."""
    expected = f"{DKIM_SELECTOR.decode()}._domainkey.{DKIM_DOMAIN.decode()}"
    record = f"v=DKIM1; k=rsa; p={dkim_public_b64}".encode()

    def resolve(name, timeout=5, **kwargs):  # noqa: ARG001
        key = name.decode() if isinstance(name, bytes) else str(name)
        if key.rstrip(".").lower() == expected:
            return record
        return b""

    return resolve


def build_message(
    *,
    from_header: str = f"Sender <hello@{DKIM_DOMAIN.decode()}>",
    subject: str = "Quarterly report",
    body: str = "Numbers attached as discussed.\n",
    extra_headers: str = "",
) -> bytes:
    """Assemble a minimal RFC 5322 message with CRLF line endings.

    CRLF matters: DKIM signs the canonicalised wire form, so a message built
    with bare LF would not verify.
    """
    headers = [
        f"From: {from_header}",
        "To: analyst@recipient.test",
        f"Subject: {subject}",
        "Date: Tue, 9 Sep 2026 14:22:25 +0530",
        "Message-ID: <test-message-0001@example-sender.test>",
        'Content-Type: text/plain; charset="utf-8"',
    ]
    raw = "\r\n".join(headers)
    if extra_headers:
        raw += "\r\n" + extra_headers.strip().replace("\n", "\r\n")
    raw += "\r\n\r\n" + body.replace("\n", "\r\n")
    return raw.encode()


@pytest.fixture
def signed_message(dkim_private_key: bytes):
    """Return a factory producing genuinely DKIM-signed messages."""

    def _sign(message: bytes | None = None, domain: bytes = DKIM_DOMAIN) -> bytes:
        message = message if message is not None else build_message()
        signature = dkim.sign(
            message,
            DKIM_SELECTOR,
            domain,
            dkim_private_key,
            include_headers=[b"from", b"to", b"subject", b"date"],
        )
        return signature + message

    return _sign


@pytest.fixture(scope="session")
def sample_paths() -> dict[str, pathlib.Path]:
    return {path.name: path for path in sorted(SAMPLES_DIR.glob("*.eml"))}
