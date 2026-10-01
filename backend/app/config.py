"""Runtime configuration, overridable via environment or a ``.env`` file."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

VERSION = "0.1.0"


class Settings(BaseSettings):
    """All settings can be set as ``MAILFORGE_<NAME>`` environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="MAILFORGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    #: Skip every DNS lookup. Useful for demoing without a network -- all
    #: three checks then report ``not_checked`` instead of ``temperror``.
    offline: bool = False

    #: Resolvers used for SPF/DKIM/DMARC lookups. Public resolvers are the
    #: default on purpose: consumer routers and corporate split-horizon DNS
    #: frequently rewrite NXDOMAIN or drop TXT records, which silently turns a
    #: genuine SPF failure into a temperror. Set to an empty list (or
    #: ``MAILFORGE_DNS_SERVERS=system``) to use the machine's own resolver.
    dns_servers: Annotated[list[str], NoDecode] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    #: Seconds to wait on a single nameserver before trying the next one.
    dns_query_timeout: float = 2.5

    #: Total budget for one DNS lookup across all nameservers.
    dns_timeout: float = 6.0

    #: Total budget for a full SPF evaluation. An SPF record with several
    #: nested ``include:`` terms needs many lookups, so this is deliberately
    #: larger than a single-lookup timeout.
    spf_querytime: float = 20.0

    #: Reject uploads larger than this. Real mail is rarely over a few MB and
    #: an unbounded upload is an easy way to exhaust memory.
    max_upload_bytes: int = 25 * 1024 * 1024

    #: Origins allowed to call the API from a browser (the Phase 1 dashboard).
    cors_origins: Annotated[list[str], NoDecode] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "https://mail.google.com",
    ]

    #: Browser-extension origins are opaque (chrome-extension://<id>) and the
    #: id changes between an unpacked build and a published one, so they are
    #: matched by pattern rather than listed.
    cors_origin_regex: str = r"^chrome-extension://[a-p]{32}$"

    @field_validator("dns_servers", "cors_origins", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        """Accept ``a,b,c`` as well as a JSON list, so the env vars stay typable.

        These fields are annotated ``NoDecode`` so pydantic-settings hands us
        the raw environment string instead of trying to JSON-decode it first;
        without that, a plain comma-separated value raises a JSONDecodeError
        before this validator ever runs.
        """
        if not isinstance(value, str):
            return value

        text = value.strip()
        if text.lower() in ("system", "default", ""):
            return []
        if text.startswith("["):
            return json.loads(text)
        return [item.strip() for item in text.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
