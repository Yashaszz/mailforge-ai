"""Pydantic response models for the Mailforge API.

These are the contract the dashboard will render against, so they are kept
explicit rather than dumping dataclasses straight to JSON.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from .services.email_auth import AuthReport, AuthVerdict
from .services.eml_parser import ParsedEmail, is_public_ip
from .services.risk import RiskAssessment


class HeaderEntry(BaseModel):
    name: str
    value: str


class ReceivedHopOut(BaseModel):
    """One hop of the relay path. Index 0 is the last MTA to touch the mail."""

    index: int
    from_host: str | None = None
    from_ip: str | None = None
    from_ip_is_public: bool = False
    by_host: str | None = None
    protocol: str | None = None
    queue_id: str | None = None
    recipient: str | None = None
    timestamp: datetime | None = None
    raw: str


class MessageSummary(BaseModel):
    subject: str | None = None
    message_id: str | None = None
    date: datetime | None = None
    from_address: str | None = None
    from_display_name: str | None = None
    from_domain: str | None = None
    reply_to_address: str | None = None
    reply_to_domain: str | None = None
    return_path: str | None = None
    envelope_from: str | None = None
    envelope_from_domain: str | None = None
    attachment_count: int = 0
    attachment_names: list[str] = Field(default_factory=list)


class OriginOut(BaseModel):
    """The SMTP envelope reconstructed from the headers.

    There is no live connection when analysing a ``.eml``, so ``client_ip`` is
    inferred; ``client_ip_source`` records exactly how, because every SPF
    result downstream depends on that choice being right.
    """

    client_ip: str | None = None
    client_ip_is_public: bool = False
    client_ip_source: str | None = None
    helo: str | None = None


class SpfOut(BaseModel):
    result: AuthVerdict
    detail: str = ""
    client_ip: str | None = None
    mail_from: str | None = None
    helo: str | None = None
    domain: str | None = None
    record: str | None = None


class DkimSignatureOut(BaseModel):
    index: int
    domain: str | None = None
    selector: str | None = None
    algorithm: str | None = None
    result: AuthVerdict
    detail: str = ""


class DkimOut(BaseModel):
    result: AuthVerdict
    detail: str = ""
    signatures: list[DkimSignatureOut] = Field(default_factory=list)


class DmarcOut(BaseModel):
    result: AuthVerdict
    detail: str = ""
    record: str | None = None
    record_domain: str | None = None
    policy: str | None = None
    subdomain_policy: str | None = None
    pct: int | None = None
    spf_alignment: str = "not_checked"
    dkim_alignment: str = "not_checked"
    alignment_mode_spf: str = "r"
    alignment_mode_dkim: str = "r"
    disposition: str | None = None


class AuthenticationOut(BaseModel):
    spf: SpfOut
    dkim: DkimOut
    dmarc: DmarcOut
    dns_available: bool = True
    notes: list[str] = Field(default_factory=list)


class RiskReasonOut(BaseModel):
    code: str
    severity: str
    points: int
    title: str
    detail: str


class AssessmentOut(BaseModel):
    """The analyst-facing verdict, derived from everything below it."""

    score: int = Field(ge=0, le=100)
    level: str = Field(description="Allow | Suspicious | High-Risk | Malicious")
    confidence: str
    summary: str
    reasons: list[RiskReasonOut] = Field(default_factory=list)


class SampleOut(BaseModel):
    name: str
    title: str
    description: str
    size_bytes: int


class AnalysisResponse(BaseModel):
    """Full Layer 1 result for one message."""

    filename: str | None = None
    size_bytes: int
    analyzed_at: datetime
    assessment: AssessmentOut
    message: MessageSummary
    origin: OriginOut
    authentication: AuthenticationOut
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Curated headers an analyst reads first.",
    )
    received_chain: list[ReceivedHopOut] = Field(default_factory=list)
    all_headers: list[HeaderEntry] = Field(default_factory=list)
    reported_authentication_results: list[str] = Field(
        default_factory=list,
        description=(
            "Authentication-Results headers stamped by the receiving MTA. "
            "Independent of our own checks and useful as a cross-check."
        ),
    )
    warnings: list[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    version: str
    offline_mode: bool


def build_response(
    parsed: ParsedEmail,
    report: AuthReport,
    assessment: RiskAssessment,
    *,
    filename: str | None,
    analyzed_at: datetime,
) -> AnalysisResponse:
    """Assemble the API response from the parser, auth and scoring results."""
    return AnalysisResponse(
        filename=filename,
        size_bytes=len(parsed.raw),
        analyzed_at=analyzed_at,
        assessment=AssessmentOut(
            score=assessment.score,
            level=assessment.level,
            confidence=assessment.confidence,
            summary=assessment.summary,
            reasons=[
                RiskReasonOut(
                    code=r.code,
                    severity=r.severity,
                    points=r.points,
                    title=r.title,
                    detail=r.detail,
                )
                for r in assessment.reasons
            ],
        ),
        message=MessageSummary(
            subject=parsed.subject,
            message_id=parsed.message_id,
            date=parsed.date,
            from_address=parsed.from_address,
            from_display_name=parsed.from_display_name,
            from_domain=parsed.from_domain,
            reply_to_address=parsed.reply_to_address,
            reply_to_domain=parsed.reply_to_domain,
            return_path=parsed.return_path,
            envelope_from=parsed.envelope_from,
            envelope_from_domain=parsed.envelope_from_domain,
            attachment_count=parsed.attachment_count,
            attachment_names=parsed.attachment_names,
        ),
        origin=OriginOut(
            client_ip=parsed.client_ip,
            client_ip_is_public=is_public_ip(parsed.client_ip),
            client_ip_source=parsed.client_ip_source,
            helo=parsed.helo,
        ),
        authentication=AuthenticationOut(
            spf=SpfOut(
                result=report.spf.result,
                detail=report.spf.detail,
                client_ip=report.spf.client_ip,
                mail_from=report.spf.mail_from,
                helo=report.spf.helo,
                domain=report.spf.domain,
                record=report.spf.record,
            ),
            dkim=DkimOut(
                result=report.dkim.result,
                detail=report.dkim.detail,
                signatures=[
                    DkimSignatureOut(
                        index=s.index,
                        domain=s.domain,
                        selector=s.selector,
                        algorithm=s.algorithm,
                        result=s.result,
                        detail=s.detail,
                    )
                    for s in report.dkim.signatures
                ],
            ),
            dmarc=DmarcOut(
                result=report.dmarc.result,
                detail=report.dmarc.detail,
                record=report.dmarc.record,
                record_domain=report.dmarc.record_domain,
                policy=report.dmarc.policy,
                subdomain_policy=report.dmarc.subdomain_policy,
                pct=report.dmarc.pct,
                spf_alignment=report.dmarc.spf_alignment,
                dkim_alignment=report.dmarc.dkim_alignment,
                alignment_mode_spf=report.dmarc.alignment_mode_spf,
                alignment_mode_dkim=report.dmarc.alignment_mode_dkim,
                disposition=report.dmarc.disposition,
            ),
            dns_available=report.dns_available,
            notes=report.notes,
        ),
        headers=parsed.headers,
        received_chain=[
            ReceivedHopOut(
                index=hop.index,
                from_host=hop.from_host,
                from_ip=hop.from_ip,
                from_ip_is_public=hop.is_public_ip,
                by_host=hop.by_host,
                protocol=hop.protocol,
                queue_id=hop.queue_id,
                recipient=hop.recipient,
                timestamp=hop.timestamp,
                raw=hop.raw,
            )
            for hop in parsed.received_chain
        ],
        all_headers=[HeaderEntry(name=n, value=v) for n, v in parsed.all_headers],
        reported_authentication_results=parsed.authentication_results,
        warnings=parsed.parse_warnings,
    )
