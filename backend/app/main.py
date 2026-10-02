"""Mailforge AI -- FastAPI application.

Serves both the JSON API and the analyst dashboard, so the whole prototype
runs from a single command.

Endpoints:
    GET  /                    the dashboard
    POST /analyze             analyse an uploaded .eml
    GET  /samples             list the bundled demo messages
    POST /samples/{name}/analyze   analyse one of them
    GET  /health              liveness + mode
    GET  /docs                generated OpenAPI UI
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from .config import VERSION, get_settings
from .schemas import (
    AnalysisResponse,
    AuthenticationOut,
    HealthResponse,
    SampleOut,
    authentication_out,
    build_response,
)
from .services.email_auth import authenticate, configure_dns
from .services.cross_check import cross_check
from .services.eml_parser import parse_eml
from .services.network_intel import lookup_many
from .services.risk import assess

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("mailforge")

settings = get_settings()

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SAMPLES_DIR = REPO_ROOT / "samples"
FRONTEND_DIR = REPO_ROOT / "frontend"

#: Short descriptions for the bundled demo messages, shown in the dashboard.
SAMPLE_LIBRARY: dict[str, tuple[str, str]] = {
    "01_legitimate_gmail.eml": (
        "Legitimate mail",
        "Genuine message relayed by an authorised Google server. "
        "Everything aligns - this is what a clean result looks like.",
    ),
    "02_spoofed_paypal_phish.eml": (
        "Spoofed brand phishing",
        "Claims to be PayPal but was sent from an unrelated VPS. "
        "SPF alone would not catch it; DMARC alignment does.",
    ),
    "03_bec_ceo_wire_fraud.eml": (
        "CEO fraud (BEC)",
        "Wire-transfer request from a lookalike domain that publishes no "
        "SPF or DMARC at all, with replies redirected elsewhere.",
    ),
    "05_vpn_anonymised_phish.eml": (
        "Anonymised sender (VPN)",
        "Credential phishing sent straight from a commercial VPN exit, so the "
        "sender's real network is hidden. Shows VPN detection on the origin.",
    ),
    "06_forged_relay_headers.eml": (
        "Forged relay headers",
        "Fake internal hops prepended to disguise the origin as the company's "
        "own mail server. The timestamps make the forgery provable.",
    ),
    "04_multihop_relay_laundering.eml": (
        "Multi-hop relay laundering",
        "Invoice fraud routed through four countries to obscure its origin. "
        "Shows the full relay path reconstructed and plotted.",
    ),
}

app = FastAPI(
    title="Mailforge AI",
    version=VERSION,
    summary="Email fraud detection and forensic tracing",
    description=(
        "Layer 1 of the Mailforge pipeline: SMTP-gateway authentication checks "
        "(SPF, DKIM, DMARC), header forensics and risk scoring over a `.eml` file."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=settings.cors_origin_regex,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

if not settings.offline:
    configure_dns(
        settings.dns_servers,
        query_timeout=settings.dns_query_timeout,
        lifetime=settings.dns_timeout,
    )


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["meta"])
def health() -> HealthResponse:
    return HealthResponse(status="ok", version=VERSION, offline_mode=settings.offline)


@app.get("/samples", response_model=list[SampleOut], tags=["analysis"])
def list_samples() -> list[SampleOut]:
    """The demo messages bundled with the repository."""
    samples: list[SampleOut] = []
    for name, (title, description) in SAMPLE_LIBRARY.items():
        path = SAMPLES_DIR / name
        if path.is_file():
            samples.append(SampleOut(
                name=name,
                title=title,
                description=description,
                size_bytes=path.stat().st_size,
            ))
    return samples


@app.post("/samples/{name}/analyze", response_model=AnalysisResponse, tags=["analysis"])
async def analyze_sample(name: str) -> AnalysisResponse:
    """Analyse a bundled sample by name, so the demo needs no file picker."""
    if name not in SAMPLE_LIBRARY:
        raise HTTPException(status_code=404, detail=f"Unknown sample {name!r}.")

    path = SAMPLES_DIR / name
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"Sample file {name!r} is missing.")

    return await _run_analysis(path.read_bytes(), filename=name)


@app.post("/analyze", response_model=AnalysisResponse, tags=["analysis"])
async def analyze(
    file: UploadFile = File(..., description="A raw RFC 5322 message (.eml)"),
) -> AnalysisResponse:
    """Parse an uploaded ``.eml`` and return its headers, authentication results
    and risk assessment."""
    raw = await _read_upload(file)
    return await _run_analysis(raw, filename=file.filename)


@app.post("/authenticate", response_model=AuthenticationOut, tags=["analysis"])
async def authenticate_only(
    file: UploadFile = File(..., description="A raw RFC 5322 message (.eml)"),
) -> AuthenticationOut:
    """SPF, DKIM and DMARC only: no risk scoring and no network-reputation lookups.

    Exists for controlled comparisons where the only intended variable is the
    message bytes -- for example verifying two retrievals of the same message
    seconds apart, so any difference in the verdict is attributable to the
    bytes rather than to DNS changing in between.
    """
    raw = await _read_upload(file)
    try:
        parsed = parse_eml(raw)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse message: {exc}") from exc

    report = await run_in_threadpool(
        authenticate,
        parsed,
        offline=settings.offline,
        timeout=settings.dns_timeout,
        spf_querytime=settings.spf_querytime,
    )
    return authentication_out(report)


async def _run_analysis(raw: bytes, *, filename: str | None) -> AnalysisResponse:
    started = datetime.now(timezone.utc)

    try:
        parsed = parse_eml(raw)
    except Exception as exc:
        logger.exception("Failed to parse %s", filename)
        raise HTTPException(
            status_code=422,
            detail=f"Could not parse the uploaded file as an email message: {exc}",
        ) from exc

    if not parsed.all_headers:
        raise HTTPException(
            status_code=422,
            detail=(
                "No email headers were found. Make sure this is a raw .eml file "
                "and not an exported PDF, .msg, or message body on its own."
            ),
        )

    # The auth checks are blocking DNS work, so keep them off the event loop.
    report = await run_in_threadpool(
        authenticate,
        parsed,
        offline=settings.offline,
        timeout=settings.dns_timeout,
        spf_querytime=settings.spf_querytime,
    )
    # Reputation for every publicly routable hop, origin first so it is the
    # one that survives the lookup cap. Never blocks the verdict.
    hop_ips = [parsed.client_ip] + [
        h.from_ip for h in parsed.received_chain if h.is_public_ip
    ]
    networks = await run_in_threadpool(lookup_many, [ip for ip in hop_ips if ip])

    assessment = assess(parsed, report, networks)
    corroboration = cross_check(parsed, report)

    logger.info(
        "analyzed %s from=%s ip=%s spf=%s dkim=%s dmarc=%s -> %s (%d)",
        filename, parsed.from_address, parsed.client_ip,
        report.spf.result, report.dkim.result, report.dmarc.result,
        assessment.level, assessment.score,
    )

    return build_response(
        parsed, report, assessment, filename=filename, analyzed_at=started,
        networks=networks, corroboration=corroboration,
    )


async def _read_upload(file: UploadFile) -> bytes:
    """Read the upload, refusing anything over the configured size limit.

    Reads one byte past the limit so an oversized file is rejected rather than
    silently truncated and analysed as a different message than was sent.
    """
    limit = settings.max_upload_bytes
    raw = await file.read(limit + 1)

    if len(raw) > limit:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {limit // (1024 * 1024)} MB upload limit.",
        )
    if not raw.strip():
        raise HTTPException(status_code=422, detail="The uploaded file is empty.")

    return raw


# --------------------------------------------------------------------------
# Dashboard -- mounted last so it never shadows an API route
# --------------------------------------------------------------------------

if FRONTEND_DIR.is_dir():
    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "index.html")

    app.mount("/", StaticFiles(directory=FRONTEND_DIR), name="frontend")
else:  # pragma: no cover - only when the frontend directory is absent
    logger.warning("Frontend directory not found at %s", FRONTEND_DIR)
