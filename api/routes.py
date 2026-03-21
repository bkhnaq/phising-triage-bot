"""
FastAPI REST API for Phishing Triage Engine
--------------------------------------------
Exposes the phishing detection pipeline as a REST API.

Endpoints:
  POST /analyze_email   – Analyze raw email text
  POST /analyze_file    – Analyze uploaded .eml file
  GET  /health          – Health check

Usage:
    uvicorn api.routes:app --host 0.0.0.0 --port 8000
"""

from collections import defaultdict, deque
import logging
import os
import re
import threading
import time
import unicodedata
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from config.settings import (
    API_KEY,
    RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    UPLOAD_DIR,
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Phishing Triage Engine API",
    description="Enterprise-grade multi-layer phishing detection REST API",
    version="2.0.0",
)


_rate_limit_lock = threading.Lock()
_rate_limit_buckets: dict[str, deque[float]] = defaultdict(deque)


# ── Request / Response Models ────────────────────────────────


class EmailAnalysisRequest(BaseModel):
    """Request body for raw email analysis."""

    email_raw: str = Field(..., description="Raw email content (RFC 5322 format)")


class RiskResult(BaseModel):
    """Risk scoring result."""

    score: int = Field(..., ge=0, le=100, description="Risk score 0-100")
    verdict: str = Field(
        ..., description="INCONCLUSIVE / LOW / MEDIUM / SUSPICIOUS / HIGH / CRITICAL"
    )
    confidence: float = Field(
        0.0, ge=0.0, le=1.0, description="Classification confidence 0.0-1.0"
    )
    data_completeness: int = Field(
        0, ge=0, le=100, description="Evidence completeness 0-100"
    )
    category_scores: dict = Field(default_factory=dict)
    breakdown: list[str] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    """Response model for email analysis."""

    success: bool
    request_id: str
    risk: RiskResult
    report: str = Field(..., description="Human-readable analysis report")
    email_metadata: dict = Field(default_factory=dict)
    auth_results: dict = Field(default_factory=dict)
    ai_verdict: dict = Field(default_factory=dict)
    url_count: int = 0
    attachment_count: int = 0
    indicators: dict = Field(
        default_factory=dict,
        description="Summary of key detection indicators",
    )


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "healthy"
    version: str = "2.0.0"
    request_id: str


class ErrorResponse(BaseModel):
    """Standardized API error response."""

    success: bool = False
    request_id: str
    error: dict[str, Any]


# ── Middleware / Error Handlers ──────────────────────────────


def _request_id_from(request: Request) -> str:
    rid = getattr(request.state, "request_id", None)
    return rid if isinstance(rid, str) and rid else str(uuid.uuid4())


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def api_key_auth_middleware(request: Request, call_next):
    public_paths = {"/health", "/docs", "/openapi.json", "/redoc"}
    if request.url.path in public_paths:
        return await call_next(request)

    if not API_KEY:
        logger.warning(
            "API_KEY is not configured; rejecting authenticated endpoint request"
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "success": False,
                "request_id": _request_id_from(request),
                "error": {
                    "code": "service_unavailable",
                    "message": "API authentication is not configured",
                },
            },
        )

    provided_key = request.headers.get("X-API-Key", "")
    if provided_key != API_KEY:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "success": False,
                "request_id": _request_id_from(request),
                "error": {
                    "code": "unauthorized",
                    "message": "Invalid API key",
                },
            },
        )

    return await call_next(request)


def _is_rate_limited(client_id: str, now: float) -> bool:
    with _rate_limit_lock:
        bucket = _rate_limit_buckets[client_id]
        threshold = now - RATE_LIMIT_WINDOW_SECONDS
        while bucket and bucket[0] <= threshold:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
            return True
        bucket.append(now)
        return False


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path in {"/health", "/docs", "/openapi.json", "/redoc"}:
        return await call_next(request)

    client_host = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_host, time.monotonic()):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "success": False,
                "request_id": _request_id_from(request),
                "error": {
                    "code": "rate_limited",
                    "message": (
                        f"Rate limit exceeded: {RATE_LIMIT_MAX_REQUESTS} requests "
                        f"per {RATE_LIMIT_WINDOW_SECONDS} seconds"
                    ),
                },
            },
        )

    return await call_next(request)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    code = "http_error"
    if exc.status_code == status.HTTP_400_BAD_REQUEST:
        code = "bad_request"
    elif exc.status_code == status.HTTP_401_UNAUTHORIZED:
        code = "unauthorized"
    elif exc.status_code == status.HTTP_404_NOT_FOUND:
        code = "not_found"

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "request_id": _request_id_from(request),
            "error": {
                "code": code,
                "message": str(exc.detail),
            },
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "success": False,
            "request_id": _request_id_from(request),
            "error": {
                "code": "validation_error",
                "message": "Invalid request payload",
                "details": exc.errors(),
            },
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "request_id": _request_id_from(request),
            "error": {
                "code": "internal_error",
                "message": f"Internal server error: {exc}",
            },
        },
    )


# ── Helpers ──────────────────────────────────────────────────


def _sanitize_filename(filename: str | None) -> str:
    candidate = unicodedata.normalize("NFKC", filename or "upload.eml")
    candidate = Path(candidate).name
    candidate = re.sub(r"[^A-Za-z0-9._-]", "_", candidate)
    return candidate[:100] or "upload.eml"


def _safe_upload_path(original_name: str, prefix: str) -> Path:
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    upload_root = Path(UPLOAD_DIR).resolve()
    safe_filename = _sanitize_filename(original_name)
    destination = (
        upload_root / f"{prefix}_{uuid.uuid4().hex}_{safe_filename}"
    ).resolve()
    if upload_root not in destination.parents and destination != upload_root:
        raise HTTPException(status_code=400, detail="Invalid upload path")
    return destination


# ── Endpoints ────────────────────────────────────────────────


@app.get("/health", response_model=HealthResponse)
async def health_check(request: Request):
    """Health check endpoint."""
    return HealthResponse(request_id=_request_id_from(request))


@app.post("/analyze_email", response_model=AnalysisResponse)
async def analyze_email(payload: EmailAnalysisRequest, request: Request):
    """
    Analyze a raw email for phishing indicators.

    Accepts raw email text (RFC 5322 / .eml format) and returns
    a complete phishing analysis with risk score.
    """
    if not payload.email_raw or not payload.email_raw.strip():
        raise HTTPException(status_code=400, detail="email_raw cannot be empty")

    try:
        from email_analysis.pipeline import PhishingPipeline

        pipeline = PhishingPipeline()
        result = pipeline.analyze_raw(payload.email_raw)

        return _build_response(result, request_id=_request_id_from(request))

    except Exception as exc:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc


@app.post("/analyze_file", response_model=AnalysisResponse)
async def analyze_file(request: Request, file: UploadFile = File(...)):
    """
    Analyze an uploaded .eml file for phishing indicators.
    """
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported",
        )

    save_path = _safe_upload_path(file.filename, prefix="api")

    try:
        content = await file.read()
        with open(save_path, "wb") as f:
            f.write(content)

        from email_analysis.pipeline import PhishingPipeline

        pipeline = PhishingPipeline()
        result = pipeline.analyze_file(str(save_path))

        return _build_response(result, request_id=_request_id_from(request))

    except Exception as exc:
        logger.exception("Analysis failed for uploaded file")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc
    finally:
        try:
            save_path.unlink(missing_ok=True)
        except OSError:
            pass
        await file.close()


# ── Response Builder ─────────────────────────────────────────


def _build_response(result: dict, request_id: str) -> AnalysisResponse:
    """Build the API response from pipeline results."""
    risk_data = result.get("risk", {})
    indicators = {
        "spf": result.get("auth_results", {}).get("spf", {}).get("result", "none"),
        "dkim": result.get("auth_results", {}).get("dkim", {}).get("result", "none"),
        "dmarc": result.get("auth_results", {}).get("dmarc", {}).get("result", "none"),
        "credential_harvesting": result.get("credential_harvesting", {}).get(
            "detected", False
        ),
        "brand_impersonation": bool(
            result.get("brand_impersonation", {}).get("domain_impersonation", [])
        ),
        "phishing_language_score": result.get("language_analysis", {}).get(
            "risk_score", 0
        ),
        "suspicious_attachments": len(result.get("attachment_risks", [])),
        "url_shorteners_detected": len(
            result.get("url_intelligence", {}).get("shortener_findings", [])
        ),
    }

    ai = result.get("ai_verdict", {})
    ai_safe = {
        "verdict": ai.get("verdict", "unknown"),
        "confidence": ai.get("confidence", 0.0),
        "reasons": ai.get("reasons", []),
        "risk_score": ai.get("risk_score", 0),
    }

    return AnalysisResponse(
        success=True,
        request_id=request_id,
        risk=RiskResult(
            score=risk_data.get("score", 0),
            verdict=risk_data.get("verdict", "LOW"),
            confidence=risk_data.get("confidence", 0.0),
            data_completeness=risk_data.get("data_completeness", 0),
            category_scores=risk_data.get("category_scores", {}),
            breakdown=risk_data.get("breakdown", []),
        ),
        report=result.get("report", ""),
        email_metadata=result.get("email_data", {}),
        auth_results={
            "spf": result.get("auth_results", {}).get("spf", {}),
            "dkim": result.get("auth_results", {}).get("dkim", {}),
            "dmarc": result.get("auth_results", {}).get("dmarc", {}),
        },
        ai_verdict=ai_safe,
        url_count=len(result.get("urls", [])),
        attachment_count=len(result.get("attachments", [])),
        indicators=indicators,
    )
