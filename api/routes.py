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

import logging
import os
import tempfile

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from config.settings import UPLOAD_DIR

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Phishing Triage Engine API",
    description="Enterprise-grade multi-layer phishing detection REST API",
    version="2.0.0",
)


# ── Request / Response Models ────────────────────────────────

class EmailAnalysisRequest(BaseModel):
    """Request body for raw email analysis."""
    email_raw: str = Field(..., description="Raw email content (RFC 5322 format)")


class RiskResult(BaseModel):
    """Risk scoring result."""
    score: int = Field(..., ge=0, le=100, description="Risk score 0-100")
    verdict: str = Field(..., description="INCONCLUSIVE / LOW / MEDIUM / SUSPICIOUS / HIGH / CRITICAL")
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Classification confidence 0.0-1.0")
    data_completeness: int = Field(0, ge=0, le=100, description="Evidence completeness 0-100")
    category_scores: dict = Field(default_factory=dict)
    breakdown: list[str] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    """Response model for email analysis."""
    success: bool
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


# ── Endpoints ────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse()


@app.post("/analyze_email", response_model=AnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    """
    Analyze a raw email for phishing indicators.

    Accepts raw email text (RFC 5322 / .eml format) and returns
    a complete phishing analysis with risk score.
    """
    if not request.email_raw or not request.email_raw.strip():
        raise HTTPException(status_code=400, detail="email_raw cannot be empty")

    try:
        from email_analysis.pipeline import PhishingPipeline

        pipeline = PhishingPipeline()
        result = pipeline.analyze_raw(request.email_raw)

        return _build_response(result)

    except Exception as exc:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}")


@app.post("/analyze_file", response_model=AnalysisResponse)
async def analyze_file(file: UploadFile = File(...)):
    """
    Analyze an uploaded .eml file for phishing indicators.
    """
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported",
        )

    # Save uploaded file
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    # Use a fixed safe filename pattern
    safe_name = os.path.basename(file.filename)
    save_path = os.path.join(UPLOAD_DIR, f"api_{safe_name}")

    try:
        content = await file.read()
        with open(save_path, "wb") as f:
            f.write(content)

        from email_analysis.pipeline import PhishingPipeline

        pipeline = PhishingPipeline()
        result = pipeline.analyze_file(save_path)

        return _build_response(result)

    except Exception as exc:
        logger.exception("Analysis failed for uploaded file")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}")
    finally:
        try:
            os.unlink(save_path)
        except OSError:
            pass


# ── Helpers ──────────────────────────────────────────────────

def _build_response(result: dict) -> AnalysisResponse:
    """Build the API response from pipeline results."""
    risk_data = result.get("risk", {})
    indicators = {
        "spf": result.get("auth_results", {}).get("spf", {}).get("result", "none"),
        "dkim": result.get("auth_results", {}).get("dkim", {}).get("result", "none"),
        "dmarc": result.get("auth_results", {}).get("dmarc", {}).get("result", "none"),
        "credential_harvesting": result.get("credential_harvesting", {}).get("detected", False),
        "brand_impersonation": bool(
            result.get("brand_impersonation", {}).get("domain_impersonation", [])
        ),
        "phishing_language_score": result.get("language_analysis", {}).get("risk_score", 0),
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
