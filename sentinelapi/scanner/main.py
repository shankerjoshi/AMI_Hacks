from __future__ import annotations

from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from detectors import detect_bola, detect_sensitive_field_exposure
from executor import SafeRequestExecutor
from parser import OpenAPIParser
from schemas import AuthProfile, Endpoint, ScanRequest

app = FastAPI(title="SentinelAPI Scanner", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanPayload(BaseModel):
    spec_text: str
    spec_format: str = "auto"
    base_url: str = "http://demo-api:8001"
    allowlist: List[str] = ["localhost", "127.0.0.1", "demo-api"]
    auth_profiles: List[AuthProfile] = [
        AuthProfile(name="alice", token="alice-token", header="Authorization", prefix="Bearer"),
        AuthProfile(name="bob", token="bob-token", header="Authorization", prefix="Bearer"),
    ]
    timeout_seconds: int = 10
    request_budget: int = 25
    concurrency: int = 2


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
async def run_scan(payload: ScanPayload):
    try:
        parser = OpenAPIParser()
        parser.parse_spec(payload.spec_text, spec_format=payload.spec_format)
        endpoints = parser.discover_endpoints()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    scan_request = ScanRequest(
        spec_source="inline",
        base_url=payload.base_url,
        allowlist=payload.allowlist,
        auth_profiles=payload.auth_profiles,
        enabled_checks=["bola", "sensitive_fields"],
        timeout_seconds=payload.timeout_seconds,
        request_budget=payload.request_budget,
        concurrency=payload.concurrency,
    )

    findings: List[Dict[str, Any]] = []

    async with SafeRequestExecutor(scan_request) as executor:
        for endpoint in endpoints:
            candidate_names = endpoint.candidate_identifiers or ["id", "userId"]
            params = {name: "1001" for name in candidate_names if name}

            baseline_request = executor.get_redacted_request_log(endpoint, scan_request.auth_profiles[0], params)
            cross_user_request = executor.get_redacted_request_log(endpoint, scan_request.auth_profiles[1], params)

            baseline = await executor.execute_request(endpoint, scan_request.auth_profiles[0], path_params=params)
            cross = await executor.execute_request(endpoint, scan_request.auth_profiles[1], path_params=params)

            if baseline.status_code == 0 and baseline.error:
                continue
            if cross.status_code == 0 and cross.error:
                continue

            bola_finding = detect_bola(
                endpoint,
                scan_request.auth_profiles[0].name,
                scan_request.auth_profiles[1].name,
                baseline_request,
                {"status_code": baseline.status_code, "body": baseline.body},
                cross_user_request,
                {"status_code": cross.status_code, "body": cross.body},
            )
            if bola_finding:
                findings.append(bola_finding.model_dump())

            sensitive_finding = detect_sensitive_field_exposure(
                endpoint,
                baseline_request,
                {"status_code": baseline.status_code, "body": baseline.body},
                cross_user_request,
                {"status_code": cross.status_code, "body": cross.body},
            )
            if sensitive_finding:
                findings.append(sensitive_finding.model_dump())

    return {
        "status": "completed",
        "endpoints_discovered": len(endpoints),
        "endpoints_tested": min(len(endpoints), 10),
        "findings": findings,
    }


@app.get("/openapi")
def openapi_spec():
    return app.openapi()
