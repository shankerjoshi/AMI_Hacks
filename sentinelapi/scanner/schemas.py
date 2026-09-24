from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum

class AuthProfile(BaseModel):
    name: str
    token: str
    header: str = "Authorization"
    prefix: str = "Bearer"

class ScanRequest(BaseModel):
    spec_source: str  # URL or file path
    base_url: str
    allowlist: List[str] = ["localhost", "127.0.0.1", "demo-api"]
    auth_profiles: List[AuthProfile] = Field(min_items=2, max_items=2)
    enabled_checks: List[str] = ["bola", "sensitive_fields"]
    timeout_seconds: int = 10
    request_budget: int = 100
    concurrency: int = 2

class EndpointParameter(BaseModel):
    name: str
    location: str  # path, query, header, body
    schema: Dict[str, Any]
    required: bool = False

class Endpoint(BaseModel):
    method: str
    path: str
    operation_id: Optional[str] = None
    parameters: List[EndpointParameter] = []
    auth_required: bool = True
    candidate_identifiers: List[str] = []  # Parameter names that look like object IDs

class FindingType(str, Enum):
    BOLA = "bola"
    SENSITIVE_FIELD_EXPOSURE = "sensitive_field_exposure"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    INFO = "info"

class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    OBSERVATION = "observation"

class Evidence(BaseModel):
    baseline_request: Dict[str, Any]
    baseline_response: Dict[str, Any]
    cross_user_request: Dict[str, Any]
    cross_user_response: Dict[str, Any]
    redactions: List[str] = []
    comparison_reason: str

class Finding(BaseModel):
    id: str
    type: FindingType
    severity: Severity
    confidence: Confidence
    endpoint: Endpoint
    evidence: Evidence
    reproduction: Dict[str, Any]
    remediation: str
    timestamp: str

class ScanResult(BaseModel):
    scan_id: str
    status: str  # running, completed, failed
    endpoints_discovered: int
    endpoints_tested: int
    findings: List[Finding] = []
    errors: List[str] = []
    started_at: str
    completed_at: Optional[str] = None