from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from schemas import Confidence, Endpoint, Evidence, Finding, FindingType, Severity


def _make_finding(
    endpoint: Endpoint,
    finding_type: FindingType,
    severity: Severity,
    confidence: Confidence,
    baseline_request: Dict[str, Any],
    baseline_response: Dict[str, Any],
    cross_user_request: Dict[str, Any],
    cross_user_response: Dict[str, Any],
    comparison_reason: str,
    remediation: str,
) -> Finding:
    evidence = Evidence(
        baseline_request=baseline_request,
        baseline_response=baseline_response,
        cross_user_request=cross_user_request,
        cross_user_response=cross_user_response,
        redactions=["Authorization", "token"],
        comparison_reason=comparison_reason,
    )
    return Finding(
        id=f"{finding_type.value}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        type=finding_type,
        severity=severity,
        confidence=confidence,
        endpoint=endpoint,
        evidence=evidence,
        reproduction={
            "baseline": baseline_request,
            "cross_user": cross_user_request,
        },
        remediation=remediation,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def detect_bola(
    endpoint: Endpoint,
    user_a_name: str,
    user_b_name: str,
    baseline_request: Dict[str, Any],
    baseline_response: Dict[str, Any],
    cross_user_request: Dict[str, Any],
    cross_user_response: Dict[str, Any],
) -> Optional[Finding]:
    baseline_body = baseline_response.get("body") if isinstance(baseline_response, dict) else baseline_response
    cross_body = cross_user_response.get("body") if isinstance(cross_user_response, dict) else cross_user_response

    if not isinstance(baseline_body, dict) or not isinstance(cross_body, dict):
        return None

    cross_owner = cross_body.get("owner")
    if cross_owner and cross_owner != user_b_name:
        return _make_finding(
            endpoint=endpoint,
            finding_type=FindingType.BOLA,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            baseline_request=baseline_request,
            baseline_response=baseline_response,
            cross_user_request=cross_user_request,
            cross_user_response=cross_user_response,
            comparison_reason=(
                f"User {user_b_name} retrieved an object whose owner is {cross_owner}, "
                f"which differs from the requester."
            ),
            remediation="Enforce ownership checks on the object ID and reject cross-user access with 403 responses.",
        )
    return None


def detect_sensitive_field_exposure(
    endpoint: Endpoint,
    baseline_request: Dict[str, Any],
    baseline_response: Dict[str, Any],
    cross_user_request: Dict[str, Any],
    cross_user_response: Dict[str, Any],
) -> Optional[Finding]:
    sensitive_names = {"api_key", "billing_details", "internal_notes", "password_hash", "ssn", "secret"}

    def contains_sensitive_field(value: Any) -> bool:
        if isinstance(value, dict):
            for key, nested in value.items():
                if key.lower() in sensitive_names:
                    return True
                if contains_sensitive_field(nested):
                    return True
        elif isinstance(value, list):
            for item in value:
                if contains_sensitive_field(item):
                    return True
        return False

    cross_body = cross_user_response.get("body") if isinstance(cross_user_response, dict) else cross_user_response
    if not isinstance(cross_body, (dict, list)):
        return None

    if contains_sensitive_field(cross_body):
        return _make_finding(
            endpoint=endpoint,
            finding_type=FindingType.SENSITIVE_FIELD_EXPOSURE,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            baseline_request=baseline_request,
            baseline_response=baseline_response,
            cross_user_request=cross_user_request,
            cross_user_response=cross_user_response,
            comparison_reason="The cross-user response contains sensitive field names that should not be returned to an unrelated account.",
            remediation="Remove sensitive keys from the response payload and apply field-level authorization controls.",
        )
    return None
