import json

from parser import OpenAPIParser
from schemas import ScanRequest, AuthProfile


def test_parse_and_discover_endpoints():
    spec = '''
    openapi: 3.0.0
    info:
      title: Demo API
      version: '1.0'
    paths:
      /orders/{id}:
        get:
          operationId: getOrder
          parameters:
            - in: path
              name: id
              required: true
              schema:
                type: string
      /profile/{userId}:
        get:
          operationId: getProfile
          parameters:
            - in: path
              name: userId
              required: true
              schema:
                type: string
    '''
    parser = OpenAPIParser()
    parser.parse_spec(spec, spec_format="yaml")
    endpoints = parser.discover_endpoints()
    assert len(endpoints) >= 2
    assert any(e.path == "/orders/{id}" for e in endpoints)
    assert any("id" in e.candidate_identifiers for e in endpoints)


def test_scan_request_redaction_and_allowlist():
    req = ScanRequest(
        spec_source="sample.yaml",
        base_url="http://demo-api:8001",
        allowlist=["demo-api"],
        auth_profiles=[
            AuthProfile(name="alice", token="alice-token", prefix="Bearer"),
            AuthProfile(name="bob", token="bob-token", prefix="Bearer"),
        ],
    )
    assert req.auth_profiles[0].token == "alice-token"
    assert req.allowlist == ["demo-api"]


def test_invalid_spec_raises_error():
    parser = OpenAPIParser()
    try:
        parser.parse_spec("not valid: [", spec_format="yaml")
    except ValueError:
        return
    raise AssertionError("Expected ValueError for invalid YAML")
