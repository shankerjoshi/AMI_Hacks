# SentinelAPI - Zero-Trust API Vulnerability Scanner

A defensive scanner that tests only explicitly authorized local sandbox APIs for API authorization failures.

## Overview

SentinelAPI is a focused API security scanner designed to detect two high-value authorization failures:
1. **BOLA (Broken Object Level Authorization)** - Cross-user data access
2. **Sensitive Field Exposure** - Excessive data exposure in API responses

Built for AmiHacks 2026 - Track C, Problem Statement 3.

## Architecture

```
sentinelapi/
├── scanner/       # Python FastAPI backend for scanning
├── demo-api/      # Intentionally vulnerable demo API (FastAPI)
├── dashboard/     # React/Vite/Tailwind frontend
├── samples/       # Demo OpenAPI documents and safe example inputs
├── docker-compose.yml
└── README.md
```

## Quick Start

```bash
# Start all services
docker-compose up --build

# Services will be available at:
# - Dashboard: http://localhost:3000
# - Scanner API: http://localhost:8000
# - Demo API: http://localhost:8001
```

## Demo Flow

1. Open dashboard at http://localhost:3000
2. Upload the sample OpenAPI spec from `samples/`
3. Select the two demo identities (Alice and Bob)
4. Start the bounded scan
5. View BOLA and sensitive-field findings with evidence
6. Switch demo API to secure mode and rescan to verify fix

## Safety Controls

- **Target Authorization**: Explicit allowlist (default: local Docker hostname)
- **Request Safety**: GET-only core scan, concurrency 2, strict timeout, maximum request budget
- **Credential Handling**: Memory-only tokens, redaction in logs/UI/export
- **Network Scope**: Reject redirects to non-allowlisted hosts and dangerous URL schemes
- **Reliability**: Retry only idempotent requests, stop after repeated errors
- **Rate Checks**: Small bounded probe only

## Development

### Scanner (Python/FastAPI)
```bash
cd scanner
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Demo API (Python/FastAPI)
```bash
cd demo-api
pip install -r requirements.txt
uvicorn main:app --reload --port 8001
```

### Dashboard (React/Vite/Tailwind)
```bash
cd dashboard
npm install
npm run dev
```

## Detection Logic

### BOLA Differential Test
1. Identify safe candidate endpoints with object identifiers
2. Call endpoint as User A to obtain A's object
3. Replay request as User B with A's object identifier
4. Compare responses for unauthorized access
5. Store redacted evidence and reproducible request pair

### Sensitive-Field Exposure Test
1. Search configured field-name patterns (password_hash, api_key, ssn, etc.)
2. Compare baseline and cross-user responses
3. Inspect nested objects and error bodies
4. Report exact field path with redacted excerpt

## Severity Levels

- **Critical**: Confirmed unauthorized destructive action
- **High**: Confirmed cross-user access to sensitive data
- **Medium**: Confirmed low-sensitivity access or bounded control weakness
- **Info**: Suspicious behavior without enough evidence

## License

Educational use only - for authorized sandbox testing.