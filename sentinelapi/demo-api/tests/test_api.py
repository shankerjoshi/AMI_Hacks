import pytest
from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_health_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_vulnerable_order_access_for_bob():
    headers = {"Authorization": "Bearer bob-token"}
    res = client.get("/orders/1001", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["owner"] == "alice"
    assert data["order_id"] == 1001


def test_secure_mode_blocks_cross_user_access():
    res = client.post("/toggle-mode", json={"mode": "secure"})
    assert res.status_code == 200

    headers = {"Authorization": "Bearer bob-token"}
    res = client.get("/orders/1001", headers=headers)
    assert res.status_code == 403

    res = client.post("/toggle-mode", json={"mode": "vulnerable"})
    assert res.status_code == 200


def test_profile_endpoint_exposes_sensitive_fields():
    res = client.get("/profile/2001", headers={"Authorization": "Bearer bob-token"})
    assert res.status_code == 200
    body = res.json()
    assert "api_key" in body
    assert "billing_details" in body
