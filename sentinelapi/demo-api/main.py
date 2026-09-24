from __future__ import annotations

from typing import Any, Dict, Literal

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="SentinelAPI Demo API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODE: Literal["vulnerable", "secure"] = "vulnerable"


class ModeRequest(BaseModel):
    mode: Literal["vulnerable", "secure"]


USERS = {
    "alice": {
        "id": "alice",
        "user_id": 2001,
        "name": "Alice",
        "token": "alice-token",
        "profile": {
            "user_id": 2001,
            "full_name": "Alice Example",
            "email": "alice@example.com",
            "role": "admin",
            "api_key": "alice-demo-key",
            "billing_details": {"card_last4": "4242", "currency": "USD"},
            "internal_notes": "Internal: alice is a team admin",
        },
    },
    "bob": {
        "id": "bob",
        "user_id": 2002,
        "name": "Bob",
        "token": "bob-token",
        "profile": {
            "user_id": 2002,
            "full_name": "Bob Example",
            "email": "bob@example.com",
            "role": "user",
            "api_key": "bob-demo-key",
            "billing_details": {"card_last4": "7777", "currency": "USD"},
            "internal_notes": "Internal: bob is a normal user",
        },
    },
}

ORDERS = {
    1001: {
        "order_id": 1001,
        "owner": "alice",
        "amount": 42.5,
        "currency": "USD",
        "status": "shipped",
        "items": ["keyboard", "mouse"],
        "shipping_address": "1 Alice Lane",
        "customer_email": "alice@example.com",
    },
    1002: {
        "order_id": 1002,
        "owner": "bob",
        "amount": 10.0,
        "currency": "USD",
        "status": "pending",
        "items": ["notebook"],
        "shipping_address": "2 Bob St",
        "customer_email": "bob@example.com",
    },
}


def get_current_user(auth_header: str | None) -> Dict[str, Any]:
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")

    token = auth_header.split(" ", 1)[1].strip()
    for user in USERS.values():
        if user["token"] == token:
            return user
    raise HTTPException(status_code=401, detail="Unknown token")


@app.get("/health")
def health():
    return {"status": "ok", "mode": MODE, "users": ["alice", "bob"]}


@app.post("/reset")
def reset():
    global MODE
    MODE = "vulnerable"
    return {"status": "reset", "mode": MODE}


@app.post("/toggle-mode")
def toggle_mode(payload: ModeRequest):
    global MODE
    MODE = payload.mode
    return {"status": "ok", "mode": MODE}


@app.get("/me")
def me(authorization: str | None = Header(default=None, alias="Authorization")):
    user = get_current_user(authorization)
    return {
        "user_id": user["user_id"],
        "name": user["name"],
        "role": user["profile"]["role"],
        "token": "[REDACTED]",
    }


@app.get("/orders/{order_id}")
def get_order(order_id: int, authorization: str | None = Header(default=None, alias="Authorization")):
    user = get_current_user(authorization)
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if MODE == "secure" and order["owner"] != user["id"]:
        raise HTTPException(status_code=403, detail="You do not have access to this order")

    return {
        "order_id": order["order_id"],
        "owner": order["owner"],
        "customer_email": order["customer_email"],
        "amount": order["amount"],
        "currency": order["currency"],
        "status": order["status"],
    }


@app.get("/profile/{user_id}")
def get_profile(user_id: int, authorization: str | None = Header(default=None, alias="Authorization")):
    user = get_current_user(authorization)
    profile = None
    for candidate in USERS.values():
        if candidate["user_id"] == user_id:
            profile = candidate["profile"]
            break

    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    if MODE == "secure" and user["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="You do not have access to this profile")

    data = {
        "user_id": user_id,
        "full_name": profile["full_name"],
        "email": profile["email"],
        "role": profile["role"],
    }

    if MODE == "vulnerable":
        data.update(
            {
                "api_key": profile["api_key"],
                "billing_details": profile["billing_details"],
                "internal_notes": profile["internal_notes"],
            }
        )

    return data


@app.get("/openapi.json")
def openapi_schema():
    return app.openapi()
