from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

DB_PATH = Path(os.getenv("SANDBOX_DB_PATH", "sandbox.sqlite3"))
app = FastAPI(
    title="M1 → USDT Admin API",
    version="0.1.0-sandbox",
    description="Simulation only. No live provider, exchange, wallet or blockchain connection.",
)

TRON_ADDRESS_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            m1_balance TEXT NOT NULL,
            usdt_balance TEXT NOT NULL
        );
        INSERT OR IGNORE INTO state(id, m1_balance, usdt_balance)
        VALUES (1, '2500.00', '0.00');

        CREATE TABLE IF NOT EXISTS conversions (
            id TEXT PRIMARY KEY,
            amount TEXT NOT NULL,
            quoted_usdt TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS payouts (
            id TEXT PRIMARY KEY,
            total TEXT NOT NULL,
            status TEXT NOT NULL,
            recipients_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            occurred_at TEXT NOT NULL,
            action TEXT NOT NULL,
            object_id TEXT,
            details_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        );
        """)
        db.commit()


def audit(db: sqlite3.Connection, action: str, object_id: str | None, details: dict[str, Any]) -> None:
    prev = db.execute("SELECT event_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    previous_hash = prev["event_hash"] if prev else "GENESIS"
    occurred_at = now()
    event_id = str(uuid.uuid4())
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
    raw = "|".join([event_id, occurred_at, action, object_id or "", details_json, previous_hash])
    event_hash = hashlib.sha256(raw.encode()).hexdigest()
    db.execute(
        """INSERT INTO audit(event_id, occurred_at, action, object_id, details_json, previous_hash, event_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (event_id, occurred_at, action, object_id, details_json, previous_hash, event_hash),
    )


def dec(value: str | int | float) -> Decimal:
    try:
        result = Decimal(str(value))
    except InvalidOperation:
        raise HTTPException(400, "Invalid decimal amount")
    if not result.is_finite():
        raise HTTPException(400, "Amount must be finite")
    return result.quantize(Decimal("0.01"))


class DepositRequest(BaseModel):
    amount: Decimal = Field(gt=0, max_digits=14, decimal_places=2)


class ConversionRequest(BaseModel):
    amount: Decimal = Field(gt=0, max_digits=14, decimal_places=2)


class Recipient(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    wallet: str = Field(min_length=34, max_length=34)
    amount: Decimal = Field(gt=0, max_digits=14, decimal_places=2)
    percentage: Decimal = Field(gt=0, le=100, max_digits=6, decimal_places=2)

    @field_validator("wallet")
    @classmethod
    def check_tron_format(cls, value: str) -> str:
        if not TRON_ADDRESS_RE.fullmatch(value):
            raise ValueError("Wallet must have TRON mainnet address format (starts with T). Format check only; ownership/network validity is not verified.")
        return value


class PayoutRequest(BaseModel):
    recipients: list[Recipient] = Field(min_length=1, max_length=100)


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/")
def root():
    return {"service": "M1 → USDT Admin API", "mode": "SANDBOX_ONLY", "live_money_movement": False}


@app.get("/api/v1/dashboard")
def dashboard():
    with connect() as db:
        row = db.execute("SELECT m1_balance, usdt_balance FROM state WHERE id=1").fetchone()
        payout_total = db.execute(
            "SELECT COALESCE(SUM(CAST(total AS REAL)), 0) AS total FROM payouts WHERE status='SIMULATED_CONFIRMED'"
        ).fetchone()["total"]
        return {
            "mode": "SANDBOX_ONLY",
            "m1_balance": row["m1_balance"],
            "usdt_balance": row["usdt_balance"],
            "simulated_payouts_total": f"{payout_total:.2f}",
            "live_money_movement": False,
        }


@app.post("/api/v1/sandbox/deposits")
def simulated_deposit(request: DepositRequest):
    amount = dec(request.amount)
    with connect() as db:
        row = db.execute("SELECT m1_balance FROM state WHERE id=1").fetchone()
        new_balance = dec(row["m1_balance"]) + amount
        db.execute("UPDATE state SET m1_balance=? WHERE id=1", (str(new_balance),))
        audit(db, "SANDBOX_DEPOSIT_ADDED", None, {"amount": str(amount)})
        db.commit()
    return {"status": "SIMULATED", "amount": str(amount), "m1_balance": str(new_balance)}


@app.post("/api/v1/conversions/quote")
def conversion_quote(request: ConversionRequest):
    amount = dec(request.amount)
    with connect() as db:
        row = db.execute("SELECT m1_balance FROM state WHERE id=1").fetchone()
        if amount > dec(row["m1_balance"]):
            raise HTTPException(400, "Requested amount exceeds sandbox M1 balance")
    # Deliberately illustrative only. Production must obtain an actual provider quote.
    return {
        "mode": "SIMULATED_QUOTE",
        "amount_m1": str(amount),
        "illustrative_rate": "1.00",
        "estimated_usdt": str(amount),
        "fees": "0.00 (placeholder, not a real quote)",
        "warning": "Not an executable exchange quote.",
    }


@app.post("/api/v1/conversions/approve")
def approve_conversion(request: ConversionRequest):
    amount = dec(request.amount)
    conversion_id = str(uuid.uuid4())
    with connect() as db:
        row = db.execute("SELECT m1_balance, usdt_balance FROM state WHERE id=1").fetchone()
        m1_balance, usdt_balance = dec(row["m1_balance"]), dec(row["usdt_balance"])
        if amount > m1_balance:
            raise HTTPException(400, "Amount exceeds sandbox M1 balance")
        # Separate approval event is represented in the workflow. This endpoint is not
        # authenticated; never expose it outside localhost until real auth is implemented.
        new_m1, new_usdt = m1_balance - amount, usdt_balance + amount
        db.execute("UPDATE state SET m1_balance=?, usdt_balance=? WHERE id=1", (str(new_m1), str(new_usdt)))
        db.execute(
            "INSERT INTO conversions(id, amount, quoted_usdt, status, created_at) VALUES(?,?,?,?,?)",
            (conversion_id, str(amount), str(amount), "SIMULATED_APPROVED", now()),
        )
        audit(db, "SANDBOX_CONVERSION_APPROVED", conversion_id, {"amount_m1": str(amount), "usdt_added": str(amount)})
        db.commit()
    return {"conversion_id": conversion_id, "status": "SIMULATED_APPROVED", "usdt_added": str(amount)}


@app.post("/api/v1/payouts/draft")
def draft_payout(request: PayoutRequest):
    recipients = [r.model_dump(mode="json") for r in request.recipients]
    total = sum((dec(r["amount"]) for r in recipients), Decimal("0.00"))
    percentage = sum((Decimal(str(r["percentage"])) for r in recipients), Decimal("0.00"))
    with connect() as db:
        row = db.execute("SELECT usdt_balance FROM state WHERE id=1").fetchone()
        balance = dec(row["usdt_balance"])
        if total != balance:
            raise HTTPException(400, f"Recipient amounts must add up exactly to available sandbox USDT ({balance})")
        if percentage != Decimal("100.00"):
            raise HTTPException(400, "Recipient percentages must add up to exactly 100.00")
        payout_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO payouts(id, total, status, recipients_json, created_at) VALUES(?,?,?,?,?)",
            (payout_id, str(total), "AWAITING_SEPARATE_OWNER_APPROVAL", json.dumps(recipients), now()),
        )
        audit(db, "SANDBOX_PAYOUT_DRAFT_CREATED", payout_id, {"total": str(total), "recipient_count": len(recipients)})
        db.commit()
    return {"payout_id": payout_id, "status": "AWAITING_SEPARATE_OWNER_APPROVAL", "total_usdt": str(total), "recipients": recipients}


@app.post("/api/v1/payouts/{payout_id}/approve")
def approve_payout(payout_id: str):
    with connect() as db:
        payout = db.execute("SELECT * FROM payouts WHERE id=?", (payout_id,)).fetchone()
        if not payout:
            raise HTTPException(404, "Payout draft not found")
        if payout["status"] != "AWAITING_SEPARATE_OWNER_APPROVAL":
            raise HTTPException(409, "Payout is not awaiting approval")
        state = db.execute("SELECT usdt_balance FROM state WHERE id=1").fetchone()
        total = dec(payout["total"])
        if total > dec(state["usdt_balance"]):
            raise HTTPException(409, "Sandbox balance changed; create and review a fresh payout draft")
        db.execute("UPDATE state SET usdt_balance=? WHERE id=1", (str(dec(state["usdt_balance"]) - total),))
        db.execute("UPDATE payouts SET status='SIMULATED_CONFIRMED' WHERE id=?", (payout_id,))
        audit(db, "SANDBOX_PAYOUT_APPROVED", payout_id, {"total": str(total), "note": "No blockchain transaction was sent"})
        db.commit()
    return {
        "payout_id": payout_id,
        "status": "SIMULATED_CONFIRMED",
        "warning": "Simulation only. No TRON transaction was broadcast or confirmed.",
        "recipients": json.loads(payout["recipients_json"]),
    }


@app.get("/api/v1/audit")
def audit_events():
    with connect() as db:
        rows = db.execute("SELECT seq,event_id,occurred_at,action,object_id,details_json,previous_hash,event_hash FROM audit ORDER BY seq").fetchall()
        return [dict(r) for r in rows]
