from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import smtplib
import sqlite3
import time
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response, Depends
from pydantic import BaseModel, EmailStr, Field

DB = Path(os.getenv("AUTH_DB_PATH", "admin_auth.sqlite3"))
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "jaggacomrade@yahoo.com").strip().lower()
BOOTSTRAP_SECRET = os.getenv("BOOTSTRAP_SECRET", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
COOKIE = "m1_admin_session"
OTP_TTL = 600
SESSION_TTL = 8 * 60 * 60
MAX_FAILURES = 5
LOCK_SECONDS = 15 * 60

app = FastAPI(title="M1 Admin Authentication", version="0.2.0-sandbox",
              description="Single-admin auth foundation. No live financial operations.")

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS admin (
          id INTEGER PRIMARY KEY CHECK(id=1), email TEXT NOT NULL,
          pin_salt TEXT NOT NULL, pin_hash TEXT NOT NULL, created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS challenges (
          id INTEGER PRIMARY KEY CHECK(id=1), code_hash TEXT NOT NULL,
          expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS throttle (
          id INTEGER PRIMARY KEY CHECK(id=1), failures INTEGER NOT NULL DEFAULT 0,
          locked_until INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO throttle(id, failures, locked_until) VALUES(1,0,0);
        """)
init()

def configured():
    if len(SESSION_SECRET.encode()) < 32:
        raise HTTPException(503, "Authentication is not configured: SESSION_SECRET must be at least 32 bytes.")
    if not BOOTSTRAP_SECRET:
        raise HTTPException(503, "Authentication is not configured: BOOTSTRAP_SECRET is missing.")

def pin_hash(pin: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 310_000).hex()

def send_code(code: str):
    required = ["SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM"]
    if any(not os.getenv(k) for k in required):
        raise HTTPException(503, "Email delivery is not configured; verification cannot be completed.")
    msg = EmailMessage()
    msg["Subject"] = "Your administrator sign-in code"
    msg["From"] = os.environ["SMTP_FROM"]
    msg["To"] = ADMIN_EMAIL
    msg.set_content(f"Your one-time administrator sign-in code is {code}. It expires in 10 minutes. Do not share it.")
    try:
        with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.getenv("SMTP_PORT", "587")), timeout=15) as s:
            s.starttls()
            s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
            s.send_message(msg)
    except Exception:
        raise HTTPException(502, "Could not send the verification email. No session was created.")

def token_issue() -> str:
    payload = f"{int(time.time()) + SESSION_TTL}:{secrets.token_urlsafe(24)}"
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig

def token_valid(token: Optional[str]) -> bool:
    if not token or "." not in token or len(SESSION_SECRET.encode()) < 32:
        return False
    payload, sig = token.rsplit(".", 1)
    expected = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    try:
        expiry = int(payload.split(":", 1)[0])
    except Exception:
        return False
    return hmac.compare_digest(sig, expected) and expiry > int(time.time())

def require_admin(request: Request):
    if not token_valid(request.cookies.get(COOKIE)):
        raise HTTPException(401, "Administrator session required.")
    return True

class Enroll(BaseModel):
    email: str
    pin: str = Field(pattern=r"^\d{6}$")

class Login(BaseModel):
    email: str
    pin: str = Field(pattern=r"^\d{6}$")

class Verify(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")

@app.get("/")
def root():
    return {"service":"M1 Admin Authentication", "mode":"SANDBOX_ONLY", "live_money_movement":False}

@app.post("/auth/enroll")
def enroll(body: Enroll, x_bootstrap_secret: str = Header(default="")):
    configured()
    if not hmac.compare_digest(x_bootstrap_secret, BOOTSTRAP_SECRET):
        raise HTTPException(403, "Invalid enrollment authorization.")
    if body.email.strip().lower() != ADMIN_EMAIL:
        raise HTTPException(400, "Email does not match the configured sole administrator.")
    salt = secrets.token_bytes(16)
    with db() as c:
        if c.execute("SELECT 1 FROM admin WHERE id=1").fetchone():
            raise HTTPException(409, "Administrator is already enrolled. Use account recovery; enrollment is closed.")
        c.execute("INSERT INTO admin(id,email,pin_salt,pin_hash,created_at) VALUES(1,?,?,?,?)",
                  (ADMIN_EMAIL, salt.hex(), pin_hash(body.pin, salt), int(time.time())))
    return {"status":"ENROLLED", "email":ADMIN_EMAIL, "note":"PIN stored as a salted PBKDF2 hash. Configure email delivery before login."}

@app.post("/auth/login")
def login(body: Login):
    configured()
    with db() as c:
        throttle = c.execute("SELECT failures,locked_until FROM throttle WHERE id=1").fetchone()
        now = int(time.time())
        if throttle["locked_until"] > now:
            raise HTTPException(429, "Login temporarily locked. Try again later.")
        admin = c.execute("SELECT * FROM admin WHERE id=1").fetchone()
        valid = bool(admin and body.email.strip().lower() == admin["email"])
        if valid:
            valid = hmac.compare_digest(pin_hash(body.pin, bytes.fromhex(admin["pin_salt"])), admin["pin_hash"])
        if not valid:
            failures = throttle["failures"] + 1
            locked = now + LOCK_SECONDS if failures >= MAX_FAILURES else 0
            c.execute("UPDATE throttle SET failures=?,locked_until=? WHERE id=1", (0 if locked else failures, locked))
            raise HTTPException(401, "Invalid administrator credentials.")
        c.execute("UPDATE throttle SET failures=0,locked_until=0 WHERE id=1")
        code = f"{secrets.randbelow(1_000_000):06d}"
        digest = hashlib.sha256(code.encode()).hexdigest()
        c.execute("INSERT OR REPLACE INTO challenges(id,code_hash,expires_at,attempts) VALUES(1,?,?,0)",
                  (digest, now + OTP_TTL))
    send_code(code)
    return {"status":"SECOND_FACTOR_REQUIRED", "destination":"configured administrator email", "expires_in_seconds":OTP_TTL}

@app.post("/auth/verify")
def verify(body: Verify, response: Response):
    configured()
    with db() as c:
        ch = c.execute("SELECT * FROM challenges WHERE id=1").fetchone()
        if not ch or ch["expires_at"] < int(time.time()) or ch["attempts"] >= 5:
            raise HTTPException(401, "Verification code expired or unavailable. Sign in again.")
        digest = hashlib.sha256(body.code.encode()).hexdigest()
        if not hmac.compare_digest(digest, ch["code_hash"]):
            c.execute("UPDATE challenges SET attempts=attempts+1 WHERE id=1")
            raise HTTPException(401, "Incorrect verification code.")
        c.execute("DELETE FROM challenges WHERE id=1")
    response.set_cookie(COOKIE, token_issue(), httponly=True, secure=os.getenv("COOKIE_SECURE","1") == "1",
                        samesite="strict", max_age=SESSION_TTL, path="/")
    return {"status":"AUTHENTICATED", "session_expires_in_seconds":SESSION_TTL, "mode":"SANDBOX_ONLY"}

@app.get("/auth/me")
def me(_: bool = Depends(require_admin)):
    return {"authenticated":True, "email":ADMIN_EMAIL, "role":"SOLE_ADMIN", "mode":"SANDBOX_ONLY"}

@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE, path="/", httponly=True, secure=os.getenv("COOKIE_SECURE","1") == "1", samesite="strict")
    return {"status":"SIGNED_OUT"}
