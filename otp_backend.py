import os
import time
import secrets
import json
import threading
import urllib.request
import urllib.error

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

app = FastAPI(title="Face Attendance OTP Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

lock = threading.Lock()
challenges = {}
last_sent = {}
failed_attempts = {}

TTL = 300
RESEND = 60
MAX_ATTEMPTS = 5

PURPOSES = {
    "super_admin_creation": "Super Admin Account Creation",
    "admin_creation": "Admin Account Creation",
}


class SendRequest(BaseModel):
    email: EmailStr
    purpose: str


class VerifyRequest(BaseModel):
    email: EmailStr
    purpose: str
    otp: str


def send_email(recipient, subject, body):
    api_key = os.getenv("BREVO_API_KEY", "").strip()
    sender = os.getenv("SENDER_EMAIL", "").strip()

    if not api_key or not sender:
        raise RuntimeError("Email API is not configured")

    payload = {
        "sender": {
            "name": "Face Attendance System",
            "email": sender,
        },
        "to": [{"email": recipient}],
        "subject": subject,
        "textContent": body,
    }

    request = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "api-key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status not in (200, 201, 202):
                raise RuntimeError("Email delivery request failed")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"Email provider rejected request: HTTP {exc.code}"
        ) from exc


@app.get("/")
def home():
    return {"status": "running", "service": "Face Attendance OTP"}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/send-otp")
def send_otp(req: SendRequest):
    email = str(req.email).lower().strip()
    purpose = req.purpose.strip()

    if purpose not in PURPOSES:
        raise HTTPException(400, "Unsupported purpose")

    key = (email, purpose)
    now = time.time()

    with lock:
        if now - last_sent.get(key, 0) < RESEND:
            raise HTTPException(
                429, "Wait 60 seconds before requesting another OTP"
            )

        otp = f"{secrets.randbelow(1000000):06d}"
        challenges[key] = {
            "otp": otp,
            "expires": now + TTL,
        }
        failed_attempts[key] = 0
        last_sent[key] = now

    try:
        send_email(
            email,
            "Face Attendance System - Verification OTP",
            f"Your OTP for {PURPOSES[purpose]} is {otp}.\n"
            "It expires in 5 minutes. Do not share this code.",
        )
    except Exception as exc:
        with lock:
            challenges.pop(key, None)
            last_sent.pop(key, None)

        raise HTTPException(
            503, f"Could not send email: {type(exc).__name__}"
        )

    return {"ok": True, "message": "OTP sent successfully"}


@app.post("/verify-otp")
def verify_otp(req: VerifyRequest):
    email = str(req.email).lower().strip()
    purpose = req.purpose.strip()
    key = (email, purpose)

    if purpose not in PURPOSES:
        raise HTTPException(400, "Unsupported purpose")

    with lock:
        challenge = challenges.get(key)

        if not challenge or time.time() > challenge["expires"]:
            challenges.pop(key, None)
            raise HTTPException(400, "OTP expired. Request a new OTP.")

        if failed_attempts.get(key, 0) >= MAX_ATTEMPTS:
            challenges.pop(key, None)
            raise HTTPException(429, "Too many attempts. Request a new OTP.")

        if not secrets.compare_digest(str(req.otp), challenge["otp"]):
            failed_attempts[key] = failed_attempts.get(key, 0) + 1
            raise HTTPException(400, "Incorrect OTP")

        challenges.pop(key, None)
        failed_attempts.pop(key, None)

    return {"ok": True, "message": "Email verified successfully"}
