import os
import re
import time
import secrets
import hashlib
import threading
import urllib.request
import urllib.error
import json

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

app = FastAPI(title="Face Attendance OTP Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

OTP_TTL = 300
RESEND_COOLDOWN = 60
MAX_ATTEMPTS = 5

PURPOSES = {
    "super_admin_creation": "Super Admin Account Creation",
    "admin_creation": "Admin Account Creation",
}

lock = threading.Lock()
challenges = {}
last_sent = {}
failed_attempts = {}


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
        raise RuntimeError(
            "Missing BREVO_API_KEY or SENDER_EMAIL environment variable"
        )

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", sender):
        raise RuntimeError("SENDER_EMAIL is not a valid email address")

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
            "accept": "application/json",
            "content-type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            response_body = response.read().decode("utf-8")
            if response.status not in (200, 201, 202):
                raise RuntimeError(
                    f"Brevo returned HTTP {response.status}"
                )
            return json.loads(response_body) if response_body else {}

    except urllib.error.HTTPError as exc:
        # Log provider details for diagnosis, without logging API credentials.
        details = exc.read().decode("utf-8", errors="replace")
        print(f"Brevo API HTTP error: {exc.code}; response: {details[:1000]}")
        raise RuntimeError(
            f"Brevo rejected email request (HTTP {exc.code}). "
            "Check Render Logs for the provider response."
        ) from exc

    except urllib.error.URLError as exc:
        print(f"Brevo network error: {type(exc.reason).__name__}")
        raise RuntimeError(
            "Could not connect to the Brevo email service"
        ) from exc


@app.get("/")
def home():
    return {
        "status": "running",
        "service": "Face Attendance OTP",
    }


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/send-otp")
def send_otp(req: SendRequest):
    email = str(req.email).strip().lower()
    purpose = req.purpose.strip()

    if purpose not in PURPOSES:
        raise HTTPException(status_code=400, detail="Unsupported purpose")

    key = (email, purpose)
    now = time.time()

    with lock:
        previous = last_sent.get(key, 0)
        wait = RESEND_COOLDOWN - (now - previous)

        if wait > 0:
            raise HTTPException(
                status_code=429,
                detail=f"Wait {int(wait) + 1} seconds before requesting another OTP",
            )

        otp = f"{secrets.randbelow(1000000):06d}"

        challenges[key] = {
            "otp_hash": hashlib.sha256(otp.encode()).hexdigest(),
            "expires": now + OTP_TTL,
        }
        failed_attempts[key] = 0
        last_sent[key] = now

    try:
        send_email(
            recipient=email,
            subject="Face Attendance System - Verification OTP",
            body=(
                f"Your OTP for {PURPOSES[purpose]} is: {otp}\n\n"
                f"This OTP expires in {OTP_TTL // 60} minutes.\n"
                "Do not share this OTP with anyone."
            ),
        )

    except Exception as exc:
        print(f"OTP email delivery failed: {type(exc).__name__}: {exc}")

        with lock:
            challenges.pop(key, None)
            last_sent.pop(key, None)
            failed_attempts.pop(key, None)

        if isinstance(exc, RuntimeError):
            raise HTTPException(
                status_code=503,
                detail=str(exc),
            )

        raise HTTPException(
            status_code=503,
            detail="Email delivery failed. Check server logs.",
        )

    return {
        "ok": True,
        "message": "OTP sent successfully",
    }


@app.post("/verify-otp")
def verify_otp(req: VerifyRequest):
    email = str(req.email).strip().lower()
    purpose = req.purpose.strip()
    otp = req.otp.strip()

    if purpose not in PURPOSES:
        raise HTTPException(status_code=400, detail="Unsupported purpose")

    if not re.fullmatch(r"\d{6}", otp):
        raise HTTPException(
            status_code=400,
            detail="OTP must contain exactly 6 digits",
        )

    key = (email, purpose)
    now = time.time()

    with lock:
        challenge = challenges.get(key)

        if not challenge:
            raise HTTPException(
                status_code=400,
                detail="No active OTP. Request a new OTP.",
            )

        if now > challenge["expires"]:
            challenges.pop(key, None)
            failed_attempts.pop(key, None)
            raise HTTPException(
                status_code=400,
                detail="OTP expired. Request a new OTP.",
            )

        attempts = failed_attempts.get(key, 0)

        if attempts >= MAX_ATTEMPTS:
            challenges.pop(key, None)
            failed_attempts.pop(key, None)
            raise HTTPException(
                status_code=429,
                detail="Too many attempts. Request a new OTP.",
            )

        supplied_hash = hashlib.sha256(otp.encode()).hexdigest()

        if not secrets.compare_digest(
            supplied_hash, challenge["otp_hash"]
        ):
            failed_attempts[key] = attempts + 1
            raise HTTPException(
                status_code=400,
                detail="Incorrect OTP",
            )

        challenges.pop(key, None)
        failed_attempts.pop(key, None)
        last_sent.pop(key, None)

    return {
        "ok": True,
        "message": "Email verified successfully",
    }
