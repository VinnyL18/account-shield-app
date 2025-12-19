"""
parser.py – Parse raw email messages into normalized IdentityGuard events.
Generic version that works for multiple providers (Yahoo, Google, etc.)
"""

import re
import email
from email.message import Message
from datetime import datetime, timezone
from typing import Dict, Any


# --- Apple detection helpers (ADD HERE) ---
APPLE_FROM_HINTS = (
    "apple.com",
    "id.apple.com",
    "appleid@id.apple.com",
    "no_reply@email.apple.com",
)

# === Microsoft / Outlook / Live detection helpers ===
MICROSOFT_FROM_HINTS = (
    "account.microsoft.com",
    "microsoft.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "login.microsoftonline.com",
    "microsoftonline.com",
    "no-reply@microsoft.com",
    "account-security-noreply@account.microsoft.com",
)



# Match either IPv4 (1.2.3.4) or IPv6 (2603:900b:...)
IP_REGEX = re.compile(
    r"\b((?:\d{1,3}(?:\.\d{1,3}){3})|(?:[0-9a-fA-F:]{8,}))\b",
    re.MULTILINE,
    )
# Map common email sender domains/fragments to a friendly service name
PROVIDER_MAP = [
    # Email providers
    ("yahoo.com",              "Yahoo Mail"),
    ("accounts.google.com",     "Google Account"),
    ("google.com",              "Google Account"),
    ("security-noreply@google.com", "Google Account"),
    ("no-reply@google.com",     "Google Account"),
    ("gmail.com",               "Google Account"),
    ("outlook.com",            "Microsoft Account"),
    ("live.com",               "Microsoft Account"),
    ("hotmail.com",            "Microsoft Account"),

    # Apple / iCloud
    ("appleid.apple.com",      "Apple ID"),
    ("id.apple.com",           "Apple ID"),
    ("icloud.com",             "Apple ID"),

    # Big commerce
    ("amazon.com",             "Amazon"),
    ("no-reply@amazon.com",    "Amazon"),
    ("account-update@amazon.com", "Amazon"),
    ("ebay.com",               "eBay"),
    ("walmart.com",            "Walmart"),
    ("target.com",             "Target"),

    # Payments
    ("paypal.com",             "PayPal"),
    ("cash.app",               "Cash App"),
    ("square.com",             "Cash App"),
    ("venmo.com",              "Venmo"),

    # Social networks
    ("facebookmail.com",       "Facebook"),
    ("facebook.com",           "Facebook"),
    ("instagram.com",          "Instagram"),
    ("twitter.com",            "X / Twitter"),
    ("x.com",                  "X / Twitter"),
    ("snapchat.com",           "Snapchat"),
    ("tiktok.com",             "TikTok"),
    ("discord.com",            "Discord"),

    # Gaming
    ("steampowered.com",       "Steam"),
    ("steamcommunity.com",     "Steam"),
    ("playstation.com",        "PlayStation Network"),
    ("sonyentertainmentnetwork.com", "PlayStation Network"),
    ("xbox.com",               "Xbox / Microsoft"),
    ("nintendo.com",           "Nintendo"),

    # Generic banks / financial (catch-all)
    ("bankofamerica.com",      "Bank of America"),
    ("chase.com",              "Chase"),
    ("wellsfargo.com",         "Wells Fargo"),
    ("capitalone.com",         "Capital One"),
]


def _get_text_body(msg: Message) -> str:
    """Extract a plain-text body from a possibly multipart message."""
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    parts.append(part.get_payload(decode=True).decode(errors="ignore"))
                except Exception:
                    continue
        return "\n".join(parts)
    else:
        try:
            return msg.get_payload(decode=True).decode(errors="ignore")
        except Exception:
            return ""


def _parse_date(msg: Message) -> str:
    """Normalize the Date header to UTC ISO8601."""
    raw_date = msg.get("Date")
    try:
        dt = email.utils.parsedate_to_datetime(raw_date)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        # Fallback to now
        return datetime.now(timezone.utc).isoformat()


def classify_event_generic(subject: str, body: str) -> str:
    """
    Classify an event based on simple keyword rules that work for many providers.
    Returns one of: "password_change", "2fa_disabled",
                    "suspicious_login", "new_device_login", "other".
    """
    text = (subject + "\n" + body).lower()

    # --- PASSWORD CHANGE / RESET ---
    password_change_keywords = [
        "password was changed",
        "password has been changed",
        "password reset",
        "reset your password",
        "we've reset your password",
        "your apple id password was reset",
        "apple id password was reset",
        "your apple id password has been reset",
        "your google account password was changed",
        "your microsoft account password was changed",
        "your instagram password was changed",
        "your facebook password was changed",
        "your amazon.com password has been changed",
        "your paypal password was changed",
    ]

    # --- 2FA / MFA DISABLED OR CHANGED ---
    twofa_disabled_keywords = [
        "2-step verification was turned off",
        "2-step verification has been turned off",
        "two-step verification was turned off",
        "two-step verification has been turned off",
        "2fa was disabled",
        "multi-factor authentication was disabled",
        "two-factor authentication was disabled",
        "security key was removed",
        "backup codes were removed",
    ]

    # --- NEW DEVICE / NEW SIGN-IN ---
    new_device_keywords = [
        "new device sign-in",
        "new sign-in on",
        "new login on",
        "new device was used to sign in",
        "signed in on a new device",
        "new iphone signed in",
        "new mac signed in",
        "new macbook signed in",
        "new windows pc signed in",
        "new sign-in from",
        "first time signing in from this device",
    ]

    # --- SUSPICIOUS / UNUSUAL LOGIN ---
    suspicious_login_keywords = [
        "suspicious sign-in attempt",
        "suspicious login attempt",
        "we detected an unusual sign-in",
        "unusual activity on your account",
        "someone may have accessed your account",
        "we blocked a sign-in attempt",
        "we prevented a login attempt",
        "sign-in attempt prevented",
        "wasn't you? secure your account",
    ]

    # FIRST: password change wins
    for kw in password_change_keywords:
        if kw in text:
            return "password_change"

    # THEN: 2FA disabled
    for kw in twofa_disabled_keywords:
        if kw in text:
            return "2fa_disabled"

    # THEN: suspicious login
    for kw in suspicious_login_keywords:
        if kw in text:
            return "suspicious_login"

    # THEN: new device / new login
    for kw in new_device_keywords:
        if kw in text:
            return "new_device_login"

    # Fallback
    return "other"


def score_risk(event_type: str) -> str:
    """Map event types to a simple risk level."""
    if event_type in ("password_change", "2fa_disabled", "suspicious_login"):
        return "high"
    if event_type in ("new_device_login", "2fa_enabled", "2fa_change"):
        return "medium"
    return "low"

def classify_apple_event(subject: str, body: str) -> str | None:
    s = subject.lower()
    b = body.lower()

    if "password" in s or "password" in b:
        return "password_change"

    if "two-factor" in s or "2fa" in b:
        return "2fa_change"

    if "sign in" in s and ("new device" in b or "new device" in s):
        return "new_device_login"

    if "apple id was used to sign in" in s:
        return "suspicious_login"

    return None


def classify_google_event(subject: str, snippet: str) -> str | None:
    s = f"{subject}\n{snippet}".lower()

    if "password" in s and "google" in s:
        return "password_change"

    if "2-step verification" in s and ("disabled" in s or "turned off" in s):
        return "2fa_disabled"

    if "new sign-in" in s or "new device" in s:
        return "new_device_login"

    if "suspicious" in s or "unusual activity" in s:
        return "suspicious_login"

    return None


def classify_microsoft_event(subject: str, body: str) -> str | None:
    s = (subject or "").lower()
    b = (body or "").lower()
    text = s + "\n" + b

    # Password change / reset
    if ("password" in text) and ("changed" in text or "reset" in text):
        return "password_change"

    # 2FA / security info changes
    if ("two-step" in text or "2-step" in text or "two factor" in text or "2fa" in text):
        if ("disabled" in text or "turned off" in text or "removed" in text):
            return "2fa_disabled"
        if ("enabled" in text or "turned on" in text or "added" in text):
            return "2fa_enabled"
        return "2fa_change"

    # New sign-in / new device
    if ("sign-in" in text or "sign in" in text or "unusual sign-in" in text or "unusual activity" in text):
        if ("new" in text or "device" in text or "location" in text or "ip" in text):
            return "new_device_login"
        return "suspicious_login"

    # Explicit suspicious wording
    if ("suspicious" in text or "unusual" in text or "don't recognize" in text or "was this you" in text):
        return "suspicious_login"

    return None


def classify_amazon_event(subject: str, body: str) -> str | None:
    s = (subject or "").lower()
    b = (body or "").lower()
    text = s + "\n" + b

    # Password change / reset
    if "password" in text and ("changed" in text or "reset" in text):
        return "password_change"

    # 2FA / OTP / verification code
    if ("verification code" in text) or ("one-time password" in text) or ("otp" in text):
        return "2fa_change"

    # New login / sign-in
    if ("sign-in" in text or "signed in" in text or "login" in text) and (
        "new" in text or "unrecognized" in text or "device" in text or "location" in text
    ):
        return "new_device_login"

    # “If this wasn’t you” / suspicious activity
    if ("suspicious" in text) or ("unusual activity" in text) or ("if this wasn't you" in text) or ("if this was not you" in text):
        return "suspicious_login"

    return None


def parse_security_email(provider: str, uid: str, msg: Message) -> Dict[str, Any]:
    """
    Given a raw email Message, try to parse it into a normalized event dict.
    Works generically across providers using keyword-based classification.
    """
    # Decode Subject safely
    dh = email.header.decode_header(msg.get("Subject", ""))
    subject_parts = []
    for part, enc in dh:
        if isinstance(part, bytes):
            subject_parts.append(part.decode(enc or "utf-8", errors="ignore"))
        else:
            subject_parts.append(part)
    subject = " ".join(subject_parts).strip()

    body = _get_text_body(msg)
    time_utc = _parse_date(msg)
    
    # Combine subject + body for keyword matching
    text_all = (subject + "\n" + body).lower()

        # Derive service name from From address when possible
    from_addr = msg.get("From", "").lower()

    service = "Unknown Service"
    for fragment, label in PROVIDER_MAP:
        if fragment in from_addr:
            service = label
            break
        print("[DEBUG] From:", msg.get("From"))
        print("[DEBUG] Matched service:", service)

    # Classify event + risk
    event_type = classify_event_generic(subject, body)
    risk_level = score_risk(event_type)

    # Extra password-change / reset detection using combined text
    if "password" in text_all and ("changed" in text_all or "reset" in text_all):
        event_type = "password_change"

        # Bump risk if the email sounds like "if this wasn't you..."
        if "if this wasn" in text_all or "if you did not request" in text_all:
            risk_level = "high"
        elif risk_level != "high":
            risk_level = "medium"

    # Try to find an IP address
    ip = None
    m = IP_REGEX.search(body)
    if m:
        ip = m.group(1)

    # Very rough location parsing (you can tune this)
    location = None
    loc_match = re.search(r"Location:\s*(.+)", body)
    if loc_match:
        location = loc_match.group(1).strip()

    # Device – rough pattern (these patterns are interview-friendly)
    device = None
    dev_match = re.search(r"sign[- ]in on (.+)", body, re.IGNORECASE)
    if dev_match:
        device = dev_match.group(1).strip()
    
    # Apple
    apple_event = None
    if provider == "Apple ID":
        apple_event = classify_apple_event(subject, body)
    
    if apple_event:
        event_type = apple_event
        risk_level = score_risk(apple_event)
   
    # Google  
    google_event = None
    if provider == "Google Account":
        google_event = classify_google_event(subject, body)
    
    if google_event:
        event_type = google_event
        risk_level = score_risk(google_event)
    
    # Microsoft
    ms_event = None 
    if provider in ("Microsoft Account", "Microsoft"):
        ms_event = classify_microsoft_event(subject, body)
    
    if ms_event:
        event_type = ms_event
        risk_level = score_risk(ms_event)
        

    # Amazon
    amazon_event = None
    if provider == "Amazon":
        amazon_event = classify_amazon_event(subject, body)

    if amazon_event:
        event_type = amazon_event
        risk_level = score_risk(amazon_event)

    
    event = {
        "provider": provider,
        "service": service,
        "event_type": event_type,
        "account_email": msg.get("To"),
        "ip": ip,
        "location": location,
        "device": device,
        "time_utc": time_utc,
        "risk_level": risk_level,
        "raw_subject": subject,
        "raw_snippet": body[:400],
        "message_uid": uid,
    }

    return event