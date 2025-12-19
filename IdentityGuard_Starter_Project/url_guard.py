"""
url_guard.py – simple URL extraction and risk scoring for IdentityGuard.

This scans the recent events in the database, pulls out any URLs found in
the subject/body snippets, and assigns a simple risk level based on
heuristics (TLD, length, hyphens, etc.).

This is a "BrandGuard-lite" module.
"""

import re
from textwrap import shorten
from urllib.parse import urlparse
from typing import List, Tuple
import sqlite3


# Simple URL regex to find http(s) links
URL_REGEX = re.compile(r"https?://[^\s)>\]]+", re.IGNORECASE)

# Brand profiles — REAL official domains
BRAND_PROFILES = {
    "pandora": {"official_domains": ["pandora.net"]},
    "apple": {"official_domains": ["apple.com", "icloud.com"]},
    "walmart": {"official_domains": ["walmart.com"]},
    "m1": {"official_domains": ["m1.com"]},
}


def extract_domain(url: str) -> str:
    """Normalize domain: remove www and ports."""
    parsed = urlparse(url)
    host = parsed.netloc.split("@")[-1]
    host = host.split(":")[0]  # strip port
    if host.startswith("www."):
        host = host[4:]
    return host.lower()


def assess_url_risk(url: str):
    """
    Assign a risk score to a URL:
      - brand impersonation
      - long/weird domains
      - risky TLDs
      - too many digits/hyphens
    """
    domain = extract_domain(url)
    reasons = []
    score = 0

    # Very long domain
    if len(domain) > 30:
        score += 15
        reasons.append("very long domain name")

    # Many hyphens
    if domain.count("-") >= 3:
        score += 10
        reasons.append("many hyphens in domain")

    # Many digits
    if sum(c.isdigit() for c in domain) >= 6:
        score += 10
        reasons.append("lots of digits in domain")

    # Suspicious TLDs
    risky_tlds = {"xyz", "top", "click", "kim", "gq", "party", "loan", "buzz", "shop"}
    tld = domain.rsplit(".", 1)[-1]
    if tld in risky_tlds:
        score += 20
        reasons.append(f"risky TLD .{tld}")

    # BRAND IMPERSONATION
    brand_hit = None
    for brand, profile in BRAND_PROFILES.items():
        if brand in domain:
            brand_hit = brand
            if domain not in profile["official_domains"]:
                score += 40
                reasons.append(f"brand mismatch for {brand}")
            break

    # Map score → risk label
    if score >= 40:
        risk = "HIGH"
    elif score >= 20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return risk, reasons, domain, brand_hit


def extract_urls(text: str) -> List[str]:
    """Return a list of URLs found in the given text."""
    if not text:
        return []
    return URL_REGEX.findall(text)


def score_url(url: str) -> Tuple[str, List[str]]:
    """
    Score a URL as low/medium/high based on simple heuristics.
    Returns (risk_level, reasons).
    """
    reasons = []
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
    except Exception:
        return "high", ["malformed URL"]

    # Remove common prefixes
    host_clean = host
    for prefix in ("www.",):
        if host_clean.startswith(prefix):
            host_clean = host_clean[len(prefix) :]

    # TLD-based checks
    tld = ""
    if "." in host_clean:
        tld = "." + host_clean.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"suspicious TLD {tld}")

    # Length / structure checks
    if len(host_clean) > 30:
        reasons.append("very long domain name")
    if host_clean.count("-") >= 3:
        reasons.append("many hyphens in domain")
    if sum(c.isdigit() for c in host_clean) >= 5:
        reasons.append("lots of digits in domain")

    # Path-based checks
    path = parsed.path or ""
    if len(path) > 40:
        reasons.append("very long URL path")

    # Overall score
    score = 0
    for r in reasons:
        if "TLD" in r:
            score += 2
        else:
            score += 1

    if score >= 3:
        level = "high"
    elif score >= 1:
        level = "medium"
    else:
        level = "low"

    return level, reasons

def analyze_urls_for_recent_events(conn, limit_events: int = 20):
    """
    Scan URLs in the last N email events.
    Detect brand impersonation, risky domains, + general heuristics.
    """
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, time_utc, raw_subject, raw_snippet
        FROM events
        ORDER BY time_utc DESC
        LIMIT ?
        """,
        (limit_events,),
    )
    rows = cur.fetchall()

    print(f"\n=== URL Scan for Last {limit_events} Events ===")
    print(
        f"{'EVT':>4}  {'RISK':6}  {'TIME (UTC)':19}  "
        f"{'DOMAIN':25}  {'BRAND':10}  URL"
    )
    print("-" * 120)

    seen = set()

    for ev_id, time_utc, raw_subject, raw_snippet in rows:
        text = (raw_subject or "") + "\n" + (raw_snippet or "")
        urls = URL_REGEX.findall(text)

        for url in urls:
            key = (ev_id, url)
            if key in seen:
                continue
            seen.add(key)

            risk, reasons, domain, brand = assess_url_risk(url)
            brand_label = brand or "-"

            print(
                f"{ev_id:>4}  {risk:6}  {(time_utc or '')[:19]:19}  "
                f"{domain[:25]:25}  {brand_label[:10]:10}  {url}"
            )
            if reasons:
                print(" " * 8 + "reasons: " + "; ".join(reasons))

    print()
