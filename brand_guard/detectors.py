import re
from .url_tools import extract_domain, normalize_url

# Common scam / phishing TLDs (not always bad, but higher risk)
SUSPICIOUS_TLDS = {
    "xyz", "top", "shop", "online", "zip", "click", "icu", "live", "site"
}

# Words commonly used in fake or phishing URLs
SUSPICIOUS_WORDS = {
    "login", "verify", "secure", "update", "confirm",
    "free", "gift", "promo", "deal", "outlet", "sale"
}

# ==========================================================
# BrandGuard – Known Brands & Official Domains
# ==========================================================

OFFICIAL_BRANDS = {

    # --- Shopping / Retail ---
    "amazon": {
        "amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de",
        "amazon.fr", "amazon.it", "amazon.es"
    },
    "walmart": {"walmart.com"},
    "target": {"target.com"},
    "bestbuy": {"bestbuy.com"},
    "ebay": {"ebay.com"},
    "etsy": {"etsy.com"},
    "homedepot": {"homedepot.com"},
    "lowes": {"lowes.com"},
    "costco": {"costco.com"},
    "ikea": {"ikea.com"},
    "wayfair": {"wayfair.com"},
    "newegg": {"newegg.com"},
    "shein": {"shein.com"},
    "temu": {"temu.com"},

    # --- Payments / Banking ---
    "paypal": {"paypal.com"},
    "venmo": {"venmo.com"},
    "cashapp": {"cash.app"},
    "zelle": {"zellepay.com"},
    "chime": {"chime.com"},
    "bankofamerica": {"bankofamerica.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "capitalone": {"capitalone.com"},
    "discover": {"discover.com"},
    "citibank": {"citi.com", "citibank.com"},
    "usbank": {"usbank.com"},
    "pnc": {"pnc.com"},
    "tdbank": {"td.com"},
    "ally": {"ally.com"},
    "sofi": {"sofi.com"},
    "robinhood": {"robinhood.com"},
    "crypto": {"crypto.com"},
    "navyfed": {"navyfederal.org"},
    "amex": {"americanexpress.com"},
    "visa": {"visa.com"},
    "mastercard": {"mastercard.com"},
    "affirm": {"affirm.com"},
    "klarna": {"klarna.com"},
    "afterpay": {"afterpay.com"},

    # --- Apple / Google / Microsoft ---
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "accounts.google.com", "gmail.com"},
    "microsoft": {
        "microsoft.com", "live.com", "outlook.com",
        "office.com", "login.microsoftonline.com"
    },

    # --- Social Media ---
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "twitter":  {"twitter.com", "x.com"},
    "tiktok": {"tiktok.com"},
    "snapchat": {"snapchat.com"},
    "linkedin": {"linkedin.com"},

    # --- Communication / Gaming ---
    "discord": {"discord.com"},
    "telegram": {"telegram.org"},
    "whatsapp": {"whatsapp.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "epicgames": {"epicgames.com"},
    "playstation": {"playstation.com"},
    "xbox": {"xbox.com"},
    "riotgames": {"riotgames.com"},
    "blizzard": {"blizzard.com"},
    "ea": {"ea.com"},
    "roblox": {"roblox.com"},
    "minecraft": {"minecraft"},
    "riot": {"riotgames.com"},

    # --- Delivery / Services ---
    "netflix": {"netflix.com"},
    "spotify": {"spotify.com"},
    "doordash": {"doordash.com"},
    "ubereats": {"ubereats.com"},
    "uber": {"uber.com"},
    "lyft": {"lyft.com"},
    "usps": {"usps.com"},
    "ups": {"ups.com"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com"},

    # --- Crypto / Finance (high-risk targets) ---
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "kraken": {"kraken.com"},
    "metamask": {"metamask.io"},
   
    # --- Email Providers ---
    "yahoo": {"yahoo.com"},
    "proton": {"proton.me", "protonmail.com"},
    "icloud": {"icloud.com"},
    "zoho": {"zoho.com"},
   
    # --- Mobile Providers ---
    "verizon": {"verizon.com"},
    "att": {"att.com"},
    "tmobile": {"t-mobile.com", "tmobile.com"},
    "xfinity": {"xfinity.com"},
    "spectrum": {"spectrum.com"},
   
    # --- Government/Public Services ---
    "irs": {"irs.gov"},
    "ssa": {"ssa.gov"},
    "dmv": {"dmv.org"},
    "medicare": {"medicare.gov"},
    
    # --- Streaming Subscriptions ---
    "hulu": {"hulu.com"},
    "disneyplus": {"disneyplus.com"},
    "hbo": {"hbomax.com"},
    "paramount": {"paramountplus.com"},
    
    # --- Cloud/Developer Platforms ---
    "github": {"github.com"},
    "gitlab": {"gitlab.com"},
    "aws": {"amazonaws.com"},
    "azure": {"azure.microsoft.com"},
    "cloudfare": {"cloudfare.com"},
}

# --- Phishing / brand spoof signals ---

PHISH_KEYWORDS = {
    "login", "signin", "sign-in",
    "verify", "verification",
    "secure", "security",
    "update", "confirm",
    "account", "support",
    "alert", "suspended", "suspension",
    "password", "reset",
}

HIGH_RISK_TLDS = {
    "zip", "mov", "top", "xyz", "icu", "click", "link", "live", "lol",
    "tk", "ml", "ga", "cf", "gq",
    "ru", "cn",
}

LOOKALIKE_MAP = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
})

def _sld(domain: str) -> str:
    # "paypal-login-alert.com" -> "paypal-login-alert"
    parts = domain.split(".")
    return parts[0] if parts else ""

def _normalize_label(label: str) -> str:
    # remove common tricks and normalize lookalike chars
    label = (label or "").lower()
    label = label.translate(LOOKALIKE_MAP)
    label = label.replace("-", "")
    return label

def _levenshtein(a: str, b: str) -> int:
    # small, dependency-free edit distance
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            ins = cur[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            cur.append(min(ins, dele, sub))
        prev = cur
    return prev[-1]

def _is_typosquat(domain: str) -> bool:
    """
    Detect close misspellings of *official* domains (typosquatting),
    e.g. paypaI.com, arnazon.com, micros0ft.com
    """
    d_label = _normalize_label(_sld(domain))

    for brand, official_domains in OFFICIAL_BRANDS.items():
        for off in official_domains:
            off_label = _normalize_label(_sld(off))
            if not off_label:
                continue

            dist = _levenshtein(d_label, off_label)
            # allow small distance thresholds; longer labels can tolerate 2
            if (len(off_label) <= 6 and dist == 1) or (len(off_label) > 6 and dist <= 2):
                # avoid matching the exact official domain label (dist=0 handled)
                if dist != 0:
                    return True
    return False

# ==========================================================
# Keywords used to detect brand impersonation
# (even when domain is NOT official)
# ==========================================================

BRAND_KEYWORDS = {
    "amazon": ["amazon", "prime"],
    "walmart": ["walmart"],
    "target": ["target"],
    "bestbuy": ["bestbuy"],
    "ebay": ["ebay"],
    "etsy": ["etsy"],

    "paypal": ["paypal"],
    "venmo": ["venmo"],
    "cashapp": ["cashapp", "cash-app"],
    "zelle": ["zelle"],
    "chime": ["chime"],
    "bankofamerica": ["bankofamerica", "boa"],
    "chase": ["chase"],
    "wellsfargo": ["wellsfargo"],
    "capitalone": ["capitalone"],
    "discover": ["discover"],

    "apple": ["apple", "icloud", "appleid"],
    "google": ["google", "gmail", "accounts.google"],
    "microsoft": ["microsoft", "outlook", "office", "onedrive"],

    "facebook": ["facebook", "fb"],
    "instagram": ["instagram"],
    "x": ["twitter", "x.com"],
    "tiktok": ["tiktok"],
    "snapchat": ["snapchat"],
    "linkedin": ["linkedin"],

    "discord": ["discord"],
    "telegram": ["telegram"],
    "whatsapp": ["whatsapp"],
    "steam": ["steam"],
    "epicgames": ["epic"],
    "playstation": ["playstation", "psn"],
    "xbox": ["xbox"],

    "netflix": ["netflix"],
    "spotify": ["spotify"],
    "doordash": ["doordash"],
    "ubereats": ["ubereats"],
    "uber": ["uber"],
    "lyft": ["lyft"],

    "coinbase": ["coinbase"],
    "binance": ["binance"],
    "kraken": ["kraken"],
    "metamask": ["metamask"],
}

def tld_of(domain: str) -> str:
    parts = domain.split(".")
    return parts[-1] if len(parts) >= 2 else ""

def has_punycode(domain: str) -> bool:
    return "xn--" in domain

def has_ip_as_domain(domain: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain))

def suspicious_subdomain(domain: str) -> bool:
    # Many dots can indicate deceptive subdomains
    return domain.count(".") >= 3

def _tokens(s: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", s.lower()) if t}

def brand_impersonation(domain: str):
    """
    Returns:
    (brand_name, is_official_domain, confidence_0_100, reasons)
    """
    if not domain:
        return None, False, 0, []

    domain = domain.lower()
    sld = domain.split(".")[0]
    tokens = _tokens(sld)
    joined = "".join(tokens)

    best = (None, False, 0, [])

    for brand, official_domains in OFFICIAL_BRANDS.items():
        b = brand.lower()
        score = 0
        reasons = []

        official_set = {d.lower() for d in official_domains}
        if domain in official_set:
            return brand, True, 100, ["official_domain_match"]

        if b in tokens:
            score += 70
            reasons.append("brand_token_match")
        elif len(b) >= 4 and b in joined:
            score += 50
            reasons.append("brand_joined_token_match")
        elif len(b) >= 5 and b in sld:
            score += 35
            reasons.append("brand_substring_match")

        if score > 0:
            if any(t in tokens for t in {"login","verify","secure","update","confirm","account"}):
                score += 10
                reasons.append("phishy_word_with_brand")

            if len(b) <= 2:
                score -= 40
                reasons.append("short_brand_penalty")

            score = max(0, min(100, score))

            if score > best[2]:
                best = (brand, False, score, reasons)

    return best

def analyze_url(url: str) -> dict:
    url = normalize_url(url)
    domain = extract_domain(url)

    result = {
    "url": url,
    "domain": domain,
    "flags": [],
    "brand": None,
    "official": False,
    "brand_score": 0,
    "brand_reasons": [],
}

    if not domain:
        result["flags"].append("empty_domain")
        return result

    # HTTPS check
    if url.startswith("http://"):
        result["flags"].append("no_https")

    # IP instead of domain
    if has_ip_as_domain(domain):
        result["flags"].append("ip_as_domain")

    # Unicode / punycode trick
    if has_punycode(domain):
        result["flags"].append("punycode")

    # Excessive subdomains
    if suspicious_subdomain(domain):
        result["flags"].append("many_subdomains")
    
    # Gov websites
    if domain.endswith(".gov"):
        result["flags"].append("gov_doamin")

    # Suspicious TLD
    tld = tld_of(domain)
    if tld in SUSPICIOUS_TLDS:
        result["flags"].append(f"suspicious_tld:{tld}")

    # Keyword-based tricks
    lowered = url.lower()
    for word in SUSPICIOUS_WORDS:
        if word in lowered:
            result["flags"].append(f"keyword:{word}")
            
    # Brand impersonation check (scored)
    brand, official, brand_score, brand_reasons = brand_impersonation(domain)
    result["brand"] = brand
    result["official"] = official
    result["brand_score"] = brand_score
    result["brand_reasons"] = brand_reasons

    if brand and not official:
        if brand_score >= 70:
            result["flags"].append("brand_spoof_high_confidence")
        elif brand_score >= 40:
            result["flags"].append("brand_spoof_medium_confidence")

    return result