# ai_agent/url_heuristics.py
# Zero-day phishing URL heuristics (entropy + obfuscation + risky TLD)

import math
import base64
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

# High-abuse TLDs commonly used in phishing
HIGH_RISK_TLDS = {
    "top", "xyz", "click", "zip", "mov", "link", "fit", "rest", "cam"
}

# Parameters frequently abused in phishing URLs
SUSPICIOUS_PARAMS = {
    "id", "token", "session", "auth", "verify", "login", "secure"
}

# Base64-looking strings (long, high-entropy)
BASE64_REGEX = re.compile(r'^[A-Za-z0-9+/=]{20,}$')


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0.0
    probabilities = [n / len(data) for n in Counter(data).values()]
    return -sum(p * math.log2(p) for p in probabilities)


def try_base64_decode(value: str) -> str | None:
    """Attempt safe Base64 decode"""
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(padded).decode(errors="ignore")
        if len(decoded.strip()) > 5:
            return decoded
    except Exception:
        return None
    return None


def analyze_url_heuristics(url: str) -> dict:
    """
    Analyze URL for phishing heuristics.
    Returns heuristic_score (0–80) + explainable reasons.
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    score = 0
    reasons = []

    # 🔴 Risky TLD detection
    domain_parts = parsed.netloc.split(".")
    if len(domain_parts) >= 2:
        tld = domain_parts[-1].lower()
        if tld in HIGH_RISK_TLDS:
            score += 15
            reasons.append(f"High-risk TLD detected: .{tld}")

    # 🔴 Analyze query parameters
    for param, values in query_params.items():
        value = values[0]

        # Entropy check (obfuscation)
        entropy = shannon_entropy(value)
        if entropy >= 4.2:
            score += 20
            reasons.append(
                f"High entropy detected in `{param}` (entropy={entropy:.2f})"
            )

        # Suspicious parameter names
        if param.lower() in SUSPICIOUS_PARAMS:
            score += 10
            reasons.append(f"Suspicious parameter name: `{param}`")

        # Base64-encoded payload detection
        if BASE64_REGEX.match(value):
            decoded = try_base64_decode(value)
            if decoded:
                score += 25
                reasons.append(
                    f"Base64-obfuscated payload detected in `{param}`"
                )

    return {
        "heuristic_score": min(score, 80),
        "heuristic_reasons": reasons
    }

SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]

def analyze_url_heuristics(url: str):
    score = 0
    reasons = []

    # 🚨 Brand impersonation detection
    if any(brand in url.lower() for brand in ["paypal", "microsoft", "amazon", "bank", "google"]):
        score += 40
        reasons.append("Brand impersonation detected")

# 🚨 Suspicious keywords
    if any(word in url.lower() for word in ["login", "verify", "secure", "account", "update"]):
        score += 30
        reasons.append("Suspicious phishing keywords in URL")

    if any(domain in url for domain in SHORTENER_DOMAINS):
        score += 40
        reasons.append("URL shortener detected (possible obfuscation)")

    return {
        "heuristic_score": score,
        "heuristic_reasons": reasons
    }
