# ai_agent/utils.py
import re
from typing import List, Tuple

URL_REGEX = re.compile(
    r"(https?://[^\s]+)|(www\.[^\s]+)",
    flags=re.IGNORECASE,
)

PHISHING_KEYWORDS = [
    "verify your account", "click here", "login", "account suspended", "reset your password",
    "confirm your identity", "unauthorized", "update your payment", "billing problem",
    "security alert", "verify identity", "provide your credentials"
]


def extract_urls(text: str) -> List[str]:
    """Return a list of URLs found in text."""
    if not text:
        return []
    matches = URL_REGEX.findall(text)
    urls = []
    for a, b in matches:
        if a:
            urls.append(a)
        elif b:
            urls.append(b)
    return urls


def contains_phishing_keywords(text: str) -> Tuple[bool, List[str]]:
    """Return (found_flag, matched_keywords_list). Case-insensitive search."""
    if not text:
        return False, []
    lowered = text.lower()
    matched = [kw for kw in PHISHING_KEYWORDS if kw in lowered]
    return (len(matched) > 0, matched)


def simple_phish_score(text: str) -> int:
    """
    Heuristic risk score for phishing/malicious text (0..100).
    - presence of URLs adds weight
    - phishing keywords add weight
    - urgency / exclamation points add weight
    """
    if not text:
        return 0

    score = 0

    urls = extract_urls(text)
    if urls:
        # more URLs -> higher base penalty
        score += min(40, 15 + 5 * (len(urls) - 1))

    has_kw, matched = contains_phishing_keywords(text)
    if has_kw:
        score += 30

    # character-based heuristics
    exclamations = text.count("!")
    if exclamations:
        score += min(10, exclamations * 2)

    # suspicious short-circuits
    lowered = text.lower()
    suspicious_phrases = ["bank", "password", "ssn", "social security", "paypal", "western union"]
    for phrase in suspicious_phrases:
        if phrase in lowered:
            score += 10

    # clamp
    score = max(0, min(100, score))
    return score
