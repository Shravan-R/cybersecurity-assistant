# ai_agent/password_checker.py
import hashlib
import math
import time
import os
from pathlib import Path
from typing import Optional

from config.settings import settings

# Optional dependency: zxcvbn for better password strength scoring.
try:
    from zxcvbn import zxcvbn  # pip package: zxcvbn
    _HAS_ZXCVBN = True
except Exception:
    _HAS_ZXCVBN = False

# Config-driven file paths (set in config.settings or .env)
COMMON_FILE = Path(getattr(settings, "COMMON_PASSWORDS_FILE", "data/common_passwords.txt"))
BREACHED_FILE = Path(getattr(settings, "BREACHED_SHA1_FILE", "data/breached_sha1.txt"))

# HIBP toggle and cache TTL (only used if ENABLE_HIBP is True)
ENABLE_HIBP = getattr(settings, "ENABLE_HIBP", False)
_HIBP_CACHE = {}
_HIBP_CACHE_TTL = getattr(settings, "HIBP_CACHE_TTL", 60 * 60)  # seconds


class PasswordChecker:
    def __init__(self, common_list_path: Optional[str] = None, breached_file_path: Optional[str] = None):
        # load common passwords
        self.common_set = set()
        path = common_list_path or COMMON_FILE
        try:
            if Path(path).exists():
                for ln in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
                    pw = ln.strip()
                    if pw:
                        self.common_set.add(pw.lower())
        except Exception:
            self.common_set = set()

        # load breached sha1 hashes (uppercase)
        self.breached_set = set()
        bpath = breached_file_path or BREACHED_FILE
        try:
            if Path(bpath).exists():
                for ln in Path(bpath).read_text(encoding="utf-8", errors="ignore").splitlines():
                    ln = ln.strip()
                    if not ln:
                        continue
                    if ":" in ln:
                        ln = ln.split(":", 1)[0]
                    self.breached_set.add(ln.upper())
        except Exception:
            self.breached_set = set()

    def _sha1(self, pwd: str) -> str:
        return hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()

    def _hibp_k_anonymity(self, sha1: str) -> int:
        """
        Query HIBP range API with k-anonymity. Returns count (0 if none), -1 on error.
        Uses a small in-memory cache keyed by prefix.
        """
        prefix = sha1[:5]
        suffix = sha1[5:].upper()

        now = time.time()
        cached = _HIBP_CACHE.get(prefix)
        if cached and (now - cached["ts"]) < _HIBP_CACHE_TTL:
            body = cached["body"]
        else:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            try:
                import requests
                resp = requests.get(url, timeout=10)
                if resp.status_code != 200:
                    return -1
                body = resp.text
                _HIBP_CACHE[prefix] = {"ts": now, "body": body}
            except Exception:
                return -1

        for line in body.splitlines():
            if not line:
                continue
            parts = line.split(":")
            if len(parts) != 2:
                continue
            suf = parts[0].strip().upper()
            count = parts[1].strip()
            if suf == suffix:
                try:
                    return int(count)
                except Exception:
                    return -1
        return 0

    def _entropy_bits(self, pwd: str) -> float:
        pool = 0
        if any(c.islower() for c in pwd):
            pool += 26
        if any(c.isupper() for c in pwd):
            pool += 26
        if any(c.isdigit() for c in pwd):
            pool += 10
        if any(not c.isalnum() for c in pwd):
            pool += 32
        if pool == 0:
            return 0.0
        return math.log2(pool) * len(pwd)

    def _zxcvbn_score(self, pwd: str):
        if not _HAS_ZXCVBN:
            return None
        try:
            res = zxcvbn(pwd)
            return {
                "score": res.get("score", None),  # 0..4
                "guesses": res.get("guesses", None),
                "entropy": res.get("entropy", None)
            }
        except Exception:
            return None

    def check_password(self, pwd: str):
        pwd = pwd or ""
        sha1 = self._sha1(pwd)
        is_common = pwd.lower() in self.common_set if pwd else False

        # local breached set lookup
        is_breached_local = sha1 in self.breached_set

        # optional HIBP check (only if enabled)
        hibp_count = None
        if ENABLE_HIBP:
            try:
                hibp_count = self._hibp_k_anonymity(sha1)
            except Exception:
                hibp_count = -1

        # pick breached result: prefer HIBP if enabled and successful, else local
        if ENABLE_HIBP and (hibp_count is not None) and (hibp_count != -1):
            pwned_count = hibp_count
        else:
            pwned_count = -1 if ENABLE_HIBP and hibp_count == -1 else (1 if is_breached_local else 0)

        # entropy heuristics and zxcvbn
        entropy_bits = self._entropy_bits(pwd)
        zx = self._zxcvbn_score(pwd)

        # strength label
        if is_common:
            strength = "very_weak"
        elif entropy_bits < 28:
            strength = "very_weak"
        elif entropy_bits < 40:
            strength = "weak"
        elif entropy_bits < 60:
            strength = "reasonable"
        else:
            strength = "strong"

        # risk score 0..100
        if pwned_count and pwned_count > 0:
            risk_score = 100
            compromised = True
        elif pwned_count == 0:
            compromised = False
            risk_score = int(max(0, min(100, round(100 - (entropy_bits / 80.0 * 100)))))
            if is_common:
                risk_score = max(risk_score, 85)
        else:
            # pwned_count == -1 (unknown) -> conservative risk
            compromised = None
            risk_score = 70

        return {
            "entropy_bits": round(entropy_bits, 2),
            "zxcvbn": zx,
            "pwned_count": pwned_count,
            "compromised": compromised,
            "common_password": is_common,
            "strength": strength,
            "risk_score": risk_score,
        }

# Convenience for quick CLI debug
if __name__ == "__main__":
    pc = PasswordChecker()
    while True:
        pw = input("Password (empty to exit): ").strip()
        if not pw:
            break
        print(pc.check_password(pw))
