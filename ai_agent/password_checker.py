# ai_agent/password_checker.py
"""
PasswordChecker (SECURITY AGENT)

Hybrid approach:
- Local breached hash list
- Optional HIBP k-anonymity (privacy-safe)
- Entropy heuristics
- Optional zxcvbn scoring

Returns AGENT-NORMALIZED output:
{
  label: malicious | suspicious | benign
  risk_score: 0..100
  reason: explanation
  details: {...}
}
"""

import hashlib
import math
import time
from pathlib import Path
from typing import Optional

from config.settings import settings

# Optional dependency
try:
    from zxcvbn import zxcvbn
    _HAS_ZXCVBN = True
except Exception:
    _HAS_ZXCVBN = False

# ------------------ CONFIG ------------------
COMMON_FILE = Path(getattr(settings, "COMMON_PASSWORDS_FILE", "data/common_passwords.txt"))
BREACHED_FILE = Path(getattr(settings, "BREACHED_SHA1_FILE", "data/breached_sha1.txt"))

ENABLE_HIBP = getattr(settings, "ENABLE_HIBP", False)
_HIBP_CACHE = {}
_HIBP_CACHE_TTL = getattr(settings, "HIBP_CACHE_TTL", 60 * 60)


class PasswordChecker:
    def __init__(self, common_list_path: Optional[str] = None, breached_file_path: Optional[str] = None):
        # ---- Common passwords ----
        self.common_set = set()
        path = Path(common_list_path) if common_list_path else COMMON_FILE
        if path.exists():
            for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if ln.strip():
                    self.common_set.add(ln.strip().lower())

        # ---- Breached hashes ----
        self.breached_set = set()
        bpath = Path(breached_file_path) if breached_file_path else BREACHED_FILE
        if bpath.exists():
            for ln in bpath.read_text(encoding="utf-8", errors="ignore").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                if ":" in ln:
                    ln = ln.split(":", 1)[0]
                self.breached_set.add(ln.upper())

    # ------------------ HELPERS ------------------
    def _sha1(self, pwd: str) -> str:
        return hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()

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
        return math.log2(pool) * len(pwd) if pool else 0.0

    def _zxcvbn_score(self, pwd: str):
        if not _HAS_ZXCVBN:
            return None
        try:
            res = zxcvbn(pwd)
            return {
                "score": res.get("score"),
                "guesses": res.get("guesses"),
                "entropy": res.get("entropy")
            }
        except Exception:
            return None

    # ------------------ HIBP ------------------
    def _hibp_k_anonymity(self, sha1: str) -> int:
        prefix, suffix = sha1[:5], sha1[5:]
        now = time.time()

        cached = _HIBP_CACHE.get(prefix)
        if cached and now - cached["ts"] < _HIBP_CACHE_TTL:
            body = cached["body"]
        else:
            import requests
            try:
                r = requests.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    timeout=10
                )
                if r.status_code != 200:
                    return -1
                body = r.text
                _HIBP_CACHE[prefix] = {"ts": now, "body": body}
            except Exception:
                return -1

        for line in body.splitlines():
            if ":" not in line:
                continue
            suf, cnt = line.split(":", 1)
            if suf.strip().upper() == suffix:
                try:
                    return int(cnt)
                except Exception:
                    return -1
        return 0

    # ------------------ MAIN AGENT ------------------
    def check_password(self, pwd: str) -> dict:
        pwd = pwd or ""
        if not pwd:
            return {
                "label": "benign",
                "risk_score": 0,
                "reason": "empty password",
                "source": "input",
            }

        sha1 = self._sha1(pwd)
        entropy_bits = self._entropy_bits(pwd)
        zx = self._zxcvbn_score(pwd)

        is_common = pwd.lower() in self.common_set
        is_breached_local = sha1 in self.breached_set

        hibp_count = None
        if ENABLE_HIBP:
            hibp_count = self._hibp_k_anonymity(sha1)

        # ---- Compromise determination ----
        if ENABLE_HIBP and hibp_count not in (None, -1):
            pwned_count = hibp_count
        else:
            pwned_count = 1 if is_breached_local else 0

        # ---- Risk scoring ----
        if pwned_count > 0:
            risk_score = 100
            label = "malicious"
            reason = "password found in breach database"
        else:
                # Improved scoring logic
            if is_common:
                risk_score = 85
            elif entropy_bits < 40:
                risk_score = 75
            elif entropy_bits < 60:
                risk_score = 50
            else:
                risk_score = 20

            if risk_score >= 70:
                label = "suspicious"
                reason = "weak or predictable password"
            else:
                label = "benign"
                reason = "no breach indicators"

       
       # ---- Strength classification (FIXED LOGIC) ----
        if is_common or pwned_count > 0:
            strength = "weak"
        elif entropy_bits < 40:
            strength = "weak"
        elif entropy_bits < 60:
            strength = "medium"
        else:
            strength = "strong"

        return {
        "label": label,
        "risk_score": int(max(0, min(100, risk_score))),
        "reason": reason,
        "strength": strength,   # ✅ FIXED
        "details": {
            "entropy_bits": round(entropy_bits, 2),
            "zxcvbn": zx,
            "common_password": is_common,
            "pwned_count": pwned_count,
        },
        "source": "password-agent",
    }
