# ai_agent/text_detector.py
"""
TextDetector

- async analyze_text(text): returns dict with keys:
  - label: one of ("malicious","suspicious","benign")
  - reason: short human-readable reason
  - risk_score: 0..100 (int)
- Uses OpenAI if OPENAI_API_KEY present; otherwise falls back to heuristics.
"""

import asyncio
import os
from typing import Dict, Any

from config.settings import settings
from .utils import extract_urls, contains_phishing_keywords, simple_phish_score

# OpenAI is optional — we will import only when used
try:
    import openai
    OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False


class TextDetector:
    def __init__(self, model: str = "gpt-3.5-turbo", openai_key: str | None = None):
        self.model = model
        self.openai_key = openai_key or settings.OPENAI_API_KEY
        if OPENAI_AVAILABLE and self.openai_key:
            openai.api_key = self.openai_key

    async def _call_openai(self, text: str) -> Dict[str, Any]:
        """
        Call OpenAI ChatCompletion in a thread to avoid blocking asyncio loop.
        Returns a parsed dict {label, reason, risk_score}.
        """
        if not OPENAI_AVAILABLE or not self.openai_key:
            raise RuntimeError("OpenAI not available or API key missing")

        prompt = (
            "You are a security assistant. Classify the following message as one of: "
            "'malicious', 'suspicious', or 'benign'. Return a JSON object only with keys: "
            "\"label\", \"reason\", \"risk_score\" where risk_score is an integer 0-100.\n\n"
            "Message:\n"
            "-----\n"
            f"{text}\n"
            "-----\n\n"
            "Guidance: 'malicious' for clear phishing/malware/call-to-action scam messages; "
            "'suspicious' for ambiguous or potentially risky messages; 'benign' for normal content."
        )

        def sync_call():
            # Using ChatCompletion for structured response
            resp = openai.ChatCompletion.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=200,
            )
            return resp

        # run in thread to avoid blocking
        loop = asyncio.get_running_loop()
        resp = await loop.run_in_executor(None, sync_call)

        # Parse assistant reply — try to parse JSON inside response content
        try:
            content = resp["choices"][0]["message"]["content"]
            import json
            # find first brace to avoid extra text
            start = content.find("{")
            end = content.rfind("}")
            if start != -1 and end != -1 and end > start:
                json_text = content[start:end+1]
                parsed = json.loads(json_text)
                # normalize fields
                label = parsed.get("label", "").lower()
                reason = parsed.get("reason", "") or ""
                risk_score = int(parsed.get("risk_score", 0))
                risk_score = max(0, min(100, risk_score))
                if label not in ("malicious", "suspicious", "benign"):
                    # fallback mapping
                    if risk_score >= 70:
                        label = "malicious"
                    elif risk_score >= 40:
                        label = "suspicious"
                    else:
                        label = "benign"
                return {"label": label, "reason": reason, "risk_score": risk_score}
            else:
                # fallback: simple parse by lines
                txt = content.strip().lower()
                if "malicious" in txt:
                    label = "malicious"
                elif "suspicious" in txt:
                    label = "suspicious"
                else:
                    label = "benign"
                # attempt to extract number
                import re
                m = re.search(r"(\d{1,3})", content)
                risk_score = int(m.group(1)) if m else 50
                return {"label": label, "reason": content.strip()[:200], "risk_score": max(0, min(100, risk_score))}
        except Exception:
            # raise up to caller to fallback
            raise

    async def analyze_text(self, text: str) -> Dict[str, Any]:
        """
        Main entry point. Returns:
        {
            "label": "malicious"|"suspicious"|"benign",
            "reason": "explanation",
            "risk_score": int 0..100,
            "urls": [...],
            "heuristic_score": int
        }
        """
        # basic normalization
        if not text or not text.strip():
            return {"label": "benign", "reason": "empty input", "risk_score": 0, "urls": [], "heuristic_score": 0}

        urls = extract_urls(text)
        heuristic = simple_phish_score(text)

        # Try OpenAI if available
        if OPENAI_AVAILABLE and self.openai_key:
            try:
                oa = await self._call_openai(text)
                # merge heuristic info
                oa["urls"] = urls
                oa["heuristic_score"] = heuristic
                # sanity clamp
                oa["risk_score"] = int(max(0, min(100, int(oa.get("risk_score", 0)))))
                return oa
            except Exception:
                # fall through to heuristics on any failure
                pass

        # Heuristic fallback
        found_kw, matched = contains_phishing_keywords(text)
        reason_parts = []
        if urls:
            reason_parts.append(f"found_url(s): {len(urls)}")
        if found_kw:
            reason_parts.append(f"keywords: {matched}")
        if heuristic >= 70:
            label = "malicious"
        elif heuristic >= 35:
            label = "suspicious"
        else:
            label = "benign"

        reason = "; ".join(reason_parts) or "heuristic analysis"
        return {"label": label, "reason": reason, "risk_score": heuristic, "urls": urls, "heuristic_score": heuristic}
