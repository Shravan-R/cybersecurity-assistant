# ai_agent/text_detector.py
# ai_agent/text_detector.py
"""
TextDetector (HYBRID AGENT)

Priority order:
1. Trained ML model (dataset-based)
2. OpenAI GPT (reasoning-based, optional)
3. Heuristic fallback (always available)

Returns:
{
  label: malicious | suspicious | benign
  reason: explanation
  risk_score: 0..100
}
"""

import asyncio
from typing import Dict, Any
from pathlib import Path

from config.settings import settings
from .utils import extract_urls, contains_phishing_keywords, simple_phish_score,modern_phish_score

# ------------------ OPTIONAL OPENAI ------------------
try:
    import openai
    OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False

# ------------------ OPTIONAL ML ------------------
try:
    import joblib
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False


MODEL_DIR = Path("ml_models")


class TextDetector:
    def __init__(self, model: str = "gpt-3.5-turbo", openai_key: str | None = None):
        self.model = model
        self.openai_key = openai_key or settings.OPENAI_API_KEY

        # OpenAI setup
        if OPENAI_AVAILABLE and self.openai_key:
            openai.api_key = self.openai_key

        # ML model setup
        self.ml_model = None
        self.vectorizer = None
        if ML_AVAILABLE:
            try:
                self.ml_model = joblib.load(MODEL_DIR / "text_phishing_model.pkl")
                self.vectorizer = joblib.load(MODEL_DIR / "text_vectorizer.pkl")
            except Exception:
                # ML is optional; do not crash agent
                self.ml_model = None
                self.vectorizer = None

    # ------------------ GPT CALL ------------------
    async def _call_openai(self, text: str) -> Dict[str, Any]:
        if not OPENAI_AVAILABLE or not self.openai_key:
            raise RuntimeError("OpenAI not available")

        prompt = (
            "You are a security assistant. Classify the following message as "
            "'malicious', 'suspicious', or 'benign'. Return JSON with keys: "
            "label, reason, risk_score (0-100).\n\n"
            f"Message:\n{text}"
        )

        def sync_call():
            return openai.ChatCompletion.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=200,
            )

        loop = asyncio.get_running_loop()
        resp = await loop.run_in_executor(None, sync_call)

        content = resp["choices"][0]["message"]["content"]
        import json, re

        try:
            start, end = content.find("{"), content.rfind("}")
            parsed = json.loads(content[start:end+1])
            score = int(parsed.get("risk_score", 0))
            score = max(0, min(100, score))
            label = parsed.get("label", "benign").lower()
            return {
                "label": label,
                "reason": parsed.get("reason", "LLM analysis"),
                "risk_score": score
            }
        except Exception:
            m = re.search(r"(\d{1,3})", content)
            score = int(m.group(1)) if m else 50
            return {
                "label": "suspicious",
                "reason": content[:200],
                "risk_score": max(0, min(100, score))
            }

    # ------------------ MAIN AGENT ENTRY ------------------
    async def analyze_text(self, text: str) -> Dict[str, Any]:
        if not text or not text.strip():
            return {"label": "benign", "reason": "empty input", "risk_score": 0}

        text_lower = text.lower()
        urls = extract_urls(text)

        ml_score = 0

    # ===== 1️⃣ ML MODEL =====
        if self.ml_model and self.vectorizer:
            vec = self.vectorizer.transform([text])
            prob = self.ml_model.predict_proba(vec)[0][1]
            ml_score = int(prob * 100)

    # ===== 2️⃣ HEURISTICS (ALWAYS RUN) =====
        heuristic_score = 0
        reasons = []

        # 🚨 Modern phishing patterns (VERY IMPORTANT)
        if any(phrase in text_lower for phrase in [
            "new device",
            "suspicious login",
            "unusual activity",
            "confirm your account",
            "confirm your session",
            "verify your identity",
            "security alert"
            ]):
            heuristic_score += 35
            reasons.append("Account security alert pattern detected")

# 🚨 Action-based words
        if any(word in text_lower for word in ["confirm", "verify", "secure"]):
            heuristic_score += 20
            reasons.append("Account action request detected")

    # Urgency
        if any(word in text_lower for word in ["urgent", "immediately", "24 hours", "suspended", "limited time"]):
            heuristic_score += 30
            reasons.append("Urgency detected")

    # Call to action
        if any(word in text_lower for word in ["click here", "verify", "login", "update", "confirm"]):
            heuristic_score += 30
            reasons.append("Call-to-action detected")

    # Threat language
        if any(word in text_lower for word in ["suspended", "blocked", "unauthorized", "security alert"]):
            heuristic_score += 25
            reasons.append("Threat language detected")

    # Link presence
        if urls:
            heuristic_score += 20
            reasons.append("Link detected")

    # ===== 3️⃣ FINAL SCORE (COMBINED) =====
        final_score = int((0.6 * heuristic_score) + (0.4 * ml_score))
        # 🔥 Minimum risk baseline for generic messages
        if final_score == 0:
            final_score = 30

        # 🔥 Strong phishing combination override
        if (
            any(word in text_lower for word in ["blocked", "suspended"]) and
            any(word in text_lower for word in ["click here", "verify", "update"]) and
            any(word in text_lower for word in ["24 hours", "immediately", "urgent"])
):
            final_score = max(final_score, 85)

        # 🔥 High-confidence phishing override (FINAL FIX)
        if any(phrase in text_lower for phrase in [
            "new device",
            "confirm your session",
            "verify your account",
            "unusual activity"
        ]):
            final_score = max(final_score, 75)

    # ===== 4️⃣ LABEL =====
        if final_score >= 70:
            label = "malicious"
        elif final_score >= 40:
            label = "suspicious"
        else:
            label = "benign"

        return {
            "label": label,
            "risk_score": final_score,
            "reason": " | ".join(reasons) if reasons else "ML + heuristic analysis",
            "urls": urls,
            "source": "ml+heuristic"
        }

        # ===== 2️⃣ OPENAI (SECONDARY) =====
        if OPENAI_AVAILABLE and self.openai_key:
            try:
                oa = await self._call_openai(text)
                oa["urls"] = urls
                oa["source"] = "openai"
                return oa
            except Exception:
                pass

        # ===== 3️⃣ HEURISTIC FALLBACK =====
        legacy_score = simple_phish_score(text)
        modern_score = modern_phish_score(text)

        # Hybrid SOC-safe scoring
        heuristic = max(legacy_score, modern_score)

        found_kw, matched = contains_phishing_keywords(text)

        # ---------- FINAL LABEL DECISION ----------# 
        if heuristic >= 70:
            label = "malicious"
        elif heuristic >= 35:
            label = "suspicious"
        else:
            label = "benign"


        reason_parts = []
        if urls:
            reason_parts.append(f"urls={len(urls)}")
        if found_kw:
            reason_parts.append(f"keywords={matched}")

        # ---------- Explainable hybrid reasoning ----------
        reason_parts = []

        if legacy_score >= 35:
            reason_parts.append("legacy phishing patterns detected")
        if modern_score >= 35:
            reason_parts.append("modern phishing behavior detected")
        reason = "; ".join(reason_parts) or "heuristic analysis"


        return{
        "label": label,
        "reason": reason,
        "risk_score": heuristic,
        "urls": urls,
        "source": "heuristic",
        }

