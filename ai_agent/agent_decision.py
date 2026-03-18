# ai_agent/agent_decision.py
from typing import Dict, Any

from ai_agent.url_analyzer import UrlAnalyzer
from ai_agent.text_detector import TextDetector
from ai_agent.password_checker import PasswordChecker
from ai_agent.url_heuristics import analyze_url_heuristics
from ai_agent.scoring import calculate_final_score


class AgentDecision:
    """
    Routes input to the correct analyzer, aggregates risk,
    and decides: ignore / log / alert
    """

    def __init__(self):
        self.url_analyzer = UrlAnalyzer()
        self.text_detector = TextDetector()
        self.password_checker = PasswordChecker()

    # ------------------ UTIL ------------------
    def _normalize_url(self, url: str) -> str:
        return (
            url.replace("hxxp://", "http://")
               .replace("hxxps://", "https://")
               .replace("[.]", ".")
               .strip()
        )

    # ------------------ MAIN ROUTER ------------------
    async def route_and_decide(self, body: Dict[str, Any]) -> Dict[str, Any]:
        input_type = body.get("type")

        # ---------- SAFETY ----------
        if input_type not in {"url", "text", "password"}:
            return {
                "type": input_type,
                "action": "ignore",
                "combined_score": 0,
                "confidence": "low",
                "reason": "Invalid or missing input type",
                "policy": "safe_default",
                "analysis_source": "unknown",
                "analysis": body,
            }

        # ---------- URL ----------
        if input_type == "url":
            raw_url = body.get("url", "")
            normalized_url = self._normalize_url(raw_url)

            # Existing reputation-based analysis
            analysis = await self.url_analyzer.scan_url(normalized_url) or {}

            reputation_score = int(analysis.get("risk_score", 0))

            # 🔥 NEW: zero-day phishing heuristics
            heuristics = analyze_url_heuristics(normalized_url)
            heuristic_score = int(heuristics.get("heuristic_score", 0))

            # 🔥 FINAL SCORE (FIX)
            final_score = calculate_final_score(
                heuristic_score,
                reputation_score,
                normalized_url
            )

            label = (
                "malicious"
                if final_score >= 70
                else "suspicious"
                if final_score >= 40
                else "benign"
            )

            # ✅ FIXED REASON LOGIC
            if final_score < 35:
                reason = "No significant phishing indicators detected"
            elif heuristics.get("heuristic_reasons"):
                reason = " | ".join(heuristics.get("heuristic_reasons"))
            else:
                reason = analysis.get("reason", "URL analysis")

            return self._final_decision(
                input_type="url",
                score=final_score,
                label=label,
                reason=reason,
                source="heuristic+reputation",
                analysis={
                    "url": normalized_url,
                    "reputation_score": reputation_score,
                    "heuristic_score": heuristic_score,
                    "heuristic_reasons": heuristics.get("heuristic_reasons", []),
                },
            )

        # ---------- TEXT ----------
        if input_type == "text":
            text = body.get("text", "")

            analysis = await self.text_detector.analyze_text(text) or {}

            risk = int(analysis.get("risk_score", 0))
            label = analysis.get("label", "benign")
            reason = analysis.get("reason", "Text analysis")
            source = analysis.get("source", "heuristic")

            return self._final_decision(
                input_type="text",
                score=risk,
                label=label,
                reason=reason,
                source=source,
                analysis={"text": text[:300]},
            )

        # ---------- PASSWORD ----------
        if input_type == "password":
            pwd = body.get("password", "")

            analysis = self.password_checker.check_password(pwd) or {}

            risk = int(analysis.get("risk_score", 0))
            compromised = analysis.get("compromised", False)
            label = "malicious" if compromised else "benign"

            return self._final_decision(
                input_type="password",
                score=risk,
                label=label,
                reason="Password strength / breach analysis",
                source="local_rules",
                analysis={"strength": analysis.get("strength")},
            )

    # ------------------ DECISION LOGIC ------------------
    def _final_decision(
        self,
        input_type: str,
        score: int,
        label: str,
        reason: str,
        source: str,
        analysis: Dict[str, Any],
    ) -> Dict[str, Any]:

        if score >= 70:
            action = "alert"
            confidence = "high"
            policy = "high_risk_policy"
        elif score >= 35:
            action = "log"
            confidence = "medium"
            policy = "medium_risk_policy"
        else:
            action = "ignore"
            confidence = "low"
            policy = "low_risk_policy"

        return {
            "type": input_type,
            "action": action,
            "combined_score": score,
            "confidence": confidence,
            "reason": reason,
            "policy": policy,
            "analysis_source": source,
            "analysis": analysis,
        }
