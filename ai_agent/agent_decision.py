# ai_agent/agent_decision.py
import asyncio

class AgentDecision:
    """
    Receives raw analyzer outputs and makes a decision:
      - action: 'alert' | 'log' | 'ignore'
      - reason: text
      - combined risk_score: 0..100
    """

    async def route_and_decide(self, body: dict):
        t = body.get("type")
        if t == "url":
            from ai_agent.url_analyzer import UrlAnalyzer
            ua = UrlAnalyzer()
            result = await ua.scan_url(body.get("url"))
            score = result.get("risk_score", 0)
            action = "alert" if score >= 50 else ("log" if score >= 20 else "ignore")
            return {
                "type": "url",
                "input": body.get("url"),
                "analyzer": result,
                "combined_score": score,
                "action": action,
                "reason": f"URL risk_score {score}",
            }
        elif t == "password":
            from ai_agent.password_checker import PasswordChecker
            pc = PasswordChecker()
            result = pc.check_password(body.get("password"))
            score = result.get("risk_score", 0)
            action = "alert" if result.get("compromised") else ("log" if score > 60 else "ignore")
            return {
                "type": "password",
                "input": None,
                "analyzer": result,
                "combined_score": score,
                "action": action,
                "reason": f"Password compromised: {result.get('compromised')}, entropy {result.get('entropy_bits')}",
            }
        elif t == "text":
            from ai_agent.text_detector import TextDetector
            td = TextDetector()
            result = await td.analyze_text(body.get("text"))
            score = int(result.get("risk_score", 50))
            # choose action
            action = "alert" if score >= 60 or result.get("label") == "malicious" else ("log" if score >= 30 else "ignore")
            return {
                "type": "text",
                "input": None,
                "analyzer": result,
                "combined_score": score,
                "action": action,
                "reason": f"Text label {result.get('label')}: {result.get('reason')}",
            }
        else:
            return {"error": "unknown_type", "body": body}
