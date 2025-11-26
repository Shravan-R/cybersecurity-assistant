# tests/test_agent_decision.py
import pytest
import asyncio

from ai_agent.agent_decision import AgentDecision

@pytest.mark.asyncio
async def test_route_and_decide_url(monkeypatch):
    ad = AgentDecision()

    # Mock UrlAnalyzer.scan_url to return a high-risk result
    async def fake_scan(url):
        return {
            "url": url,
            "malicious_votes": 3,
            "suspicious_votes": 1,
            "harmless_votes": 2,
            "undetected": 4,
            "risk_score": 75,
            "engines": {"VendorA": "malicious"}
        }

    monkeypatch.setattr("ai_agent.agent_decision.UrlAnalyzer", lambda *args, **kwargs: type("X", (), {"scan_url": fake_scan})())

    payload = {"type": "url", "url": "http://bad.example"}
    res = await ad.route_and_decide(payload)

    assert res["type"] == "url"
    assert "analyzer" in res
    assert res["combined_score"] == 75
    assert res["action"] == "alert"  # 75 should trigger alert per decision logic

@pytest.mark.asyncio
async def test_route_and_decide_password(monkeypatch):
    ad = AgentDecision()

    # Mock PasswordChecker.check_password to return compromised/non-compromised variants
    def fake_check(pwd):
        return {
            "entropy_bits": 10,
            "pwned_count": 5,
            "compromised": True,
            "strength": "very_weak",
            "risk_score": 100
        }

    monkeypatch.setattr("ai_agent.agent_decision.PasswordChecker", lambda *args, **kwargs: type("X", (), {"check_password": fake_check})())

    payload = {"type": "password", "password": "password123"}
    res = await ad.route_and_decide(payload)

    assert res["type"] == "password"
    assert res["analyzer"]["compromised"] is True
    assert res["combined_score"] == 100
    assert res["action"] == "alert"

@pytest.mark.asyncio
async def test_route_and_decide_text(monkeypatch):
    ad = AgentDecision()

    # Mock TextDetector.analyze_text to return a suspicious/malicious label
    async def fake_analyze(text):
        return {"label": "malicious", "reason": "phishing", "risk_score": 80}

    monkeypatch.setattr("ai_agent.agent_decision.TextDetector", lambda *args, **kwargs: type("X", (), {"analyze_text": fake_analyze})())

    payload = {"type": "text", "text": "Please reset your password: http://phish.test"}
    res = await ad.route_and_decide(payload)

    assert res["type"] == "text"
    assert res["analyzer"]["label"] == "malicious"
    assert res["combined_score"] == 80
    assert res["action"] == "alert"

@pytest.mark.asyncio
async def test_route_and_decide_unknown_type():
    ad = AgentDecision()
    payload = {"type": "something_else"}
    res = await ad.route_and_decide(payload)
    assert "error" in res
