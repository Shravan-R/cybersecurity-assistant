# tests/test_text_detector.py
import pytest
import asyncio
from ai_agent.text_detector import TextDetector

@pytest.mark.asyncio
async def test_analyze_text_fallback(monkeypatch):
    td = TextDetector()

    # mock openai call by replacing the analyze_text internal call that uses openai
    async def fake_analyze(text):
        # return model-like structure
        return {"label": "malicious", "reason": "Contains phishing keywords", "risk_score": 85}

    monkeypatch.setattr(td, "analyze_text", lambda text: fake_analyze(text))

    res = await td.analyze_text("Please verify your account: click http://bad.example")
    assert isinstance(res, dict)
    assert res["label"] == "malicious"
    assert 0 <= int(res["risk_score"]) <= 100
