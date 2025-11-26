# tests/test_url_analyzer.py
import asyncio
import pytest
from ai_agent.url_analyzer import UrlAnalyzer

@pytest.mark.asyncio
async def test_scan_url_parsing(monkeypatch):
    ua = UrlAnalyzer(api_key="TESTKEY")

    # fake submit response -> returns analysis id
    async def fake_submit(client, url):
        return {"data": {"id": "fake-analysis-id"}}

    # fake analysis: completed status
    async def fake_get_analysis(client, analysis_id):
        return {"data": {"attributes": {"status": "completed"}}}

    # fake url object with last_analysis_stats
    async def fake_get_url_object(client, url_id):
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 5, "undetected": 10},
                    "last_analysis_results": {
                        "VendorA": {"category": "malicious"},
                        "VendorB": {"category": "harmless"}
                    }
                }
            }
        }

    monkeypatch.setattr(ua, "_submit_url", lambda client, url: fake_submit(client, url))
    monkeypatch.setattr(ua, "_get_analysis", lambda client, aid: fake_get_analysis(client, aid))
    monkeypatch.setattr(ua, "_get_url_object", lambda client, uid: fake_get_url_object(client, uid))

    result = await ua.scan_url("http://example.test")
    assert result["malicious_votes"] == 2
    assert result["suspicious_votes"] == 1
    assert "risk_score" in result
    assert 0 <= result["risk_score"] <= 100
