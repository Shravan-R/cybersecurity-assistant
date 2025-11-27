# ai_agent/url_analyzer.py
import base64
import asyncio
import time
from typing import Any, Dict, Optional

import httpx
from config.settings import settings

VT_API = settings.VT_API_KEY
VT_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT = 30.0


class UrlAnalyzer:
    """
    VirusTotal (v3) URL analysis helper with robust polling, rate-limit handling,
    exponential backoff and a normalized risk_score (0-100).

    Usage:
      ua = UrlAnalyzer()
      await ua.scan_url("http://example.com")
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or VT_API
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}

    @staticmethod
    def _encode_url_id(url: str) -> str:
        # VT expects URL-safe base64 without padding
        enc = base64.urlsafe_b64encode(url.encode()).decode()
        return enc.rstrip("=")

    async def _request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        json: dict | None = None,
        data: dict | None = None,
        params: dict | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> httpx.Response:
        backoff = 1.0
        max_backoff = 16.0
        attempts = 0
        while True:
            try:
                resp = await client.request(method, url, json=json, data=data, params=params, timeout=timeout)
                if resp.status_code == 429:
                    # rate limited: exponential backoff using Retry-After header if present
                    retry_after = resp.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after else backoff
                    await asyncio.sleep(wait)
                    backoff = min(backoff * 2, max_backoff)
                    attempts += 1
                    if attempts > 6:
                        resp.raise_for_status()
                    continue
                resp.raise_for_status()
                return resp
            except httpx.HTTPStatusError:
                raise
            except (httpx.RequestError, asyncio.TimeoutError) as exc:
                # transient network error: backoff & retry
                attempts += 1
                if attempts > 5:
                    raise
                await asyncio.sleep(min(backoff, max_backoff))
                backoff *= 2

    async def _submit_url(self, client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
        # POST /urls to submit URL for analysis
        endpoint = f"{VT_BASE}/urls"
        resp = await self._request(client, "POST", endpoint, data={"url": url})
        return resp.json()

    async def _get_analysis(self, client: httpx.AsyncClient, analysis_id: str) -> Dict[str, Any]:
        endpoint = f"{VT_BASE}/analyses/{analysis_id}"
        resp = await self._request(client, "GET", endpoint)
        return resp.json()

    async def _get_url_object(self, client: httpx.AsyncClient, url_id: str) -> Dict[str, Any]:
        endpoint = f"{VT_BASE}/urls/{url_id}"
        resp = await self._request(client, "GET", endpoint)
        return resp.json()

    async def scan_url(self, url: str, *, poll_interval: float = 1.0, max_polls: int = 12) -> Dict[str, Any]:
        """
        Submit URL -> poll analysis -> fetch URL object -> return normalized result.

        Returns:
          {
            "url": url,
            "malicious_votes": int,
            "suspicious_votes": int,
            "harmless_votes": int,
            "undetected": int,
            "risk_score": 0..100,
            "engines_count": int,
            "engines": {vendor: category, ...},
            "raw": {...}
          }
        """
        async with httpx.AsyncClient(headers=self.headers, timeout=DEFAULT_TIMEOUT) as client:
            submit = await self._submit_url(client, url)
            analysis_id = submit.get("data", {}).get("id")
            # If VT accepted the URL and provided an analysis id, poll it.
            analysis = None
            if analysis_id:
                for i in range(max_polls):
                    analysis = await self._get_analysis(client, analysis_id)
                    status = analysis.get("data", {}).get("attributes", {}).get("status")
                    if status == "completed":
                        break
                    await asyncio.sleep(poll_interval)
            # Best effort: fetch the URL object directly
            url_id = self._encode_url_id(url)
            url_obj = None
            try:
                url_obj = await self._get_url_object(client, url_id)
            except Exception:
                url_obj = analysis or submit

            # extract stats safely
            attributes = (url_obj.get("data", {}) or {}).get("attributes", {}) if isinstance(url_obj, dict) else {}
            last_stats = attributes.get("last_analysis_stats", {}) or {}
            engines = attributes.get("last_analysis_results", {}) or {}

            malicious_votes = int(last_stats.get("malicious", 0))
            suspicious_votes = int(last_stats.get("suspicious", 0))
            harmless_votes = int(last_stats.get("harmless", 0))
            undetected = int(last_stats.get("undetected", 0))

            total = malicious_votes + suspicious_votes + harmless_votes + undetected
            total = total if total > 0 else 1

            # risk_score: malicious_weight=1.0, suspicious_weight=0.5
            risk = (malicious_votes * 1.0 + suspicious_votes * 0.5) / total
            risk_score = int(max(0, min(100, round(risk * 100))))

            engines_parsed = {}
            for k, v in engines.items():
                try:
                    engines_parsed[k] = v.get("category")
                except Exception:
                    engines_parsed[k] = str(v)

            return {
                "url": url,
                "malicious_votes": malicious_votes,
                "suspicious_votes": suspicious_votes,
                "harmless_votes": harmless_votes,
                "undetected": undetected,
                "risk_score": risk_score,
                "engines_count": len(engines_parsed),
                "engines": engines_parsed,
                "raw": {"submit": submit, "analysis": analysis, "url_object": url_obj},
            }
