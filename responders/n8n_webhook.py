# responders/n8n_webhook.py
import asyncio
import httpx
from typing import Any, Dict, Optional

class N8NResponder:
    """
    Async responder to send decision payloads to an n8n webhook.
    """

    def __init__(self, webhook_url: str, timeout: float = 10.0):
        self.webhook_url = webhook_url
        self.timeout = timeout

    async def trigger_workflow(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send payload to the configured n8n webhook.
        Returns dict with status and details.
        """
        if not self.webhook_url:
            return {"status": "error", "error": "no_webhook_configured"}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.post(self.webhook_url, json=payload)
                resp.raise_for_status()
                return {"status": "sent", "status_code": resp.status_code, "response_text": resp.text}
            except httpx.HTTPStatusError as e:
                return {"status": "error", "error": f"HTTPStatusError: {e.response.status_code}", "detail": e.response.text}
            except Exception as e:
                return {"status": "error", "error": str(e)}
