# responders/slack_alert.py
import requests
from typing import Dict, Optional

class SlackAlert:
    """
    Post a message to a Slack Incoming Webhook.
    Provide 'webhook_url' (incoming webhook). Optionally set a username and channel in payload.
    """

    def __init__(self, webhook_url: Optional[str]):
        self.webhook_url = webhook_url

    def post_message(self, text: str, username: Optional[str] = None, channel: Optional[str] = None, blocks: Optional[list] = None) -> Dict:
        """
        Sends a message. Returns status dict.
        """
        if not self.webhook_url:
            return {"status": "error", "error": "no_webhook_configured"}

        payload = {"text": text}
        if username:
            payload["username"] = username
        if channel:
            payload["channel"] = channel
        if blocks:
            payload["blocks"] = blocks

        try:
            r = requests.post(self.webhook_url, json=payload, timeout=10)
            r.raise_for_status()
            return {"status": "sent", "status_code": r.status_code, "response_text": r.text}
        except requests.HTTPError as e:
            return {"status": "error", "error": f"HTTPError: {e.response.status_code}", "detail": e.response.text}
        except Exception as e:
            return {"status": "error", "error": str(e)}
