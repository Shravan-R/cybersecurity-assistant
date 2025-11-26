# responders/email_alert.py
import smtplib
import ssl
import time
from email.message import EmailMessage
from typing import Dict, Optional

class EmailAlert:
    """
    Simple SMTP/TLS email sender with basic retry/backoff.
    Expects:
      smtp_host, smtp_port, smtp_user, smtp_pass, from_addr
    Use TLS (STARTTLS) by default.
    """

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_user: Optional[str] = None,
        smtp_pass: Optional[str] = None,
        from_addr: Optional[str] = None,
        use_tls: bool = True,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = int(smtp_port)
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.from_addr = from_addr or smtp_user
        self.use_tls = use_tls

    def send_email(self, to_addrs, subject: str, body: str, max_retries: int = 3, retry_delay: float = 1.0) -> Dict:
        """
        Send a plaintext email. 'to_addrs' can be str or list.
        Returns dict with status.
        """
        if isinstance(to_addrs, str):
            to_addrs = [to_addrs]

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(to_addrs)
        msg.set_content(body)

        attempt = 0
        while attempt < max_retries:
            try:
                context = ssl.create_default_context()
                with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=20) as server:
                    server.ehlo()
                    if self.use_tls:
                        server.starttls(context=context)
                        server.ehlo()
                    if self.smtp_user and self.smtp_pass:
                        server.login(self.smtp_user, self.smtp_pass)
                    server.send_message(msg)
                return {"status": "sent", "attempts": attempt + 1}
            except Exception as e:
                attempt += 1
                if attempt >= max_retries:
                    return {"status": "error", "error": str(e), "attempts": attempt}
                time.sleep(retry_delay * attempt)
