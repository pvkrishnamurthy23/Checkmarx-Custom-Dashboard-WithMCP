"""Notification channels (spec section 13): SMTP email (HTML) and generic webhook (Slack/Teams JSON).

Both are blocking and are called from a worker thread. Secrets (SMTP password, webhook URL)
come from settings only and are never logged.
"""

from __future__ import annotations

import logging
import re
import smtplib
import ssl
from email.message import EmailMessage
from typing import Protocol

import httpx

from cxdash.config import Settings

log = logging.getLogger(__name__)
_EMAIL = re.compile(r"^[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+$")
_CRLF = re.compile(r"[\r\n]+")


class NotifyError(RuntimeError):
    pass


class Notifier(Protocol):
    name: str

    def available(self) -> bool: ...
    def send(self, subject: str, text: str, html: str | None, recipients: list[str]) -> None: ...


class EmailNotifier:
    name = "email"

    def __init__(self, settings: Settings) -> None:
        self._s = settings

    def available(self) -> bool:
        return bool(self._s.smtp_host and self._s.alert_email_from)

    def send(self, subject: str, text: str, html: str | None, recipients: list[str]) -> None:
        to = [r.strip() for r in recipients if _EMAIL.match(r.strip())]
        if not to:
            raise NotifyError("no valid email recipients")
        msg = EmailMessage()
        msg["Subject"] = _CRLF.sub(" ", subject)[:200]  # header-injection safe
        msg["From"] = self._s.alert_email_from
        msg["To"] = ", ".join(to)
        msg.set_content(text)
        if html:
            msg.add_alternative(html, subtype="html")
        try:
            with smtplib.SMTP(self._s.smtp_host, self._s.smtp_port, timeout=20) as smtp:
                if self._s.smtp_port != 25:
                    smtp.starttls(context=ssl.create_default_context())
                if self._s.smtp_user:
                    smtp.login(self._s.smtp_user, self._s.smtp_password.get_secret_value())
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise NotifyError(f"smtp send failed: {type(exc).__name__}") from exc


class WebhookNotifier:
    name = "webhook"

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self._url = settings.alert_webhook_url.get_secret_value()
        self._transport = transport

    def available(self) -> bool:
        return self._url.startswith("https://") or self._url.startswith("http://")

    def send(self, subject: str, text: str, html: str | None, recipients: list[str]) -> None:
        body = {
            "text": f"*{subject}*\n{text}"[:3500]
        }  # Slack and Teams incoming webhooks both accept {"text": ...}
        try:
            with httpx.Client(timeout=15, transport=self._transport, follow_redirects=False) as client:
                resp = client.post(self._url, json=body)
        except httpx.HTTPError as exc:
            raise NotifyError(f"webhook failed: {type(exc).__name__}") from exc
        if resp.status_code >= 300:
            raise NotifyError(f"webhook returned HTTP {resp.status_code}")


def default_notifiers(settings: Settings) -> dict[str, Notifier]:
    return {"email": EmailNotifier(settings), "webhook": WebhookNotifier(settings)}
