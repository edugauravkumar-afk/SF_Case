#!/usr/bin/env python3
"""Simple SMTP email sender for run notifications."""
from __future__ import annotations

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Iterable


def _split_recipients(value: str | None) -> list[str]:
    if not value:
        return []
    parts = [item.strip() for item in value.split(",")]
    return [item for item in parts if item]


class EmailSender:
    def __init__(self) -> None:
        self.smtp_server = os.getenv("SMTP_SERVER", "")
        self.smtp_port = int(os.getenv("SMTP_PORT", "25") or "25")
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.from_email = os.getenv("FROM_EMAIL", "") or os.getenv("SENDER_EMAIL", "")
        self.recipients = _split_recipients(os.getenv("RECIPIENTS") or os.getenv("RECIPIENT_EMAILS"))
        self.cc_recipients = _split_recipients(os.getenv("CC_RECIPIENTS"))

    def is_configured(self) -> bool:
        return bool(self.smtp_server and self.from_email and self.recipients)

    def send(self, subject: str, html_body: str) -> None:
        if not self.is_configured():
            return

        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = self.from_email
        message["To"] = ", ".join(self.recipients)
        if self.cc_recipients:
            message["Cc"] = ", ".join(self.cc_recipients)

        message.attach(MIMEText(html_body, "html"))

        recipients: Iterable[str] = list(self.recipients) + list(self.cc_recipients)
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            if self.smtp_port == 587:
                server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
            server.sendmail(self.from_email, list(recipients), message.as_string())


class GeoEdgeEmailReporter:
    def __init__(self) -> None:
        self._sender = EmailSender()

    def send_run_report(self, subject: str, html_body: str) -> None:
        self._sender.send(subject, html_body)
