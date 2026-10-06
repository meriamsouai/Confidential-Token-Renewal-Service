"""SMTP email notifications for token lifecycle events."""

from __future__ import annotations

import html
import logging
import smtplib
import ssl
from email.message import EmailMessage

from app.config import settings
from app.models import ManagedToken, User

logger = logging.getLogger("ctrs.notifications")

DASHBOARD_LINK_LABEL = "Open the CTRS dashboard"


def smtp_configured() -> bool:
    return bool(settings.smtp_host and (settings.smtp_from or settings.smtp_user))


def send_email(to: str, subject: str, body_plain: str, body_html: str | None = None) -> bool:
    if not to:
        logger.warning("No recipient email; skipping notification")
        return False
    if not smtp_configured():
        logger.warning("SMTP not configured; skipping email to %s (%s)", to, subject)
        return False

    sender = settings.smtp_from or settings.smtp_user
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body_plain)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    try:
        if settings.smtp_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                if settings.smtp_user:
                    server.login(settings.smtp_user, settings.smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as server:
                if settings.smtp_user:
                    server.login(settings.smtp_user, settings.smtp_password)
                server.send_message(msg)
        logger.info("Sent email to %s: %s", to, subject)
        return True
    except Exception:
        logger.exception("Failed to send email to %s (%s)", to, subject)
        return False


def _dashboard_url() -> str:
    return (settings.dashboard_url or "http://127.0.0.1:5173").rstrip("/")


def _dashboard_hint_plain() -> str:
    # Plain-text clients: label only; URL kept as bare link for clickability.
    return f"{DASHBOARD_LINK_LABEL}\n{_dashboard_url()}"


def _dashboard_hint_html() -> str:
    url = html.escape(_dashboard_url(), quote=True)
    label = html.escape(DASHBOARD_LINK_LABEL)
    return f'<a href="{url}">{label}</a>'


def _wrap_html(paragraphs: list[str]) -> str:
    """Build a simple HTML body; paragraphs may already contain HTML (e.g. the dashboard link)."""
    parts = []
    for p in paragraphs:
        parts.append(f"<p>{p}</p>")
    return (
        "<!DOCTYPE html><html><body style=\"font-family:sans-serif;line-height:1.45\">"
        + "".join(parts)
        + "</body></html>"
    )


def notify_token_created(user: User | None, token: ManagedToken) -> None:
    if not user or not user.notify_email_enabled:
        return
    name = user.name or user.username
    plain = (
        f"Hello {name},\n\n"
        f"A token was registered in CTRS.\n"
        f"  Name: {token.name}\n"
        f"  Id: {token.id}\n"
        f"  Target: {token.target_system}\n"
        f"  Expires: {token.expires_at}\n\n"
        f"{_dashboard_hint_plain()}\n"
    )
    html_body = _wrap_html(
        [
            f"Hello {html.escape(name)},",
            "A token was registered in CTRS.",
            (
                f"<strong>Name:</strong> {html.escape(str(token.name))}<br>"
                f"<strong>Id:</strong> {html.escape(str(token.id))}<br>"
                f"<strong>Target:</strong> {html.escape(str(token.target_system))}<br>"
                f"<strong>Expires:</strong> {html.escape(str(token.expires_at))}"
            ),
            _dashboard_hint_html(),
        ]
    )
    send_email(user.email, f"[CTRS] Token registered: {token.name}", plain, html_body)


def notify_token_rotated(user: User | None, token: ManagedToken, message: str = "") -> None:
    if not user or not user.notify_email_enabled:
        return
    name = user.name or user.username
    detail = message or "n/a"
    plain = (
        f"Hello {name},\n\n"
        f"A token was rotated successfully.\n"
        f"  Name: {token.name}\n"
        f"  Id: {token.id}\n"
        f"  New expiry: {token.expires_at}\n"
        f"  Detail: {detail}\n\n"
        f"Your CI handle is unchanged.\n\n"
        f"{_dashboard_hint_plain()}\n"
    )
    html_body = _wrap_html(
        [
            f"Hello {html.escape(name)},",
            "A token was rotated successfully.",
            (
                f"<strong>Name:</strong> {html.escape(str(token.name))}<br>"
                f"<strong>Id:</strong> {html.escape(str(token.id))}<br>"
                f"<strong>New expiry:</strong> {html.escape(str(token.expires_at))}<br>"
                f"<strong>Detail:</strong> {html.escape(detail)}"
            ),
            "Your CI handle is unchanged.",
            _dashboard_hint_html(),
        ]
    )
    send_email(user.email, f"[CTRS] Token rotated: {token.name}", plain, html_body)


def notify_token_revoked(user: User | None, token: ManagedToken, reason: str = "") -> None:
    if not user or not user.notify_email_enabled:
        return
    name = user.name or user.username
    why = reason or "revoked"
    plain = (
        f"Hello {name},\n\n"
        f"A token was revoked.\n"
        f"  Name: {token.name}\n"
        f"  Id: {token.id}\n"
        f"  Reason: {why}\n\n"
        f"Later exchanges with this handle will fail.\n\n"
        f"{_dashboard_hint_plain()}\n"
    )
    html_body = _wrap_html(
        [
            f"Hello {html.escape(name)},",
            "A token was revoked.",
            (
                f"<strong>Name:</strong> {html.escape(str(token.name))}<br>"
                f"<strong>Id:</strong> {html.escape(str(token.id))}<br>"
                f"<strong>Reason:</strong> {html.escape(why)}"
            ),
            "Later exchanges with this handle will fail.",
            _dashboard_hint_html(),
        ]
    )
    send_email(user.email, f"[CTRS] Token revoked: {token.name}", plain, html_body)


def notify_token_expiring_soon(user: User | None, token: ManagedToken, days_left: float) -> None:
    if not user or not user.notify_email_enabled:
        return
    name = user.name or user.username
    plain = (
        f"Hello {name},\n\n"
        f"A managed token will expire soon.\n"
        f"  Name: {token.name}\n"
        f"  Id: {token.id}\n"
        f"  Expires: {token.expires_at}\n"
        f"  Days left: {days_left:.1f}\n\n"
        f"CTRS will attempt automatic renewal if configured.\n\n"
        f"{_dashboard_hint_plain()}\n"
    )
    html_body = _wrap_html(
        [
            f"Hello {html.escape(name)},",
            "A managed token will expire soon.",
            (
                f"<strong>Name:</strong> {html.escape(str(token.name))}<br>"
                f"<strong>Id:</strong> {html.escape(str(token.id))}<br>"
                f"<strong>Expires:</strong> {html.escape(str(token.expires_at))}<br>"
                f"<strong>Days left:</strong> {days_left:.1f}"
            ),
            "CTRS will attempt automatic renewal if configured.",
            _dashboard_hint_html(),
        ]
    )
    send_email(user.email, f"[CTRS] Token expiring soon: {token.name}", plain, html_body)
