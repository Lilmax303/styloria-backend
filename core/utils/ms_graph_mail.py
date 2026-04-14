# core/utils/ms_graph_mail.py

import base64
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from django.conf import settings

logger = logging.getLogger(__name__)

TOKEN_URI = "https://oauth2.googleapis.com/token"
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]


def _get_gmail_service():
    """Build Gmail API service using OAuth2 refresh token."""
    credentials = Credentials(
        token=None,
        refresh_token=settings.GMAIL_REFRESH_TOKEN,
        token_uri=TOKEN_URI,
        client_id=settings.GMAIL_CLIENT_ID,
        client_secret=settings.GMAIL_CLIENT_SECRET,
        scopes=SCOPES,
    )
    service = build("gmail", "v1", credentials=credentials)
    return service


def _build_message(from_email, to_email, subject, body_text, html_message=None):
    """Build a MIME email message."""
    if html_message:
        message = MIMEMultipart("alternative")
        message.attach(MIMEText(body_text, "plain"))
        message.attach(MIMEText(html_message, "html"))
    else:
        message = MIMEText(body_text, "plain")

    message["to"] = to_email
    message["from"] = from_email
    message["subject"] = subject

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")
    return {"raw": raw}


def send_email_with_fallback(
    to_email,
    subject,
    body_text,
    html_message=None,
    fail_silently=False,
    from_email=None,
):
    """
    Send email using Gmail API (HTTPS, not SMTP).

    Parameters:
    - to_email: Single email string or list of emails
    - subject: Email subject
    - body_text: Plain text body
    - html_message: Optional HTML body
    - fail_silently: If True, suppress exceptions
    - from_email: Optional sender email (defaults to DEFAULT_FROM_EMAIL)
    """
    try:
        sender = from_email or settings.DEFAULT_FROM_EMAIL
        if not sender:
            raise ValueError("No sender email configured")

        service = _get_gmail_service()

        recipients = [to_email] if isinstance(to_email, str) else list(to_email)

        for recipient in recipients:
            msg = _build_message(sender, recipient, subject, body_text, html_message)
            service.users().messages().send(userId="me", body=msg).execute()
            logger.info(f"Email sent successfully to {recipient}")

        return True

    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        if fail_silently:
            return False
        raise