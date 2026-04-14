# core/utils/ms_graph_mail.py

import logging
from django.core.mail import EmailMultiAlternatives
from django.conf import settings

logger = logging.getLogger(__name__)


def send_email_with_fallback(
    to_email,
    subject,
    body_text,
    html_message=None,
    fail_silently=False,
    from_email=None,
):
    """
    Send email using Django's SMTP backend (Gmail).

    Parameters:
    - to_email: Single email string or list of emails
    - subject: Email subject
    - body_text: Plain text body
    - html_message: Optional HTML body
    - fail_silently: If True, suppress exceptions
    - from_email: Optional sender email (defaults to DEFAULT_FROM_EMAIL)
    """
    try:
        sender_email = from_email or getattr(settings, 'DEFAULT_FROM_EMAIL', None)
        if not sender_email:
            raise ValueError("No sender email configured (DEFAULT_FROM_EMAIL)")

        # Handle single recipient or list
        recipients = [to_email] if isinstance(to_email, str) else list(to_email)

        msg = EmailMultiAlternatives(
            subject=subject,
            body=body_text,
            from_email=sender_email,
            to=recipients,
        )

        if html_message:
            msg.attach_alternative(html_message, "text/html")

        msg.send(fail_silently=False)
        logger.info(f"Email sent successfully to {recipients}")
        return True

    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        if fail_silently:
            return False
        raise