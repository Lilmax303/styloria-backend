# core/utils/ms_graph_mail.py

import logging
from django.core.mail import send_mail as django_send_mail
from django.core.mail import EmailMultiAlternatives
from django.conf import settings

logger = logging.getLogger(__name__)


def send_email_via_graph(to_email: str, subject: str, body_text: str) -> None:
    """
    Send plain text email via Django SMTP.
    Named 'via_graph' for backward compatibility, but uses SMTP.
    """
    logger.info(f"Sending email to {to_email}: {subject}")
    
    django_send_mail(
        subject=subject,
        message=body_text,
        from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@styloria.app'),
        recipient_list=[to_email],
        fail_silently=False,
    )


def send_html_email_via_graph(to_email: str, subject: str, html_body: str, plain_body: str = None) -> None:
    """
    Send HTML email via Django SMTP.
    """
    logger.info(f"Sending HTML email to {to_email}: {subject}")
    
    text_content = plain_body or "Please view this email in an HTML-compatible email client."
    
    email = EmailMultiAlternatives(
        subject=subject,
        body=text_content,
        from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@styloria.app'),
        to=[to_email],
    )
    email.attach_alternative(html_body, "text/html")
    email.send(fail_silently=False)


def send_email_with_fallback(to_email: str, subject: str, body_text: str, fail_silently: bool = False) -> bool:
    """
    Send email via Django SMTP with error handling.
    """
    try:
        django_send_mail(
            subject=subject,
            message=body_text,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@styloria.app'),
            recipient_list=[to_email],
            fail_silently=fail_silently,
        )
        logger.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Email failed for {to_email}: {e}")
        if not fail_silently:
            raise
        return False