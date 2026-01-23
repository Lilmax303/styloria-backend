# core/utils/ms_graph_mail.py

import os
import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
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
    Send email using SendGrid HTTP API.
    
    Parameters:
    - to_email: Single email string or list of emails
    - subject: Email subject
    - body_text: Plain text body
    - html_message: Optional HTML body
    - fail_silently: If True, suppress exceptions
    - from_email: Optional sender email (defaults to DEFAULT_FROM_EMAIL)
    """
    try:
        api_key = os.environ.get('SENDGRID_API_KEY')
        if not api_key:
            raise ValueError("SENDGRID_API_KEY not set")
        
        sg = SendGridAPIClient(api_key)
        
        # Use provided from_email or default
        sender_email = from_email or getattr(settings, 'DEFAULT_FROM_EMAIL', None)
        if not sender_email:
            raise ValueError("No sender email configured")
        
        # Handle single recipient or list
        recipients = [to_email] if isinstance(to_email, str) else list(to_email)
        
        for recipient in recipients:
            mail = Mail(
                from_email=Email(sender_email),
                to_emails=To(recipient),
                subject=subject,
                plain_text_content=Content("text/plain", body_text),
            )
            
            # Add HTML content if provided
            if html_message:
                mail.add_content(Content("text/html", html_message))
            
            response = sg.send(mail)
            logger.info(f"Email sent to {recipient}, status: {response.status_code}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        if fail_silently:
            return False
        raise