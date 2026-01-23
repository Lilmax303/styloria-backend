# core/utils/ms_graph_mail.py

import os
import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from django.conf import settings

logger = logging.getLogger(__name__)

def send_email_with_fallback(subject, message, from_email, recipient_list, html_message=None):
    """
    Send email using SendGrid HTTP API.
    More reliable than SMTP on cloud platforms.
    """
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        
        from_email_addr = from_email or settings.DEFAULT_FROM_EMAIL
        
        # Handle single recipient or list
        if isinstance(recipient_list, str):
            recipient_list = [recipient_list]
        
        for recipient in recipient_list:
            mail = Mail(
                from_email=Email(from_email_addr),
                to_emails=To(recipient),
                subject=subject,
                plain_text_content=Content("text/plain", message),
            )
            
            # Add HTML content if provided
            if html_message:
                mail.add_content(Content("text/html", html_message))
            
            response = sg.send(mail)
            logger.info(f"Email sent to {recipient}, status: {response.status_code}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return False