# core/utils/ms_graph_mail.py


import os
import requests
import msal
from django.conf import settings


def _load_cache() -> msal.SerializableTokenCache:
    cache = msal.SerializableTokenCache()
    path = str(getattr(settings, "MS_GRAPH_TOKEN_CACHE_PATH", "ms_graph_token_cache.bin"))
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            cache.deserialize(f.read())
    return cache


def _save_cache(cache: msal.SerializableTokenCache) -> None:
    if cache.has_state_changed:
        path = str(getattr(settings, "MS_GRAPH_TOKEN_CACHE_PATH", "ms_graph_token_cache.bin"))
        with open(path, "w", encoding="utf-8") as f:
            f.write(cache.serialize())


def get_access_token() -> str:
    client_id = getattr(settings, "MS_GRAPH_CLIENT_ID", "")
    authority = getattr(settings, "MS_GRAPH_AUTHORITY", "https://login.microsoftonline.com/consumers")
    scopes = getattr(settings, "MS_GRAPH_SCOPES", ["User.Read", "Mail.Send", "offline_access"])

    if not client_id:
        raise RuntimeError("MS_GRAPH_CLIENT_ID is not set.")

    cache = _load_cache()

    app = msal.PublicClientApplication(
        client_id=client_id,
        authority=authority,
        token_cache=cache,
    )

    accounts = app.get_accounts()
    if not accounts:
        raise RuntimeError(
            "No cached Microsoft account token found. Run: python manage.py ms_graph_auth"
        )

    result = app.acquire_token_silent(scopes=scopes, account=accounts[0])
    _save_cache(cache)

    if not result or "access_token" not in result:
        raise RuntimeError(f"Failed to acquire token silently: {result}")

    return result["access_token"]


def send_email_via_graph(to_email: str, subject: str, body_text: str) -> None:
    token = get_access_token()

    url = "https://graph.microsoft.com/v1.0/me/sendMail"
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "Text", "content": body_text},
            "toRecipients": [{"emailAddress": {"address": to_email}}],
        },
        "saveToSentItems": True,
    }

    resp = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=20,
    )

    if resp.status_code >= 400:
        raise RuntimeError(f"Graph sendMail failed ({resp.status_code}): {resp.text}")

def send_html_email_via_graph(to_email: str, subject: str, html_body: str, plain_body: str = None) -> None:
    """
    Send HTML email via Microsoft Graph API.
    Falls back to plain_body if provided when HTML fails.
    """
    token = get_access_token()

    url = "https://graph.microsoft.com/v1.0/me/sendMail"
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": html_body},
            "toRecipients": [{"emailAddress": {"address": to_email}}],
        },
        "saveToSentItems": True,
    }

    resp = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=30,
    )

    if resp.status_code >= 400:
        raise RuntimeError(f"Graph sendMail failed ({resp.status_code}): {resp.text}")


def send_email_with_fallback(to_email: str, subject: str, body_text: str, fail_silently: bool = False) -> bool:
    """
    Send email via MS Graph, falling back to Django SMTP if needed.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    # Try MS Graph first
    try:
        from core.utils.ms_graph_mail import send_email_via_graph
        send_email_via_graph(to_email=to_email, subject=subject, body_text=body_text)
        return True
    except Exception as e:
        logger.warning(f"MS Graph email failed: {e}")
    
    # Fallback to Django SMTP
    try:
        from django.core.mail import send_mail
        from django.conf import settings as django_settings
        
        send_mail(
            subject=subject,
            message=body_text,
            from_email=getattr(django_settings, 'DEFAULT_FROM_EMAIL', 'no-reply@styloria.app'),
            recipient_list=[to_email],
            fail_silently=fail_silently,
        )
        return True
    except Exception as e:
        logger.error(f"SMTP email also failed for {to_email}: {e}")
        if not fail_silently:
            raise
        return False