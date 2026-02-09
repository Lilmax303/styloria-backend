# core/views.py

from __future__ import annotations

from decimal import Decimal, ROUND_UP
import random
import string
from datetime import timedelta
import requests
from io import BytesIO
import uuid
import statistics
import os
import logging

logger = logging.getLogger(__name__)

import stripe
import json

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail
from django.db import transaction
from django.db.models import Avg
from django.http import HttpResponse, JsonResponse

from django.db.models import (
    Case,
    Count,
    DecimalField,
    Q,
    Sum,
    Value,
    When,
)
from django.db.models.functions import Coalesce, TruncDay, TruncMonth, TruncWeek, TruncYear

from django.shortcuts import render
from django.utils import timezone
from django.utils.html import escape
from django.views.generic import TemplateView
from geopy.distance import geodesic
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import RefreshToken
from twilio.rest import Client

from core.utils.stripe_money import from_minor_units
from core.utils.regions import is_african_country_name, parse_stripe_allowed_african_countries
from core.utils.currency import get_currency_for_country
from core.utils.paystack_countries import get_payment_gateway_for_country
from django.views.decorators.http import require_http_methods

from core.utils.paystack_countries import is_paystack_country, get_paystack_currency, get_payment_gateway_for_country
from core.services.paystack import (
    initialize_transaction as paystack_initialize,
    verify_transaction as paystack_verify,
    verify_webhook_signature as paystack_verify_webhook,
    list_banks as paystack_list_banks,
    resolve_account as paystack_resolve_account,
)
from core.services.payouts import finalize_paystack_payout_from_webhook

from core.services.payouts import (
    credit_provider_pending_from_request,
    payout_wallet,
    payout_wallet_flutterwave,
    finalize_flutterwave_payout_from_webhook,
    credit_provider_cancellation_fee,
    process_cancellation_refund,
    release_matured_pending_balances,
    payout_wallet_paystack,
)

from core.utils.trust_score import (
    calculate_provider_trust_score,
    get_provider_tier,
    is_provider_eligible_for_tier,
)

# Notification functions
from core.utils.notifications import (
    send_websocket_notification,
    notify_eligible_providers_of_new_job,
)

from core.utils.booking_cleanup import cancel_stale_unpaid_bookings

from .models import (
    AccountDeletionFeedback,
    ChatMessage,
    ChatThread,
    CustomUser,
    EmailVerificationCode,
    LocationUpdate,
    MFACode,
    Notification,
    PasswordResetCode,
    ProviderPortfolioMedia,
    ProviderPortfolioPost,
    Review,
    Referral,
    ServiceProvider,
    ProviderCertification,
    RequesterReview,
    ServiceProviderPricing,
    ServiceRequest,
    SupportMessage,
    SupportThread,
    ProviderWallet,
    WalletLedgerEntry,
    Payout,
    ProviderPayoutSettings,
    PasswordResetCode,
)
from .serializers import (
    ChatMessageSerializer,
    ChatThreadSerializer,
    ReviewSerializer,
    RequesterReviewSerializer,
    ServiceProviderSerializer,
    ServiceRequestSerializer,
    SupportMessageSerializer,
    SupportThreadSerializer,
    UserLocationCodesSerializer,
    UserSerializer,
    ProviderCertificationSerializer,
    ProviderWalletSerializer,
    WalletLedgerEntrySerializer,
    PayoutSerializer,
    ProviderPayoutSettingsSerializer,
)

User = get_user_model()



@csrf_exempt
@require_http_methods(["GET", "POST"])
def flutterwave_redirect(request):
    """
    Public landing page for Flutterwave redirectUrl.
    Handles both:
    1. Card payments: individual query params (status, tx_ref, transaction_id)
    2. Mobile money: JSON-encoded 'resp' parameter
    """
    import json
    from urllib.parse import unquote
    
    tx_ref = ""
    status_val = ""
    transaction_id = ""
    
    # Method 1: Try individual query parameters (card payments)
    tx_ref = (request.GET.get("tx_ref") or request.POST.get("tx_ref") or "").strip()
    status_val = (request.GET.get("status") or request.POST.get("status") or "").strip()
    transaction_id = (request.GET.get("transaction_id") or request.POST.get("transaction_id") or "").strip()
    
    # Method 2: Try JSON 'resp' parameter (mobile money payments)
    if not tx_ref or not transaction_id:
        resp_raw = request.GET.get("resp") or request.POST.get("resp") or ""
        if resp_raw:
            try:
                # URL decode and parse JSON
                resp_decoded = unquote(resp_raw)
                resp_json = json.loads(resp_decoded)
                
                # Extract from nested data object
                data = resp_json.get("data", {})
                if not tx_ref:
                    tx_ref = str(data.get("txRef", "") or data.get("tx_ref", "")).strip()
                if not transaction_id:
                    transaction_id = str(data.get("id", "")).strip()
                if not status_val:
                    # Flutterwave uses "successful" in data.status for success
                    data_status = str(data.get("status", "")).strip().lower()
                    if data_status == "successful":
                        status_val = "successful"
                    elif data_status:
                        status_val = data_status
                    else:
                        # Fallback to top-level status
                        status_val = str(resp_json.get("status", "")).strip()
            except (json.JSONDecodeError, TypeError, AttributeError) as e:
                # Log for debugging but don't crash
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to parse Flutterwave resp param: {e}")
    
    # Method 3: Try 'data' parameter (some Flutterwave versions)
    if not tx_ref or not transaction_id:
        data_raw = request.GET.get("data") or request.POST.get("data") or ""
        if data_raw:
            try:
                data_decoded = unquote(data_raw)
                data_json = json.loads(data_decoded)
                if not tx_ref:
                    tx_ref = str(data_json.get("txRef", "") or data_json.get("tx_ref", "")).strip()
                if not transaction_id:
                    transaction_id = str(data_json.get("id", "") or data_json.get("transaction_id", "")).strip()
                if not status_val:
                    status_val = str(data_json.get("status", "")).strip()
            except (json.JSONDecodeError, TypeError, AttributeError):
                pass
    
    # Escape for HTML output
    tx_ref = escape(tx_ref)
    status_val = escape(status_val)
    transaction_id = escape(transaction_id)
    
    # Build deep link
    scheme = getattr(settings, "APP_DEEPLINK_SCHEME", "styloria").strip() or "styloria"
    deeplink = f"{scheme}://payment-return?status={status_val}&tx_ref={tx_ref}&transaction_id={transaction_id}"
    
    # Log for debugging
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Flutterwave redirect: status={status_val}, tx_ref={tx_ref}, transaction_id={transaction_id}")

    html = f"""
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width,initial-scale=1" />
        <title>Payment complete</title>
        <style>
          body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; padding: 24px; }}
          .card {{ max-width: 520px; margin: 0 auto; border: 1px solid #e5e7eb; border-radius: 12px; padding: 18px; }}
          .title {{ font-weight: 800; font-size: 18px; margin-bottom: 8px; }}
          .muted {{ color: #6b7280; font-size: 14px; }}
          .btn {{ display: inline-block; margin-top: 14px; padding: 10px 14px; border-radius: 10px; background: #16a34a; color: white; text-decoration: none; font-weight: 700; }}
          .sub {{ margin-top: 10px; font-size: 12px; color: #6b7280; word-break: break-all; }}
          .success {{ color: #16a34a; }}
          .pending {{ color: #f59e0b; }}
          .failed {{ color: #dc2626; }}
        </style>
      </head>
      <body>
        <div class="card">
          <div class="title">Payment complete</div>
          <div class="muted">You can now return to the Styloria app to finish verification and continue.</div>
          <a class="btn" href="{deeplink}">Return to app</a>
          <div class="sub">
            status: <span class="{'success' if status_val.lower() == 'successful' else 'pending' if status_val else ''}">{status_val or "-"}</span><br/>
            tx_ref: {tx_ref or "-"}<br/>
            transaction_id: {transaction_id or "-"}
          </div>
        </div>
        <script>
          // Auto-redirect to app after 2 seconds (if deep links work)
          setTimeout(function() {{
            window.location.href = "{deeplink}";
          }}, 2000);
        </script>
      </body>
    </html>
    """
    return HttpResponse(html, content_type="text/html")


# -------------------------
# CERTIFICATION REQUIREMENT HELPERS
# -------------------------

def _check_service_certification_requirement(provider, service_type: str) -> dict | None:
    """
    Check if a service requires certification and if the provider has it.
    Returns error dict if requirement not met, None if OK.
    """
    from core.models import CERTIFICATION_REQUIRED_SERVICES, ProviderCertification
    
    service_type_lower = service_type.lower().strip()
    
    if service_type_lower not in CERTIFICATION_REQUIRED_SERVICES:
        return None  # No certification required for this service
    
    requirement = CERTIFICATION_REQUIRED_SERVICES[service_type_lower]
    keywords = requirement['keywords']
    message = requirement['message']
    
    # Check if provider has a VERIFIED certification matching any keyword
    has_verified_cert = ProviderCertification.objects.filter(
        provider=provider,
        is_verified=True,
    ).exists()
    
    if not has_verified_cert:
        return {
            "detail": message,
            "error_code": "certification_required",
            "service_type": service_type,
            "requirement": {
                "service": service_type,
                "keywords": keywords,
                "has_any_verified_cert": False,
                "has_matching_cert": False,
            },
        }
    
    # Check if any verified certification matches the keywords (case-insensitive)
    from django.db.models import Q
    keyword_query = Q()
    for keyword in keywords:
        keyword_query |= Q(name__icontains=keyword)

    matching_cert = ProviderCertification.objects.filter(
        provider=provider,
        is_verified=True,
    ).filter(keyword_query).first()
    
    if not matching_cert:
        return {
            "detail": f"{message} Please ensure your certification name includes relevant keywords (e.g., 'massage therapy', 'licensed massage therapist').",
            "error_code": "certification_required",
            "service_type": service_type,
            "requirement": {
                "service": service_type,
                "keywords": keywords,
                "has_any_verified_cert": True,
                "has_matching_cert": False,
            },
        }
    
    # Check if certification is expired
    if matching_cert.is_expired:
        return {
            "detail": f"Your massage certification '{matching_cert.name}' has expired. Please upload a valid certification.",
            "error_code": "certification_expired",
            "service_type": service_type,
        }
    
    return None  # All checks passed


def _get_provider_certification_status(provider) -> dict:
    """
    Get certification status for all services that require certification.
    Returns dict like: {'massage': {'has_verified_cert': True, 'cert_name': 'LMT License'}}
    """
    from core.models import CERTIFICATION_REQUIRED_SERVICES, ProviderCertification
    from django.db.models import Q
    
    status = {}
    
    for service_type, requirement in CERTIFICATION_REQUIRED_SERVICES.items():
        keywords = requirement['keywords']

        # Build query for matching keywords
        keyword_query = Q()
        for keyword in keywords:
            keyword_query |= Q(name__icontains=keyword)
        
        # Find matching verified certification
        matching_cert = ProviderCertification.objects.filter(
            provider=provider,
            is_verified=True,
        ).filter(keyword_query).first()
        
        # Also check for pending (uploaded but not yet verified)
        pending_cert = ProviderCertification.objects.filter(
            provider=provider,
            is_verified=False,
        ).filter(keyword_query).first()

        is_expired = False
        if matching_cert and hasattr(matching_cert, 'is_expired'):
            is_expired = matching_cert.is_expired        

        status[service_type] = {
            'required': True,
            'has_verified_cert': matching_cert is not None,
            'is_expired': matching_cert.is_expired if matching_cert else False,
            'cert_name': matching_cert.name if matching_cert else None,
            'cert_id': matching_cert.id if matching_cert else None,
            'has_pending_cert': pending_cert is not None,
            'pending_cert_name': pending_cert.name if pending_cert else None,
            'keywords': keywords,
            'message': requirement['message'],
        }
    
    return status


# ============================================================
# ADMIN PAYOUT DASHBOARD ENDPOINTS
# ============================================================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_payout_dashboard(request):
    """
    GET /api/admin/payouts/dashboard/
    Overview of payout system for admin
    """
    if not request.user.is_staff:
        return Response({"detail": "Admin access required"}, status=403)

    from django.db.models import Sum, Count
    from datetime import timedelta

    now = timezone.now()

    # Queued instant payouts
    queued_instant = Payout.objects.filter(
        status='queued',
        method='instant',
    ).select_related('provider__user', 'provider__payout_settings').order_by('-created_at')[:20]

    # Processing payouts
    processing_payouts = Payout.objects.filter(
        status='processing',
    ).select_related('provider__user').order_by('-created_at')[:20]

    # Failed payouts needing attention
    failed_payouts = Payout.objects.filter(
        status='failed',
    ).select_related('provider__user').order_by('-created_at')[:20]

    # Upcoming scheduled payouts (next 7 days)
    upcoming_providers = []
    for settings in ProviderPayoutSettings.objects.filter(
        auto_payout_enabled=True,
    ).select_related('provider__user')[:50]:
        next_date = settings.get_next_scheduled_payout_date()
        if next_date and next_date <= now + timedelta(days=7):
            # Get wallet balance
            wallets = ProviderWallet.objects.filter(provider=settings.provider)
            total_balance = sum(float(w.available_balance) for w in wallets)

            if total_balance > 0:
                upcoming_providers.append({
                    'provider_id': settings.provider_id,
                    'provider_name': settings.provider.user.get_full_name() or settings.provider.user.username,
                    'next_payout_date': next_date.isoformat(),
                    'frequency': settings.payout_frequency,
                    'payout_gateway': settings.payout_gateway,
                    'method': settings.flutterwave_method,
                    'available_balance': total_balance,
                    'currency': wallets.first().currency if wallets.exists() else 'USD',
                })

    # Sort by next payout date
    upcoming_providers.sort(key=lambda x: x['next_payout_date'])

    # Summary stats
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    paid_today_stats = Payout.objects.filter(
        status='paid',
        processed_at__gte=today_start,
    ).aggregate(
        count=Count('id'),
        total=Sum('net_amount'),
    )

    stats = {
        'queued_count': Payout.objects.filter(status='queued').count(),
        'processing_count': Payout.objects.filter(status='processing').count(),
        'failed_count': Payout.objects.filter(status='failed').count(),
        'paid_today_count': paid_today_stats['count'] or 0,
        'paid_today_total': float(paid_today_stats['total'] or 0),
    }

    def get_payout_info(payout):
        """Helper to extract payout info with account details"""
        try:
            settings = payout.provider.payout_settings
            if settings.payout_gateway == 'stripe':
                account = payout.provider.stripe_account_id or 'N/A'
                method = 'stripe'
            elif settings.flutterwave_method == 'mobile_money':
                account = settings.flutterwave_phone_number or 'N/A'
                method = 'mobile_money'
            else:
                account = settings.flutterwave_account_number or 'N/A'
                method = 'bank'
        except Exception:
            account = 'N/A'
            method = 'unknown'

        return {
            'id': payout.id,
            'provider_id': payout.provider_id,
            'provider_name': payout.provider.user.get_full_name() or payout.provider.user.username,
            'provider_email': payout.provider.user.email,
            'method': method,
            'account': account,
            'amount': float(payout.net_amount),
            'gross_amount': float(payout.gross_amount),
            'fee_amount': float(payout.fee_amount),
            'currency': payout.currency,
            'status': payout.status,
            'failure_reason': payout.failure_reason or '',
            'created_at': payout.created_at.isoformat(),
            'processed_at': payout.processed_at.isoformat() if payout.processed_at else None,
        }

    return Response({
        'stats': stats,
        'queued_instant_payouts': [get_payout_info(p) for p in queued_instant],
        'processing_payouts': [get_payout_info(p) for p in processing_payouts],
        'failed_payouts': [get_payout_info(p) for p in failed_payouts],
        'upcoming_scheduled': upcoming_providers[:20],
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def admin_process_payout(request, pk):
    """
    POST /api/admin/payouts/<id>/process/
    Manually trigger processing of a payout
    """
    if not request.user.is_staff:
        return Response({"detail": "Admin access required"}, status=403)

    try:
        payout = Payout.objects.select_related('provider').get(pk=pk)
    except Payout.DoesNotExist:
        return Response({"detail": "Payout not found"}, status=404)

    if payout.status not in ('queued', 'failed'):
        return Response({"detail": f"Cannot process payout with status: {payout.status}"}, status=400)

    from core.services.payouts import payout_wallet_routed, get_or_create_wallet

    try:
        # Reset if failed
        if payout.status == 'failed':
            payout.status = 'queued'
            payout.failure_reason = ''
            payout.save(update_fields=['status', 'failure_reason'])

        # Process the payout
        result = payout_wallet_routed(
            provider=payout.provider,
            currency=payout.currency,
            amount=payout.gross_amount,
            method=payout.method,
        )

        return Response({
            "detail": "Payout processed",
            "payout_id": result.id,
            "status": result.status,
        })
    except Exception as e:
        return Response({"detail": str(e)}, status=400)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def admin_mark_payout_paid(request, pk):
    """
    POST /api/admin/payouts/<id>/mark_paid/
    Manually mark a payout as paid (for manual transfers)
    """
    if not request.user.is_staff:
        return Response({"detail": "Admin access required"}, status=403)

    try:
        payout = Payout.objects.get(pk=pk)
    except Payout.DoesNotExist:
        return Response({"detail": "Payout not found"}, status=404)

    if payout.status == 'paid':
        return Response({"detail": "Payout already marked as paid"}, status=400)

    payout.status = 'paid'
    payout.processed_at = timezone.now()
    payout.save(update_fields=['status', 'processed_at'])

    return Response({
        "detail": "Payout marked as paid",
        "payout_id": payout.id,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_provider_payout_details(request, provider_id):
    """
    GET /api/admin/providers/<id>/payout_details/
    Get detailed payout settings and history for a provider
    """
    if not request.user.is_staff:
        return Response({"detail": "Admin access required"}, status=403)

    try:
        provider = ServiceProvider.objects.select_related('user').get(pk=provider_id)
    except ServiceProvider.DoesNotExist:
        return Response({"detail": "Provider not found"}, status=404)

    # Get payout settings
    try:
        settings = provider.payout_settings
        settings_data = {
            'payout_gateway': settings.payout_gateway,
            'payout_frequency': settings.payout_frequency,
            'payout_weekday': settings.payout_weekday,
            'payout_hour_utc': settings.payout_hour_utc,
            'auto_payout_enabled': settings.auto_payout_enabled,
            'instant_payout_enabled': settings.instant_payout_enabled,
            'minimum_payout_amount': float(settings.minimum_payout_amount),
            'flutterwave_method': settings.flutterwave_method,
            'flutterwave_currency': settings.flutterwave_currency,
            'flutterwave_full_name': settings.flutterwave_full_name,
            'flutterwave_phone_number': settings.flutterwave_phone_number,
            'flutterwave_bank_code': settings.flutterwave_bank_code,
            'flutterwave_account_number': settings.flutterwave_account_number,
            'instant_payouts_remaining': settings.get_instant_payouts_remaining(),
            'next_scheduled_payout': settings.get_next_scheduled_payout_date().isoformat() if settings.get_next_scheduled_payout_date() else None,
        }
    except ProviderPayoutSettings.DoesNotExist:
        settings_data = None

    # Get wallets
    wallets = ProviderWallet.objects.filter(provider=provider)
    wallets_data = [
        {
            'currency': w.currency,
            'available_balance': float(w.available_balance),
            'pending_balance': float(w.pending_balance),
            'lifetime_earnings': float(w.lifetime_earnings),
            'lifetime_payouts': float(w.lifetime_payouts),
        }
        for w in wallets
    ]

    # Get recent payouts
    payouts = Payout.objects.filter(provider=provider).order_by('-created_at')[:20]
    payouts_data = [
        {
            'id': p.id,
            'amount': float(p.net_amount),
            'currency': p.currency,
            'method': p.method,
            'status': p.status,
            'failure_reason': p.failure_reason,
            'created_at': p.created_at.isoformat(),
            'processed_at': p.processed_at.isoformat() if p.processed_at else None,
        }
        for p in payouts
    ]

    return Response({
        'provider': {
            'id': provider.id,
            'username': provider.user.username,
            'full_name': provider.user.get_full_name(),
            'email': provider.user.email,
            'stripe_account_id': provider.stripe_account_id,
        },
        'payout_settings': settings_data,
        'wallets': wallets_data,
        'recent_payouts': payouts_data,
    })


# -------------------------
# Currency utils (safe import + fallback)
# -------------------------
try:
    from .utils.currency import convert_amount, get_currency_symbol
except Exception:

    def convert_amount(amount: float, _from: str, _to: str) -> float:
        return float(amount)

    def get_currency_symbol(_currency: str) -> str:
        return "$"


# Penalty: 10% of offered_price if user cancels > 7 minutes after acceptance
USER_LATE_CANCEL_PENALTY_PERCENT = Decimal("0.10")

# Platform keeps 20% of total paid (service + transportation + service fee)
PLATFORM_FEE_PERCENT = Decimal(str(getattr(settings, "PLATFORM_FEE_PERCENT", "0.20")))

def _compute_split(total_paid: Decimal) -> tuple[Decimal, Decimal]:
    """
    Returns (platform_fee, provider_gross_share) from total paid by requester.
    Provider gross share = 80% of total paid.
    """
    platform_fee = (total_paid * PLATFORM_FEE_PERCENT).quantize(Decimal("0.01"))
    provider_gross = (total_paid - platform_fee).quantize(Decimal("0.01"))
    return platform_fee, provider_gross

def _compute_provider_net(provider_gross: Decimal | None, stripe_fee: Decimal | None) -> Decimal | None:
    if provider_gross is None:
        return None
    fee = stripe_fee or Decimal("0.00")
    net = (provider_gross - fee).quantize(Decimal("0.01"))
    if net < Decimal("0.00"):
        net = Decimal("0.00")
    return net


# -------------------------
# Guards / helpers
# -------------------------
def require_email_verified(user):
    if not user or not user.is_authenticated:
        return {"detail": "Authentication required."}
    if not getattr(user, "email_verified", False):
        return {"detail": "Verify your email to continue."}
    return None


def _require_provider_kyc_approved(user):
    """
    Return None if access allowed.
    Return a Response payload dict if blocked.
    """
    if not user or not user.is_authenticated:
        return {"detail": "Authentication required."}

    if getattr(user, "role", "") != "provider":
        return None

    try:
        provider = ServiceProvider.objects.get(user=user)
    except ServiceProvider.DoesNotExist:
        return {"detail": "Provider profile not found."}

    if provider.verification_status != "approved":
        return {
            "detail": "Complete KYC verification to access provider features.",
            "verification_status": provider.verification_status,
        }

    return None


# -------------------------------
# WebSocket Notification Helper
# -------------------------------
def send_websocket_notification(user, message, notification_type="info"):
    """
    Send real-time notification via WebSocket + save to DB.
    """
    Notification.objects.create(
        user=user,
        message=message,
        read=False,
        timestamp=timezone.now(),
    )

    channel_layer = get_channel_layer()
    user_room_group = f"notifications_{user.id}"

    try:
        async_to_sync(channel_layer.group_send)(
            user_room_group,
            {
                "type": "send_notification",
                "message": {
                    "type": notification_type,
                    "text": message,
                    "timestamp": timezone.now().isoformat(),
                },
            },
        )
    except Exception:
        # WebSocket might not be connected; ignore
        pass

# -------------------------------
# Google Directions API Helper
# -------------------------------
def get_route_eta(origin_lat, origin_lng, dest_lat, dest_lng):
    """
    Get route-based distance and ETA using Google Directions API.
    
    Returns:
        {
            "distance_meters": int,
            "distance_miles": float,
            "duration_seconds": int,
            "duration_minutes": float,
            "duration_text": str,  # e.g., "15 mins"
            "distance_text": str,  # e.g., "5.2 mi"
            "success": True
        }
        or {"success": False, "error": "..."} on failure
    """
    api_key = getattr(settings, "GOOGLE_MAPS_API_KEY", "")
    
    if not api_key:
        # Fallback to straight-line estimate if no API key
        from geopy.distance import geodesic
        distance_km = geodesic((origin_lat, origin_lng), (dest_lat, dest_lng)).km
        distance_miles = float(distance_km * 0.621371)
        # Estimate: average 25 mph in urban areas
        estimated_minutes = (distance_miles / 25) * 60
        
        return {
            "success": True,
            "distance_meters": int(distance_km * 1000),
            "distance_miles": round(distance_miles, 2),
            "duration_seconds": int(estimated_minutes * 60),
            "duration_minutes": round(estimated_minutes, 1),
            "duration_text": f"{int(estimated_minutes)} mins (est.)",
            "distance_text": f"{distance_miles:.1f} mi",
            "is_estimate": True,
        }
    
    try:
        url = "https://maps.googleapis.com/maps/api/directions/json"
        params = {
            "origin": f"{origin_lat},{origin_lng}",
            "destination": f"{dest_lat},{dest_lng}",
            "mode": "driving",
            "key": api_key,
        }
        
        response = requests.get(url, params=params, timeout=10)
        data = response.json()
        
        if data.get("status") != "OK":
            # Fallback to estimate
            from geopy.distance import geodesic
            distance_km = geodesic((origin_lat, origin_lng), (dest_lat, dest_lng)).km
            distance_miles = float(distance_km * 0.621371)
            estimated_minutes = (distance_miles / 25) * 60
            
            return {
                "success": True,
                "distance_meters": int(distance_km * 1000),
                "distance_miles": round(distance_miles, 2),
                "duration_seconds": int(estimated_minutes * 60),
                "duration_minutes": round(estimated_minutes, 1),
                "duration_text": f"{int(estimated_minutes)} mins (est.)",
                "distance_text": f"{distance_miles:.1f} mi",
                "is_estimate": True,
                "api_status": data.get("status"),
            }
        
        route = data["routes"][0]
        leg = route["legs"][0]
        
        distance_meters = leg["distance"]["value"]
        duration_seconds = leg["duration"]["value"]
        
        distance_miles = distance_meters / 1609.34
        duration_minutes = duration_seconds / 60
        
        return {
            "success": True,
            "distance_meters": distance_meters,
            "distance_miles": round(distance_miles, 2),
            "duration_seconds": duration_seconds,
            "duration_minutes": round(duration_minutes, 1),
            "duration_text": leg["duration"]["text"],
            "distance_text": f"{distance_miles:.1f} mi",
            "is_estimate": False,
        }
        
    except Exception as e:
        # Fallback to straight-line estimate
        from geopy.distance import geodesic
        distance_km = geodesic((origin_lat, origin_lng), (dest_lat, dest_lng)).km
        distance_miles = float(distance_km * 0.621371)
        estimated_minutes = (distance_miles / 25) * 60
        
        return {
            "success": True,
            "distance_meters": int(distance_km * 1000),
            "distance_miles": round(distance_miles, 2),
            "duration_seconds": int(estimated_minutes * 60),
            "duration_minutes": round(estimated_minutes, 1),
            "duration_text": f"{int(estimated_minutes)} mins (est.)",
            "distance_text": f"{distance_miles:.1f} mi",
            "is_estimate": True,
            "error": str(e),
        }


# -------------------------------
# Provider Arrival Detection
# -------------------------------
ARRIVAL_THRESHOLD_METERS = 150  # ~500 feet - considered "arrived"

def check_provider_arrived(provider_lat, provider_lng, dest_lat, dest_lng):
    """
    Check if provider is within arrival threshold of destination.
    Returns True if provider has arrived (within ~150 meters / 500 feet).
    """
    from geopy.distance import geodesic
    
    distance_meters = geodesic(
        (provider_lat, provider_lng),
        (dest_lat, dest_lng)
    ).meters
    
    return distance_meters <= ARRIVAL_THRESHOLD_METERS, distance_meters


# ═══════════════════════════════════════════════════════════════════
# REFERRAL SYSTEM CONSTANTS & HELPERS
# ═══════════════════════════════════════════════════════════════════

REFERRAL_DISCOUNT_PERCENT = Decimal("7.00")  # 7% discount
REFERRAL_CREDITS_PER_REFERRAL = 5  # 5 discounted bookings per successful referral


def apply_referral_discount_if_eligible(service_request, user):
    """
    Check if user has referral credits and apply discount.
    Returns (discounted_amount, discount_applied, discount_amount).
    
    IMPORTANT: The discount comes from platform fee, not provider's cut.
    """
    original_price = service_request.offered_price or service_request.estimated_price
    if original_price is None or original_price <= Decimal("0"):
        return original_price, False, Decimal("0")

    # IMPORTANT: Check if discount was already applied to this booking
    # This prevents multiple deductions on payment retry
    if service_request.referral_discount_applied:
        # Return the already-discounted price without deducting again
        discounted_price = service_request.offered_price or original_price
        discount_amount = service_request.referral_discount_amount or Decimal("0")
        return discounted_price, True, discount_amount
    
    # Check if user has referral credits
    if user.referral_credits <= 0:
        return original_price, False, Decimal("0")
    
    # Calculate discount (7% of total)
    discount_amount = (original_price * REFERRAL_DISCOUNT_PERCENT / Decimal("100")).quantize(Decimal("0.01"))
    discounted_price = (original_price - discount_amount).quantize(Decimal("0.01"))
    
    # Ensure discounted price is positive
    if discounted_price <= Decimal("0"):
        return original_price, False, Decimal("0")
    
    return discounted_price, True, discount_amount


def finalize_referral_discount(service_request, user, discount_amount, original_price):
    """
    Apply the referral discount to the service request and decrement user's credits.
    Call this when payment is being created (before sending to payment gateway).

    IMPORTANT: This function is idempotent - it won't deduct credits twice
    for the same booking.
    """
    from django.db import transaction

    # IDEMPOTENT CHECK: If discount already applied to this booking, don't deduct again
    if service_request.referral_discount_applied:
        return False
    
    with transaction.atomic():
        # Lock user for update
        user_locked = CustomUser.objects.select_for_update().get(pk=user.pk)
        
        if user_locked.referral_credits <= 0:
            return False

        # Lock service request too to prevent race conditions
        sr_locked = ServiceRequest.objects.select_for_update().get(pk=service_request.pk)
        
        # Double-check inside transaction (race condition protection)
        if sr_locked.referral_discount_applied:
            return False
        
        # Decrement credits
        user_locked.referral_credits -= 1
        user_locked.total_referral_credits_used += 1
        user_locked.save(update_fields=['referral_credits', 'total_referral_credits_used'])
        
        # Update service request
        sr_locked.referral_discount_applied = True
        sr_locked.referral_discount_percent = REFERRAL_DISCOUNT_PERCENT
        sr_locked.referral_discount_amount = discount_amount
        sr_locked.pre_discount_price = original_price
        sr_locked.save(update_fields=[
            'referral_discount_applied',
            'referral_discount_percent', 
            'referral_discount_amount',
            'pre_discount_price'
        ])

        # Refresh the original object to reflect changes
        service_request.refresh_from_db()
        
        return True


def check_and_award_referral_credits(service_request):
    """
    Check if this is the user's first paid booking and award referral credits
    to whoever referred them.
    
    Call this after payment is confirmed (in webhook/verify endpoints).
    """
    user = service_request.user
    
    # Check if user was referred
    if not user.referred_by:
        return False
    
    # Check if there's a pending referral record
    try:
        referral = Referral.objects.get(
            referrer=user.referred_by,
            referred_user=user,
            status='pending',
            credits_awarded=False
        )
    except Referral.DoesNotExist:
        return False
    
    # Check if this is user's first PAID booking
    first_paid_booking = ServiceRequest.objects.filter(
        user=user,
        payment_status='paid'
    ).order_by('request_time').first()
    
    # Only award if this is the first paid booking
    if first_paid_booking and first_paid_booking.pk == service_request.pk:
        referral.award_credits(qualifying_booking=service_request)
        
        # Send notification to referrer
        try:
            send_websocket_notification(
                referral.referrer,
                f"🎉 Great news! {user.first_name or user.username} just completed their first booking. "
                f"You've earned {referral.credits_amount} discount credits!",
                notification_type="referral_success"
            )
        except Exception:
            pass
        
        return True
    
    return False


def _compute_split_with_referral(paid_amount, service_request):
    """
    Compute platform/provider split accounting for referral discount.
    
    KEY: Provider gets 85% of ORIGINAL price (before discount).
    Platform absorbs the discount from their 15%.
    """
    if service_request.referral_discount_applied and service_request.pre_discount_price:
        original_price = service_request.pre_discount_price
    else:
        original_price = paid_amount
    
    # Provider always gets 85% of original price
    provider_gross = (original_price * Decimal("0.85")).quantize(Decimal("0.01"))
    
    # Platform gets whatever is left after provider
    platform_fee = (paid_amount - provider_gross).quantize(Decimal("0.01"))
    
    # Ensure platform fee doesn't go negative
    if platform_fee < Decimal("0"):
        platform_fee = Decimal("0")
    
    return platform_fee, provider_gross



# -------------------------------
# Permissions
# -------------------------------
class IsStyloriaAdmin(BasePermission):
    """
    DRF permission: allow only staff or role=admin.
    """

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and (user.is_staff or getattr(user, "role", "") == "admin")
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def admin_release_pending_balances(request):
    if not (request.user.is_staff or getattr(request.user, "role", "") == "admin"):
        return Response({"detail": "Admin access required."}, status=403)
    force = bool(request.data.get("force_mature", False))
    if force:
        WalletLedgerEntry.objects.filter(status="pending").update(available_at=timezone.now())
    moved = release_matured_pending_balances()
    return Response({"moved": moved, "forced": force}, status=200)


# -------------------------------
# Public Home and Dashboard Views
# -------------------------------
def is_admin_user(user):
    """
    Return True if this user is allowed to access the Styloria admin dashboard
    and admin-only APIs.
    """
    return user.is_authenticated and (user.is_staff or getattr(user, "role", "") == "admin")


def send_mfa_sms(to_number: str, code: str):
    """
    Send MFA code via Twilio SMS.
    """
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    message_body = f"Your Styloria verification code is: {code}"
    client.messages.create(
        body=message_body,
        from_=settings.TWILIO_FROM_NUMBER,
        to=to_number,
    )


def home(request):
    """
    Public landing page for the application.
    """
    return render(request, "core/home.html")


@user_passes_test(is_admin_user)
def admin_dashboard(request):
    """
    Custom Styloria admin dashboard.
    """
    total_users = CustomUser.objects.filter(role="user").count()
    total_providers = CustomUser.objects.filter(role="provider").count()
    total_admins = CustomUser.objects.filter(role="admin").count()

    total_bookings = ServiceRequest.objects.count()
    pending_bookings = ServiceRequest.objects.filter(status="pending").count()
    completed_bookings = ServiceRequest.objects.filter(status="completed").count()
    cancelled_bookings = ServiceRequest.objects.filter(status="cancelled").count()

    revenue_agg = ServiceRequest.objects.filter(
        status="completed",
        estimated_price__isnull=False,
    ).aggregate(total=Sum("estimated_price"))
    total_revenue = revenue_agg["total"] or 0

    recent_bookings = (
        ServiceRequest.objects.select_related("user", "service_provider__user")
        .order_by("-request_time")[:10]
    )
    recent_users = CustomUser.objects.order_by("-date_joined")[:10]
    recent_reviews = Review.objects.select_related("user", "service_provider__user").order_by("-created_at")[:10]

    context = {
        "total_users": total_users,
        "total_providers": total_providers,
        "total_admins": total_admins,
        "total_bookings": total_bookings,
        "pending_bookings": pending_bookings,
        "completed_bookings": completed_bookings,
        "cancelled_bookings": cancelled_bookings,
        "total_revenue": total_revenue,
        "recent_bookings": recent_bookings,
        "recent_users": recent_users,
        "recent_reviews": recent_reviews,
    }
    return render(request, "core/admin_dashboard.html", context)


@login_required
def dashboard(request):
    """
    Protected dashboard page showing user-specific information.
    """
    user_notifications = []
    context = {
        "user": request.user,
        "notifications": user_notifications,
        "page_title": "Dashboard",
    }
    return render(request, "core/dashboard.html", context)


class DashboardView(LoginRequiredMixin, TemplateView):
    """
    Alternative class-based dashboard view (optional).
    """

    template_name = "core/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["user"] = self.request.user
        context["page_title"] = "Dashboard"
        context["websocket_url"] = f"/ws/notifications/{self.request.user.id}/"
        return context


# -------------------------
# EMAIL VERIFICATION / PASSWORD RESET / USERNAME REMINDER
# -------------------------
def _generate_6_digit_code():
    return f"{random.randint(0, 999999):06d}"


@api_view(["POST"])
@permission_classes([AllowAny])
def send_email_verification(request):
    """
    Body: { "identifier": "user@example.com" } OR { "identifier": "username" }
    Always returns 200 to avoid leaking.
    Do not leak whether an email exists.
    """
    identifier = (request.data.get("identifier") or "").strip()
    if not identifier:
        return Response({"detail": "identifier is required."}, status=400)

    user = User.objects.filter(Q(email__iexact=identifier) | Q(username__iexact=identifier)).first()

    # Don't leak whether user exists
    if not user or not user.email:
        return Response({"detail": "If that account exists, a verification code was sent."}, status=200)

    if getattr(user, "email_verified", False):
        return Response({"detail": "Email already verified."}, status=200)

    EmailVerificationCode.objects.filter(user=user, used=False).update(used=True)

    code = _generate_6_digit_code()
    EmailVerificationCode.objects.create(
        user=user,
        code=code,
        expires_at=timezone.now() + timedelta(minutes=15),
        used=False,
    )

    from core.utils.ms_graph_mail import send_email_with_fallback
    
    send_email_with_fallback(
        to_email=user.email,
        subject="Verify your Styloria email",
        body_text=f"Your Styloria verification code is: {code}\n\nThis code expires in 15 minutes.",
        fail_silently=False,
    )

    return Response({"detail": "If that account exists, a verification code was sent."}, status=200)


@api_view(["POST"])
@permission_classes([AllowAny])
def confirm_email_verification(request):
    """
    Body: { "identifier": "email_or_username", "code": "123456" }
    """
    identifier = (request.data.get("identifier") or "").strip()
    code = (request.data.get("code") or "").strip()

    if not identifier or not code:
        return Response({"detail": "identifier and code are required."}, status=400)

    user = User.objects.filter(Q(email__iexact=identifier) | Q(username__iexact=identifier)).first()
    if not user:
        return Response({"detail": "Invalid code or identifier."}, status=400)

    if getattr(user, "email_verified", False):
        return Response({"detail": "Email already verified."}, status=200)

    obj = EmailVerificationCode.objects.filter(user=user, used=False).order_by("-created_at").first()
    if not obj:
        return Response({"detail": "No active verification code. Request a new one."}, status=400)

    if not obj.is_valid():
        obj.used = True
        obj.save(update_fields=["used"])
        return Response({"detail": "Code expired. Request a new one."}, status=400)

    if obj.code != code:
        return Response({"detail": "Invalid code."}, status=400)

    obj.used = True
    obj.save(update_fields=["used"])

    user.email_verified = True
    user.email_verified_at = timezone.now()
    user.save(update_fields=["email_verified", "email_verified_at"])

    return Response({"detail": "Email verified."}, status=200)

def _get_client_ip(request) -> str:
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


def _get_user_agent(request) -> str:
    """Extract user agent from request."""
    return (request.META.get('HTTP_USER_AGENT') or '')[:500]


def _send_password_reset_email(user, code: str, expires_minutes: int = 15) -> bool:
    """Send password reset code via email."""
    from core.utils.ms_graph_mail import send_email_with_fallback
    
    subject = "Styloria Password Reset Code"
    message = f"""Hello {user.first_name or user.username},

You requested to reset your password for your Styloria account.

Your password reset code is: {code}

This code will expire in {expires_minutes} minutes.

If you did not request this, please ignore this email or contact support if you're concerned about your account security.

— The Styloria Team
"""
    return send_email_with_fallback(
        to_email=user.email,
        subject=subject,
        body_text=message,
        fail_silently=True,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_request(request):
    """
    POST /api/auth/password/reset/request/
    Body: { "email": "user@example.com" }
    
    Sends a 6-digit code to the user's email for password reset.
    Rate limited to 3 requests per hour.
    """
    email = (request.data.get("email") or "").strip().lower()
    
    if not email:
        return Response({"detail": "Email is required."}, status=400)
    
    # Validate email format
    if "@" not in email or "." not in email:
        return Response({"detail": "Please enter a valid email address."}, status=400)
    
    # Find user by email
    try:
        user = CustomUser.objects.get(email__iexact=email)
    except CustomUser.DoesNotExist:
        # Don't reveal if email exists (security)
        return Response({
            "message": "If an account with this email exists, a reset code has been sent."
        }, status=200)
    
    # Rate limiting check using the model's class method
    can_request, reason = PasswordResetCode.can_request_new_code(user, max_per_hour=3)
    if not can_request:
        return Response({"detail": reason}, status=429)
    
    # Get request metadata for security tracking
    ip_address = _get_client_ip(request)
    user_agent = _get_user_agent(request)
    
    # Create reset code using the manager
    expires_minutes = 15
    reset_code = PasswordResetCode.objects.create_for_user(
        user=user,
        expires_minutes=expires_minutes,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    
    # Send email
    email_sent = _send_password_reset_email(user, reset_code.code, expires_minutes)
    
    if not email_sent:
        # Delete the code if email failed
        reset_code.delete()
        return Response({
            "detail": "Failed to send reset email. Please try again."
        }, status=500)
    
    return Response({
        "message": "If an account with this email exists, a reset code has been sent.",
        "expires_in_minutes": expires_minutes,
    }, status=200)


@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_confirm(request):
    """
    POST /api/auth/password/reset/confirm/
    Body: { "email": "user@example.com", "code": "123456", "new_password": "newpass123" }
    
    Verifies the code and resets the password.
    Tracks failed attempts and locks after 5 failures.
    """
    email = (request.data.get("email") or "").strip().lower()
    code = (request.data.get("code") or "").strip()
    new_password = request.data.get("new_password") or ""
    
    if not email or not code or not new_password:
        return Response({
            "detail": "Email, code, and new_password are required."
        }, status=400)
    
    # Validate password strength
    if len(new_password) < 8:
        return Response({
            "detail": "Password must be at least 8 characters."
        }, status=400)
    
    # Additional password validation (optional - add more rules)
    has_letter = any(c.isalpha() for c in new_password)
    has_digit = any(c.isdigit() for c in new_password)
    if not (has_letter and has_digit):
        return Response({
            "detail": "Password must contain at least one letter and one number."
        }, status=400)
    
    # Find user
    try:
        user = CustomUser.objects.get(email__iexact=email)
    except CustomUser.DoesNotExist:
        return Response({"detail": "Invalid email or code."}, status=400)
    
    # Get client IP for tracking
    ip_address = _get_client_ip(request)
    
    # Verify code using the model's class method
    success, message, reset_code = PasswordResetCode.verify_code(
        user=user,
        code=code,
        ip_address=ip_address,
    )
    
    if not success:
        # Record failed attempt if code exists but is wrong
        wrong_code = PasswordResetCode.objects.filter(
            user=user,
            used=False,
        ).order_by("-created_at").first()
        
        if wrong_code and not wrong_code.is_expired():
            wrong_code.record_failed_attempt()
            
            remaining_attempts = 5 - wrong_code.failed_attempts
            if remaining_attempts > 0:
                message = f"{message} {remaining_attempts} attempts remaining."
        
        return Response({"detail": message}, status=400)
    
    # Reset password
    with transaction.atomic():
        user.password = make_password(new_password)
        user.save(update_fields=["password"])
        
        # Mark code as used with IP tracking
        reset_code.mark_used(ip_address=ip_address)
        
        # Invalidate all other unused codes for this user
        PasswordResetCode.objects.filter(
            user=user,
            used=False,
        ).exclude(pk=reset_code.pk).update(used=True, used_at=timezone.now())
    
    # Optional: Send confirmation email
    from core.utils.ms_graph_mail import send_email_with_fallback
    
    send_email_with_fallback(
        to_email=user.email,
        subject="Styloria Password Changed",
        body_text=f"""Hello {user.first_name or user.username},

Your password was successfully changed.

If you did not make this change, please contact our support team immediately.

— The Styloria Team
""",
        fail_silently=True,  # Don't fail the request if confirmation email fails
    )
    
    return Response({
        "message": "Password reset successfully. You can now log in with your new password."
    }, status=200)


@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_resend(request):
    """
    POST /api/auth/password/reset/resend/
    Body: { "email": "user@example.com" }
    
    Resends a new reset code, invalidating the old one.
    Useful when the code expires before use.
    """
    email = (request.data.get("email") or "").strip().lower()
    
    if not email:
        return Response({"detail": "Email is required."}, status=400)
    
    try:
        user = CustomUser.objects.get(email__iexact=email)
    except CustomUser.DoesNotExist:
        return Response({
            "message": "If an account with this email exists, a new reset code has been sent."
        }, status=200)
    
    # Rate limiting
    can_request, reason = PasswordResetCode.can_request_new_code(user, max_per_hour=5)
    if not can_request:
        return Response({"detail": reason}, status=429)
    
    # Invalidate all existing codes
    PasswordResetCode.objects.invalidate_all_for_user(user)
    
    # Create new code
    ip_address = _get_client_ip(request)
    user_agent = _get_user_agent(request)
    expires_minutes = 15
    
    reset_code = PasswordResetCode.objects.create_for_user(
        user=user,
        expires_minutes=expires_minutes,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    
    # Send email
    email_sent = _send_password_reset_email(user, reset_code.code, expires_minutes)
    
    if not email_sent:
        reset_code.delete()
        return Response({
            "detail": "Failed to send reset email. Please try again."
        }, status=500)
    
    return Response({
        "message": "If an account with this email exists, a new reset code has been sent.",
        "expires_in_minutes": expires_minutes,
    }, status=200)


@api_view(["POST"])
@permission_classes([AllowAny])
def send_username_reminder(request):
    email = (request.data.get("email") or "").strip().lower()
    if not email:
        return Response({"detail": "email is required."}, status=400)

    user = User.objects.filter(email__iexact=email).first()

    # Do not leak whether email exists
    if user:
        subject = "Your Styloria Username"
        message = f"""Hello,

You requested a reminder of your Styloria username.

Your username is: {user.get_username()}

— The Styloria Team
"""
        from core.utils.ms_graph_mail import send_email_with_fallback
        
        send_email_with_fallback(
            to_email=user.email,
            subject=subject,
            body_text=message,
            fail_silently=False,
        )

    return Response({"detail": "If that email exists, your username was sent."}, status=200)

# ----------------
# DELETE PROFILE PICTURE
# ----------------
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_profile_picture(request):
    """
    DELETE /api/users/me/profile_picture/
    Removes the user's profile picture.
    """
    user = request.user
    if user.profile_picture:
        # Delete the file from storage
        user.profile_picture.delete(save=False)
        user.profile_picture = None
        user.save(update_fields=["profile_picture"])
        return Response({"detail": "Profile picture deleted successfully."}, status=status.HTTP_200_OK)
    return Response({"detail": "No profile picture to delete."}, status=status.HTTP_200_OK)


# ----------------
# USER VIEWSET
# ----------------
class UserViewSet(viewsets.ModelViewSet):
    """
    - Anyone can register: POST /api/users/
    - Authenticated users can use: GET/PATCH /api/users/me/
    - Authenticated users can set codes: POST /api/users/me/set_location_codes/
    - Normal users can only retrieve/update themselves via /api/users/<id>/
    - Admin/staff can list/retrieve/update anyone
    """

    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_permissions(self):
        if self.action == "create":
            return [AllowAny()]

        if self.action in ("me", "set_location_codes", "update_my_location", "delete_account"):
            return [IsAuthenticated()]

        if self.action == "list":
            return [IsStyloriaAdmin()]

        return [IsAuthenticated()]

    def get_queryset(self):
        user = self.request.user
        if user and user.is_authenticated and (user.is_staff or getattr(user, "role", "") == "admin"):
            return User.objects.all()
        if user and user.is_authenticated:
            return User.objects.filter(pk=user.pk)
        return User.objects.none()

    def create(self, request, *args, **kwargs):
        """
        Signup + handle referral code + email verification
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save()

        if getattr(user, "role", "") == "provider":
            ServiceProvider.objects.get_or_create(
                user=user,
                defaults={
                    "available": False,
                    "verification_status": "not_submitted",
                    "is_verified": False,
                },
            )

        # ========== HANDLE REFERRAL CODE ==========
        referral_code = (request.data.get('referral_code') or '').strip().upper()
    
        if referral_code:
            try:
                # Find referrer by code
                referrer = CustomUser.objects.get(referral_code__iexact=referral_code)
             
                # Prevent self-referral
                if referrer.id != user.id:
                    # Link new user to referrer
                    user.referred_by = referrer
                    user.save(update_fields=['referred_by'])
                
                    # Create pending Referral record
                    # Credits will be awarded when user completes first booking
                    Referral.objects.create(
                        referrer=referrer,
                        referred_user=user,
                        status='pending',
                        credits_amount=5,
                        credits_awarded=False,
                    )
                
                    # Notify referrer
                    try:
                        send_websocket_notification(
                            referrer,
                            f"🎉 {user.first_name or user.username} just signed up using your referral code! "
                            f"You'll earn 5 discount credits when they complete their first booking.",
                            notification_type="referral_signup"
                        )
                    except Exception:
                        pass  # Don't block registration if notification fails
                    
            except CustomUser.DoesNotExist:
                # Invalid code - ignore (don't block registration)
                pass

        # ========== EMAIL VERIFICATION ==========
        # If no email, we can't send verification
        if not user.email:
            headers = self.get_success_headers(serializer.data)
            data = dict(serializer.data)
            data["verification_sent"] = False
            data["verification_detail"] = "No email on file; verification not sent."
            return Response(data, status=status.HTTP_201_CREATED, headers=headers)

        # If already verified, don't spam
        if getattr(user, "email_verified", False):
            headers = self.get_success_headers(serializer.data)
            data = dict(serializer.data)
            data["verification_sent"] = False
            data["verification_detail"] = "Email already verified."
            return Response(data, status=status.HTTP_201_CREATED, headers=headers)

        # Invalidate old codes
        EmailVerificationCode.objects.filter(user=user, used=False).update(used=True)

        # Generate new code
        code = _generate_6_digit_code()
        EmailVerificationCode.objects.create(
            user=user,
            code=code,
            expires_at=timezone.now() + timedelta(minutes=15),
            used=False,
        )

        # Send email
        from core.utils.ms_graph_mail import send_email_with_fallback
        
        try:
            send_email_with_fallback(
                to_email=user.email,
                subject="Verify your Styloria email",
                body_text=(
                    "Welcome to Styloria!\n\n"
                    f"Your email verification code is: {code}\n\n"
                    "This code expires in 15 minutes."
                ),
                fail_silently=False,
            )
            verification_sent = True
            verification_detail = "Verification code sent."
        except Exception as e:
            verification_sent = False
            verification_detail = f"User created, but email failed to send: {e}"

        headers = self.get_success_headers(serializer.data)
        data = dict(serializer.data)
        data["verification_sent"] = verification_sent
        data["verification_detail"] = verification_detail
        return Response(data, status=status.HTTP_201_CREATED, headers=headers)

    @action(detail=False, methods=["get", "patch"], permission_classes=[IsAuthenticated])
    def me(self, request):
        """
        GET   /api/users/me/   -> return current user's details
        PATCH /api/users/me/   -> update current user (supports multipart for profile_picture)
        """
        if request.method == "GET":
            serializer = self.get_serializer(request.user, context={"request": request})
            return Response(serializer.data)

        serializer = self.get_serializer(
            request.user,
            data=request.data,
            partial=True,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(self.get_serializer(user, context={"request": request}).data)

    @action(detail=False, methods=["delete"], url_path="me/profile_picture", permission_classes=[IsAuthenticated])
    def delete_profile_picture(self, request):
        """
        DELETE /api/users/me/profile_picture/
        Removes the user's profile picture.
        """
        user = request.user
        if user.profile_picture:
            # Delete the file from storage
            user.profile_picture.delete(save=False)
            user.profile_picture = None
            user.save(update_fields=["profile_picture"])
            return Response({"detail": "Profile picture deleted successfully."}, status=status.HTTP_200_OK)
        return Response({"detail": "No profile picture to delete."}, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=["post"],
        permission_classes=[IsAuthenticated],
        url_path="me/location",
    )
    def update_my_location(self, request):
        """
        POST /api/users/me/location/
        Body: { "latitude": ..., "longitude": ... }
        """
        block = require_email_verified(request.user)
        if block:
            return Response(block, status=403)

        lat = request.data.get("latitude")
        lng = request.data.get("longitude")
        if lat is None or lng is None:
            return Response({"detail": "latitude and longitude are required."}, status=400)

        try:
            lat = float(lat)
            lng = float(lng)
        except ValueError:
            return Response({"detail": "Invalid latitude/longitude."}, status=400)

        u = request.user
        u.last_known_latitude = lat
        u.last_known_longitude = lng
        u.last_location_update = timezone.now()
        u.save(update_fields=["last_known_latitude", "last_known_longitude", "last_location_update"])

        if getattr(u, "role", "") == "provider":
            ServiceProvider.objects.filter(user=u).update(
                location_latitude=lat,
                location_longitude=lng,
            )

        if getattr(u, "role", "") == "provider":
            provider = ServiceProvider.objects.filter(user=u).first()
            if provider:
                _notify_waiting_requests_if_providers_now_available(provider)

        return Response(
            {
                "detail": "Location updated.",
                "latitude": lat,
                "longitude": lng,
                "updated_at": u.last_location_update,
            },
            status=200,
        )

    @action(
        detail=False,
        methods=["post"],
        permission_classes=[IsAuthenticated],
        url_path="me/set_location_codes",
    )
    def set_location_codes(self, request):
        serializer = UserLocationCodesSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(self.get_serializer(user, context={"request": request}).data)

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="me/delete_account")
    def delete_account(self, request):
        user = request.user

        reasons = request.data.get("reasons", []) or []
        reason_text = (request.data.get("reason_text") or "").strip()
        suggestions = (request.data.get("suggestions") or "").strip()

        with transaction.atomic():
            AccountDeletionFeedback.objects.create(
                user=user,
                role=getattr(user, "role", "") or "",
                reasons=reasons if isinstance(reasons, list) else [],
                reason_text=reason_text,
                suggestions=suggestions,
            )

            if getattr(user, "role", "") == "provider":
                ServiceProvider.objects.filter(user=user).update(available=False)

            user.is_active = False
            user.email = f"deleted_{user.id}@styloria.invalid"
            user.phone_number = None
            user.username = f"deleted_{user.id}"
            user.first_name = ""
            user.last_name = ""
            user.save()

        return Response({"detail": "Account deleted."}, status=200)


# -------------------------
# SERVICE PROVIDER VIEWSET
# -------------------------
class ServiceProviderViewSet(viewsets.ModelViewSet):
    queryset = ServiceProvider.objects.all()
    serializer_class = ServiceProviderSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=["get"])
    def availability(self, request, pk=None):
        provider = self.get_object()
        return Response({"available": provider.available})

    @action(detail=False, methods=["get", "post", "patch"], permission_classes=[IsAuthenticated])
    def me(self, request):
        block = require_email_verified(request.user)
        if block:
            return Response(block, status=403)

        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "No provider profile"}, status=404)

        # KYC gate: allow GET so app can read status and show KYC screen
        if provider.verification_status != "approved":
            if request.method == "GET":
                data = self.get_serializer(provider, context={"request": request}).data
                return Response(
                    {
                        "detail": "KYC required before managing provider profile.",
                        "next_action": "kyc_submit",
                        "verification_status": provider.verification_status,
                        "provider": data,
                    },
                    status=200,
                )

            return Response(
                {
                    "detail": "Complete KYC verification to edit provider profile.",
                    "next_action": "kyc_submit",
                    "verification_status": provider.verification_status,
                },
                status=403,
            )

        if request.method == "GET":
            serializer = self.get_serializer(provider, context={"request": request})
            data = serializer.data
            # Include certification status for restricted services
            data['certification_status'] = _get_provider_certification_status(provider)
            return Response(data)

        serializer = self.get_serializer(
            provider,
            data=request.data,
            partial=True,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        provider = serializer.save()

        _notify_waiting_requests_if_providers_now_available(provider)

        # pricing update
        service_prices_data = request.data.get("service_prices", None)
        if service_prices_data is not None:
            unavailable_services = request.data.get("unavailable_services", []) or []

            if isinstance(service_prices_data, dict):
                for service_type, price in service_prices_data.items():
                    offered = service_type not in unavailable_services
                    try:
                        price_decimal = Decimal(str(price))
                    except Exception:
                        continue

                    # Validate: if service is offered, price must be > 0
                    if offered and price_decimal <= Decimal("0.00"):
                        return Response(
                            {
                                "detail": f"Please set a price greater than 0 for '{service_type}' or mark it as 'Not Offered'.",
                                "error_code": "invalid_price",
                                "service_type": service_type,
                            },
                            status=400,
                        )

                    # Validate: check certification requirements for restricted services
                    if offered:
                        cert_error = _check_service_certification_requirement(provider, service_type)
                        if cert_error:
                            return Response(cert_error, status=400)

                    ServiceProviderPricing.objects.update_or_create(
                        provider=provider,
                        service_type=service_type,
                        defaults={"price": price_decimal, "offered": offered},
                    )

            elif isinstance(service_prices_data, list):
                for price_data in service_prices_data:
                    service_type = price_data.get("service_type")
                    price = price_data.get("price")
                    offered = bool(price_data.get("offered", True))

                    if not service_type:
                        continue
                    try:
                        price_decimal = Decimal(str(price))
                    except Exception:
                        continue

                    # Validate: if service is offered, price must be > 0
                    if offered and price_decimal <= Decimal("0.00"):
                        return Response(
                            {
                                "detail": f"Please set a price greater than 0 for '{service_type}' or mark it as 'Not Offered'.",
                                "error_code": "invalid_price",
                                "service_type": service_type,
                            },
                            status=400,
                        )

                    # Validate: check certification requirements for restricted services
                    if offered:
                        cert_error = _check_service_certification_requirement(provider, service_type)
                        if cert_error:
                            return Response(cert_error, status=400)

                    ServiceProviderPricing.objects.update_or_create(
                        provider=provider,
                        service_type=service_type,
                        defaults={"price": price_decimal, "offered": offered},
                    )

        response_data = self.get_serializer(provider, context={"request": request}).data
        response_data['certification_status'] = _get_provider_certification_status(provider)
        return Response(response_data)

    # ==========================
    # PROVIDER PORTFOLIO
    # ==========================
    @action(detail=False, methods=["get", "post"], url_path="me/portfolio", permission_classes=[IsAuthenticated])
    def my_portfolio(self, request):
        """
        GET  /api/service_providers/me/portfolio/  -> list my posts
        POST /api/service_providers/me/portfolio/  -> create post {caption}
        """
        block = require_email_verified(request.user)
        if block:
            return Response(block, status=403)

        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "You are not a provider."}, status=400)

        if provider.verification_status != "approved":
            return Response(
                {
                    "detail": "Complete KYC verification to access portfolio features.",
                    "verification_status": provider.verification_status,
                },
                status=403,
            )

        if request.method == "GET":
            data = ServiceProviderSerializer(provider, context={"request": request}).data.get("portfolio_posts", [])
            return Response(data)

        caption = (request.data.get("caption") or "").strip()
        is_public = bool(request.data.get("is_public", False))
        post = ProviderPortfolioPost.objects.create(provider=provider, caption=caption, is_public=is_public)

        return Response({"detail": "Portfolio post created.", "post_id": post.id}, status=201)

    @action(
        detail=False,
        methods=["post"],
        url_path=r"me/portfolio/(?P<post_id>[^/.]+)/media",
        permission_classes=[IsAuthenticated],
    )
    def upload_portfolio_media(self, request, post_id=None):
        """
        POST /api/service_providers/me/portfolio/<post_id>/media/
        multipart/form-data:
          - file: single file OR
          - files: multiple files
        """
        block = require_email_verified(request.user)
        if block:
            return Response(block, status=403)

        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "You are not a provider."}, status=400)

        if provider.verification_status != "approved":
            return Response(
                {
                    "detail": "Complete KYC verification to access portfolio features.",
                    "verification_status": provider.verification_status,
                },
                status=403,
            )

        try:
            post = ProviderPortfolioPost.objects.get(id=post_id, provider=provider)
        except ProviderPortfolioPost.DoesNotExist:
            return Response({"detail": "Post not found."}, status=404)

        if "files" in request.FILES:
            files = request.FILES.getlist("files")
        elif "file" in request.FILES:
            files = [request.FILES["file"]]
        else:
            files = []

        if not files:
            return Response({"detail": "No file uploaded. Use 'file' or 'files'."}, status=400)

        created = []
        for f in files:
            name = (f.name or "").lower()
            if name.endswith((".jpg", ".jpeg", ".png", ".webp")):
                media_type = "image"
            elif name.endswith((".mp4", ".mov", ".m4v", ".webm")):
                media_type = "video"
            else:
                return Response(
                    {
                        "detail": (
                            f"Unsupported file type for {f.name}. "
                            "Allowed: images(jpg,png,webp) videos(mp4,mov,webm)."
                        )
                    },
                    status=400,
                )

            m = ProviderPortfolioMedia.objects.create(
                post=post,
                media_type=media_type,
                file=f,
            )
            created.append(m.id)

        return Response({"detail": "Media uploaded.", "media_ids": created}, status=201)

    @action(
        detail=False,
        methods=["delete"],
        url_path=r"me/portfolio/(?P<post_id>[^/.]+)",
        permission_classes=[IsAuthenticated],
    )
    def delete_portfolio_post(self, request, post_id=None):
        """
        DELETE /api/service_providers/me/portfolio/<post_id>/
        """
        block = require_email_verified(request.user)
        if block:
            return Response(block, status=403)

        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "You are not a provider."}, status=400)

        if provider.verification_status != "approved":
            return Response(
                {
                    "detail": "Complete KYC verification to access portfolio features.",
                    "verification_status": provider.verification_status,
                },
                status=403,
            )

        try:
            post = ProviderPortfolioPost.objects.get(id=post_id, provider=provider)
        except ProviderPortfolioPost.DoesNotExist:
            return Response({"detail": "Post not found."}, status=404)

        post.delete()
        return Response({"detail": "Post deleted."})

    @action(detail=True, methods=["get"], url_path="portfolio", permission_classes=[IsAuthenticated])
    def portfolio(self, request, pk=None):
        """
        GET /api/service_providers/<provider_id>/portfolio/

        Restriction:
        - allowed if request.user is provider owner/admin OR
        - request.user has a booking with this provider in accepted/in_progress
        """
        provider = self.get_object()

        u = request.user
        if u.is_staff or getattr(u, "role", "") == "admin":
            allowed = True
        elif u.pk == provider.user_id:
            allowed = True
        else:
            allowed = provider.can_user_view_portfolio(u)

        if not allowed:
            return Response({"detail": "Not authorized to view provider portfolio."}, status=403)

        data = ServiceProviderSerializer(provider, context={"request": request}).data.get("portfolio_posts", [])
        return Response(data)


    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def my_certifications(self, request):
        """
        GET /api/service_providers/my_certifications/
        List all certifications for the current provider.
        """
        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "No provider profile"}, status=404)
        
        certifications = provider.certifications.all()
        serializer = ProviderCertificationSerializer(
            certifications, 
            many=True, 
            context={"request": request}
        )
        
        # Also return trust score info
        from core.utils import calculate_provider_trust_score, get_provider_tier
        
        return Response({
            "certifications": serializer.data,
            "count": certifications.count(),
            "trust_score": calculate_provider_trust_score(provider),
            "current_tier": get_provider_tier(provider),
        })

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated])
    def add_certification(self, request):
        """
        POST /api/service_providers/add_certification/
        Add a new certification.
        """
        import traceback
        import os
        
        print(f"[CERT] === Starting certification upload ===")
        print(f"[CERT] User: {request.user.id} - {request.user.username}")
        
        try:
            provider = ServiceProvider.objects.get(user=request.user)
            print(f"[CERT] Provider found: {provider.id}")
        except ServiceProvider.DoesNotExist:
            print(f"[CERT] ERROR: No provider profile for user {request.user.id}")
            return Response({"detail": "No provider profile"}, status=404)
        
        # Limit certifications
        MAX_CERTIFICATIONS = 10
        cert_count = provider.certifications.count()
        print(f"[CERT] Current certification count: {cert_count}")
        
        if cert_count >= MAX_CERTIFICATIONS:
            return Response({
                "detail": f"Maximum {MAX_CERTIFICATIONS} certifications allowed."
            }, status=400)
        
        name = request.data.get('name')
        print(f"[CERT] Certification name: {name}")
        
        if not name or not name.strip():
            return Response({"detail": "Certification name is required."}, status=400)
        
        # Get the document file
        document = request.FILES.get('document')
        print(f"[CERT] Document received: {document is not None}")
        
        if document:
            print(f"[CERT] Document name: {document.name}")
            print(f"[CERT] Document size: {document.size} bytes")
            print(f"[CERT] Document content_type: {getattr(document, 'content_type', 'unknown')}")
            
            # Validate file extension
            ext = os.path.splitext(document.name)[1].lower().replace('.', '')
            allowed_extensions = ['png', 'jpg', 'jpeg', 'pdf']
            print(f"[CERT] File extension: {ext}")
            
            if ext not in allowed_extensions:
                return Response({
                    "detail": f"Unsupported file type '.{ext}'. Allowed types: PNG, JPG, JPEG, PDF",
                    "error_code": "invalid_file_type",
                }, status=400)
            
            # Check file size
            max_size_image = 5 * 1024 * 1024  # 5 MB
            max_size_pdf = 10 * 1024 * 1024   # 10 MB
            max_size = max_size_pdf if ext == 'pdf' else max_size_image
            
            if document.size > max_size:
                return Response({
                    "detail": f"File too large. Max size is {max_size // (1024*1024)} MB.",
                    "error_code": "file_too_large",
                }, status=400)
        
        # Prepare data
        issue_date = request.data.get('issue_date') or None
        expiry_date = request.data.get('expiry_date') or None
        issuing_org = request.data.get('issuing_organization', '').strip()
        
        print(f"[CERT] Issue date: {issue_date}")
        print(f"[CERT] Expiry date: {expiry_date}")
        print(f"[CERT] Issuing org: {issuing_org}")
        
        # Create certification
        print(f"[CERT] Creating certification object...")
        
        try:
            certification = ProviderCertification.objects.create(
                provider=provider,
                name=name.strip(),
                issuing_organization=issuing_org,
                document=document,
                issue_date=issue_date,
                expiry_date=expiry_date,
            )
            print(f"[CERT] SUCCESS! Certification created with ID: {certification.id}")
            
        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            full_tb = traceback.format_exc()
            
            print(f"[CERT] EXCEPTION: {error_msg}")
            print(f"[CERT] TRACEBACK:\n{full_tb}")
            
            # Check if storage-related
            error_str = str(e).lower()
            if any(x in error_str for x in ['s3', 'storage', 'bucket', 'boto', 'connection', 'r2']):
                return Response({
                    "detail": "Failed to upload document. Please try again.",
                    "error_code": "storage_error",
                    "error_type": type(e).__name__,
                    "debug_message": error_msg,
                }, status=500)
            
            return Response({
                "detail": "Failed to add certification. Please try again.",
                "error_code": "creation_failed",
                "error_type": type(e).__name__,
                "debug_message": error_msg,
            }, status=500)
        
        # Success - serialize and return
        serializer = ProviderCertificationSerializer(
            certification, 
            context={"request": request}
        )
        
        from core.utils import calculate_provider_trust_score, get_provider_tier
        
        print(f"[CERT] Returning success response")
        
        return Response({
            "detail": "Certification added successfully!",
            "certification": serializer.data,
            "trust_score": calculate_provider_trust_score(provider),
            "current_tier": get_provider_tier(provider),
        }, status=201)

    @action(detail=False, methods=['delete'], url_path='delete_certification/(?P<cert_id>[0-9]+)')
    def delete_certification(self, request, cert_id=None):
        """
        DELETE /api/service_providers/delete_certification/<cert_id>/
        Delete a certification.
        """


        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "No provider profile"}, status=404)
        
        try:
            certification = provider.certifications.get(id=cert_id)
        except ProviderCertification.DoesNotExist:
            return Response({"detail": "Certification not found."}, status=404)
        
        certification.delete()
        
        # Return updated trust score
        from core.utils import calculate_provider_trust_score, get_provider_tier
        
        return Response({
            "detail": "Certification deleted successfully!",
            "trust_score": calculate_provider_trust_score(provider),
            "current_tier": get_provider_tier(provider),
        })

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def certification_upload_info(self, request):
        """
        GET /api/service_providers/certification_upload_info/
        Returns file upload requirements for certifications.
        
        Use this to show users what files are allowed before they attempt upload.
        """
        return Response({
            "allowed_file_types": {
                "extensions": ["png", "jpg", "jpeg", "pdf"],
                "mime_types": [
                    "image/png",
                    "image/jpeg",
                    "image/jpg", 
                    "application/pdf"
                ],
                "description": "Images (PNG, JPG, JPEG) or PDF documents"
            },
            "max_file_sizes": {
                "image": {
                    "bytes": 5 * 1024 * 1024,
                    "display": "5 MB",
                    "extensions": ["png", "jpg", "jpeg"],
                    "description": "For PNG, JPG, JPEG images"
                },
                "pdf": {
                    "bytes": 10 * 1024 * 1024,
                    "display": "10 MB",
                    "extensions": ["pdf"],
                    "description": "For PDF documents"
                }
            },
            "max_certifications": 10,
            "tips": [
                "Ensure your document is clear and readable",
                "Include your full name on the certification",
                "For massage services, include 'massage' in the certification name",
                "Certifications will be verified by our admin team"
            ]
        })


# -------------------------
# SERVICE REQUEST VIEWSET
# -------------------------
class ServiceRequestViewSet(viewsets.ModelViewSet):
    queryset = ServiceRequest.objects.all()
    serializer_class = ServiceRequestSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_staff or getattr(user, "role", "") == "admin":
            return ServiceRequest.objects.all()
        return ServiceRequest.objects.filter(Q(user=user) | Q(service_provider__user=user))

    def perform_create(self, serializer):
        """
        Create a booking:
        - status='pending' (waiting for payment)
        - payment_status='unpaid'
        - currency based on user's country
        - estimated_price based on nearest verified provider distance (simple logic)
        """
        if not getattr(self.request.user, "email_verified", False):
            raise PermissionDenied("Verify your email before creating a booking.")

        # Lazy cleanup: cancel this user's stale unpaid bookings before creating new one
        try:
            cancel_stale_unpaid_bookings(user=self.request.user)
        except Exception:
            pass  # Don't block booking creation if cleanup fails

        user_lat = serializer.validated_data["location_latitude"]
        user_lng = serializer.validated_data["location_longitude"]
        user_location = (user_lat, user_lng)

        has_provider = _has_nearby_available_provider_for_service(
            user_lat=user_lat,
            user_lng=user_lng,
            service_type=serializer.validated_data["service_type"],
        )

        nearest_provider = None
        min_distance = None  # Decimal

        for provider in ServiceProvider.objects.filter(available=True, is_verified=True):
            if provider.location_latitude is None or provider.location_longitude is None:
                continue

            provider_location = (provider.location_latitude, provider.location_longitude)
            distance_km = Decimal(str(geodesic(user_location, provider_location).km))

            if min_distance is None or distance_km < min_distance:
                min_distance = distance_km
                nearest_provider = provider

        estimated_price = None
        if has_provider and nearest_provider and min_distance is not None:
            transportation_cost = min_distance * Decimal("0.8")
            estimated_price = transportation_cost

        # ═══════════════════════════════════════════════════════════════════
        # NEW: Set currency based on user's country and payment gateway
        # ═══════════════════════════════════════════════════════════════════
        from core.utils.payment_routing import get_booking_currency_for_user
    
        user_currency = get_booking_currency_for_user(self.request.user)


        req = serializer.save(
            user=self.request.user,
            estimated_price=estimated_price,
            service_provider=None,
            status="pending",
            payment_status="unpaid",
            currency=user_currency,  # ← NEW: Set currency at creation time
        )

        if not has_provider:
            send_websocket_notification(
                req.user,
                "We’re sorry—there are currently no available providers for this service in your area. Please try again later.",
                notification_type="info",
            )
            req.no_providers_notified = True
            req.save(update_fields=["no_providers_notified"])

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        old_status = instance.status

        response = super().update(request, *args, **kwargs)

        service_request = self.get_object()
        new_status = service_request.status

        if old_status != "completed" and new_status == "completed" and service_request.completed_at is None:
            service_request.completed_at = timezone.now()
            service_request.save(update_fields=["completed_at"])

        if old_status != new_status:
            channel_layer = get_channel_layer()

            ws_message = {
                "type": "service_request_update",
                "service_request_id": service_request.id,
                "old_status": old_status,
                "new_status": new_status,
            }

            Notification.objects.create(
                user=service_request.user,
                message=f"Your booking #{service_request.id} status changed from {old_status} to {new_status}.",
            )
            user_room_group = f"notifications_{service_request.user.id}"
            async_to_sync(channel_layer.group_send)(
                user_room_group,
                {"type": "send_notification", "message": ws_message},
            )

            if service_request.service_provider:
                Notification.objects.create(
                    user=service_request.service_provider.user,
                    message=(
                        f"Booking #{service_request.id} assigned to you changed from "
                        f"{old_status} to {new_status}."
                    ),
                )
                provider_room_group = f"notifications_{service_request.service_provider.user.id}"
                async_to_sync(channel_layer.group_send)(
                    provider_room_group,
                    {"type": "send_notification", "message": ws_message},
                )

        return response

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def my_requests(self, request):
        # Lazy cleanup: cancel user's stale unpaid bookings
        try:
            cancelled = cancel_stale_unpaid_bookings(user=request.user)
            if cancelled > 0:
                # Send WebSocket notification if any were cancelled
                from core.views import send_websocket_notification
                send_websocket_notification(
                    request.user,
                    f"{cancelled} booking(s) were automatically cancelled due to non-payment after 48 hours.",
                    notification_type="booking_auto_cancelled",
                )
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Error in stale booking cleanup: {e}")

        qs = self.get_queryset().filter(user=request.user).order_by("-request_time")
        serializer = self.get_serializer(qs, many=True, context={"request": request})
        return Response(serializer.data)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def assigned_to_me(self, request):
        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "You are not a provider"}, status=400)

        # Lazy cleanup: run global cleanup occasionally (1 in 10 requests)
        import random
        if random.random() < 0.1:  # 10% chance
            try:
                cancel_stale_unpaid_bookings(user=None)  # Global cleanup
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"Error in global stale booking cleanup: {e}")

        qs = self.get_queryset().filter(service_provider=provider).order_by("-request_time")
        serializer = self.get_serializer(qs, many=True, context={"request": request})
        return Response(serializer.data)

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated])
    def job_details(self, request, pk=None):
        """
        GET /api/service_requests/<id>/job_details/
        Shows enhanced job details - only available after job is accepted by provider
        """
        job = self.get_object()
        
        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "You are not a provider"}, status=400)
        
        # Only assigned provider can see enhanced details
        if job.service_provider != provider:
            return Response({"detail": "Not authorized to view this job"}, status=403)
        
        # Only show enhanced details for accepted+ jobs
        if job.status not in ['accepted', 'in_progress', 'completed']:
            return Response({"detail": "Enhanced job details only available after acceptance"}, status=403)
        
        # Return enhanced serialization with customer details
        from .serializers import JobDetailSerializer
        serializer = JobDetailSerializer(job, context={'request': request})
        return Response(serializer.data)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def open_jobs(self, request):
        block = require_email_verified(request.user)
        if block:
            return Response(block, status=403)

        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "You are not a provider"}, status=400)

        if provider.verification_status != "approved":
            return Response(
                {
                    "detail": "Complete KYC verification to access provider features.",
                    "verification_status": provider.verification_status,
                },
                status=403,
            )

        # Check if provider is available for bookings
        if not provider.available:
            return Response(
                {
                    "detail": "You are currently set as unavailable for bookings.",
                    "error_code": "provider_unavailable",
                    "message": "To view and accept open jobs, please enable 'Available for Bookings' in your Provider Profile settings.",
                    "action_required": "enable_availability",
                },
                status=403,
            )


        if provider.location_latitude is None or provider.location_longitude is None:
            return Response({"detail": "Please set your provider location before viewing open jobs."}, status=400)

        provider_location = (provider.location_latitude, provider.location_longitude)

        # Get provider's tier for filtering
        provider_tier = get_provider_tier(provider)

        candidates = ServiceRequest.objects.filter(
            payment_status="paid",
            status="open",
            service_provider__isnull=True,
        ).exclude(user=request.user).order_by("-request_time")

        max_distance_km = Decimal("24.14")  # ≈ 15 miles
        nearby_jobs = []

        for job in candidates:
            # Skip jobs the provider isn't eligible for
            if job.selected_tier and not is_provider_eligible_for_tier(provider, job.selected_tier):
                continue

            user_location = (job.location_latitude, job.location_longitude)
            distance_km = Decimal(str(geodesic(provider_location, user_location).km))

            if provider.get_service_price(job.service_type) is None:
                continue

            if distance_km <= max_distance_km:
                job.distance_miles = float(distance_km * Decimal("0.621371"))
                job.job_tier = job.selected_tier  # Expose tier to serializer
                nearby_jobs.append(job)

        nearby_jobs.sort(key=lambda x: x.distance_miles)
        serializer = self.get_serializer(nearby_jobs, many=True, context={"request": request})
        return Response({
            "jobs": serializer.data,
            "provider_tier": provider_tier,
            "provider_trust_score": calculate_provider_trust_score(provider),
            "eligible_tiers": self._get_eligible_tiers(provider_tier),
        })


    @staticmethod
    def _get_eligible_tiers(provider_tier):
        """Return list of tiers a provider can accept jobs from."""
        if provider_tier == 'premium':
            return ['budget', 'standard', 'premium']
        elif provider_tier == 'standard':
            return ['budget', 'standard']
        else:
            return ['budget']

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated])
    def price_options(self, request, pk=None):
        """
        GET /api/service_requests/<id>/price_options/

        Returns tier-based pricing with quality matching.
        """
        service_request = self.get_object()

        if service_request.user != request.user:
            return Response({"detail": "Not authorized."}, status=403)

        user_location = (service_request.location_latitude, service_request.location_longitude)
        service_type = service_request.service_type

        user_currency = (service_request.currency or "USD").upper()
        currency_symbol = get_currency_symbol(user_currency)

        max_distance_km = Decimal("24.14")

        # ===== FETCH NEARBY PROVIDERS =====
        providers = (
            ServiceProvider.objects.filter(
                available=True,
                is_verified=True,
                location_latitude__isnull=False,
                location_longitude__isnull=False,
            )
            .select_related("user")
            .prefetch_related(
                "service_prices",
                "portfolio_posts__media",  # Your portfolio structure
                "certifications",           # New certifications model
            )
        )

        nearby_providers = []

        for provider in providers:
            service_price = provider.get_service_price(service_type)
            if service_price is None:
                continue

            provider_location = (provider.location_latitude, provider.location_longitude)
            distance_km = Decimal(str(geodesic(user_location, provider_location).km))
            if distance_km > max_distance_km:
                continue

            # Convert currency
            provider_currency = (provider.user.preferred_currency or user_currency).upper()
            original_price_decimal = Decimal(str(service_price))

            if provider_currency != user_currency:
                try:
                    converted = convert_amount(float(original_price_decimal), provider_currency, user_currency)
                    converted_price_decimal = Decimal(str(converted))
                except Exception:
                    converted_price_decimal = original_price_decimal
            else:
                converted_price_decimal = original_price_decimal

            provider.converted_price = converted_price_decimal
            provider.distance_km = distance_km
            nearby_providers.append(provider)


        # ===== NO PROVIDERS =====
        if not nearby_providers:
            return Response({
                "detail": "No available providers for this service in your area. Please try again later.",
                "budget_price": None,
                "standard_price": None,
                "premium_price": None,
                "providers_count": 0,
                "user_currency": user_currency,
                "currency_symbol": currency_symbol,
            })

        # ===== SEGMENT BY TIER =====
        tiers = {'budget': [], 'standard': [], 'premium': []}
    
        for provider in nearby_providers:
            tier = get_provider_tier(provider)
            trust_score = calculate_provider_trust_score(provider)
        
            tiers[tier].append({
                'provider': provider,
                'price': provider.converted_price,
                'trust_score': trust_score,
                'distance_km': float(provider.distance_km),
            })
    
        # ===== CALCULATE TIER PRICES =====
        def calc_tier_price(tier_providers, percentile):
            if not tier_providers:
                return None
            prices = sorted([Decimal(str(p['price'])) for p in tier_providers])
            n = len(prices)
            if n == 1:
                return prices[0]
            index = min(int((n - 1) * percentile), n - 1)
            return prices[index]
    
        budget_base = calc_tier_price(tiers['budget'], 0.25)
        standard_base = calc_tier_price(tiers['standard'], 0.50)
        premium_base = calc_tier_price(tiers['premium'], 0.75)
    
        # ===== SMART FALLBACK FOR EMPTY TIERS =====
        # Instead of using all providers, we cascade upward:
        #   - Empty budget → use standard prices (if available) at lower percentile
        #   - Empty standard → blend budget and premium
        #   - Empty premium → use standard prices at higher percentile

        all_prices = sorted([Decimal(str(p.converted_price)) for p in nearby_providers])
        n = len(all_prices)

        # Track which tiers are naturally populated
        tier_availability = {
            'budget': len(tiers['budget']) > 0,
            'standard': len(tiers['standard']) > 0,
            'premium': len(tiers['premium']) > 0,
        }

        if budget_base is None:
            if standard_base is not None:
                # Use standard price minus 15%
                budget_base = (standard_base * Decimal("0.85")).quantize(Decimal("0.01"))
            else:
                # Last resort: 25th percentile of all
                budget_base = all_prices[max(0, int((n - 1) * 0.25))]

        if standard_base is None:
            if budget_base is not None and premium_base is not None:
                # Blend: midpoint between budget and premium
                standard_base = ((budget_base + premium_base) / Decimal("2")).quantize(Decimal("0.01"))
            elif budget_base is not None:
                # Use budget + 15%
                standard_base = (budget_base * Decimal("1.15")).quantize(Decimal("0.01"))
            else:
                # Last resort: median of all
                standard_base = Decimal(str(statistics.median([float(p) for p in all_prices])))

        if premium_base is None:
            if standard_base is not None:
                # Use standard price + 15%
                premium_base = (standard_base * Decimal("1.15")).quantize(Decimal("0.01"))
            else:
                # Last resort: 75th percentile of all
                premium_base = all_prices[min(n - 1, int((n - 1) * 0.75))]
    
        # ===== ENSURE 15% MINIMUM SPREAD =====
        MIN_SPREAD = Decimal("0.15")
    
        min_standard = budget_base * (1 + MIN_SPREAD)
        standard_base = max(standard_base, min_standard)
    
        min_premium = standard_base * (1 + MIN_SPREAD)
        premium_base = max(premium_base, min_premium)
    
        # ===== TRANSPORTATION =====
        avg_distance = sum((p.distance_km for p in nearby_providers), Decimal("0")) / Decimal(str(len(nearby_providers)))
    
        usd_rate_per_km = Decimal("0.55")
        if user_currency != "USD":
            try:
                rate_per_km = Decimal(str(convert_amount(float(usd_rate_per_km), "USD", user_currency)))
            except Exception:
                rate_per_km = usd_rate_per_km
        else:
            rate_per_km = usd_rate_per_km
    
        transport_base = (avg_distance * rate_per_km).quantize(Decimal("0.01"))
    
        transport = {
            'budget': transport_base,
            'standard': transport_base,
            'premium': (transport_base * Decimal("0.90")).quantize(Decimal("0.01")),
        }
    
        # ===== SERVICE FEES =====
        def calc_fee(price):
            rate = Decimal("0.10") if price < Decimal("100") else Decimal("0.07")
            return (price * rate).quantize(Decimal("0.01")), int(rate * 100)
    
        # ===== BUILD BREAKDOWN =====
        def build_breakdown(base_price, transport_cost, tier_name):
            fee_amount, fee_percent = calc_fee(base_price)
            total = (base_price + transport_cost + fee_amount).quantize(Decimal("0.01"))
            return {
                "service_price": float(base_price.quantize(Decimal("0.01"))),
                "transportation_cost": float(transport_cost),
                "service_fee_percent": fee_percent,
                "service_fee_amount": float(fee_amount),
                "total_price": float(total),
                "providers_available": len(tiers[tier_name]),
            }
    
        breakdown = {
            "budget": build_breakdown(budget_base, transport['budget'], 'budget'),
            "standard": build_breakdown(standard_base, transport['standard'], 'standard'),
            "premium": build_breakdown(premium_base, transport['premium'], 'premium'),
        }
    
        # ===== TIER INFO =====
        tier_info = {
            "budget": {
                "name": "budget",
                "title": "New & Eager",
                "subtitle": "Great value from rising providers",
                "description": "Providers building their reputation. Great service at the best price.",
                "badge": "💚 Value Pick",
                "icon": "leaf",
                "color": "#22c55e",
            },
            "standard": {
                "name": "standard",
                "title": "Verified Pro",
                "subtitle": "Trusted & established",
                "description": "Verified providers with complete profiles and quality portfolios.",
                "badge": "💙 Most Popular",
                "icon": "shield-check",
                "color": "#3b82f6",
                "recommended": True,
            },
            "premium": {
                "name": "premium",
                "title": "Certified Expert",
                "subtitle": "Top-tier professionals",
                "description": "Highly credentialed experts with certifications and proven work.",
                "badge": "💜 Premium Choice",
                "icon": "crown",
                "color": "#a855f7",
            },
        }
    
        return Response({
            "budget_price": breakdown['budget']['total_price'],
            "standard_price": breakdown['standard']['total_price'],
            "premium_price": breakdown['premium']['total_price'],

            # Legacy field
            "priority_price": breakdown['premium']['total_price'],

            "transportation_cost": float(transport_base),
            "service_fee_percent": {"under_100": 10, "over_99": 7},

            "breakdown": breakdown,
            "tier_info": tier_info,

            "providers_count": len(nearby_providers),
            "providers_by_tier": {
                "budget": len(tiers['budget']),
                "standard": len(tiers['standard']),
                "premium": len(tiers['premium']),
            },

            # NEW: Tier availability (helps frontend show/hide tiers)
            "tier_availability": tier_availability,
            "tier_notes": {
                "budget": None if tier_availability['budget'] else "Price estimated from available providers",
                "standard": None if tier_availability['standard'] else "Price estimated from available providers",
                "premium": None if tier_availability['premium'] else "Price estimated from available providers",
            },

            "provider_service_prices": sorted([
                float(Decimal(str(p.converted_price)).quantize(Decimal("0.01")))
                for p in nearby_providers
            ]),
         
            "user_currency": user_currency,
            "currency_symbol": currency_symbol,
            "service_type": service_type,
        })



    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def accept(self, request, pk=None):
        """
        Provider accepts a booking request with first-come-first-serve locking.
        """
        block = require_email_verified(request.user)
        if block:
            return Response(block, status=403)

        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "You are not a provider"}, status=400)

        if provider.verification_status != "approved":
            return Response(
                {
                    "detail": "Complete KYC verification to access provider features.",
                    "verification_status": provider.verification_status,
                },
                status=403,
            )

        try:
            with transaction.atomic():
                service_request = ServiceRequest.objects.select_for_update().get(
                    pk=pk,
                    status="open",
                    payment_status="paid",
                    service_provider__isnull=True,
                )

                # ===== TIER ELIGIBILITY CHECK =====
                if service_request.selected_tier:
                    if not is_provider_eligible_for_tier(provider, service_request.selected_tier):
                        provider_tier = get_provider_tier(provider)
                        return Response({
                            "detail": f"This is a {service_request.selected_tier.title()} tier job. Your current tier ({provider_tier.title()}) is not eligible.",
                            "error_code": "tier_mismatch",
                            "your_tier": provider_tier,
                            "required_tier": service_request.selected_tier,
                            "how_to_upgrade": "Complete your profile (bio, portfolio, certifications) to increase your tier."
                        }, status=403)


                # Prevent providers from accepting their own booking
                # if service_request.user_id == request.user.id:
                    # return Response({"detail": "You cannot accept your own booking."}, status=400)

                provider_location = (provider.location_latitude, provider.location_longitude)
                user_location = (service_request.location_latitude, service_request.location_longitude)

                distance_miles = geodesic(provider_location, user_location).km * 0.621371
                if distance_miles > 15:
                    return Response(
                        {"detail": f"You are {distance_miles:.1f} miles away (15-mile limit)."},
                        status=400,
                    )

                if provider.get_service_price(service_request.service_type) is None:
                    return Response({"detail": "You do not offer this service."}, status=400)

                if not provider.available:
                    return Response({"detail": "You are not currently available."}, status=400)

                service_request.service_provider = provider
                service_request.status = "accepted"
                service_request.accepted_at = timezone.now()
                service_request.save()

        except ServiceRequest.DoesNotExist:
            return Response({"detail": "Request not found or already accepted."}, status=400)
        except Exception as e:
            return Response({"detail": f"Error accepting request: {str(e)}"}, status=400)

        # Calculate route-based ETA
        eta_data = get_route_eta(
            origin_lat=provider.location_latitude,
            origin_lng=provider.location_longitude,
            dest_lat=service_request.location_latitude,
            dest_lng=service_request.location_longitude,
        )

        # Build notification message with ETA
        eta_text = eta_data.get("duration_text", "")
        distance_text = eta_data.get("distance_text", "")
        eta_info = f" ETA: {eta_text} ({distance_text})" if eta_text else ""

        send_websocket_notification(
            service_request.user,
            (
                f"✅ Your request #{pk} has been accepted by {provider.user.username}!{eta_info} "
                "You have 7 minutes to cancel without penalty."
            ),
            notification_type="booking_accepted",
        )

        serializer = self.get_serializer(service_request, context={"request": request})
        return Response(
            {
                "detail": "Request accepted successfully!",
                "booking": serializer.data,
                "cancellation_deadline": service_request.accepted_at + timedelta(minutes=7),
                "provider_name": provider.user.username,
                "provider_first_name": provider.user.first_name,
                "eta": eta_data,
            }
        )

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def set_offered_price(self, request, pk=None):
        service_request = self.get_object()

        if service_request.user != request.user:
            return Response({"detail": "You do not own this request."}, status=403)

        # IMPORTANT SECURITY CHANGE:
        # This endpoint is NO LONGER allowed to mark a booking as paid.
        # Payment is finalized ONLY by:
        # - Stripe webhook (payment_intent.succeeded)
        # - Flutterwave verify endpoint (server-to-server verification)

        if service_request.payment_status == "paid":
            return Response({"detail": "This request is already paid."}, status=400)


        # Only allow selecting price while still pending/unpaid
        if service_request.status != "pending" or service_request.payment_status != "unpaid":
            return Response({"detail": "This booking is not eligible for price selection."}, status=400)

        offered_price = request.data.get("offered_price")
        if offered_price is None:
            return Response({"detail": "offered_price is required."}, status=400)

        # Get selected tier (required)
        selected_tier = request.data.get("selected_tier")
        if selected_tier not in ['budget', 'standard', 'premium']:
            return Response({
                "detail": "selected_tier is required and must be 'budget', 'standard', or 'premium'."
            }, status=400)

        try:
            offered_decimal = Decimal(str(offered_price))
        except Exception:
            return Response({"detail": "Invalid offered_price."}, status=400)

        if offered_decimal <= 0:
            return Response({"detail": "offered_price must be positive."}, status=400)

        offered_decimal = offered_decimal.quantize(Decimal("0.01"))
        service_request.offered_price = offered_decimal
        service_request.selected_tier = selected_tier

        # Do NOT mark paid here. Payment is finalized only by:
        # - Stripe webhook / Stripe confirmation endpoint
        # - Flutterwave server-side verification
        # Keep it pending/unpaid until a real payment confirmation happens.


        service_request.save(update_fields=["offered_price", "selected_tier"])


        serializer = self.get_serializer(service_request, context={"request": request})
        return Response(serializer.data)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def reset_appointment_time(self, request, pk=None):
        """
        Reset appointment time for unpaid bookings.
        Used when user returns to pay after leaving booking unpaid.

        Rules:
        - Only booking owner can reset
        - Only unpaid/pending bookings can be reset
        - New appointment time must be TODAY (same day)
        - New appointment time must be in the future (not past)
        """
        service_request = self.get_object()

        # Only booking owner can reset
        if service_request.user != request.user:
            return Response({"detail": "You do not own this request."}, status=403)

        # Only allow reset for unpaid/pending bookings
        if service_request.payment_status == "paid":
            return Response({"detail": "This booking is already paid."}, status=400)

        if service_request.status not in ("pending", "open"):
            return Response({
                "detail": "Only pending bookings can have their appointment time reset."
            }, status=400)

        new_appointment_time = request.data.get("appointment_time")
        if not new_appointment_time:
            return Response({"detail": "appointment_time is required."}, status=400)

        try:
            # Parse the new appointment time
            from django.utils.dateparse import parse_datetime
            new_dt = parse_datetime(new_appointment_time)
            if new_dt is None:
                raise ValueError("Invalid datetime format")

            # Make timezone aware if not already
            if new_dt.tzinfo is None:
                new_dt = timezone.make_aware(new_dt)
 
        except (ValueError, TypeError) as e:
            return Response({
                "detail": f"Invalid appointment_time format. Use ISO format (YYYY-MM-DDTHH:MM:SS). Error: {str(e)}"
            }, status=400)

        now = timezone.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)

        # Validation 1: Must be today
        if new_dt < today_start or new_dt >= today_end:
            return Response({
                "detail": "Appointment time must be scheduled for today only.",
                "error_code": "not_today"
            }, status=400)

        # Validation 2: Must be in the future (at least 30 minutes from now)
        min_future_time = now + timedelta(minutes=30)
        if new_dt < min_future_time:
            return Response({
                "detail": "Appointment time must be at least 30 minutes from now.",
                "error_code": "time_too_soon"
            }, status=400)

        # Update the appointment time
        service_request.appointment_time = new_dt
        service_request.save(update_fields=["appointment_time"])

        serializer = self.get_serializer(service_request, context={"request": request})
        return Response({
            "detail": "Appointment time updated successfully.",
            "booking": serializer.data
        })

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def cancel(self, request, pk=None):
        service_request = self.get_object()
        user = request.user

        if service_request.status == "cancelled":
            return Response({"detail": "Request is already cancelled."}, status=400)

        if service_request.status == "completed":
            return Response({"detail": "Completed requests cannot be cancelled."}, status=400)

        actor = None
        if user == service_request.user:
            actor = "user"
        elif service_request.service_provider and service_request.service_provider.user == user:
            actor = "provider"

        if actor is None:
            return Response({"detail": "You are not part of this booking."}, status=403)

        now = timezone.now()
        penalty_amount = Decimal("0.00")
        penalty_message = ""
        refund_amount = Decimal("0.00")
        refund_result = None
        credit_refunded = False  # Initialize early

        if actor == "user":
            # Determine if booking was paid
            was_paid = service_request.payment_status == "paid"
            price = service_request.offered_price or service_request.estimated_price or Decimal("0.00")

            # Check if within free cancellation window (7 minutes after acceptance)
            within_free_window = True
            if service_request.service_provider and service_request.accepted_at:
                free_cancel_deadline = service_request.accepted_at + timedelta(minutes=7)
                within_free_window = now <= free_cancel_deadline
            if was_paid and price > Decimal("0.00"):
                if within_free_window:
                    # FULL REFUND - No penalty
                    refund_amount = price
                    penalty_amount = Decimal("0.00")
                    penalty_message = " (full refund - cancelled within free period)"
                else:
                    # LATE CANCELLATION - Apply 10% penalty
                    penalty_amount = (price * USER_LATE_CANCEL_PENALTY_PERCENT).quantize(Decimal("0.01"))
                    refund_amount = (price - penalty_amount).quantize(Decimal("0.01"))

                    # Split penalty: 80% to provider, 20% to platform
                    provider_penalty_share = (penalty_amount * Decimal("0.80")).quantize(Decimal("0.01"))
                    platform_penalty_share = (penalty_amount * Decimal("0.20")).quantize(Decimal("0.01"))

                    # Credit provider's PENDING balance with their share
                    if service_request.service_provider and provider_penalty_share > Decimal("0.00"):
                        try:
                            from core.services.payouts import credit_provider_cancellation_fee
                            credit_provider_cancellation_fee(
                                sr=service_request,
                                amount=provider_penalty_share,
                            )
                            service_request.provider_cancellation_fee = provider_penalty_share
                        except Exception as e:
                            import logging
                            logging.getLogger(__name__).error(f"Failed to credit cancellation fee: {e}")

                    penalty_message = f" (${penalty_amount} penalty applied, ${refund_amount} refunded)"

                # Process refund via original payment gateway
                if refund_amount > Decimal("0.00"):
                    try:
                        from core.services.payouts import process_cancellation_refund
                        refund_result = process_cancellation_refund(service_request, refund_amount)

                        if refund_result.get("success"):
                            service_request.refund_status = "full" if refund_amount == price else "partial"
                            service_request.refund_amount = refund_amount
                            service_request.refund_reason = "user_cancelled"
                            service_request.refunded_at = now

                            if refund_result.get("refund_id"):
                                if service_request.payment_gateway == "stripe":
                                    service_request.stripe_refund_id = refund_result.get("refund_id")
                                elif service_request.payment_gateway == "flutterwave":
                                    service_request.flutterwave_refund_id = refund_result.get("refund_id")
                        else:
                            service_request.refund_status = "failed"
                            import logging
                            logging.getLogger(__name__).error(
                                f"Refund failed for booking #{pk}: {refund_result.get('error')}"
                            )
                    except Exception as e:
                        service_request.refund_status = "failed"
                        import logging
                        logging.getLogger(__name__).error(f"Refund exception for booking #{pk}: {e}")

            service_request.status = "cancelled"
            service_request.cancelled_at = now
            service_request.cancelled_by = actor

            if penalty_amount > 0:
                service_request.penalty_applied = True
                service_request.penalty_amount = penalty_amount
            else:
                service_request.penalty_applied = False
                service_request.penalty_amount = None

        elif actor == "provider":
            # Provider cancellation - full refund to user, no penalty to user
            was_paid = service_request.payment_status == "paid"
            price = service_request.offered_price or service_request.estimated_price or Decimal("0.00")

            if was_paid and price > Decimal("0.00"):
                refund_amount = price
                try: 
                    from core.services.payouts import process_cancellation_refund
                    refund_result = process_cancellation_refund(service_request, refund_amount)

                    if refund_result.get("success"):
                        service_request.refund_status = "full"
                        service_request.refund_amount = refund_amount
                        service_request.refund_reason = "provider_cancelled"
                        service_request.refunded_at = now

                        if refund_result.get("refund_id"):
                            if service_request.payment_gateway == "stripe":
                                service_request.stripe_refund_id = refund_result.get("refund_id")
                            elif service_request.payment_gateway == "flutterwave":
                                service_request.flutterwave_refund_id = refund_result.get("refund_id")

                    else:
                        service_request.refund_status = "failed"
                except Exception as e:
                    service_request.refund_status = "failed"
                    import logging
                    logging.getLogger(__name__).error(f"Provider cancel refund failed: {e}")

            service_request.service_provider = None
            service_request.status = "open"
            service_request.accepted_at = None
            service_request.cancelled_at = None
            service_request.cancelled_by = None
            service_request.penalty_applied = False
            service_request.penalty_amount = None
            penalty_message = " - Request returned to open pool for other providers"
        
        service_request.save()

        if actor == "user" and service_request.service_provider:
            send_websocket_notification(
                service_request.service_provider.user,
                f"❌ Booking #{pk} was cancelled by the user{penalty_message}.",
                notification_type="booking_cancelled",
            )
        elif actor == "provider":
            send_websocket_notification(
                service_request.user,
                f"❌ Booking #{pk} was cancelled by the provider{penalty_message}.",
                notification_type="booking_cancelled",
            )

        # ✅ Refund referral credit if applicable (BEFORE building response)
        credit_refunded = service_request.refund_referral_credit_if_applicable()

        # Refresh from DB to get updated fields
        service_request.refresh_from_db()
        serializer = self.get_serializer(service_request, context={"request": request})

        response_data = {
            "detail": f"Booking cancelled successfully.{penalty_message}",
            "booking": serializer.data,
            "credit_refunded": credit_refunded,
            "refund_status": service_request.refund_status,
        }

        if refund_result:
            response_data["refund"] = {
                "success": refund_result.get("success", False),
                "amount": str(refund_amount),
                "status": service_request.refund_status,
            }
            if not refund_result.get("success"):
                response_data["refund"]["error"] = refund_result.get("error", "Unknown error")

        return Response(response_data)



    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def confirm_completion(self, request, pk=None):
        service_request = self.get_object()
        user = request.user

        if service_request.status == "cancelled":
            return Response({"detail": "Cancelled bookings cannot be completed."}, status=400)

        if service_request.payment_status != "paid":
            return Response({"detail": "Booking is not paid yet."}, status=400)

        if user == service_request.user:
            service_request.user_confirmed_completion = True
        elif service_request.service_provider and service_request.service_provider.user == user:
            service_request.provider_confirmed_completion = True
        else:
            return Response({"detail": "You are not part of this booking."}, status=403)

        if service_request.user_confirmed_completion and service_request.provider_confirmed_completion:
            service_request.status = "completed"
            if service_request.completed_at is None:
                service_request.completed_at = timezone.now()

        service_request.save()

        if service_request.status == "completed":

            # Create provider earning as PENDING in wallet (cooldown applies)
            try:
                credit_provider_pending_from_request(service_request)
            except Exception:
                pass

            send_websocket_notification(
                service_request.user,
                f"🎉 Booking #{pk} completed! Payment will be released to provider.",
                notification_type="booking_completed",
            )

            if service_request.service_provider:
                send_websocket_notification(
                    service_request.service_provider.user,
                    f"🎉 Booking #{pk} completed! Payment will be released to you.",
                    notification_type="booking_completed",
                )

        else:
            # Only one side confirmed so far -> notify the other side (professional notice)
            notice = (
                f"Action required: Please confirm completion for booking #{pk} so we can finalize the service and proceed with payment processing."
            )
            if user == service_request.user and service_request.service_provider:
                send_websocket_notification(
                    service_request.service_provider.user,
                    notice,
                    notification_type="completion_confirmation_needed",
                )
            elif service_request.service_provider and user == service_request.service_provider.user:
                send_websocket_notification(
                    service_request.user,
                    notice,
                    notification_type="completion_confirmation_needed",
                )

        serializer = self.get_serializer(service_request, context={"request": request})
        return Response(serializer.data)

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated])
    def contact_info(self, request, pk=None):
        service_request = self.get_object()

        provider_user = (
            service_request.service_provider.user 
            if service_request.service_provider 
            else None
        )

        if request.user not in (service_request.user, provider_user):
            return Response({"detail": "You are not part of this booking."}, status=403)

        if not service_request.is_chat_allowed():
            return Response(
                {
                    "detail": (
                        "Chat and calls are only available when the booking is "
                        "accepted, in progress, or completed within the last day."
                    )
                },
                status=400,
            )

        if request.user == service_request.user:
            if not provider_user:
                return Response({"detail": "No provider assigned yet."}, status=400)
            counterpart = provider_user
        else:
            counterpart = service_request.user

        if not counterpart.phone_number:
            return Response(
                {"detail": "The other user has no phone number on file."}, 
                status=400,
            )

        return Response(
            {"name": counterpart.username, "phone_number": counterpart.phone_number}
        )

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated])
    def eta(self, request, pk=None):
        """
        GET /api/service_requests/<id>/eta/
        Returns route-based ETA from provider to requester location.
        """
        service_request = self.get_object()
        user = request.user

        # Check authorization
        provider_user = (
            service_request.service_provider.user 
            if service_request.service_provider 
            else None
        )

        if user not in (service_request.user, provider_user):
            return Response({"detail": "You are not part of this booking."}, status=403)

        # Only available for accepted/in_progress bookings
        if service_request.status not in ("accepted", "in_progress"):
            return Response(
                {"detail": "ETA is only available for accepted or in-progress bookings."},
                status=400,
            )

        if not service_request.service_provider:
            return Response({"detail": "No provider assigned yet."}, status=400)

        provider = service_request.service_provider

        # Get provider's latest location (prefer LocationUpdate if available)
        latest_location = (
            LocationUpdate.objects.filter(
                booking=service_request,
                is_provider=True,
            )
            .order_by("-timestamp")
            .first()
        )

        if latest_location:
            provider_lat = latest_location.latitude
            provider_lng = latest_location.longitude
        else:
            provider_lat = provider.location_latitude
            provider_lng = provider.location_longitude

        if provider_lat is None or provider_lng is None:
            return Response({"detail": "Provider location not available."}, status=400)

        # Check if provider has arrived
        has_arrived, distance_meters = check_provider_arrived(
            provider_lat=provider_lat,
            provider_lng=provider_lng,
            dest_lat=service_request.location_latitude,
            dest_lng=service_request.location_longitude,
        )

        # Calculate ETA
        eta_data = get_route_eta(
            origin_lat=provider_lat,
            origin_lng=provider_lng,
            dest_lat=service_request.location_latitude,
            dest_lng=service_request.location_longitude,
        )

        # Add arrival status to eta_data
        eta_data["provider_arrived"] = has_arrived
        eta_data["distance_to_destination_meters"] = round(distance_meters, 1)

        return Response({
            "booking_id": service_request.id,
            "provider_location": {
                "latitude": provider_lat,
                "longitude": provider_lng,
            },
            "requester_location": {
                "latitude": service_request.location_latitude,
                "longitude": service_request.location_longitude,
            },
            "eta": eta_data,
            "provider_arrived": has_arrived,
        })

    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated])
    def provider_reviews(self, request, pk=None):
        """
        GET /api/service_requests/<id>/provider_reviews/
        Returns recent reviews (max 7) for the provider assigned to this booking.
        Allows requesters to see provider reputation after acceptance.
        """
        from django.db.models import Avg

        service_request = self.get_object()
        user = request.user

        # Only the requester can view this
        if service_request.user != user:
            return Response({"detail": "Not authorized."}, status=403)

        # Only available for accepted/in_progress/completed bookings
        if service_request.status not in ("accepted", "in_progress", "completed"):
            return Response(
                {"detail": "Reviews only available after provider accepts."},
                status=400,
            )

        if not service_request.service_provider:
            return Response({"detail": "No provider assigned yet."}, status=400)

        provider = service_request.service_provider

        # Get recent reviews (max 7, only those with comments)
        reviews = (
            Review.objects.filter(service_provider=provider)
            .exclude(comment__exact='')
            .exclude(comment__isnull=True)
            .select_related("user")
            .order_by("-created_at")[:7]
        )

        reviews_data = [
            {
                "id": review.id,
                "rating": review.rating,
                "comment": review.comment,
                "created_at": review.created_at.isoformat() if review.created_at else None,
                "user": {
                    "first_name": review.user.first_name,
                    "last_name": review.user.last_name,
                    "username": review.user.username,
                    "profile_picture_url": (
                        request.build_absolute_uri(review.user.profile_picture.url)
                        if review.user.profile_picture else None
                    ),
                },
            }
            for review in reviews
        ]

        return Response({
            "provider_id": provider.id,
            "average_rating": provider.reviews.aggregate(avg=Avg("rating"))["avg"] or 0,
            "review_count": provider.reviews.count(),
            "reviews": reviews_data,
        })


    # TIPS (Stripe PaymentIntent)

    @action(
        detail=True, 
        methods=["post"], 
        url_path=r"tip/create_payment_intent",
        permission_classes=[IsAuthenticated],
    )
    def tip_create_payment_intent(self, request, pk=None):
        """
        POST /api/service_requests/<id>/tip/create_payment_intent/

        """
        if not getattr(request.user, "email_verified", False):
            return Response({"detail": "Verify your email before making payments."}, status=403)

        # ═══════════════════════════════════════════════════════════════════
        # GATEWAY CHECK
        # ═══════════════════════════════════════════════════════════════════
        from core.utils.paystack_countries import get_payment_gateway_for_country
    
        user_country = (request.user.country_name or "").strip()
        correct_gateway = get_payment_gateway_for_country(user_country)
    
        if correct_gateway != "stripe":
            return Response({
                "detail": f"Tip payments in your country are processed via {correct_gateway.title()}.",
                "error_code": f"{correct_gateway}_required",
            }, status=403)
        # ═══════════════════════════════════════════════════════════════════

        service_request = self.get_object()


        if service_request.user != request.user:
            return Response(
                {"detail": "Not allowed to tip for this booking."}, 
                status=403,
            )

        if service_request.payment_status != "paid":
            return Response({"detail": "Booking must be paid before tipping."}, status=400)

        if service_request.status != "completed":
            return Response({"detail": "You can only tip after the booking is completed."}, status=400)

        # If already handled, don't create a new PaymentIntent.
        if getattr(service_request, "tip_payment_status", "unpaid") in ("paid", "skipped"):
            return Response({"detail": "Tip already handled for this booking."}, status=400)

        raw_tip = request.data.get("tip_amount")
        if raw_tip is None:
            return Response({"detail": "tip_amount is required."}, status=400)

        try:
            tip_amount = Decimal(str(raw_tip)).quantize(Decimal("0.01"))
        except Exception:
            return Response({"detail": "Invalid tip_amount."}, status=400)

        if tip_amount < Decimal("0.00"):
            return Response({"detail": "tip_amount cannot be negative."}, status=400)

        # Tip of 0 is allowed, but should be persisted via /tip/set/ (skipped).
        # We do NOT create a Stripe PaymentIntent for 0.
        if tip_amount == Decimal("0.00"):
            return Response(
                {
                    "client_secret": None,
                    "message": "no_payment_required",
                    "tip_amount": "0.00",
                },
                status=200,
            )

        # ═══════════════════════════════════════════════════════════════════
        # CURRENCY VALIDATION
        # ═══════════════════════════════════════════════════════════════════
        from core.utils.payment_routing import validate_and_convert_for_stripe, normalize_currency
    
        booking_currency = normalize_currency(service_request.currency)
        final_tip, final_currency, was_converted = validate_and_convert_for_stripe(
            tip_amount, booking_currency, request.user
        )
        # ═══════════════════════════════════════════════════════════════════

        stripe.api_key = settings.STRIPE_SECRET_KEY
        amount_int = _to_stripe_minor_units(final_tip, final_currency)

        try:
            pi = stripe.PaymentIntent.create(
                amount=amount_int,
                currency=final_currency.lower(),
                automatic_payment_methods={"enabled": True},
                metadata={
                    "type": "tip",
                    "service_request_id": str(service_request.id),
                    "user_id": str(request.user.id),
                },
            )

        except stripe.error.InvalidRequestError as e:
            error_message = str(e).lower()
            if "payment method" in error_message:
                try:
                    pi = stripe.PaymentIntent.create(
                        amount=amount_int,
                        currency=final_currency.lower(),
                        payment_method_types=["card"],
                        metadata={
                            "type": "tip",
                            "service_request_id": str(service_request.id),
                            "user_id": str(request.user.id),
                        },
                    )
                except stripe.error.StripeError as fallback_e:
                    return Response({"detail": str(fallback_e)}, status=400)
            else:
                return Response({"detail": str(e)}, status=400)

        except stripe.error.StripeError as e:
            return Response({"detail": str(e)}, status=400)

        service_request.stripe_tip_payment_intent_id = pi.id
        service_request.save(update_fields=["stripe_tip_payment_intent_id"])

        return Response(
            {
                "client_secret": pi["client_secret"],
                "payment_intent_id": pi["id"],
                "currency": final_currency.lower(),
                "tip_amount": str(final_tip),
            },
            status=200,
        )

    @action(detail=True, methods=["post"], url_path=r"tip/set", permission_classes=[IsAuthenticated])
    def tip_set(self, request, pk=None):
        """
        POST /api/service_requests/<id>/tip/set/
        Body: { "tip_amount": 12.34 }

        Confirms tip after Stripe sheet succeeds and marks booking as tipped.
        Server verifies PaymentIntent succeeded.
        """
        service_request = self.get_object()

        if service_request.user != request.user:
            return Response({"detail": "Not allowed."}, status=403)

        # Do not allow changing tip after it was already handled.
        current_status = getattr(service_request, "tip_payment_status", "unpaid")
        if current_status in ("paid", "skipped"):
            serializer = self.get_serializer(service_request, context={"request": request})
            return Response(serializer.data, status=200)


        raw_tip = request.data.get("tip_amount")
        if raw_tip is None:
            return Response({"detail": "tip_amount is required."}, status=400)

        try:
            tip_amount = Decimal(str(raw_tip)).quantize(Decimal("0.01"))
        except Exception:
            return Response({"detail": "Invalid tip_amount."}, status=400)

        if tip_amount < Decimal("0.00"):
            return Response({"detail": "tip_amount cannot be negative."}, status=400)

        # If user chose 0, persist "skipped" and finish.
        if tip_amount == Decimal("0.00"):
            service_request.tip_amount = Decimal("0.00")
            service_request.tip_payment_status = "skipped"
            service_request.tip_paid_at = timezone.now()
            service_request.save(update_fields=["tip_amount", "tip_payment_status", "tip_paid_at"])

            serializer = self.get_serializer(service_request, context={"request": request})
            return Response(serializer.data, status=200)

        pi_id = (getattr(service_request, "stripe_tip_payment_intent_id", None) or "").strip()
        if not pi_id:
            return Response({"detail": "No tip PaymentIntent exists for this booking."}, status=400)

        stripe.api_key = settings.STRIPE_SECRET_KEY
        try:
            pi = stripe.PaymentIntent.retrieve(pi_id)
        except Exception as e:
            return Response({"detail": f"Unable to verify tip payment: {e}"}, status=400)

        if pi.get("status") != "succeeded":
            return Response({"detail": "Tip payment has not succeeded."}, status=400)

        currency_u = (service_request.currency or "USD").upper().strip()

        # Verify this PI is actually for this booking/user
        meta = pi.get("metadata") or {}
        if str(meta.get("service_request_id") or "") != str(service_request.id):
            return Response({"detail": "Tip payment intent does not match this booking."}, status=400)
        if str(meta.get("user_id") or "") != str(request.user.id):
            return Response({"detail": "Tip payment intent does not match this user."}, status=400)

        # Record the actual paid amount from Stripe (don't trust the client amount)
        amount_minor = int(pi.get("amount") or 0)
        exp = _currency_exponent(currency_u)
        if exp == 0:
            paid_tip_amount = Decimal(str(amount_minor)).quantize(Decimal("1"))
        else:
            paid_tip_amount = (Decimal(str(amount_minor)) / Decimal("100")).quantize(Decimal("0.01"))

        # Persist tip fields (must exist in model)
        service_request.tip_amount = paid_tip_amount
        service_request.tip_payment_status = "paid"
        service_request.tip_paid_at = timezone.now()
        service_request.save(update_fields=["tip_amount", "tip_payment_status", "tip_paid_at"])

        # Credit provider wallet with tip
        if service_request.service_provider:
            try:
                from core.services.payouts import credit_provider_pending_from_request
                credit_provider_pending_from_request(service_request, is_tip=True)
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"Failed to credit tip to provider wallet: {e}")

        serializer = self.get_serializer(service_request, context={"request": request})
        return Response(serializer.data, status=200)

    @action(
        detail=True,
        methods=["post"],
        url_path=r"tip/flutterwave_checkout",
        permission_classes=[IsAuthenticated],
    )
    def tip_flutterwave_checkout(self, request, pk=None):
        """
        POST /api/service_requests/<id>/tip/flutterwave_checkout/
        Body: { "tip_amount": 12.34 }

        Creates a Flutterwave checkout for tipping (African users only).
        """
        if not getattr(request.user, "email_verified", False):
            return Response(
                {"detail": "Verify your email before making payments."},
                status=403,
            )

        # Only African users should use Flutterwave
        user_country = (request.user.country_name or "").strip()
        if not is_african_country_name(user_country):
            return Response(
                {"detail": "Flutterwave tips are only available for African users."},
                status=403,
            )

        service_request = self.get_object()

        if service_request.user != request.user:
            return Response(
                {"detail": "Not allowed to tip for this booking."},
                status=403,
            )

        if service_request.payment_status != "paid":
            return Response({"detail": "Booking must be paid before tipping."}, status=400)

        if service_request.status != "completed":
            return Response({"detail": "You can only tip after the booking is completed."}, status=400)

        # If already handled, don't allow new tip
        current_tip_status = getattr(service_request, "tip_payment_status", "unpaid") or "unpaid"
        if current_tip_status in ("paid", "skipped"):
            return Response({"detail": "Tip already handled for this booking."}, status=400)

        raw_tip = request.data.get("tip_amount")
        if raw_tip is None:
            return Response({"detail": "tip_amount is required."}, status=400)

        try:
            tip_amount = Decimal(str(raw_tip)).quantize(Decimal("0.01"))
        except Exception:
            return Response({"detail": "Invalid tip_amount."}, status=400)

        if tip_amount < Decimal("0.00"):
            return Response({"detail": "tip_amount cannot be negative."}, status=400)

        # Tip of 0 doesn't need payment
        if tip_amount == Decimal("0.00"):
            return Response(
                {
                    "public_key": None,
                    "tx_ref": None,
                    "message": "no_payment_required",
                    "tip_amount": "0.00",
                },
                status=200,
            )

        # Generate unique tx_ref for tip
        tx_ref = f"styloria_tip_sr{service_request.id}_{uuid.uuid4().hex[:12]}"

        # Store tip info on service request
        service_request.tip_flutterwave_tx_ref = tx_ref
        service_request.tip_amount = tip_amount
        service_request.save(update_fields=["tip_flutterwave_tx_ref", "tip_amount"])

        # Use user's preferred currency
        currency_u = get_currency_for_country(request.user.country_name).upper().strip()

        full_name = f"{(request.user.first_name or '').strip()} {(request.user.last_name or '').strip()}".strip()
        if not full_name:
            full_name = request.user.username

        return Response(
            {
                "public_key": getattr(settings, "FLUTTERWAVE_PUBLIC_KEY", ""),
                "encryption_key": getattr(settings, "FLUTTERWAVE_ENCRYPTION_KEY", ""),
                "is_test_mode": bool(getattr(settings, "FLUTTERWAVE_TEST_MODE", True)),
                "tx_ref": tx_ref,
                "currency": currency_u,
                "amount": float(tip_amount),
                "customer_email": request.user.email or "",
                "customer_phone": request.user.phone_number or "",
                "customer_name": full_name,
            },
            status=200,
        )

    @action(
        detail=True,
        methods=["post"],
        url_path=r"tip/flutterwave_verify",
        permission_classes=[IsAuthenticated],
    )
    def tip_flutterwave_verify(self, request, pk=None):
        """
        POST /api/service_requests/<id>/tip/flutterwave_verify/
        Body: { "tx_ref": "...", "transaction_id": 12345 }

        Server-to-server verification for Flutterwave tip payment.
        """
        if not getattr(request.user, "email_verified", False):
            return Response(
                {"detail": "Verify your email before making payments."},
                status=403,
            )

        service_request = self.get_object()

        if service_request.user != request.user:
            return Response({"detail": "Not authorized."}, status=403)

        tx_ref = (request.data.get("tx_ref") or "").strip()
        transaction_id = request.data.get("transaction_id")

        if not tx_ref or transaction_id is None:
            return Response({"detail": "tx_ref and transaction_id are required."}, status=400)

        # Verify tx_ref matches what we stored
        stored_tx_ref = getattr(service_request, "tip_flutterwave_tx_ref", "") or ""
        if stored_tx_ref != tx_ref:
            return Response({"verified": False, "detail": "Transaction reference mismatch."}, status=400)

        # If already paid, return success (idempotent)
        current_tip_status = getattr(service_request, "tip_payment_status", "unpaid") or "unpaid"
        if current_tip_status == "paid":
            serializer = self.get_serializer(service_request, context={"request": request})
            return Response({"verified": True, "booking": serializer.data}, status=200)

        # Call Flutterwave verify endpoint
        try:
            import requests as http_requests
        except Exception:
            return Response({"verified": False, "detail": "Server missing 'requests' dependency."}, status=500)

        try:
            url = f"{_flutterwave_base_url()}/transactions/{int(transaction_id)}/verify"
        except Exception:
            return Response({"verified": False, "detail": "Invalid transaction_id."}, status=400)

        try:
            r = http_requests.get(url, headers=_flutterwave_auth_headers(), timeout=25)
            data = r.json() if r.content else {}
        except Exception as e:
            return Response({"verified": False, "detail": f"Verification request failed: {e}"}, status=400)

        if r.status_code < 200 or r.status_code >= 300:
            return Response({"verified": False, "detail": "Flutterwave verification failed.", "raw": data}, status=400)

        fw_data = (data or {}).get("data") or {}
        fw_status = (fw_data.get("status") or "").lower().strip()
        fw_tx_ref = (fw_data.get("tx_ref") or "").strip()

        if fw_status != "successful":
            return Response({"verified": False, "detail": "Transaction not successful."}, status=400)

        if fw_tx_ref != tx_ref:
            return Response({"verified": False, "detail": "tx_ref mismatch."}, status=400)

        # Get verified amount
        try:
            fw_amount = Decimal(str(fw_data.get("amount") or "0")).quantize(Decimal("0.01"))
        except Exception:
            return Response({"verified": False, "detail": "Invalid amount in Flutterwave response."}, status=400)

        # Mark tip as paid
        with transaction.atomic():
            sr_locked = ServiceRequest.objects.select_for_update().get(pk=service_request.pk)
            sr_locked.tip_amount = fw_amount
            sr_locked.tip_payment_status = "paid"
            sr_locked.tip_paid_at = timezone.now()
            sr_locked.tip_flutterwave_transaction_id = str(transaction_id)
            sr_locked.save(update_fields=[
                "tip_amount",
                "tip_payment_status",
                "tip_paid_at",
                "tip_flutterwave_transaction_id",
            ])

        # Credit provider wallet with tip
        if service_request.service_provider:
            try:
                credit_provider_pending_from_request(service_request, is_tip=True)
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"Failed to credit tip to provider: {e}")

        sr_refresh = ServiceRequest.objects.get(pk=service_request.pk)
        serializer = self.get_serializer(sr_refresh, context={"request": request})
        return Response({"verified": True, "booking": serializer.data}, status=200)

    @action(
        detail=True,
        methods=["post"],
        url_path=r"tip/flutterwave_verify_by_ref",
        permission_classes=[IsAuthenticated],
    )
    def tip_flutterwave_verify_by_ref(self, request, pk=None):
        """
        POST /api/service_requests/<id>/tip/flutterwave_verify_by_ref/
        Body: { "tx_ref": "..." }

        Verifies Flutterwave tip payment by tx_ref only (for MoMo where redirect fails).
        Uses Flutterwave's verify-by-reference endpoint.
        """
        service_request = self.get_object()

        if service_request.user != request.user:
            return Response({"detail": "Not authorized."}, status=403)

        tx_ref = (request.data.get("tx_ref") or "").strip()
        if not tx_ref:
            return Response({"detail": "tx_ref is required."}, status=400)

        # Verify tx_ref matches what we stored
        stored_tx_ref = getattr(service_request, "tip_flutterwave_tx_ref", "") or ""
        if stored_tx_ref != tx_ref:
            return Response({"verified": False, "detail": "Transaction reference mismatch."}, status=400)

        # If already paid, return success (idempotent)
        current_tip_status = getattr(service_request, "tip_payment_status", "unpaid") or "unpaid"
        if current_tip_status == "paid":
            serializer = self.get_serializer(service_request, context={"request": request})
            return Response({"verified": True, "booking": serializer.data}, status=200)

        # Call Flutterwave verify-by-reference endpoint
        try:
            import requests as http_requests
        except Exception:
            return Response({"verified": False, "detail": "Server missing 'requests' dependency."}, status=500)

        url = f"{_flutterwave_base_url()}/transactions/verify_by_reference?tx_ref={tx_ref}"

        try:
            r = http_requests.get(url, headers=_flutterwave_auth_headers(), timeout=25)
            data = r.json() if r.content else {}
        except Exception as e:
            return Response({"verified": False, "detail": f"Verification request failed: {e}"}, status=400)

        if r.status_code < 200 or r.status_code >= 300:
            return Response({
                "verified": False, 
                "detail": "Flutterwave verification failed or payment not found.",
                "raw": data
            }, status=400)

        fw_data = (data or {}).get("data") or {}
        fw_status = (fw_data.get("status") or "").lower().strip()
        fw_tx_ref = (fw_data.get("tx_ref") or "").strip()
        transaction_id = fw_data.get("id")

        if fw_status != "successful":
            return Response({
                "verified": False, 
                "detail": f"Transaction status: {fw_status}",
                "status": fw_status,
            }, status=400)

        if fw_tx_ref != tx_ref:
            return Response({"verified": False, "detail": "tx_ref mismatch from Flutterwave."}, status=400)

        # Get verified amount
        try:
            fw_amount = Decimal(str(fw_data.get("amount") or "0")).quantize(Decimal("0.01"))
        except Exception:
            return Response({"verified": False, "detail": "Invalid amount in Flutterwave response."}, status=400)

        # Mark tip as paid
        with transaction.atomic():
            sr_locked = ServiceRequest.objects.select_for_update().get(pk=service_request.pk)
            sr_locked.tip_amount = fw_amount
            sr_locked.tip_payment_status = "paid"
            sr_locked.tip_paid_at = timezone.now()
            if transaction_id:
                sr_locked.tip_flutterwave_transaction_id = str(transaction_id)
            sr_locked.save(update_fields=[
                "tip_amount",
                "tip_payment_status",
                "tip_paid_at",
                "tip_flutterwave_transaction_id",
            ])

        # Credit provider wallet with tip
        if service_request.service_provider:
            try:
                credit_provider_pending_from_request(service_request, is_tip=True)
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"Failed to credit tip to provider: {e}")

        sr_refresh = ServiceRequest.objects.get(pk=service_request.pk)
        serializer = self.get_serializer(sr_refresh, context={"request": request})
        return Response({"verified": True, "booking": serializer.data}, status=200)

    @action(
        detail=True,
        methods=["post"],
        url_path=r"tip/paystack_checkout",
        permission_classes=[IsAuthenticated],
    )
    def tip_paystack_checkout(self, request, pk=None):
        """
        POST /api/service_requests/<id>/tip/paystack_checkout/
        Body: { "tip_amount": 10.00 }

        Creates a Paystack checkout for tipping (Paystack countries only).
        """
        if not getattr(request.user, "email_verified", False):
            return Response(
                {"detail": "Verify your email before making payments."},
                status=403,
            )

        # Only Paystack country users should use this
        user_country = (request.user.country_name or "").strip()
        if not is_paystack_country(user_country):
            return Response(
                {"detail": "Paystack tips are only available for supported countries."},
                status=403,
            )

        service_request = self.get_object()

        if service_request.user != request.user:
            return Response(
                {"detail": "Not allowed to tip for this booking."},
                status=403,
            )

        if service_request.payment_status != "paid":
            return Response({"detail": "Booking must be paid before tipping."}, status=400)

        if service_request.status != "completed":
            return Response({"detail": "You can only tip after the booking is completed."}, status=400)

        current_tip_status = getattr(service_request, "tip_payment_status", "unpaid") or "unpaid"
        if current_tip_status in ("paid", "skipped"):
            return Response({"detail": "Tip already handled for this booking."}, status=400)

        raw_tip = request.data.get("tip_amount")
        if raw_tip is None:
            return Response({"detail": "tip_amount is required."}, status=400)

        try:
            tip_amount = Decimal(str(raw_tip)).quantize(Decimal("0.01"))
        except Exception:
            return Response({"detail": "Invalid tip_amount."}, status=400)

        if tip_amount < Decimal("0.00"):
            return Response({"detail": "tip_amount cannot be negative."}, status=400)

        # Tip of 0 doesn't need payment
        if tip_amount == Decimal("0.00"):
            return Response(
                {
                    "authorization_url": None,
                    "message": "no_payment_required",
                    "tip_amount": "0.00",
                },
                status=200,
            )

        # Get currency and generate reference
        currency_u = get_paystack_currency(user_country) or get_currency_for_country(user_country)
        currency_u = currency_u.upper().strip()

        reference = f"styloria_tip_sr{service_request.id}_{uuid.uuid4().hex[:12]}"

        # Store tip info
        service_request.tip_paystack_reference = reference
        service_request.tip_amount = tip_amount
        service_request.save(update_fields=["tip_paystack_reference", "tip_amount"])

        # Build callback URL
        callback_url = getattr(settings, "PAYSTACK_CALLBACK_URL", None)
        if not callback_url:
            callback_url = f"{getattr(settings, 'PUBLIC_BASE_URL', '')}/paystack/callback/"

        # Initialize Paystack transaction
        result = paystack_initialize(
            email=request.user.email,
            amount=tip_amount,
            currency=currency_u,
            reference=reference,
            callback_url=callback_url,
            metadata={
                "service_request_id": str(service_request.id),
                "user_id": str(request.user.id),
                "payment_type": "tip",
            },
        )

        if not result.get("success"):
            return Response({
                "detail": result.get("message") or "Failed to initialize tip payment",
            }, status=400)

        return Response({
            "authorization_url": result.get("authorization_url"),
            "access_code": result.get("access_code"),
            "reference": reference,
            "currency": currency_u,
            "amount": float(tip_amount),
            "public_key": getattr(settings, "PAYSTACK_PUBLIC_KEY", ""),
        }, status=200)

    @action(
        detail=True,
        methods=["post"],
        url_path=r"tip/paystack_verify",
        permission_classes=[IsAuthenticated],
    )
    def tip_paystack_verify(self, request, pk=None):
        """
        POST /api/service_requests/<id>/tip/paystack_verify/
        Body: { "reference": "styloria_tip_sr123_abc" }

        Server-to-server verification for Paystack tip payment.
        """
        service_request = self.get_object()

        if service_request.user != request.user:
            return Response({"detail": "Not authorized."}, status=403)

        reference = (request.data.get("reference") or "").strip()
        if not reference:
            return Response({"detail": "reference is required."}, status=400)

        # Verify reference matches
        stored_ref = getattr(service_request, "tip_paystack_reference", "") or ""
        if stored_ref != reference:
            return Response({"verified": False, "detail": "Reference mismatch."}, status=400)

        # Idempotent: if already paid
        current_tip_status = getattr(service_request, "tip_payment_status", "unpaid") or "unpaid"
        if current_tip_status == "paid":
            serializer = self.get_serializer(service_request, context={"request": request})
            return Response({"verified": True, "booking": serializer.data}, status=200)

        # Verify with Paystack
        result = paystack_verify(reference)

        if not result.get("success"):
            return Response({
                "verified": False,
                "detail": result.get("message") or "Tip payment verification failed.",
            }, status=400)

        # Get verified amount
        verified_amount = result.get("amount") or Decimal("0.00")
        transaction_id = result.get("transaction_id")

        # Mark tip as paid
        with transaction.atomic():
            sr_locked = ServiceRequest.objects.select_for_update().get(pk=service_request.pk)
            sr_locked.tip_amount = verified_amount
            sr_locked.tip_payment_status = "paid"
            sr_locked.tip_paid_at = timezone.now()
            sr_locked.tip_paystack_transaction_id = str(transaction_id) if transaction_id else ""
            sr_locked.save(update_fields=[
                "tip_amount",
                "tip_payment_status",
                "tip_paid_at",
                "tip_paystack_transaction_id",
            ])

        # Credit provider wallet with tip
        if service_request.service_provider:
            try:
                credit_provider_pending_from_request(service_request, is_tip=True)
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"Failed to credit tip to provider: {e}")

        service_request.refresh_from_db()
        serializer = self.get_serializer(service_request, context={"request": request})
        return Response({"verified": True, "booking": serializer.data}, status=200)


class RequesterReviewViewSet(viewsets.ModelViewSet):
    """
    API for providers to review requesters after completing a service.
    """
    queryset = RequesterReview.objects.all()
    serializer_class = RequesterReviewSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        # Providers see reviews they've given
        # Users see reviews they've received
        if hasattr(user, 'provider_profile'):
            return RequesterReview.objects.filter(provider=user.provider_profile)
        return RequesterReview.objects.filter(user=user)

    @action(detail=False, methods=['get'], url_path='my-reputation')
    def my_reputation(self, request):
        """
        GET /api/requester_reviews/my-reputation/
        Get all reviews written about the current user (for customers to see their reputation).
        """
        user = request.user
        reviews = RequesterReview.objects.filter(user=user).select_related(
            'provider', 'provider__user', 'service_request'
        ).order_by('-created_at')

        # Calculate stats
        total_reviews = reviews.count()
        avg_rating = reviews.aggregate(avg=Avg('rating'))['avg'] or 0.0

        # Serialize reviews
        reviews_data = []
        for review in reviews[:50]:  # Limit to 50 most recent
            reviews_data.append({
                'id': review.id,
                'rating': review.rating,
                'comment': review.comment or '',
                'created_at': review.created_at.isoformat() if review.created_at else None,
                'provider_name': (
                    review.provider.user.first_name
                    if review.provider and review.provider.user
                    else 'Provider'
                ),
                'service_type': (
                    review.service_request.service_type
                    if review.service_request
                    else None
                ),
            })

        return Response({
            'average_rating': round(float(avg_rating), 1),
            'total_reviews': total_reviews,
            'reviews': reviews_data,
        })

    @action(detail=False, methods=['get'], url_path='user-reputation/(?P<user_id>[^/.]+)')
    def user_reputation(self, request, user_id=None):
        """
        GET /api/requester_reviews/user-reputation/<user_id>/
        Get reviews about a specific user (for providers to see requester reputation).
        Only accessible by authenticated providers.
        """
        # Verify caller is a provider
        if not hasattr(request.user, 'provider_profile'):
            return Response({'detail': 'Only providers can view user reputation.'}, status=403)

        try:
            target_user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=404)

        reviews = RequesterReview.objects.filter(user=target_user).select_related(
            'provider', 'provider__user', 'service_request'
        ).order_by('-created_at')

        total_reviews = reviews.count()
        avg_rating = reviews.aggregate(avg=Avg('rating'))['avg'] or 0.0

        reviews_data = []
        for review in reviews[:20]:  # Limit to 20 for provider view
            reviews_data.append({
                'id': review.id,
                'rating': review.rating,
                'comment': review.comment or '',
                'created_at': review.created_at.isoformat() if review.created_at else None,
                'provider_name': (
                    review.provider.user.first_name
                    if review.provider and review.provider.user
                    else 'Provider'
                ),
                'service_type': (
                    review.service_request.service_type
                    if review.service_request
                    else None
                ),
            })

        return Response({
            'user_id': target_user.id,
            'user_name': target_user.first_name or target_user.username,
            'profile_picture_url': (
                request.build_absolute_uri(target_user.profile_picture.url)
                if target_user.profile_picture
                else None
            ),
            'average_rating': round(float(avg_rating), 1),
            'total_reviews': total_reviews,
            'reviews': reviews_data,
        })

    
    def create(self, request, *args, **kwargs):
        """
        POST /api/requester_reviews/
        Provider submits a review for a requester after completing service.
        
        Body:
            - service_request_id: int (required)
            - rating: int 1-5 (required)
            - comment: string (optional)
        """
        # Must be a provider
        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "Only providers can review requesters."}, status=403)
        
        service_request_id = request.data.get('service_request_id')
        rating = request.data.get('rating')
        comment = request.data.get('comment', '')
        
        if not service_request_id:
            return Response({"detail": "service_request_id is required."}, status=400)
        
        if not rating or int(rating) < 1 or int(rating) > 5:
            return Response({"detail": "rating must be between 1 and 5."}, status=400)
        
        # Get the service request
        try:
            service_request = ServiceRequest.objects.get(
                id=service_request_id,
                service_provider=provider,
                status='completed'
            )
        except ServiceRequest.DoesNotExist:
            return Response({
                "detail": "Service request not found or not completed by you."
            }, status=404)
        
        # Check if already reviewed
        if RequesterReview.objects.filter(provider=provider, service_request=service_request).exists():
            return Response({"detail": "You have already reviewed this requester for this booking."}, status=400)
        
        # Create review
        review = RequesterReview.objects.create(
            provider=provider,
            user=service_request.user,
            service_request=service_request,
            rating=int(rating),
            comment=comment.strip(),
        )
        
        serializer = self.get_serializer(review)
        return Response({
            "detail": "Review submitted successfully!",
            "review": serializer.data,
            "requester_new_rating": float(service_request.user.requester_average_rating or 0),
            "requester_review_count": service_request.user.requester_review_count,
        }, status=201)
    
    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def for_booking(self, request):
        """
        GET /api/requester_reviews/for_booking/?booking_id=123
        Check if provider has reviewed the requester for a specific booking.
        """
        booking_id = request.query_params.get('booking_id')
        if not booking_id:
            return Response({"detail": "booking_id is required."}, status=400)
        
        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "Not a provider."}, status=403)
        
        review = RequesterReview.objects.filter(
            provider=provider,
            service_request_id=booking_id
        ).first()
        
        if review:
            return Response({
                "has_reviewed": True,
                "review": RequesterReviewSerializer(review).data
            })
        
        return Response({"has_reviewed": False, "review": None})


# -------------------------
# CHAT THREAD VIEWSET
# -------------------------
class ChatThreadViewSet(viewsets.ModelViewSet):
    queryset = ChatThread.objects.all()
    serializer_class = ChatThreadSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return (
            ChatThread.objects.filter(
                Q(service_request__user=user) | Q(service_request__service_provider__user=user)
            )
            .select_related("service_request", "service_request__user", "service_request__service_provider__user")
            .order_by("-id")
        )

    def create(self, request, *args, **kwargs):
        return Response({"detail": "Use /api/chats/for_request/<service_request_id>/"}, status=405)

    @action(detail=False, methods=["get"], url_path="for_request/(?P<request_id>[^/.]+)")
    def for_request(self, request, request_id=None):
        try:
            service_request = ServiceRequest.objects.get(id=request_id)
        except ServiceRequest.DoesNotExist:
            return Response({"detail": "Invalid service_request_id."}, status=400)

        provider_user = service_request.service_provider.user if service_request.service_provider else None
        if request.user not in (service_request.user, provider_user):
            return Response({"detail": "You are not part of this booking."}, status=403)

        if not service_request.is_chat_allowed():
            return Response(
                {
                    "detail": (
                        "Chat is only available when the booking is accepted, "
                        "in progress, or completed within the last day."
                    )
                },
                status=400,
            )

        thread, _ = ChatThread.objects.get_or_create(service_request=service_request)
        serializer = self.get_serializer(thread)
        return Response(serializer.data)

    @action(detail=True, methods=["get", "post"])
    def messages(self, request, pk=None):
        thread = self.get_object()
        service_request = thread.service_request

        provider_user = service_request.service_provider.user if service_request.service_provider else None
        if request.user not in (service_request.user, provider_user):
            return Response({"detail": "You are not part of this chat."}, status=403)

        if not service_request.is_chat_allowed():
            return Response(
                {
                    "detail": (
                        "Chat is only available when the booking is accepted, "
                        "in progress, or completed within the last day."
                    )
                },
                status=400,
            )

        if request.method == "GET":
            qs = ChatMessage.objects.filter(thread=thread).select_related("sender").order_by("created_at")
            serializer = ChatMessageSerializer(qs, many=True)
            return Response(serializer.data)

        content = request.data.get("content", "")
        serializer = ChatMessageSerializer(
            data={"content": content},
            context={"request": request, "thread": thread},
        )
        serializer.is_valid(raise_exception=True)
        msg = serializer.save()

        # ════════════════════════════════════════════════════════════
        # SEND NOTIFICATION TO RECEIVER
        # ════════════════════════════════════════════════════════════

        # Determine the receiver (the other participant)
        sender = request.user
        if sender == service_request.user:
            # Sender is the requester, receiver is the provider
            receiver = provider_user
        else:
            # Sender is the provider, receiver is the requester
            receiver = service_request.user

        if receiver and receiver != sender:
            # Get sender's display name
            sender_name = sender.first_name or sender.username

            # Truncate message for notification preview
            preview = content[:50] + "..." if len(content) > 50 else content

            # Send WebSocket notification
            send_websocket_notification(
                receiver,
                f"💬 New message from {sender_name}: {preview}",
                notification_type="chat_message",
            )

            # Also send via WebSocket with structured data for chat screen
            channel_layer = get_channel_layer()
            try:
                async_to_sync(channel_layer.group_send)(
                    f"notifications_{receiver.id}",
                    {
                        "type": "send_notification",
                        "message": {
                            "type": "chat_message",
                            "thread_id": thread.id,
                            "service_request_id": service_request.id,
                            "sender_id": sender.id,
                            "sender_name": sender_name,
                            "content_preview": preview,
                            "message_id": msg.id,
                            "timestamp": msg.created_at.isoformat(),
                        },
                    },
                )
            except Exception:
                pass  # WebSocket not connected

        return Response(ChatMessageSerializer(msg).data, status=201)


# -------------------------
# SUPPORT CHAT VIEWSET
# -------------------------
class SupportThreadViewSet(viewsets.ModelViewSet):
    queryset = SupportThread.objects.all()
    serializer_class = SupportThreadSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_staff or getattr(user, "role", "") == "admin":
            return SupportThread.objects.select_related("user").order_by("-id")
        return SupportThread.objects.filter(user=user).select_related("user").order_by("-id")

    def create(self, request, *args, **kwargs):
        return Response({"detail": "Use /api/support_chats/my_thread/ to access your support chat."}, status=405)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def my_thread(self, request):
        thread, _ = SupportThread.objects.get_or_create(user=request.user)
        serializer = self.get_serializer(thread)
        return Response(serializer.data)

    @action(detail=True, methods=["get", "post"], permission_classes=[IsAuthenticated])
    def messages(self, request, pk=None):
        thread = self.get_object()
        user = request.user

        if thread.user != user and not (user.is_staff or getattr(user, "role", "") == "admin"):
            return Response({"detail": "You are not allowed to access this chat."}, status=403)

        if request.method == "GET":
            qs = SupportMessage.objects.filter(thread=thread).select_related("sender").order_by("created_at")
            serializer = SupportMessageSerializer(qs, many=True)
            return Response(serializer.data)

        content = request.data.get("content", "")
        serializer = SupportMessageSerializer(
            data={"content": content},
            context={"request": request, "thread": thread},
        )
        serializer.is_valid(raise_exception=True)
        msg = serializer.save()
        return Response(SupportMessageSerializer(msg).data, status=201)


# -------------------------
# REVIEW VIEWSET
# -------------------------
class ReviewViewSet(viewsets.ModelViewSet):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        provider_id = self.request.data.get("service_provider_id")
        service_request_id = self.request.data.get("service_request_id")

        try:
            provider = ServiceProvider.objects.get(id=provider_id)
        except ServiceProvider.DoesNotExist:
            raise serializers.ValidationError({"service_provider_id": "Invalid service provider ID"})

        # Get the service request if provided
        service_request = None
        if service_request_id:
            try:
                service_request = ServiceRequest.objects.get(id=service_request_id)

                # Verify the user owns this booking
                if service_request.user != user:
                    raise serializers.ValidationError({"detail": "You can only review your own bookings."})

                # Verify the booking is completed
                if service_request.status != 'completed':
                    raise serializers.ValidationError({"detail": "You can only review completed bookings."})

                # Verify the provider matches
                if service_request.service_provider != provider:
                    raise serializers.ValidationError({"detail": "Provider does not match this booking."})

                # Prevent duplicate reviews for this booking
                existing_review = Review.objects.filter(user=user, service_request=service_request).exists()
                if existing_review:
                    raise serializers.ValidationError({"detail": "You have already reviewed this booking."})

            except ServiceRequest.DoesNotExist:
                raise serializers.ValidationError({"service_request_id": "Invalid booking ID"})

        serializer.save(user=user, service_provider=provider, service_request=service_request)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def my_reviews(self, request):
        qs = self.get_queryset().filter(user=request.user).order_by("-created_at")
        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated], url_path="for_provider/(?P<provider_id>[^/.]+)")
    def for_provider(self, request, provider_id=None):
        """
        GET /api/reviews/for_provider/<provider_id>/
        Returns reviews for a specific provider.
        """
        from django.db.models import Avg

        try:
            provider = ServiceProvider.objects.get(id=provider_id)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "Provider not found."}, status=404)

        reviews = Review.objects.filter(service_provider=provider).select_related("user").order_by("-created_at")[:50]

        data = [
            {
                "id": review.id,
                "rating": review.rating,
                "comment": review.comment,
                "created_at": review.created_at.isoformat() if review.created_at else None,
                "user": {
                    "id": review.user.id,
                    "username": review.user.username,
                    "first_name": review.user.first_name,
                    "last_name": review.user.last_name,
                },
            }
            for review in reviews
        ]
 
        return Response({
            "provider_id": provider.id,
            "average_rating": provider.reviews.aggregate(avg=Avg("rating"))["avg"] or 0,
            "review_count": provider.reviews.count(),
            "reviews": data,
        })

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def received(self, request):
        """
        GET /api/reviews/received/
        Returns reviews received by the current user (if they are a provider).
        For use in provider's Manage Profile screen.
        """
        from django.db.models import Avg

        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "You are not a provider."}, status=400)

        reviews = Review.objects.filter(service_provider=provider).select_related("user").order_by("-created_at")[:50]
        
        data = [
            {
                "id": review.id,
                "rating": review.rating,
                "comment": review.comment,
                "created_at": review.created_at.isoformat() if review.created_at else None,
                "user": {
                    "id": review.user.id,
                    "username": review.user.username,
                    "first_name": review.user.first_name,
                    "last_name": review.user.last_name,
                    "profile_picture_url": (
                        request.build_absolute_uri(review.user.profile_picture.url)
                        if review.user.profile_picture else None
                    ),
                },
            }
            for review in reviews
        ]
        
        return Response({
            "average_rating": provider.reviews.aggregate(avg=Avg("rating"))["avg"] or 0,
            "review_count": provider.reviews.count(),
            "reviews": data,
        })


# ==================== PROVIDER VERIFICATION VIEWSET ====================
class ProviderVerificationViewSet(viewsets.GenericViewSet):
    """
    Handles provider verification submission and status
    """

    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=["get"], url_path="status")
    def verification_status(self, request):
        try:
            provider = ServiceProvider.objects.get(user=request.user)
            serializer = ServiceProviderSerializer(provider, context={"request": request})
            return Response(serializer.data)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "Provider profile not found."}, status=404)

    @action(detail=False, methods=["post"], url_path="submit")
    def submit_verification(self, request):
        block = require_email_verified(request.user)
        if block:
            return Response(block, status=403)

        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "Provider profile not found."}, status=404)

        if provider.verification_status in ["pending", "approved"]:
            return Response({"detail": f"Verification already {provider.verification_status}."}, status=400)

        required_fields = ["id_document_front", "id_document_back", "verification_selfie"]
        missing = [field for field in required_fields if field not in request.FILES]
        if missing:
            return Response({"detail": f'Missing required files: {", ".join(missing)}'}, status=400)

        if "id_document_front" in request.FILES:
            provider.id_document_front = request.FILES["id_document_front"]
        if "id_document_back" in request.FILES:
            provider.id_document_back = request.FILES["id_document_back"]
        if "verification_selfie" in request.FILES:
            provider.verification_selfie = request.FILES["verification_selfie"]

        provider.verification_status = "pending"
        provider.save()

        serializer = ServiceProviderSerializer(provider, context={"request": request})
        return Response(serializer.data)

    @action(detail=False, methods=["post"], url_path="resubmit")
    def resubmit_verification(self, request):
        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({"detail": "Provider profile not found."}, status=404)

        if provider.verification_status != "rejected":
            return Response(
                {"detail": f"Cannot resubmit. Current status: {provider.verification_status}"},
                status=400,
            )

        if "id_document_front" in request.FILES:
            provider.id_document_front = request.FILES["id_document_front"]
        if "id_document_back" in request.FILES:
            provider.id_document_back = request.FILES["id_document_back"]
        if "verification_selfie" in request.FILES:
            provider.verification_selfie = request.FILES["verification_selfie"]

        provider.verification_status = "pending"
        provider.verification_review_notes = None
        provider.save()

        serializer = ServiceProviderSerializer(provider, context={"request": request})
        return Response(serializer.data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_pending_verifications(request):
    if not is_admin_user(request.user):
        return Response({"detail": "Admin access required."}, status=403)

    pending_providers = (
        ServiceProvider.objects.filter(verification_status="pending")
        .select_related("user")
        .order_by("verification_submitted_at")
    )
    serializer = ServiceProviderSerializer(pending_providers, many=True, context={"request": request})
    return Response(serializer.data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def admin_review_verification(request, provider_id):
    if not is_admin_user(request.user):
        return Response({"detail": "Admin access required."}, status=403)

    try:
        provider = ServiceProvider.objects.get(id=provider_id)
    except ServiceProvider.DoesNotExist:
        return Response({"detail": "Provider not found."}, status=404)

    action_value = request.data.get("action")  # approve|reject
    notes = request.data.get("notes", "")

    if action_value not in ["approve", "reject"]:
        return Response({"detail": 'Action must be "approve" or "reject".'}, status=400)

    if provider.verification_status != "pending":
        return Response(
            {"detail": f"Provider is not pending review. Current status: {provider.verification_status}"},
            status=400,
        )

    provider.verification_status = "approved" if action_value == "approve" else "rejected"
    provider.verification_review_notes = notes
    provider.verification_reviewed_by = request.user
    provider.save()

    if provider.verification_status == "approved":

        _notify_waiting_requests_if_providers_now_available(provider)

    if provider.user.email:
        subject = f"Styloria KYC Verification {provider.verification_status.upper()}"
        if provider.verification_status == "rejected":
            body = (
                "Your Styloria KYC verification was rejected.\n\n"
                f"Reason from reviewer:\n{notes}\n\n"
                "Please review your documents and resubmit in the app."
            )
        else:
            body = "Your Styloria KYC verification was approved.\n\nYou now have full access to provider features."

        from core.utils.ms_graph_mail import send_email_with_fallback
        
        send_email_with_fallback(
            to_email=provider.user.email,
            subject=subject,
            body_text=body,
            fail_silently=True,
        )

    send_websocket_notification(
        provider.user,
        f"Your verification has been {provider.verification_status}. {notes}",
        notification_type="verification_update",
    )

    serializer = ServiceProviderSerializer(provider, context={"request": request})
    return Response(serializer.data)


# -------------------------
# Stripe helpers
# -------------------------
ZERO_DECIMAL_CURRENCIES = {
    "BIF",
    "CLP",
    "DJF",
    "GNF",
    "JPY",
    "KMF",
    "KRW",
    "MGA",
    "PYG",
    "RWF",
    "UGX",
    "VND",
    "VUV",
    "XAF",
    "XOF",
    "XPF",
}


def _currency_exponent(currency: str) -> int:
    c = (currency or "USD").upper().strip()
    return 0 if c in ZERO_DECIMAL_CURRENCIES else 2


def _min_amount_for_currency(currency: str) -> Decimal:
    """
    Approx Stripe minimum using 0.50 USD converted to the booking currency,
    with a 10% buffer to reduce FX/rounding edge failures.
    """
    c = (currency or "USD").upper().strip()

    min_usd = Decimal("0.50")
    buffer_multiplier = Decimal("1.10")

    if c == "USD":
        min_amt = min_usd * buffer_multiplier
    else:
        try:
            converted = convert_amount(float(min_usd), "USD", c)
            min_amt = Decimal(str(converted)) * buffer_multiplier
        except Exception:
            min_amt = min_usd * buffer_multiplier

    exp = _currency_exponent(c)
    quant = Decimal("1") if exp == 0 else Decimal("0.01")
    return min_amt.quantize(quant, rounding=ROUND_UP)


def _to_stripe_minor_units(amount: Decimal, currency: str) -> int:
    """
    Convert Decimal major units into Stripe integer minor units.
    """
    c = (currency or "USD").upper().strip()
    exp = _currency_exponent(c)
    if exp == 0:
        return int(amount.quantize(Decimal("1"), rounding=ROUND_UP))
    return int((amount * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_UP))


# -------------------------
# STRIPE PAYMENT INTENT
# -------------------------
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_payment(request):
    """
    Create Stripe PaymentIntent for non-African users.
    """
    if not getattr(request.user, "email_verified", False):
        return Response({"error": "Verify your email before making payments."}, status=403)

    stripe.api_key = settings.STRIPE_SECRET_KEY
    service_request_id = request.data.get("service_request_id")

    if not service_request_id:
        return Response({"error": "service_request_id is required"}, status=400)

    try:
        service_request = ServiceRequest.objects.get(id=service_request_id)
    except ServiceRequest.DoesNotExist:
        return Response({"error": "Invalid service_request_id"}, status=400)

    if service_request.user != request.user:
        return Response({"error": "Not allowed to pay for this booking"}, status=403)

    # ═══════════════════════════════════════════════════════════════════
    # GATEWAY ROUTING CHECK
    # ═══════════════════════════════════════════════════════════════════
    from core.utils.payment_routing import (
        validate_and_convert_for_stripe,
        normalize_currency,
    )
    from core.utils.paystack_countries import get_payment_gateway_for_country

    user_country = (request.user.country_name or "").strip()
    correct_gateway = get_payment_gateway_for_country(user_country)
    
    if correct_gateway == "paystack":
        return Response({
            "error": "Please use Paystack for payments in your country.",
            "error_code": "paystack_required",
            "correct_gateway": "paystack",
        }, status=403)
    
    if correct_gateway == "flutterwave":
        return Response({
            "error": "Please use Flutterwave for payments in your country.",
            "error_code": "flutterwave_required", 
            "correct_gateway": "flutterwave",
        }, status=403)
    # ═══════════════════════════════════════════════════════════════════

    # Only allow paying while booking is still pending payment
    if service_request.status != "pending" or service_request.payment_status != "unpaid":
        return Response({"error": "This booking is not eligible for payment."}, status=400)

    # HARD GATE: user can only pay if there is at least one eligible provider
    # within 15 miles who offers the requested service.
    has_provider = _has_nearby_available_provider_for_service(
        user_lat=service_request.location_latitude,
        user_lng=service_request.location_longitude,
        service_type=service_request.service_type,
    )
    if not has_provider:
        return Response(
            {
                "error": (
                    "We’re sorry—there are currently no available providers for this service "
                    "in your area. Please try again later."
                )
            },
            status=400,
        )

    # Get amount
    offered_override = request.data.get("offered_price")
    if offered_override is not None:
        try:
            amount_source = Decimal(str(offered_override))
        except Exception:
            return Response({"error": "Invalid offered_price"}, status=400)
    else:
        amount_source = service_request.offered_price or service_request.estimated_price

    if amount_source is None:
        return Response({"error": "This booking has no price set"}, status=400)

    if amount_source <= 0:
        return Response({"error": "Amount must be positive"}, status=400)


    # ═══════════════════════════════════════════════════════════════════
    # REFERRAL DISCOUNT CHECK
    # ═══════════════════════════════════════════════════════════════════
    original_price = amount_source
    discount_applied = False
    discount_amount = Decimal("0")
    
    # Check if user wants to use referral credit (default: yes if available)
    use_referral = request.data.get("use_referral_credit", True)
    
    if use_referral and request.user.referral_credits > 0:
        discounted_price, discount_applied, discount_amount = apply_referral_discount_if_eligible(
            service_request, request.user
        )
        if discount_applied:
            amount_source = discounted_price
            # Finalize the discount (decrement credits, update booking)
            finalize_referral_discount(service_request, request.user, discount_amount, original_price)


    # ═══════════════════════════════════════════════════════════════════
    # CURRENCY VALIDATION & CONVERSION
    # ═══════════════════════════════════════════════════════════════════
    booking_currency = normalize_currency(service_request.currency)
    
    # Validate and convert if necessary
    final_amount, final_currency, was_converted = validate_and_convert_for_stripe(
        amount_source, booking_currency, request.user
    )

    # Update service request if currency was converted
    if was_converted or service_request.currency != final_currency:
        service_request.currency = final_currency
        service_request.offered_price = final_amount
        service_request.save(update_fields=["currency", "offered_price"])
    elif offered_override is not None and service_request.offered_price != amount_source:
        service_request.offered_price = final_amount
        service_request.save(update_fields=["offered_price"])
    
    # Log if conversion happened (for debugging)
    if was_converted:
        import logging
        logging.getLogger(__name__).info(
            f"Currency converted for booking #{service_request.id}: "
            f"{booking_currency} {amount_source} → {final_currency} {final_amount}"
        )
    # ═══════════════════════════════════════════════════════════════════

    currency_u = final_currency.upper()
    currency = currency_u.lower()

    # Minimum amount check
    min_amount = _min_amount_for_currency(currency_u)
    if final_amount < min_amount:
        return Response(
            {
                "error": f"Amount is below the minimum allowed for {currency_u}. Minimum is {min_amount} {currency_u}.",
                "minimum_amount": str(min_amount),
                "currency": currency,
            },
            status=400,
        )

    amount_int = _to_stripe_minor_units(final_amount, currency_u)


    # ═══════════════════════════════════════════════════════════════════
    # CREATE STRIPE PAYMENT INTENT WITH FALLBACK
    # ═══════════════════════════════════════════════════════════════════

    try:
        # Try automatic_payment_methods first (recommended by Stripe)
        payment_intent = stripe.PaymentIntent.create(
            amount=amount_int,
            currency=currency,
            automatic_payment_methods={"enabled": True},
            metadata={
                "service_request_id": str(service_request_id),
                "user_id": str(request.user.id),
            },
        )
    except stripe.error.InvalidRequestError as e:
        error_message = str(e).lower()

        # If automatic_payment_methods fails due to currency, try explicit card
        if "payment method" in error_message or "payment_method" in error_message:
            try:
                payment_intent = stripe.PaymentIntent.create(
                    amount=amount_int,
                    currency=currency,
                    payment_method_types=["card"],
                    metadata={
                        "service_request_id": str(service_request_id),
                        "user_id": str(request.user.id),
                    },
                )
            except stripe.error.StripeError as fallback_error:
                import logging
                logging.getLogger(__name__).error(
                    f"Stripe fallback failed for {currency}: {fallback_error}"
                )
                return Response({
                    "error": f"Unable to process payment in {currency_u}. Please contact support.",
                    "error_code": "payment_method_unavailable",
                }, status=400)
        else:
            return Response({"error": str(e)}, status=400)
    except stripe.error.StripeError as e:
        return Response({"error": str(e)}, status=400)
    # ═══════════════════════════════════════════════════════════════════

    service_request.stripe_payment_intent_id = payment_intent.id
    service_request.payment_gateway = "stripe"
    service_request.save(update_fields=["stripe_payment_intent_id", "payment_gateway"])

    return Response(
        {
            "client_secret": payment_intent["client_secret"],
            "payment_intent_id": payment_intent.id,
            "message": "Payment will be held until service completion",
            "currency": currency,
            "amount": float(final_amount),
            "currency_converted": was_converted,
            # Referral info
            "referral_discount_applied": discount_applied,
            "referral_discount_amount": float(discount_amount) if discount_applied else 0,
            "original_price": float(original_price) if discount_applied else None,
        }
    )


@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def stripe_webhook(request):
    """
    Stripe webhook endpoint.
    Purpose:
      - booking PaymentIntent succeeded => mark ServiceRequest paid, set offered_price to Stripe amount,
       set status pending->open, store Stripe fee, compute split and provider net.
      - Store charge_id / balance_transaction_id for audit/debug
      - Compute provider_net_amount when possible (provider_gross - stripe_fee)    

      - tip PaymentIntent succeeded => do NOT touch booking payment_status; tips are handled by tip_set()
       (we only keep it idempotent-safe if you later want to auto-mark tips here).

    """
    stripe.api_key = settings.STRIPE_SECRET_KEY

    payload = request.body
    sig_header = request.META.get("HTTP_STRIPE_SIGNATURE", "")
    webhook_secret = getattr(settings, "STRIPE_WEBHOOK_SECRET", "")

    try:
        if webhook_secret:
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        else:
            # Dev fallback (not recommended for production)
            event = stripe.Event.construct_from(request.data, stripe.api_key)
    except Exception:
        return Response(status=400)

    event_type = (event.get("type") or "").strip()
    if event.get("type") != "payment_intent.succeeded":
        return Response(status=200)

    pi = event["data"]["object"]
    pi_id = pi.get("id")
    if not pi_id:
        return Response(status=200)

    # Expand charge.balance_transaction so we can read Stripe fee
    try:
        pi_full = stripe.PaymentIntent.retrieve(
            pi_id,
            expand=["latest_charge.balance_transaction"],
        )
    except Exception:
        return Response(status=200)

    meta = pi_full.get("metadata") or {}
    meta_type = (meta.get("type") or "").strip().lower()

    # Tip payments are isolated from booking payment pipeline
    if meta_type == "tip":
        return Response(status=200)

    sr = ServiceRequest.objects.filter(stripe_payment_intent_id=pi_id).first()
    if not sr:
        return Response(status=200)

    # Stripe amount is truth
    currency_u = (pi_full.get("currency") or sr.currency or "USD").upper().strip()
    amount_minor = int(pi_full.get("amount") or 0)
    paid_amount = from_minor_units(amount_minor, currency_u)

    # Stripe fee + ids
    stripe_charge_id = None
    stripe_bt_id = None
    stripe_fee_major = None

    charge = pi_full.get("latest_charge")
    if charge:

        stripe_charge_id = charge.get("id")
        bt = charge.get("balance_transaction")
        if isinstance(bt, dict):
            stripe_bt_id = bt.get("id")
            fee_minor = bt.get("fee")  # integer in minor units

            if fee_minor is not None:
                stripe_fee_major = from_minor_units(int(fee_minor), currency_u)
                    
    with transaction.atomic():
        sr_locked = ServiceRequest.objects.select_for_update().get(pk=sr.pk)

        # Idempotent: if already paid, only fill missing audit fields
        sr_locked.currency = currency_u
        sr_locked.offered_price = paid_amount  # Stripe truth
        sr_locked.payment_status = "paid"
        sr_locked.payment_gateway = "stripe"

        if sr_locked.status == "pending":
            sr_locked.status = "open"

        # store stripe ids
        if stripe_charge_id:
            sr_locked.stripe_charge_id = stripe_charge_id
        if stripe_bt_id:
            sr_locked.stripe_balance_transaction_id = stripe_bt_id
        if stripe_fee_major is not None:
            sr_locked.stripe_fee_amount = stripe_fee_major

        # Compute split (accounting for referral discount)
        platform_fee, provider_gross = _compute_split_with_referral(paid_amount, sr_locked)
        sr_locked.platform_fee_amount = platform_fee
        sr_locked.provider_earnings_amount = provider_gross

        # Compute provider net (provider_gross - stripe_fee)
        sr_locked.provider_net_amount = _compute_provider_net(provider_gross, sr_locked.stripe_fee_amount)

        sr_locked.save(update_fields=[
            "currency",
            "offered_price",
            "payment_status",
            "payment_gateway",
            "status",
            "stripe_charge_id",
            "stripe_balance_transaction_id",
            "stripe_fee_amount",
            "platform_fee_amount",
            "provider_earnings_amount",
            "provider_net_amount",
        ])

    # Check and award referral credits if this is user's first paid booking
    check_and_award_referral_credits(sr_locked)

    # Notify eligible providers of the new job
    try:
        from core.utils.notifications import notify_eligible_providers_of_new_job
        sr_refresh = ServiceRequest.objects.get(pk=sr.pk)
        notify_eligible_providers_of_new_job(sr_refresh)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to notify providers for job #{sr.pk}: {e}")

    return Response(status=200)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def stripe_confirm_payment(request):
    """
    Dev-friendly / mobile-friendly confirmation endpoint.
    Use this after Stripe PaymentSheet reports success to immediately reconcile DB state,
    even if webhooks are delayed/unreachable (e.g., localhost testing).

    Body:
      { "service_request_id": 123 }
        OR
      {"payment_intent_id": "pi_..." }
    """
    if not getattr(request.user, "email_verified", False):
        return Response({"detail": "Verify your email before making payments."}, status=403)

    stripe.api_key = settings.STRIPE_SECRET_KEY

    sr_id = request.data.get("service_request_id")
    pi_id = (request.data.get("payment_intent_id") or "").strip()

    sr = None
    if sr_id is not None:
        try:
            sr = ServiceRequest.objects.get(id=sr_id, user=request.user)
        except ServiceRequest.DoesNotExist:
            return Response({"detail": "Booking not found."}, status=404)
        pi_id = (sr.stripe_payment_intent_id or "").strip()

    if not pi_id:
        return Response({"detail": "payment_intent_id is required."}, status=400)

    # Retrieve PI with charge fee expansion (same as webhook)
    try:
        pi_full = stripe.PaymentIntent.retrieve(
            pi_id,
            expand=["latest_charge.balance_transaction"],
        )
    except Exception as e:
        return Response({"detail": f"Unable to retrieve payment intent: {e}"}, status=400)

    if (pi_full.get("status") or "") != "succeeded":
        return Response(
            {"detail": "PaymentIntent not succeeded.", "status": pi_full.get("status")},
            status=400,
        )

    # Find SR if not already loaded by id
    if sr is None:
        sr = ServiceRequest.objects.filter(stripe_payment_intent_id=pi_id, user=request.user).first()
    if not sr:
        return Response({"detail": "No booking linked to this payment intent."}, status=404)

    # Mark paid using the same rules as webhook
    currency_u = (pi_full.get("currency") or sr.currency or "USD").upper().strip()
    amount_minor = int(pi_full.get("amount") or 0)
    paid_amount = from_minor_units(amount_minor, currency_u)

    stripe_charge_id = None
    stripe_bt_id = None
    stripe_fee_major = None
    charge = pi_full.get("latest_charge")
    if charge:
        stripe_charge_id = charge.get("id")
        bt = charge.get("balance_transaction")
        if isinstance(bt, dict):
            stripe_bt_id = bt.get("id")
            fee_minor = bt.get("fee")
            if fee_minor is not None:
                stripe_fee_major = from_minor_units(int(fee_minor), currency_u)

    with transaction.atomic():
        sr_locked = ServiceRequest.objects.select_for_update().get(pk=sr.pk)
        sr_locked.currency = currency_u
        sr_locked.offered_price = paid_amount
        sr_locked.payment_status = "paid"
        sr_locked.payment_gateway = "stripe"

        if sr_locked.status == "pending":
            sr_locked.status = "open"

        if stripe_charge_id:
            sr_locked.stripe_charge_id = stripe_charge_id
        if stripe_bt_id:
            sr_locked.stripe_balance_transaction_id = stripe_bt_id
        if stripe_fee_major is not None:
            sr_locked.stripe_fee_amount = stripe_fee_major

        platform_fee, provider_gross = _compute_split(paid_amount)
        sr_locked.platform_fee_amount = platform_fee
        sr_locked.provider_earnings_amount = provider_gross
        sr_locked.provider_net_amount = _compute_provider_net(provider_gross, sr_locked.stripe_fee_amount)

        sr_locked.save(update_fields=[
            "currency",
            "offered_price",
            "payment_status",
            "payment_gateway",
            "status",
            "stripe_charge_id",
            "stripe_balance_transaction_id",
            "stripe_fee_amount",
            "platform_fee_amount",
            "provider_earnings_amount",
            "provider_net_amount",
        ])

    sr_refresh = ServiceRequest.objects.get(pk=sr.pk)

    # Notify eligible providers of the new job
    try:
        from core.utils.notifications import notify_eligible_providers_of_new_job
        notify_eligible_providers_of_new_job(sr_refresh)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to notify providers for job #{sr.pk}: {e}")

    return Response(
        {"detail": "confirmed", "booking": ServiceRequestSerializer(sr_refresh, context={"request": request}).data},
        status=200,
    )




# -------------------------
# FLUTTERWAVE (AFRICA)
# -------------------------
def _flutterwave_base_url() -> str:
    # Flutterwave v3
    return "https://api.flutterwave.com/v3"


def _flutterwave_auth_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {getattr(settings, 'FLUTTERWAVE_SECRET_KEY', '')}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def _flutterwave_webhook_is_valid(request) -> bool:
    """
    Flutterwave sends `verif-hash` header. You set the same secret/hash in Flutterwave dashboard.
    """
    incoming = (request.META.get("HTTP_VERIF_HASH") or "").strip()
    expected = (getattr(settings, "FLUTTERWAVE_WEBHOOK_HASH", "") or "").strip()
    return bool(expected) and incoming == expected


def _flutterwave_create_transfer(*, amount: Decimal, currency: str, narration: str, reference: str,
                                bank_code: str = "", account_number: str = "", phone_number: str = "",
                                beneficiary_id: str = "") -> dict:
    """
    Creates a transfer via Flutterwave v3.
    NOTE: Payload fields vary by country and by method. This is a minimal baseline.
    """
    try:
        import requests  # type: ignore
    except Exception:
        raise Exception("Server missing 'requests' dependency.")

    url = f"{_flutterwave_base_url()}/transfers"
    payload: dict = {
        "amount": float(amount),
        "currency": currency.upper().strip(),
        "narration": narration,
        "reference": reference,
    }

    # Prefer beneficiary if you store one
    if beneficiary_id:
        payload["beneficiary"] = beneficiary_id
    else:
        # Bank transfer style
        if bank_code and account_number:
            payload["account_bank"] = bank_code
            payload["account_number"] = account_number
        # Mobile money style (varies; you may need extra fields per country)
        elif phone_number:
            payload["account_number"] = phone_number

    r = requests.post(url, headers=_flutterwave_auth_headers(), json=payload, timeout=25)
    data = r.json() if r.content else {}
    if r.status_code < 200 or r.status_code >= 300:
        raise Exception(f"Flutterwave transfer failed: {data}")
    return data


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_flutterwave_checkout(request):
    """
    Creates a Flutterwave checkout payload and stores tx_ref on the ServiceRequest.
    Client will open Flutterwave Standard SDK with returned keys.
    """
    # DEBUG: Log incoming request
    print("=" * 50)
    print("FLUTTERWAVE CHECKOUT DEBUG")
    print(f"User: {request.user.username} (ID: {request.user.id})")
    print(f"Request data: {request.data}")
    print("=" * 50)

    if not getattr(request.user, "email_verified", False):
        return Response({"detail": "Verify your email before making payments."}, status=403)

    service_request_id = request.data.get("service_request_id")
    amount_raw = request.data.get("amount")

    if not service_request_id or amount_raw is None:
        return Response({"detail": "service_request_id and amount are required."}, status=400)

    try:
        sr = ServiceRequest.objects.get(id=service_request_id)
    except ServiceRequest.DoesNotExist:
        return Response({"detail": "Invalid service_request_id"}, status=400)

    # DEBUG: Log booking state
    print(f"DEBUG: Booking ID={sr.id}")
    print(f"DEBUG: Booking status='{sr.status}'")
    print(f"DEBUG: Booking payment_status='{sr.payment_status}'")
    print(f"DEBUG: Booking user_id={sr.user_id}, request.user.id={request.user.id}")


    if sr.user != request.user:
        print("DEBUG: User mismatch")
        return Response({"detail": "Not allowed to pay for this booking."}, status=403)

    if sr.status != "pending" or sr.payment_status not in ("unpaid",):
        print(f"DEBUG: Not eligible - status={sr.status}, payment_status={sr.payment_status}")
        return Response({"detail": "This booking is not eligible for payment."}, status=400)

    # Prevent double-payment attempts
    if sr.payment_status in ("pending", "paid"):
        return Response({"detail": "Payment is already in progress for this booking."}, status=409)

    # Rule: Flutterwave is intended for Africa users.
    user_country = (request.user.country_name or "").strip()
    if not is_african_country_name(user_country):
        return Response({"detail": "Flutterwave checkout is not available for this user country."}, status=403)

    # HARD GATE: only allow paying if there is at least one eligible provider
    has_provider = _has_nearby_available_provider_for_service(
        user_lat=sr.location_latitude,
        user_lng=sr.location_longitude,
        service_type=sr.service_type,
    )
    if not has_provider:
        return Response(
            {
                "detail": (
                    "We’re sorry—there are currently no available providers for this service "
                    "in your area. Please try again later."
                )
            },
            status=400,
        )

    try:
        amount = Decimal(str(amount_raw)).quantize(Decimal("0.01"))
    except Exception:
        return Response({"detail": "Invalid amount."}, status=400)

    if amount <= 0:
        return Response({"detail": "amount must be positive."}, status=400)

    # ═══════════════════════════════════════════════════════════════════
    # REFERRAL DISCOUNT CHECK
    # ═══════════════════════════════════════════════════════════════════
    original_price = amount
    discount_applied = False
    discount_amount = Decimal("0")
    
    use_referral = request.data.get("use_referral_credit", True)

    if use_referral and request.user.referral_credits > 0:
        discount_amount = (amount * REFERRAL_DISCOUNT_PERCENT / Decimal("100")).quantize(Decimal("0.01"))
        discounted_price = (amount - discount_amount).quantize(Decimal("0.01"))
        
        if discounted_price > Decimal("0"):
            discount_applied = True
            amount = discounted_price
            finalize_referral_discount(sr, request.user, discount_amount, original_price)

    # Persist the amount user intends to pay
    sr.offered_price = amount
    sr.payment_gateway = "flutterwave"

    # Unique reference
    tx_ref = f"styloria_sr{sr.id}_{uuid.uuid4().hex[:12]}"
    sr.flutterwave_tx_ref = tx_ref
    sr.save(update_fields=["offered_price", "payment_gateway", "flutterwave_tx_ref"])

    # IMPORTANT: prefer user's preferred currency for Flutterwave to avoid verify() currency mismatch.
    # Also persist the chosen currency onto the ServiceRequest so verification compares against the same value.
    currency_u = get_currency_for_country(request.user.country_name).upper().strip()
    if sr.currency != currency_u:
        sr.currency = currency_u

        sr.save(update_fields=["currency"])

    full_name = f"{(request.user.first_name or '').strip()} {(request.user.last_name or '').strip()}".strip()
    if not full_name:
        full_name = request.user.username

    return Response(
        {
            "public_key": getattr(settings, "FLUTTERWAVE_PUBLIC_KEY", ""),
            "encryption_key": getattr(settings, "FLUTTERWAVE_ENCRYPTION_KEY", ""),
            "is_test_mode": bool(getattr(settings, "FLUTTERWAVE_TEST_MODE", True)),
            "tx_ref": tx_ref,
            "currency": currency_u,
            "amount": float(amount),
            "customer_email": request.user.email or "",
            "customer_phone": request.user.phone_number or "",
            "customer_name": full_name,
            "redirect_url": settings.FLUTTERWAVE_REDIRECT_URL,
            # Referral info
            "referral_discount_applied": discount_applied,
            "referral_discount_amount": float(discount_amount) if discount_applied else 0,
            "original_price": float(original_price) if discount_applied else None,
        },
        status=200,
    )

@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def flutterwave_webhook(request):
    """
    Flutterwave webhook for transfers (payouts).
    You must configure the webhook URL in Flutterwave dashboard and set FLUTTERWAVE_WEBHOOK_HASH.
    """
    if not _flutterwave_webhook_is_valid(request):
        return Response(status=401)

    payload = request.data if isinstance(request.data, dict) else {}
    event = (payload.get("event") or "").strip().lower()
    data = payload.get("data") or {}

    # If Flutterwave sends mixed webhook events to this URL, ignore non-transfer events.
    # (If you confirm this endpoint ONLY receives transfer webhooks, you can remove this guard.)
    if event and ("transfer" not in event):
        return Response(status=200)

    reference = (data.get("reference") or "").strip()
    status = (data.get("status") or "").strip()
    transfer_id = str(data.get("id") or "").strip()

    if reference:
        finalize_flutterwave_payout_from_webhook(
            reference=reference,
            transfer_id=transfer_id,
            status=status,
        )

    return Response(status=200)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_flutterwave_payment(request):
    """
    Server-to-server verification with Flutterwave.
    This endpoint is allowed to finalize the booking as paid.

    Body: { "tx_ref": "...", "transaction_id": 12345 }
    Returns: { "verified": true, "booking": {...} }
    """
    if not getattr(request.user, "email_verified", False):
        return Response({"detail": "Verify your email before making payments."}, status=403)

    tx_ref = (request.data.get("tx_ref") or "").strip()
    transaction_id = request.data.get("transaction_id")
    if not tx_ref or transaction_id is None:
        return Response({"detail": "tx_ref and transaction_id are required."}, status=400)

    # Lookup booking by tx_ref + ownership
    sr = ServiceRequest.objects.filter(flutterwave_tx_ref=tx_ref, user=request.user).first()
    if not sr:
        return Response({"verified": False, "detail": "No matching booking for this tx_ref."}, status=400)

    if sr.payment_status == "paid":
        # idempotent
        return Response({"verified": True, "booking": ServiceRequestSerializer(sr, context={"request": request}).data}, status=200)

    if sr.status != "pending" or sr.payment_status not in ("pending", "unpaid"):
        return Response({"verified": False, "detail": "Booking not eligible for verification."}, status=400)

    # Call Flutterwave verify endpoint
    # Requires 'requests' package installed.
    try:
        import requests  # type: ignore
    except Exception:
        return Response({"verified": False, "detail": "Server missing 'requests' dependency."}, status=500)

    try:
        url = f"{_flutterwave_base_url()}/transactions/{int(transaction_id)}/verify"
    except Exception:
        return Response({"verified": False, "detail": "Invalid transaction_id."}, status=400)

    try:
        r = requests.get(url, headers=_flutterwave_auth_headers(), timeout=25)
        data = r.json() if r.content else {}
    except Exception as e:
        return Response({"verified": False, "detail": f"Verification request failed: {e}"}, status=400)

    if r.status_code < 200 or r.status_code >= 300:
        return Response({"verified": False, "detail": "Flutterwave verification failed.", "raw": data}, status=400)

    fw_data = (data or {}).get("data") or {}
    fw_status = (fw_data.get("status") or "").lower().strip()
    fw_tx_ref = (fw_data.get("tx_ref") or "").strip()

    if fw_status != "successful":
        return Response({"verified": False, "detail": "Transaction not successful."}, status=400)

    if fw_tx_ref != tx_ref:
        return Response({"verified": False, "detail": "tx_ref mismatch."}, status=400)

    # Flutterwave amount/currency truth
    currency_u = (fw_data.get("currency") or sr.currency or "USD").upper().strip()
    try:
        fw_amount = Decimal(str(fw_data.get("amount") or "0")).quantize(Decimal("0.01"))
    except Exception:
        return Response({"verified": False, "detail": "Invalid amount in Flutterwave response."}, status=400)

    # Optional: enforce currency match (recommended)
    sr_currency = (sr.currency or "USD").upper().strip()
    if currency_u != sr_currency:
        return Response({"verified": False, "detail": f"Currency mismatch ({currency_u} vs {sr_currency})."}, status=400)

    # Optional: enforce amount matches expected offered_price (recommended)
    expected = (sr.offered_price or sr.estimated_price or Decimal("0.00")).quantize(Decimal("0.01"))
    if expected > Decimal("0.00") and fw_amount != expected:
        return Response({"verified": False, "detail": "Amount mismatch."}, status=400)

    # Save as paid (server truth)
    with transaction.atomic():
        sr_locked = ServiceRequest.objects.select_for_update().get(pk=sr.pk)
        if sr_locked.payment_status != "paid":
            sr_locked.currency = currency_u
            sr_locked.offered_price = fw_amount
            sr_locked.payment_status = "paid"
            sr_locked.payment_gateway = "flutterwave"
            sr_locked.flutterwave_transaction_id = str(transaction_id)

            if sr_locked.status == "pending":
                sr_locked.status = "open"

            platform_fee, provider_gross = _compute_split_with_referral(fw_amount, sr_locked)
            sr_locked.platform_fee_amount = platform_fee
            sr_locked.provider_earnings_amount = provider_gross
            # Flutterwave fee not computed here; provider net = gross for now
            sr_locked.provider_net_amount = provider_gross

            sr_locked.save(update_fields=[
                "currency",
                "offered_price",
                "payment_status",
                "status",
                "payment_gateway",
                "flutterwave_transaction_id",
                "platform_fee_amount",
                "provider_earnings_amount",
                "provider_net_amount",
            ])

    # Check and award referral credits
    check_and_award_referral_credits(sr_locked)

    sr_refresh = ServiceRequest.objects.get(pk=sr.pk)

    # Notify eligible providers of the new job
    try:
        from core.utils.notifications import notify_eligible_providers_of_new_job
        notify_eligible_providers_of_new_job(sr_refresh)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to notify providers for job #{sr.pk}: {e}")

    return Response(
        {"verified": True, "booking": ServiceRequestSerializer(sr_refresh, context={"request": request}).data},
        status=200,
    )

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_flutterwave_by_txref(request):
    """
    Verify Flutterwave payment using only tx_ref.
    Looks up the transaction on Flutterwave's API by tx_ref.
    Used when the Flutter SDK doesn't return a transaction_id.
    """
    tx_ref = (request.data.get("tx_ref") or "").strip()
    
    if not tx_ref:
        return Response({"verified": False, "detail": "tx_ref is required."}, status=400)
    
    # Find booking by tx_ref
    sr = ServiceRequest.objects.filter(flutterwave_tx_ref=tx_ref, user=request.user).first()
    if not sr:
        return Response({"verified": False, "detail": "No matching booking for this tx_ref."}, status=400)
    
    if sr.payment_status == "paid":
        return Response({
            "verified": True, 
            "booking": ServiceRequestSerializer(sr, context={"request": request}).data
        }, status=200)
    
    # Query Flutterwave to find transaction by tx_ref
    try:
        import requests
    except ImportError:
        return Response({"verified": False, "detail": "Server missing requests library."}, status=500)
    
    try:
        # Flutterwave API to verify by tx_ref
        url = f"{_flutterwave_base_url()}/transactions/verify_by_reference?tx_ref={tx_ref}"
        r = requests.get(url, headers=_flutterwave_auth_headers(), timeout=25)
        data = r.json() if r.content else {}
    except Exception as e:
        return Response({"verified": False, "detail": f"Verification request failed: {e}"}, status=400)
    
    if r.status_code < 200 or r.status_code >= 300:
        return Response({"verified": False, "detail": "Transaction not found on Flutterwave."}, status=400)
    
    fw_data = data.get("data") or {}
    fw_status = (fw_data.get("status") or "").lower().strip()
    fw_tx_ref = (fw_data.get("tx_ref") or "").strip()
    transaction_id = fw_data.get("id")
    
    if fw_status != "successful":
        return Response({"verified": False, "detail": f"Transaction status: {fw_status}"}, status=400)
    
    if fw_tx_ref != tx_ref:
        return Response({"verified": False, "detail": "tx_ref mismatch."}, status=400)
    
    # Get amount and currency from Flutterwave
    currency_u = (fw_data.get("currency") or sr.currency or "USD").upper().strip()
    try:
        fw_amount = Decimal(str(fw_data.get("amount") or "0")).quantize(Decimal("0.01"))
    except Exception:
        return Response({"verified": False, "detail": "Invalid amount."}, status=400)
    
    # Update booking as paid
    with transaction.atomic():
        sr_locked = ServiceRequest.objects.select_for_update().get(pk=sr.pk)
        if sr_locked.payment_status != "paid":
            sr_locked.currency = currency_u
            sr_locked.offered_price = fw_amount
            sr_locked.payment_status = "paid"
            sr_locked.payment_gateway = "flutterwave"
            sr_locked.flutterwave_transaction_id = str(transaction_id) if transaction_id else ""
            
            if sr_locked.status == "pending":
                sr_locked.status = "open"
            
            platform_fee, provider_gross = _compute_split_with_referral(fw_amount, sr_locked)
            sr_locked.platform_fee_amount = platform_fee
            sr_locked.provider_earnings_amount = provider_gross
            sr_locked.provider_net_amount = provider_gross
            
            sr_locked.save(update_fields=[
                "currency", "offered_price", "payment_status", "status",
                "payment_gateway", "flutterwave_transaction_id",
                "platform_fee_amount", "provider_earnings_amount", "provider_net_amount",
            ])

    # Check and award referral credits
    check_and_award_referral_credits(sr_locked)
    
    sr.refresh_from_db()

    # Notify eligible providers of the new job
    try:
        from core.utils.notifications import notify_eligible_providers_of_new_job
        notify_eligible_providers_of_new_job(sr)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to notify providers for job #{sr.pk}: {e}")

    return Response({
        "verified": True,
        "booking": ServiceRequestSerializer(sr, context={"request": request}).data
    }, status=200)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def reset_flutterwave_payment(request):
    """
    Reset a booking's payment status if Flutterwave payment was cancelled or failed.
    """
    service_request_id = request.data.get("service_request_id")
    
    if not service_request_id:
        return Response({"detail": "service_request_id is required."}, status=400)
    
    try:
        sr = ServiceRequest.objects.get(id=service_request_id, user=request.user)
    except ServiceRequest.DoesNotExist:
        return Response({"detail": "Booking not found."}, status=404)
    
    if sr.payment_status == "pending" and sr.status == "pending":
        sr.payment_status = "unpaid"
        sr.flutterwave_tx_ref = None
        sr.save(update_fields=["payment_status", "flutterwave_tx_ref"])
        return Response({"detail": "Payment reset. You can try again."}, status=200)
    
    if sr.payment_status == "paid":
        return Response({"detail": "This booking is already paid."}, status=400)
    
    return Response({"detail": "Cannot reset this booking."}, status=400)


# =============================================================================
# PAYSTACK PAYMENTS (Ghana, Nigeria, South Africa, Kenya, Côte d'Ivoire)
# =============================================================================

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_paystack_checkout(request):
    """
    Creates a Paystack checkout for users in supported African countries.
    
    POST /api/paystack/create_checkout/
    Body: { "service_request_id": 123, "amount": 100.00 }
    
    Returns:
        {
            "authorization_url": "https://checkout.paystack.com/...",
            "access_code": "...",
            "reference": "...",
            "currency": "GHS",
            "amount": 100.00
        }
    """
    if not getattr(request.user, "email_verified", False):
        return Response({"detail": "Verify your email before making payments."}, status=403)
    
    service_request_id = request.data.get("service_request_id")
    amount_raw = request.data.get("amount")
    
    if not service_request_id or amount_raw is None:
        return Response({"detail": "service_request_id and amount are required."}, status=400)
    
    try:
        sr = ServiceRequest.objects.get(id=service_request_id)
    except ServiceRequest.DoesNotExist:
        return Response({"detail": "Invalid service_request_id"}, status=400)
    
    if sr.user != request.user:
        return Response({"detail": "Not allowed to pay for this booking."}, status=403)
    
    if sr.status != "pending" or sr.payment_status not in ("unpaid",):
        return Response({"detail": "This booking is not eligible for payment."}, status=400)
    
    # Prevent double-payment attempts
    if sr.payment_status in ("pending", "paid"):
        return Response({"detail": "Payment is already in progress for this booking."}, status=409)
    
    # Rule: Paystack is for specific African countries only
    user_country = (request.user.country_name or "").strip()
    if not is_paystack_country(user_country):
        # Check if should use Flutterwave or Stripe
        gateway = get_payment_gateway_for_country(user_country)
        if gateway == "flutterwave":
            return Response({
                "detail": "Please use Flutterwave for payments in your country.",
                "error_code": "flutterwave_required",
                "country": user_country,
            }, status=403)
        else:
            return Response({
                "detail": "Please use Stripe for payments in your country.",
                "error_code": "stripe_required",
                "country": user_country,
            }, status=403)
    
    # Check for available providers
    has_provider = _has_nearby_available_provider_for_service(
        user_lat=sr.location_latitude,
        user_lng=sr.location_longitude,
        service_type=sr.service_type,
    )
    if not has_provider:
        return Response({
            "detail": "We're sorry—there are currently no available providers for this service in your area."
        }, status=400)
    
    try:
        amount = Decimal(str(amount_raw)).quantize(Decimal("0.01"))
    except Exception:
        return Response({"detail": "Invalid amount."}, status=400)
    
    if amount <= 0:
        return Response({"detail": "amount must be positive."}, status=400)

    # ═══════════════════════════════════════════════════════════════════
    # REFERRAL DISCOUNT CHECK
    # ═══════════════════════════════════════════════════════════════════
    original_price = amount
    discount_applied = False
    discount_amount = Decimal("0")
    
    use_referral = request.data.get("use_referral_credit", True)

    if use_referral and request.user.referral_credits > 0:
        discount_amount = (amount * REFERRAL_DISCOUNT_PERCENT / Decimal("100")).quantize(Decimal("0.01"))
        discounted_price = (amount - discount_amount).quantize(Decimal("0.01"))
        
        if discounted_price > Decimal("0"):
            discount_applied = True
            amount = discounted_price
            finalize_referral_discount(sr, request.user, discount_amount, original_price)

    # Get currency for user's country
    currency_u = get_paystack_currency(user_country) or get_currency_for_country(user_country)
    currency_u = currency_u.upper().strip()
    
    # Generate unique reference
    reference = f"styloria_sr{sr.id}_{uuid.uuid4().hex[:12]}"
    
    # Update service request
    sr.offered_price = amount
    sr.payment_gateway = "paystack"
    sr.paystack_reference = reference
    sr.currency = currency_u
    sr.save(update_fields=["offered_price", "payment_gateway", "paystack_reference", "currency"])
    
    # Build callback URL
    callback_url = getattr(settings, "PAYSTACK_CALLBACK_URL", None)
    if not callback_url:
        callback_url = f"{getattr(settings, 'PUBLIC_BASE_URL', '')}/paystack/callback/"
    
    # Initialize Paystack transaction
    result = paystack_initialize(
        email=request.user.email,
        amount=amount,
        currency=currency_u,
        reference=reference,
        callback_url=callback_url,
        metadata={
            "service_request_id": str(sr.id),
            "user_id": str(request.user.id),
            "booking_type": "service",
        },
        channels=["card", "bank", "mobile_money", "ussd"],
    )
    
    if not result.get("success"):
        return Response({
            "detail": result.get("message") or "Failed to initialize payment",
            "error_code": "paystack_init_failed",
        }, status=400)
    
    # Store access code
    sr.paystack_access_code = result.get("access_code") or ""
    sr.save(update_fields=["paystack_access_code"])
    
    return Response({
        "authorization_url": result.get("authorization_url"),
        "access_code": result.get("access_code"),
        "reference": reference,
        "currency": currency_u,
        "amount": float(amount),
        "public_key": getattr(settings, "PAYSTACK_PUBLIC_KEY", ""),
        # Referral info
        "referral_discount_applied": discount_applied,
        "referral_discount_amount": float(discount_amount) if discount_applied else 0,
        "original_price": float(original_price) if discount_applied else None,
    }, status=200)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def verify_paystack_payment(request):
    """
    Verify Paystack payment by reference.
    
    POST /api/paystack/verify_payment/
    Body: { "reference": "styloria_sr123_abc123" }
    
    Returns:
        { "verified": true, "booking": {...} }
    """
    if not getattr(request.user, "email_verified", False):
        return Response({"detail": "Verify your email before making payments."}, status=403)
    
    reference = (request.data.get("reference") or "").strip()
    if not reference:
        return Response({"detail": "reference is required."}, status=400)
    
    # Find booking by reference
    sr = ServiceRequest.objects.filter(paystack_reference=reference, user=request.user).first()
    if not sr:
        return Response({"verified": False, "detail": "No matching booking for this reference."}, status=400)
    
    # Idempotent: if already paid
    if sr.payment_status == "paid":
        return Response({
            "verified": True,
            "booking": ServiceRequestSerializer(sr, context={"request": request}).data
        }, status=200)
    
    if sr.status != "pending" or sr.payment_status not in ("pending", "unpaid"):
        return Response({"verified": False, "detail": "Booking not eligible for verification."}, status=400)
    
    # Verify with Paystack
    result = paystack_verify(reference)
    
    if not result.get("success"):
        return Response({
            "verified": False,
            "detail": result.get("message") or "Payment verification failed.",
            "status": result.get("status"),
        }, status=400)
    
    # Get verified amount and currency
    verified_amount = result.get("amount") or Decimal("0.00")
    verified_currency = (result.get("currency") or sr.currency or "NGN").upper().strip()
    transaction_id = result.get("transaction_id")
    fees = result.get("fees") or Decimal("0.00")
    channel = result.get("channel") or ""
    
    # Verify currency matches
    sr_currency = (sr.currency or "NGN").upper().strip()
    if verified_currency != sr_currency:
        return Response({
            "verified": False,
            "detail": f"Currency mismatch ({verified_currency} vs {sr_currency})."
        }, status=400)
    
    # Verify amount matches (with small tolerance for rounding)
    expected = (sr.offered_price or sr.estimated_price or Decimal("0.00")).quantize(Decimal("0.01"))
    if expected > Decimal("0.00") and abs(verified_amount - expected) > Decimal("0.50"):
        return Response({
            "verified": False,
            "detail": f"Amount mismatch (paid {verified_amount} vs expected {expected})."
        }, status=400)
    
    # Mark as paid
    with transaction.atomic():
        sr_locked = ServiceRequest.objects.select_for_update().get(pk=sr.pk)
        
        if sr_locked.payment_status != "paid":
            sr_locked.currency = verified_currency
            sr_locked.offered_price = verified_amount
            sr_locked.payment_status = "paid"
            sr_locked.payment_gateway = "paystack"
            sr_locked.paystack_transaction_id = str(transaction_id) if transaction_id else ""
            sr_locked.paystack_fee_amount = fees
            sr_locked.paystack_channel = channel
            
            if sr_locked.status == "pending":
                sr_locked.status = "open"
            
            # Compute fee split
            platform_fee, provider_gross = _compute_split_with_referral(verified_amount, sr_locked)
            sr_locked.platform_fee_amount = platform_fee
            sr_locked.provider_earnings_amount = provider_gross
            sr_locked.provider_net_amount = provider_gross  # Paystack fee is separate
            
            sr_locked.save(update_fields=[
                "currency",
                "offered_price",
                "payment_status",
                "status",
                "payment_gateway",
                "paystack_transaction_id",
                "paystack_fee_amount",
                "paystack_channel",
                "platform_fee_amount",
                "provider_earnings_amount",
                "provider_net_amount",
            ])

    # Check and award referral credits
    check_and_award_referral_credits(sr_locked)
    
    sr.refresh_from_db()

    # Notify eligible providers of the new job
    try:
        from core.utils.notifications import notify_eligible_providers_of_new_job
        notify_eligible_providers_of_new_job(sr)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to notify providers for job #{sr.pk}: {e}")

    return Response({
        "verified": True,
        "booking": ServiceRequestSerializer(sr, context={"request": request}).data
    }, status=200)


@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def paystack_webhook(request):
    """
    Paystack webhook endpoint for payment and transfer events.
    
    Events handled:
    - charge.success: Payment completed
    - transfer.success: Payout completed
    - transfer.failed: Payout failed
    - transfer.reversed: Payout reversed
    - refund.processed: Refund completed
    """
    # Verify webhook signature
    signature = request.META.get("HTTP_X_PAYSTACK_SIGNATURE", "")
    if not paystack_verify_webhook(request.body, signature):
        return Response({"detail": "Invalid signature"}, status=401)
    
    payload = request.data if isinstance(request.data, dict) else {}
    event = (payload.get("event") or "").strip().lower()
    data = payload.get("data") or {}
    
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Paystack webhook received: event={event}")
    
    # Handle payment success
    if event == "charge.success":
        reference = (data.get("reference") or "").strip()
        if reference:
            _handle_paystack_charge_success(data)
    
    # Handle transfer events (payouts)
    elif event == "transfer.success":
        reference = (data.get("reference") or "").strip()
        transfer_code = (data.get("transfer_code") or "").strip()
        if reference:
            finalize_paystack_payout_from_webhook(
                reference=reference,
                transfer_code=transfer_code,
                status="success",
            )
    
    elif event == "transfer.failed":
        reference = (data.get("reference") or "").strip()
        transfer_code = (data.get("transfer_code") or "").strip()
        if reference:
            finalize_paystack_payout_from_webhook(
                reference=reference,
                transfer_code=transfer_code,
                status="failed",
            )
    
    elif event == "transfer.reversed":
        reference = (data.get("reference") or "").strip()
        transfer_code = (data.get("transfer_code") or "").strip()
        if reference:
            finalize_paystack_payout_from_webhook(
                reference=reference,
                transfer_code=transfer_code,
                status="reversed",
            )
    
    return Response(status=200)


def _handle_paystack_charge_success(data: dict) -> None:
    """
    Handle Paystack charge.success webhook event.
    Marks booking as paid if not already.
    """
    reference = (data.get("reference") or "").strip()
    if not reference:
        return
    
    sr = ServiceRequest.objects.filter(paystack_reference=reference).first()
    if not sr:
        return
    
    if sr.payment_status == "paid":
        return
    
    # Get payment details
    status = (data.get("status") or "").lower()
    if status != "success":
        return
    
    amount = data.get("amount") or 0
    currency = (data.get("currency") or "NGN").upper()
    transaction_id = data.get("id")
    fees = data.get("fees") or 0
    channel = data.get("channel") or ""
    
    # Convert from kobo to main currency
    amount_decimal = (Decimal(str(amount)) / Decimal("100")).quantize(Decimal("0.01"))
    fees_decimal = (Decimal(str(fees)) / Decimal("100")).quantize(Decimal("0.01"))
    
    with transaction.atomic():
        sr_locked = ServiceRequest.objects.select_for_update().get(pk=sr.pk)
        
        if sr_locked.payment_status == "paid":
            return
        
        sr_locked.currency = currency
        sr_locked.offered_price = amount_decimal
        sr_locked.payment_status = "paid"
        sr_locked.payment_gateway = "paystack"
        sr_locked.paystack_transaction_id = str(transaction_id) if transaction_id else ""
        sr_locked.paystack_fee_amount = fees_decimal
        sr_locked.paystack_channel = channel
        
        if sr_locked.status == "pending":
            sr_locked.status = "open"
        
        platform_fee, provider_gross = _compute_split(amount_decimal)
        sr_locked.platform_fee_amount = platform_fee
        sr_locked.provider_earnings_amount = provider_gross
        sr_locked.provider_net_amount = provider_gross
        
        sr_locked.save(update_fields=[
            "currency",
            "offered_price",
            "payment_status",
            "status",
            "payment_gateway",
            "paystack_transaction_id",
            "paystack_fee_amount",
            "paystack_channel",
            "platform_fee_amount",
            "provider_earnings_amount",
            "provider_net_amount",
        ])

    # Notify eligible providers of the new job (outside transaction)
    try:
        from core.utils.notifications import notify_eligible_providers_of_new_job
        sr_refresh = ServiceRequest.objects.get(pk=sr.pk)
        notify_eligible_providers_of_new_job(sr_refresh)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to notify providers for job #{sr.pk}: {e}")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def reset_paystack_payment(request):
    """
    Reset a booking's payment status if Paystack payment was cancelled.
    
    POST /api/paystack/reset_payment/
    Body: { "service_request_id": 123 }
    """
    service_request_id = request.data.get("service_request_id")
    
    if not service_request_id:
        return Response({"detail": "service_request_id is required."}, status=400)
    
    try:
        sr = ServiceRequest.objects.get(id=service_request_id, user=request.user)
    except ServiceRequest.DoesNotExist:
        return Response({"detail": "Booking not found."}, status=404)
    
    # Already paid - nothing to reset
    if sr.payment_status == "paid":
        return Response({"detail": "This booking is already paid."}, status=400)
    
    # Can only reset if booking is still pending
    if sr.status != "pending":
        return Response({"detail": "Cannot reset payment for this booking status."}, status=400)

    # Reset payment state - works for both 'unpaid' and 'pending' payment_status
    sr.payment_status = "unpaid"
    sr.paystack_reference = None
    sr.paystack_access_code = None
    sr.save(update_fields=["payment_status", "paystack_reference", "paystack_access_code"])

    return Response({"detail": "Payment reset. You can try again."}, status=200)


# ═══════════════════════════════════════════════════════════════════
# REFERRAL SYSTEM ENDPOINTS
# ═══════════════════════════════════════════════════════════════════

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_referral_stats(request):
    """
    Get the current user's referral stats and code.
    
    GET /api/referral/stats/
    
    Returns:
    {
        "referral_code": "JOHN1X2K",
        "referral_credits": 10,
        "total_referrals": 2,
        "total_credits_earned": 10,
        "total_credits_used": 0,
        "discount_percent": 7,
        "credits_per_referral": 5,
        "pending_referrals": 1,
        "referrals": [...]
    }
    """
    user = request.user
    
    # Ensure user has a referral code
    if not user.referral_code:
        user.referral_code = user.generate_referral_code()
        user.save(update_fields=['referral_code'])
    
    # Get referral records
    referrals = Referral.objects.filter(referrer=user).select_related('referred_user')
    
    referral_list = []
    for ref in referrals[:20]:  # Limit to 20 most recent
        referral_list.append({
            "referred_username": ref.referred_user.username,
            "referred_first_name": ref.referred_user.first_name,
            "status": ref.status,
            "created_at": ref.created_at.isoformat(),
            "qualified_at": ref.qualified_at.isoformat() if ref.qualified_at else None,
            "credits_awarded": ref.credits_awarded,
        })
    
    pending_count = referrals.filter(status='pending').count()
    
    return Response({
        "referral_code": user.referral_code,
        "referral_credits": user.referral_credits,
        "total_referrals": user.total_referrals,
        "total_credits_earned": user.total_referral_credits_earned,
        "total_credits_used": user.total_referral_credits_used,
        "discount_percent": float(REFERRAL_DISCOUNT_PERCENT),
        "credits_per_referral": REFERRAL_CREDITS_PER_REFERRAL,
        "pending_referrals": pending_count,
        "referrals": referral_list,
    })


@api_view(["POST"])
@permission_classes([AllowAny])
def validate_referral_code(request):
    """
    Validate a referral code before registration.
    
    POST /api/referral/validate/
    Body: { "code": "JOHN1X2K" }
    
    Returns:
    {
        "valid": true,
        "referrer_first_name": "John"
    }
    """
    code = (request.data.get("code") or "").strip().upper()
    
    if not code:
        return Response({"valid": False, "detail": "Code is required."}, status=400)
    
    try:
        referrer = CustomUser.objects.get(referral_code__iexact=code)
        return Response({
            "valid": True,
            "referrer_first_name": referrer.first_name or referrer.username,
        })
    except CustomUser.DoesNotExist:
        return Response({
            "valid": False,
            "detail": "Invalid referral code."
        })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_referral_discount_preview(request, service_request_id):
    """
    Preview the referral discount for a booking before payment.
    
    GET /api/referral/discount_preview/<service_request_id>/
    
    Returns:
    {
        "eligible": true,
        "original_price": 100.00,
        "discount_percent": 7,
        "discount_amount": 7.00,
        "final_price": 93.00,
        "credits_remaining": 4
    }
    """
    try:
        sr = ServiceRequest.objects.get(id=service_request_id, user=request.user)
    except ServiceRequest.DoesNotExist:
        return Response({"detail": "Booking not found."}, status=404)
    
    if sr.payment_status == "paid":
        return Response({"detail": "Booking already paid."}, status=400)
    
    original_price = sr.offered_price or sr.estimated_price or Decimal("0")
    user = request.user
    
    if user.referral_credits <= 0:
        return Response({
            "eligible": False,
            "original_price": float(original_price),
            "discount_percent": 0,
            "discount_amount": 0,
            "final_price": float(original_price),
            "credits_remaining": 0,
            "message": "No referral credits available."
        })
    
    discount_amount = (original_price * REFERRAL_DISCOUNT_PERCENT / Decimal("100")).quantize(Decimal("0.01"))
    final_price = (original_price - discount_amount).quantize(Decimal("0.01"))
    
    return Response({
        "eligible": True,
        "original_price": float(original_price),
        "discount_percent": float(REFERRAL_DISCOUNT_PERCENT),
        "discount_amount": float(discount_amount),
        "final_price": float(final_price),
        "credits_remaining": user.referral_credits,
        "credits_after_use": user.referral_credits - 1,
    })


@csrf_exempt
@require_http_methods(["GET", "POST"])
def paystack_callback(request):
    """
    Paystack callback/redirect URL after payment.
    Renders a page that redirects to the mobile app via deep link.
    """
    reference = (request.GET.get("reference") or request.POST.get("reference") or "").strip()
    trxref = (request.GET.get("trxref") or request.POST.get("trxref") or "").strip()
    
    # Use whichever reference is available
    ref = reference or trxref
    
    # Build deep link
    scheme = getattr(settings, "APP_DEEPLINK_SCHEME", "styloria").strip() or "styloria"
    deeplink = f"{scheme}://payment-return?reference={ref}&gateway=paystack"
    
    html = f"""
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width,initial-scale=1" />
        <title>Payment Complete</title>
        <style>
          body {{ 
            font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; 
            padding: 24px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
          }}
          .card {{ 
            max-width: 420px; 
            background: white;
            border-radius: 16px; 
            padding: 32px; 
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
          }}
          .icon {{
            width: 64px;
            height: 64px;
            background: #10b981;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
          }}
          .icon svg {{
            width: 32px;
            height: 32px;
            fill: white;
          }}
          .title {{ 
            font-weight: 800; 
            font-size: 24px; 
            margin-bottom: 12px;
            color: #1f2937;
          }}
          .muted {{ 
            color: #6b7280; 
            font-size: 16px;
            line-height: 1.5;
            margin-bottom: 24px;
          }}
          .btn {{ 
            display: inline-block; 
            padding: 14px 28px; 
            border-radius: 12px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            text-decoration: none; 
            font-weight: 700;
            font-size: 16px;
            transition: transform 0.2s, box-shadow 0.2s;
          }}
          .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
          }}
          .ref {{ 
            margin-top: 20px; 
            font-size: 12px; 
            color: #9ca3af;
            word-break: break-all;
          }}
          .spinner {{
            border: 3px solid #e5e7eb;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 24px;
            height: 24px;
            animation: spin 1s linear infinite;
            margin: 0 auto 16px;
          }}
          @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
          }}
        </style>
      </head>
      <body>
        <div class="card">
          <div class="icon">
            <svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
          </div>
          <div class="title">Payment Processing</div>
          <div class="muted">Your payment is being verified. You'll be redirected to the app automatically.</div>
          <div class="spinner"></div>
          <a class="btn" href="{deeplink}">Return to App</a>
          <div class="ref">Reference: {ref or "N/A"}</div>
        </div>
        <script>
          setTimeout(function() {{
            window.location.href = "{deeplink}";
          }}, 2000);
        </script>
      </body>
    </html>
    """
    return HttpResponse(html, content_type="text/html")


# =============================================================================
# PAYSTACK BANKS & ACCOUNT RESOLUTION
# =============================================================================

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def paystack_banks(request):
    """
    Get list of banks for Paystack-supported countries.
    
    GET /api/paystack/banks/?country=ghana
    GET /api/paystack/banks/?currency=GHS
    """
    country = (request.GET.get("country") or "").strip()
    currency = (request.GET.get("currency") or "").strip()
    
    if not country and not currency:
        # Try to get from user's country
        user_country = (request.user.country_name or "").strip()
        if is_paystack_country(user_country):
            country = user_country.lower()
            currency = get_paystack_currency(user_country)
        else:
            return Response({"detail": "country or currency parameter is required."}, status=400)
    
    result = paystack_list_banks(country=country or currency, currency=currency or "NGN")
    
    if result.get("success"):
        return Response({
            "banks": result.get("banks", []),
            "count": len(result.get("banks", [])),
        }, status=200)
    else:
        return Response({
            "detail": result.get("message") or "Failed to fetch banks",
            "banks": [],
        }, status=400)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def paystack_resolve_bank_account(request):
    """
    Resolve/verify a bank account number to get the account name.
    
    POST /api/paystack/resolve_account/
    Body: { "account_number": "0123456789", "bank_code": "058" }
    """
    account_number = (request.data.get("account_number") or "").strip()
    bank_code = (request.data.get("bank_code") or "").strip()
    
    if not account_number or not bank_code:
        return Response({"detail": "account_number and bank_code are required."}, status=400)
    
    result = paystack_resolve_account(
        account_number=account_number,
        bank_code=bank_code,
    )
    
    if result.get("success"):
        return Response({
            "success": True,
            "account_name": result.get("account_name"),
            "account_number": result.get("account_number"),
            "bank_id": result.get("bank_id"),
        }, status=200)
    else:
        return Response({
            "success": False,
            "detail": result.get("message") or "Could not resolve account",
        }, status=400)


# -------------------------
# NOTIFICATIONS
# -------------------------
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_notifications(request):
    notes = Notification.objects.filter(user=request.user).order_by("-created_at")
    data = [{"id": n.id, "message": n.message, "created_at": n.created_at, "read": n.read} for n in notes]
    return Response(data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def mark_as_read(request, pk):
    try:
        note = Notification.objects.get(id=pk, user=request.user)
        note.read = True
        note.save()
        return Response({"status": "ok"})
    except Notification.DoesNotExist:
        return Response({"error": "not found"}, status=404)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_notifications(request):
    notes = Notification.objects.filter(user=request.user).order_by("-id")
    data = [{"id": n.id, "message": n.message, "read": n.read, "timestamp": n.timestamp} for n in notes]
    return Response(data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def unread_count(request):
    count = Notification.objects.filter(user=request.user, read=False).count()
    return Response({"unread_count": count})

@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_notification(request, pk):
    """Delete a notification for the current user."""
    try:
        notification = Notification.objects.get(pk=pk, user=request.user)
        notification.delete()
        return Response({"detail": "Notification deleted."}, status=200)
    except Notification.DoesNotExist:
        return Response({"detail": "Notification not found."}, status=404)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def mark_all_notifications_read(request):
    """Mark all notifications as read for the current user."""
    count = Notification.objects.filter(user=request.user, read=False).update(read=True)
    return Response({"detail": f"Marked {count} notifications as read."}, status=200)

@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def clear_all_notifications(request):
    """Delete all notifications for the current user."""
    count, _ = Notification.objects.filter(user=request.user).delete()
    return Response({"detail": f"Deleted {count} notifications."}, status=200)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def delete_selected_notifications(request):
    """
    Delete multiple notifications by IDs.
    
    POST /api/notifications/delete_selected/
    Body: {"ids": [1, 2, 3, 4, 5]}
    """
    ids = request.data.get('ids', [])
    
    if not ids:
        return Response({"detail": "No notification IDs provided."}, status=400)
    
    if not isinstance(ids, list):
        return Response({"detail": "ids must be a list."}, status=400)
    
    # Only delete notifications belonging to the current user
    deleted_count, _ = Notification.objects.filter(
        id__in=ids,
        user=request.user
    ).delete()
    
    return Response({
        "detail": f"Deleted {deleted_count} notification(s).",
        "deleted_count": deleted_count,
    }, status=200)


# -------------------
# ADMIN PAYOUT TOOLING
# -------------------
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_pending_payouts(request):
    if not is_admin_user(request.user):
        return Response({"detail": "Admin access required."}, status=403)

    qs = ServiceRequest.objects.filter(
        payment_status="paid",
        status="completed",
        payout_released=False,
        user_confirmed_completion=True,
        provider_confirmed_completion=True,
    ).order_by("-completed_at")

    serializer = ServiceRequestSerializer(qs, many=True)
    return Response(serializer.data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def admin_release_payout(request, pk):
    if not is_admin_user(request.user):
        return Response({"detail": "Admin access required."}, status=403)

    try:
        service_request = ServiceRequest.objects.get(
            id=pk,
            payment_status="paid",
            status="completed",
            payout_released=False,
        )
    except ServiceRequest.DoesNotExist:
        return Response({"detail": "No eligible booking found for this id."}, status=404)

    service_request.payout_released = True
    service_request.payout_released_at = timezone.now()
    service_request.save()

    # Create a Stripe Transfer to provider connected account:
    # Provider receives (85% of total paid - Stripe fee). Platform keeps 15%.
    if service_request.service_provider and not service_request.stripe_transfer_id:
        provider = service_request.service_provider
        acct = acct = (getattr(provider, "stripe_account_id", "") or "").strip()
        if acct:
            try:
                stripe.api_key = settings.STRIPE_SECRET_KEY

                total = service_request.offered_price or service_request.estimated_price or Decimal("0.00")
                total = Decimal(str(total)).quantize(Decimal("0.01"))

                # Ensure provider gross exists; compute if missing
                if service_request.provider_earnings_amount is None or service_request.platform_fee_amount is None:
                    platform_fee, provider_gross = _compute_split(total)
                    service_request.platform_fee_amount = platform_fee
                    service_request.provider_earnings_amount = provider_gross
                else:                
                    provider_gross = service_request.provider_earnings_amount

                provider_net = service_request.provider_net_amount
                if provider_net is None:
                    provider_net = _compute_provider_net(provider_gross, service_request.stripe_fee_amount) or Decimal("0.00")
                    service_request.provider_net_amount = provider_net

                currency_u = (service_request.currency or "USD").upper().strip()

                amount_int = _to_stripe_minor_units(Decimal(str(provider_net)), currency_u)

                if amount_int > 0:
                    tr = stripe.Transfer.create(
                        amount=amount_int,
                        currency=(service_request.currency or "USD").lower(),
                        destination=acct,
                        metadata={"service_request_id": str(service_request.id)},
                    )
                    service_request.stripe_transfer_id = tr.id

                service_request.save(update_fields=[
                    "platform_fee_amount",
                    "provider_earnings_amount",
                    "stripe_fee_amount",
                    "provider_net_amount",
                    "stripe_transfer_id",
                ])
            except Exception:
                pass

    if service_request.service_provider:
        send_websocket_notification(
            service_request.service_provider.user,
            f"💰 Payment for booking #{pk} has been released!",
            notification_type="payout_released",
        )

    serializer = ServiceRequestSerializer(service_request)
    return Response(serializer.data)


# -------------------------
# PROVIDER EARNINGS
# -------------------------
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def provider_earnings_summary(request):
    block = _require_provider_kyc_approved(request.user)
    if block:
        return Response(block, status=403)

    try:
        provider = ServiceProvider.objects.get(user=request.user)
    except ServiceProvider.DoesNotExist:
        return Response({"detail": "You are not a provider."}, status=400)

    released_qs = ServiceRequest.objects.filter(
        service_provider=provider,
        payment_status="paid",
        status="completed",
        payout_released=True,
    )

    pending_qs = ServiceRequest.objects.filter(
        service_provider=provider,
        payment_status="paid",
        status="completed",
        payout_released=False,
        user_confirmed_completion=True,
        provider_confirmed_completion=True,
    )

    
    # Use provider_net_amount if available (85% minus Stripe fee), fallback to provider_earnings_amount.
    total_paid = float(released_qs.aggregate(total=Sum(Coalesce("provider_net_amount", "provider_earnings_amount")))["total"] or 0.0)
    total_pending = float(pending_qs.aggregate(total=Sum(Coalesce("provider_net_amount", "provider_earnings_amount")))["total"] or 0.0)

    data = {
        "currency": (request.user.preferred_currency or "USD").lower(),
        "total": total_paid + total_pending,
        "paid": total_paid,
        "pending": total_pending,
    }
    return Response(data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def provider_earnings_report_pdf(request):
    block = _require_provider_kyc_approved(request.user)
    if block:
        return Response(block, status=403)

    try:
        provider = ServiceProvider.objects.get(user=request.user)
    except ServiceProvider.DoesNotExist:
        return Response({"detail": "You are not a provider."}, status=400)

    period = request.GET.get("period", "all_time").lower().strip()
    now = timezone.now()

    qs = ServiceRequest.objects.filter(
        service_provider=provider,
        payment_status="paid",
        status="completed",
        payout_released=True
    )

    try:
        since = _provider_period_to_since(period)
    except ValueError:
        return Response(
            {
                "detail": "Invalid period.",
                "allowed": [
                    "this_month",
                    "last_month",
                    "ytd",
                    "all_time",
                    "daily",
                    "weekly",
                    "monthly",
                    "yearly",
                    "all",
                ],
            },
            status=400,
        )

    # last_month returns a range tuple
    if isinstance(since, tuple):
        start, end = since
        qs = qs.filter(completed_at__gte=start, completed_at__lt=end)
    elif since is not None:
        qs = qs.filter(completed_at__gte=since)

    agg = qs.aggregate(total=Sum("offered_price"))
    total = float(agg["total"] or 0.0)

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    _draw_styloria_watermark(p, width, height, text="STYLORIA")

    p.setFont("Helvetica-Bold", 18)
    p.drawString(50, height - 80, "Styloria Earnings Report")


    p.setFont("Helvetica", 12)
    p.drawString(50, height - 110, f"Provider: {provider.user.username}")
    p.drawString(50, height - 130, f"Period: {period}")
    p.drawString(50, height - 150, f"Generated at: {now.isoformat()}")

    currency = (provider.user.preferred_currency or "USD").upper()
    p.drawString(50, height - 190, f"Total earnings ({currency}): {total:.2f}")
    p.drawString(50, height - 210, "Included: completed, paid bookings where payout has been released.")

    p.showPage()
    p.save()
    buffer.seek(0)

    response = HttpResponse(buffer.getvalue(), content_type="application/pdf")
    filename = f"styloria_earnings_{provider.user.username}_{period}.pdf"
    response["Content-Disposition"] = f'attachment; filename="{filename}"'

    return response


def _month_start(dt):
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

def _year_start(dt):
    return dt.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)

def _provider_period_to_since(period: str):
    """
    Supports BOTH:
      - new Flutter periods: this_month, last_month, ytd, all_time
      - old periods: daily, weekly, monthly, yearly, all

    Returns: datetime | None | tuple(datetime, datetime)
    """

    period = (period or "all_time").lower().strip()
    now = timezone.now()
 
    if period in ("all_time", "all"): 
        return None

    if period in ("ytd",):
        return _year_start(now)

    if period in ("this_month",):
        return _month_start(now)

    if period in ("last_month",):
        this_month_start = _month_start(now)
        last_month_end = this_month_start - timedelta(seconds=1)
        last_month_start = _month_start(last_month_end)
        return last_month_start, this_month_start

    # legacy support
    days_map = {
        "daily": 1,
        "weekly": 7,
        "monthly": 30,
        "yearly": 365,
    }

    if period in days_map:
        return now - timedelta(days=days_map[period])

    raise ValueError("Invalid period.")


@api_view(["GET", "PATCH"])
@permission_classes([IsAuthenticated])
def provider_payout_settings(request):
    block = _require_provider_kyc_approved(request.user)
    if block:
        return Response(block, status=403)

    provider = ServiceProvider.objects.filter(user=request.user).first()
    if not provider:
        return Response({"detail": "You are not a provider."}, status=400)

    settings_obj, created = ProviderPayoutSettings.objects.get_or_create(provider=provider)

    # Auto-set gateway based on country when first created or if still default
    provider_country = (provider.user.country_name or "").strip()
    if created or settings_obj.payout_gateway == "stripe":
        correct_gateway = get_payment_gateway_for_country(provider_country)
        if settings_obj.payout_gateway != correct_gateway:
            settings_obj.payout_gateway = correct_gateway
            if correct_gateway == "paystack":
                settings_obj.paystack_currency = get_paystack_currency(provider_country) or get_currency_for_country(provider_country)
            elif correct_gateway == "flutterwave":
                settings_obj.flutterwave_currency = get_currency_for_country(provider_country)
            settings_obj.save(update_fields=["payout_gateway", "paystack_currency", "flutterwave_currency", "updated_at"])

    if request.method == "GET":
        return Response(ProviderPayoutSettingsSerializer(settings_obj).data)

    ser = ProviderPayoutSettingsSerializer(settings_obj, data=request.data, partial=True)
    ser.is_valid(raise_exception=True)

    provider_country = (provider.user.country_name or "").strip()

    # STRICT RULE: Route based on country
    if is_paystack_country(provider_country):
        # Paystack countries: Ghana, Nigeria, South Africa, Kenya, Côte d'Ivoire
        locked_cur = get_paystack_currency(provider_country) or get_currency_for_country(provider_country)
        locked_cur = locked_cur.upper().strip()
        ser.save(payout_gateway="paystack", paystack_currency=locked_cur)
    elif is_african_country_name(provider_country):
        # Other African countries: Flutterwave
        locked_cur = get_currency_for_country(provider_country).upper().strip()
        ser.save(payout_gateway="flutterwave", flutterwave_currency=locked_cur)
    else:
        # Rest of world: Stripe
        ser.save()

    return Response(ser.data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def provider_payout_history(request):
    block = _require_provider_kyc_approved(request.user)
    if block:
        return Response(block, status=403)

    provider = ServiceProvider.objects.filter(user=request.user).first()
    if not provider:
        return Response({"detail": "You are not a provider."}, status=400)

    currency = (request.GET.get("currency") or "").upper().strip()
    qs = Payout.objects.filter(provider=provider).order_by("-created_at")
    if currency:
        qs = qs.filter(currency=currency)

    return Response(PayoutSerializer(qs[:200], many=True).data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def provider_wallet_summary(request):
    block = _require_provider_kyc_approved(request.user)
    if block:
        return Response(block, status=403)

    provider = ServiceProvider.objects.filter(user=request.user).first()
    if not provider:
        return Response({"detail": "You are not a provider."}, status=400)

    wallets = ProviderWallet.objects.filter(provider=provider).order_by("currency")
    return Response(ProviderWalletSerializer(wallets, many=True).data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def provider_wallet_transactions(request):
    block = _require_provider_kyc_approved(request.user)
    if block:
        return Response(block, status=403)

    provider = ServiceProvider.objects.filter(user=request.user).first()
    if not provider:
        return Response({"detail": "You are not a provider."}, status=400)

    currency = (request.GET.get("currency") or "").upper().strip()
    wallets = ProviderWallet.objects.filter(provider=provider)
    if currency:
        wallets = wallets.filter(currency=currency)

    entries = WalletLedgerEntry.objects.filter(wallet__in=wallets).select_related("service_request", "payout").order_by("-created_at")[:200]
    return Response(WalletLedgerEntrySerializer(entries, many=True).data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def provider_wallet_cash_out(request):
    """
    Instant cash out: debits available wallet balance and creates Stripe Transfer to connected account.
    Body: { "currency": "USD", "amount": "12.34" }

    Rules:
    - Weekly payout providers: 1 instant cashout per period
    - Monthly payout providers: 3 instant cashouts per period
    - Minimum amount: $5 USD (converted to provider's currency)
    - 5% fee applies to instant cashouts

    """
    block = _require_provider_kyc_approved(request.user)
    if block:
        return Response(block, status=403)

    provider = ServiceProvider.objects.filter(user=request.user).first()
    if not provider:
        return Response({"detail": "You are not a provider."}, status=400)

    settings_obj, _ = ProviderPayoutSettings.objects.get_or_create(provider=provider)

    provider_country = (provider.user.country_name or "").strip()

    # Determine payout gateway based on country
    use_paystack = is_paystack_country(provider_country)
    use_flutterwave = is_african_country_name(provider_country) and not use_paystack

    if not use_flutterwave and not use_paystack:
        if not (provider.stripe_account_id or "").strip():
            return Response({"detail": "Provider has no Stripe connected account."}, status=400)

    if not settings_obj.instant_payout_enabled:
        return Response({"detail": "Instant cash out is disabled in your payout settings."}, status=403)

    currency = (request.data.get("currency") or request.user.preferred_currency or "USD").upper().strip()
    wallet = ProviderWallet.objects.filter(provider=provider, currency=currency).first()
    if not wallet:
        return Response({"detail": f"No wallet found for currency {currency}."}, status=404)

    # Calculate minimum amount in wallet currency
    min_usd = Decimal("5.00")
    if currency == "USD":
        min_amount_in_currency = min_usd
    else:
        try:
            converted = convert_amount(float(min_usd), "USD", currency)
            min_amount_in_currency = Decimal(str(converted)).quantize(Decimal("0.01"))
        except Exception:
            min_amount_in_currency = min_usd


    raw_amount = request.data.get("amount", None)
    try:
        amount = wallet.available_balance if raw_amount in (None, "", 0, "0") else  Decimal(str(raw_amount))
    except Exception:
        return Response({"detail": "Invalid amount."}, status=400)

    # Amount is now REQUIRED - provider must specify how much to cash out
    if raw_amount is None or raw_amount == "" or raw_amount == 0 or raw_amount == "0":  
        return Response({
            "detail": "Please specify the amount you want to cash out.",
            "available_balance": str(wallet.available_balance),
            "minimum_amount": str(min_amount_in_currency),
            "currency": currency,
        }, status=400)

    try:
        amount = Decimal(str(raw_amount)).quantize(Decimal("0.01"))
    except Exception:
        return Response({"detail": "Invalid amount format."}, status=400)

    # Validate amount
    if amount <= Decimal("0.00"):
        return Response({"detail": "Amount must be greater than zero."}, status=400)

    if amount < min_amount_in_currency:
        return Response({
            "detail": f"Minimum cashout amount is {min_amount_in_currency} {currency}.",
            "minimum_amount": str(min_amount_in_currency),
        }, status=400)

    if amount > wallet.available_balance:
        return Response({
            "detail": f"Insufficient balance. Available: {wallet.available_balance} {currency}.",
            "available_balance": str(wallet.available_balance),
            "requested_amount": str(amount),
        }, status=400)

    try:
        if use_paystack:
            payout = payout_wallet_paystack(provider=provider, currency=currency, amount=amount, method="instant")
        elif use_flutterwave:
            payout = payout_wallet_flutterwave(provider=provider, currency=currency, amount=amount, method="instant")
        else:
            payout = payout_wallet(provider=provider, currency=currency, amount=amount, method="instant")

    except Exception as e:
        return Response({"detail": str(e)}, status=400)

    # Check if the payout actually succeeded (Flutterwave may fail asynchronously)
    if payout.status == "failed":
        wallet.refresh_from_db()
        failure_reason = payout.failure_reason or "Transfer could not be completed. Please check your payout settings."
        return Response({
            "success": False,
            "detail": failure_reason,
            "payout": PayoutSerializer(payout).data,
            "wallet": ProviderWalletSerializer(wallet).data,
        }, status=400)


    # Get updated remaining uses
    remaining = settings_obj.get_instant_payouts_remaining()

    # Refresh wallet to get updated balance
    wallet.refresh_from_db()

    return Response({
        "success": True,
        "payout": PayoutSerializer(payout).data,
        "wallet": ProviderWalletSerializer(wallet).data,
        "instant_payouts_remaining": remaining,
        "message": f"Cashout of {payout.net_amount} {currency} initiated successfully. A 5% fee ({payout.fee_amount} {currency}) was applied.",
    }, status=200)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def provider_instant_cashout_info(request):
    """
    GET /api/provider/instant-cashout-info/

    Returns information needed for the instant cashout UI:
    - Can use instant payout?
    - Remaining uses this period
    - Button state and notice message
    - Available wallets with balances
    """
    block = _require_provider_kyc_approved(request.user)
    if block:
        return Response(block, status=403)

    provider = ServiceProvider.objects.filter(user=request.user).first()
    if not provider:
        return Response({"detail": "You are not a provider."}, status=400)

    settings_obj, _ = ProviderPayoutSettings.objects.get_or_create(provider=provider)
    wallets = ProviderWallet.objects.filter(provider=provider)

    wallet_data = ProviderWalletSerializer(wallets, many=True).data
    settings_data = ProviderPayoutSettingsSerializer(settings_obj).data

    return Response({
        "payout_settings": settings_data,
        "wallets": wallet_data,
        "fee_percent": 5,
        "fee_description": "A 5% fee is applied to instant cashouts. Scheduled payouts have no fees.",
    })



# -------------------------
# PDF HELPERS (WATERMARK + PERIOD)
# -------------------------
def _period_to_since(period: str):
    """
    period: daily|weekly|monthly|yearly|all

    returns: datetime or None

    """
    period = (period or "all").lower().strip()
    now = timezone.now()

    days_map = {"daily": 1, "weekly": 7, "monthly": 30, "yearly": 365, "all": None}
    if period not in days_map:
        raise ValueError("Invalid period. Use daily|weekly|monthly|yearly|all.")
    delta_days = days_map[period]
    if delta_days is None:
        return None
    return now - timedelta(days=delta_days)


def _draw_styloria_watermark(p: canvas.Canvas, width: float, height: float, text: str = "STYLORIA"):

    """
    Professional repeated watermark across the whole page.

    """
    p.saveState()
    p.setFont("Helvetica-Bold", 48)
    p.setFillColorRGB(0.92, 0.92, 0.92)

    p.translate(width / 2, height / 2)
    p.rotate(35)

    step_x = 300
    step_y = 220
    for y in range(-2000, 2000, step_y):
        for x in range(-2000, 2000, step_x):
            p.drawString(x, y, text)

    p.restoreState()


def _pdf_title_block(p: canvas.Canvas, width: float, height: float, title: str, subtitle_lines: list[str]):

    p.setFont("Helvetica-Bold", 18)
    p.drawString(50, height - 80, title)

    p.setFont("Helvetica", 11)
    y = height - 105
    for line in subtitle_lines:
        p.drawString(50, y, line)
        y -= 16


def _format_money(v) -> str:
    try:
        return f"{float(v or 0):,.2f}"
    except Exception:
        return "0.00"


# -------------------------
# USER SPENDINGS REPORT (PDF)
# -------------------------
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_spendings_report_pdf(request):
    period = request.GET.get("period", "monthly").lower().strip()

    try:
        since = _period_to_since(period)
    except ValueError as e:
        return Response({"detail": str(e)}, status=400)

    qs = ServiceRequest.objects.filter(user=request.user, payment_status="paid")
    if since is not None:
        qs = qs.filter(request_time__gte=since)

    amount_expr = Case(
        When(status="cancelled", penalty_applied=True, then=Coalesce("penalty_amount", Value(0))),
        default=Coalesce("offered_price", "estimated_price", Value(0)),
        output_field=DecimalField(max_digits=12, decimal_places=2),
    )

    if period == "daily":
        bucket = TruncDay("request_time")
        label = "Day"
    elif period == "weekly":
        bucket = TruncWeek("request_time")
        label = "Week"
    elif period == "monthly":
        bucket = TruncMonth("request_time")
        label = "Month"
    elif period == "yearly":
        bucket = TruncYear("request_time")
        label = "Year"
    else:
        bucket = TruncMonth("request_time")
        label = "Month"

    grouped = (
        qs.annotate(bucket=bucket)
        .values("bucket")
        .annotate(count=Count("id"), total=Sum(amount_expr))
        .order_by("bucket")
    )

    grand_total = 0.0
    for row in grouped:
        grand_total += float(row["total"] or 0.0)

    now = timezone.now()
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    _draw_styloria_watermark(p, width, height, text="STYLORIA")
    _pdf_title_block(
        p,
        width,
        height,
        title="Styloria Spendings Report",
        subtitle_lines=[
            f"User: {request.user.username}",
            f"Period: {period}",
            f"Generated at: {now.isoformat()}",
        ],
    )

    p.setFont("Helvetica-Bold", 12)
    p.drawString(50, height - 170, f"Total Spendings (USD): {_format_money(grand_total)}")

    p.setFont("Helvetica", 10)
    p.drawString(50, height - 190, "Included: paid bookings; cancelled bookings count penalty only (if applied).")

    y = height - 230
    p.setFont("Helvetica-Bold", 11)
    p.drawString(50, y, label)
    p.drawString(260, y, "Count")
    p.drawString(340, y, "Amount (USD)")
    y -= 10
    p.line(50, y, width - 50, y)
    y -= 18

    p.setFont("Helvetica", 10)

    for row in grouped:
        if y < 80:
            p.showPage()
            _draw_styloria_watermark(p, width, height, text="STYLORIA")
            _pdf_title_block(
                p,
                width,
                height,
                title="Styloria Spendings Report (continued)",
                subtitle_lines=[f"User: {request.user.username}", f"Period: {period}"],
            )

            y = height - 160
            p.setFont("Helvetica-Bold", 11)
            p.drawString(50, y, label)
            p.drawString(260, y, "Count")
            p.drawString(340, y, "Amount (USD)")
            y -= 10
            p.line(50, y, width - 50, y)
            y -= 18
            p.setFont("Helvetica", 10)

        bucket_dt = row["bucket"]
        bucket_str = bucket_dt.date().isoformat() if hasattr(bucket_dt, "date") else str(bucket_dt)

        p.drawString(50, y, bucket_str)
        p.drawString(260, y, str(row["count"] or 0))
        p.drawRightString(width - 50, y, _format_money(row["total"]))
        y -= 16

    p.showPage()
    p.save()
    buffer.seek(0)

    response = HttpResponse(buffer.getvalue(), content_type="application/pdf")
    filename = f"styloria_spendings_{request.user.username}_{period}.pdf"
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


# -------------------------
# ADMIN EXPORT REPORT (PDF)
# -------------------------
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_export_report_pdf(request):
    if not is_admin_user(request.user):
        return Response({"detail": "Admin access required."}, status=403)

    report_type = request.GET.get("type", "all").lower().strip()
    period = request.GET.get("period", "monthly").lower().strip()

    report_type = request.GET.get("type", "all").lower().strip()
    period = request.GET.get("period", "monthly").lower().strip()

    allowed_types = {"transactions", "requests", "chats", "support", "users", "all"}
    if report_type not in allowed_types:
        return Response({"detail": "Invalid type. Use transactions|requests|chats|support|users|all."}, status=400)

    try:
        since = _period_to_since(period)
    except ValueError as e:
        return Response({"detail": str(e)}, status=400)

    now = timezone.now()
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    def new_page(title: str, subtitle: list[str]):
        p.showPage()
        _draw_styloria_watermark(p, width, height, text="STYLORIA")
        _pdf_title_block(p, width, height, title=title, subtitle_lines=subtitle)

    _draw_styloria_watermark(p, width, height, text="STYLORIA")
    _pdf_title_block(
        p,
        width,
        height,
        title="Styloria Admin Export Report",
        subtitle_lines=[
            f"Generated by: {request.user.username}",
            f"Type: {report_type}",
            f"Period: {period}",
            f"Generated at: {now.isoformat()}",
        ],
    )

    y = height - 180
    p.setFont("Helvetica", 11)

    def write_lines(lines: list[str]):
        nonlocal y
        for line in lines:
            if y < 80:
                new_page("Styloria Admin Export Report (continued)", [f"Type: {report_type}", f"Period: {period}"])
                y = height - 140
                p.setFont("Helvetica", 11)
            p.drawString(50, y, line[:140])
            y -= 16

    def apply_since(qs, field_name: str):
        if since is None:
            return qs
        kwargs = {f"{field_name}__gte": since}
        return qs.filter(**kwargs)

    if report_type in ("users", "all"):
        users_qs = apply_since(CustomUser.objects.all().order_by("-date_joined"), "date_joined")
        total_users = users_qs.count()

        write_lines(["", f"USERS ({total_users})", "-" * 60])
        for u in users_qs[:200]:
            write_lines(
                [
                    (
                        f"@{u.username} | {u.role} | email={u.email or ''} | phone={u.phone_number or ''} | "
                        f"joined={u.date_joined.isoformat()} | styloria_id={u.styloria_id or ''}"
                    )
                ]
            )

    if report_type in ("requests", "all"):
        req_qs = apply_since(
            ServiceRequest.objects.select_related("user", "service_provider__user").order_by("-request_time"),
            "request_time",
        )
        total_reqs = req_qs.count()

        write_lines(["", f"SERVICE REQUESTS ({total_reqs})", "-" * 60])
        for r in req_qs[:300]:
            provider_name = r.service_provider.user.username if r.service_provider else ""
            amount = r.offered_price or r.estimated_price or 0
            write_lines(
                [
                    (
                        f"#{r.id} | user={r.user.username} | provider={provider_name} | status={r.status} | "
                        f"pay={r.payment_status} | amount={amount} | time={r.request_time.isoformat()}"
                    )
                ]
            )

    if report_type in ("transactions", "all"):
        paid_qs = apply_since(
            ServiceRequest.objects.filter(payment_status="paid").select_related("user").order_by("-request_time"),
            "request_time",
        )
        amount_expr = Case(
            When(status="cancelled", penalty_applied=True, then=Coalesce("penalty_amount", Value(0))),
            default=Coalesce("offered_price", "estimated_price", Value(0)),
            output_field=DecimalField(max_digits=12, decimal_places=2),
        )
        totals = paid_qs.aggregate(total=Sum(amount_expr), count=Count("id"))

        write_lines(["", f"TRANSACTIONS (paid requests) ({totals['count'] or 0})", "-" * 60])
        write_lines([f"Total (USD): {_format_money(totals['total'])}"])

        for r in paid_qs[:300]:
            amount = (
                r.penalty_amount
                if (r.status == "cancelled" and r.penalty_applied)
                else (r.offered_price or r.estimated_price or 0)
            )

            write_lines([f"#{r.id} | user={r.user.username} | status={r.status} | amount={amount} | time={r.request_time.isoformat()}"])

    if report_type in ("chats", "all"):
        msg_qs = apply_since(
            ChatMessage.objects.select_related("sender", "thread", "thread__service_request").order_by("-created_at"),
            "created_at",
        )

        total_msgs = msg_qs.count()

        write_lines(["", f"CHATS (messages) ({total_msgs})", "-" * 60])
        for m in msg_qs[:500]:
            req_id = m.thread.service_request_id if m.thread_id else None
            write_lines([f"[{m.created_at.isoformat()}] req#{req_id} sender={m.sender.username}: {m.content}"])

    if report_type in ("support", "all"):
        sm_qs = apply_since(
            SupportMessage.objects.select_related("sender", "thread", "thread__user").order_by("-created_at"),
            "created_at",
        )

        total_sm = sm_qs.count()

        write_lines(["", f"SUPPORT CHATS (messages) ({total_sm})", "-" * 60])
        for m in sm_qs[:500]:
            owner = m.thread.user.username if m.thread_id else ""
            write_lines([f"[{m.created_at.isoformat()}] thread_user={owner} sender={m.sender.username}: {m.content}"])

    p.showPage()
    p.save()
    buffer.seek(0)

    response = HttpResponse(buffer.getvalue(), content_type="application/pdf")
    filename = f"styloria_admin_export_{report_type}_{period}.pdf"
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


# -------------------
# MFA (Two-Factor) API
# -------------------
@api_view(["POST"])
@permission_classes([AllowAny])
def mfa_verify(request):
    user_id = request.data.get("user_id")
    code = (request.data.get("code") or "").strip()

    if not user_id or not code:
        return Response({"detail": "user_id and code are required."}, status=400)

    try:
        user = CustomUser.objects.get(id=user_id)
    except CustomUser.DoesNotExist:
        return Response({"detail": "User not found."}, status=400)

    if not getattr(user, "email_verified", False):
        return Response({"detail": "Verify your email before signing in."}, status=403)

    if not user.is_active:
        return Response({"detail": "Account is disabled."}, status=403)

    mfa = MFACode.objects.filter(user=user, code=code, used=False).order_by("-created_at").first()
    if not mfa or not mfa.is_valid():
        return Response({"detail": "Invalid or expired code."}, status=400)

    mfa.used = True
    mfa.save(update_fields=["used"])

    refresh = RefreshToken.for_user(user)
    access = str(refresh.access_token)

    return Response({"refresh": str(refresh), "access": access})


# -------------------------
# LOCATION TRACKING
# -------------------------
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def update_location(request):
    """
    Update user/provider location for tracking.
    POST /api/location/update/
    Body: {booking_id, latitude, longitude, is_provider}

    """
    booking_id = request.data.get("booking_id")
    latitude = request.data.get("latitude")
    longitude = request.data.get("longitude")
    is_provider = request.data.get("is_provider", False)

    if booking_id is None or latitude is None or longitude is None:
        return Response({"detail": "booking_id, latitude, and longitude are required"}, status=400)

    try:
        latitude = float(latitude)
        longitude = float(longitude)
    except ValueError:
        return Response({"detail": "Invalid latitude/longitude"}, status=400)

    try:
        booking = ServiceRequest.objects.get(id=booking_id)
    except ServiceRequest.DoesNotExist:
        return Response({"detail": "Booking not found"}, status=404)

    user = request.user
    if user != booking.user and (not booking.service_provider or user != booking.service_provider.user):
        return Response({"detail": "Not authorized for this booking"}, status=403)

    if booking.status not in ["accepted", "in_progress"]:
        return Response({"detail": "Location tracking only available for active bookings"}, status=400)

    requester_is_provider = bool(booking.service_provider and user == booking.service_provider.user)
    is_provider = bool(is_provider) and requester_is_provider

    LocationUpdate.objects.create(
        booking=booking,
        user=user,
        latitude=latitude,
        longitude=longitude,
        is_provider=is_provider,
    )

    # Check if provider has arrived at requester's location
    provider_arrived = False
    if is_provider and booking.status == "accepted":
        has_arrived, distance_meters = check_provider_arrived(
            provider_lat=latitude,
            provider_lng=longitude,
            dest_lat=booking.location_latitude,
            dest_lng=booking.location_longitude,
        )
        
        if has_arrived:
            provider_arrived = True
            provider_name = booking.service_provider.user.first_name or booking.service_provider.user.username
         
            # Only notify once - check if we already notified
            already_notified = Notification.objects.filter(
                user=booking.user,
                message__contains=f"has arrived",
            ).filter(
                message__contains=f"#{booking_id}",
            ).exists()

            if not already_notified:
                send_websocket_notification(
                booking.user,
                f"🎉 Great news! {provider_name} has arrived at your location for booking #{booking_id}. "
                f"Please meet them to begin your {booking.service_type} service.",
                notification_type="provider_arrived",
            )

    return Response({
        "status": "success",
        "provider_arrived": provider_arrived,
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_other_party_location(request, booking_id):
    """
    Get the latest location of the other party in the booking.
    GET /api/location/other_party/<booking_id>/

    """
    try:
        booking = ServiceRequest.objects.get(id=booking_id)
    except ServiceRequest.DoesNotExist:
        return Response({"detail": "Booking not found"}, status=404)

    user = request.user
    if user != booking.user and (not booking.service_provider or user != booking.service_provider.user):
        return Response({"detail": "Not authorized"}, status=403)

    if booking.status not in ["accepted", "in_progress"]:
        return Response({"detail": "Booking not active"}, status=400)

    user_is_provider = bool(booking.service_provider and user == booking.service_provider.user)

    other_is_provider_flag = False if user_is_provider else True

    latest_location = (
        LocationUpdate.objects.filter(booking=booking, is_provider=other_is_provider_flag)
        .order_by("-timestamp")
        .first()
    )

    if not latest_location:
        return Response({"detail": "No location data available"}, status=404)

    return Response(
        {
            "latitude": latest_location.latitude,
            "longitude": latest_location.longitude,
            "timestamp": latest_location.timestamp,
            "role": "provider" if other_is_provider_flag else "user",
        }
    )


# -------------------------
# CURRENCY ENDPOINTS
# -------------------------
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def update_currency_from_location(request):
    """
    Update user's currency based on GPS coordinates.
    POST /api/users/update_currency_from_location/
    Body: {"latitude": 5.6037, "longitude": -0.1870}
    """
    from .utils.currency import get_country_from_coordinates, get_currency_for_country, get_currency_symbol

    latitude = request.data.get("latitude")
    longitude = request.data.get("longitude")

    if latitude is None or longitude is None:
        return Response({"detail": "Latitude and longitude are required."}, status=400)

    try:
        lat = float(latitude)
        lng = float(longitude)
    except ValueError:
        return Response({"detail": "Invalid coordinates."}, status=400)

    country = get_country_from_coordinates(lat, lng)
    if not country:
        return Response({"detail": "Could not determine country from coordinates."}, status=400)

    new_currency = get_currency_for_country(country)

    user = request.user
    currency_changed = user.preferred_currency != new_currency

    user.preferred_currency = new_currency
    user.currency_source = "gps"
    user.last_currency_update = timezone.now()
    user.last_known_latitude = lat
    user.last_known_longitude = lng
    user.last_location_update = timezone.now()
    user.save()

    return Response(
        {
            "detail": "Currency updated successfully." if currency_changed else "Currency already up to date.",
            "country": country,
            "currency": new_currency,
            "currency_symbol": get_currency_symbol(new_currency),
            "currency_changed": currency_changed,
        }
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def update_currency_manually(request):
    """
    Manually set user's preferred currency.
    POST /api/users/update_currency_manually/
    Body: {"currency": "GHS"}
    """
    from .utils.currency import get_currency_symbol

    currency = (request.data.get("currency") or "").upper().strip()
    if len(currency) != 3 or not currency.isalpha():
        return Response(
            {"detail": "Invalid currency code. Use 3-letter ISO code (USD, EUR, GHS, etc.)."},
            status=400,
        )

    user = request.user
    currency_changed = user.preferred_currency != currency

    user.preferred_currency = currency
    user.currency_source = "manual"
    user.last_currency_update = timezone.now()
    user.save()

    return Response(
        {
            "detail": "Currency updated successfully." if currency_changed else "Currency already set.",
            "currency": currency,
            "currency_symbol": get_currency_symbol(currency),
            "currency_changed": currency_changed,
        }
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_currency_info(request):
    """
    Get user's current currency information.
    GET /api/users/currency_info/
    """
    from .utils.currency import get_currency_symbol

    user = request.user
    return Response(
        {
            "preferred_currency": user.preferred_currency,
            "currency_symbol": get_currency_symbol(user.preferred_currency),
            "currency_source": user.currency_source,
            "last_currency_update": user.last_currency_update,
            "country_name": user.country_name,
            "last_known_location": {
                "latitude": user.last_known_latitude,
                "longitude": user.last_known_longitude,
                "updated_at": user.last_location_update,
            },
        }
    )


@api_view(["GET"])
@permission_classes([AllowAny])
def get_supported_currencies(request):
    """
    Get list of supported currencies.
    GET /api/currencies/

    """
    from .utils.currency import COUNTRY_TO_CURRENCY, get_currency_symbol

    currencies = sorted(set(COUNTRY_TO_CURRENCY.values()))
    return Response([{"code": c, "symbol": get_currency_symbol(c), "name": c} for c in currencies])


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_exchange_rate_info(request):
    """
    Get exchange rates for user's currency.
    GET /api/users/exchange_rates/

    """
    from .utils.currency import get_exchange_rate, get_currency_symbol

    user_currency = request.user.preferred_currency
    major_currencies = ["USD", "EUR", "GBP", "JPY", "CNY", "INR", "GHS", "NGN", "KES", "ZAR", "AUD"]

    rates = {}
    for currency in major_currencies:
        if currency != user_currency:
            rates[currency] = {
                "rate": get_exchange_rate(user_currency, currency),
                "symbol": get_currency_symbol(currency),
            }

    return Response(
        {
            "base_currency": user_currency,
            "base_symbol": get_currency_symbol(user_currency),
            "rates": rates,
            "updated_at": timezone.now(),
        }
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def debug_bookings(request):
    user = request.user
    data = {
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "total_bookings": ServiceRequest.objects.filter(user=user).count(),
        "bookings_list": list(
            ServiceRequest.objects.filter(user=user).values("id", "status", "payment_status", "appointment_time")
        ),
        "assigned_bookings": list(
            ServiceRequest.objects.filter(service_provider__user=user).values("id", "status", "payment_status")
        ),
    }

    return Response(data)


def _has_nearby_available_provider_for_service(*, user_lat, user_lng, service_type: str) -> bool:
    """
    True if at least one provider is available + verified + approved + offers service_type
    and is within 15 miles (~24.14 km).
    """
    user_location = (user_lat, user_lng)
    max_distance_km = Decimal("24.14")

    qs = (
        ServiceProvider.objects.filter(
            available=True,
            is_verified=True,  # is_verified == verification_status approved (your model syncs this)
            location_latitude__isnull=False,
            location_longitude__isnull=False,
        )
        .prefetch_related("service_prices")
        .select_related("user")
    )

    for provider in qs:
        if provider.get_service_price(service_type) is None:
            continue

        provider_location = (provider.location_latitude, provider.location_longitude)
        distance_km = Decimal(str(geodesic(user_location, provider_location).km))
        if distance_km <= max_distance_km:
            return True

    return False


def _notify_waiting_requests_if_providers_now_available(provider: ServiceProvider):
    """
    When a provider becomes available/approved/located, notify users who previously had
    no providers near them for that service.
    One-time notification per request (no spam).
    """
    if not provider.available or not provider.is_verified:
        return
    if provider.location_latitude is None or provider.location_longitude is None:
        return

    # Find requests that are still waiting (unpaid + pending)
    waiting = ServiceRequest.objects.filter(
        status="pending",
        payment_status="unpaid",
        no_providers_notified=True,
        providers_available_notified=False,
    ).order_by("-request_time")[:200]

    for req in waiting:
        # Must match service type
        if provider.get_service_price(req.service_type) is None:
            continue

        # Must be within radius
        user_location = (req.location_latitude, req.location_longitude)
        provider_location = (provider.location_latitude, provider.location_longitude)
        distance_km = Decimal(str(geodesic(user_location, provider_location).km))
        if distance_km > Decimal("24.14"):
            continue

        # Notify requester (premium customer-care tone)
        send_websocket_notification(
            req.user,
            (
                "Good news—providers are now available for your request. "
                "Thank you for your patience. You can now proceed to payment to place your request in the queue."
                "If you no longer need the service, you can cancel your request at any time."
            ),
            notification_type="info",
        )

        req.providers_available_notified = True
        req.save(update_fields=["providers_available_notified"])



# ============================================================
# STRIPE CONNECT (PROVIDER ONBOARDING / STATUS / LOGIN LINK)
# ============================================================

def _stripe_public_base_url(request) -> str:
    """
    Used to build refresh_url/return_url for Stripe Connect account links.
    In production, prefer a fixed HTTPS base URL (e.g. https://api.yourdomain.com)
    instead of request.build_absolute_uri which may reflect internal hosts.
    """
    base = getattr(settings, "PUBLIC_BASE_URL", "") or ""
    if base:
        return base.rstrip("/")
    #fallback: best-effort
    return request.build_absolute_uri("/").rstrip("/")


def _ensure_provider_stripe_account(provider: ServiceProvider, user) -> str:
    acct_id = (provider.stripe_account_id or "").strip()
    if acct_id:
        return acct_id
    stripe.api_key = settings.STRIPE_SECRET_KEY
    country = getattr(settings, "STRIPE_DEFAULT_CONNECT_COUNTRY", "US")
    acct = stripe.Account.create(
        type="express",
        country=country,
        email=getattr(user, "email", None) or None,
        business_type="individual",
        capabilities={"transfers": {"requested": True}},
        metadata={"provider_id": str(provider.id), "user_id": str(user.id)},
    )
    provider.stripe_account_id = acct.id
    provider.save(update_fields=["stripe_account_id"])
    return acct.id


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def provider_stripe_status(request):
    block = _require_provider_kyc_approved(request.user)
    if block:
        return Response(block, status=403)

    provider = ServiceProvider.objects.filter(user=request.user).first()
    if not provider:
        return Response({"detail": "You are not a provider."}, status=400)

    acct_id = (provider.stripe_account_id or "").strip()
    if not acct_id:
        return Response(
            {
                "has_account": False,
                "stripe_account_id": "",
                "charges_enabled": False,
                "payouts_enabled": False,
                "details_submitted": False,
                "requirements": None,
            },
            status=200,
        )

    stripe.api_key = settings.STRIPE_SECRET_KEY
    try:
        acct = stripe.Account.retrieve(acct_id)
    except Exception as e:
        return Response(
            {
                "has_account": True,
                "stripe_account_id": acct_id,
                "error": str(e),
            },
            status=200,
        )

    reqs = acct.get("requirements") or {}
    return Response(
        {
            "has_account": True,
            "stripe_account_id": acct_id,
            "charges_enabled": bool(acct.get("charges_enabled")),
            "payouts_enabled": bool(acct.get("payouts_enabled")),
            "details_submitted": bool(acct.get("details_submitted")),
            "requirements": {
                "currently_due": reqs.get("currently_due", []),
                "eventually_due": reqs.get("eventually_due", []),
                "past_due": reqs.get("past_due", []),
                "disabled_reason": reqs.get("disabled_reason"),
            },
        },
        status=200,
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def provider_stripe_create_account(request):
    """
    Creates (if missing) a Stripe Express connected account for this provider and stores acct_... on ServiceProvider.
    """
    block = _require_provider_kyc_approved(request.user)
    if block:
        return Response(block, status=403)

    provider = ServiceProvider.objects.filter(user=request.user).first()
    if not provider:
        return Response({"detail": "You are not a provider."}, status=400)

    try:
        existing = (provider.stripe_account_id or "").strip()
        acct_id = _ensure_provider_stripe_account(provider, request.user)
    except stripe.error.StripeError as e:
        return Response({"detail": str(e)}, status=400)
    except Exception as e:
        return Response({"detail": f"server_error: {e.__class__.__name__}: {e}"}, status=500)


    return Response({"stripe_account_id": acct_id, "created": (not bool(existing))}, status=200)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def provider_stripe_account_link(request):
    """
    Creates a Stripe Account Link for onboarding.
    Returns { url } that the mobile app should open.
    """
    block = _require_provider_kyc_approved(request.user)
    if block:
        return Response(block, status=403)

    provider = ServiceProvider.objects.filter(user=request.user).first()
    if not provider:
        return Response({"detail": "You are not a provider."}, status=400)

    stripe.api_key = settings.STRIPE_SECRET_KEY

    acct_id = (provider.stripe_account_id or "").strip()
    if not acct_id:
        try:
            acct_id = _ensure_provider_stripe_account(provider, request.user)
        except stripe.error.StripeError as e:
            return Response({"detail": str(e)}, status=400)

    # You should set these in settings to stable HTTPS endpoints.
    # For mobile deep links, commonly you use an HTTPS landing page that redirects into the app.
    public_base = _stripe_public_base_url(request)
    refresh_url = getattr(settings, "STRIPE_CONNECT_REFRESH_URL", "") or f"{public_base}/stripe/connect/refresh"
    return_url = getattr(settings, "STRIPE_CONNECT_RETURN_URL", "") or f"{public_base}/stripe/connect/return"

    try:
        link = stripe.AccountLink.create(
            account=acct_id,
            refresh_url=refresh_url,
            return_url=return_url,
            type="account_onboarding",
        )
    except stripe.error.StripeError as e:
        return Response({"detail": str(e)}, status=400)
    except Exception as e:
        return Response({"detail": f"server_error: {e.__class__.__name__}: {e}"}, status=500)

    return Response({"url": link.url, "expires_at": link.expires_at, "stripe_account_id": acct_id}, status=200)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def provider_stripe_login_link(request):
    """
    Creates an Express dashboard login link (useful so providers can manage payout details).
    """
    block = _require_provider_kyc_approved(request.user)
    if block:
        return Response(block, status=403)

    provider = ServiceProvider.objects.filter(user=request.user).first()
    if not provider:
        return Response({"detail": "You are not a provider."}, status=400)

    acct_id = (provider.stripe_account_id or "").strip()
    if not acct_id:
        return Response({"detail": "Provider has no Stripe connected account."}, status=400)

    stripe.api_key = settings.STRIPE_SECRET_KEY
    try:
        link = stripe.Account.create_login_link(acct_id)
    except stripe.error.StripeError as e:
        return Response({"detail": str(e)}, status=400)

    return Response({"url": link.url}, status=200)

@api_view(["GET"])
@permission_classes([AllowAny])
def stripe_connect_return(request):
    return HttpResponse("Stripe Connect: return OK. You can close this window.")

@api_view(["GET"])
@permission_classes([AllowAny])
def stripe_connect_refresh(request):
    return HttpResponse("Stripe Connect: refresh OK. Please return to the app and retry.")