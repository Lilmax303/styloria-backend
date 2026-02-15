# core/services/payouts.py

from __future__ import annotations

from decimal import Decimal
from django.conf import settings
from django.db import transaction
from django.utils import timezone
import stripe
import uuid

from core.models import (
    ServiceProvider,
    ServiceRequest,
    ProviderWallet,
    WalletLedgerEntry,
    Payout,
    ProviderPayoutSettings,
    Notification,
)
from core.utils.regions import is_african_country_name
from core.utils.paystack_countries import is_paystack_country, get_paystack_currency
from core.utils.currency import convert_amount as currency_convert_amount, get_currency_symbol
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer


ZERO_DECIMAL_CURRENCIES = {

"BIF","CLP","DJF","GNF","JPY","KMF","KRW","MGA","PYG","RWF","UGX","VND","VUV","XAF","XOF","XPF"
}

# At the top, add constants for tip maturation
TIP_COOLDOWN_HOURS = 48  # Tips mature in 48 hours (shorter than regular earnings)



def _to_minor_units(amount: Decimal, currency: str) -> int:
    c = (currency or "USD").upper().strip()
    amt = _q(amount)
    return int(amt) if c in ZERO_DECIMAL_CURRENCIES else int((amt * Decimal("100")).quantize(Decimal("1")))

def _q(amount: Decimal) -> Decimal:
    return Decimal(str(amount)).quantize(Decimal("0.01"))


def get_or_create_wallet(provider: ServiceProvider, currency: str) -> ProviderWallet:
    currency_u = (currency or "USD").upper().strip()
    wallet, _ = ProviderWallet.objects.get_or_create(provider=provider, currency=currency_u)
    return wallet


def compute_instant_fee(amount: Decimal) -> Decimal:
    rate = Decimal(str(getattr(settings, "INSTANT_PAYOUT_FEE_RATE", "0.05")))  # 5%
    min_fee = Decimal(str(getattr(settings, "INSTANT_PAYOUT_MIN_FEE", "0.50")))
    fee = _q(max(min_fee, _q(amount * rate)))
    if fee > amount:
        fee = amount
    return fee


def credit_provider_pending_from_request(sr: ServiceRequest, is_tip: bool = False) -> bool:    
    """
    Called when a booking becomes completed (confirmed by both).
    Creates a pending wallet credit entry and updates ServiceRequest.wallet_credited.

    CURRENCY CONVERSION: The booking stores amounts in the REQUESTER's currency.
    This function converts to the PROVIDER's preferred currency before crediting
    the wallet. Providers only ever see/receive their own currency.

    If is_tip=True, credits the tip_amount instead of provider earnings.
    Tips have a shorter maturation period (48 hours vs 7 days for earnings).
    """
    if not is_tip:
        if sr.wallet_credited:
            return True

    if sr.payment_status != "paid" or sr.status != "completed":
        return False

    if not sr.service_provider_id:
        return False

    provider = sr.service_provider

    # CRITICAL: booking currency is the REQUESTER's currency
    booking_currency = (sr.currency or "USD").upper().strip()

    # Provider's own currency (what their wallet should be in)
    provider_currency = (provider.user.preferred_currency or "USD").upper().strip()

    if is_tip:
        # Credit the tip amount
        amount = sr.tip_amount
        if amount is None or amount <= Decimal("0.00"):
            return True
        description_base = f"Tip for booking #{sr.id}"
        # Tips have shorter cooldown (48 hours)
        cooldown_hours = TIP_COOLDOWN_HOURS
    else:
        # Prefer net (provider share - stripe fee); fall back to provider_earnings_amount.
        amount = sr.provider_net_amount or sr.provider_earnings_amount
        if amount is None:
            return False
        description_base = f"Earning for booking #{sr.id}"
        # Regular earnings: 7 days
        cooldown_hours = int(getattr(settings, "PAYOUT_COOLDOWN_HOURS", 168))

    amount = _q(amount)
    if amount <= Decimal("0.00"):
        if not is_tip:
            sr.wallet_credited = True
            sr.wallet_credited_at = timezone.now()
            sr.save(update_fields=["wallet_credited", "wallet_credited_at"])
        return True

    # ═══════════════════════════════════════════════════════════════
    # CURRENCY CONVERSION: Convert from booking currency to provider currency
    # ═══════════════════════════════════════════════════════════════
    if booking_currency != provider_currency:
        try:
            converted = currency_convert_amount(float(amount), booking_currency, provider_currency)
            converted_amount = _q(Decimal(str(converted)))
            description = (
                f"{description_base} "
                f"(converted from {get_currency_symbol(booking_currency)}{amount} {booking_currency})"
            )
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(
                f"Currency conversion failed ({booking_currency}->{provider_currency}) "
                f"for booking #{sr.id}: {e}. Falling back to original amount."
            )
            converted_amount = amount
            description = f"{description_base} (conversion failed, original {booking_currency} amount)"
    else:
        converted_amount = amount
        description = description_base
    # ═══════════════════════════════════════════════════════════════

    # Use provider's currency for the wallet
    wallet_currency = provider_currency

    available_at = timezone.now() + timezone.timedelta(hours=cooldown_hours)

    wallet = get_or_create_wallet(provider, wallet_currency)

    with transaction.atomic():
        if not is_tip:
            # idempotency guard (double check inside txn)
            sr_locked = ServiceRequest.objects.select_for_update().get(pk=sr.pk)
            if sr_locked.wallet_credited:
                return True
        else:
            sr_locked = sr

        WalletLedgerEntry.objects.create(
            wallet=wallet,
            service_request=sr_locked,
            direction="credit",
            kind="earning",
            amount=converted_amount,
            status="pending",
            available_at=available_at,
            description=description,
        )

        wallet.pending_balance = _q(wallet.pending_balance + converted_amount)
        wallet.lifetime_earnings = _q(wallet.lifetime_earnings + converted_amount)
        wallet.save(update_fields=["pending_balance", "lifetime_earnings", "updated_at"])

        if not is_tip:
            sr_locked.wallet_credited = True
            sr_locked.wallet_credited_at = timezone.now()
            sr_locked.save(update_fields=["wallet_credited", "wallet_credited_at"])

    # Notify provider about tip credit (in their currency)
    if is_tip:
        symbol = get_currency_symbol(wallet_currency)
        _notify_provider_payout(
            provider=provider,
            message=(
                f"You received a tip of {symbol}{converted_amount} {wallet_currency} "
                f"for booking #{sr.id}! It will be available for cashout in 48 hours."
            ),
            notification_type="tip_received",
        )

    return True


# =============================================================================
# CANCELLATION FEE CREDITING
# =============================================================================

def credit_provider_cancellation_fee(sr: ServiceRequest, amount: Decimal) -> bool:
    """
    Credits provider's PENDING balance with their share of cancellation fee.
    Provider gets 80% of the cancellation penalty.

    CURRENCY CONVERSION: Converts from booking currency to provider's currency.
    """
    if not sr.service_provider_id:
        return False

    provider = sr.service_provider
    booking_currency = (sr.currency or "USD").upper().strip()
    provider_currency = (provider.user.preferred_currency or "USD").upper().strip()
    amount = _q(amount)

    if amount <= Decimal("0.00"):
        return True

    # Convert to provider's currency if different
    if booking_currency != provider_currency:
        try:
            converted = currency_convert_amount(float(amount), booking_currency, provider_currency)
            converted_amount = _q(Decimal(str(converted)))
            description = (
                f"Cancellation fee for booking #{sr.id} "
                f"(converted from {get_currency_symbol(booking_currency)}{amount} {booking_currency})"
            )
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(
                f"Currency conversion failed for cancellation fee booking #{sr.id}: {e}"
            )
            converted_amount = amount
            description = f"Cancellation fee for booking #{sr.id} (conversion failed)"
    else:
        converted_amount = amount
        description = f"Cancellation fee for booking #{sr.id}"

    wallet_currency = provider_currency

    # Same 7-day maturation as regular earnings
    cooldown_hours = int(getattr(settings, "PAYOUT_COOLDOWN_HOURS", 168))
    available_at = timezone.now() + timezone.timedelta(hours=cooldown_hours)

    wallet = get_or_create_wallet(provider, wallet_currency)

    with transaction.atomic():
        WalletLedgerEntry.objects.create(
            wallet=wallet,
            service_request=sr,
            direction="credit",
            kind="earning",
            amount=converted_amount,
            status="pending",
            available_at=available_at,
            description=description,
        )

        wallet.pending_balance = _q(wallet.pending_balance + converted_amount)
        wallet.lifetime_earnings = _q(wallet.lifetime_earnings + converted_amount)
        wallet.save(update_fields=["pending_balance", "lifetime_earnings", "updated_at"])

    return True


# =============================================================================
# PAYSTACK REFUND
# =============================================================================

def _refund_via_paystack(sr: ServiceRequest, amount: Decimal, currency: str) -> dict:
    """
    Creates a Paystack refund for the transaction.
    """
    from core.services.paystack import create_refund
    
    reference = (sr.paystack_reference or "").strip()
    if not reference:
        return {"success": False, "error": "No Paystack reference found for this booking"}
    
    result = create_refund(
        transaction_reference=reference,
        amount=amount,
        currency=currency,
        reason="Booking cancellation refund",
    )
    
    if result.get("success"):
        return {
            "success": True,
            "refund_id": str(result.get("refund_id") or ""),
            "status": result.get("status"),
            "amount": str(amount),
            "gateway": "paystack",
        }
    else:
        return {
            "success": False,
            "error": result.get("message") or "Refund failed",
            "gateway": "paystack",
        }



# =============================================================================
# REFUND PROCESSING
# =============================================================================

def process_cancellation_refund(sr: ServiceRequest, amount: Decimal) -> dict:
    """
    Processes refund to requester via the original payment gateway.
    Returns result dict with status and refund details.
    """
    amount = _q(amount)
    gateway = (sr.payment_gateway or "").strip().lower()
    currency_u = (sr.currency or "USD").upper().strip()

    if amount <= Decimal("0.00"):
        return {"success": True, "message": "No refund needed (amount is zero)"}

    if gateway == "stripe":
        return _refund_via_stripe(sr, amount, currency_u)
    elif gateway == "flutterwave":
        return _refund_via_flutterwave(sr, amount, currency_u)
    elif gateway == "paystack":
        return _refund_via_paystack(sr, amount, currency_u)
    else:
        return {"success": False, "error": f"Unknown payment gateway: {gateway}"}


def _refund_via_stripe(sr: ServiceRequest, amount: Decimal, currency: str) -> dict:
    """
    Creates a Stripe refund for the payment intent.
    Supports both full and partial refunds.
    """
    pi_id = (sr.stripe_payment_intent_id or "").strip()
    if not pi_id:
        return {"success": False, "error": "No Stripe payment intent found for this booking"}

    stripe.api_key = settings.STRIPE_SECRET_KEY
    amount_int = _to_minor_units(amount, currency)

    if amount_int <= 0:
        return {"success": False, "error": "Refund amount must be greater than zero"}

    try:
        refund = stripe.Refund.create(
            payment_intent=pi_id,
            amount=amount_int,
            metadata={
                "service_request_id": str(sr.id),
                "reason": "cancellation",
                "refund_type": "full" if amount == sr.offered_price else "partial",
            }
        )
        return {
            "success": True,
            "refund_id": refund.id,
            "status": refund.status,
            "amount": str(amount),
            "gateway": "stripe",
        }
    except stripe.error.StripeError as e:
        return {"success": False, "error": str(e), "gateway": "stripe"}


def _refund_via_flutterwave(sr: ServiceRequest, amount: Decimal, currency: str) -> dict:
    """
    Creates a Flutterwave refund for the transaction.
    Note: Flutterwave refunds can take time to process.
    """
    transaction_id = (sr.flutterwave_transaction_id or "").strip()
    if not transaction_id:
        return {"success": False, "error": "No Flutterwave transaction ID found for this booking"}

    try:
        import requests
    except Exception:
        return {"success": False, "error": "Server missing 'requests' dependency"}

    url = f"{_flutterwave_base_url()}/transactions/{transaction_id}/refund"
    payload = {"amount": float(amount)}

    try:
        r = requests.post(url, headers=_flutterwave_auth_headers(), json=payload, timeout=25)
        data = r.json() if r.content else {}

        if r.status_code >= 200 and r.status_code < 300:
            fw_data = data.get("data") or {}
            return {
                "success": True,
                "refund_id": str(fw_data.get("id") or ""),
                "status": fw_data.get("status", ""),
                "amount": str(amount),
                "gateway": "flutterwave",
                "raw": data,
            }
        else:
            error_message = data.get("message") or str(data)
            return {"success": False, "error": error_message, "gateway": "flutterwave", "raw": data}
    except Exception as e:
        return {"success": False, "error": str(e), "gateway": "flutterwave"}


def release_matured_pending_balances(now=None) -> int:
    now = now or timezone.now()
    matured = WalletLedgerEntry.objects.select_related("wallet").filter(
        status="pending",
        available_at__isnull=False,
        available_at__lte=now,
        direction="credit",
    )

    moved = 0
    with transaction.atomic():
        for entry in matured.select_for_update():
            wallet = entry.wallet
            amt = _q(entry.amount)

            # Move balance
            wallet.pending_balance = _q(wallet.pending_balance - amt)
            wallet.available_balance = _q(wallet.available_balance + amt)
            wallet.save(update_fields=["pending_balance", "available_balance", "updated_at"])

            entry.status = "available"
            entry.save(update_fields=["status"])

            moved += 1

    return moved


def _stripe_transfer_to_connected_account(provider: ServiceProvider, amount: Decimal, currency: str, metadata: dict) -> str:
    acct = (provider.stripe_account_id or "").strip()
    if not acct:
        raise ValueError("Provider has no stripe_account_id")

    stripe.api_key = settings.STRIPE_SECRET_KEY
    # Ensure account is actually payout-enabled (prevents “payouts not enabled” failures)
    a = stripe.Account.retrieve(acct)
    if not bool(a.get("payouts_enabled")):
        raise ValueError("Stripe account is not payout-enabled. Complete Stripe onboarding.")

    amount_int = _to_minor_units(amount, currency)
    if amount_int <= 0:
        raise ValueError("Transfer amount must be > 0")

    tr = stripe.Transfer.create(
        amount=amount_int,
        currency=(currency or "USD").lower(),
        destination=acct,
        metadata=metadata,
    )
    return tr.id


def payout_wallet(provider: ServiceProvider, currency: str, amount: Decimal, method: str = "weekly") -> Payout:
    """
    Executes a payout: creates Stripe Transfer, records Payout, debits wallet.
    """
    currency_u = (currency or "USD").upper().strip()
    amount = _q(amount)

    wallet = get_or_create_wallet(provider, currency_u)

    # Minimum is $5 USD, convert to wallet currency
    min_usd = Decimal("5.00")
    if currency_u == "USD":
        min_amount = min_usd
    else:
        try:
            from core.utils.currency import convert_amount
            converted = convert_amount(float(min_usd), "USD", currency_u)
            min_amount = Decimal(str(converted)).quantize(Decimal("0.01"))
        except Exception:
            min_amount = min_usd
    daily_max = Decimal(str(getattr(settings, "INSTANT_PAYOUT_DAILY_MAX", "500.00")))

    if method == "instant":
        if amount < min_amount:
            raise ValueError(f"Minimum instant payout is {min_amount} {currency_u}")
        if amount > daily_max:
            raise ValueError(f"Instant payout exceeds daily max ({daily_max} {currency_u})")

    with transaction.atomic():
        wallet = ProviderWallet.objects.select_for_update().get(pk=wallet.pk)

        if amount > wallet.available_balance:
            raise ValueError("Insufficient available balance")

        fee = Decimal("0.00")
        if method == "instant":
            fee = compute_instant_fee(amount)

        net = _q(amount - fee)

        payout = Payout.objects.create(
            provider=provider,
            currency=currency_u,
            gross_amount=amount,
            fee_amount=fee,
            net_amount=net,
            method=method,
            status="processing",
        )

        # Stripe transfer only for net amount
        transfer_id = _stripe_transfer_to_connected_account(
            provider=provider,
            amount=net,
            currency=currency_u,
            metadata={"payout_id": str(payout.id), "provider_id": str(provider.id), "method": method},
        )

        payout.stripe_transfer_id = transfer_id
        payout.status = "paid"
        payout.processed_at = timezone.now()
        payout.save(update_fields=["stripe_transfer_id", "status", "processed_at"])

        # Enhanced notification with more details
        if method == "instant":
            fee_msg = f" (5% fee: {fee} {currency_u})"
        else:
            fee_msg = ""
        
        _notify_provider_payout(
            provider=provider,
            message=f"💰 Cashout successful! Your payout of {net} {currency_u}{fee_msg} has been processed and sent to your connected account. It should arrive within 1-2 business days.",
            notification_type="payout_paid",
        )

        # Debit wallet: gross amount leaves available (fee is platform revenue)
        WalletLedgerEntry.objects.create(
            wallet=wallet,
            payout=payout,
            direction="debit",
            kind="payout",
            amount=amount,
            status="paid",
            description=f"{method.title()} payout #{payout.id}",
        )

        wallet.available_balance = _q(wallet.available_balance - amount)
        wallet.lifetime_payouts = _q(wallet.lifetime_payouts + amount)
        wallet.save(update_fields=["available_balance", "lifetime_payouts", "updated_at"])

    return payout

def _notify_provider_payout(*, provider: ServiceProvider, message: str, notification_type: str = "payout") -> None:
    """
    Creates an in-app notification and sends a websocket event to the provider.
    Idempotency should be ensured by calling this only on state transitions (e.g. processing->paid).
    """
    try:
        Notification.objects.create(user=provider.user, message=message)
    except Exception:
        pass

    try:
        channel_layer = get_channel_layer()
        ws_message = {"type": notification_type, "message": message}
        provider_room_group = f"notifications_{provider.user.id}"
        async_to_sync(channel_layer.group_send)(
            provider_room_group,
            {"type": "send_notification", "message": ws_message},
        )
    except Exception:
        pass

# =============================================================================
# PAYSTACK PAYOUTS (Ghana, Nigeria, South Africa, Kenya, Côte d'Ivoire)
# =============================================================================

def payout_wallet_paystack(
    provider: ServiceProvider,
    currency: str,
    amount: Decimal,
    method: str = "weekly"
) -> Payout:
    """
    Creates a Paystack transfer payout for providers in supported countries.
    
    Supported: Ghana (GHS), Nigeria (NGN), South Africa (ZAR), Kenya (KES), Côte d'Ivoire (XOF)
    """
    from core.services.paystack import (
        create_transfer_recipient,
        initiate_transfer,
        generate_reference,
    )
    
    currency_u = (currency or "NGN").upper().strip()
    amount = _q(amount)
    
    settings_obj, _ = ProviderPayoutSettings.objects.get_or_create(provider=provider)
    provider_country = (provider.user.country_name or "").strip() if getattr(provider, "user", None) else ""
    
    if not is_paystack_country(provider_country):
        raise ValueError(f"Paystack payouts are not available for {provider_country}. Use Flutterwave instead.")
    
    wallet = get_or_create_wallet(provider, currency_u)
    
    # Minimum is $5 USD equivalent
    min_usd = Decimal("5.00")
    if currency_u == "USD":
        min_amount = min_usd
    else:
        try:
            from core.utils.currency import convert_amount
            converted = convert_amount(float(min_usd), "USD", currency_u)
            min_amount = Decimal(str(converted)).quantize(Decimal("0.01"))
        except Exception:
            min_amount = min_usd
    
    daily_max = Decimal(str(getattr(settings, "INSTANT_PAYOUT_DAILY_MAX", "500.00")))
    
    if method == "instant":
        if amount < min_amount:
            raise ValueError(f"Minimum instant payout is {min_amount} {currency_u}")
        if amount > daily_max:
            raise ValueError(f"Instant payout exceeds daily max ({daily_max} {currency_u})")
    
    # Calculate fee
    fee = Decimal("0.00")
    if method == "instant":
        fee = compute_instant_fee(amount)
    net = _q(amount - fee)
    
    if net <= Decimal("0.00"):
        raise ValueError("Net payout amount must be > 0")
    
    # Get Paystack payout destination
    bank_code = (settings_obj.paystack_bank_code or "").strip()
    account_number = (settings_obj.paystack_account_number or "").strip()
    account_name = (settings_obj.paystack_account_name or "").strip()
    recipient_code = (settings_obj.paystack_recipient_code or "").strip()
    paystack_currency = (settings_obj.paystack_currency or currency_u).upper().strip()
    
    # Fallback to user's name if account_name not set
    if not account_name:
        user = provider.user
        account_name = f"{user.first_name} {user.last_name}".strip()
        if not account_name:
            account_name = user.username
    
    if not bank_code or not account_number:
        raise ValueError("Paystack payout settings incomplete. Please configure your bank account.")
    
    # 1) Reserve funds + create payout atomically
    with transaction.atomic():
        wallet = ProviderWallet.objects.select_for_update().get(pk=wallet.pk)
        
        if amount > wallet.available_balance:
            raise ValueError("Insufficient available balance")
        
        payout = Payout.objects.create(
            provider=provider,
            currency=currency_u,
            gross_amount=amount,
            fee_amount=fee,
            net_amount=net,
            method=method,
            status="processing",
        )
        
        # Generate unique reference
        reference = generate_reference(f"styloria_payout_{payout.id}")
        payout.paystack_reference = reference
        payout.save(update_fields=["paystack_reference"])
        
        WalletLedgerEntry.objects.create(
            wallet=wallet,
            payout=payout,
            direction="debit",
            kind="payout",
            amount=amount,
            status="paid",
            description=f"{method.title()} payout #{payout.id} (Paystack)",
        )
        
        # Debit wallet immediately
        wallet.available_balance = _q(wallet.available_balance - amount)
        wallet.save(update_fields=["available_balance", "updated_at"])
    
    # 2) Create or reuse transfer recipient
    try:
        if not recipient_code:
            # Create new recipient
            recipient_type = (settings_obj.paystack_recipient_type or "").strip()
            recipient_result = create_transfer_recipient(
                name=account_name,
                account_number=account_number,
                bank_code=bank_code,
                currency=paystack_currency,
                recipient_type=recipient_type or None,
                metadata={"provider_id": str(provider.id)},
            )
            
            if not recipient_result.get("success"):
                raise ValueError(f"Failed to create recipient: {recipient_result.get('message')}")
            
            recipient_code = recipient_result.get("recipient_code")
            
            # Save for future use
            settings_obj.paystack_recipient_code = recipient_code
            settings_obj.save(update_fields=["paystack_recipient_code"])
        
        # 3) Initiate transfer
        transfer_result = initiate_transfer(
            amount=net,
            recipient_code=recipient_code,
            currency=paystack_currency,
            reason=f"Styloria payout #{payout.id}",
            reference=reference,
        )
        
        if not transfer_result.get("success"):
            raise ValueError(f"Transfer failed: {transfer_result.get('message')}")
        
        # Update payout with transfer details
        Payout.objects.filter(pk=payout.pk).update(
            paystack_transfer_code=transfer_result.get("transfer_code") or "",
            paystack_transfer_id=str(transfer_result.get("transfer_id") or ""),
            paystack_recipient_code=recipient_code,
            paystack_status=transfer_result.get("status") or "pending",
        )
        
        # Paystack transfers can be instant or require OTP
        # Final status will come via webhook
        
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Paystack payout failed for provider {provider.id}: {e}")
        
        # Mark failed + refund wallet
        with transaction.atomic():
            payout_locked = Payout.objects.select_for_update().get(pk=payout.pk)
            wallet_locked = ProviderWallet.objects.select_for_update().get(provider=provider, currency=currency_u)
            
            payout_locked.status = "failed"
            payout_locked.failure_reason = str(e)
            payout_locked.processed_at = timezone.now()
            payout_locked.save(update_fields=["status", "failure_reason", "processed_at"])
            
            # Mark ledger reversed and refund
            WalletLedgerEntry.objects.filter(payout=payout_locked, kind="payout", direction="debit").update(status="reversed")
            already_refunded = WalletLedgerEntry.objects.filter(payout=payout_locked, kind="refund").exists()
            
            if not already_refunded:
                WalletLedgerEntry.objects.create(
                    wallet=wallet_locked,
                    payout=payout_locked,
                    direction="credit",
                    kind="refund",
                    amount=amount,
                    status="available",
                    description=f"Refund for failed payout #{payout_locked.id}",
                )
                wallet_locked.available_balance = _q(wallet_locked.available_balance + amount)
                wallet_locked.save(update_fields=["available_balance", "updated_at"])
        
        return Payout.objects.get(pk=payout.pk)
    
    return Payout.objects.get(pk=payout.pk)


def finalize_paystack_payout_from_webhook(
    *,
    reference: str,
    transfer_code: str = "",
    status: str = "",
) -> None:
    """
    Finalize Paystack payout based on webhook event.
    
    Paystack transfer statuses:
    - success: Transfer completed
    - failed: Transfer failed
    - reversed: Transfer reversed
    - pending: Still processing
    """
    reference = (reference or "").strip()
    if not reference:
        return
    
    payout = Payout.objects.filter(paystack_reference=reference).select_related("provider").first()
    if not payout:
        return
    
    new_status = (status or "").strip().lower()
    transfer_code = (transfer_code or "").strip()
    
    with transaction.atomic():
        payout_locked = Payout.objects.select_for_update().get(pk=payout.pk)
        
        # If already terminal, just update tracking fields
        if payout_locked.status in ("paid", "failed"):
            updates = []
            if transfer_code and not payout_locked.paystack_transfer_code:
                payout_locked.paystack_transfer_code = transfer_code
                updates.append("paystack_transfer_code")
            if new_status and payout_locked.paystack_status != new_status:
                payout_locked.paystack_status = new_status
                updates.append("paystack_status")
            if updates:
                payout_locked.save(update_fields=updates)
            return
        
        if transfer_code and not payout_locked.paystack_transfer_code:
            payout_locked.paystack_transfer_code = transfer_code
        if new_status:
            payout_locked.paystack_status = new_status
        
        provider = payout_locked.provider
        currency_u = (payout_locked.currency or "NGN").upper().strip()
        wallet = ProviderWallet.objects.select_for_update().get(provider=provider, currency=currency_u)
        
        debit_qs = WalletLedgerEntry.objects.filter(payout=payout_locked, kind="payout", direction="debit")
        
        if new_status == "success":
            payout_locked.status = "paid"
            payout_locked.processed_at = timezone.now()
            payout_locked.save(update_fields=["paystack_transfer_code", "paystack_status", "status", "processed_at"])
            debit_qs.update(status="paid")
            
            wallet.lifetime_payouts = _q(wallet.lifetime_payouts + _q(payout_locked.gross_amount))
            wallet.save(update_fields=["lifetime_payouts", "updated_at"])
            
            # Notify success
            method = payout_locked.method or "scheduled"
            fee_msg = f" (5% fee: {payout_locked.fee_amount} {currency_u})" if method == "instant" else ""
            
            _notify_provider_payout(
                provider=provider,
                message=f"💰 Cashout successful! Your payout of {payout_locked.net_amount} {currency_u}{fee_msg} has been processed via Paystack.",
                notification_type="payout_paid",
            )
            return
        
        if new_status in ("failed", "reversed"):
            payout_locked.status = "failed"
            payout_locked.failure_reason = f"paystack_{new_status}"
            payout_locked.processed_at = timezone.now()
            payout_locked.save(update_fields=["paystack_transfer_code", "paystack_status", "status", "failure_reason", "processed_at"])
            debit_qs.update(status="reversed")
            
            # Refund wallet
            already_refunded = WalletLedgerEntry.objects.filter(payout=payout_locked, kind="refund").exists()
            if not already_refunded:
                amt = _q(payout_locked.gross_amount)
                WalletLedgerEntry.objects.create(
                    wallet=wallet,
                    payout=payout_locked,
                    direction="credit",
                    kind="refund",
                    amount=amt,
                    status="available",
                    description=f"Refund for failed payout #{payout_locked.id}",
                )
                wallet.available_balance = _q(wallet.available_balance + amt)
                wallet.save(update_fields=["available_balance", "updated_at"])
            
            # Notify failure
            _notify_provider_payout(
                provider=provider,
                message=f"⚠️ Payout failed: Your cashout of {payout_locked.gross_amount} {currency_u} could not be processed. The amount has been returned to your available balance.",
                notification_type="payout_failed",
            )
            return



# ============================================================
# Flutterwave payouts (Africa)
# ============================================================

def _flutterwave_base_url() -> str:
    return "https://api.flutterwave.com/v3"


def _flutterwave_auth_headers() -> dict:
    return {
        "Authorization": f"Bearer {getattr(settings, 'FLUTTERWAVE_SECRET_KEY', '')}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _flutterwave_create_transfer(*, amount: Decimal, currency: str, reference: str, narration: str,
                                 bank_code: str = "", account_number: str = "",
                                 phone_number: str = "", mobile_network: str = "",  # ADD THIS
                                 beneficiary_id: str = "", beneficiary_name: str = "") -> dict:
    """
    Minimal Flutterwave transfer creation.
    Transfer fields vary by country and corridor; expand as you add supported corridors.
    """
    try:
        import requests  # type: ignore
    except Exception:
        raise ValueError("Server missing 'requests' dependency.")

    payload: dict = {
        "amount": float(_q(amount)),
        "currency": (currency or "USD").upper().strip(),
        "reference": reference,
        "narration": narration,
    }

    # Beneficiary name is required for most corridors
    if beneficiary_name:
        payload["beneficiary_name"] = beneficiary_name

    if beneficiary_id:
        payload["beneficiary"] = beneficiary_id
    elif bank_code and account_number:
        # Bank transfer
        payload["account_bank"] = bank_code
        payload["account_number"] = account_number
    elif phone_number:
        # Mobile Money transfer
        payload["account_number"] = phone_number
        # For MoMo, account_bank must be the network code (MTN, VODAFONE, etc.)
        if mobile_network:
            payload["account_bank"] = mobile_network.upper()
        else:
            raise ValueError("Mobile money network is required for MoMo transfers. Please update your payout settings.")
    else:
        raise ValueError("Flutterwave payout destination not configured.")

    url = f"{_flutterwave_base_url()}/transfers"
    r = requests.post(url, headers=_flutterwave_auth_headers(), json=payload, timeout=25)
    data = r.json() if r.content else {}
    if r.status_code < 200 or r.status_code >= 300:
        raise ValueError(f"Flutterwave transfer failed: {data}")

    return data

def payout_wallet_flutterwave(provider: ServiceProvider, currency: str, amount: Decimal, method: str = "weekly") -> Payout:
    """
    Creates a Flutterwave transfer payout.
    Wallet debit happens immediately with status=processing.
    Final status (paid/failed) should be set by webhook calling `finalize_flutterwave_payout_from_webhook`.
    """
    currency_u = (currency or "USD").upper().strip()
    amount = _q(amount)

    settings_obj, _ = ProviderPayoutSettings.objects.get_or_create(provider=provider)
    provider_country = (provider.user.country_name or "").strip() if getattr(provider, "user", None) else ""
    if not is_african_country_name(provider_country):
        raise ValueError("Flutterwave payouts are only enabled for Africa providers.")
    # STRICT: Africa providers always use Flutterwave. No payout_gateway gating here.

    wallet = get_or_create_wallet(provider, currency_u)

    # Minimum is $5 USD, convert to wallet currency
    min_usd = Decimal("5.00")
    if currency_u == "USD":
        min_amount = min_usd
    else:
        try:
            from core.utils.currency import convert_amount
            converted = convert_amount(float(min_usd), "USD", currency_u)
            min_amount = Decimal(str(converted)).quantize(Decimal("0.01"))
        except Exception:
            min_amount = min_usd

    daily_max = Decimal(str(getattr(settings, "INSTANT_PAYOUT_DAILY_MAX", "500.00")))
    if method == "instant":
        if amount < min_amount:
            raise ValueError(f"Minimum instant payout is {min_amount} {currency_u}")
        if amount > daily_max:
            raise ValueError(f"Instant payout exceeds daily max ({daily_max} {currency_u})")

    # fees (same policy as Stripe path): fee is platform revenue, provider receives net
    fee = Decimal("0.00")
    if method == "instant":
        fee = compute_instant_fee(amount)
    net = _q(amount - fee)
    if net <= Decimal("0.00"):
        raise ValueError("Net payout amount must be > 0")

    # Destination data
    fw_currency = (settings_obj.flutterwave_currency or currency_u).upper().strip()
    bank_code = (settings_obj.flutterwave_bank_code or "").strip()
    acct_no = (settings_obj.flutterwave_account_number or "").strip()
    phone = (settings_obj.flutterwave_phone_number or "").strip()
    dial_code = (getattr(settings_obj, "flutterwave_country_code", "") or "").strip()
    beneficiary_id = (settings_obj.flutterwave_beneficiary_id or "").strip()
    mobile_network = (settings_obj.flutterwave_mobile_network or "").strip()
    beneficiary_name = (settings_obj.flutterwave_full_name or "").strip()
   
    # Fallback to user's name if beneficiary_name not set
    if not beneficiary_name:
        user = provider.user
        beneficiary_name = f"{user.first_name} {user.last_name}".strip()
        if not beneficiary_name:
            beneficiary_name = user.username

    # 1) Reserve funds + create payout + ledger entry atomically
    with transaction.atomic():
        wallet = ProviderWallet.objects.select_for_update().get(pk=wallet.pk)
        if amount > wallet.available_balance:
            raise ValueError("Insufficient available balance")

        payout = Payout.objects.create(
            provider=provider,
            currency=currency_u,
            gross_amount=amount,
            fee_amount=fee,
            net_amount=net,
            method=method,
            status="processing",
        )

        # Stable unique reference for Flutterwave (used to match webhook)
        reference = f"styloria_payout_{payout.id}_{uuid.uuid4().hex[:10]}"
        payout.flutterwave_reference = reference
        payout.save(update_fields=["flutterwave_reference"])

        WalletLedgerEntry.objects.create(
            wallet=wallet,
            payout=payout,
            direction="debit",
            kind="payout",
            amount=amount,
            status="paid",
            description=f"{method.title()} payout #{payout.id} (Flutterwave)",
        )

        # remove from available immediately (prevents double-withdraw)
        wallet.available_balance = _q(wallet.available_balance - amount)
        wallet.save(update_fields=["available_balance", "updated_at"])

    # 2) Call Flutterwave outside the DB transaction
    try:
        momo_msisdn = _build_momo_msisdn(dial_code=dial_code, phone=phone)
        res = _flutterwave_create_transfer(
            amount=net,
            currency=fw_currency,
            reference=reference,
            narration=f"Styloria payout #{payout.id}",
            bank_code=bank_code,
            account_number=acct_no,
            phone_number=momo_msisdn,
            mobile_network=mobile_network,  # ADD THIS
            beneficiary_id=beneficiary_id,
            beneficiary_name=beneficiary_name,
        )
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Flutterwave payout failed for provider {provider.id}: {e}")

        # Mark failed + refund wallet
        with transaction.atomic():
            payout_locked = Payout.objects.select_for_update().get(pk=payout.pk)
            wallet_locked = ProviderWallet.objects.select_for_update().get(provider=provider, currency=currency_u)

            payout_locked.status = "failed"
            payout_locked.failure_reason = str(e)
            payout_locked.processed_at = timezone.now()
            payout_locked.save(update_fields=["status", "failure_reason", "processed_at"])

            # mark ledger failed, refund wallet once
            WalletLedgerEntry.objects.filter(payout=payout_locked, kind="payout", direction="debit").update(status="reversed")
            already_refunded = WalletLedgerEntry.objects.filter(payout=payout_locked, kind="refund").exists()
            if not already_refunded:
                WalletLedgerEntry.objects.create(
                    wallet=wallet_locked,
                    payout=payout_locked,
                    direction="credit",
                    kind="refund",
                    amount=amount,
                    status="available",
                    description=f"Refund for failed payout #{payout_locked.id}",
                )
                wallet_locked.available_balance = _q(wallet_locked.available_balance + amount)
                wallet_locked.save(update_fields=["available_balance", "updated_at"])

        return Payout.objects.get(pk=payout.pk)

    # Save transfer id/status (final paid/failed should come from webhook)
    fw_data = (res or {}).get("data") or {}
    transfer_id = str(fw_data.get("id") or "").strip()
    fw_status = str(fw_data.get("status") or "").strip().lower()

    Payout.objects.filter(pk=payout.pk).update(
        flutterwave_transfer_id=transfer_id,
        flutterwave_status=fw_status,
    )

    return Payout.objects.get(pk=payout.pk)


def finalize_flutterwave_payout_from_webhook(*, reference: str, transfer_id: str = "", status: str = "") -> None:
    """
    Idempotent reconciliation:
    - success => mark payout paid, mark ledger paid, add lifetime_payouts
    - failure => mark payout failed, mark ledger failed, refund wallet if not already refunded
    """
    reference = (reference or "").strip()
    if not reference:
        return

    payout = Payout.objects.filter(flutterwave_reference=reference).select_related("provider").first()
    if not payout:
        return

    new_status = (status or "").strip().lower()
    transfer_id = (transfer_id or "").strip()

    with transaction.atomic():
        payout_locked = Payout.objects.select_for_update().get(pk=payout.pk)

        # If already terminal, just fill missing ids/status and exit
        if payout_locked.status in ("paid", "failed"):
            updates = []
            if transfer_id and not payout_locked.flutterwave_transfer_id:
                payout_locked.flutterwave_transfer_id = transfer_id
                updates.append("flutterwave_transfer_id")
            if new_status and payout_locked.flutterwave_status != new_status:
                payout_locked.flutterwave_status = new_status
                updates.append("flutterwave_status")
            if updates:
                payout_locked.save(update_fields=updates)
            return

        if transfer_id and not payout_locked.flutterwave_transfer_id:
            payout_locked.flutterwave_transfer_id = transfer_id
        if new_status:
            payout_locked.flutterwave_status = new_status

        provider = payout_locked.provider
        currency_u = (payout_locked.currency or "USD").upper().strip()
        wallet = ProviderWallet.objects.select_for_update().get(provider=provider, currency=currency_u)

        debit_qs = WalletLedgerEntry.objects.filter(payout=payout_locked, kind="payout", direction="debit")

        if new_status in ("successful", "completed"):
            payout_locked.status = "paid"
            payout_locked.processed_at = timezone.now()
            payout_locked.save(update_fields=["flutterwave_transfer_id", "flutterwave_status", "status", "processed_at"])
            debit_qs.update(status="paid")

            # lifetime_payouts counts actual successful cash-outs
            wallet.lifetime_payouts = _q(wallet.lifetime_payouts + _q(payout_locked.gross_amount))
            wallet.save(update_fields=["lifetime_payouts", "updated_at"])

            # Enhanced notification for successful payout
            method = payout_locked.method or "scheduled"
            if method == "instant":
                fee_msg = f" (5% fee: {payout_locked.fee_amount} {currency_u})"
            else:
                fee_msg = ""


            _notify_provider_payout(
                provider=provider,
                message=f"💰 Cashout successful! Your payout of {payout_locked.net_amount} {currency_u}{fee_msg} has been processed and sent to your account. Please allow 1-3 business days for the funds to reflect.",
                notification_type="payout_paid",
            )
            return

        if new_status in ("failed", "cancelled", "reversed"):
            payout_locked.status = "failed"
            payout_locked.failure_reason = f"flutterwave_{new_status}"
            payout_locked.processed_at = timezone.now()
            payout_locked.save(update_fields=["flutterwave_transfer_id", "flutterwave_status", "status", "failure_reason", "processed_at"])
            debit_qs.update(status="reversed")

            already_refunded = WalletLedgerEntry.objects.filter(payout=payout_locked, kind="refund").exists()
            if not already_refunded:
                amt = _q(payout_locked.gross_amount)
                WalletLedgerEntry.objects.create(
                    wallet=wallet,
                    payout=payout_locked,
                    direction="credit",
                    kind="refund",
                    amount=amt,
                    status="available",
                    description=f"Refund for failed payout #{payout_locked.id}",
                )
                wallet.available_balance = _q(wallet.available_balance + amt)
                wallet.save(update_fields=["available_balance", "updated_at"])

            # Notify provider about failed payout
            _notify_provider_payout(
                provider=provider,
                message=f"⚠️ Payout failed: Your cashout of {payout_locked.gross_amount} {currency_u} could not be processed. The amount has been returned to your available balance. Please check your payout settings and try again.",
                notification_type="payout_failed",
            )

            return


def payout_wallet_routed(provider: ServiceProvider, currency: str, amount: Decimal, method: str = "weekly") -> Payout:
    """
    Single entry point for payouts.
    - If provider is in Paystack country (Ghana, Nigeria, South Africa, Kenya, Côte d'Ivoire) => Paystack transfer
    - If provider is in other African country + payout_gateway=flutterwave => Flutterwave transfer
    - else => Stripe transfer (existing payout_wallet)
    """
    settings_obj, _ = ProviderPayoutSettings.objects.get_or_create(provider=provider)
    provider_country = (provider.user.country_name or "").strip() if getattr(provider, "user", None) else ""

    # Priority 1: Paystack countries always use Paystack
    if is_paystack_country(provider_country):
        return payout_wallet_paystack(provider=provider, currency=currency, amount=amount, method=method)
    
    # Priority 2: Other African countries use Flutterwave
    if is_african_country_name(provider_country) and settings_obj.payout_gateway in ("flutterwave", "paystack"):
        return payout_wallet_flutterwave(provider=provider, currency=currency, amount=amount, method=method)

    # Priority 3: Rest of world uses Stripe
    return payout_wallet(provider=provider, currency=currency, amount=amount, method=method)


# ============================================================
# Auto payouts + helpers
# ============================================================

def _digits_only(s: str) -> str:
    return "".join(ch for ch in (s or "") if ch.isdigit())


def _build_momo_msisdn(*, dial_code: str, phone: str) -> str:
    """
    Build Flutterwave-friendly MSISDN for MoMo payouts.
    - UI currently stores dial code separately (e.g. +233) and local phone (e.g. 054xxxxxxx).
    - Flutterwave generally expects digits-only with country code (e.g. 23354xxxxxxx).
    This function also tolerates the case where `phone` is already full (+233...).
    """
    p = (phone or "").strip()
    d = (dial_code or "").strip()
    if not p:
        return ""

    # If user already stored +233... or 233..., just normalize to digits
    if p.startswith("+") or (p and p[0].isdigit() and len(_digits_only(p)) >= 10 and d == ""):
        return _digits_only(p)

    # dial code like "+233" -> "233"
    cc = _digits_only(d)
    local = _digits_only(p)

    # drop leading 0 in local format: 054xxxxxxx -> 54xxxxxxx
    if local.startswith("0"):
        local = local[1:]

    return f"{cc}{local}" if cc else local


def run_scheduled_auto_payouts(now=None) -> dict:
    """
    Intended to be run by cron/Celery beat (e.g. hourly).

    Steps:
      1) release matured pending balances -> moves pending->available
      2) if provider auto_payout_enabled and schedule matches (weekday+hour UTC),
         then payout each wallet currency if available_balance >= minimum_payout_amount

    Returns simple stats for logging/monitoring.
    """
    now = now or timezone.now()
    stats = {"released": 0, "attempted": 0, "paid": 0, "failed": 0}

    stats["released"] = release_matured_pending_balances(now=now)

    due_settings = ProviderPayoutSettings.objects.select_related("provider").filter(
        auto_payout_enabled=True,
    )

    for s in due_settings:
        # Only run at provider's configured weekly time (UTC)
        weekday = int(getattr(s, "payout_weekday", 0) or 0)
        hour_utc = int(getattr(s, "payout_hour_utc", 2) or 2)
        if now.weekday() != weekday or now.hour != hour_utc:
            continue

        provider = s.provider
        min_amt = Decimal(str(getattr(s, "minimum_payout_amount", "0.00") or "0.00"))

        wallets = ProviderWallet.objects.filter(provider=provider)
        for w in wallets:
            amt = _q(w.available_balance)
            if amt <= Decimal("0.00") or amt < min_amt:
                continue

            stats["attempted"] += 1
            try:
                p = payout_wallet_routed(provider=provider, currency=w.currency, amount=amt, method="weekly")
                if p.status == "failed":
                    stats["failed"] += 1
                else:
                    # For Flutterwave this will often be "processing" until webhook; count as paid attempt.
                    stats["paid"] += 1
            except Exception:
                stats["failed"] += 1

    return stats