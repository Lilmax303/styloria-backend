# core/services/paystack.py

"""
Paystack payment and payout service for African countries:
Ghana, Nigeria, South Africa, Kenya, Côte d'Ivoire
"""

from __future__ import annotations

import uuid
import requests
import logging
from decimal import Decimal
from typing import Optional, Dict, Any, List

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


class PaystackError(Exception):
    """Custom exception for Paystack errors"""
    pass


def _paystack_base_url() -> str:
    """Paystack API base URL"""
    return "https://api.paystack.co"


def _paystack_auth_headers() -> Dict[str, str]:
    """Get authorization headers for Paystack API"""
    secret_key = getattr(settings, "PAYSTACK_SECRET_KEY", "")
    return {
        "Authorization": f"Bearer {secret_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _to_kobo(amount: Decimal, currency: str) -> int:
    """
    Convert amount to smallest currency unit.
    Paystack expects amounts in kobo (NGN), pesewas (GHS), cents (ZAR/KES), etc.
    """
    # All Paystack-supported currencies use 100 subunits
    return int((Decimal(str(amount)) * Decimal("100")).quantize(Decimal("1")))


def _from_kobo(amount: int, currency: str) -> Decimal:
    """Convert from smallest unit back to main currency."""
    return (Decimal(str(amount)) / Decimal("100")).quantize(Decimal("0.01"))


def generate_reference(prefix: str = "styloria") -> str:
    """Generate unique transaction reference"""
    timestamp = int(timezone.now().timestamp())
    unique_id = uuid.uuid4().hex[:12]
    return f"{prefix}_{timestamp}_{unique_id}"


# =============================================================================
# PAYMENT INITIALIZATION & VERIFICATION
# =============================================================================

def initialize_transaction(
    email: str,
    amount: Decimal,
    currency: str,
    reference: str,
    callback_url: str | None = None,
    metadata: Dict[str, Any] | None = None,
    channels: List[str] | None = None,
) -> Dict[str, Any]:
    """
    Initialize a Paystack transaction.
    
    Args:
        email: Customer's email address
        amount: Amount in main currency units (e.g., 100.00 GHS)
        currency: Currency code (GHS, NGN, ZAR, KES, XOF)
        reference: Unique transaction reference
        callback_url: URL to redirect after payment
        metadata: Additional data to attach to transaction
        channels: Payment channels to allow (card, bank, mobile_money, etc.)
    
    Returns:
        {
            'success': bool,
            'authorization_url': str,  # URL to redirect user for payment
            'access_code': str,
            'reference': str,
            'message': str,
            'raw': dict
        }
    """
    url = f"{_paystack_base_url()}/transaction/initialize"
    
    amount_kobo = _to_kobo(amount, currency)
    
    payload = {
        "email": email,
        "amount": amount_kobo,
        "currency": currency.upper(),
        "reference": reference,
    }
    
    if callback_url:
        payload["callback_url"] = callback_url
    
    if metadata:
        payload["metadata"] = metadata
    
    if channels:
        payload["channels"] = channels
    
    try:
        response = requests.post(
            url,
            headers=_paystack_auth_headers(),
            json=payload,
            timeout=30
        )
        data = response.json() if response.content else {}
        
        logger.info(f"Paystack initialize response: {data}")
        
        if response.status_code == 200 and data.get("status") is True:
            tx_data = data.get("data", {})
            return {
                "success": True,
                "authorization_url": tx_data.get("authorization_url"),
                "access_code": tx_data.get("access_code"),
                "reference": tx_data.get("reference") or reference,
                "message": data.get("message", "Transaction initialized"),
                "raw": data,
            }
        else:
            error_msg = data.get("message") or str(data)
            logger.error(f"Paystack initialize failed: {error_msg}")
            return {
                "success": False,
                "authorization_url": None,
                "access_code": None,
                "reference": reference,
                "message": error_msg,
                "raw": data,
            }
    
    except requests.exceptions.Timeout:
        logger.error("Paystack initialize timeout")
        return {
            "success": False,
            "authorization_url": None,
            "access_code": None,
            "reference": reference,
            "message": "Request timed out",
            "raw": {},
        }
    except Exception as e:
        logger.error(f"Paystack initialize error: {e}")
        return {
            "success": False,
            "authorization_url": None,
            "access_code": None,
            "reference": reference,
            "message": str(e),
            "raw": {},
        }


def verify_transaction(reference: str) -> Dict[str, Any]:
    """
    Verify a Paystack transaction by reference.
    
    Returns:
        {
            'success': bool,
            'status': str,  # 'success', 'failed', 'abandoned', etc.
            'amount': Decimal,  # Amount in main currency
            'currency': str,
            'reference': str,
            'transaction_id': int,
            'paid_at': str,
            'channel': str,
            'fees': Decimal,
            'message': str,
            'raw': dict
        }
    """
    url = f"{_paystack_base_url()}/transaction/verify/{reference}"
    
    try:
        response = requests.get(
            url,
            headers=_paystack_auth_headers(),
            timeout=30
        )
        data = response.json() if response.content else {}
        
        logger.info(f"Paystack verify response for {reference}: status={response.status_code}")
        
        if response.status_code == 200 and data.get("status") is True:
            tx_data = data.get("data", {})
            tx_status = (tx_data.get("status") or "").lower()
            currency = (tx_data.get("currency") or "NGN").upper()
            amount_kobo = int(tx_data.get("amount") or 0)
            fees_kobo = int(tx_data.get("fees") or 0)
            
            return {
                "success": tx_status == "success",
                "status": tx_status,
                "amount": _from_kobo(amount_kobo, currency),
                "currency": currency,
                "reference": tx_data.get("reference") or reference,
                "transaction_id": tx_data.get("id"),
                "paid_at": tx_data.get("paid_at"),
                "channel": tx_data.get("channel"),
                "fees": _from_kobo(fees_kobo, currency),
                "customer_email": tx_data.get("customer", {}).get("email"),
                "message": data.get("message", ""),
                "raw": data,
            }
        else:
            error_msg = data.get("message") or "Verification failed"
            return {
                "success": False,
                "status": "failed",
                "amount": Decimal("0.00"),
                "currency": "",
                "reference": reference,
                "transaction_id": None,
                "paid_at": None,
                "channel": None,
                "fees": Decimal("0.00"),
                "message": error_msg,
                "raw": data,
            }
    
    except Exception as e:
        logger.error(f"Paystack verify error for {reference}: {e}")
        return {
            "success": False,
            "status": "error",
            "amount": Decimal("0.00"),
            "currency": "",
            "reference": reference,
            "transaction_id": None,
            "paid_at": None,
            "channel": None,
            "fees": Decimal("0.00"),
            "message": str(e),
            "raw": {},
        }


# =============================================================================
# REFUNDS
# =============================================================================

def create_refund(
    transaction_reference: str,
    amount: Decimal | None = None,
    currency: str = "NGN",
    reason: str = "Customer requested refund",
) -> Dict[str, Any]:
    """
    Create a refund for a Paystack transaction.
    
    Args:
        transaction_reference: Original transaction reference
        amount: Amount to refund (None for full refund)
        currency: Currency for amount conversion
        reason: Reason for refund
    
    Returns:
        {
            'success': bool,
            'refund_id': int,
            'status': str,
            'amount': Decimal,
            'message': str,
            'raw': dict
        }
    """
    url = f"{_paystack_base_url()}/refund"
    
    payload = {
        "transaction": transaction_reference,
        "merchant_note": reason,
    }
    
    if amount is not None:
        payload["amount"] = _to_kobo(amount, currency)
    
    try:
        response = requests.post(
            url,
            headers=_paystack_auth_headers(),
            json=payload,
            timeout=30
        )
        data = response.json() if response.content else {}
        
        if response.status_code == 200 and data.get("status") is True:
            refund_data = data.get("data", {})
            refund_amount = int(refund_data.get("amount") or 0)
            return {
                "success": True,
                "refund_id": refund_data.get("id"),
                "status": refund_data.get("status"),
                "amount": _from_kobo(refund_amount, currency),
                "message": data.get("message", "Refund initiated"),
                "raw": data,
            }
        else:
            return {
                "success": False,
                "refund_id": None,
                "status": "failed",
                "amount": Decimal("0.00"),
                "message": data.get("message") or "Refund failed",
                "raw": data,
            }
    
    except Exception as e:
        logger.error(f"Paystack refund error: {e}")
        return {
            "success": False,
            "refund_id": None,
            "status": "error",
            "amount": Decimal("0.00"),
            "message": str(e),
            "raw": {},
        }


# =============================================================================
# BANKS & ACCOUNT RESOLUTION
# =============================================================================

def list_banks(country: str = "nigeria", currency: str = "NGN") -> Dict[str, Any]:
    """
    Get list of banks for a country.
    
    Args:
        country: Country name or code (nigeria, ghana, south-africa, kenya)
        currency: Currency code
    
    Returns:
        {
            'success': bool,
            'banks': [{'name': str, 'code': str, 'type': str}, ...],
            'message': str
        }
    """
    # Map country names to Paystack's expected format
    country_map = {
        "ghana": "ghana",
        "gh": "ghana",
        "ghs": "ghana",
        "nigeria": "nigeria",
        "ng": "nigeria",
        "ngn": "nigeria",
        "south africa": "south-africa",
        "south-africa": "south-africa",
        "za": "south-africa",
        "zar": "south-africa",
        "kenya": "kenya",
        "ke": "kenya",
        "kes": "kenya",
        "côte d'ivoire": "cote-divoire",
        "cote d'ivoire": "cote-divoire",
        "ivory coast": "cote-divoire",
        "ci": "cote-divoire",
        "xof": "cote-divoire",
    }
    
    country_param = country_map.get(country.lower().strip(), "nigeria")
    
    url = f"{_paystack_base_url()}/bank"
    params = {"country": country_param, "perPage": 100}
    
    try:
        response = requests.get(
            url,
            headers=_paystack_auth_headers(),
            params=params,
            timeout=30
        )
        data = response.json() if response.content else {}
        
        if response.status_code == 200 and data.get("status") is True:
            banks_data = data.get("data", [])
            banks = [
                {
                    "name": b.get("name"),
                    "code": b.get("code"),
                    "type": b.get("type"),
                    "currency": b.get("currency"),
                    "country": b.get("country"),
                }
                for b in banks_data
            ]
            return {
                "success": True,
                "banks": banks,
                "message": f"Found {len(banks)} banks",
            }
        else:
            return {
                "success": False,
                "banks": [],
                "message": data.get("message") or "Failed to fetch banks",
            }
    
    except Exception as e:
        logger.error(f"Paystack list banks error: {e}")
        return {
            "success": False,
            "banks": [],
            "message": str(e),
        }


def resolve_account(
    account_number: str,
    bank_code: str,
) -> Dict[str, Any]:
    """
    Resolve/verify a bank account number to get the account name.
    
    Returns:
        {
            'success': bool,
            'account_name': str,
            'account_number': str,
            'bank_id': int,
            'message': str
        }
    """
    url = f"{_paystack_base_url()}/bank/resolve"
    params = {
        "account_number": account_number,
        "bank_code": bank_code,
    }
    
    try:
        response = requests.get(
            url,
            headers=_paystack_auth_headers(),
            params=params,
            timeout=30
        )
        data = response.json() if response.content else {}
        
        if response.status_code == 200 and data.get("status") is True:
            acct_data = data.get("data", {})
            return {
                "success": True,
                "account_name": acct_data.get("account_name"),
                "account_number": acct_data.get("account_number") or account_number,
                "bank_id": acct_data.get("bank_id"),
                "message": "Account resolved successfully",
            }
        else:
            return {
                "success": False,
                "account_name": None,
                "account_number": account_number,
                "bank_id": None,
                "message": data.get("message") or "Could not resolve account",
            }
    
    except Exception as e:
        logger.error(f"Paystack resolve account error: {e}")
        return {
            "success": False,
            "account_name": None,
            "account_number": account_number,
            "bank_id": None,
            "message": str(e),
        }


# =============================================================================
# TRANSFERS (PAYOUTS)
# =============================================================================

def create_transfer_recipient(
    name: str,
    account_number: str,
    bank_code: str,
    currency: str = "NGN",
    recipient_type: str = "nuban",
    metadata: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Create a transfer recipient for payouts.
    
    Args:
        name: Recipient's name (as on bank account)
        account_number: Bank account number
        bank_code: Bank code from list_banks
        currency: Currency (NGN, GHS, ZAR, KES)
        recipient_type: Type of recipient ('nuban' for Nigeria, 'mobile_money' for Ghana, etc.)
        metadata: Additional data
    
    Returns:
        {
            'success': bool,
            'recipient_code': str,  # Use this for transfers
            'recipient_id': int,
            'name': str,
            'message': str,
            'raw': dict
        }
    """
    url = f"{_paystack_base_url()}/transferrecipient"
    
    # Determine recipient type based on currency
    # Nigeria: nuban (bank) or mobile_money
    # Ghana: ghipss (bank) or mobile_money
    # South Africa: basa (bank)
    # Kenya: mobile_money
    type_map = {
        "NGN": "nuban",
        "GHS": "ghipss",  # For bank, or 'mobile_money' for MoMo
        "ZAR": "basa",
        "KES": "mobile_money",
        "XOF": "mobile_money",
    }
    
    if not recipient_type or recipient_type == "nuban":
        recipient_type = type_map.get(currency.upper(), "nuban")
    
    payload = {
        "type": recipient_type,
        "name": name,
        "account_number": account_number,
        "bank_code": bank_code,
        "currency": currency.upper(),
    }
    
    if metadata:
        payload["metadata"] = metadata
    
    try:
        response = requests.post(
            url,
            headers=_paystack_auth_headers(),
            json=payload,
            timeout=30
        )
        data = response.json() if response.content else {}
        
        logger.info(f"Paystack create recipient response: {data}")
        
        if response.status_code in (200, 201) and data.get("status") is True:
            recipient_data = data.get("data", {})
            return {
                "success": True,
                "recipient_code": recipient_data.get("recipient_code"),
                "recipient_id": recipient_data.get("id"),
                "name": recipient_data.get("name") or name,
                "message": data.get("message", "Recipient created"),
                "raw": data,
            }
        else:
            return {
                "success": False,
                "recipient_code": None,
                "recipient_id": None,
                "name": name,
                "message": data.get("message") or "Failed to create recipient",
                "raw": data,
            }
    
    except Exception as e:
        logger.error(f"Paystack create recipient error: {e}")
        return {
            "success": False,
            "recipient_code": None,
            "recipient_id": None,
            "name": name,
            "message": str(e),
            "raw": {},
        }


def initiate_transfer(
    amount: Decimal,
    recipient_code: str,
    currency: str = "NGN",
    reason: str = "Payout",
    reference: str | None = None,
) -> Dict[str, Any]:
    """
    Initiate a transfer/payout to a recipient.
    
    Args:
        amount: Amount in main currency units
        recipient_code: Recipient code from create_transfer_recipient
        currency: Currency code
        reason: Narration for the transfer
        reference: Unique reference (auto-generated if not provided)
    
    Returns:
        {
            'success': bool,
            'transfer_code': str,
            'transfer_id': int,
            'reference': str,
            'status': str,  # 'pending', 'success', 'failed', etc.
            'message': str,
            'raw': dict
        }
    """
    url = f"{_paystack_base_url()}/transfer"
    
    if not reference:
        reference = generate_reference("payout")
    
    payload = {
        "source": "balance",
        "amount": _to_kobo(amount, currency),
        "recipient": recipient_code,
        "reason": reason,
        "reference": reference,
        "currency": currency.upper(),
    }
    
    try:
        response = requests.post(
            url,
            headers=_paystack_auth_headers(),
            json=payload,
            timeout=30
        )
        data = response.json() if response.content else {}
        
        logger.info(f"Paystack transfer response: {data}")
        
        if response.status_code == 200 and data.get("status") is True:
            transfer_data = data.get("data", {})
            return {
                "success": True,
                "transfer_code": transfer_data.get("transfer_code"),
                "transfer_id": transfer_data.get("id"),
                "reference": transfer_data.get("reference") or reference,
                "status": transfer_data.get("status", "pending"),
                "message": data.get("message", "Transfer initiated"),
                "raw": data,
            }
        else:
            return {
                "success": False,
                "transfer_code": None,
                "transfer_id": None,
                "reference": reference,
                "status": "failed",
                "message": data.get("message") or "Transfer failed",
                "raw": data,
            }
    
    except Exception as e:
        logger.error(f"Paystack transfer error: {e}")
        return {
            "success": False,
            "transfer_code": None,
            "transfer_id": None,
            "reference": reference,
            "status": "error",
            "message": str(e),
            "raw": {},
        }


def verify_transfer(reference: str) -> Dict[str, Any]:
    """
    Verify/check status of a transfer.
    
    Returns:
        {
            'success': bool,
            'status': str,
            'transfer_code': str,
            'amount': Decimal,
            'message': str,
            'raw': dict
        }
    """
    url = f"{_paystack_base_url()}/transfer/verify/{reference}"
    
    try:
        response = requests.get(
            url,
            headers=_paystack_auth_headers(),
            timeout=30
        )
        data = response.json() if response.content else {}
        
        if response.status_code == 200 and data.get("status") is True:
            transfer_data = data.get("data", {})
            amount = int(transfer_data.get("amount") or 0)
            currency = transfer_data.get("currency", "NGN")
            return {
                "success": True,
                "status": transfer_data.get("status"),
                "transfer_code": transfer_data.get("transfer_code"),
                "amount": _from_kobo(amount, currency),
                "message": data.get("message", ""),
                "raw": data,
            }
        else:
            return {
                "success": False,
                "status": "unknown",
                "transfer_code": None,
                "amount": Decimal("0.00"),
                "message": data.get("message") or "Transfer not found",
                "raw": data,
            }
    
    except Exception as e:
        logger.error(f"Paystack verify transfer error: {e}")
        return {
            "success": False,
            "status": "error",
            "transfer_code": None,
            "amount": Decimal("0.00"),
            "message": str(e),
            "raw": {},
        }


# =============================================================================
# WEBHOOK VERIFICATION
# =============================================================================

def verify_webhook_signature(payload: bytes, signature: str) -> bool:
    """
    Verify Paystack webhook signature.
    
    Args:
        payload: Raw request body (bytes)
        signature: Value of 'x-paystack-signature' header
    
    Returns:
        True if signature is valid
    """
    import hmac
    import hashlib
    
    secret_key = getattr(settings, "PAYSTACK_SECRET_KEY", "")
    if not secret_key or not signature:
        return False
    
    computed = hmac.new(
        secret_key.encode("utf-8"),
        payload,
        hashlib.sha512
    ).hexdigest()
    
    return hmac.compare_digest(computed, signature)