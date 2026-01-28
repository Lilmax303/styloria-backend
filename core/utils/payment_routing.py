# core/utils/payment_routing.py

"""
Payment currency validation and conversion for Styloria.
Works with existing gateway routing from paystack_countries.py
"""

from __future__ import annotations
from decimal import Decimal, ROUND_HALF_UP
from typing import Tuple

from core.utils.currency import convert_amount, get_currency_for_country


# ═══════════════════════════════════════════════════════════════════════════════
# CURRENCY CLASSIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Currencies well-supported by Stripe for card payments
STRIPE_SUPPORTED_CURRENCIES = {
    # Major
    'USD', 'EUR', 'GBP', 'CAD', 'AUD', 'JPY', 'CHF', 'CNY',
    # European
    'SEK', 'NOK', 'DKK', 'PLN', 'CZK', 'HUF', 'RON', 'BGN',
    # Asia-Pacific
    'SGD', 'HKD', 'NZD', 'MYR', 'THB', 'PHP', 'TWD', 'KRW', 'INR', 'IDR', 'VND',
    # Middle East
    'AED', 'SAR', 'ILS', 'TRY',
    # Americas
    'MXN', 'BRL', 'ARS', 'CLP', 'COP', 'PEN',
}

# African currencies - must use Paystack or Flutterwave
AFRICAN_CURRENCIES = {
    'NGN', 'GHS', 'KES', 'ZAR', 'XOF', 'XAF',  # Paystack-supported
    'UGX', 'TZS', 'RWF', 'EGP', 'MAD', 'ZMW', 'MWK', 'BWP',
    'ETB', 'GMD', 'MZN', 'TND', 'DZD', 'LYD', 'SDG', 'AOA',
    'NAD', 'MUR', 'ZWL',
}

# Paystack-supported currencies
PAYSTACK_CURRENCIES = {'NGN', 'GHS', 'ZAR', 'KES', 'XOF'}

# Flutterwave-supported currencies
FLUTTERWAVE_CURRENCIES = AFRICAN_CURRENCIES | {'USD', 'EUR', 'GBP'}


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def normalize_currency(currency: str | None) -> str:
    """Normalize currency code to uppercase, stripped."""
    return (currency or "USD").upper().strip()


def is_stripe_supported_currency(currency: str | None) -> bool:
    """Check if currency is supported by Stripe for card payments."""
    return normalize_currency(currency) in STRIPE_SUPPORTED_CURRENCIES


def is_african_currency(currency: str | None) -> bool:
    """Check if currency is African (should use Paystack/Flutterwave)."""
    return normalize_currency(currency) in AFRICAN_CURRENCIES


def is_paystack_currency(currency: str | None) -> bool:
    """Check if currency is supported by Paystack."""
    return normalize_currency(currency) in PAYSTACK_CURRENCIES


def is_flutterwave_currency(currency: str | None) -> bool:
    """Check if currency is supported by Flutterwave."""
    return normalize_currency(currency) in FLUTTERWAVE_CURRENCIES


# ═══════════════════════════════════════════════════════════════════════════════
# CURRENCY VALIDATION & CONVERSION FOR EACH GATEWAY
# ═══════════════════════════════════════════════════════════════════════════════

def validate_and_convert_for_stripe(
    amount: Decimal,
    current_currency: str,
    user
) -> Tuple[Decimal, str, bool]:
    """
    Validate and optionally convert currency for Stripe payment.
    
    Args:
        amount: The amount to charge
        current_currency: The currency currently on the booking
        user: The user making the payment (to get their country's currency as fallback)
    
    Returns:
        Tuple of (final_amount, final_currency, was_converted)
    """
    current_currency = normalize_currency(current_currency)
    
    # If already Stripe-supported, no conversion needed
    if is_stripe_supported_currency(current_currency):
        return amount, current_currency, False
    
    # Currency not Stripe-supported, need to convert
    # Try user's country currency first
    user_country = getattr(user, 'country_name', '') or ''
    user_currency = normalize_currency(get_currency_for_country(user_country))
    
    if is_stripe_supported_currency(user_currency):
        target_currency = user_currency
    else:
        # Fallback to USD
        target_currency = "USD"
    
    # Convert amount
    try:
        converted = convert_amount(float(amount), current_currency, target_currency)
        converted_amount = Decimal(str(converted)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception:
        # If conversion fails, use original amount (edge case)
        converted_amount = amount
    
    return converted_amount, target_currency, True


def validate_and_convert_for_paystack(
    amount: Decimal,
    current_currency: str,
    user
) -> Tuple[Decimal, str, bool]:
    """
    Validate and optionally convert currency for Paystack payment.
    """
    from core.utils.paystack_countries import get_paystack_currency
    
    current_currency = normalize_currency(current_currency)
    user_country = getattr(user, 'country_name', '') or ''
    
    # Get Paystack currency for user's country
    paystack_currency = get_paystack_currency(user_country)
    
    if not paystack_currency:
        # User shouldn't be using Paystack - default to NGN
        paystack_currency = "NGN"
    
    paystack_currency = normalize_currency(paystack_currency)
    
    if current_currency == paystack_currency:
        return amount, current_currency, False
    
    # Convert to Paystack-supported currency
    try:
        converted = convert_amount(float(amount), current_currency, paystack_currency)
        converted_amount = Decimal(str(converted)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception:
        converted_amount = amount
    
    return converted_amount, paystack_currency, True


def validate_and_convert_for_flutterwave(
    amount: Decimal,
    current_currency: str,
    user
) -> Tuple[Decimal, str, bool]:
    """
    Validate and optionally convert currency for Flutterwave payment.
    """
    current_currency = normalize_currency(current_currency)
    
    # Flutterwave supports most African currencies + USD/EUR/GBP
    if is_flutterwave_currency(current_currency):
        return amount, current_currency, False
    
    # Convert to user's currency
    user_country = getattr(user, 'country_name', '') or ''
    user_currency = normalize_currency(get_currency_for_country(user_country))
    
    if is_flutterwave_currency(user_currency):
        target_currency = user_currency
    else:
        target_currency = "USD"
    
    try:
        converted = convert_amount(float(amount), current_currency, target_currency)
        converted_amount = Decimal(str(converted)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception:
        converted_amount = amount
    
    return converted_amount, target_currency, True


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE: GET CURRENCY FOR BOOKING CREATION
# ═══════════════════════════════════════════════════════════════════════════════

def get_booking_currency_for_user(user) -> str:
    """
    Get the appropriate currency to set on a new booking based on user's country
    and the payment gateway they'll use.
    """
    from core.utils.paystack_countries import get_payment_gateway_for_country, get_paystack_currency
    
    user_country = getattr(user, 'country_name', '') or ''
    gateway = get_payment_gateway_for_country(user_country)
    
    if gateway == "paystack":
        currency = get_paystack_currency(user_country)
        return normalize_currency(currency) if currency else "NGN"
    
    elif gateway == "flutterwave":
        currency = get_currency_for_country(user_country)
        return normalize_currency(currency) if currency else "USD"
    
    else:  # stripe
        currency = get_currency_for_country(user_country)
        currency = normalize_currency(currency)
        # Ensure it's Stripe-supported
        if is_stripe_supported_currency(currency):
            return currency
        return "USD"