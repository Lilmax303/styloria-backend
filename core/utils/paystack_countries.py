# core/utils/paystack_countries.py

"""
Paystack supported countries for payments and payouts.
These countries will use Paystack instead of Flutterwave.
"""

# Countries supported by Paystack with their currency codes
PAYSTACK_COUNTRIES = {
    "Ghana": "GHS",
    "Nigeria": "NGN",
    "South Africa": "ZAR",
    "Kenya": "KES",
    "Côte d'Ivoire": "XOF",
    "Cote d'Ivoire": "XOF",
    "Ivory Coast": "XOF",
}

# Paystack country codes (ISO 3166-1 alpha-2)
PAYSTACK_COUNTRY_CODES = {
    "Ghana": "GH",
    "Nigeria": "NG",
    "South Africa": "ZA",
    "Kenya": "KE",
    "Côte d'Ivoire": "CI",
    "Cote d'Ivoire": "CI",
    "Ivory Coast": "CI",
}

# Bank codes vary by country - Paystack uses different formats
PAYSTACK_BANK_COUNTRY_PARAM = {
    "GHS": "ghana",
    "NGN": "nigeria",
    "ZAR": "south-africa",
    "KES": "kenya",
    "XOF": "cote-divoire",
}


def _normalize(s: str) -> str:
    """Normalize country name for comparison."""
    return (
        (s or "")
        .strip()
        .replace("'", "'")
        .replace("'", "'")
        .lower()
    )


def is_paystack_country(country_name: str | None) -> bool:
    """
    Check if a country is supported by Paystack.
    Returns True for Ghana, Nigeria, South Africa, Kenya, Côte d'Ivoire.
    """
    if not country_name:
        return False
    normalized = _normalize(country_name)
    return normalized in {_normalize(c) for c in PAYSTACK_COUNTRIES.keys()}


def get_paystack_currency(country_name: str) -> str | None:
    """
    Get the Paystack-supported currency for a country.
    Returns None if country is not supported by Paystack.
    """
    if not country_name:
        return None
    normalized = _normalize(country_name)
    for country, currency in PAYSTACK_COUNTRIES.items():
        if _normalize(country) == normalized:
            return currency
    return None


def get_paystack_country_code(country_name: str) -> str | None:
    """
    Get the ISO country code for Paystack API calls.
    """
    if not country_name:
        return None
    normalized = _normalize(country_name)
    for country, code in PAYSTACK_COUNTRY_CODES.items():
        if _normalize(country) == normalized:
            return code
    return None


def get_paystack_bank_country_param(currency: str) -> str | None:
    """
    Get the country parameter for Paystack's list banks endpoint.
    """
    return PAYSTACK_BANK_COUNTRY_PARAM.get((currency or "").upper().strip())


def get_payment_gateway_for_country(country_name: str | None) -> str:
    """
    Determine which payment gateway to use based on country.
    
    Returns:
        'paystack' - For Ghana, Nigeria, South Africa, Kenya, Côte d'Ivoire
        'flutterwave' - For other African countries
        'stripe' - For non-African countries
    """
    from core.utils.regions import is_african_country_name
    
    if not country_name:
        return "stripe"
    
    # Check Paystack countries first (subset of Africa)
    if is_paystack_country(country_name):
        return "paystack"
    
    # Other African countries use Flutterwave
    if is_african_country_name(country_name):
        return "flutterwave"
    
    # Rest of the world uses Stripe
    return "stripe"