# core/utils/stripe_money.py


from __future__ import annotations
from decimal import Decimal, ROUND_HALF_UP, ROUND_UP

ZERO_DECIMAL_CURRENCIES = {
    "BIF","CLP","DJF","GNF","JPY","KMF","KRW","MGA","PYG","RWF","UGX","VND","VUV","XAF","XOF","XPF",
}

def currency_exponent(currency: str) -> int:
    c = (currency or "USD").upper().strip()
    return 0 if c in ZERO_DECIMAL_CURRENCIES else 2

def quantize_money(amount: Decimal, currency: str) -> Decimal:
    exp = currency_exponent(currency)
    q = Decimal("1") if exp == 0 else Decimal("0.01")
    return Decimal(str(amount)).quantize(q, rounding=ROUND_HALF_UP)

def to_minor_units(amount: Decimal, currency: str) -> int:
    """
    Stripe expects integer minor units.
    For 0-decimal currencies, minor units == major units.
    """
    c = (currency or "USD").upper().strip()
    exp = currency_exponent(c)
    amt = Decimal(str(amount))

    if exp == 0:
        return int(amt.quantize(Decimal("1"), rounding=ROUND_UP))
    return int((amt * Decimal("100")).quantize(Decimal("1"), rounding=ROUND_UP))

def from_minor_units(amount_minor: int, currency: str) -> Decimal:
    c = (currency or "USD").upper().strip()
    exp = currency_exponent(c)
    if exp == 0:
        return Decimal(str(int(amount_minor))).quantize(Decimal("1"))
    return (Decimal(str(int(amount_minor))) / Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)