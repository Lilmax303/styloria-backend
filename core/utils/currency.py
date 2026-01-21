# core/utils/currency.py

"""
Currency utility functions for Styloria.
"""

import requests
from django.conf import settings
from django.core.cache import cache
from decimal import Decimal, ROUND_HALF_UP
import json

# Country to Currency Mapping
COUNTRY_TO_CURRENCY = {
    # North America
    'United States': 'USD',
    'USA': 'USD',
    'United States of America': 'USD',
    'Canada': 'CAD',
    'Mexico': 'MXN',
    
    # Europe
    'United Kingdom': 'GBP',
    'UK': 'GBP',
    'Great Britain': 'GBP',
    'Germany': 'EUR',
    'France': 'EUR',
    'Italy': 'EUR',
    'Spain': 'EUR',
    'Netherlands': 'EUR',
    'Belgium': 'EUR',
    'Portugal': 'EUR',
    'Ireland': 'EUR',
    'Austria': 'EUR',
    'Switzerland': 'CHF',
    'Sweden': 'SEK',
    'Norway': 'NOK',
    'Denmark': 'DKK',
    'Finland': 'EUR',
    'Poland': 'PLN',
    'Czech Republic': 'CZK',
    'Hungary': 'HUF',
    'Romania': 'RON',
    'Bulgaria': 'BGN',
    'Greece': 'EUR',
    
    # Africa
    'Ghana': 'GHS',
    'Nigeria': 'NGN',
    'Kenya': 'KES',
    'South Africa': 'ZAR',
    'Egypt': 'EGP',
    'Morocco': 'MAD',
    'Tunisia': 'TND',
    'Ethiopia': 'ETB',
    'Tanzania': 'TZS',
    'Uganda': 'UGX',
    'Rwanda': 'RWF',
    'Senegal': 'XOF',
    'Ivory Coast': 'XOF',
    'Cameroon': 'XAF',
    'Algeria': 'DZD',
    'Libya': 'LYD',
    'Sudan': 'SDG',
    'Angola': 'AOA',
    'Mozambique': 'MZN',
    'Zambia': 'ZMW',
    'Zimbabwe': 'ZWL',
    'Botswana': 'BWP',
    'Namibia': 'NAD',
    'Mauritius': 'MUR',
    
    # Asia
    'China': 'CNY',
    'Japan': 'JPY',
    'India': 'INR',
    'South Korea': 'KRW',
    'Singapore': 'SGD',
    'Malaysia': 'MYR',
    'Thailand': 'THB',
    'Vietnam': 'VND',
    'Philippines': 'PHP',
    'Indonesia': 'IDR',
    'Pakistan': 'PKR',
    'Bangladesh': 'BDT',
    'Sri Lanka': 'LKR',
    'Nepal': 'NPR',
    'Bhutan': 'BTN',
    'Maldives': 'MVR',
    'Mongolia': 'MNT',
    'Myanmar': 'MMK',
    'Cambodia': 'KHR',
    'Laos': 'LAK',
    'Brunei': 'BND',
    
    # Middle East
    'Saudi Arabia': 'SAR',
    'United Arab Emirates': 'AED',
    'UAE': 'AED',
    'Qatar': 'QAR',
    'Kuwait': 'KWD',
    'Oman': 'OMR',
    'Bahrain': 'BHD',
    'Israel': 'ILS',
    'Turkey': 'TRY',
    'Iran': 'IRR',
    'Iraq': 'IQD',
    'Jordan': 'JOD',
    'Lebanon': 'LBP',
    'Syria': 'SYP',
    'Yemen': 'YER',
    
    # Oceania
    'Australia': 'AUD',
    'New Zealand': 'NZD',
    'Fiji': 'FJD',
    'Papua New Guinea': 'PGK',
    'Solomon Islands': 'SBD',
    'Vanuatu': 'VUV',
    
    # Latin America
    'Brazil': 'BRL',
    'Argentina': 'ARS',
    'Chile': 'CLP',
    'Colombia': 'COP',
    'Peru': 'PEN',
    'Venezuela': 'VES',
    'Uruguay': 'UYU',
    'Paraguay': 'PYG',
    'Bolivia': 'BOB',
    'Ecuador': 'USD',  # Ecuador uses USD
    'Costa Rica': 'CRC',
    'Panama': 'PAB',
    'Guatemala': 'GTQ',
    'Honduras': 'HNL',
    'Nicaragua': 'NIO',
    'El Salvador': 'USD',  # El Salvador uses USD
    
    # Caribbean
    'Jamaica': 'JMD',
    'Bahamas': 'BSD',
    'Barbados': 'BBD',
    'Trinidad and Tobago': 'TTD',
    'Dominican Republic': 'DOP',
    'Haiti': 'HTG',
    'Cuba': 'CUP',
}

# Currency Symbols
CURRENCY_SYMBOLS = {
    'USD': '$',
    'EUR': '€',
    'GBP': '£',
    'JPY': '¥',
    'CNY': '¥',
    'INR': '₹',
    'RUB': '₽',
    'KRW': '₩',
    'TRY': '₺',
    'GHS': 'GH₵',
    'NGN': '₦',
    'KES': 'KSh',
    'ZAR': 'R',
    'EGP': 'E£',
    'MAD': 'DH',
    'CAD': 'C$',
    'AUD': 'A$',
    'NZD': 'NZ$',
    'CHF': 'CHF',
    'SEK': 'kr',
    'NOK': 'kr',
    'DKK': 'kr',
    'PLN': 'zł',
    'CZK': 'Kč',
    'HUF': 'Ft',
    'RON': 'lei',
    'BGN': 'лв',
    'ARS': '$',
    'BRL': 'R$',
    'MXN': '$',
    'CLP': '$',
    'COP': '$',
    'PEN': 'S/',
    'VES': 'Bs',
    'SAR': '﷼',
    'AED': 'د.إ',
    'QAR': '﷼',
    'KWD': 'د.ك',
    'OMR': '﷼',
    'BHD': '.د.ب',
    'ILS': '₪',
    'IRR': '﷼',
    'IQD': 'ع.د',
    'SGD': 'S$',
    'MYR': 'RM',
    'THB': '฿',
    'VND': '₫',
    'PHP': '₱',
    'IDR': 'Rp',
    'PKR': '₨',
    'BDT': '৳',
    'LKR': 'Rs',
    'NPR': 'Rs',
    'XOF': 'CFA',
    'XAF': 'FCFA',
    'ETB': 'Br',
    'TZS': 'TSh',
    'UGX': 'USh',
    'RWF': 'RF',
    'TND': 'DT',
    'DZD': 'د.ج',
    'LYD': 'ل.د',
    'SDG': 'ج.س.',
    'AOA': 'Kz',
    'MZN': 'MT',
    'ZMW': 'ZK',
    'ZWL': 'Z$',
    'BWP': 'P',
    'NAD': 'N$',
    'MUR': '₨',
    'JOD': 'د.أ',
    'LBP': 'ل.ل',
    'SYP': '£',
    'YER': '﷼',
    'FJD': 'FJ$',
    'PGK': 'K',
    'SBD': 'SI$',
    'VUV': 'VT',
    'UYU': '$U',
    'PYG': '₲',
    'BOB': 'Bs.',
    'CRC': '₡',
    'PAB': 'B/.',
    'GTQ': 'Q',
    'HNL': 'L',
    'NIO': 'C$',
    'JMD': 'J$',
    'BSD': 'B$',
    'BBD': 'Bds$',
    'TTD': 'TT$',
    'DOP': 'RD$',
    'HTG': 'G',
    'CUP': '$MN',
}

# Fallback for common country names/codes
COUNTRY_ALIASES = {
    'USA': 'United States',
    'US': 'United States',
    'UK': 'United Kingdom',
    'UAE': 'United Arab Emirates',
    'Korea': 'South Korea',
    'South Korea': 'South Korea',
    'North Korea': 'North Korea',
    'Russia': 'Russian Federation',
    'Iran': 'Iran',
    'Syria': 'Syria',
    'Ivory Coast': 'Ivory Coast',
    'Côte d\'Ivoire': 'Ivory Coast',
    'Burkina Faso': 'Burkina Faso',
    'Mali': 'Mali',
    'Niger': 'Niger',
    'Senegal': 'Senegal',
    'Guinea': 'Guinea',
    'Benin': 'Benin',
    'Togo': 'Togo',
    'Cameroon': 'Cameroon',
    'CAR': 'Central African Republic',
    'Chad': 'Chad',
    'Congo': 'Republic of the Congo',
    'DRC': 'Democratic Republic of the Congo',
    'Gabon': 'Gabon',
    'Equatorial Guinea': 'Equatorial Guinea',
}


def get_currency_for_country(country_name):
    """
    Get currency code for a country name.
    Returns USD as default if country not found.
    """
    if not country_name:
        return 'USD'
    
    # Clean the country name
    country_name = str(country_name).strip().title()
    
    # Check aliases first
    if country_name in COUNTRY_ALIASES:
        country_name = COUNTRY_ALIASES[country_name]
    
    # Get currency from mapping
    currency = COUNTRY_TO_CURRENCY.get(country_name)
    if currency:
        return currency
    
    # Try case-insensitive match
    country_lower = country_name.lower()
    for country, curr in COUNTRY_TO_CURRENCY.items():
        if country.lower() == country_lower:
            return curr
    
    # Try partial match
    for country, curr in COUNTRY_TO_CURRENCY.items():
        if country_lower in country.lower() or country.lower() in country_lower:
            return curr
    
    # Default to USD
    return 'USD'


def get_country_from_coordinates(latitude, longitude):
    """
    Reverse geocode coordinates to get country name.
    Uses OpenStreetMap Nominatim API.
    """
    if not latitude or not longitude:
        return None
    
    cache_key = f'geocode_{latitude}_{longitude}'
    country = cache.get(cache_key)
    
    if country is None:
        try:
            response = requests.get(
                'https://nominatim.openstreetmap.org/reverse',
                params={
                    'lat': latitude,
                    'lon': longitude,
                    'format': 'json',
                    'accept-language': 'en',
                    'zoom': 3,  # Country level
                },
                headers={'User-Agent': 'Styloria/1.0 (contact@styloria.com)'},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                address = data.get('address', {})
                country = address.get('country')
                
                # If no country found, try country_code
                if not country and 'country_code' in address:
                    country_code = address['country_code'].upper()
                    # Convert country code to country name (basic mapping)
                    code_to_country = {
                        'US': 'United States', 'GB': 'United Kingdom',
                        'DE': 'Germany', 'FR': 'France', 'IT': 'Italy',
                        'ES': 'Spain', 'CN': 'China', 'JP': 'Japan',
                        'IN': 'India', 'KR': 'South Korea', 'GH': 'Ghana',
                        'NG': 'Nigeria', 'KE': 'Kenya', 'ZA': 'South Africa',
                        'AU': 'Australia', 'CA': 'Canada', 'BR': 'Brazil',
                        'RU': 'Russia', 'MX': 'Mexico', 'SA': 'Saudi Arabia',
                        'AE': 'United Arab Emirates', 'TR': 'Turkey',
                        'EG': 'Egypt', 'MA': 'Morocco', 'TN': 'Tunisia',
                        'ET': 'Ethiopia', 'TZ': 'Tanzania', 'UG': 'Uganda',
                        'RW': 'Rwanda', 'SN': 'Senegal', 'CI': 'Ivory Coast',
                        'CM': 'Cameroon', 'DZ': 'Algeria', 'LY': 'Libya',
                        'SD': 'Sudan', 'AO': 'Angola', 'MZ': 'Mozambique',
                        'ZM': 'Zambia', 'ZW': 'Zimbabwe', 'BW': 'Botswana',
                        'NA': 'Namibia', 'MU': 'Mauritius',
                    }
                    country = code_to_country.get(country_code, '')
                
                if country:
                    # Cache for 24 hours
                    cache.set(cache_key, country, 86400)
        except Exception as e:
            print(f"Error reverse geocoding: {e}")
            # Fallback: Use a simple latitude-based guess
            if -35 <= latitude <= 37 and -17 <= longitude <= 51:
                country = 'Ghana'  # Rough approximation for Ghana
            elif 25 <= latitude <= 49 and -125 <= longitude <= -66:
                country = 'United States'
            elif 35 <= latitude <= 71 and -10 <= longitude <= 40:
                country = 'United Kingdom'
            else:
                country = 'United States'  # Default
    
    return country


def get_exchange_rate(base_currency, target_currency):
    """
    Get exchange rate from base to target currency.
    Using free API from exchangerate-api.com
    Returns 1.0 if same currency or error.
    """
    if base_currency == target_currency:
        return 1.0
    
    cache_key = f"exchange_rate_{base_currency}_{target_currency}"
    cached = cache.get(cache_key)
    
    if cached:
        return Decimal(str(cached))
    
    try:
        # Free tier API (limited to 1500 requests/month)
        url = f"https://api.exchangerate-api.com/v4/latest/{base_currency}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if 'rates' in data and target_currency in data['rates']:
                rate = Decimal(str(data['rates'][target_currency]))
                # Cache for 1 hour to respect API limits
                cache.set(cache_key, float(rate), 3600)
                return rate
        else:
            # Try fallback API
            url = f"https://api.frankfurter.app/latest?from={base_currency}&to={target_currency}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if 'rates' in data and target_currency in data['rates']:
                    rate = Decimal(str(data['rates'][target_currency]))
                    cache.set(cache_key, float(rate), 3600)
                    return rate
    
    except Exception as e:
        print(f"Exchange rate error: {e}")
    
    # Default to 1:1 if API fails (or use hardcoded rates for common currencies)
    fallback_rates = {
        ('USD', 'EUR'): Decimal('0.92'),
        ('USD', 'GBP'): Decimal('0.79'),
        ('USD', 'GHS'): Decimal('12.50'),
        ('USD', 'NGN'): Decimal('1500.00'),
        ('USD', 'KES'): Decimal('150.00'),
        ('USD', 'ZAR'): Decimal('18.50'),
        ('USD', 'INR'): Decimal('83.00'),
        ('USD', 'CNY'): Decimal('7.20'),
        ('USD', 'JPY'): Decimal('150.00'),
        ('EUR', 'USD'): Decimal('1.09'),
        ('EUR', 'GBP'): Decimal('0.86'),
        ('EUR', 'GHS'): Decimal('13.60'),
        ('GBP', 'USD'): Decimal('1.27'),
        ('GBP', 'EUR'): Decimal('1.16'),
        ('GBP', 'GHS'): Decimal('15.80'),
    }
    
    fallback_rate = fallback_rates.get((base_currency, target_currency), Decimal('1.0'))
    cache.set(cache_key, float(fallback_rate), 3600)
    return fallback_rate


def convert_amount(amount, from_currency, to_currency):
    """
    Convert amount from one currency to another.
    Returns rounded Decimal with 2 decimal places.
    """
    if from_currency == to_currency:
        return Decimal(str(amount)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    
    try:
        amount_decimal = Decimal(str(amount))
        rate = get_exchange_rate(from_currency, to_currency)
        converted = amount_decimal * rate
        
        # Round to 2 decimal places for display
        return converted.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    except Exception as e:
        print(f"Currency conversion error: {e}")
        return Decimal(str(amount)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)


def get_currency_symbol(currency_code):
    """
    Get currency symbol for display.
    Falls back to currency code if symbol not found.
    """
    if not currency_code:
        return '$'
    
    currency_code = currency_code.upper()
    return CURRENCY_SYMBOLS.get(currency_code, currency_code)


def format_amount(amount, country_name=None, currency_code=None):
    """
    Format amount with proper currency symbol and decimal places.
    """
    if not currency_code and country_name:
        currency_code = get_currency_for_country(country_name)
    elif not currency_code:
        currency_code = 'USD'
    
    symbol = get_currency_symbol(currency_code)
    
    try:
        amount_decimal = Decimal(str(amount))
        formatted_amount = f"{amount_decimal:,.2f}"
        
        # Some currencies don't use decimal places
        if currency_code in ['JPY', 'KRW', 'VND', 'IDR']:
            formatted_amount = f"{amount_decimal:,.0f}"
        
        return f"{symbol}{formatted_amount}"
    except:
        return f"{symbol}{amount}"


def calculate_transportation_cost(user_currency):
    """
    Calculate transportation cost: 80% of 1 unit of user's currency × 10
    This is a fixed cost per booking.
    """
    # Transportation cost = 0.8 * 1 [currency] * 10 = 8 [currency]
    return Decimal('8.00')


def calculate_service_fee(service_price):
    """
    Calculate service fee based on service price:
    - 10% if service price < 100
    - 7% if service price >= 100
    """
    service_price_decimal = Decimal(str(service_price))
    
    if service_price_decimal < Decimal('100'):
        fee_percent = Decimal('0.10')
    else:
        fee_percent = Decimal('0.07')
    
    fee = service_price_decimal * fee_percent
    return fee.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)


def calculate_total_price(service_price, transportation_cost, service_fee):
    """
    Calculate total price: service + transportation + service fee
    """
    service_decimal = Decimal(str(service_price))
    transport_decimal = Decimal(str(transportation_cost))
    fee_decimal = Decimal(str(service_fee))
    
    total = service_decimal + transport_decimal + fee_decimal
    return total.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)


def get_supported_currencies():
    """
    Get list of all supported currency codes.
    """
    currencies = set(COUNTRY_TO_CURRENCY.values())
    return sorted(list(currencies))


def validate_currency_code(currency_code):
    """
    Validate if a currency code is supported.
    """
    supported = get_supported_currencies()
    return currency_code.upper() in supported