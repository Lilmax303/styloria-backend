# core/utils/flutterwave_transfer.py

import requests
import uuid
from decimal import Decimal
from django.conf import settings
from django.utils import timezone


class FlutterwaveTransferError(Exception):
    """Custom exception for Flutterwave transfer errors"""
    pass


def generate_reference():
    """Generate unique transfer reference"""
    return f"STYLORIA_PAYOUT_{uuid.uuid4().hex[:12].upper()}_{int(timezone.now().timestamp())}"


def initiate_bank_transfer(
    account_number: str,
    bank_code: str,
    amount: Decimal,
    currency: str,
    narration: str,
    beneficiary_name: str,
    reference: str = None,
) -> dict:
    """
    Initiate bank transfer via Flutterwave
    
    Returns:
        {
            'success': bool,
            'transfer_id': int or None,
            'reference': str,
            'status': str,
            'message': str,
            'raw_response': dict
        }
    """
    if not reference:
        reference = generate_reference()
    
    url = f"{settings.FLUTTERWAVE_BASE_URL}/transfers"
    
    headers = {
        "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
        "Content-Type": "application/json",
    }
    
    payload = {
        "account_bank": bank_code,
        "account_number": account_number,
        "amount": float(amount),
        "currency": currency,
        "narration": narration,
        "reference": reference,
        "beneficiary_name": beneficiary_name,
        "callback_url": settings.get('FLUTTERWAVE_PAYOUT_CALLBACK_URL', ''),
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        data = response.json()
        
        if response.status_code == 200 and data.get('status') == 'success':
            transfer_data = data.get('data', {})
            return {
                'success': True,
                'transfer_id': transfer_data.get('id'),
                'reference': reference,
                'status': transfer_data.get('status', 'NEW'),
                'message': data.get('message', 'Transfer initiated'),
                'raw_response': data,
            }
        else:
            return {
                'success': False,
                'transfer_id': None,
                'reference': reference,
                'status': 'FAILED',
                'message': data.get('message', 'Transfer failed'),
                'raw_response': data,
            }
    except requests.exceptions.Timeout:
        return {
            'success': False,
            'transfer_id': None,
            'reference': reference,
            'status': 'TIMEOUT',
            'message': 'Request timed out',
            'raw_response': {},
        }
    except Exception as e:
        return {
            'success': False,
            'transfer_id': None,
            'reference': reference,
            'status': 'ERROR',
            'message': str(e),
            'raw_response': {},
        }


def initiate_mobile_money_transfer(
    phone_number: str,
    amount: Decimal,
    currency: str,
    narration: str,
    beneficiary_name: str,
    reference: str = None,
) -> dict:
    """
    Initiate mobile money transfer via Flutterwave
    
    Supports: GHS (Ghana), KES (Kenya), UGX (Uganda), RWF (Rwanda), etc.
    """
    if not reference:
        reference = generate_reference()
    
    url = f"{settings.FLUTTERWAVE_BASE_URL}/transfers"
    
    headers = {
        "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
        "Content-Type": "application/json",
    }
    
    # Mobile money network detection based on currency
    # Flutterwave uses specific bank codes for mobile money
    mobile_money_codes = {
        'GHS': 'MPS',  # Ghana Mobile Money
        'KES': 'MPS',  # Kenya M-Pesa
        'UGX': 'MPS',  # Uganda Mobile Money
        'RWF': 'MPS',  # Rwanda Mobile Money
        'ZMW': 'MPS',  # Zambia Mobile Money
        'TZS': 'MPS',  # Tanzania Mobile Money
        'XOF': 'MPS',  # West Africa (CFA)
        'XAF': 'MPS',  # Central Africa (CFA)
    }
    
    account_bank = mobile_money_codes.get(currency.upper(), 'MPS')
    
    payload = {
        "account_bank": account_bank,
        "account_number": phone_number,
        "amount": float(amount),
        "currency": currency,
        "narration": narration,
        "reference": reference,
        "beneficiary_name": beneficiary_name,
        "callback_url": settings.get('FLUTTERWAVE_PAYOUT_CALLBACK_URL', ''),
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        data = response.json()
        
        if response.status_code == 200 and data.get('status') == 'success':
            transfer_data = data.get('data', {})
            return {
                'success': True,
                'transfer_id': transfer_data.get('id'),
                'reference': reference,
                'status': transfer_data.get('status', 'NEW'),
                'message': data.get('message', 'Transfer initiated'),
                'raw_response': data,
            }
        else:
            return {
                'success': False,
                'transfer_id': None,
                'reference': reference,
                'status': 'FAILED',
                'message': data.get('message', 'Transfer failed'),
                'raw_response': data,
            }
    except requests.exceptions.Timeout:
        return {
            'success': False,
            'transfer_id': None,
            'reference': reference,
            'status': 'TIMEOUT',
            'message': 'Request timed out',
            'raw_response': {},
        }
    except Exception as e:
        return {
            'success': False,
            'transfer_id': None,
            'reference': reference,
            'status': 'ERROR',
            'message': str(e),
            'raw_response': {},
        }


def get_transfer_status(transfer_id: int) -> dict:
    """
    Check status of a transfer
    """
    url = f"{settings.FLUTTERWAVE_BASE_URL}/transfers/{transfer_id}"
    
    headers = {
        "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        data = response.json()
        
        if response.status_code == 200 and data.get('status') == 'success':
            transfer_data = data.get('data', {})
            return {
                'success': True,
                'status': transfer_data.get('status'),
                'message': transfer_data.get('complete_message', ''),
                'raw_response': data,
            }
        else:
            return {
                'success': False,
                'status': 'UNKNOWN',
                'message': data.get('message', 'Could not get status'),
                'raw_response': data,
            }
    except Exception as e:
        return {
            'success': False,
            'status': 'ERROR',
            'message': str(e),
            'raw_response': {},
        }


def retry_transfer(transfer_id: int) -> dict:
    """
    Retry a failed transfer
    """
    url = f"{settings.FLUTTERWAVE_BASE_URL}/transfers/{transfer_id}/retries"
    
    headers = {
        "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
        "Content-Type": "application/json",
    }
    
    try:
        response = requests.post(url, headers=headers, timeout=30)
        data = response.json()
        
        return {
            'success': response.status_code == 200 and data.get('status') == 'success',
            'message': data.get('message', ''),
            'raw_response': data,
        }
    except Exception as e:
        return {
            'success': False,
            'message': str(e),
            'raw_response': {},
        }