# core/tasks.py

from celery import shared_task
from decimal import Decimal
from django.utils import timezone
from django.db import transaction
from django.db.models import Q
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def process_single_payout(self, payout_id: int):
    """
    Process a single payout via Flutterwave
    """
    from core.models import Payout, ProviderWallet, WalletLedgerEntry
    from core.utils.flutterwave_transfer import (
        initiate_bank_transfer,
        initiate_mobile_money_transfer,
        generate_reference,
    )
    
    try:
        payout = Payout.objects.select_related(
            'provider', 'provider__user', 'provider__payout_settings'
        ).get(id=payout_id)
    except Payout.DoesNotExist:
        logger.error(f"Payout {payout_id} not found")
        return {'success': False, 'error': 'Payout not found'}
    
    # Skip if already processed
    if payout.status in ('paid', 'processing'):
        logger.info(f"Payout {payout_id} already {payout.status}")
        return {'success': True, 'status': payout.status}
    
    # Get provider payout settings
    try:
        settings = payout.provider.payout_settings
    except Exception:
        payout.status = 'failed'
        payout.failure_reason = 'No payout settings configured'
        payout.save()
        return {'success': False, 'error': 'No payout settings'}
    
    # Skip if not using Flutterwave
    if settings.payout_gateway != 'flutterwave':
        logger.info(f"Payout {payout_id} uses {settings.payout_gateway}, skipping Flutterwave")
        return {'success': False, 'error': 'Not a Flutterwave payout'}
    
    # Prepare transfer details
    reference = generate_reference()
    beneficiary_name = settings.flutterwave_full_name or payout.provider.user.get_full_name()
    narration = f"Styloria Payout #{payout.id}"
    
    # Update status to processing
    payout.status = 'processing'
    payout.flutterwave_reference = reference
    payout.save()
    
    # Execute transfer based on method
    if settings.flutterwave_method == 'mobile_money':
        result = initiate_mobile_money_transfer(
            phone_number=settings.flutterwave_phone_number,
            amount=payout.net_amount,
            currency=settings.flutterwave_currency or payout.currency,
            narration=narration,
            beneficiary_name=beneficiary_name,
            reference=reference,
        )
    else:  # bank transfer
        result = initiate_bank_transfer(
            account_number=settings.flutterwave_account_number,
            bank_code=settings.flutterwave_bank_code,
            amount=payout.net_amount,
            currency=settings.flutterwave_currency or payout.currency,
            narration=narration,
            beneficiary_name=beneficiary_name,
            reference=reference,
        )
    
    # Update payout based on result
    if result['success']:
        payout.flutterwave_transfer_id = str(result.get('transfer_id', ''))
        payout.flutterwave_status = result.get('status', 'NEW')
        
        # Mark as paid if status indicates success
        if result['status'] in ('SUCCESS', 'SUCCESSFUL', 'NEW'):
            payout.status = 'paid'
            payout.processed_at = timezone.now()
            
            # Deduct from wallet
            with transaction.atomic():
                wallet = ProviderWallet.objects.select_for_update().get(
                    provider=payout.provider,
                    currency=payout.currency,
                )
                wallet.available_balance -= payout.net_amount
                wallet.lifetime_payouts += payout.net_amount
                wallet.save()
                
                # Create ledger entry
                WalletLedgerEntry.objects.create(
                    wallet=wallet,
                    payout=payout,
                    direction='debit',
                    kind='payout',
                    amount=payout.net_amount,
                    status='paid',
                    description=f"Payout #{payout.id} - {settings.flutterwave_method}",
                )
        
        payout.save()
        
        # Notify provider
        _notify_provider_payout_success(payout)
        
        logger.info(f"Payout {payout_id} processed successfully")
        return {'success': True, 'transfer_id': result.get('transfer_id')}
    
    else:
        payout.status = 'failed'
        payout.failure_reason = result.get('message', 'Unknown error')
        payout.flutterwave_status = result.get('status', 'FAILED')
        payout.save()
        
        # Notify provider of failure
        _notify_provider_payout_failed(payout)
        
        logger.error(f"Payout {payout_id} failed: {result.get('message')}")
        return {'success': False, 'error': result.get('message')}


@shared_task
def process_queued_instant_payouts():
    """
    Process all queued instant payout requests
    Runs every 2 minutes
    """
    from core.models import Payout
    
    queued_payouts = Payout.objects.filter(
        status='queued',
        method='instant',
    ).select_related('provider__payout_settings').order_by('created_at')[:10]
    
    processed = 0
    for payout in queued_payouts:
        # Check if provider uses Flutterwave
        try:
            if payout.provider.payout_settings.payout_gateway == 'flutterwave':
                process_single_payout.delay(payout.id)
                processed += 1
        except Exception as e:
            logger.error(f"Error queuing payout {payout.id}: {e}")
    
    logger.info(f"Queued {processed} instant payouts for processing")
    return {'queued': processed}


@shared_task
def process_scheduled_payouts():
    """
    Check and process scheduled (weekly/monthly) payouts
    Runs every hour
    """
    from core.models import ServiceProvider, ProviderPayoutSettings, ProviderWallet, Payout
    
    now = timezone.now()
    current_weekday = now.weekday()
    current_hour = now.hour
    current_day = now.day
    
    processed = 0
    
    # Get providers with auto-payout enabled
    providers_settings = ProviderPayoutSettings.objects.filter(
        auto_payout_enabled=True,
        payout_gateway='flutterwave',
    ).select_related('provider', 'provider__user')
    
    for settings in providers_settings:
        should_payout = False
        
        # Check if it's payout time
        if settings.payout_frequency == 'weekly':
            # Weekly: check weekday and hour
            if current_weekday == settings.payout_weekday and current_hour == settings.payout_hour_utc:
                should_payout = True
        
        elif settings.payout_frequency == 'monthly':
            # Monthly: payout on 1st of month
            if current_day == 1 and current_hour == settings.payout_hour_utc:
                should_payout = True
        
        if not should_payout:
            continue
        
        # Check if already processed today
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        existing_payout = Payout.objects.filter(
            provider=settings.provider,
            method__in=['weekly', 'monthly'],
            created_at__gte=today_start,
        ).exists()
        
        if existing_payout:
            continue
        
        # Get wallet balance
        wallets = ProviderWallet.objects.filter(
            provider=settings.provider,
            available_balance__gt=Decimal('0'),
        )
        
        for wallet in wallets:
            # Check minimum payout amount
            if wallet.available_balance < settings.minimum_payout_amount:
                continue
            
            # Calculate fee (0% for scheduled payouts)
            gross_amount = wallet.available_balance
            fee_amount = Decimal('0.00')
            net_amount = gross_amount - fee_amount
            
            # Create payout
            payout = Payout.objects.create(
                provider=settings.provider,
                currency=wallet.currency,
                gross_amount=gross_amount,
                fee_amount=fee_amount,
                net_amount=net_amount,
                method=settings.payout_frequency,
                status='queued',
            )
            
            # Process immediately
            process_single_payout.delay(payout.id)
            processed += 1
            
            # Update settings
            settings.last_auto_payout_at = now
            settings.reset_instant_payout_counter()
    
    logger.info(f"Created {processed} scheduled payouts")
    return {'processed': processed}


@shared_task
def release_pending_balances():
    """
    Release pending balances to available after hold period (e.g., 24-48 hours)
    """
    from core.models import WalletLedgerEntry, ProviderWallet
    
    # Find pending entries that should be released
    release_threshold = timezone.now() - timezone.timedelta(hours=24)
    
    pending_entries = WalletLedgerEntry.objects.filter(
        status='pending',
        created_at__lte=release_threshold,
    ).select_related('wallet')
    
    released = 0
    
    for entry in pending_entries:
        with transaction.atomic():
            wallet = ProviderWallet.objects.select_for_update().get(id=entry.wallet_id)
            
            # Move from pending to available
            wallet.pending_balance -= entry.amount
            wallet.available_balance += entry.amount
            wallet.save()
            
            # Update entry status
            entry.status = 'available'
            entry.available_at = timezone.now()
            entry.save()
            
            released += 1
    
    logger.info(f"Released {released} pending balances")
    return {'released': released}


@shared_task
def check_payout_status(payout_id: int):
    """
    Check and update status of a payout from Flutterwave
    """
    from core.models import Payout
    from core.utils.flutterwave_transfer import get_transfer_status
    
    try:
        payout = Payout.objects.get(id=payout_id)
    except Payout.DoesNotExist:
        return {'success': False, 'error': 'Payout not found'}
    
    if not payout.flutterwave_transfer_id:
        return {'success': False, 'error': 'No transfer ID'}
    
    result = get_transfer_status(int(payout.flutterwave_transfer_id))
    
    if result['success']:
        old_status = payout.flutterwave_status
        payout.flutterwave_status = result['status']
        
        if result['status'] in ('SUCCESSFUL', 'SUCCESS'):
            payout.status = 'paid'
            payout.processed_at = timezone.now()
        elif result['status'] == 'FAILED':
            payout.status = 'failed'
            payout.failure_reason = result.get('message', 'Transfer failed')
        
        payout.save()
        
        return {
            'success': True,
            'old_status': old_status,
            'new_status': payout.flutterwave_status,
        }
    
    return {'success': False, 'error': result.get('message')}


def _notify_provider_payout_success(payout):
    """Send notification to provider about successful payout"""
    from core.models import Notification
    
    try:
        Notification.objects.create(
            user=payout.provider.user,
            message=f"Your payout of {payout.net_amount} {payout.currency} has been processed successfully!",
        )
    except Exception as e:
        logger.error(f"Failed to notify provider about payout: {e}")


def _notify_provider_payout_failed(payout):
    """Send notification to provider about failed payout"""
    from core.models import Notification
    
    try:
        Notification.objects.create(
            user=payout.provider.user,
            message=f"Your payout of {payout.net_amount} {payout.currency} failed. Reason: {payout.failure_reason}. Please check your payout settings.",
        )
    except Exception as e:
        logger.error(f"Failed to notify provider about failed payout: {e}")