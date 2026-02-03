# core/utils/booking_cleanup.py

"""
Utility functions for automatic booking cleanup.
These run "lazily" when bookings are fetched, avoiding the need for cron jobs.
"""

import logging
from datetime import timedelta
from django.utils import timezone
from django.db import transaction

logger = logging.getLogger(__name__)

# Configuration
UNPAID_BOOKING_TIMEOUT_HOURS = 48


def cancel_stale_unpaid_bookings(user=None):
    """
    Cancel bookings left unpaid for more than UNPAID_BOOKING_TIMEOUT_HOURS.
    
    This function is designed to be called from views when fetching bookings,
    providing "lazy" cleanup without needing cron jobs.
    
    Args:
        user: Optional - if provided, only check this user's bookings.
              If None, checks all users' bookings (use sparingly).
    
    Returns:
        int: Number of bookings cancelled
    """
    from core.models import ServiceRequest, Notification
    
    cutoff_time = timezone.now() - timedelta(hours=UNPAID_BOOKING_TIMEOUT_HOURS)
    
    # Build the query
    queryset = ServiceRequest.objects.filter(
        payment_status='unpaid',
        status='pending',
        request_time__lt=cutoff_time,
    )
    
    # If user is provided, only check their bookings
    if user is not None:
        queryset = queryset.filter(user=user)
    
    # Limit to prevent performance issues (process max 50 at a time)
    stale_bookings = queryset[:50]
    
    cancelled_count = 0
    
    for booking in stale_bookings:
        try:
            with transaction.atomic():
                # Re-fetch with lock to prevent race conditions
                locked_booking = ServiceRequest.objects.select_for_update().get(
                    pk=booking.pk,
                    payment_status='unpaid',
                    status='pending',
                )
                
                locked_booking.status = 'cancelled'
                locked_booking.cancelled_at = timezone.now()
                locked_booking.cancelled_by = 'system'
                locked_booking.save(update_fields=['status', 'cancelled_at', 'cancelled_by'])
                
                # Calculate how long it was unpaid
                hours_unpaid = (timezone.now() - locked_booking.request_time).total_seconds() / 3600
                
                # Notify the user
                Notification.objects.create(
                    user=locked_booking.user,
                    message=(
                        f"Your booking #{locked_booking.id} for {locked_booking.service_type} "
                        f"has been automatically cancelled because it was left unpaid for "
                        f"more than {UNPAID_BOOKING_TIMEOUT_HOURS} hours."
                    ),
                )
                
                cancelled_count += 1
                logger.info(
                    f"Auto-cancelled stale unpaid booking #{locked_booking.id} "
                    f"(unpaid for {hours_unpaid:.1f} hours)"
                )
                
        except ServiceRequest.DoesNotExist:
            # Booking was already modified by another process
            continue
        except Exception as e:
            logger.error(f"Failed to auto-cancel booking #{booking.id}: {e}")
            continue
    
    if cancelled_count > 0:
        logger.info(f"Auto-cancelled {cancelled_count} stale unpaid booking(s)")
    
    return cancelled_count


def get_booking_staleness_warning(booking):
    """
    Check if an unpaid booking is approaching the auto-cancel deadline.
    
    Args:
        booking: ServiceRequest instance
        
    Returns:
        dict or None: Warning info if booking is close to being cancelled
    """
    if booking.payment_status != 'unpaid' or booking.status != 'pending':
        return None
    
    age_hours = (timezone.now() - booking.request_time).total_seconds() / 3600
    hours_remaining = UNPAID_BOOKING_TIMEOUT_HOURS - age_hours
    
    if hours_remaining <= 0:
        return {
            'level': 'critical',
            'message': 'This booking will be cancelled very soon due to non-payment.',
            'hours_remaining': 0,
        }
    elif hours_remaining <= 6:
        return {
            'level': 'warning',
            'message': f'This booking will be auto-cancelled in {hours_remaining:.0f} hours if not paid.',
            'hours_remaining': hours_remaining,
        }
    elif hours_remaining <= 24:
        return {
            'level': 'info',
            'message': f'Please complete payment within {hours_remaining:.0f} hours to avoid cancellation.',
            'hours_remaining': hours_remaining,
        }
    
    return None