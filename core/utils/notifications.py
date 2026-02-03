# core/utils/notifications.py

from decimal import Decimal
import logging

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.utils import timezone

logger = logging.getLogger(__name__)


def send_websocket_notification(user, message, notification_type='info'):
    """
    Send real-time notification via WebSocket + save to DB.
    """
    from core.models import Notification
    
    # Save to database
    Notification.objects.create(
        user=user,
        message=message,
        read=False,
        timestamp=timezone.now()
    )
    
    # Send via WebSocket
    channel_layer = get_channel_layer()
    user_room_group = f'notifications_{user.id}'
    
    try:
        async_to_sync(channel_layer.group_send)(
            user_room_group,
            {
                'type': 'send_notification',
                'message': {
                    'type': notification_type,
                    'text': message,
                    'timestamp': timezone.now().isoformat()
                }
            }
        )
    except Exception:
        pass  # WebSocket might not be connected, that's okay


def notify_eligible_providers_of_new_job(service_request):
    """
    Notify all eligible providers when a new paid job becomes available.
    
    Eligibility criteria:
    - Provider offers the specific service type
    - Provider is within 15 miles (24.14 km) of the request location
    - Provider is available (available=True)
    - Provider is verified (verification_status="approved")
    - Provider matches tier requirements (if selected_tier is set)
    - Provider is not the requester themselves
    
    Args:
        service_request: The ServiceRequest instance that just became available
        
    Returns:
        int: Number of providers notified
    """
    from core.models import ServiceProvider
    from geopy.distance import geodesic
    from core.utils.trust_score import is_provider_eligible_for_tier
    
    # Validate service request has location
    if not service_request.location_latitude or not service_request.location_longitude:
        logger.warning(f"Service request {service_request.id} has no location - skipping provider notifications")
        return 0
    
    # Only notify for open, paid jobs
    if service_request.status != "open" or service_request.payment_status != "paid":
        logger.info(f"Service request {service_request.id} not open/paid - skipping notifications")
        return 0
    
    request_location = (service_request.location_latitude, service_request.location_longitude)
    service_type = service_request.service_type
    selected_tier = getattr(service_request, 'selected_tier', None)
    max_distance_km = Decimal("24.14")  # ≈ 15 miles
    
    # Find all potential providers
    providers = ServiceProvider.objects.filter(
        available=True,
        verification_status="approved",
        location_latitude__isnull=False,
        location_longitude__isnull=False,
    ).exclude(
        user=service_request.user  # Don't notify the requester if they're also a provider
    ).select_related('user')
    
    notified_count = 0
    
    for provider in providers:
        # Check if provider offers this service
        if provider.get_service_price(service_type) is None:
            continue
        
        # Check tier eligibility
        if selected_tier and not is_provider_eligible_for_tier(provider, selected_tier):
            continue
        
        # Check distance
        provider_location = (provider.location_latitude, provider.location_longitude)
        try:
            distance_km = Decimal(str(geodesic(provider_location, request_location).km))
        except Exception as e:
            logger.error(f"Error calculating distance for provider {provider.id}: {e}")
            continue
        
        if distance_km > max_distance_km:
            continue
        
        # Provider is eligible - send notification
        distance_miles = float(distance_km * Decimal("0.621371"))
        
        # Format service type for display
        service_display = service_type.replace('_', ' ').title()
        
        # Build notification message
        tier_info = ""
        if selected_tier:
            tier_badges = {
                'budget': '💚 Budget',
                'standard': '💙 Standard', 
                'premium': '💜 Premium'
            }
            tier_info = f" [{tier_badges.get(selected_tier, selected_tier.title())}]"
        
        # Format price if available
        price_info = ""
        if service_request.offered_price:
            currency_symbol = _get_currency_symbol(service_request.currency or "USD")
            price_info = f" • {currency_symbol}{service_request.offered_price:.2f}"
        
        message = (
            f"🆕 New Job{tier_info}: {service_display} "
            f"• {distance_miles:.1f} mi away{price_info}. "
            f"Open the app to view details and accept!"
        )
        
        # Send in-app notification (DB + WebSocket)
        try:
            send_websocket_notification(
                provider.user,
                message,
                notification_type='new_job_available'
            )
            notified_count += 1
            logger.info(f"Notified provider {provider.id} ({provider.user.username}) of new job #{service_request.id}")
        except Exception as e:
            logger.error(f"Failed to notify provider {provider.id}: {e}")
    
    logger.info(f"Notified {notified_count} eligible providers of new job #{service_request.id}")
    return notified_count


def _get_currency_symbol(currency_code: str) -> str:
    """Get currency symbol for notification display."""
    symbols = {
        'USD': '$',
        'GBP': '£',
        'EUR': '€',
        'GHS': 'GH₵',
        'NGN': '₦',
        'KES': 'KSh',
        'ZAR': 'R',
        'XOF': 'CFA',
        'XAF': 'CFA',
        'CAD': 'C$',
        'AUD': 'A$',
        'TZS': 'TSh',
        'UGX': 'USh',
        'RWF': 'FRw',
        'ZMW': 'ZK',
        'BWP': 'P',
        'MWK': 'MK',
        'ETB': 'Br',
        'MAD': 'DH',
        'EGP': 'E£',
    }
    return symbols.get(currency_code.upper(), currency_code + ' ')