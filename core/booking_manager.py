# core\booking_manager.py


"""
Manages the real-time booking acceptance system with first-come-first-serve logic.
"""
import threading
from datetime import timedelta
from decimal import Decimal
from django.utils import timezone
from django.db import transaction
from django.core.cache import cache
from django.db.models import Q
from geopy.distance import geodesic

class BookingManager:
    """
    Manages concurrent booking acceptance with locking mechanism.
    Uses cache for distributed locks across multiple servers.
    """
    
    PENALTY_PERCENT = Decimal('0.10')  # 10% penalty
    
    @staticmethod
    def can_provider_accept_request(provider, service_request, max_distance_miles=15):
        """
        Check if provider can accept this request.
        Returns (can_accept: bool, reason: str)
        """
        # 1. Check if request is already accepted
        if service_request.service_provider is not None:
            return False, "Request already accepted by another provider."
        
        # 2. Check if request is paid
        if service_request.payment_status != 'paid':
            return False, "Request is not paid yet."
        
        # 3. Check if request is pending
        if service_request.status != 'pending':
            return False, f"Request status is {service_request.status}, not pending."
        
        # 4. Check 15-mile radius
        if (provider.location_latitude is None or 
            provider.location_longitude is None or
            service_request.location_latitude is None or
            service_request.location_longitude is None):
            return False, "Location data missing."
        
        provider_location = (provider.location_latitude, provider.location_longitude)
        user_location = (service_request.location_latitude, service_request.location_longitude)
        
        distance_km = geodesic(provider_location, user_location).km
        distance_miles = distance_km * 0.621371
        
        if distance_miles > max_distance_miles:
            return False, f"You are {distance_miles:.1f} miles away (limit: {max_distance_miles} miles)."
        
        # 5. Check if provider is available
        if not provider.available:
            return False, "You are not currently available for new requests."
        
        return True, ""

    @staticmethod
    def attempt_accept_request(provider, service_request_id):
        """
        Attempt to accept a request with thread-safe locking.
        Returns (success: bool, request: ServiceRequest, message: str)
        """
        # Create a lock key for this specific request
        lock_key = f"accept_lock_{service_request_id}"
        
        # Try to acquire lock with 5-second timeout
        lock_acquired = cache.add(lock_key, "locked", timeout=5)
        
        if not lock_acquired:
            return False, None, "Another provider is currently accepting this request. Please try again."
        
        try:
            with transaction.atomic():
                # Use select_for_update to lock the row
                service_request = ServiceRequest.objects.select_for_update().get(
                    id=service_request_id
                )
                
                # Double-check all conditions
                can_accept, reason = BookingManager.can_provider_accept_request(
                    provider, service_request
                )
                
                if not can_accept:
                    return False, service_request, reason
                
                # All checks passed - accept the request
                service_request.service_provider = provider
                service_request.status = 'accepted'
                service_request.accepted_at = timezone.now()
                service_request.save()
                
                return True, service_request, "Request accepted successfully!"
                
        except ServiceRequest.DoesNotExist:
            return False, None, "Request not found."
        except Exception as e:
            return False, None, f"Error accepting request: {str(e)}"
        finally:
            # Release the lock
            cache.delete(lock_key)

    @staticmethod
    def calculate_cancellation_penalty(service_request):
        """
        Calculate penalty if user cancels after 7 minutes.
        Returns (penalty_applies: bool, penalty_amount: Decimal)
        """
        if not service_request.accepted_at:
            return False, Decimal('0.00')
        
        # Calculate if more than 7 minutes have passed
        seven_minutes = timedelta(minutes=7)
        free_cancel_deadline = service_request.accepted_at + seven_minutes
        
        if timezone.now() <= free_cancel_deadline:
            return False, Decimal('0.00')
        
        # Calculate penalty (10% of offered price)
        price = service_request.offered_price or service_request.estimated_price
        if not price:
            return False, Decimal('0.00')
        
        penalty_amount = price * BookingManager.PENALTY_PERCENT
        penalty_amount = penalty_amount.quantize(Decimal('0.01'))
        
        return True, penalty_amount

    @staticmethod
    def get_nearby_requests_for_provider(provider, max_distance_miles=15):
        """
        Get all pending requests within max_distance_miles from provider.
        """
        from .models import ServiceRequest
        
        if (provider.location_latitude is None or 
            provider.location_longitude is None):
            return []
        
        provider_location = (provider.location_latitude, provider.location_longitude)
        
        # Get all pending, paid requests without provider
        pending_requests = ServiceRequest.objects.filter(
            status='pending',
            payment_status='paid',
            service_provider__isnull=True
        )
        
        nearby_requests = []
        for request in pending_requests:
            if (request.location_latitude is None or 
                request.location_longitude is None):
                continue
            
            user_location = (request.location_latitude, request.location_longitude)
            distance_km = geodesic(provider_location, user_location).km
            distance_miles = distance_km * 0.621371
            
            if distance_miles <= max_distance_miles:
                # Add distance to request object for display
                request.distance_miles = distance_miles
                nearby_requests.append(request)
        
        # Sort by distance (closest first)
        nearby_requests.sort(key=lambda x: x.distance_miles)
        return nearby_requests