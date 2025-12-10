# core/views.py

from decimal import Decimal
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.http import HttpResponse
import json

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from rest_framework import viewsets, serializers
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from datetime import timedelta

import random
from twilio.rest import Client

from django.db.models import Sum
from django.utils import timezone
from django.contrib.auth import get_user_model, authenticate
from geopy.distance import geodesic
import stripe
from django.conf import settings

from .models import CustomUser, ServiceProvider, ServiceRequest, Review, Notification, MFACode
from .serializers import UserSerializer, ServiceProviderSerializer, ServiceRequestSerializer, ReviewSerializer


# -------------------------------
# Public Home and Dashboard Views
# -------------------------------

def is_admin_user(user):
    """
    Return True if this user is allowed to access the Styloria admin dashboard.
    """
    return user.is_authenticated and (user.is_staff or getattr(user, 'role', '') == 'admin')

def send_mfa_sms(to_number: str, code: str):
    """
    Send MFA code via Twilio SMS.
    """
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    message_body = f"Your Styloria verification code is: {code}"
    client.messages.create(
        body=message_body,
        from_=settings.TWILIO_FROM_NUMBER,
        to=to_number,
    )

def home(request):
    """
    Public landing page for the application
    """
    return render(request, 'core/home.html')

@user_passes_test(is_admin_user)
def admin_dashboard(request):
    """
    Custom Styloria admin dashboard.
    """
    # Basic statistics
    total_users = CustomUser.objects.filter(role='user').count()
    total_providers = CustomUser.objects.filter(role='provider').count()
    total_admins = CustomUser.objects.filter(role='admin').count()

    total_bookings = ServiceRequest.objects.count()
    pending_bookings = ServiceRequest.objects.filter(status='pending').count()
    completed_bookings = ServiceRequest.objects.filter(status='completed').count()
    cancelled_bookings = ServiceRequest.objects.filter(status='cancelled').count()

    revenue_agg = ServiceRequest.objects.filter(
        status='completed',
        estimated_price__isnull=False
    ).aggregate(total=Sum('estimated_price'))
    total_revenue = revenue_agg['total'] or 0

    # Recent objects
    recent_bookings = ServiceRequest.objects.select_related('user', 'service_provider__user') \
        .order_by('-request_time')[:10]

    recent_users = CustomUser.objects.order_by('-date_joined')[:10]
    recent_reviews = Review.objects.select_related('user', 'service_provider__user') \
        .order_by('-created_at')[:10]

    context = {
        'total_users': total_users,
        'total_providers': total_providers,
        'total_admins': total_admins,
        'total_bookings': total_bookings,
        'pending_bookings': pending_bookings,
        'completed_bookings': completed_bookings,
        'cancelled_bookings': cancelled_bookings,
        'total_revenue': total_revenue,
        'recent_bookings': recent_bookings,
        'recent_users': recent_users,
        'recent_reviews': recent_reviews,
    }
    return render(request, 'core/admin_dashboard.html', context)

@login_required
def dashboard(request):
    """
    Protected dashboard page showing user-specific information
    """
    # Get recent notifications for the user (you can expand this)
    user_notifications = []

    context = {
        'user': request.user,
        'notifications': user_notifications,
        'page_title': 'Dashboard',
    }
    return render(request, 'core/dashboard.html', context)


class DashboardView(LoginRequiredMixin, TemplateView):
    """
    Alternative class-based dashboard view (optional)
    """
    template_name = 'core/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user
        context['page_title'] = 'Dashboard'
        context['websocket_url'] = f'/ws/notifications/{self.request.user.id}/'
        return context


# Get the user model (either default or custom)
User = get_user_model()


# USER VIEWSET: Handles user-related API operations
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]  # Adjust permission as needed

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def me(self, request):
        """
        Return the currently authenticated user's details.
        GET /api/users/me/
        """
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)


# SERVICE PROVIDER VIEWSET: Manages service provider data and availability
class ServiceProviderViewSet(viewsets.ModelViewSet):
    queryset = ServiceProvider.objects.all()
    serializer_class = ServiceProviderSerializer
    permission_classes = [IsAuthenticated]  # Only authenticated users can interact with service providers

    # Custom action to check the availability of a specific service provider
    @action(detail=True, methods=['get'])
    def availability(self, request, pk=None):
        provider = self.get_object()
        return Response({'available': provider.available})

    @action(detail=False, methods=['get', 'post'], permission_classes=[IsAuthenticated])
    def me(self, request):
        """
        GET  /api/service_providers/me/   -> return current user's provider profile (if exists)
        POST /api/service_providers/me/   -> create or update current user's provider profile
        """
        if request.method == 'GET':
            try:
                provider = ServiceProvider.objects.get(user=request.user)
            except ServiceProvider.DoesNotExist:
                return Response({'detail': 'No provider profile'}, status=404)

            serializer = self.get_serializer(provider)
            return Response(serializer.data)

        # POST: create or update
        try:
            provider = ServiceProvider.objects.get(user=request.user)
            serializer = self.get_serializer(
                provider,
                data=request.data,
                partial=True,
                context={'request': request},
            )
        except ServiceProvider.DoesNotExist:
            # create new
            serializer = self.get_serializer(
                data=request.data,
                context={'request': request},
            )

        serializer.is_valid(raise_exception=True)
        provider = serializer.save()
        return Response(self.get_serializer(provider).data)


# SERVICE REQUEST VIEWSET: Manages service requests, including distance and price estimation
class ServiceRequestViewSet(viewsets.ModelViewSet):
    queryset = ServiceRequest.objects.all()
    serializer_class = ServiceRequestSerializer
    permission_classes = [IsAuthenticated]  # Only authenticated users can create service requests

    # This method is called automatically when a new service request is created
    def perform_create(self, serializer):
        # Get the user's location from the request data
        user_lat = serializer.validated_data['location_latitude']
        user_lng = serializer.validated_data['location_longitude']
        user_location = (user_lat, user_lng)

        # Find the nearest available service provider
        nearest_provider = None
        min_distance = None  # store as Decimal

        for provider in ServiceProvider.objects.filter(available=True):
            # Skip providers without a location
            if provider.location_latitude is None or provider.location_longitude is None:
                continue

            provider_location = (provider.location_latitude, provider.location_longitude)

            # geodesic returns a float (km) – convert to Decimal for money math
            distance_km_float = geodesic(user_location, provider_location).km
            distance_km = Decimal(str(distance_km_float))

            if min_distance is None or distance_km < min_distance:
                min_distance = distance_km
                nearest_provider = provider

        # Estimate the price based on the distance and provider's price per km
        estimated_price = None
        if nearest_provider and min_distance is not None:
            estimated_price = min_distance * nearest_provider.price_per_km

        # Save the new service request with the user, the nearest provider, and the estimated price
        serializer.save(
            user=self.request.user,
            service_provider=nearest_provider,
            estimated_price=estimated_price,
        )

    def update(self, request, *args, **kwargs):
        # Save the old status
        old_status = self.get_object().status

        # Perform the update
        response = super().update(request, *args, **kwargs)

        # Get the updated status
        new_status = self.get_object().status

        # Send a notification if the status has changed
        if old_status != new_status:
            service_request = self.get_object()
            channel_layer = get_channel_layer()

            # Prepare websocket message
            ws_message = {
                'type': 'service_request_update',
                'service_request_id': service_request.id,
                'old_status': old_status,
                'new_status': new_status,
            }

            # Create DB notifications + send websockets for the user (customer)
            Notification.objects.create(
                user=service_request.user,
                message=f"Your booking #{service_request.id} status changed from {old_status} to {new_status}.",
            )
            user_room_group = f'notifications_{service_request.user.id}'
            async_to_sync(channel_layer.group_send)(
                user_room_group,
                {
                    'type': 'send_notification',
                    'message': ws_message
                }
            )

            # For the provider (if exists)
            if service_request.service_provider:
                Notification.objects.create(
                    user=service_request.service_provider.user,
                    message=f"Booking #{service_request.id} assigned to you changed from {old_status} to {new_status}.",
                )
                provider_room_group = (
                    f'notifications_{service_request.service_provider.user.id}'
                )
                async_to_sync(channel_layer.group_send)(
                    provider_room_group,
                    {
                        'type': 'send_notification',
                        'message': ws_message
                    }
                )

        return response

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def my_requests(self, request):
        """
        GET /api/service_requests/my_requests/
        Returns all requests created by the current user (customers).
        """
        qs = self.get_queryset().filter(user=request.user).order_by('-request_time')
        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def assigned_to_me(self, request):
        """
        GET /api/service_requests/assigned_to_me/
        Returns all requests assigned to the current provider.
        """
        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({'detail': 'You are not a provider'}, status=400)

        qs = self.get_queryset().filter(service_provider=provider).order_by('-request_time')
        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)

# REVIEW VIEWSET: Manages reviews
class ReviewViewSet(viewsets.ModelViewSet):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user = self.request.user
        provider_id = self.request.data.get('service_provider_id')

        try:
            provider = ServiceProvider.objects.get(id=provider_id)
        except ServiceProvider.DoesNotExist:
            raise serializers.ValidationError({"service_provider_id": "Invalid service provider ID"})

        serializer.save(user=user, service_provider=provider)

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def my_reviews(self, request):
        """
        GET /api/reviews/my_reviews/
        Returns reviews written by the current user.
        """
        qs = self.get_queryset().filter(user=request.user).order_by('-created_at')
        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)


# PAYMENT FUNCTION: Handle creating a Stripe payment intent for a service request
# PAYMENT FUNCTION: Handle creating a Stripe payment intent for a service request
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_payment(request):
    import stripe

    stripe.api_key = settings.STRIPE_SECRET_KEY
    service_request_id = request.data.get('service_request_id')

    try:
        service_request = ServiceRequest.objects.get(id=service_request_id)
    except ServiceRequest.DoesNotExist:
        return Response({"error": "Invalid service_request_id"}, status=400)

    if service_request.estimated_price is None:
        return Response({"error": "This booking has no estimated_price"}, status=400)

    # Convert Decimal amount (e.g. 25.50) to integer cents (2550)
    amount_cents = int(service_request.estimated_price * 100)

    try:
        payment_intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency='usd',
            payment_method_types=['card'],  # Explicitly use card in test mode
        )
    except stripe.error.StripeError as e:
        # Return the Stripe error message to the client for debugging
        return Response({"error": str(e)}, status=400)

    return Response({'client_secret': payment_intent['client_secret']})


# USER NOTIFICATIONS ENDPOINT
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_notifications(request):
    user = request.user
    notes = Notification.objects.filter(user=user).order_by("-created_at")

    data = [
        {
            "id": n.id,
            "message": n.message,
            "created_at": n.created_at,
            "read": n.read,
        }
        for n in notes
    ]

    return Response(data)


# NEW: MARK A NOTIFICATION AS READ
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def mark_as_read(request, pk):
    user = request.user
    try:
        note = Notification.objects.get(id=pk, user=user)
        note.read = True
        note.save()
        return Response({"status": "ok"})
    except Notification.DoesNotExist:
        return Response({"error": "not found"}, status=404)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_notifications(request):
    user = request.user
    notes = Notification.objects.filter(user=user).order_by("-id")
    data = [
        {
            "id": n.id,
            "message": n.message,
            "read": n.read,
            "timestamp": n.timestamp,
        }
        for n in notes
    ]
    return Response(data)


# COUNT UNREAD NOTIFICATIONS
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def unread_count(request):
    user = request.user
    count = Notification.objects.filter(user=user, read=False).count()
    return Response({"unread_count": count})

# -------------------
# MFA (Two-Factor) API
# -------------------

@api_view(['POST'])
@permission_classes([AllowAny])
def mfa_start(request):
    """
    Step 1 of login:
    - Check username & password.
    - Generate 6-digit code.
    - Send via SMS to user's phone_number using Twilio.
    - Return mfa_user_id used for the second step.
    """
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({"detail": "Username and password are required."}, status=400)

    user = authenticate(request, username=username, password=password)
    if not user or not user.is_active:
        return Response({"detail": "Invalid credentials."}, status=400)

    if not user.phone_number:
        return Response({"detail": "No phone number set for this user."}, status=400)

    # Generate 6-digit code
    code = f"{random.randint(0, 999999):06d}"
    expires_at = timezone.now() + timedelta(minutes=5)

    # Optional: invalidate old codes for this user
    MFACode.objects.filter(user=user, used=False).update(used=True)

    MFACode.objects.create(
        user=user,
        code=code,
        expires_at=expires_at,
    )

    try:
        send_mfa_sms(user.phone_number, code)
    except Exception as e:
        # In production you would log this error properly
        return Response({"detail": f"Failed to send SMS: {e}"}, status=500)

    return Response({
        "detail": "OTP sent via SMS.",
        "mfa_user_id": user.id,
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def mfa_verify(request):
    """
    Step 2 of login:
    - Receive user_id and code.
    - Validate MFACode.
    - Mark it used.
    - Return JWT access & refresh tokens.
    """
    user_id = request.data.get('user_id')
    code = request.data.get('code')

    if not user_id or not code:
        return Response({"detail": "user_id and code are required."}, status=400)

    try:
        user = CustomUser.objects.get(id=user_id)
    except CustomUser.DoesNotExist:
        return Response({"detail": "User not found."}, status=400)

    mfa = (
        MFACode.objects
        .filter(user=user, code=code, used=False)
        .order_by('-created_at')
        .first()
    )

    if not mfa or not mfa.is_valid():
        return Response({"detail": "Invalid or expired code."}, status=400)

    # Mark as used
    mfa.used = True
    mfa.save()

    # Issue JWT tokens
    refresh = RefreshToken.for_user(user)
    access = str(refresh.access_token)

    return Response({
        "refresh": str(refresh),
        "access": access,
    })