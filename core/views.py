# core/views.py

from decimal import Decimal
import json
import random

from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.db.models import Sum, Q
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.utils import timezone
from django.views.generic import TemplateView
from geopy.distance import geodesic
from rest_framework import viewsets, serializers
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from twilio.rest import Client

from datetime import timedelta

import stripe

from .models import (
    CustomUser,
    ServiceProvider,
    ServiceRequest,
    Review,
    Notification,
    MFACode,
    ChatThread,
    ChatMessage,
    SupportThread,
    SupportMessage,
)
from .serializers import (
    UserSerializer,
    ServiceProviderSerializer,
    ServiceRequestSerializer,
    ReviewSerializer,
    ChatThreadSerializer,
    ChatMessageSerializer,
    SupportThreadSerializer,
    SupportMessageSerializer,
)

# Penalty: 10% of offered_price if user cancels > 7 minutes after acceptance
USER_LATE_CANCEL_PENALTY_PERCENT = Decimal('0.10')


# -------------------------------
# Public Home and Dashboard Views
# -------------------------------

def is_admin_user(user):
    """
    Return True if this user is allowed to access the Styloria admin dashboard
    and admin-only APIs.
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
    Public landing page for the application.
    """
    return render(request, 'core/home.html')


@user_passes_test(is_admin_user)
def admin_dashboard(request):
    """
    Custom Styloria admin dashboard.
    """
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
    Protected dashboard page showing user-specific information.
    """
    user_notifications = []  # you can expand this

    context = {
        'user': request.user,
        'notifications': user_notifications,
        'page_title': 'Dashboard',
    }
    return render(request, 'core/dashboard.html', context)


class DashboardView(LoginRequiredMixin, TemplateView):
    """
    Alternative class-based dashboard view (optional).
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


# ----------------
# USER VIEWSET
# ----------------

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


# -------------------------
# SERVICE PROVIDER VIEWSET
# -------------------------

class ServiceProviderViewSet(viewsets.ModelViewSet):
    queryset = ServiceProvider.objects.all()
    serializer_class = ServiceProviderSerializer
    permission_classes = [IsAuthenticated]

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
            serializer = self.get_serializer(
                data=request.data,
                context={'request': request},
            )

        serializer.is_valid(raise_exception=True)
        provider = serializer.save()
        return Response(self.get_serializer(provider).data)


# -------------------------
# SERVICE REQUEST VIEWSET
# -------------------------

class ServiceRequestViewSet(viewsets.ModelViewSet):
    queryset = ServiceRequest.objects.all()
    serializer_class = ServiceRequestSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Limit which bookings each user can see:
        - Normal user: only their own bookings.
        - Provider: bookings assigned to them.
        - Admin/staff: all bookings.
        """
        user = self.request.user
        if user.is_staff or getattr(user, 'role', '') == 'admin':
            return ServiceRequest.objects.all()

        return ServiceRequest.objects.filter(
            Q(user=user) |
            Q(service_provider__user=user)
        )

    def perform_create(self, serializer):
        """
        When a new service request is created:
        - Compute estimated_price based on nearest available provider's price_per_km.
        - Do NOT assign a provider yet (service_provider remains None).
        - payment_status stays "unpaid" until payment succeeds.
        """
        user_lat = serializer.validated_data['location_latitude']
        user_lng = serializer.validated_data['location_longitude']
        user_location = (user_lat, user_lng)

        nearest_provider = None
        min_distance = None  # Decimal

        for provider in ServiceProvider.objects.filter(available=True):
            if provider.location_latitude is None or provider.location_longitude is None:
                continue

            provider_location = (provider.location_latitude, provider.location_longitude)
            distance_km_float = geodesic(user_location, provider_location).km
            distance_km = Decimal(str(distance_km_float))

            if min_distance is None or distance_km < min_distance:
                min_distance = distance_km
                nearest_provider = provider

        estimated_price = None
        if nearest_provider and min_distance is not None:
            estimated_price = min_distance * nearest_provider.price_per_km

        serializer.save(
            user=self.request.user,
            estimated_price=estimated_price,
            service_provider=None,
        )

    def update(self, request, *args, **kwargs):
        # Save the old status
        instance = self.get_object()
        old_status = instance.status

        # Perform the update
        response = super().update(request, *args, **kwargs)

        # Get the updated instance & status
        service_request = self.get_object()
        new_status = service_request.status

        # If just completed, set completed_at once
        if old_status != 'completed' and new_status == 'completed' and service_request.completed_at is None:
            service_request.completed_at = timezone.now()
            service_request.save(update_fields=['completed_at'])

        # Send a notification if the status has changed
        if old_status != new_status:
            channel_layer = get_channel_layer()

            ws_message = {
                'type': 'service_request_update',
                'service_request_id': service_request.id,
                'old_status': old_status,
                'new_status': new_status,
            }

            # Notification for the user (customer)
            Notification.objects.create(
                user=service_request.user,
                message=f"Your booking #{service_request.id} status changed from {old_status} to {new_status}.",
            )
            user_room_group = f'notifications_{service_request.user.id}'
            async_to_sync(channel_layer.group_send)(
                user_room_group,
                {
                    'type': 'send_notification',
                    'message': ws_message,
                }
            )

            # Notification for the provider (if exists)
            if service_request.service_provider:
                Notification.objects.create(
                    user=service_request.service_provider.user,
                    message=f"Booking #{service_request.id} assigned to you changed from {old_status} to {new_status}.",
                )
                provider_room_group = f'notifications_{service_request.service_provider.user.id}'
                async_to_sync(channel_layer.group_send)(
                    provider_room_group,
                    {
                        'type': 'send_notification',
                        'message': ws_message,
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

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def open_jobs(self, request):
        """
        GET /api/service_requests/open_jobs/
        For providers: list all PAID requests that do not yet have a provider,
        and are within ~15 miles (~24.14 km) of the provider's location.
        """
        try:
            provider = ServiceProvider.objects.get(user=request.user, available=True)
        except ServiceProvider.DoesNotExist:
            return Response({'detail': 'You are not an available provider'}, status=400)

        if provider.location_latitude is None or provider.location_longitude is None:
            return Response(
                {'detail': 'Please set your provider location before viewing open jobs.'},
                status=400,
            )

        provider_location = (provider.location_latitude, provider.location_longitude)

        # Candidate jobs: paid, pending, no provider yet
        candidates = ServiceRequest.objects.filter(
            payment_status='paid',
            status='pending',
            service_provider__isnull=True,
        ).order_by('-request_time')

        max_distance_km = Decimal('24.14')  # ≈ 15 miles
        nearby_jobs = []

        for job in candidates:
            user_location = (job.location_latitude, job.location_longitude)
            distance_km_float = geodesic(provider_location, user_location).km
            distance_km = Decimal(str(distance_km_float))

            if distance_km <= max_distance_km:
                nearby_jobs.append(job)

        serializer = self.get_serializer(nearby_jobs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def accept(self, request, pk=None):
        """
        POST /api/service_requests/{id}/accept/
        Called by a provider to claim a paid, waiting job.
        First provider to succeed gets it (atomic).
        """
        try:
            provider = ServiceProvider.objects.get(user=request.user)
        except ServiceProvider.DoesNotExist:
            return Response({'detail': 'You are not a provider'}, status=400)

        with transaction.atomic():
            try:
                service_request = ServiceRequest.objects.select_for_update().get(pk=pk)
            except ServiceRequest.DoesNotExist:
                return Response({'detail': 'Request not found.'}, status=404)

            if service_request.payment_status != 'paid':
                return Response({'detail': 'Request is not paid yet.'}, status=400)

            if service_request.service_provider is not None or service_request.status != 'pending':
                return Response({'detail': 'Request already accepted by another provider.'}, status=400)

            service_request.service_provider = provider
            service_request.status = 'accepted'
            service_request.accepted_at = timezone.now()
            service_request.save()

        serializer = self.get_serializer(service_request)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def set_offered_price(self, request, pk=None):
        """
        POST /api/service_requests/{id}/set_offered_price/
        Body: { "offered_price": 25.50 }

        Only the request owner can call this.
        Marks payment_status='paid' and stores offered_price.
        """
        service_request = self.get_object()

        if service_request.user != request.user:
            return Response({'detail': 'You do not own this request.'}, status=403)

        if service_request.payment_status == 'paid':
            return Response({'detail': 'This request is already marked as paid.'}, status=400)

        offered_price = request.data.get('offered_price')
        if offered_price is None:
            return Response({'detail': 'offered_price is required.'}, status=400)

        try:
            offered_decimal = Decimal(str(offered_price))
        except Exception:
            return Response({'detail': 'Invalid offered_price.'}, status=400)

        if offered_decimal <= 0:
            return Response({'detail': 'offered_price must be positive.'}, status=400)

        service_request.offered_price = offered_decimal
        service_request.payment_status = 'paid'
        service_request.save()

        serializer = self.get_serializer(service_request)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def cancel(self, request, pk=None):
        """
        POST /api/service_requests/{id}/cancel/
        Called by the user or the provider to cancel a booking.

        Rules (user side):
        - If user cancels BEFORE acceptance or while still 'pending' -> no penalty.
        - If user cancels AFTER acceptance:
            * Free if within the first 7 minutes (early window).
            * Penalty if between 7 and 40 minutes after acceptance.
            * Free again if 40+ minutes have passed since acceptance.
        - Provider cancellation -> no penalty to user here (in a full Stripe
          flow, user would be refunded).

        Money flow (refund/transfer) is not implemented here; we only record
        penalty info.
        """
        service_request = self.get_object()
        user = request.user

        if service_request.status == 'cancelled':
            return Response({'detail': 'Request is already cancelled.'}, status=400)

        if service_request.status == 'completed':
            return Response({'detail': 'Completed requests cannot be cancelled.'}, status=400)

        # Identify actor (user or provider)
        actor = None
        if user == service_request.user:
            actor = 'user'
        elif service_request.service_provider and service_request.service_provider.user == user:
            actor = 'provider'

        if actor is None:
            return Response({'detail': 'You are not part of this booking.'}, status=403)

        now = timezone.now()
        penalty_amount = Decimal('0')

        if actor == 'user':
            # If not yet accepted or still pending -> no penalty
            if service_request.service_provider is None or service_request.status == 'pending':
                penalty_amount = Decimal('0')
            else:
                # accepted / in_progress -> check penalty windows
                if not service_request.can_user_cancel_without_penalty():
                    if service_request.offered_price:
                        penalty_amount = (
                            service_request.offered_price * USER_LATE_CANCEL_PENALTY_PERCENT
                        ).quantize(Decimal('0.01'))
        else:
            # Provider cancellation -> no penalty to user here
            penalty_amount = Decimal('0')

        service_request.status = 'cancelled'
        service_request.cancelled_at = now
        service_request.cancelled_by = actor

        if penalty_amount > 0:
            service_request.penalty_applied = True
            service_request.penalty_amount = penalty_amount
        else:
            service_request.penalty_applied = False
            service_request.penalty_amount = None

        service_request.save()

        # NOTE: In a real Stripe integration, here you would:
        # - Refund (offered_price - penalty_amount) to the user.
        # - Transfer penalty_amount to the provider if actor == 'user' and penalty > 0.

        serializer = self.get_serializer(service_request)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def confirm_completion(self, request, pk=None):
        """
        POST /api/service_requests/{id}/confirm_completion/
        Called by user OR provider to confirm that service is done.

        Logic:
        - If user calls -> user_confirmed_completion = True
        - If provider calls -> provider_confirmed_completion = True
        - When BOTH are True:
            - status becomes 'completed'
            - completed_at is set (if not already)
            - Booking is now READY for payout, but payout_released remains False.
              Admin releases payout via separate tooling.
        """
        service_request = self.get_object()
        user = request.user

        if service_request.status == 'cancelled':
            return Response({'detail': 'Cancelled bookings cannot be completed.'}, status=400)

        if service_request.payment_status != 'paid':
            return Response({'detail': 'Booking is not paid yet.'}, status=400)

        # Identify who is confirming
        if user == service_request.user:
            service_request.user_confirmed_completion = True
        elif service_request.service_provider and service_request.service_provider.user == user:
            service_request.provider_confirmed_completion = True
        else:
            return Response({'detail': 'You are not part of this booking.'}, status=403)

        # If both have confirmed, mark as completed (ready for payout)
        if service_request.user_confirmed_completion and service_request.provider_confirmed_completion:
            service_request.status = 'completed'
            if service_request.completed_at is None:
                service_request.completed_at = timezone.now()
            # NOTE: payout_released stays False here.
            # Admin uses /api/admin/payouts/ endpoints to release payouts.

        service_request.save()

        serializer = self.get_serializer(service_request)
        return Response(serializer.data)

    @action(detail=True, methods=['get'], permission_classes=[IsAuthenticated])
    def contact_info(self, request, pk=None):
        """
        GET /api/service_requests/{id}/contact_info/
        Return the other party's name and phone number, but only if:
        - current user is either the booking user or the assigned provider
        - chat/call is allowed (based on status and completed_at)
        """
        service_request = self.get_object()

        # Check participant
        provider_user = (
            service_request.service_provider.user
            if service_request.service_provider
            else None
        )
        if request.user not in (service_request.user, provider_user):
            return Response({'detail': 'You are not part of this booking.'}, status=403)

        # Check status/time window
        if not service_request.is_chat_allowed():
            return Response(
                {
                    'detail': (
                        'Chat and calls are only available when the booking is '
                        'accepted, in progress, or completed within the last day.'
                    )
                },
                status=400,
            )

        # Determine counterpart
        if request.user == service_request.user:
            if not provider_user:
                return Response({'detail': 'No provider assigned yet.'}, status=400)
            counterpart = provider_user
        else:
            # current user is provider -> counterpart is booking user
            counterpart = service_request.user

        if not counterpart.phone_number:
            return Response(
                {'detail': 'The other user has no phone number on file.'},
                status=400,
            )

        return Response(
            {
                'name': counterpart.username,
                'phone_number': counterpart.phone_number,
            }
        )


# -------------------------
# CHAT THREAD VIEWSET
# -------------------------

class ChatThreadViewSet(viewsets.ModelViewSet):
    """
    Manages chat threads and messages tied to service requests.
    """
    queryset = ChatThread.objects.all()
    serializer_class = ChatThreadSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return ChatThread.objects.filter(
            Q(service_request__user=user) |
            Q(service_request__service_provider__user=user)
        ).select_related(
            'service_request',
            'service_request__user',
            'service_request__service_provider__user',
        ).order_by('-id')

    def create(self, request, *args, **kwargs):
        # We don't allow arbitrary creation; use /api/chats/for_request/{id}/
        return Response(
            {'detail': 'Use /api/chats/for_request/<service_request_id>/'},
            status=405,
        )

    @action(detail=False, methods=['get'], url_path='for_request/(?P<request_id>[^/.]+)')
    def for_request(self, request, request_id=None):
        """
        GET /api/chats/for_request/<service_request_id>/
        Get or create the chat thread for this booking, if user is a participant
        and chat is allowed by the booking rules.
        """
        try:
            service_request = ServiceRequest.objects.get(id=request_id)
        except ServiceRequest.DoesNotExist:
            return Response({'detail': 'Invalid service_request_id.'}, status=400)

        provider_user = (
            service_request.service_provider.user
            if service_request.service_provider
            else None
        )
        if request.user not in (service_request.user, provider_user):
            return Response({'detail': 'You are not part of this booking.'}, status=403)

        if not service_request.is_chat_allowed():
            return Response(
                {
                    'detail': (
                        'Chat is only available when the booking is accepted, '
                        'in progress, or completed within the last day.'
                    )
                },
                status=400,
            )

        thread, created = ChatThread.objects.get_or_create(service_request=service_request)
        serializer = self.get_serializer(thread)
        return Response(serializer.data)

    @action(detail=True, methods=['get', 'post'])
    def messages(self, request, pk=None):
        """
        GET  /api/chats/{id}/messages/  -> list messages
        POST /api/chats/{id}/messages/ -> send message { "content": "..." }
        """
        thread = self.get_object()
        service_request = thread.service_request

        provider_user = (
            service_request.service_provider.user
            if service_request.service_provider
            else None
        )
        if request.user not in (service_request.user, provider_user):
            return Response({'detail': 'You are not part of this chat.'}, status=403)

        if not service_request.is_chat_allowed():
            return Response(
                {
                    'detail': (
                        'Chat is only available when the booking is accepted, '
                        'in progress, or completed within the last day.'
                    )
                },
                status=400,
            )

        if request.method == 'GET':
            qs = ChatMessage.objects.filter(thread=thread).select_related('sender').order_by('created_at')
            serializer = ChatMessageSerializer(qs, many=True)
            return Response(serializer.data)

        # POST: create message
        content = request.data.get('content', '')
        serializer = ChatMessageSerializer(
            data={'content': content},
            context={'request': request, 'thread': thread},
        )
        serializer.is_valid(raise_exception=True)
        msg = serializer.save()
        return Response(ChatMessageSerializer(msg).data, status=201)


# -------------------------
# SUPPORT CHAT VIEWSET
# -------------------------

class SupportThreadViewSet(viewsets.ModelViewSet):
    """
    One support thread per user for chatting with customer service.
    Admin/staff can see all threads; normal users only see their own.
    """
    queryset = SupportThread.objects.all()
    serializer_class = SupportThreadSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_staff or getattr(user, 'role', '') == 'admin':
            return SupportThread.objects.select_related('user').order_by('-id')
        return SupportThread.objects.filter(user=user).select_related('user').order_by('-id')

    def create(self, request, *args, **kwargs):
        # We don't allow arbitrary creation; use /api/support_chats/my_thread/
        return Response(
            {'detail': 'Use /api/support_chats/my_thread/ to access your support chat.'},
            status=405,
        )

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def my_thread(self, request):
        """
        GET /api/support_chats/my_thread/
        Get or create the single support thread for the current user.
        """
        thread, created = SupportThread.objects.get_or_create(user=request.user)
        serializer = self.get_serializer(thread)
        return Response(serializer.data)

    @action(detail=True, methods=['get', 'post'], permission_classes=[IsAuthenticated])
    def messages(self, request, pk=None):
        """
        GET  /api/support_chats/{id}/messages/  -> list messages
        POST /api/support_chats/{id}/messages/ -> send message { "content": "..." }
        """
        thread = self.get_object()
        user = request.user

        # User can only access their own thread unless they are admin/staff
        if thread.user != user and not (user.is_staff or getattr(user, 'role', '') == 'admin'):
            return Response({'detail': 'You are not allowed to access this chat.'}, status=403)

        if request.method == 'GET':
            qs = SupportMessage.objects.filter(thread=thread).select_related('sender').order_by('created_at')
            serializer = SupportMessageSerializer(qs, many=True)
            return Response(serializer.data)

        # POST: create message
        content = request.data.get('content', '')
        serializer = SupportMessageSerializer(
            data={'content': content},
            context={'request': request, 'thread': thread},
        )
        serializer.is_valid(raise_exception=True)
        msg = serializer.save()
        return Response(SupportMessageSerializer(msg).data, status=201)


# -------------------------
# REVIEW VIEWSET
# -------------------------

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


# -------------------------
# STRIPE PAYMENT INTENT
# -------------------------

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_payment(request):
    """
    Create a Stripe PaymentIntent for a given service_request_id.

    Behavior:
    - If "offered_price" is provided in the body, use that amount.
    - Otherwise, if offered_price is already stored on the request, use that.
    - Otherwise, fall back to estimated_price.
    """
    stripe.api_key = settings.STRIPE_SECRET_KEY
    service_request_id = request.data.get('service_request_id')

    try:
        service_request = ServiceRequest.objects.get(id=service_request_id)
    except ServiceRequest.DoesNotExist:
        return Response({"error": "Invalid service_request_id"}, status=400)

    offered_override = request.data.get('offered_price')

    amount_source = None

    if offered_override is not None:
        try:
            amount_source = Decimal(str(offered_override))
        except Exception:
            return Response({"error": "Invalid offered_price"}, status=400)
    else:
        amount_source = service_request.offered_price or service_request.estimated_price

    if amount_source is None:
        return Response({"error": "This booking has no price set"}, status=400)

    if amount_source <= 0:
        return Response({"error": "Amount must be positive"}, status=400)

    amount_cents = int(amount_source * 100)

    try:
        payment_intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency='usd',
            payment_method_types=['card'],
        )
    except stripe.error.StripeError as e:
        return Response({"error": str(e)}, status=400)

    return Response({'client_secret': payment_intent['client_secret']})


# -------------------------
# NOTIFICATIONS
# -------------------------

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


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def unread_count(request):
    user = request.user
    count = Notification.objects.filter(user=user, read=False).count()
    return Response({"unread_count": count})


# -------------------
# ADMIN PAYOUT TOOLING
# -------------------

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_pending_payouts(request):
    """
    GET /api/admin/payouts/pending/
    Admin-only. Returns all paid & completed bookings where payout_released=False.
    """
    if not is_admin_user(request.user):
        return Response({'detail': 'Admin access required.'}, status=403)

    qs = ServiceRequest.objects.filter(
        payment_status='paid',
        status='completed',
        payout_released=False,
        user_confirmed_completion=True,
        provider_confirmed_completion=True,
    ).order_by('-completed_at')

    serializer = ServiceRequestSerializer(qs, many=True)
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def admin_release_payout(request, pk):
    """
    POST /api/admin/payouts/<id>/release/
    Admin-only. Marks payout_released=True and sets payout_released_at.
    In a real integration, you would trigger a Stripe Transfer/Connect payout here.
    """
    if not is_admin_user(request.user):
        return Response({'detail': 'Admin access required.'}, status=403)

    try:
        service_request = ServiceRequest.objects.get(
            id=pk,
            payment_status='paid',
            status='completed',
            payout_released=False,
        )
    except ServiceRequest.DoesNotExist:
        return Response(
            {'detail': 'No eligible booking found for this id.'},
            status=404,
        )

    service_request.payout_released = True
    service_request.payout_released_at = timezone.now()
    service_request.save()

    serializer = ServiceRequestSerializer(service_request)
    return Response(serializer.data)


# -------------------------
# PROVIDER EARNINGS
# -------------------------

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def provider_earnings_summary(request):
    """
    GET /api/providers/earnings/summary/
    For providers: returns aggregated earnings for different time ranges.
    Uses offered_price of completed, paid, payout_released bookings.
    """
    try:
        provider = ServiceProvider.objects.get(user=request.user)
    except ServiceProvider.DoesNotExist:
        return Response({'detail': 'You are not a provider.'}, status=400)

    now = timezone.now()

    def sum_since(delta_days: int | None):
        qs = ServiceRequest.objects.filter(
            service_provider=provider,
            payment_status='paid',
            status='completed',
            payout_released=True,
        )
        if delta_days is not None:
            since = now - timedelta(days=delta_days)
            qs = qs.filter(completed_at__gte=since)
        agg = qs.aggregate(total=Sum('offered_price'))
        return float(agg['total'] or 0.0)

    data = {
        'currency': 'usd',
        'daily': sum_since(1),
        'weekly': sum_since(7),
        'monthly': sum_since(30),
        'yearly': sum_since(365),
        'all_time': sum_since(None),
    }
    return Response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def provider_earnings_report_pdf(request):
    """
    GET /api/providers/earnings/report/?period=daily|weekly|monthly|yearly|all
    Returns a simple PDF report with Styloria watermark.
    """
    try:
        provider = ServiceProvider.objects.get(user=request.user)
    except ServiceProvider.DoesNotExist:
        return Response({'detail': 'You are not a provider.'}, status=400)

    period = request.GET.get('period', 'all').lower()
    now = timezone.now()

    days_map = {
        'daily': 1,
        'weekly': 7,
        'monthly': 30,
        'yearly': 365,
        'all': None,
    }
    if period not in days_map:
        return Response({'detail': 'Invalid period. Use daily|weekly|monthly|yearly|all.'}, status=400)

    delta_days = days_map[period]

    qs = ServiceRequest.objects.filter(
        service_provider=provider,
        payment_status='paid',
        status='completed',
        payout_released=True,
    )
    if delta_days is not None:
        since = now - timedelta(days=delta_days)
        qs = qs.filter(completed_at__gte=since)

    agg = qs.aggregate(total=Sum('offered_price'))
    total = float(agg['total'] or 0.0)

    # Generate PDF
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # Watermark
    p.saveState()
    p.setFont("Helvetica-Bold", 40)
    p.setFillColorRGB(0.9, 0.9, 0.9)
    p.translate(width / 2, height / 2)
    p.rotate(45)
    p.drawCentredString(0, 0, "STYLORIA")
    p.restoreState()

    p.setFont("Helvetica-Bold", 18)
    p.drawString(50, height - 80, "Styloria Earnings Report")

    p.setFont("Helvetica", 12)
    p.drawString(50, height - 110, f"Provider: {provider.user.username}")
    p.drawString(50, height - 130, f"Period: {period}")
    p.drawString(50, height - 150, f"Generated at: {now.isoformat()}")

    p.drawString(50, height - 190, f"Total earnings (USD): {total:.2f}")
    p.drawString(50, height - 210,
                 "Only completed, paid bookings with payout released are included.")

    p.showPage()
    p.save()
    buffer.seek(0)

    response = HttpResponse(buffer.getvalue(), content_type='application/pdf')
    filename = f"styloria_earnings_{provider.user.username}_{period}.pdf"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


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

    code = f"{random.randint(0, 999999):06d}"
    expires_at = timezone.now() + timedelta(minutes=5)

    MFACode.objects.filter(user=user, used=False).update(used=True)

    MFACode.objects.create(
        user=user,
        code=code,
        expires_at=expires_at,
    )

    try:
        send_mfa_sms(user.phone_number, code)
    except Exception as e:
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

    mfa.used = True
    mfa.save()

    refresh = RefreshToken.for_user(user)
    access = str(refresh.access_token)

    return Response({
        "refresh": str(refresh),
        "access": access,
    })