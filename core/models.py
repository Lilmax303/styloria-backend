# core/models.py

from datetime import timedelta

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils import timezone

# --- BUSINESS RULE CONSTANTS ---

# Free cancel window immediately after acceptance
USER_FREE_CANCEL_BEFORE_MINUTES = 7

# When penalty window ends; after this time user can cancel free again
# (change to 35 if you prefer 35 minutes)
USER_FREE_CANCEL_AFTER_MINUTES = 40


# Custom user model (extends AbstractUser)
class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('user', 'User'),
        ('provider', 'Service Provider'),
        ('admin', 'Admin'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    date_of_birth = models.DateField(null=True, blank=True)  # required at signup

    def __str__(self):
        return self.username


# Service provider model (linked to a user)
class ServiceProvider(models.Model):
    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='provider_profile'
    )
    bio = models.TextField(blank=True)
    certification = models.FileField(upload_to='certifications/', blank=True, null=True)
    location_latitude = models.FloatField(null=True, blank=True)
    location_longitude = models.FloatField(null=True, blank=True)
    price_per_km = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    available = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username} (Provider)"


# Service request model (links user, service provider, and appointment details)
class ServiceRequest(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),        # created, waiting for provider
        ('accepted', 'Accepted'),      # accepted by a provider
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    )

    PAYMENT_STATUS_CHOICES = (
        ('unpaid', 'Unpaid'),
        ('paid', 'Paid'),
    )

    SERVICE_TYPE_CHOICES = (
        ('haircut', 'Haircut'),
        ('braids', 'Braids'),
        ('shave', 'Shave'),
        ('color', 'Hair Coloring'),
        ('other', 'Other'),
    )

    CANCELLED_BY_CHOICES = (
        ('user', 'User'),
        ('provider', 'Provider'),
        ('system', 'System'),
    )

    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='requests'
    )

    # Will be set only after a provider accepts the job
    service_provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='requests',
        null=True,
        blank=True,
    )

    request_time = models.DateTimeField(auto_now_add=True)
    appointment_time = models.DateTimeField()

    service_type = models.CharField(
        max_length=20,
        choices=SERVICE_TYPE_CHOICES,
        default='haircut',
    )
    notes = models.TextField(blank=True)

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
    )

    # When a provider accepted the job
    accepted_at = models.DateTimeField(null=True, blank=True)

    # When the request reached "completed" state
    completed_at = models.DateTimeField(null=True, blank=True)

    # System‑computed suggested price based on distance & provider price_per_km
    estimated_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
    )

    # Price the user agrees to pay (can be same as estimated_price or a different tier)
    offered_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
    )

    payment_status = models.CharField(
        max_length=20,
        choices=PAYMENT_STATUS_CHOICES,
        default='unpaid',
    )

    location_latitude = models.FloatField()
    location_longitude = models.FloatField()

    # Cancellation + penalty information
    cancelled_at = models.DateTimeField(null=True, blank=True)
    cancelled_by = models.CharField(
        max_length=20,
        choices=CANCELLED_BY_CHOICES,
        null=True,
        blank=True,
    )
    penalty_applied = models.BooleanField(default=False)
    penalty_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
    )

    # Dual completion confirmation
    user_confirmed_completion = models.BooleanField(default=False)
    provider_confirmed_completion = models.BooleanField(default=False)

    # Payout flag (admin "releases" payment to provider)
    payout_released = models.BooleanField(default=False)
    payout_released_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        provider_name = (
            self.service_provider.user.username
            if self.service_provider and self.service_provider.user
            else 'No provider yet'
        )
        return f"Request #{self.id} by {self.user.username} (provider: {provider_name})"

    def is_chat_allowed(self) -> bool:
        """
        Chat/call allowed when:
        - status is 'accepted' or 'in_progress', OR
        - status is 'completed' AND completed_at is within last 24 hours.
        """
        if self.status in ('accepted', 'in_progress'):
            return True

        if self.status == 'completed' and self.completed_at:
            return timezone.now() <= self.completed_at + timedelta(days=1)

        return False

    def user_cancel_deadline(self):
        """
        Returns the datetime until which the user can cancel WITHOUT penalty
        in the first free window after acceptance.

        Business rule: first free window ends USER_FREE_CANCEL_BEFORE_MINUTES
        minutes after provider accepts.
        """
        if not self.accepted_at:
            return None
        return self.accepted_at + timedelta(minutes=USER_FREE_CANCEL_BEFORE_MINUTES)

    def user_penalty_window_end(self):
        """
        Returns the datetime when the penalty window ends.

        Business rule: after USER_FREE_CANCEL_AFTER_MINUTES minutes from
        acceptance, user can cancel free again.
        """
        if not self.accepted_at:
          return None
        return self.accepted_at + timedelta(minutes=USER_FREE_CANCEL_AFTER_MINUTES)

    def can_user_cancel_without_penalty(self) -> bool:
        """
        True if user is allowed to cancel without penalty right now.

        Rules:
        - If status is not 'accepted' or 'in_progress'  -> always no penalty.
        - If accepted_at is missing                     -> no penalty.
        - Otherwise:
            * Free before accepted_at + 7 minutes.
            * Penalty between 7 and 40 minutes after acceptance.
            * Free again after 40 minutes from acceptance.
        """
        if self.status not in ('accepted', 'in_progress'):
            # Pending or already cancelled/completed -> no penalty concept
            return True

        if not self.accepted_at:
            # Should not happen in normal flow, but safest = no penalty
            return True

        now = timezone.now()
        early_deadline = self.user_cancel_deadline()
        late_deadline = self.user_penalty_window_end()

        # If we don't have deadlines for some reason, default to no penalty
        if early_deadline is None or late_deadline is None:
            return True

        # Free in first window OR after penalty window is over
        if now <= early_deadline or now >= late_deadline:
            return True

        # Inside penalty window
        return False


# Review model
class Review(models.Model):
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='reviews'
    )
    service_provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='reviews'
    )
    rating = models.IntegerField(
        choices=[(i, i) for i in range(1, 6)]  # Rating from 1 to 5
    )
    comment = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Review by {self.user.username} for {self.service_provider.user.username}"


# Notification model
class Notification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.message[:30]}"


# MFA Code model for SMS/email verification
class MFACode(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='mfa_codes'
    )
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    def is_valid(self):
        return (not self.used) and timezone.now() <= self.expires_at

    def __str__(self):
        return f"MFA for {self.user} - {self.code}"


# Chat thread tied to a single service request
class ChatThread(models.Model):
    service_request = models.OneToOneField(
        ServiceRequest,
        on_delete=models.CASCADE,
        related_name='chat_thread',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ChatThread for request #{self.service_request_id}"


# Individual chat messages (booking-specific)
class ChatMessage(models.Model):
    thread = models.ForeignKey(
        ChatThread,
        on_delete=models.CASCADE,
        related_name='messages',
    )
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='sent_messages',
    )
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Msg #{self.id} in thread {self.thread_id} by {self.sender}"


# Support chat: 1 thread per user talking to customer service
class SupportThread(models.Model):
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='support_threads',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"SupportThread for {self.user.username}"


class SupportMessage(models.Model):
    thread = models.ForeignKey(
        SupportThread,
        on_delete=models.CASCADE,
        related_name='messages',
    )
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='support_messages',
    )
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"SupportMsg #{self.id} in thread {self.thread_id} by {self.sender}"