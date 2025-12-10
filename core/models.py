# core/models.py

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils import timezone

# Custom user model (extends AbstractUser)
class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('user', 'User'),
        ('provider', 'Service Provider'),
        ('admin', 'Admin'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    
    def __str__(self):
        return self.username


# Service provider model (linked to a user)
class ServiceProvider(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='provider_profile')
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
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    )

    SERVICE_TYPE_CHOICES = (
        ('haircut', 'Haircut'),
        ('braids', 'Braids'),
        ('shave', 'Shave'),
        ('color', 'Hair Coloring'),
        ('other', 'Other'),
    )

    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='requests'
    )
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
    estimated_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
    )
    location_latitude = models.FloatField()
    location_longitude = models.FloatField()

    def __str__(self):
        return f"Request by {self.user.username} for {self.service_provider.user.username if self.service_provider else 'N/A'}"


# Review model
class Review(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='reviews')
    service_provider = models.ForeignKey(ServiceProvider, on_delete=models.CASCADE, related_name='reviews')
    rating = models.IntegerField(choices=[(i, i) for i in range(1, 6)])  # Rating from 1 to 5
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