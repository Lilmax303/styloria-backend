from django.db import models

from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('user', 'User'),
        ('provider', 'Service Provider'),
        ('admin', 'Admin')
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    # Any other fields you want to add

    def __str__(self):
        return self.username

class ServiceProvider(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    bio = models.TextField(blank=True)
    certification = models.FileField(upload_to='certifications/', blank=True, null=True)
    location_latitude = models.FloatField(null=True, blank=True)
    location_longitude = models.FloatField(null=True, blank=True)
    price_per_km = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    available = models.BooleanField(default=True)

    def __str__(self):
        return self.user.username


class ServiceRequest(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    )
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='requests')
    service_provider = models.ForeignKey(ServiceProvider, on_delete=models.CASCADE, related_name='requests', null=True, blank=True)
    request_time = models.DateTimeField(auto_now_add=True)
    appointment_time = models.DateTimeField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    estimated_price = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    location_latitude = models.FloatField()
    location_longitude = models.FloatField()

    def __str__(self):
        return f"Request by {self.user.username} for {self.service_provider.user.username if self.service_provider else 'N/A'}"