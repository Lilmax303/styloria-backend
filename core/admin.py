# core/admin.py

from django.contrib import admin
from django.utils import timezone

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


@admin.register(ServiceRequest)
class ServiceRequestAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'user',
        'service_provider',
        'status',
        'payment_status',
        'offered_price',
        'payout_released',
        'payout_released_at',
    )
    list_filter = (
        'status',
        'payment_status',
        'payout_released',
    )
    search_fields = (
        'id',
        'user__username',
        'service_provider__user__username',
    )
    actions = ['mark_payout_released']

    def mark_payout_released(self, request, queryset):
        """
        Admin action: mark selected completed & paid bookings as payout_released.
        """
        eligible = queryset.filter(
            payment_status='paid',
            status='completed',
            payout_released=False,
        )
        count = eligible.update(
            payout_released=True,
            payout_released_at=timezone.now(),
        )
        self.message_user(
            request,
            f"Payout released for {count} booking(s). "
            "Make sure you also trigger the actual payment transfer."
        )

    mark_payout_released.short_description = "Mark payout as released for selected bookings"


@admin.register(ServiceProvider)
class ServiceProviderAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'user',
        'available',
        'price_per_km',
        'location_latitude',
        'location_longitude',
    )
    search_fields = ('user__username',)


@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'username',
        'email',
        'phone_number',
        'role',
        'is_active',
        'is_staff',
    )
    list_filter = ('role', 'is_active', 'is_staff')
    search_fields = ('username', 'email', 'phone_number')


@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'service_provider', 'rating', 'created_at')
    search_fields = ('user__username', 'service_provider__user__username')


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'message', 'read', 'created_at')
    list_filter = ('read',)
    search_fields = ('user__username', 'message')


@admin.register(MFACode)
class MFACodeAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'code', 'created_at', 'expires_at', 'used')
    list_filter = ('used',)


@admin.register(ChatThread)
class ChatThreadAdmin(admin.ModelAdmin):
    list_display = ('id', 'service_request', 'created_at')


@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'thread', 'sender', 'created_at')
    search_fields = ('sender__username', 'content')


@admin.register(SupportThread)
class SupportThreadAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'created_at')


@admin.register(SupportMessage)
class SupportMessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'thread', 'sender', 'created_at')
    search_fields = ('sender__username', 'content')