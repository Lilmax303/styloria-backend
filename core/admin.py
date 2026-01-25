# core/admin.py

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from core.models import PasswordResetCode
from core.models import RequesterReview
from core.models import ProviderCertification
from django.utils.html import format_html
from django.urls import reverse
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages as admin_messages
from core.emails import send_kyc_approved_email, send_kyc_rejected_email

from .models import (
    CustomUser,
    ServiceProvider,
    ServiceRequest,
    Review,
    Notification,
    MFACode,
    ProviderCertification,
    ChatThread,
    ChatMessage,
    SupportThread,
    SupportMessage,
    LocationUpdate,
    StripePaymentIntent,
    AccountDeletionFeedback,
    ProviderWallet,
    WalletLedgerEntry,
    Payout,
    ProviderPayoutSettings,
    PendingKYCProvider,
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
    list_display = [
        "id",
        "user",
        "bio_preview",
        "verification_status",
        "is_verified",
        "available",
        "verification_submitted_at",
        "verification_reviewed_at",
        "verification_reviewed_by",
    ]

    list_filter = ["verification_status", "is_verified", "available"]
    search_fields = ["user__username", "user__email", "user__first_name", "user__last_name"]
    ordering = ["-verification_submitted_at", "-id"]

    readonly_fields = (
        "verification_submitted_at",
        "verification_reviewed_at",
        "verification_reviewed_by",
    )

    actions = ["approve_kyc", "reject_kyc"]

    def bio_preview(self, obj):
        bio = (obj.bio or "").strip()
        return (bio[:50] + "...") if len(bio) > 50 else bio
    bio_preview.short_description = "Bio Preview"

    def approve_kyc(self, request, queryset):
        """
        Approve selected KYC submissions.
        Use save() so model logic runs (timestamps + is_verified sync).
        """
        count = 0
        email_sent = 0
        for provider in queryset:
            # optional: only allow approving pending
            if provider.verification_status != "pending":
                continue
            provider.verification_status = "approved"
            provider.verification_review_notes = ""
            provider.verification_reviewed_by = request.user
            provider.save()  # triggers your ServiceProvider.save() logic
            count += 1

            # Send approval email
            if send_kyc_approved_email(provider):
                email_sent += 1

        self.message_user(request, f"Approved {count} provider(s). {email_sent} email(s) sent.")

    approve_kyc.short_description = "Approve selected KYC submissions"

    def reject_kyc(self, request, queryset):
        """
        Reject selected KYC submissions.
        Use save() so model logic runs (timestamps + is_verified sync).
        """
        count = 0
        email_sent = 0
        for provider in queryset:
            if provider.verification_status != "pending":
                continue
            provider.verification_status = "rejected"
            provider.verification_reviewed_by = request.user
            provider.save()
            count += 1

            # Send rejection email
            if send_kyc_rejected_email(provider):
                email_sent += 1

        self.message_user(request, f"Rejected {count} provider(s). {email_sent} email(s) sent.")

    reject_kyc.short_description = "Reject selected KYC submissions"

    def save_model(self, request, obj, form, change):
        """Send email when verification status changes via the change form."""
        import logging
        logger = logging.getLogger(__name__)
        
        new_status = obj.verification_status
        old_status = None
        
        logger.info(f"[KYC-SP] save_model called: change={change}, pk={obj.pk}, new_status={new_status}")
        
        if change:
            try:
                old_obj = ServiceProvider.objects.get(pk=obj.pk)
                old_status = old_obj.verification_status
                logger.info(f"[KYC-SP] Old status from DB: {old_status}")
            except ServiceProvider.DoesNotExist:
                logger.warning(f"[KYC-SP] Provider {obj.pk} not found in DB")
                old_status = None
        
        # Set reviewer if status is being changed to approved/rejected
        if new_status in ['approved', 'rejected'] and old_status != new_status:
            obj.verification_reviewed_by = request.user
            logger.info(f"[KYC-SP] Setting reviewer to {request.user}")
        
        super().save_model(request, obj, form, change)
        logger.info(f"[KYC-SP] Model saved successfully")
        
        # Send email if status changed
        logger.info(f"[KYC-SP] Email check: old_status={old_status}, new_status={new_status}")
        
        if old_status and old_status != new_status:
            if new_status == 'approved':
                logger.info(f"[KYC-SP] Sending APPROVAL email to {obj.user.email}")
                try:
                    result = send_kyc_approved_email(obj)
                    logger.info(f"[KYC-SP] Approval email result: {result}")
                    if result:
                        self.message_user(request, f"✅ Approval email sent to {obj.user.email}")
                    else:
                        self.message_user(request, f"⚠️ Failed to send approval email to {obj.user.email}", level='warning')
                except Exception as e:
                    logger.error(f"[KYC-SP] Exception sending approval email: {e}", exc_info=True)
                    self.message_user(request, f"❌ Error sending approval email: {e}", level='error')
                    
            elif new_status == 'rejected':
                logger.info(f"[KYC-SP] Sending REJECTION email to {obj.user.email}")
                try:
                    result = send_kyc_rejected_email(obj)
                    logger.info(f"[KYC-SP] Rejection email result: {result}")
                    if result:
                        self.message_user(request, f"✅ Rejection email sent to {obj.user.email}")
                    else:
                        self.message_user(request, f"⚠️ Failed to send rejection email to {obj.user.email}", level='warning')
                except Exception as e:
                    logger.error(f"[KYC-SP] Exception sending rejection email: {e}", exc_info=True)
                    self.message_user(request, f"❌ Error sending rejection email: {e}", level='error')
        else:
            logger.info(f"[KYC-SP] No email sent - old_status={old_status}, new_status={new_status}")


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    """
    USER MANAGEMENT RULES (matches what you requested)

    - Public signup happens in the app/API.
    - Only SUPERUSERS can create users inside Django Admin.
    - Only SUPERUSERS can edit users (assign access controls: is_staff, groups, permissions, role=admin).
    - Staff can VIEW users (read-only) for support purposes.
    """

    model = CustomUser

    list_display = (
        'id',
        'username',
        'email',
        'phone_number',
        'role',
        'is_active',
        'is_staff',
        'is_superuser',
        'styloria_id',
        'accepted_terms',
        'date_joined',
    )
    list_filter = ('role', 'is_active', 'is_staff', 'is_superuser', 'accepted_terms')
    search_fields = ('username', 'email', 'phone_number', 'styloria_id')
    ordering = ('-date_joined',)

    # Show extra fields on the user detail page
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'email', 'phone_number', 'date_of_birth')}),
        (_('Location codes'), {'fields': ('country_code', 'city_code')}),
        (_('Styloria ID'), {'fields': ('styloria_id', 'member_number', 'age_at_signup')}),
        (_('Agreement'), {'fields': ('accepted_terms', 'accepted_terms_at')}),
        (_('Permissions'), {'fields': ('role', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )

    # Fields shown when adding a new user from admin (superusers only)
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'username',
                'first_name',
                'last_name',
                'email',
                'phone_number',
                'date_of_birth',
                'country_code',
                'city_code',
                'accepted_terms',
                'password1',
                'password2',
            ),
        }),
    )

    # Always read-only fields (system-generated)
    readonly_fields = (
        'styloria_id',
        'member_number',
        'age_at_signup',
        'accepted_terms_at',
        'last_login',
        'date_joined',
    )

    # ---- Permission enforcement ----

    def has_add_permission(self, request):
        # Only superusers can create users via Django Admin
        return bool(request.user and request.user.is_authenticated and request.user.is_superuser)

    def has_change_permission(self, request, obj=None):
        # Only superusers can edit users via Django Admin
        return bool(request.user and request.user.is_authenticated and request.user.is_superuser)

    def has_delete_permission(self, request, obj=None):
        # Only superusers can delete users via Django Admin
        return bool(request.user and request.user.is_authenticated and request.user.is_superuser)

    def has_view_permission(self, request, obj=None):
        # Staff (and superusers) can view
        return bool(request.user and request.user.is_authenticated and request.user.is_staff)


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
    search_fields = ('user__username', 'code')
    ordering = ['-created_at']


@admin.register(ChatThread)
class ChatThreadAdmin(admin.ModelAdmin):
    list_display = ('id', 'service_request', 'created_at')


@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'thread', 'sender', 'created_at')
    search_fields = ('sender__username', 'content')


# ============================================================
# ENHANCED CUSTOMER SUPPORT ADMIN
# ============================================================

class SupportMessageInline(admin.TabularInline):
    """Inline display of messages within a thread"""
    model = SupportMessage
    extra = 0
    readonly_fields = ['sender', 'content', 'created_at', 'message_preview']
    fields = ['sender', 'message_preview', 'created_at']
    ordering = ['created_at']
    can_delete = False
    max_num = 0

    def message_preview(self, obj):
        content = obj.content or ''
        if len(content) > 100:
            content = content[:100] + '...'
        
        is_support = obj.sender.is_staff if obj.sender else False
        if is_support:
            return format_html(
                '<div style="background: #dbeafe; padding: 8px; border-radius: 4px; '
                'border-left: 3px solid #3b82f6;">'
                '<strong>Support:</strong> {}</div>',
                content
            )
        else:
            return format_html(
                '<div style="background: #f3f4f6; padding: 8px; border-radius: 4px; '
                'border-left: 3px solid #6b7280;">{}</div>',
                content
            )
    message_preview.short_description = "Message"

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(SupportThread)
class SupportThreadAdmin(admin.ModelAdmin):
    list_display = [
        'id',
        'user_display',
        'user_email',
        'status_display',
        'message_count',
        'last_message_preview',
        'last_activity',
        'created_at',
        'reply_button',
    ]
    list_filter = ['created_at']
    search_fields = [
        'user__username',
        'user__email',
        'user__first_name',
        'user__last_name',
        'messages__content',
    ]
    ordering = ['-created_at']
    readonly_fields = ['user', 'created_at', 'conversation_display']
    inlines = [SupportMessageInline]
    list_per_page = 25

    fieldsets = (
        ('Thread Info', {
            'fields': ('user', 'created_at'),
        }),
        ('Conversation', {
            'fields': ('conversation_display',),
        }),
    )

    def user_display(self, obj):
        user = obj.user
        name = f"{user.first_name} {user.last_name}".strip()
        display_name = name if name else user.username
        return format_html('<strong>{}</strong>', display_name)
    user_display.short_description = "Customer"
    user_display.admin_order_field = 'user__first_name'

    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = "Email"

    def status_display(self, obj):
        last_staff_msg = obj.messages.filter(sender__is_staff=True).order_by('-created_at').first()
        last_user_msg = obj.messages.filter(sender__is_staff=False).order_by('-created_at').first()
        
        if last_user_msg:
            if not last_staff_msg or last_user_msg.created_at > last_staff_msg.created_at:
                return format_html(
                    '<span style="background: #fef3c7; color: #92400e; padding: 3px 8px; '
                    'border-radius: 4px; font-weight: bold;">⚠ Needs Reply</span>'
                )
        
        if last_staff_msg:
            return format_html(
                '<span style="background: #d1fae5; color: #065f46; padding: 3px 8px; '
                'border-radius: 4px;">✓ Replied</span>'
            )
        
        return format_html(
            '<span style="background: #fee2e2; color: #991b1b; padding: 3px 8px; '
            'border-radius: 4px;">New</span>'
        )
    status_display.short_description = "Status"

    def message_count(self, obj):
        count = obj.messages.count()
        return format_html('<span style="font-weight: bold;">{}</span>', count)
    message_count.short_description = "Messages"

    def last_message_preview(self, obj):
        last_msg = obj.messages.order_by('-created_at').first()
        if last_msg:
            content = last_msg.content[:50] + '...' if len(last_msg.content) > 50 else last_msg.content
            sender_name = "Support" if last_msg.sender.is_staff else "Customer"
            return f"{sender_name}: {content}"
        return '-'
    last_message_preview.short_description = "Last Message"

    def last_activity(self, obj):
        last_msg = obj.messages.order_by('-created_at').first()
        if last_msg:
            return last_msg.created_at.strftime("%Y-%m-%d %H:%M")
        return obj.created_at.strftime("%Y-%m-%d %H:%M")
    last_activity.short_description = "Last Activity"

    def reply_button(self, obj):
        return format_html(
            '<a class="button" style="background: #3b82f6; color: white; padding: 6px 12px; '
            'border-radius: 4px; text-decoration: none;" href="{}">💬 View & Reply</a>',
            reverse('admin:core_supportthread_change', args=[obj.pk])
        )
    reply_button.short_description = "Action"

    def conversation_display(self, obj):
        """Display the full conversation in a chat-like format"""
        messages_qs = obj.messages.select_related('sender').order_by('created_at')
        
        html_parts = ['<div style="max-height: 500px; overflow-y: auto; padding: 10px; '
                      'background: #f9fafb; border-radius: 8px;">']
        
        for msg in messages_qs:
            is_staff = msg.sender.is_staff if msg.sender else False
            sender_name = msg.sender.get_full_name() or msg.sender.username if msg.sender else "Unknown"
            timestamp = msg.created_at.strftime("%Y-%m-%d %H:%M")
            
            if is_staff:
                html_parts.append(
                    f'<div style="display: flex; justify-content: flex-end; margin-bottom: 12px;">'
                    f'<div style="background: #3b82f6; color: white; padding: 10px 14px; '
                    f'border-radius: 12px 12px 0 12px; max-width: 70%;">'
                    f'<div style="font-size: 11px; opacity: 0.8; margin-bottom: 4px;">'
                    f'👤 {sender_name} (Support) • {timestamp}</div>'
                    f'<div>{msg.content}</div>'
                    f'</div></div>'
                )
            else:
                html_parts.append(
                    f'<div style="display: flex; justify-content: flex-start; margin-bottom: 12px;">'
                    f'<div style="background: #e5e7eb; color: #1f2937; padding: 10px 14px; '
                    f'border-radius: 12px 12px 12px 0; max-width: 70%;">'
                    f'<div style="font-size: 11px; color: #6b7280; margin-bottom: 4px;">'
                    f'👤 {sender_name} • {timestamp}</div>'
                    f'<div>{msg.content}</div>'
                    f'</div></div>'
                )
        
        if not messages_qs.exists():
            html_parts.append('<p style="color: #6b7280; text-align: center;">No messages yet.</p>')
        
        html_parts.append('</div>')
        
        # Add reply form
        html_parts.append('''
            <div style="margin-top: 20px; padding: 15px; background: #f0f9ff; border-radius: 8px; border: 1px solid #bae6fd;">
                <h4 style="margin-top: 0; color: #0369a1;">💬 Send Reply</h4>
                <p style="font-size: 12px; color: #6b7280;">To reply, add a new Support Message below with yourself as sender.</p>
            </div>
        ''')
        
        return format_html(''.join(html_parts))
    conversation_display.short_description = "Conversation"


@admin.register(SupportMessage)
class SupportMessageAdmin(admin.ModelAdmin):
    list_display = ['id', 'thread_link', 'sender_display', 'content_preview', 'created_at']
    list_filter = ['created_at', 'sender__is_staff']
    search_fields = ['content', 'sender__username', 'sender__email', 'thread__user__email']
    ordering = ['-created_at']
    list_per_page = 50

    def thread_link(self, obj):
        return format_html(
            '<a href="{}">Thread #{}</a>',
            reverse('admin:core_supportthread_change', args=[obj.thread.pk]),
            obj.thread.pk
        )
    thread_link.short_description = "Thread"

    def sender_display(self, obj):
        if obj.sender.is_staff:
            return format_html('<span style="color: #3b82f6;">👤 {} (Staff)</span>', obj.sender.username)
        return format_html('<span>👤 {}</span>', obj.sender.username)
    sender_display.short_description = "Sender"

    def content_preview(self, obj):
        content = obj.content or ''
        return content[:80] + '...' if len(content) > 80 else content
    content_preview.short_description = "Message"


@admin.register(LocationUpdate)
class LocationUpdateAdmin(admin.ModelAdmin):
    list_display = ('id', 'booking', 'user', 'is_provider', 'timestamp')
    list_filter = ('is_provider', 'timestamp')
    search_fields = ('booking__id', 'user__username')
    ordering = ['-timestamp']


@admin.register(StripePaymentIntent)
class StripePaymentIntentAdmin(admin.ModelAdmin):
    list_display = ('id', 'payment_intent_id', 'service_request', 'amount', 'currency', 'status', 'created_at')
    list_filter = ('status', 'currency')
    search_fields = ('payment_intent_id', 'service_request__id', 'service_request__user__username')
    readonly_fields = ('created_at', 'updated_at')
    
    def amount(self, obj):
        return f"${obj.amount / 100:.2f}"
    amount.short_description = 'Amount'

@admin.register(AccountDeletionFeedback)
class AccountDeletionFeedbackAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "role", "created_at")
    list_filter = ("role", "created_at")
    search_fields = ("user__username", "user__email", "reason_text", "suggestions")


# ============================================================
# ENHANCED PAYOUT ADMIN
# ============================================================

@admin.register(Payout)
class PayoutAdmin(admin.ModelAdmin):
    list_display = [
        'id',
        'provider_name',
        'payout_method_display',
        'account_info_display',
        'amount_display',
        'status_display',
        'method',
        'created_at',
    ]
    list_filter = ['status', 'method', 'currency', 'created_at']
    search_fields = [
        'provider__user__username',
        'provider__user__first_name',
        'provider__user__last_name',
        'provider__user__email',
        'flutterwave_reference',
        'stripe_transfer_id',
    ]
    readonly_fields = [
        'provider', 'currency', 'gross_amount', 'fee_amount', 'net_amount',
        'method', 'flutterwave_transfer_id', 'flutterwave_reference',
        'flutterwave_status', 'stripe_transfer_id', 'created_at', 'processed_at',
        'payout_details_display',
    ]
    ordering = ['-created_at']
    actions = ['process_payouts', 'retry_failed_payouts', 'mark_as_paid']
    list_per_page = 50

    fieldsets = (
        ('Provider Info', {
            'fields': ('provider', 'payout_details_display'),
        }),
        ('Amount', {
            'fields': ('currency', 'gross_amount', 'fee_amount', 'net_amount'),
        }),
        ('Status', {
            'fields': ('status', 'method', 'failure_reason'),
        }),
        ('Stripe', {
            'fields': ('stripe_transfer_id',),
            'classes': ('collapse',),
        }),
        ('Flutterwave', {
            'fields': ('flutterwave_transfer_id', 'flutterwave_reference', 'flutterwave_status'),
            'classes': ('collapse',),
        }),
        ('Timestamps', {
            'fields': ('created_at', 'processed_at'),
        }),
    )

    def provider_name(self, obj):
        user = obj.provider.user
        name = f"{user.first_name} {user.last_name}".strip()
        return name if name else user.username
    provider_name.short_description = "Provider"
    provider_name.admin_order_field = 'provider__user__first_name'

    def payout_method_display(self, obj):
        try:
            settings = obj.provider.payout_settings
            method = settings.flutterwave_method
            gateway = settings.payout_gateway
            
            if gateway == 'stripe':
                return format_html('<span style="color: #6772e5;">💳 Stripe</span>')
            elif method == 'mobile_money':
                return format_html('<span style="color: #059669;">📱 Mobile Money</span>')
            else:
                return format_html('<span style="color: #2563eb;">🏦 Bank Transfer</span>')
        except Exception:
            return "-"
    payout_method_display.short_description = "Payout Method"

    def account_info_display(self, obj):
        try:
            settings = obj.provider.payout_settings
            if settings.payout_gateway == 'stripe':
                acct = obj.provider.stripe_account_id or '-'
                return format_html(f'<code style="font-size: 11px;">{acct[:20]}...</code>' if len(acct) > 20 else f'<code>{acct}</code>')
            elif settings.flutterwave_method == 'mobile_money':
                phone = settings.flutterwave_phone_number or 'N/A'
                return format_html(f'<code>{phone}</code>')
            else:
                account = settings.flutterwave_account_number or 'N/A'
                bank = settings.flutterwave_bank_code or ''
                return format_html(f'<code>{account}</code> <small>({bank})</small>')
        except Exception:
            return "-"
    account_info_display.short_description = "Account"

    def amount_display(self, obj):
        return format_html(
            '<strong>{} {}</strong>',
            obj.net_amount,
            obj.currency
        )
    amount_display.short_description = "Net Amount"

    def status_display(self, obj):
        colors = {
            'queued': '#f59e0b',
            'processing': '#3b82f6',
            'paid': '#10b981',
            'failed': '#ef4444',
            'canceled': '#6b7280',
        }
        color = colors.get(obj.status, '#6b7280')
        return format_html(
            '<span style="background: {}; color: white; padding: 3px 8px; border-radius: 4px; font-size: 11px;">{}</span>',
            color,
            obj.status.upper()
        )
    status_display.short_description = "Status"

    def payout_details_display(self, obj):
        try:
            settings = obj.provider.payout_settings
            user = obj.provider.user

            html = f"""
            <table style="border-collapse: collapse; width: 100%;">
                <tr>
                    <td style="padding: 6px 12px; font-weight: bold; background: #f3f4f6;">Full Name:</td>
                    <td style="padding: 6px 12px;">{settings.flutterwave_full_name or user.get_full_name() or user.username}</td>
                </tr>
                <tr>
                    <td style="padding: 6px 12px; font-weight: bold; background: #f3f4f6;">Gateway:</td>
                    <td style="padding: 6px 12px;">{settings.payout_gateway.upper()}</td>
                </tr>
                <tr>
                    <td style="padding: 6px 12px; font-weight: bold; background: #f3f4f6;">Method:</td>
                    <td style="padding: 6px 12px;">{settings.flutterwave_method or 'N/A'}</td>
                </tr>
                <tr>
                    <td style="padding: 6px 12px; font-weight: bold; background: #f3f4f6;">Currency:</td>
                    <td style="padding: 6px 12px;">{settings.flutterwave_currency or obj.currency}</td>
                </tr>
            """

            if settings.payout_gateway == 'stripe':
                html += f"""
                <tr>
                    <td style="padding: 6px 12px; font-weight: bold; background: #f3f4f6;">Stripe Account:</td>
                    <td style="padding: 6px 12px;"><code>{obj.provider.stripe_account_id or 'Not connected'}</code></td>
                </tr>
                """
            elif settings.flutterwave_method == 'mobile_money':
                html += f"""
                <tr>
                    <td style="padding: 6px 12px; font-weight: bold; background: #f3f4f6;">Phone Number:</td>
                    <td style="padding: 6px 12px;"><code>{settings.flutterwave_phone_number or 'N/A'}</code></td>
                </tr>
                <tr>
                    <td style="padding: 6px 12px; font-weight: bold; background: #f3f4f6;">Country Code:</td>
                    <td style="padding: 6px 12px;">{settings.flutterwave_country_code or 'N/A'}</td>
                </tr>
                """
            else:
                html += f"""
                <tr>
                    <td style="padding: 6px 12px; font-weight: bold; background: #f3f4f6;">Bank Code:</td>
                    <td style="padding: 6px 12px;">{settings.flutterwave_bank_code or 'N/A'}</td>
                </tr>
                <tr>
                    <td style="padding: 6px 12px; font-weight: bold; background: #f3f4f6;">Account Number:</td>
                    <td style="padding: 6px 12px;"><code>{settings.flutterwave_account_number or 'N/A'}</code></td>
                </tr>
                """

            html += "</table>"
            return format_html(html)
        except Exception as e:
            return f"No payout settings configured ({e})"
    payout_details_display.short_description = "Payout Details"

    @admin.action(description="🚀 Process selected queued payouts")
    def process_payouts(self, request, queryset):
        from core.services.payouts import payout_wallet_routed

        count = 0
        errors = []
        for payout in queryset.filter(status='queued'):
            try:
                # Re-trigger payout
                payout_wallet_routed(
                    provider=payout.provider,
                    currency=payout.currency,
                    amount=payout.gross_amount,
                    method=payout.method,
                )
                count += 1
            except Exception as e:
                errors.append(f"Payout #{payout.id}: {str(e)}")

        if errors:
            self.message_user(request, f"Processed {count} payouts. Errors: {'; '.join(errors[:3])}", level='warning')
        else:
            self.message_user(request, f"Successfully processed {count} payouts.")

    @admin.action(description="🔄 Retry failed payouts")
    def retry_failed_payouts(self, request, queryset):
        from core.services.payouts import payout_wallet_routed, get_or_create_wallet, _q
        from decimal import Decimal

        count = 0
        errors = []

        for payout in queryset.filter(status='failed'):
            try:
                # Check if wallet was already refunded
                wallet = get_or_create_wallet(payout.provider, payout.currency)

                # Reset payout status
                payout.status = 'queued'
                payout.failure_reason = ''
                payout.save(update_fields=['status', 'failure_reason'])

                count += 1
            except Exception as e:
                errors.append(f"Payout #{payout.id}: {str(e)}")

        if errors:
            self.message_user(request, f"Queued {count} payouts for retry. Errors: {'; '.join(errors[:3])}", level='warning')
        else:
            self.message_user(request, f"Queued {count} failed payouts for retry.")

    @admin.action(description="✅ Mark as paid (manual transfer)")
    def mark_as_paid(self, request, queryset):
        count = queryset.filter(status__in=['queued', 'processing']).update(
            status='paid',
            processed_at=timezone.now(),
        )
        self.message_user(request, f"Marked {count} payouts as paid.")


@admin.register(ProviderPayoutSettings)
class ProviderPayoutSettingsAdmin(admin.ModelAdmin):
    list_display = [
        'provider_name',
        'payout_gateway',
        'payout_method_display',
        'account_display',
        'frequency_display',
        'next_payout_display',
        'instant_payouts_display',
        'auto_payout_enabled',
    ]
    list_filter = [
        'payout_gateway',
        'flutterwave_method',
        'payout_frequency',
        'auto_payout_enabled',
        'instant_payout_enabled',
    ]
    search_fields = [
        'provider__user__username',
        'provider__user__first_name',
        'provider__user__last_name',
        'provider__user__email',
        'flutterwave_phone_number',
        'flutterwave_account_number',
    ]
    list_per_page = 50

    fieldsets = (
        ('Provider', {
            'fields': ('provider',),
        }),
        ('Payout Gateway', {
            'fields': ('payout_gateway',),
        }),
        ('Schedule', {
            'fields': ('auto_payout_enabled', 'payout_frequency', 'payout_weekday', 'payout_hour_utc', 'minimum_payout_amount'),
        }),
        ('Instant Payout', {
            'fields': ('instant_payout_enabled', 'instant_payout_count_this_period', 'instant_payout_period_start'),
        }),
        ('Flutterwave Settings', {
            'fields': (
                'flutterwave_method',
                'flutterwave_currency',
                'flutterwave_full_name',
                'flutterwave_country_code',
                'flutterwave_bank_code',
                'flutterwave_bank_name',           # ADD THIS
                'flutterwave_account_number',
                'flutterwave_phone_number',
                'flutterwave_mobile_network',      # ADD THIS - THIS IS THE KEY!
                'flutterwave_beneficiary_id',
            ),
            'classes': ('collapse',),
        }),
        ('Timestamps', {
            'fields': ('last_auto_payout_at', 'updated_at'),
        }),
    )
    readonly_fields = ['last_auto_payout_at', 'updated_at', 'instant_payout_count_this_period', 'instant_payout_period_start']

    def provider_name(self, obj):
        user = obj.provider.user
        name = f"{user.first_name} {user.last_name}".strip()
        return name if name else user.username
    provider_name.short_description = "Provider"

    def payout_method_display(self, obj):
        if obj.payout_gateway == 'stripe':
            return format_html('<span style="color: #6772e5;">💳 Stripe</span>')
        elif obj.flutterwave_method == 'mobile_money':
            return format_html('<span style="color: #059669;">📱 Mobile Money</span>')
        elif obj.flutterwave_method == 'bank':
            return format_html('<span style="color: #2563eb;">🏦 Bank</span>')
        return "-"
    payout_method_display.short_description = "Method"

    def account_display(self, obj):
        if obj.payout_gateway == 'stripe':
            acct = obj.provider.stripe_account_id or '-'
            return format_html(f'<code style="font-size: 10px;">{acct[:15]}...</code>' if len(acct) > 15 else f'<code>{acct}</code>')
        if obj.flutterwave_method == 'mobile_money':
            return obj.flutterwave_phone_number or '-'
        return f"{obj.flutterwave_account_number or '-'} ({obj.flutterwave_bank_code or '-'})"
    account_display.short_description = "Account"

    def frequency_display(self, obj):
        day_names = {1: 'Tue', 3: 'Thu', 4: 'Fri'}
        if obj.payout_frequency == 'weekly':
            day = day_names.get(obj.payout_weekday, '?')
            return f"Weekly ({day} @ {obj.payout_hour_utc}:00 UTC)"
        return f"Monthly (1st @ {obj.payout_hour_utc}:00 UTC)"
    frequency_display.short_description = "Frequency"

    def next_payout_display(self, obj):
        next_date = obj.get_next_scheduled_payout_date()
        if next_date:
            return next_date.strftime("%b %d, %Y %H:%M UTC")
        return "-"
    next_payout_display.short_description = "Next Payout"

    def instant_payouts_display(self, obj):
        remaining = obj.get_instant_payouts_remaining()
        limit = obj.get_instant_payout_limit()
        if obj.instant_payout_enabled:
            color = '#10b981' if remaining > 0 else '#ef4444'
            return format_html(
                '<span style="color: {};">{}/{} remaining</span>',
                color, remaining, limit
            )
        return format_html('<span style="color: #6b7280;">Disabled</span>')
    instant_payouts_display.short_description = "Instant Payouts"


@admin.register(ProviderWallet)
class ProviderWalletAdmin(admin.ModelAdmin):
    list_display = [
        'provider_name',
        'currency',
        'available_balance_display',
        'pending_balance_display',
        'lifetime_earnings',
        'lifetime_payouts',
        'updated_at',
    ]
    list_filter = ['currency']
    search_fields = [
        'provider__user__username',
        'provider__user__first_name',
        'provider__user__email',
    ]
    readonly_fields = ['provider', 'currency', 'lifetime_earnings', 'lifetime_payouts', 'updated_at']
    list_per_page = 50

    def provider_name(self, obj):
        user = obj.provider.user
        name = f"{user.first_name} {user.last_name}".strip()
        return name if name else user.username
    provider_name.short_description = "Provider"

    def available_balance_display(self, obj):
        return format_html(
            '<strong style="color: #10b981;">{} {}</strong>',
            obj.available_balance,
            obj.currency
        )
    available_balance_display.short_description = "Available"

    def pending_balance_display(self, obj):
        return format_html(
            '<span style="color: #f59e0b;">{} {}</span>',
            obj.pending_balance,
            obj.currency
        )
    pending_balance_display.short_description = "Pending"


@admin.register(WalletLedgerEntry)
class WalletLedgerEntryAdmin(admin.ModelAdmin):
    list_display = [
        'id',
        'wallet_provider',
        'direction_display',
        'kind',
        'amount_display',
        'status_display',
        'available_at',
        'created_at',
    ]
    list_filter = ['status', 'kind', 'direction', 'wallet__currency']
    search_fields = [
        'wallet__provider__user__username',
        'description',
    ]
    ordering = ['-created_at']
    list_per_page = 50

    def wallet_provider(self, obj):
        return obj.wallet.provider.user.username
    wallet_provider.short_description = "Provider"

    def direction_display(self, obj):
        if obj.direction == 'credit':
            return format_html('<span style="color: #10b981;">↑ Credit</span>')
        return format_html('<span style="color: #ef4444;">↓ Debit</span>')
    direction_display.short_description = "Direction"

    def amount_display(self, obj):
        return f"{obj.amount} {obj.wallet.currency}"
    amount_display.short_description = "Amount"

    def status_display(self, obj):
        colors = {
            'pending': '#f59e0b',
            'available': '#10b981',
            'paid': '#3b82f6',
            'reversed': '#ef4444',
        }
        color = colors.get(obj.status, '#6b7280')
        return format_html(
            '<span style="color: {};">{}</span>',
            color, obj.status.title()
        )
    status_display.short_description = "Status"

@admin.register(PasswordResetCode)
class PasswordResetCodeAdmin(admin.ModelAdmin):
    list_display = ['user', 'code', 'created_at', 'expires_at', 'used', 'failed_attempts', 'ip_address']
    list_filter = ['used', 'created_at']
    search_fields = ['user__email', 'user__username', 'code', 'ip_address']
    readonly_fields = ['created_at', 'used_at', 'last_failed_at']
    date_hierarchy = 'created_at'
    
    def has_add_permission(self, request):
        return False  # Codes should only be created via the API


# ============================================================
# PENDING KYC VERIFICATION ADMIN
# ============================================================

@admin.register(PendingKYCProvider)
class PendingKYCProviderAdmin(admin.ModelAdmin):
    """
    Dedicated admin view for pending KYC verifications.
    Shows only providers awaiting approval.
    """
    list_display = [
        'id',
        'provider_name',
        'provider_email',
        'provider_phone',
        'submitted_at',
        'days_waiting',
        'quick_actions',
    ]
    list_filter = ['verification_submitted_at']
    search_fields = [
        'user__username',
        'user__email',
        'user__first_name',
        'user__last_name',
        'user__phone_number',
    ]
    ordering = ['verification_submitted_at']
    list_per_page = 25
    
    readonly_fields = [
        'user',
        'bio',
        'verification_submitted_at',
        'kyc_documents_display',
    ]
 
    fieldsets = (
        ('Provider Info', {
            'fields': ('user', 'bio'),
        }),
        ('KYC Documents', {
            'fields': ('kyc_documents_display',),
        }),
        ('Verification', {
            'fields': ('verification_status', 'verification_review_notes'),
        }),
    )
    
    actions = ['approve_selected', 'reject_selected']

    def get_queryset(self, request):
        """Only show pending verifications"""
        return super().get_queryset(request).filter(
            verification_status='pending'
        ).select_related('user')

    def provider_name(self, obj):
        user = obj.user
        name = f"{user.first_name} {user.last_name}".strip()
        return name if name else user.username
    provider_name.short_description = "Name"
    provider_name.admin_order_field = 'user__first_name'

    def provider_email(self, obj):
        return obj.user.email
    provider_email.short_description = "Email"
    provider_email.admin_order_field = 'user__email'

    def provider_phone(self, obj):
        return obj.user.phone_number or '-'
    provider_phone.short_description = "Phone"

    def submitted_at(self, obj):
        if obj.verification_submitted_at:
            return obj.verification_submitted_at.strftime("%Y-%m-%d %H:%M")
        return '-'
    submitted_at.short_description = "Submitted"
    submitted_at.admin_order_field = 'verification_submitted_at'

    def days_waiting(self, obj):
        if obj.verification_submitted_at:
            delta = timezone.now() - obj.verification_submitted_at
            days = delta.days
            if days == 0:
                hours = delta.seconds // 3600
                return format_html('<span style="color: #10b981;">{}h ago</span>', hours)
            elif days <= 2:
                return format_html('<span style="color: #f59e0b;">{} days</span>', days)
            else:
                return format_html('<span style="color: #ef4444; font-weight: bold;">{} days</span>', days)
        return '-'
    days_waiting.short_description = "Waiting"

    def quick_actions(self, obj):
        return format_html(
            '<a class="button" style="background: #10b981; color: white; padding: 4px 8px; '
            'border-radius: 4px; text-decoration: none; margin-right: 4px;" '
            'href="{}">✓ View</a>',
            reverse('admin:core_pendingkycprovider_change', args=[obj.pk]),
        )
    quick_actions.short_description = "Actions"

    def kyc_documents_display(self, obj):
        """Display KYC document images/links"""
        html_parts = []
     
        # Actual field names from ServiceProvider model
        doc_fields = [
            ('id_document_front', 'ID Front'),
            ('id_document_back', 'ID Back'),
            ('verification_selfie', 'Selfie with ID'),
            ('proof_of_address', 'Proof of Address'),
            ('certification', 'Certification'),
        ]
        
        for field_name, label in doc_fields:
            doc = getattr(obj, field_name, None)
            if doc:
                try:
                    url = doc.url
                    html_parts.append(
                        f'<div style="margin-bottom: 10px;">'
                        f'<strong>{label}:</strong><br>'
                        f'<a href="{url}" target="_blank">'
                        f'<img src="{url}" style="max-width: 300px; max-height: 200px; border: 1px solid #ccc;"></a>'
                        f'</div>'
                    )
                except Exception:
                    html_parts.append(f'<div><strong>{label}:</strong> (file exists but cannot display)</div>')
        
        if not html_parts:
            return "No documents uploaded yet"
        
        return format_html(''.join(html_parts))
    kyc_documents_display.short_description = "KYC Documents"

    @admin.action(description="✓ Approve selected KYC applications")
    def approve_selected(self, request, queryset):
        count = 0
        email_sent = 0
        for provider in queryset:
            provider.verification_status = 'approved'
            provider.verification_reviewed_by = request.user
            provider.save()
            count += 1

            # Send approval email
            if send_kyc_approved_email(provider):
                email_sent += 1

        self.message_user(request, f"Approved {count} provider(s). {email_sent} email(s) sent.")

    @admin.action(description="✗ Reject selected KYC applications")
    def reject_selected(self, request, queryset):
        count = 0
        email_sent = 0
        for provider in queryset:
            provider.verification_status = 'rejected'
            provider.verification_reviewed_by = request.user
            provider.save()
            count += 1

            # Send rejection email
            if send_kyc_rejected_email(provider):
                email_sent += 1

        self.message_user(request, f"Rejected {count} provider(s). {email_sent} email(s) sent.")

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def save_model(self, request, obj, form, change):
        """Send email when verification status changes via the change form."""
        import logging
        logger = logging.getLogger(__name__)
        
        new_status = obj.verification_status
        old_status = None
        
        logger.info(f"[KYC] save_model called: change={change}, pk={obj.pk}, new_status={new_status}")
        
        if change:
            try:
                from core.models import ServiceProvider
                old_obj = ServiceProvider.objects.get(pk=obj.pk)
                old_status = old_obj.verification_status
                logger.info(f"[KYC] Old status from DB: {old_status}")
            except ServiceProvider.DoesNotExist:
                logger.warning(f"[KYC] Provider {obj.pk} not found in DB")
                old_status = None
        
        # Set reviewer if status is being changed to approved/rejected
        if new_status in ['approved', 'rejected'] and old_status != new_status:
            obj.verification_reviewed_by = request.user
            logger.info(f"[KYC] Setting reviewer to {request.user}")
        
        # Save the model
        super().save_model(request, obj, form, change)
        logger.info(f"[KYC] Model saved successfully")
        
        # Send email if status changed
        logger.info(f"[KYC] Email check: old_status={old_status}, new_status={new_status}, should_send={old_status and old_status != new_status}")
        
        if old_status and old_status != new_status:
            if new_status == 'approved':
                logger.info(f"[KYC] Sending APPROVAL email to {obj.user.email}")
                try:
                    result = send_kyc_approved_email(obj)
                    logger.info(f"[KYC] Approval email result: {result}")
                    if result:
                        self.message_user(request, f"✅ Approval email sent to {obj.user.email}")
                    else:
                        self.message_user(request, f"⚠️ Failed to send approval email to {obj.user.email}", level='warning')
                except Exception as e:
                    logger.error(f"[KYC] Exception sending approval email: {e}", exc_info=True)
                    self.message_user(request, f"❌ Error sending approval email: {e}", level='error')
                    
            elif new_status == 'rejected':
                logger.info(f"[KYC] Sending REJECTION email to {obj.user.email}")
                try:
                    result = send_kyc_rejected_email(obj)
                    logger.info(f"[KYC] Rejection email result: {result}")
                    if result:
                        self.message_user(request, f"✅ Rejection email sent to {obj.user.email}")
                    else:
                        self.message_user(request, f"⚠️ Failed to send rejection email to {obj.user.email}", level='warning')
                except Exception as e:
                    logger.error(f"[KYC] Exception sending rejection email: {e}", exc_info=True)
                    self.message_user(request, f"❌ Error sending rejection email: {e}", level='error')
        else:
            logger.info(f"[KYC] No email sent - old_status={old_status}, new_status={new_status}")


@admin.register(ProviderCertification)
class ProviderCertificationAdmin(admin.ModelAdmin):
    """
    Admin interface for reviewing and verifying provider certifications.
    Admins can:
    - View all uploaded certifications
    - Verify/unverify certifications
    - Filter by verification status
    - Search by provider or certification name
    """
    list_display = [
        'id',
        'provider_username',
        'name',
        'issuing_organization',
        'verification_status_display',
        'expiry_status',
        'created_at',
    ]
    list_filter = [
        'is_verified',
        ('created_at', admin.DateFieldListFilter),
        ('expiry_date', admin.DateFieldListFilter),
    ]
    search_fields = [
        'name',
        'issuing_organization',
        'provider__user__username',
        'provider__user__email',
        'provider__user__first_name',
        'provider__user__last_name',
    ]
    readonly_fields = ['created_at', 'document_preview', 'provider_trust_score']
    ordering = ['-created_at']
    date_hierarchy = 'created_at'
    list_per_page = 25
    
    fieldsets = (
        ('Provider Information', {
            'fields': ('provider', 'provider_trust_score'),
        }),
        ('Certification Details', {
            'fields': ('name', 'issuing_organization', 'issue_date', 'expiry_date'),
        }),
        ('Document', {
            'fields': ('document', 'document_preview'),
        }),
        ('Verification Status', {
            'fields': ('is_verified',),
            'description': 'Check this box after verifying the certification is legitimate.',
        }),
        ('Metadata', {
            'fields': ('created_at',),
            'classes': ('collapse',),
        }),
    )
    
    actions = ['verify_certifications', 'unverify_certifications']
    
    def provider_username(self, obj):
        return f"{obj.provider.user.username}"
    provider_username.short_description = 'Provider'
    provider_username.admin_order_field = 'provider__user__username'
    
    def verification_status_display(self, obj):
        if obj.is_verified:
            return format_html('<span style="color: green; font-weight: bold;">✓ Verified</span>')
        return format_html('<span style="color: orange;">⏳ Pending</span>')
    verification_status_display.short_description = 'Verified'
    verification_status_display.admin_order_field = 'is_verified'
    
    def expiry_status(self, obj):
        if obj.expiry_date is None:
            return format_html('<span style="color: gray;">No expiry</span>')
        if obj.is_expired:
            return format_html('<span style="color: red; font-weight: bold;">⚠️ Expired</span>')
        return format_html('<span style="color: green;">✓ Valid</span>')
    expiry_status.short_description = 'Expiry Status'
    
    def has_document(self, obj):
        if obj.document:
            return format_html('<span style="color: green;">📄 Yes</span>')
        return format_html('<span style="color: gray;">—</span>')
    has_document.short_description = 'Document'
    
    def document_preview(self, obj):
        if not obj.document:
            return 'No document uploaded'
        
        url = obj.document.url
        # Check if it's an image
        if any(url.lower().endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp']):
            return format_html(
                '<a href="{}" target="_blank">'
                '<img src="{}" style="max-width: 400px; max-height: 400px; border: 1px solid #ddd; border-radius: 8px;" />'
                '</a><br/>'
                '<a href="{}" target="_blank">Open full size ↗</a>',
                url, url, url
            )
        else:
            return format_html(
                '<a href="{}" target="_blank" style="font-size: 16px;">📄 View/Download Document</a>',
                url
            )
    document_preview.short_description = 'Document Preview'
    
    def provider_trust_score(self, obj):
        from core.utils import calculate_provider_trust_score, get_provider_tier
        score = calculate_provider_trust_score(obj.provider)
        tier = get_provider_tier(obj.provider)
        
        tier_colors = {
            'premium': '#a855f7',
            'standard': '#3b82f6',
            'budget': '#22c55e',
        }
        color = tier_colors.get(tier, '#666')
        
        return format_html(
            '<strong style="font-size: 18px;">{}/100</strong><br/>'
            '<span style="color: {}; font-weight: bold;">{} Tier</span>',
            score, color, tier.title()
        )
    provider_trust_score.short_description = 'Provider Trust Score'
    
    def save_model(self, request, obj, form, change):
        """
        Override save to send email notification when certification is verified.
        """
        if change:  # Only on update, not create
            try:
                old_obj = ProviderCertification.objects.get(pk=obj.pk)
                was_verified = old_obj.is_verified
            except ProviderCertification.DoesNotExist:
                was_verified = False
        else:
            was_verified = False
        
        super().save_model(request, obj, form, change)
        
        # Send email if certification was just verified
        if obj.is_verified and not was_verified:
            self._send_certification_approved_email(obj, request)
    
    def _send_certification_approved_email(self, certification, request):
        """Send email notification when certification is approved."""
        from django.core.mail import send_mail
        from django.conf import settings
        import logging
        
        logger = logging.getLogger(__name__)
        
        provider = certification.provider
        user = provider.user
        
        if not user.email:
            logger.warning(f"Cannot send certification approval email - no email for user {user.id}")
            return
        
        subject = "🎉 Your Certification Has Been Verified - Styloria"
        
        message = f"""
 Hi {user.first_name or user.username},

 Great news! Your certification has been verified by our team.
 
 📜 Certification Details:
    • Name: {certification.name}
    • Issuing Organization: {certification.issuing_organization or 'N/A'}
    • Status: ✅ Verified

 This verification contributes to your Trust Score, helping you attract more clients and access higher-tier jobs.
 
 What this means for you:
    • Your profile now shows this as a verified certification
    • Clients can see you have verified credentials
    • Your trust score has been updated
 
 Keep up the great work!

 Best regards,
 The Styloria Team
 
 ---
 This is an automated message. Please do not reply directly to this email.
 """
        
        html_message = f"""
 <!DOCTYPE html>
 <html>
 <head>
     <style>
         body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
         .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
         .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
         .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
         .certification-box {{ background: white; border-left: 4px solid #22c55e; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
         .badge {{ display: inline-block; background: #22c55e; color: white; padding: 5px 15px; border-radius: 20px; font-weight: bold; }}
         .benefits {{ background: #e8f5e9; padding: 15px; border-radius: 5px; margin-top: 20px; }}
         .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 20px; }}
     </style>
 </head>
 <body>
     <div class="container">
         <div class="header">
             <h1>🎉 Certification Verified!</h1>
         </div>
         <div class="content">
             <p>Hi <strong>{user.first_name or user.username}</strong>,</p>
             <p>Great news! Your certification has been verified by our team.</p>
             
             <div class="certification-box">
                 <h3 style="margin-top: 0;">📜 Certification Details</h3>
                 <p><strong>Name:</strong> {certification.name}</p>
                 <p><strong>Issuing Organization:</strong> {certification.issuing_organization or 'N/A'}</p>
                 <p><strong>Status:</strong> <span class="badge">✅ Verified</span></p>
             </div>
             
             <div class="benefits">
                 <h4 style="margin-top: 0;">✨ What this means for you:</h4>
                 <ul>
                     <li>Your profile now shows this as a verified certification</li>
                     <li>Clients can see you have verified credentials</li>
                     <li>Your trust score has been updated</li>
                 </ul>
             </div>
             
             <p>Keep up the great work!</p>
             <p>Best regards,<br><strong>The Styloria Team</strong></p>
         </div>
         <div class="footer">
             <p>This is an automated message. Please do not reply directly to this email.</p>
         </div>
     </div>
 </body>
 </html>
 """
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False,
            )
            logger.info(f"Certification approval email sent to {user.email} for cert {certification.id}")
            self.message_user(request, f"✉️ Approval notification sent to {user.email}", level='SUCCESS')
        except Exception as e:
            logger.error(f"Failed to send certification approval email: {str(e)}")
            self.message_user(request, f"⚠️ Certification verified but email failed to send: {str(e)}", level='WARNING')


    @admin.action(description='✓ Verify selected certifications')
    def verify_certifications(self, request, queryset):
        # Get certifications that weren't already verified
        to_verify = queryset.filter(is_verified=False)
        count = 0

        for cert in to_verify:
            cert.is_verified = True
            cert.save()
            self._send_certification_approved_email(cert, request)
            count += 1

        self.message_user(
            request, 
            f'Successfully verified {count} certification(s). Email notifications sent.',
            level='SUCCESS'
        )
    
    @admin.action(description='✗ Unverify selected certifications')
    def unverify_certifications(self, request, queryset):
        count = queryset.update(is_verified=False)
        self.message_user(
            request, 
            f'Unverified {count} certification(s).',
            level='WARNING'
        )

@admin.register(RequesterReview)
class RequesterReviewAdmin(admin.ModelAdmin):
    list_display = [
        'id',
        'provider_name',
        'requester_name',
        'rating',
        'comment_preview',
        'created_at',
    ]
    list_filter = ['rating', 'created_at']
    search_fields = [
        'provider__user__username',
        'user__username',
        'comment',
    ]
    readonly_fields = ['created_at']
    ordering = ['-created_at']
    
    def provider_name(self, obj):
        return obj.provider.user.username
    provider_name.short_description = 'Provider'
    
    def requester_name(self, obj):
        return obj.user.username
    requester_name.short_description = 'Requester'
    
    def comment_preview(self, obj):
        if obj.comment:
            return obj.comment[:50] + '...' if len(obj.comment) > 50 else obj.comment
        return '—'
    comment_preview.short_description = 'Comment'
