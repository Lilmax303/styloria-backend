# styloria_project/urls.py

from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from django.conf import settings
from django.conf.urls.static import static


from core import views as core_views
from core.views import RequesterReviewViewSet
from core.auth_views import EmailOrUsernameTokenObtainPairView
from core.views import list_notifications, mark_as_read, unread_count
from core.views import flutterwave_redirect

router = DefaultRouter()
router.register(r'users', core_views.UserViewSet)
router.register(r'service_providers', core_views.ServiceProviderViewSet)
router.register(r'service_requests', core_views.ServiceRequestViewSet)
router.register(r'reviews', core_views.ReviewViewSet)
router.register(r'chats', core_views.ChatThreadViewSet, basename='chats')
router.register(r'support_chats', core_views.SupportThreadViewSet, basename='support_chats')
router.register(r'provider-verification', core_views.ProviderVerificationViewSet, basename='provider-verification')
router.register(r'requester_reviews', RequesterReviewViewSet, basename='requester_review')


def no_favicon(request):
    return HttpResponse(status=204)

urlpatterns = [
    path('admin/', admin.site.urls),

    path('', include('core.urls')),
    path('api/', include(router.urls)),

    # Notifications
    path("api/notifications/", list_notifications, name="list_notifications"),
    path("api/notifications/read/<int:pk>/", mark_as_read),
    path("api/notifications/unread/count/", unread_count),
    path("api/notifications/<int:pk>/delete/", core_views.delete_notification, name="delete_notification"),
    path("api/notifications/delete_selected/", core_views.delete_selected_notifications, name="delete_selected_notifications"),
    path("api/notifications/mark_all_read/", core_views.mark_all_notifications_read, name="mark_all_notifications_read"),
    path("api/notifications/clear_all/", core_views.clear_all_notifications, name="clear_all_notifications"),

    # JWT auth (username or email)
    path('api/token/', EmailOrUsernameTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # FCM Push Notifications
    # path('api/fcm/register/', core_views.register_fcm_token, name='register_fcm_token'),

    # Email verification / password reset / username reminder
    path('api/auth/email/send-verification/', core_views.send_email_verification, name='send_email_verification'),
    path('api/auth/email/confirm-verification/', core_views.confirm_email_verification, name='confirm_email_verification'),


    path('api/auth/username/remind/', core_views.send_username_reminder, name='send_username_reminder'),

    # Password Reset
    path('api/auth/password/reset/request/', core_views.password_reset_request, name='password_reset_request'),
    path('api/auth/password/reset/confirm/', core_views.password_reset_confirm, name='password_reset_confirm'),
    path('api/auth/password/reset/resend/', core_views.password_reset_resend, name='password_reset_resend'),

    # MFA endpoints
    # path('api/mfa/start/', core_views.mfa_start, name='mfa_start'),
    # path('api/mfa/verify/', core_views.mfa_verify, name='mfa_verify'),

    # Stripe
    path('api/create_payment/', core_views.create_payment, name='create_payment'),
    path('api/stripe/webhook/', core_views.stripe_webhook, name='stripe_webhook'),
    path('api/stripe/confirm_payment/', core_views.stripe_confirm_payment, name='stripe_confirm_payment'),

    # Flutterwave
    path('api/flutterwave/create_checkout/', core_views.create_flutterwave_checkout, name='create_flutterwave_checkout'),
    path('api/flutterwave/verify_payment/', core_views.verify_flutterwave_payment, name='verify_flutterwave_payment'),
    path('api/flutterwave/webhook/', core_views.flutterwave_webhook, name='flutterwave_webhook'),
    path('api/flutterwave/payout-webhook/', core_views.flutterwave_webhook, name='flutterwave_payout_webhook'),

    # Flutterwave redirect landing page (must be public + return 200)
    path('flutterwave/redirect/', core_views.flutterwave_redirect, name='flutterwave_redirect'),

    path('api/flutterwave/verify_by_txref/', core_views.verify_flutterwave_by_txref, name='verify_flutterwave_by_txref'),
    path('api/flutterwave/reset_payment/', core_views.reset_flutterwave_payment, name='reset_flutterwave_payment'),

    # Paystack (Ghana, Nigeria, South Africa, Kenya, Côte d'Ivoire)
    path('api/paystack/create_checkout/', core_views.create_paystack_checkout, name='create_paystack_checkout'),
    path('api/paystack/verify_payment/', core_views.verify_paystack_payment, name='verify_paystack_payment'),
    path('api/paystack/webhook/', core_views.paystack_webhook, name='paystack_webhook'),
    path('api/paystack/reset_payment/', core_views.reset_paystack_payment, name='reset_paystack_payment'),
    path('api/paystack/banks/', core_views.paystack_banks, name='paystack_banks'),
    path('api/paystack/resolve_account/', core_views.paystack_resolve_bank_account, name='paystack_resolve_account'),
    path('paystack/callback/', core_views.paystack_callback, name='paystack_callback'),

    # Stripe Connect (Provider)
    path('api/providers/stripe/status/', core_views.provider_stripe_status, name='provider_stripe_status'),
    path('api/providers/stripe/create_account/', core_views.provider_stripe_create_account, name='provider_stripe_create_account'),
    path('api/providers/stripe/account_link/', core_views.provider_stripe_account_link, name='provider_stripe_account_link'),
    path('api/providers/stripe/login_link/', core_views.provider_stripe_login_link, name='provider_stripe_login_link'),

    # Stripe Connect landing (dev)
    path('stripe/connect/return', core_views.stripe_connect_return, name='stripe_connect_return'),
    path('stripe/connect/refresh', core_views.stripe_connect_refresh, name='stripe_connect_refresh'),

    path('api/provider/instant-cashout-info/', core_views.provider_instant_cashout_info, name='provider_instant_cashout_info'),

    # Admin payout dashboard
    path('api/admin/payouts/dashboard/', core_views.admin_payout_dashboard, name='admin_payout_dashboard'),
    path('api/admin/payouts/<int:pk>/process/', core_views.admin_process_payout, name='admin_process_payout'),
    path('api/admin/payouts/<int:pk>/mark_paid/', core_views.admin_mark_payout_paid, name='admin_mark_payout_paid'),
    path('api/admin/providers/<int:provider_id>/payout_details/', core_views.admin_provider_payout_details, name='admin_provider_payout_details'),


    # Admin payout tooling
    path('api/admin/payouts/pending/', core_views.admin_pending_payouts, name='admin_pending_payouts'),
    path('api/admin/payouts/<int:pk>/release/', core_views.admin_release_payout, name='admin_release_payout'),

    # Admin verification endpoints
    path('api/admin/verifications/pending/', core_views.admin_pending_verifications, name='admin_pending_verifications'),
    path('api/admin/verifications/<int:provider_id>/review/', core_views.admin_review_verification, name='admin_review_verification'),

    # Provider earnings
    path('api/providers/earnings/summary/', core_views.provider_earnings_summary, name='provider_earnings_summary'),
    path('api/providers/earnings/report/', core_views.provider_earnings_report_pdf, name='provider_earnings_report_pdf'),


    # Provider Wallet
    path('api/providers/wallet/summary/', core_views.provider_wallet_summary, name='provider_wallet_summary'),
    path('api/providers/wallet/transactions/', core_views.provider_wallet_transactions, name='provider_wallet_transactions'),
    path('api/providers/wallet/cash_out/', core_views.provider_wallet_cash_out, name='provider_wallet_cash_out'),

    # Payout Settings
    path("api/providers/payout-settings/", core_views.provider_payout_settings, name="provider_payout_settings"),
    path("api/providers/payouts/history/", core_views.provider_payout_history, name="provider_payout_history"),

    # User spendings report
    path('api/users/spendings/report/', core_views.user_spendings_report_pdf, name='user_spendings_report_pdf'),

    # Admin export reports
    path('api/admin/exports/report/', core_views.admin_export_report_pdf, name='admin_export_report_pdf'),

    # Admin dev tool: release pending wallet balances
    path('api/admin/wallets/release_pending/', core_views.admin_release_pending_balances, name='admin_release_pending_balances'),

    # Django auth views (optional)
    path('accounts/', include('django.contrib.auth.urls')),

    # Location tracking
    path('api/location/update/', core_views.update_location, name='update_location'),
    path('api/location/other_party/<int:booking_id>/', core_views.get_other_party_location, name='get_other_party_location'),

    # Currency endpoints
    path('api/users/update_currency_from_location/', core_views.update_currency_from_location, name='update_currency_from_location'),
    path('api/users/update_currency_manually/', core_views.update_currency_manually, name='update_currency_manually'),
    path('api/users/currency_info/', core_views.get_currency_info, name='get_currency_info'),
    path('api/users/exchange_rates/', core_views.get_exchange_rate_info, name='get_exchange_rate_info'),
    path('api/currencies/', core_views.get_supported_currencies, name='get_supported_currencies'),

    # Debug endpoint
    path('api/debug/bookings/', core_views.debug_bookings, name='debug_bookings'),

    path("favicon.ico", no_favicon),
]

# Serve media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)