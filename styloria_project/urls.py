# styloria_project/urls.py

from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from core import views as core_views
from core.auth_views import EmailOrUsernameTokenObtainPairView
from core.views import list_notifications, mark_as_read, unread_count

router = DefaultRouter()
router.register(r'users', core_views.UserViewSet)
router.register(r'service_providers', core_views.ServiceProviderViewSet)
router.register(r'service_requests', core_views.ServiceRequestViewSet)
router.register(r'reviews', core_views.ReviewViewSet)
router.register(r'chats', core_views.ChatThreadViewSet, basename='chats')
router.register(r'support_chats', core_views.SupportThreadViewSet, basename='support_chats')

urlpatterns = [
    path('admin/', admin.site.urls),

    path('', include('core.urls')),

    path('api/', include(router.urls)),

    # Notification endpoints
    path("notifications/read/<int:pk>/", mark_as_read),
    path("notifications/", list_notifications, name="list_notifications"),
    path("notifications/unread/count/", unread_count),

    # JWT auth (username or email)
    path('api/token/', EmailOrUsernameTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # MFA endpoints (your custom Twilio-based flow)
    path('api/mfa/start/', core_views.mfa_start, name='mfa_start'),
    path('api/mfa/verify/', core_views.mfa_verify, name='mfa_verify'),

    # Stripe
    path('api/create_payment/', core_views.create_payment, name='create_payment'),

    # Admin payout tooling
    path('api/admin/payouts/pending/', core_views.admin_pending_payouts, name='admin_pending_payouts'),
    path('api/admin/payouts/<int:pk>/release/', core_views.admin_release_payout, name='admin_release_payout'),

    # Provider earnings (for providers in the app)
    path('api/providers/earnings/summary/', core_views.provider_earnings_summary, name='provider_earnings_summary'),
    path('api/providers/earnings/report/', core_views.provider_earnings_report_pdf, name='provider_earnings_report_pdf'),

    # Django's default HTML auth views (optional, under /accounts/)
    path('accounts/', include('django.contrib.auth.urls')),
]