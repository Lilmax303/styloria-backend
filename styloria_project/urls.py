# styloria_project/urls.py

from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from core import views as core_views
from two_factor.urls import urlpatterns as tf_urls
from core.views import list_notifications, mark_as_read, unread_count

# Create a router to automatically generate API routes
router = DefaultRouter()
router.register(r'users', core_views.UserViewSet)
router.register(r'service_providers', core_views.ServiceProviderViewSet)
router.register(r'service_requests', core_views.ServiceRequestViewSet)
router.register(r'reviews', core_views.ReviewViewSet)  # Registered in step 16.3

urlpatterns = [
    # Admin panel URL
    path('admin/', admin.site.urls),

    # Core app URLs (homepage, etc.)
    path('', include('core.urls')),

    # API endpoints (automatically generated from viewsets)
    path('api/', include(router.urls)),

    # Two-factor auth URLs
    path('accounts/two_factor/', include(tf_urls)),

    # Notification endpoints
    path("notifications/read/<int:pk>/", mark_as_read),
    path("notifications/", list_notifications, name="list_notifications"),
    path("notifications/unread/count/", unread_count),

    # JWT authentication endpoints
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # MFA endpoints
    path('api/mfa/start/', core_views.mfa_start, name='mfa_start'),
    path('api/mfa/verify/', core_views.mfa_verify, name='mfa_verify'),

    # Stripe payment endpoint
    path('api/create_payment/', core_views.create_payment, name='create_payment'),


    # Optionally, if you’re using Django’s default login/logout views
    path('accounts/', include('django.contrib.auth.urls')),
]