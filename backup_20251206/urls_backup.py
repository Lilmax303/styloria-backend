from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from core import views as core_views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)


router = DefaultRouter()
router.register(r'users', core_views.UserViewSet)
router.register(r'service_providers', core_views.ServiceProviderViewSet)
router.register(r'service_requests', core_views.ServiceRequestViewSet)


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]