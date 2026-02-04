# core/urls.py

from django.urls import path
from . import views
from .consumers import NotificationConsumer

urlpatterns = [
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    # Alternative class-based view:
    # path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    
    # Your existing WebSocket URL patterns
    path('ws/notifications/<str:user_id>/', NotificationConsumer.as_asgi()),
]