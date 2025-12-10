from rest_framework import serializers
from .models import CustomUser, ServiceProvider, ServiceRequest

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'phone_number', 'role']


class ServiceProviderSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = ServiceProvider
        fields = ['id', 'user', 'bio', 'certification', 'price_per_km', 'available']


class ServiceRequestSerializer(serializers.ModelSerializer):
    user = UserSerializer()
    service_provider = ServiceProviderSerializer()

    class Meta:
        model = ServiceRequest
        fields = ['id', 'user', 'service_provider', 'request_time', 'appointment_time', 'status', 'estimated_price', 'location_latitude', 'location_longitude']