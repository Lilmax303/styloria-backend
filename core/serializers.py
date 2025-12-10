# core/serializers.py

from rest_framework import serializers
from .models import CustomUser, ServiceProvider, ServiceRequest, Review
from django.db.models import Avg

# User serializer (with password for registration)
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'phone_number', 'role', 'password']

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = CustomUser(**validated_data)
        user.set_password(password)  # hashes the password
        user.save()
        return user


# Service provider serializer (includes nested user details, creates profile for logged-in user)
class ServiceProviderSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)  # Nested user serializer (read-only)
    average_rating = serializers.SerializerMethodField()
    review_count = serializers.SerializerMethodField()

    class Meta:
        model = ServiceProvider
        fields = [
            'id',
            'user',
            'bio',
            'certification',
            'price_per_km',
            'available',
            'location_latitude',
            'location_longitude',
            'average_rating',
            'review_count',
        ]

    def get_average_rating(self, obj):
        result = obj.reviews.aggregate(avg=Avg('rating'))['avg']
        if result is None:
            return 0.0
        return float(result)

    def get_review_count(self, obj):
        return obj.reviews.count()

    def create(self, validated_data):
        """
        Link the provider profile to the currently authenticated user.
        """
        request = self.context.get('request')
        return ServiceProvider.objects.create(user=request.user, **validated_data)


# Service request serializer (unchanged)
class ServiceRequestSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    service_provider = ServiceProviderSerializer(read_only=True)

    class Meta:
        model = ServiceRequest
        fields = [
            'id',
            'user',
            'service_provider',
            'request_time',
            'appointment_time',
            'service_type',
            'notes',
            'status',
            'estimated_price',
            'location_latitude',
            'location_longitude',
        ]


# Review serializer (unchanged)
class ReviewSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    service_provider = ServiceProviderSerializer(read_only=True)

    class Meta:
        model = Review
        fields = [
            'id',
            'user',
            'service_provider',
            'rating',
            'comment',
            'created_at',
        ]