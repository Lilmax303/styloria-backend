# core/serializers.py

import re
from datetime import date

from django.db.models import Avg
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from .models import (
    CustomUser,
    ServiceProvider,
    ServiceRequest,
    Review,
    ChatThread,
    ChatMessage,
    SupportThread,
    SupportMessage,
)


# User serializer (with password for registration + editable profile)
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = CustomUser
        fields = [
            'id',
            'username',
            'first_name',
            'last_name',
            'email',
            'phone_number',
            'date_of_birth',
            'role',
            'password',
        ]
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def _validate_dob_and_phone(self, validated_data):
        dob = validated_data.get('date_of_birth')
        phone = validated_data.get('phone_number')

        if dob is None:
            raise serializers.ValidationError(
                {'date_of_birth': 'Date of birth is required.'}
            )

        today = date.today()
        age = (
            today.year
            - dob.year
            - ((today.month, today.day) < (dob.month, dob.day))
        )

        if age < 18:
            raise serializers.ValidationError(
                {'date_of_birth': 'You must be at least 18 years old to use Styloria.'}
            )

        if not phone or not str(phone).strip():
            raise serializers.ValidationError(
                {'phone_number': 'Phone number is required.'}
            )

    def _validate_password(self, password):
        try:
            validate_password(password)
        except DjangoValidationError as e:
            # Map Django's validation errors to DRF error on the password field
            raise serializers.ValidationError({'password': list(e.messages)})

    def create(self, validated_data):
        """
        Registration rules:
        - phone_number is required
        - date_of_birth is required and user must be at least 18
        - password must satisfy ComplexityValidator (10-50 chars etc.)
        """
        password = validated_data.pop('password')

        self._validate_dob_and_phone(validated_data)
        self._validate_password(password)

        user = CustomUser(**validated_data)
        user.set_password(password)  # hashes the password
        user.is_active = True
        user.save()
        return user

    def update(self, instance, validated_data):
        # Handle password separately in case we ever allow changing via /me/
        password = validated_data.pop('password', None)

        # If DOB or phone_number are being updated, re-validate them
        if 'date_of_birth' in validated_data or 'phone_number' in validated_data:
            new_data = {
                'date_of_birth': validated_data.get(
                    'date_of_birth', instance.date_of_birth
                ),
                'phone_number': validated_data.get(
                    'phone_number', instance.phone_number
                ),
            }
            self._validate_dob_and_phone(new_data)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            self._validate_password(password)
            instance.set_password(password)

        instance.save()
        return instance


# Service provider serializer
class ServiceProviderSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
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
        request = self.context.get('request')
        return ServiceProvider.objects.create(user=request.user, **validated_data)


# Service request serializer
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
            'payment_status',
            'estimated_price',
            'offered_price',
            'location_latitude',
            'location_longitude',
            'completed_at',
            'accepted_at',
            'cancelled_at',
            'cancelled_by',
            'penalty_applied',
            'penalty_amount',
            'user_confirmed_completion',
            'provider_confirmed_completion',
            'payout_released',
            'payout_released_at',
        ]


# Review serializer
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


# Chat thread serializer (booking-specific)
class ChatThreadSerializer(serializers.ModelSerializer):
    service_request_id = serializers.IntegerField(
        source='service_request.id', read_only=True
    )

    class Meta:
        model = ChatThread
        fields = ['id', 'service_request_id', 'created_at']


# Chat message serializer (booking-specific)
class ChatMessageSerializer(serializers.ModelSerializer):
    sender = UserSerializer(read_only=True)

    class Meta:
        model = ChatMessage
        fields = ['id', 'sender', 'content', 'created_at']

    def validate_content(self, value: str):
        """
        Block messages that contain email addresses or phone numbers.
        """
        email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
        phone_pattern = re.compile(r'(\+?\d[\d \-\(\)]{7,}\d)')

        if email_pattern.search(value) or phone_pattern.search(value):
            raise serializers.ValidationError(
                "Sharing phone numbers or email addresses is not allowed in chat."
            )
        return value

    def create(self, validated_data):
        request = self.context['request']
        thread = self.context['thread']
        return ChatMessage.objects.create(
            thread=thread,
            sender=request.user,
            content=validated_data['content'],
        )


# Support chat serializers
class SupportThreadSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = SupportThread
        fields = ['id', 'user', 'created_at']


class SupportMessageSerializer(serializers.ModelSerializer):
    sender = UserSerializer(read_only=True)

    class Meta:
        model = SupportMessage
        fields = ['id', 'sender', 'content', 'created_at']

    def validate_content(self, value: str):
        email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
        phone_pattern = re.compile(r'(\+?\d[\d \-\(\)]{7,}\d)')

        if email_pattern.search(value) or phone_pattern.search(value):
            raise serializers.ValidationError(
                "Sharing phone numbers or email addresses is not allowed in chat."
            )
        return value

    def create(self, validated_data):
        request = self.context['request']
        thread = self.context['thread']
        return SupportMessage.objects.create(
            thread=thread,
            sender=request.user,
            content=validated_data['content'],
        )