# core/auth_serializers.py

from django.contrib.auth import get_user_model
from django.db.models import Q
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

User = get_user_model()


class EmailOrUsernameTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Allow login using either username OR email in the 'username' field.
    Block login if email is not verified.
    """

    def validate(self, attrs):
        identifier = attrs.get(self.username_field)
        password = attrs.get("password")

        if not identifier or not password:
            raise serializers.ValidationError(
                {"detail": "Username/email and password are required."}
            )

        # Try to find a user by username OR email (case-insensitive)
        user = User.objects.filter(
            Q(username__iexact=identifier) | Q(email__iexact=identifier)
        ).first()

        # If user not found, fall back to default behavior (will raise invalid credentials)
        if not user:
            return super().validate(attrs)

        # Replace identifier with actual username so parent auth works normally
        attrs[self.username_field] = user.username

        # Authenticate & generate tokens
        data = super().validate(attrs)

        # Enforce email verification AFTER successful authentication
        if not getattr(user, "email_verified", False):
            raise AuthenticationFailed("Please verify your email before logging in.")

        return data