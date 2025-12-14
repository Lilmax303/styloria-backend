# core/auth_serializers.py

from django.contrib.auth import get_user_model
from django.db.models import Q
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers

User = get_user_model()


class EmailOrUsernameTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Allow login using either username OR email in the 'username' field.
    """

    def validate(self, attrs):
        # 'username' in the request body may be either username or email.
        identifier = attrs.get(self.username_field)
        password = attrs.get('password')

        if not identifier or not password:
            raise serializers.ValidationError(
                {'detail': 'Username/email and password are required.'}
            )

        # Try to find a user by username OR email (case-insensitive)
        try:
            user = User.objects.get(
                Q(username__iexact=identifier) | Q(email__iexact=identifier)
            )
        except User.DoesNotExist:
            # Fall back to default behavior (will raise standard invalid credentials)
            return super().validate(attrs)

        # Replace identifier with the actual username so the parent class
        # can authenticate normally.
        attrs[self.username_field] = user.username

        return super().validate(attrs)