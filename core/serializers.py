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
    ServiceProviderPricing,
    ServiceRequest,
    Review,
    RequesterReview,
    ChatThread,
    ChatMessage,
    SupportThread,
    SupportMessage,
    generate_location_code,
    ProviderPortfolioPost,
    ProviderPortfolioMedia,
    ProviderCertification,
    ProviderWallet,
    WalletLedgerEntry,
    Payout,
    ProviderPayoutSettings,
    Referral,
    SERVICE_TYPE_CHOICES,  # ← NEW: Import for validation
)

try:
    from .utils.currency import convert_amount, get_currency_symbol
except ImportError:
    def convert_amount(amount, from_currency, to_currency):
        return amount

    def get_currency_symbol(currency_code):
        return '$'


def calculate_age(dob: date) -> int:
    today = date.today()
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, allow_blank=False)
    password_confirm = serializers.CharField(write_only=True, required=False, allow_blank=False)

    profile_picture = serializers.ImageField(write_only=True, required=False, allow_null=True)
    profile_picture_url = serializers.SerializerMethodField()

    email_verified = serializers.BooleanField(read_only=True)
    email_verified_at = serializers.DateTimeField(read_only=True)

    needs_kyc = serializers.SerializerMethodField()
    provider_verification_status = serializers.SerializerMethodField()

    # Write-only fields for signup location tracking
    detected_country = serializers.CharField(write_only=True, required=False, allow_blank=True, allow_null=True)
    country_mismatch = serializers.BooleanField(write_only=True, required=False, default=False)

    # Referral fields
    referral_code = serializers.CharField(read_only=True)
    referral_credits = serializers.IntegerField(read_only=True)
    total_referrals = serializers.IntegerField(read_only=True)
    referred_by_code = serializers.CharField(
        write_only=True, 
        required=False, 
        allow_blank=True,
        allow_null=True,
        help_text="Referral code used during signup"
    )

    class Meta:
        model = CustomUser
        fields = [
            "id",
            "styloria_id",
            "member_number",
            "age_at_signup",
            "country_name",
            "city_name",
            "country_code",
            "city_code",
            "accepted_terms",
            "accepted_terms_at",
            "username",
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "date_of_birth",
            "role",
            "password",
            "password_confirm",
            "email_verified",
            "email_verified_at",
            "preferred_currency",
            "currency_source",
            "last_currency_update",
            "last_known_latitude",
            "last_known_longitude",
            "last_location_update",
            "profile_picture",
            "profile_picture_url",
            "preferred_language",
            "needs_kyc",
            "provider_verification_status",
            "detected_country",
            "country_mismatch",
            "referral_code",
            "referral_credits",
            "total_referrals",
            "referred_by_code",
        ]
        extra_kwargs = {
            "styloria_id": {"read_only": True},
            "member_number": {"read_only": True},
            "age_at_signup": {"read_only": True},
            "accepted_terms_at": {"read_only": True},
            "country_code": {"read_only": True},
            "city_code": {"read_only": True},
            "currency_source": {"read_only": True},
            "last_currency_update": {"read_only": True},
            "last_known_latitude": {"read_only": True},
            "last_known_longitude": {"read_only": True},
            "last_location_update": {"read_only": True},
            "profile_picture_url": {"read_only": True},
        }

    def get_profile_picture_url(self, obj):
        if obj.profile_picture:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_picture.url)
            return obj.profile_picture.url
        return None

    def _validate_password(self, password):
        try:
            validate_password(password)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"password": list(e.messages)})

    def validate(self, attrs):
        request = self.context.get("request")
        creating = self.instance is None

        role = (attrs.get("role") or (self.instance.role if self.instance else "user") or "user").strip().lower()
        is_superuser_request = bool(
            request and request.user and request.user.is_authenticated and request.user.is_superuser
        )
        if creating and (not is_superuser_request) and role not in ("user", "provider"):
            raise serializers.ValidationError({"role": "Only 'user' or 'provider' can sign up publicly."})

        password = attrs.get("password")
        password_confirm = attrs.get("password_confirm")

        if creating:
            if not password:
                raise serializers.ValidationError({"password": "Password is required."})
            if not password_confirm:
                raise serializers.ValidationError({"password_confirm": "Please confirm your password."})
            if password != password_confirm:
                raise serializers.ValidationError({"password_confirm": "Passwords do not match."})
        else:
            if password:
                if not password_confirm:
                    raise serializers.ValidationError({"password_confirm": "Please confirm your password."})
                if password != password_confirm:
                    raise serializers.ValidationError({"password_confirm": "Passwords do not match."})

        if creating:
            if not (attrs.get("first_name") or "").strip():
                raise serializers.ValidationError({"first_name": "First name is required."})
            if not (attrs.get("last_name") or "").strip():
                raise serializers.ValidationError({"last_name": "Last name is required."})

            dob = attrs.get("date_of_birth")
            if dob is None:
                raise serializers.ValidationError({"date_of_birth": "Date of birth is required."})
            if calculate_age(dob) < 18:
                raise serializers.ValidationError({"date_of_birth": "You must be at least 18 years old to use Styloria."})

            email = (attrs.get("email") or "").strip().lower()
            phone = (attrs.get("phone_number") or "").strip()
            if not email:
                raise serializers.ValidationError({"email": "Email is required."})
            if not phone:
                raise serializers.ValidationError({"phone_number": "Phone number is required."})

            country_name = (attrs.get("country_name") or "").strip()
            city_name = (attrs.get("city_name") or "").strip()
            if not country_name:
                raise serializers.ValidationError({"country_name": "Country is required."})
            if not city_name:
                raise serializers.ValidationError({"city_name": "City is required."})

            if attrs.get("accepted_terms") is not True:
                raise serializers.ValidationError(
                    {"accepted_terms": "You must accept the User Agreement and Policies to continue."}
                )

        if (not creating) and ("accepted_terms" in attrs) and (attrs["accepted_terms"] is False):
            raise serializers.ValidationError({"accepted_terms": "You cannot unset accepted terms once accepted."})

        qs = CustomUser.objects.all()
        if self.instance is not None:
            qs = qs.exclude(pk=self.instance.pk)

        if "email" in attrs:
            email = (attrs.get("email") or "").strip().lower()
            if email and qs.filter(email__iexact=email).exists():
                raise serializers.ValidationError({"email": "This email is already in use."})

        if "phone_number" in attrs:
            phone = (attrs.get("phone_number") or "").strip()
            if phone and qs.filter(phone_number=phone).exists():
                raise serializers.ValidationError({"phone_number": "This phone number is already in use."})

        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        validated_data.pop("password_confirm", None)
        detected_country = validated_data.pop("detected_country", None)
        country_mismatch = validated_data.pop("country_mismatch", False)

        # ═══════════════════════════════════════════════════════════════════
        # ADD THIS LINE HERE - Pop referral code BEFORE creating user
        # ═══════════════════════════════════════════════════════════════════
        referred_by_code = validated_data.pop("referred_by_code", None)
        if referred_by_code:
            referred_by_code = referred_by_code.strip().upper()
        # ═══════════════════════════════════════════════════════════════════

        self._validate_password(password)

        country_name = validated_data.get("country_name") or ""
        city_name = validated_data.get("city_name") or ""
        validated_data["country_code"] = generate_location_code(country_name)
        validated_data["city_code"] = generate_location_code(city_name)

        if not validated_data["country_code"]:
            raise serializers.ValidationError({"country_name": "Could not generate country code from country name."})
        if not validated_data["city_code"]:
            raise serializers.ValidationError({"city_name": "Could not generate city code from city name."})

        # Store detected location info
        if detected_country:
            validated_data["detected_country_at_signup"] = detected_country
        validated_data["country_mismatch_at_signup"] = bool(country_mismatch)

        user = CustomUser(**validated_data)
        user.set_password(password)
        user.is_active = True

        if hasattr(user, "email_verified"):
            user.email_verified = False

        user.save()

        # Process referral if code was provided
        if referred_by_code:
            try:
                referrer = CustomUser.objects.get(referral_code__iexact=referred_by_code)
                if referrer.pk != user.pk:  # Can't refer yourself
                    user.referred_by = referrer
                    user.save(update_fields=['referred_by'])
                    
                    # Create referral record
                    Referral.objects.create(
                        referrer=referrer,
                        referred_user=user,
                        status='pending'
                    )
            except CustomUser.DoesNotExist:
                pass  # Invalid code - silently ignore (don't block registration)

        # Auto-create provider profile for providers
        if (user.role or "").strip().lower() == "provider":
            ServiceProvider.objects.get_or_create(user=user)

        return user

    def get_provider_verification_status(self, obj):
        if (obj.role or "").lower() != "provider":
            return None
        provider = getattr(obj, "provider_profile", None)
        return getattr(provider, "verification_status", None) if provider else None

    def get_needs_kyc(self, obj):
        if (obj.role or "").lower() != "provider":
            return False
        provider = getattr(obj, "provider_profile", None)
        if not provider:
            return True
        return provider.verification_status != "approved"

    def update(self, instance, validated_data):
        request = self.context.get("request")
        is_superuser_request = bool(
            request and request.user and request.user.is_authenticated and request.user.is_superuser
        )

        if not is_superuser_request:
            validated_data.pop("role", None)

        password = validated_data.pop("password", None)
        validated_data.pop("password_confirm", None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            self._validate_password(password)
            instance.set_password(password)

        instance.save()
        return instance


class UserLocationCodesSerializer(serializers.Serializer):
    country_name = serializers.CharField(required=True)
    city_name = serializers.CharField(required=True)

    def validate_country_name(self, value: str):
        if not (value or "").strip():
            raise serializers.ValidationError("Country is required.")
        return value.strip()

    def validate_city_name(self, value: str):
        if not (value or "").strip():
            raise serializers.ValidationError("City is required.")
        return value.strip()

    def save(self, **kwargs):
        user = self.context["request"].user
        user.country_name = self.validated_data["country_name"]
        user.city_name = self.validated_data["city_name"]
        user.save()
        return user


class ServiceProviderPricingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceProviderPricing
        fields = ['service_type', 'price', 'offered']
        read_only_fields = ['provider']


# ==========================
# PROVIDER PORTFOLIO (NEW)
# ==========================

class ProviderPortfolioMediaSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()
    thumbnail_url = serializers.SerializerMethodField()

    class Meta:
        model = ProviderPortfolioMedia
        fields = [
            "id",
            "media_type",
            "file_url",
            "thumbnail_url",
            "created_at",
        ]

    def get_file_url(self, obj):
        if not obj.file:
            return None
        request = self.context.get("request")
        if request:
            return request.build_absolute_uri(obj.file.url)
        return obj.file.url

    def get_thumbnail_url(self, obj):
        if not obj.thumbnail:
            return None
        request = self.context.get("request")
        if request:
            return request.build_absolute_uri(obj.thumbnail.url)
        return obj.thumbnail.url


class ProviderPortfolioPostSerializer(serializers.ModelSerializer):
    media = ProviderPortfolioMediaSerializer(many=True, read_only=True)
    cover_media_url = serializers.SerializerMethodField()
    cover_media_type = serializers.SerializerMethodField()

    class Meta:
        model = ProviderPortfolioPost
        fields = [
            "id",
            "caption",
            "is_public",
            "created_at",
            "cover_media_url",
            "cover_media_type",
            "media",
        ]

    def _cover_media(self, obj):
        # Pick the first media item as cover. (Change to .last() if you prefer latest.)
        try:
            return obj.media.first()
        except Exception:
            return None

    def get_cover_media_url(self, obj):
        m = self._cover_media(obj)
        if not m or not m.file:
            return None
        request = self.context.get("request")
        return request.build_absolute_uri(m.file.url) if request else m.file.url

    def get_cover_media_type(self, obj):
        m = self._cover_media(obj)
        return getattr(m, "media_type", None)


class ServiceProviderSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    average_rating = serializers.SerializerMethodField()
    review_count = serializers.SerializerMethodField()

    service_prices = ServiceProviderPricingSerializer(
        source="service_prices.all",
        many=True,
        read_only=True,
    )

    id_document_front_url = serializers.SerializerMethodField()
    id_document_back_url = serializers.SerializerMethodField()
    verification_selfie_url = serializers.SerializerMethodField()

    # Portfolio posts:
    # IMPORTANT CHANGE: only provider owner/admin/staff can see portfolio via provider endpoints.
    # Users will see portfolio via ServiceRequestSerializer (7-minute booking window logic).
    portfolio_posts = serializers.SerializerMethodField()

    # Reviews received by this provider
    reviews = serializers.SerializerMethodField()

    class Meta:
        model = ServiceProvider
        fields = [
            "id",
            "user",
            "bio",
            "certification",
            "available",
            "location_latitude",
            "location_longitude",
            "average_rating",
            "review_count",
            "service_prices",

            "is_verified",
            "verification_status",
            "verification_submitted_at",
            "verification_reviewed_at",
            "verification_review_notes",

            "id_document_front_url",
            "id_document_back_url",
            "verification_selfie_url",

            "portfolio_posts",
            "reviews",
        ]

        read_only_fields = [
            "is_verified",
            "verification_submitted_at",
            "verification_reviewed_at",
            "verification_review_notes",
            "verification_reviewed_by",
        ]

        extra_kwargs = {
            # Never expose raw KYC files for reading through generic provider responses
            "id_document_front": {"write_only": True, "required": False, "allow_null": True},
            "id_document_back": {"write_only": True, "required": False, "allow_null": True},
            "verification_selfie": {"write_only": True, "required": False, "allow_null": True},
        }


    def _can_view_kyc(self, obj: ServiceProvider) -> bool:
        request = self.context.get("request")
        if not request or not request.user or not request.user.is_authenticated:
            return False
        u = request.user
        return bool(u.is_staff or getattr(u, "role", "") == "admin" or u.pk == obj.user_id)


    def get_average_rating(self, obj):
        result = obj.reviews.aggregate(avg=Avg("rating"))["avg"]
        return float(result or 0.0)

    def get_review_count(self, obj):
        return obj.reviews.count()

    def get_id_document_front_url(self, obj):
        if not self._can_view_kyc(obj):
            return None
        if not obj.id_document_front:
            return None
        request = self.context.get("request")
        return request.build_absolute_uri(obj.id_document_front.url) if request else obj.id_document_front.url

    def get_id_document_back_url(self, obj):
        if not self._can_view_kyc(obj):
            return None
        if not obj.id_document_back:
            return None
        request = self.context.get("request")
        return request.build_absolute_uri(obj.id_document_back.url) if request else obj.id_document_back.url

    def get_verification_selfie_url(self, obj):
        if not self._can_view_kyc(obj):
            return None
        if not obj.verification_selfie:
            return None
        request = self.context.get("request")
        return request.build_absolute_uri(obj.verification_selfie.url) if request else obj.verification_selfie.url


    def get_portfolio_posts(self, obj: ServiceProvider):
        """
        Provider profile endpoint rule:
        - Only provider owner OR staff/admin can see portfolio here.
        - Requesters will see portfolio via ServiceRequestSerializer (gated).
        """
        request = self.context.get("request")
        if not request or not request.user or not request.user.is_authenticated:
            return []

        user = request.user
        is_admin = bool(user.is_staff or getattr(user, "role", "") == "admin")
        is_owner = (user.pk == obj.user_id)

        if not (is_admin or is_owner):
            return []

        posts = (
            obj.portfolio_posts
            .prefetch_related("media")
            .all()
            .order_by("-created_at")[:20]
        )
        return ProviderPortfolioPostSerializer(posts, many=True, context={"request": request}).data

    def get_reviews(self, obj: ServiceProvider):
        """
        Returns reviews for this provider.
        - Provider owner can always see their own reviews
        - Admin/staff can see all reviews
        - Other users can see reviews (public for reputation)
        """
        request = self.context.get("request")
        if not request or not request.user or not request.user.is_authenticated:
            return []

        # Get reviews for this provider, ordered by most recent first
        reviews = obj.reviews.select_related("user").order_by("-created_at")[:50]
        
        return [
            {
                "id": review.id,
                "rating": review.rating,
                "comment": review.comment,
                "created_at": review.created_at.isoformat() if review.created_at else None,
                "user": {
                    "id": review.user.id,
                    "username": review.user.username,
                    "first_name": review.user.first_name,
                    "last_name": review.user.last_name,
                    "profile_picture_url": (
                        request.build_absolute_uri(review.user.profile_picture.url)
                        if review.user.profile_picture else None
                    ),
                },
            }
            for review in reviews
        ]

    def create(self, validated_data):
        request = self.context.get("request")
        return ServiceProvider.objects.create(user=request.user, **validated_data)



class ServiceProviderPublicSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    average_rating = serializers.SerializerMethodField()
    review_count = serializers.SerializerMethodField()

    service_prices = ServiceProviderPricingSerializer(
        source="service_prices.all",
        many=True,
        read_only=True,
    )

    class Meta:
        model = ServiceProvider
        fields = [
            "id",
            "user",
            "bio",
            "available",
            "location_latitude",
            "location_longitude",
            "average_rating",
            "review_count",
            "service_prices",
            "is_verified",
            "verification_status",
        ]

    def get_average_rating(self, obj):
        result = obj.reviews.aggregate(avg=Avg("rating"))["avg"]
        return float(result or 0.0)

    def get_review_count(self, obj):
        return obj.reviews.count()

class ProviderCertificationSerializer(serializers.ModelSerializer):
    is_expired = serializers.BooleanField(read_only=True)
    document_url = serializers.SerializerMethodField()
    allowed_file_types = serializers.SerializerMethodField()
    max_file_sizes = serializers.SerializerMethodField()
    
    # ═══════════════════════════════════════════════════════════════════
    # NEW: Service types field for linking cert to services
    # ═══════════════════════════════════════════════════════════════════
    certified_service_types = serializers.ListField(
        child=serializers.ChoiceField(choices=SERVICE_TYPE_CHOICES),
        required=False,
        allow_empty=True,
        help_text="Services this certification qualifies for"
    )

    class Meta:
        model = ProviderCertification
        fields = [
            'id',
            'name',
            'issuing_organization',
            'document',
            'document_url',
            'issue_date',
            'expiry_date',
            'is_verified',
            'is_expired',
            'certified_service_types',  # ← NEW
            'created_at',
            'allowed_file_types',
            'max_file_sizes',
        ]
        read_only_fields = ['id', 'is_verified', 'created_at']

    def get_allowed_file_types(self, obj):
        """Return allowed file types for document upload"""
        return {
            "extensions": ["png", "jpg", "jpeg", "pdf"],
            "mime_types": [
                "image/png",
                "image/jpeg", 
                "image/jpg",
                "application/pdf"
            ],
            "description": "Images (PNG, JPG, JPEG) or PDF documents"
        }
   
    def get_max_file_sizes(self, obj):
        """Return max file sizes for document upload"""
        return {
            "image": {
                "bytes": 5 * 1024 * 1024,
                "display": "5 MB",
                "extensions": ["png", "jpg", "jpeg"]
            },
            "pdf": {
                "bytes": 10 * 1024 * 1024,
                "display": "10 MB", 
                "extensions": ["pdf"]
            }
        }
    
    def get_document_url(self, obj):
        request = self.context.get("request")
        if not request or not request.user or not request.user.is_authenticated:
            return None
        u = request.user
        is_admin = bool(u.is_staff or getattr(u, "role", "") == "admin")
        is_owner = bool(obj.provider and obj.provider.user_id == u.id)
        if not (is_admin or is_owner):
            return None

        if obj.document:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.document.url)
            return obj.document.url
        return None


class ServiceRequestSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    service_provider = ServiceProviderPublicSerializer(read_only=True)

    converted_price = serializers.SerializerMethodField()
    converted_estimated_price = serializers.SerializerMethodField()
    currency_symbol = serializers.SerializerMethodField()
    booking_currency_symbol = serializers.SerializerMethodField()

    distance_miles = serializers.SerializerMethodField()
    requester_first_name = serializers.SerializerMethodField()
    requester_address = serializers.SerializerMethodField()

    # Requester rating info (for providers to see)
    requester_average_rating = serializers.SerializerMethodField()
    requester_review_count = serializers.SerializerMethodField()

    # Auto-cancel warning for unpaid bookings
    auto_cancel_warning = serializers.SerializerMethodField()

    class Meta:
        model = ServiceRequest
        fields = [
            "id",
            "user",
            "service_provider",
            "request_time",
            "appointment_time",
            "service_type",
            "notes",
            "status",
            "payment_status",
            "estimated_price",
            "offered_price",
            "platform_fee_amount",
            "provider_earnings_amount",
            "stripe_fee_amount",
            "provider_net_amount",
            "stripe_charge_id",
            "stripe_balance_transaction_id",
            "stripe_transfer_id",
            "payment_gateway",
            "flutterwave_tx_ref",
            "flutterwave_transaction_id",
            "flutterwave_fee_amount",
            "paystack_reference",
            "paystack_transaction_id",
            "paystack_fee_amount",
            "paystack_channel",
            "currency",
            "location_latitude",
            "location_longitude",
            "location_address",
            "completed_at",
            "accepted_at",
            "cancelled_at",
            "cancelled_by",
            "penalty_applied",
            "penalty_amount",
            "user_confirmed_completion",
            "provider_confirmed_completion",
            "payout_released",
            "payout_released_at",
            "provider_portfolio_posts",
            "stripe_payment_intent_id",
            "tip_amount",
            "tip_payment_status",
            "tip_paid_at",
            "stripe_tip_payment_intent_id",
            "refund_status",
            "refund_amount",
            "refund_reason",
            "refunded_at",
            "stripe_refund_id",
            "flutterwave_refund_id",
            "provider_cancellation_fee",
            "converted_price",
            "converted_estimated_price",
            "currency_symbol",
            "booking_currency_symbol",
            "distance_miles",
            "has_user_review",
            "requester_first_name",
            "requester_address",
            "requester_average_rating",
            "requester_review_count",
            "auto_cancel_warning",
            "referral_discount_applied",
            "referral_discount_percent",
            "referral_discount_amount",
            "pre_discount_price",
        ]
        # Keep booking/payment truth server-controlled.
        read_only_fields = [
            "id",
            "user",
            "service_provider",
            "request_time",
            "status",
            "payment_status",
            "platform_fee_amount",
            "provider_earnings_amount",
            "stripe_fee_amount",
            "provider_net_amount",
            "stripe_charge_id",
            "stripe_balance_transaction_id",
            "stripe_transfer_id",
            "payment_gateway",
            "flutterwave_tx_ref",
            "flutterwave_transaction_id",
            "flutterwave_fee_amount",
            "paystack_reference",
            "paystack_transaction_id",
            "paystack_fee_amount",
            "paystack_channel",
            "completed_at",
            "accepted_at",
            "cancelled_at",
            "cancelled_by",
            "penalty_applied",
            "penalty_amount",
            "user_confirmed_completion",
            "provider_confirmed_completion",
            "payout_released",
            "payout_released_at",
            "wallet_credited",
            "wallet_credited_at",
            "stripe_payment_intent_id",
            "tip_payment_status",
            "tip_paid_at",
            "stripe_tip_payment_intent_id",
            "refund_status",
            "refund_amount",
            "refund_reason",
            "refunded_at",
            "stripe_refund_id",
            "flutterwave_refund_id",
            "provider_cancellation_fee",
        ]

    def get_auto_cancel_warning(self, obj):
        """Return warning info if booking is approaching auto-cancel deadline."""
        from core.utils.booking_cleanup import get_booking_staleness_warning
        return get_booking_staleness_warning(obj)

    def get_distance_miles(self, obj):
        return getattr(obj, "distance_miles", None)

    def get_converted_price(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return None

        if obj.offered_price:
            return convert_amount(
                float(obj.offered_price),
                obj.currency,
                request.user.preferred_currency
            )
        return None

    def get_converted_estimated_price(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return None

        if obj.estimated_price:
            return convert_amount(
                float(obj.estimated_price),
                obj.currency,
                request.user.preferred_currency
            )
        return None

    def get_currency_symbol(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return '$'
        return get_currency_symbol(request.user.preferred_currency)

    def get_booking_currency_symbol(self, obj):
        """Symbol of the currency the booking was originally paid in (requester's currency)."""
        return get_currency_symbol(obj.currency or 'USD')

    provider_portfolio_posts = serializers.SerializerMethodField()

    has_user_review = serializers.SerializerMethodField()
    
    def get_has_user_review(self, obj):
        # Check if user has reviewed THIS specific booking
        if obj.service_provider is None:
            return False
        return Review.objects.filter(
            user=obj.user,
            service_request=obj
        ).exists()

    def get_requester_first_name(self, obj):
        """Return requester's first name for providers to see."""
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
           return None
       
        # Always show for open jobs (provider browsing)
        # Also show after provider accepts the job
        if obj.user:
            return obj.user.first_name or obj.user.username
        return None

    def get_requester_address(self, obj):
        """Return requester's address/city for providers to see."""
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return None
       
        # Return the booking's service location, not user's signup address
        parts = []
        
        # First, try the saved address
        if obj.location_address:
            parts.append(obj.location_address)
        
        # Always include coordinates
        if obj.location_latitude and obj.location_longitude:
            coords = f"({obj.location_latitude:.6f}, {obj.location_longitude:.6f})"
            parts.append(coords)
        
        return " ".join(parts) if parts else None

    def get_requester_average_rating(self, obj):
        if obj.user and obj.user.requester_average_rating:
            return float(obj.user.requester_average_rating)
        return None

    def get_requester_review_count(self, obj):
        if obj.user:
            return obj.user.requester_review_count
        return 0

    def get_provider_portfolio_posts(self, obj: ServiceRequest):
        request = self.context.get("request")
        if not request or not request.user or not request.user.is_authenticated:
            return []

        # Only the requester can see this
        if obj.user_id != request.user.id:
            return []

        if not obj.service_provider_id:
            return []

        # Only show while job is active (accepted or in_progress)
        # Hide portfolio once job is completed for privacy
        if obj.status not in ("accepted", "in_progress"):
            return []

        # OPTIONAL: if you truly want only the first 7 minutes after acceptance:
        # if obj.status == "accepted" and not obj.is_within_free_cancel_period():
        #     return []

        posts = (
            obj.service_provider.portfolio_posts
            .prefetch_related("media")
            .all()
            .order_by("-created_at")[:20]
        )
        return ProviderPortfolioPostSerializer(posts, many=True, context={"request": request}).data


# Add this new serializer after your existing ServiceRequestSerializer
class JobDetailSerializer(serializers.ModelSerializer):
    """
    Enhanced serializer for job details - only available after job acceptance
    Shows full customer details including contact info and navigation data
    """
    user = UserSerializer(read_only=True)
    service_provider = ServiceProviderSerializer(read_only=True)
    
    # Customer details for navigation and contact
    customer_full_name = serializers.SerializerMethodField()
    customer_phone = serializers.SerializerMethodField()
    customer_address = serializers.SerializerMethodField()
    navigation_address = serializers.SerializerMethodField()
    
    # Distance and location info
    distance_miles = serializers.SerializerMethodField()
    
    class Meta:
        model = ServiceRequest
        fields = [
            "id",
            "user",
            "service_provider", 
            "request_time",
            "appointment_time",
            "service_type",
            "notes",
            "status",
            "payment_status",
            "estimated_price",
            "offered_price",
            "currency",
            "location_latitude",
            "location_longitude",
            "location_address",
            "completed_at",
            "accepted_at",
            "customer_full_name",
            "customer_phone",
            "customer_address", 
            "navigation_address",
            "distance_miles",
        ]
        read_only_fields = ["id", "user", "service_provider", "request_time", "status", "payment_status"]
        
    def get_customer_full_name(self, obj):
        """Return customer's full name for provider"""
        if obj.user:
            first = obj.user.first_name or ''
            last = obj.user.last_name or ''
            full_name = f"{first} {last}".strip()
            return full_name if full_name else obj.user.username
        return None
    
    def get_customer_phone(self, obj):
        """Return customer's phone for provider contact"""
        if obj.user:
            return obj.user.phone_number
        return None
    
    def get_customer_address(self, obj):
        """Return the booking's service location address for provider"""
        # Use the booking's location_address (where service will be performed)
        if obj.location_address:
            return obj.location_address
        # Fallback to coordinates if no address saved
        if obj.location_latitude and obj.location_longitude:
            return f"({obj.location_latitude}, {obj.location_longitude})"
        return None
    
    def get_navigation_address(self, obj):
        # Use the booking's service location for navigation
        if obj.location_address:
            return obj.location_address
        # Fallback to coordinates for Google Maps
        if obj.location_latitude and obj.location_longitude:
            return f"{obj.location_latitude},{obj.location_longitude}"
        return None
    
    def get_distance_miles(self, obj):
        return getattr(obj, "distance_miles", None)


class ReviewSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    service_provider = ServiceProviderSerializer(read_only=True)

    class Meta:
        model = Review
        fields = ["id", "user", "service_provider", "rating", "comment", "created_at"]


class RequesterReviewSerializer(serializers.ModelSerializer):
    provider_username = serializers.CharField(source='provider.user.username', read_only=True)
    provider_first_name = serializers.CharField(source='provider.user.first_name', read_only=True)
    
    class Meta:
        model = RequesterReview
        fields = [
            'id',
            'provider',
            'provider_username',
            'provider_first_name',
            'user',
            'service_request',
            'rating',
            'comment',
            'created_at',
        ]
        read_only_fields = ['id', 'provider', 'created_at']



class ChatThreadSerializer(serializers.ModelSerializer):
    service_request_id = serializers.IntegerField(source="service_request.id", read_only=True)

    class Meta:
        model = ChatThread
        fields = ["id", "service_request_id", "created_at"]


class ChatMessageSerializer(serializers.ModelSerializer):
    sender = UserSerializer(read_only=True)

    class Meta:
        model = ChatMessage
        fields = ["id", "sender", "content", "created_at"]

    def validate_content(self, value: str):
        email_pattern = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+")
        phone_pattern = re.compile(r"(\+?\d[\d \-\(\)]{7,}\d)")
        if email_pattern.search(value) or phone_pattern.search(value):
            raise serializers.ValidationError("Sharing phone numbers or email addresses is not allowed in chat.")
        return value

    def create(self, validated_data):
        request = self.context["request"]
        thread = self.context["thread"]
        return ChatMessage.objects.create(thread=thread, sender=request.user, content=validated_data["content"])


class SupportThreadSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = SupportThread
        fields = ["id", "user", "created_at"]


class SupportMessageSerializer(serializers.ModelSerializer):
    sender = UserSerializer(read_only=True)

    class Meta:
        model = SupportMessage
        fields = ["id", "sender", "content", "created_at", "is_system_message"]

    def validate_content(self, value: str):
        email_pattern = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+")
        phone_pattern = re.compile(r"(\+?\d[\d \-\(\)]{7,}\d)")
        if email_pattern.search(value) or phone_pattern.search(value):
            raise serializers.ValidationError("Sharing phone numbers or email addresses is not allowed in chat.")
        return value

    def create(self, validated_data):
        request = self.context["request"]
        thread = self.context["thread"]
        return SupportMessage.objects.create(
            thread=self.context["thread"], 
            sender=self.context["request"].user, 
            content=validated_data["content"]
        )

class ProviderWalletSerializer(serializers.ModelSerializer):
    # Add computed field for instant cashout button state
    can_instant_cashout = serializers.SerializerMethodField()
    instant_cashout_button_state = serializers.SerializerMethodField()
    minimum_cashout_amount = serializers.SerializerMethodField()

    class Meta:
        model = ProviderWallet
        fields = [
            "id",
            "currency",
            "available_balance",
            "pending_balance",
            "lifetime_earnings",
            "lifetime_payouts",
            "updated_at",
            "can_instant_cashout",
            "instant_cashout_button_state",
            "minimum_cashout_amount",
        ]

    def get_minimum_cashout_amount(self, obj) -> str:
        """
        Returns minimum cashout amount in wallet's currency.
        Base is $5 USD, converted to wallet currency.
        """
        from decimal import Decimal
        try:
            from core.utils.currency import convert_amount
        except ImportError:
            return "5.00"
        
        base_min = Decimal("5.00")
        currency = (obj.currency or "USD").upper()
        
        if currency == "USD":
            return str(base_min)
        
        try:
            converted = convert_amount(float(base_min), "USD", currency)
            return str(Decimal(str(converted)).quantize(Decimal("0.01")))
        except Exception:
            return str(base_min)

    def get_can_instant_cashout(self, obj) -> bool:
        """
        Returns True if instant cashout button should be enabled.
        """
        from decimal import Decimal
        
        # Check if balance is sufficient
        min_amount = Decimal(self.get_minimum_cashout_amount(obj))
        if obj.available_balance < min_amount:
            return False
        
        # Check provider's payout settings
        try:
            settings = obj.provider.payout_settings
            return settings.can_use_instant_payout()
        except Exception:
            return False

    def get_instant_cashout_button_state(self, obj) -> dict:
        """
        Returns detailed button state for the Flutter app.
        """
        from decimal import Decimal
        
        min_amount = Decimal(self.get_minimum_cashout_amount(obj))
        currency = (obj.currency or "USD").upper()
        available = obj.available_balance
        
        # Check balance first
        if available <= Decimal("0.00"):
            return {
                "enabled": False,
                "reason": "no_balance",
                "message": "No available balance to cash out.",
            }
        
        if available < min_amount:
            return {
                "enabled": False,
                "reason": "below_minimum",
                "message": f"Minimum cashout is {min_amount} {currency}. Your available balance is {available} {currency}.",
            }
        
        # Check payout settings
        try:
            settings = obj.provider.payout_settings
        except Exception:
            return {
                "enabled": False,
                "reason": "no_settings",
                "message": "Please configure your payout settings first.",
            }
        
        if not settings.instant_payout_enabled:
            return {
                "enabled": False,
                "reason": "disabled",
                "message": "Instant cashout is disabled in your settings.",
            }
        
        remaining = settings.get_instant_payouts_remaining()

        # -1 means unlimited, so only block if remaining is exactly 0
        if remaining == 0:
            next_payout = settings.get_next_scheduled_payout_date()
            next_str = next_payout.strftime("%B %d") if next_payout else "your next scheduled payout"
            return {
                "enabled": False,
                "reason": "limit_reached",
                "message": f"You've used all instant cashouts for this period. Next available after {next_str}.",
            }
        
        # All checks passed
        
        return {
            "enabled": True,
            "reason": "available",
            "message": "Instant cashout available anytime. 5% fee applies.",
            "remaining_uses": -1,
            "unlimited": True,
            "max_amount": str(available),
            "min_amount": str(min_amount),
            "fee_percent": 5,
        }

class WalletLedgerEntrySerializer(serializers.ModelSerializer):
    payout_status = serializers.SerializerMethodField()
    payout_method = serializers.SerializerMethodField()
    currency = serializers.SerializerMethodField()

    class Meta:
        model = WalletLedgerEntry
        fields = [
            "id",
            "direction",
            "kind",
            "amount",
            "status",
            "description",
            "available_at",
            "created_at",
            "service_request",
            "payout",
            "payout_status",
            "payout_method",
            "currency",
        ]

    def get_payout_status(self, obj):
        """Get the status of the associated payout"""
        if obj.payout:
            return obj.payout.status
        return None

    def get_payout_method(self, obj):
        """Get the method of the associated payout (instant/weekly/monthly)"""
        if obj.payout:
            return obj.payout.method
        return None

    def get_currency(self, obj):
        return obj.wallet.currency if obj.wallet else None


class PayoutSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payout
        fields = [
            "id",
            "currency",
            "gross_amount",
            "fee_amount",
            "net_amount",
            "method",
            "status",
            "stripe_transfer_id",
            "flutterwave_transfer_id",
            "flutterwave_reference",
            "flutterwave_status",
            "failure_reason",
            "created_at",
            "processed_at",
        ]


class ProviderPayoutSettingsSerializer(serializers.ModelSerializer):
    VALID_PAYOUT_DAYS = [1, 3, 4]  # Tuesday, Thursday, Friday

    # Read-only computed fields for the app
    instant_payout_limit = serializers.SerializerMethodField()
    instant_payouts_remaining = serializers.SerializerMethodField()
    can_use_instant_payout = serializers.SerializerMethodField()
    next_scheduled_payout = serializers.SerializerMethodField()
    instant_payout_notice = serializers.SerializerMethodField()

    class Meta:
        model = ProviderPayoutSettings
        fields = [
            "payout_gateway",
            "payout_frequency",
            "flutterwave_method",
            "flutterwave_currency",
            "flutterwave_full_name",
            "flutterwave_country_code",
            "flutterwave_zip_code",
            "flutterwave_bank_code",
            "flutterwave_bank_name",
            "flutterwave_account_number",
            "flutterwave_phone_number",
            "flutterwave_mobile_network",
            "flutterwave_beneficiary_id",
            "paystack_recipient_code",
            "paystack_bank_code",
            "paystack_bank_name",
            "paystack_account_number",
            "paystack_account_name",
            "paystack_currency",
            "paystack_recipient_type",
            "auto_payout_enabled",
            "payout_weekday",
            "payout_hour_utc",
            "minimum_payout_amount",
            "instant_payout_enabled",
            "instant_payout_count_this_period",
            "last_auto_payout_at",
            "updated_at",
            # Computed fields
            "instant_payout_limit",
            "instant_payouts_remaining",
            "can_use_instant_payout",
            "next_scheduled_payout",
            "instant_payout_notice",
        ]
        read_only_fields = [
            "last_auto_payout_at",
            "updated_at",
            "instant_payout_count_this_period",
            "instant_payout_limit",
            "instant_payouts_remaining",
            "can_use_instant_payout",
            "next_scheduled_payout",
            "instant_payout_notice",
        ]

    def get_instant_payout_limit(self, obj) -> int:
        return -1  # Unlimited

    def get_instant_payouts_remaining(self, obj) -> int:
        return -1  # Unlimited

    def get_can_use_instant_payout(self, obj) -> bool:
        return obj.instant_payout_enabled  # Just check if enabled

    def get_next_scheduled_payout(self, obj) -> str | None:
        next_date = obj.get_next_scheduled_payout_date()
        if next_date:
            return next_date.isoformat()
        return None

    def get_instant_payout_notice(self, obj) -> dict:
        """
        Returns notice information for the instant payout button.
        """
        if not obj.instant_payout_enabled:
            return {
                "message": "Instant cashout is disabled in your settings.",
                "type": "disabled",
                "can_cashout": False,
            }
        
        return {
            "message": "Instant cashout available anytime. A 5% fee applies.",
            "type": "available",
            "can_cashout": True,
            "unlimited": True,
            "fee_percent": 5,
        }

    def validate_payout_weekday(self, value):
        """
        Ensure payout_weekday is only Tuesday (1), Thursday (3), or Friday (4).
        """
        if value not in self.VALID_PAYOUT_DAYS:
            day_names = {1: "Tuesday", 3: "Thursday", 4: "Friday"}
            allowed = ", ".join([f"{day_names[d]} ({d})" for d in self.VALID_PAYOUT_DAYS])
            raise serializers.ValidationError(
                f"Invalid payout day. Allowed days are: {allowed}"
            )
        return value

    def validate_payout_frequency(self, value):
        """
        Ensure payout_frequency is either 'weekly' or 'monthly'.
        """
        if value not in ["weekly", "monthly"]:
            raise serializers.ValidationError(
                "Invalid payout frequency. Allowed values are: 'weekly', 'monthly'"
            )
        return value

    def validate_payout_hour_utc(self, value):
        """
        Ensure payout_hour_utc is between 0 and 23.
        """
        if value < 0 or value > 23:
            raise serializers.ValidationError(
                "Invalid payout hour. Must be between 0 and 23 (UTC)."
            )
        return value