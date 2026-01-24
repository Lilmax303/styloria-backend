# core/models.py

from __future__ import annotations

from datetime import datetime, timedelta
from datetime import date as date_cls
from decimal import Decimal
import re
import random
import string 

from django.db import models, transaction
from django.db.models import Max
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator
from django.core.validators import MinValueValidator, MaxValueValidator


# --- BUSINESS RULE CONSTANTS ---
USER_FREE_CANCEL_BEFORE_MINUTES = 7
USER_FREE_CANCEL_AFTER_MINUTES = 40

# --- SERVICE TYPE CHOICES (moved to module level to avoid circular reference) ---
SERVICE_TYPE_CHOICES = (
    ('haircut', 'Haircut'),
    ('braids', 'Braids'),
    ('shave', 'Shave'),
    ('color', 'Hair Coloring'),
    ('manicure', 'Manicure'),
    ('pedicure', 'Pedicure'),
    ('nails', 'Nail Art'),
    ('makeup', 'Makeup'),
    ('facial', 'Facial'),
    ('waxing', 'Waxing'),
    ('massage', 'Massage'),
    ('tattoo', 'Tattoo'),
    ('styling', 'Hair Styling'),
    ('treatment', 'Hair Treatment'),
    ('extensions', 'Hair Extensions'),
    ('other', 'Other'),
)

# Services that require verified certifications
CERTIFICATION_REQUIRED_SERVICES = {
    'massage': {
        'keywords': ['massage', 'massage therapy', 'massage therapist', 'lmt', 'bodywork', 'therapeutic massage'],
        'message': 'Massage services require a verified massage therapy certification.',
    },
    # Add more services here if needed in the future
    # 'tattoo': {
    #     'keywords': ['tattoo', 'tattoo artist', 'body art'],
    #     'message': 'Tattoo services require a verified tattoo artist certification.',
    # },
}


def calculate_age_on_date(dob, on_date=None) -> int:
    """
    Calculate age in years based on date of birth.
    This is used to freeze age_at_signup at registration time.
    """
    if dob is None:
        return 0
    if on_date is None:
        on_date = date_cls.today()
    return on_date.year - dob.year - ((on_date.month, on_date.day) < (dob.month, dob.day))


def _normalize_country_code(country_code: str | None) -> str:
    if not country_code:
        return ""
    return str(country_code).strip().upper()


def _normalize_city_code(city_code: str | None) -> str:
    if not city_code:
        return ""
    return str(city_code).strip().upper()


def _get_initials(first_name: str | None, last_name: str | None, username: str | None) -> str:
    """
    Initials come from first & last name (e.g., Kwame K -> KK).
    If missing, we fall back to username.
    """
    first_name = (first_name or "").strip()
    last_name = (last_name or "").strip()
    username = (username or "").strip()

    if first_name and last_name:
        return (first_name[0] + last_name[0]).upper()

    if first_name and not last_name:
        return first_name[0].upper()

    if last_name and not first_name:
        return last_name[0].upper()

    if username:
        letters = "".join([c for c in username if c.isalpha()])
        if len(letters) >= 2:
            return letters[:2].upper()
        if len(letters) == 1:
            return letters.upper()

    return "XX"


def generate_location_code(name: str) -> str:
    """
    Your rule:
    - Single word -> first 3 letters (uppercase)
    - Two or more words -> initials (uppercase)

    Examples:
      Ghana -> GHA
      Accra -> ACC
      United States -> US
      New York -> NY

    If single-word shorter than 3, we pad with X:
      UK -> UKX
    """
    raw = (name or "").strip()
    words = re.findall(r"[A-Za-z]+", raw)
    if not words:
        return ""

    if len(words) == 1:
        w = words[0].upper()
        return w[:3].ljust(3, "X")

    return "".join(w[0].upper() for w in words)


class MembershipCounter(models.Model):
    """
    Single-row counter table to generate sequential membership numbers safely.
    We'll use pk=1 always.
    """
    next_number = models.PositiveIntegerField(default=1)

    def __str__(self):
        return f"MembershipCounter(next_number={self.next_number})"


class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('user', 'User'),
        ('provider', 'Service Provider'),
        ('admin', 'Admin'),
    )

    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')

    # Profile picture field
    profile_picture = models.ImageField(
        upload_to='profile_pictures/%Y/%m/%d/',
        null=True,
        blank=True,
        verbose_name="Profile Picture"
    )

    # Unique email/phone (DB-level)
    email = models.EmailField(blank=True, null=True, unique=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True, unique=True)

    # Signup details
    date_of_birth = models.DateField(null=True, blank=True)

    # Human-friendly names (selected in app)
    country_name = models.CharField(max_length=100, blank=True, null=True)
    city_name = models.CharField(max_length=100, blank=True, null=True)

    # Generated codes (used in styloria_id)
    country_code = models.CharField(max_length=10, blank=True, null=True)  # e.g., GHA, US
    city_code = models.CharField(max_length=20, blank=True, null=True)     # e.g., ACC, NY

    # Terms acceptance (required for public signup)
    accepted_terms = models.BooleanField(default=False)
    accepted_terms_at = models.DateTimeField(null=True, blank=True)

    # Server-generated
    member_number = models.PositiveIntegerField(blank=True, null=True, unique=True)
    age_at_signup = models.PositiveSmallIntegerField(blank=True, null=True)
    styloria_id = models.CharField(max_length=64, blank=True, null=True, unique=True)

    # Email verification
    email_verified = models.BooleanField(default=False)
    email_verified_at = models.DateTimeField(null=True, blank=True)

    preferred_language = models.CharField(
        max_length=20,
        default="en",
        help_text="BCP-47 language code, e.g. en, fr, es, pt-BR"
    )

    # Currency preferences
    preferred_currency = models.CharField(
        max_length=3,
        default='USD',
        help_text='ISO 4217 currency code (USD, EUR, GHS, etc.)'
    )
    last_currency_update = models.DateTimeField(null=True, blank=True)
    currency_source = models.CharField(
        max_length=20,
        choices=(
            ('signup', 'Signup Country'),
            ('gps', 'GPS Location'),
            ('manual', 'Manual Selection'),
        ),
        default='signup'
    )

    # Signup location verification
    detected_country_at_signup = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text='Country detected via GPS at signup time'
    )
    country_mismatch_at_signup = models.BooleanField(
        default=False,
        help_text='True if user selected different country than GPS detected'
    )

    # Last known location for currency detection
    last_known_latitude = models.FloatField(null=True, blank=True)
    last_known_longitude = models.FloatField(null=True, blank=True)
    last_location_update = models.DateTimeField(null=True, blank=True)

    # Requester rating (reviews from providers)
    requester_average_rating = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Average rating received from providers"
    )
    requester_review_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of reviews received from providers"
    )

    def __str__(self):
        return self.username

    def clean(self):
        """
        Enforce required signup fields for normal public signups.
        Superusers created via CLI can bypass and fill later.
        """
        super().clean()

        if self._state.adding and not self.is_superuser:
            missing = []
            if not (self.first_name or "").strip():
                missing.append("first_name")
            if not (self.last_name or "").strip():
                missing.append("last_name")
            if not self.date_of_birth:
                missing.append("date_of_birth")
            if not (self.country_name or "").strip():
                missing.append("country_name")
            if not (self.city_name or "").strip():
                missing.append("city_name")
            if self.accepted_terms is not True:
                missing.append("accepted_terms")

            if missing:
                raise ValidationError({field: "This field is required." for field in missing})

    @staticmethod
    def _build_styloria_id(
        role: str,
        age_at_signup: int,
        country_code: str,
        member_number: int,
        city_code: str,
        initials: str,
    ) -> str:
        """
        Provider:
          STP + age_at_signup + country_code + membership_number(8 digits) + city_code + initials
        User:
          STU + age_at_signup + initials + country_code + membership_number(8 digits) + city_code
        Admin:
          STA + age_at_signup + membership_number(8 digits) + city_code + initials
        """
        age_str = str(int(age_at_signup))
        mem8 = f"{int(member_number):08d}"

        if role == "provider":
            return f"STP{age_str}{country_code}{mem8}{city_code}{initials}"
        if role == "admin":
            return f"STA{age_str}{mem8}{city_code}{initials}"

        return f"STU{age_str}{initials}{country_code}{mem8}{city_code}"

    def has_required_fields_for_styloria_id(self) -> bool:
        if not self.date_of_birth:
            return False
        if not (self.first_name or "").strip():
            return False
        if not (self.last_name or "").strip():
            return False
        if not _normalize_country_code(self.country_code):
            return False
        if not _normalize_city_code(self.city_code):
            return False
        return True

    def _assign_membership_and_styloria_id(self):
        if self.styloria_id:
            return

        if not self.has_required_fields_for_styloria_id():
            raise ValidationError(
                "Cannot generate styloria_id yet. first_name, last_name, date_of_birth, country_code, and city_code are required."
            )

        self.country_code = _normalize_country_code(self.country_code)
        self.city_code = _normalize_city_code(self.city_code)

        if self.age_at_signup is None:
            signup_date = timezone.localdate()
            self.age_at_signup = calculate_age_on_date(self.date_of_birth, on_date=signup_date)

        initials = _get_initials(self.first_name, self.last_name, self.username)

        if self.member_number is None:
            # Lock the single counter row so two signups cannot get the same number
            counter, _ = MembershipCounter.objects.select_for_update().get_or_create(
                pk=1,
                defaults={"next_number": 1},
            )

            # IMPORTANT: self-heal if counter is behind the current max in DB
            current_max = (
                CustomUser.objects.aggregate(Max("member_number")).get("member_number__max") or 0
            )
            if counter.next_number <= current_max:
                counter.next_number = current_max + 1

            self.member_number = counter.next_number
            counter.next_number = counter.next_number + 1
            counter.save(update_fields=["next_number"])

        self.styloria_id = self._build_styloria_id(
            role=self.role or "user",
            age_at_signup=self.age_at_signup,
            country_code=self.country_code,
            member_number=self.member_number,
            city_code=self.city_code,
            initials=initials,
        )

    def save(self, *args, **kwargs):
        """
        Combined save logic (IMPORTANT):
        This merged version preserves:
        - currency detection
        - unique NULL handling for email/phone
        - accepted_terms timestamp
        - code generation
        - styloria_id generation (atomic)
        - frozen location after styloria_id generated
        """
        # Normalize email/phone unique collisions
        if self.email == "":
            self.email = None
        if self.phone_number == "":
            self.phone_number = None

        # accepted_terms timestamp
        if self.accepted_terms and self.accepted_terms_at is None:
            self.accepted_terms_at = timezone.now()

        # Generate codes from names (your rules)
        if (not (self.country_code or "").strip()) and (self.country_name or "").strip():
            self.country_code = generate_location_code(self.country_name)

        if (not (self.city_code or "").strip()) and (self.city_name or "").strip():
            self.city_code = generate_location_code(self.city_name)

        # Freeze after ID exists (unless superuser edits)
        if self.pk and self.styloria_id and not self.is_superuser:
            old = CustomUser.objects.filter(pk=self.pk).only(
                "country_name", "city_name", "country_code", "city_code"
            ).first()
            if old:
                if (old.country_name or "") != (self.country_name or ""):
                    raise ValidationError({"country_name": "country_name cannot be changed after styloria_id is generated."})
                if (old.city_name or "") != (self.city_name or ""):
                    raise ValidationError({"city_name": "city_name cannot be changed after styloria_id is generated."})
                if (old.country_code or "") != (self.country_code or ""):
                    raise ValidationError({"country_code": "country_code cannot be changed after styloria_id is generated."})
                if (old.city_code or "") != (self.city_code or ""):
                    raise ValidationError({"city_code": "city_code cannot be changed after styloria_id is generated."})

        # Currency detection (signup-based) — keep it lightweight
        try:
            from .utils.currency import get_currency_for_country
        except Exception:
            get_currency_for_country = None

        if get_currency_for_country and self.country_name:
            if (not self.preferred_currency) or self.preferred_currency == "USD":
                currency = get_currency_for_country(self.country_name)
                if currency and currency != "USD":
                    self.preferred_currency = currency
                    self.currency_source = "signup"

        # Generate ID if possible
        if not self.styloria_id and self.has_required_fields_for_styloria_id():
            self.full_clean()
            with transaction.atomic():
                self._assign_membership_and_styloria_id()
                return super().save(*args, **kwargs)

        return super().save(*args, **kwargs)


class ServiceProvider(models.Model):
    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='provider_profile'
    )
    bio = models.TextField(blank=True)
    certification = models.FileField(upload_to='certifications/', blank=True, null=True)
    location_latitude = models.FloatField(null=True, blank=True)
    location_longitude = models.FloatField(null=True, blank=True)
    available = models.BooleanField(default=True)

    # Stripe Connect (Express) connected account id (acct_...)
    stripe_account_id = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="Stripe connected account id (acct_...)",
    )

    # ==================== VERIFICATION FIELDS ====================
    is_verified = models.BooleanField(default=False, verbose_name="Verified Provider")
    verification_status = models.CharField(
        max_length=20,
        choices=(
            ('not_submitted', 'Not Submitted'),
            ('pending', 'Pending Review'),
            ('approved', 'Approved'),
            ('rejected', 'Rejected'),
        ),
        default='not_submitted',
    )
    id_document_front = models.ImageField(
        upload_to='verification/ids/front/%Y/%m/%d/',
        null=True,
        blank=True,
        verbose_name="ID Front"
    )
    id_document_back = models.ImageField(
        upload_to='verification/ids/back/%Y/%m/%d/',
        null=True,
        blank=True,
        verbose_name="ID Back"
    )
    verification_selfie = models.ImageField(
        upload_to='verification/selfies/%Y/%m/%d/',
        null=True,
        blank=True,
        verbose_name="Selfie with ID"
    )
    verification_submitted_at = models.DateTimeField(null=True, blank=True)
    verification_reviewed_at = models.DateTimeField(null=True, blank=True)
    verification_review_notes = models.TextField(blank=True, null=True)
    verification_reviewed_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='verified_providers'
    )
    # ==================== END FIELDS ====================

    def __str__(self):
        status = self.get_verification_status_display()
        return f"{self.user.username} (Provider) - {status}"

    def clean(self):
        """Validate verification requirements"""
        super().clean()
        if self.verification_status in ['pending', 'approved']:
            if not self.id_document_front:
                raise ValidationError({'id_document_front': 'ID front image is required for verification.'})
            if not self.id_document_back:
                raise ValidationError({'id_document_back': 'ID back image is required for verification.'})
            if not self.verification_selfie:
                raise ValidationError({'verification_selfie': 'Selfie with ID is required for verification.'})

    def get_service_price(self, service_type):
        """
        Get the price for a specific service.
        Returns None if provider doesn't offer this service.
        """
        try:
            pricing = self.service_prices.get(service_type=service_type, offered=True)
            return pricing.price
        except ServiceProviderPricing.DoesNotExist:
            return None

    def can_user_view_portfolio(self, user: CustomUser) -> bool:
        """
        Business rule:
        A user can view provider portfolio ONLY if they have a booking with this provider
        that is accepted / in_progress / completed.

        This supports your "7-min review window after acceptance" and prevents random browsing.
        """
        if not user or not getattr(user, "is_authenticated", False):
            return False

        # provider owner can always view their own portfolio
        if user.pk == self.user_id:
            return True

        return ServiceRequest.objects.filter(
            user=user,
            service_provider=self,
            status__in=("accepted", "in_progress"),
        ).exists()

    def save(self, *args, **kwargs):
        """Automatically update timestamps"""
        # Set submitted timestamp when status changes to pending
        if self.pk:
            try:
                old = ServiceProvider.objects.get(pk=self.pk)
                if old.verification_status != 'pending' and self.verification_status == 'pending':
                    self.verification_submitted_at = timezone.now()
            except ServiceProvider.DoesNotExist:
                pass

        # Set reviewed timestamp when status changes to approved/rejected
        if self.pk and self.verification_status in ['approved', 'rejected']:
            try:
                old = ServiceProvider.objects.get(pk=self.pk)
                if old.verification_status not in ['approved', 'rejected']:
                    self.verification_reviewed_at = timezone.now()
            except ServiceProvider.DoesNotExist:
                pass

        # Sync is_verified with status
        self.is_verified = (self.verification_status == 'approved')

        super().save(*args, **kwargs)


# ==========================
# PROVIDER PORTFOLIO (NEW)
# ==========================

class ProviderPortfolioPost(models.Model):
    """
    A provider's "proof of skill" post. Think: a finished haircut, braids, nails, etc.
    One post can contain multiple media items (images/videos).
    """
    provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name="portfolio_posts",
    )
    caption = models.CharField(max_length=300, blank=True)

    # Optional toggle if you later want public previews. For now, keep False by default.
    is_public = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"PortfolioPost #{self.id} by {self.provider.user.username}"


class ProviderPortfolioMedia(models.Model):
    """
    Actual uploaded media for a ProviderPortfolioPost.
    Supports both images and videos.
    """
    MEDIA_TYPE_CHOICES = (
        ("image", "Image"),
        ("video", "Video"),
    )

    post = models.ForeignKey(
        ProviderPortfolioPost,
        on_delete=models.CASCADE,
        related_name="media",
    )

    media_type = models.CharField(max_length=10, choices=MEDIA_TYPE_CHOICES)

    file = models.FileField(
        upload_to="provider_portfolio/%Y/%m/%d/",
        validators=[
            FileExtensionValidator(
                allowed_extensions=["jpg", "jpeg", "png", "webp", "mp4", "mov", "m4v", "webm"]
            )
        ],
    )

    # Optional: store thumbnail for videos (generated server-side later)
    thumbnail = models.ImageField(
        upload_to="provider_portfolio_thumbs/%Y/%m/%d/",
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def clean(self):
        super().clean()

        # Basic validation: ensure media_type aligns with extension.
        name = (self.file.name or "").lower()
        image_ext = (".jpg", ".jpeg", ".png", ".webp")
        video_ext = (".mp4", ".mov", ".m4v", ".webm")

        if self.media_type == "image" and not name.endswith(image_ext):
            raise ValidationError({"file": "File extension does not match media_type=image."})
        if self.media_type == "video" and not name.endswith(video_ext):
            raise ValidationError({"file": "File extension does not match media_type=video."})

    def __str__(self):
        return f"PortfolioMedia #{self.id} ({self.media_type}) for post #{self.post_id}"



class ProviderCertification(models.Model):
    """
    Professional certifications/licenses.
    Multiple certifications per provider.
    """
    provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='certifications'
    )
    name = models.CharField(
        max_length=150,
        help_text="e.g., 'Licensed Cosmetologist', 'Nail Tech Certificate'"
    )
    issuing_organization = models.CharField(
        max_length=150,
        blank=True,
        help_text="Organization that issued this certification"
    )
    document = models.FileField(
        upload_to='certifications/%Y/%m/%d/',
        blank=True,
        null=True,
        help_text="Upload certification document (optional)"
    )
    issue_date = models.DateField(null=True, blank=True)
    expiry_date = models.DateField(
        null=True,
        blank=True,
        help_text="Leave blank if no expiration"
    )
    is_verified = models.BooleanField(
        default=False,
        help_text="Admin verified this certification"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Provider Certification"
        verbose_name_plural = "Provider Certifications"
    
    def __str__(self):
        return f"{self.provider.user.username} - {self.name}"
    
    @property
    def is_expired(self):
        if self.expiry_date:
            from django.utils import timezone
            return self.expiry_date < timezone.now().date()
        return False


class ServiceRequest(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending Payment'),
        ('open', 'Open for Providers'),
        ('accepted', 'Accepted by Provider'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    )

    PAYMENT_STATUS_CHOICES = (
        ('unpaid', 'Unpaid'),
        ('pending', 'Pending'),
        ('paid', 'Paid'),
    )

    CANCELLED_BY_CHOICES = (
        ('user', 'User'),
        ('provider', 'Provider'),
        ('system', 'System'),
    )

    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='requests'
    )

    service_provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='requests',
        null=True,
        blank=True,
    )

    no_providers_notified = models.BooleanField(default=False)
    providers_available_notified = models.BooleanField(default=False)

    request_time = models.DateTimeField(auto_now_add=True)
    appointment_time = models.DateTimeField()

    service_type = models.CharField(
        max_length=20,
        choices=SERVICE_TYPE_CHOICES,
        default='haircut',
    )
    notes = models.TextField(blank=True)

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
    )

    accepted_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    estimated_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
    )

    offered_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
    )

    # Tier selected by user during payment
    selected_tier = models.CharField(
        max_length=20,
        choices=[
            ('budget', 'Budget'),
            ('standard', 'Standard'),
            ('premium', 'Premium'),
        ],
        null=True,
        blank=True,
        help_text="Quality tier selected by user during booking"
    )

    # Currency for this booking (fixed at booking time)
    currency = models.CharField(
        max_length=3,
        default='USD',
        help_text='Currency used for this booking'
    )

    payment_status = models.CharField(
        max_length=20,
        choices=PAYMENT_STATUS_CHOICES,
        default='unpaid',
    )

    location_latitude = models.FloatField()
    location_longitude = models.FloatField()

    location_address = models.CharField(
        max_length=500,
        blank=True,
        null=True,
        help_text="Human-readable address of the service location"
    )

    cancelled_at = models.DateTimeField(null=True, blank=True)
    cancelled_by = models.CharField(
        max_length=20,
        choices=CANCELLED_BY_CHOICES,
        null=True,
        blank=True,
    )
    penalty_applied = models.BooleanField(default=False)
    penalty_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
    )

    user_confirmed_completion = models.BooleanField(default=False)
    provider_confirmed_completion = models.BooleanField(default=False)

    payout_released = models.BooleanField(default=False)
    payout_released_at = models.DateTimeField(null=True, blank=True)

    wallet_credited = models.BooleanField(default=False)
    wallet_credited_at = models.DateTimeField(null=True, blank=True)


    stripe_payment_intent_id = models.CharField(max_length=100, blank=True, null=True)

    # Tips (Optional)
    tip_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Optional tip amount left by the requester.",
    )

    tip_payment_status = models.CharField(
        max_length=20,
        choices=(
            ("unpaid", "Unpaid"),
            ("paid", "Paid"),
            ("skipped", "Skipped"),
        ),
        default="unpaid",
    )

    # When tip was handled (paid or skipped).
    tip_paid_at = models.DateTimeField(null=True, blank=True)

    stripe_tip_payment_intent_id = models.CharField(max_length=100, blank=True, null=True)

    # Flutterwave tip fields (for African users)
    tip_flutterwave_tx_ref = models.CharField(
        max_length=120,
        blank=True,
        null=True,
        help_text="Flutterwave transaction reference for tip payment.",
    )
    tip_flutterwave_transaction_id = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="Flutterwave transaction ID for tip payment.",
    ) 

    # =============================================================================
    # REFUND TRACKING
    # =============================================================================
    refund_status = models.CharField(
        max_length=20,
        choices=(
            ("none", "No Refund"),
            ("pending", "Refund Pending"),
            ("partial", "Partially Refunded"),
            ("full", "Fully Refunded"),
            ("failed", "Refund Failed"),
        ),
        default="none",
        help_text="Status of refund for this booking.",
    )
    refund_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Amount refunded to the requester.",
    )
    refund_reason = models.CharField(
        max_length=50,
        blank=True,
        default="",
        help_text="Reason for refund (e.g., 'user_cancelled', 'provider_cancelled').",
    )
    refunded_at = models.DateTimeField(null=True, blank=True)
    
    # Stripe refund tracking
    stripe_refund_id = models.CharField(max_length=100, blank=True, null=True)
    
    # Flutterwave refund tracking
    flutterwave_refund_id = models.CharField(max_length=100, blank=True, null=True)

    # Provider's share of cancellation fee (credited to their wallet)
    provider_cancellation_fee = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Provider's 80% share of cancellation penalty.",
    )


    # --- Fee split + Stripe fee bookkeeping ---
    platform_fee_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    provider_earnings_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Provider share before Stripe processing fee (85% of total paid).",
    )
    stripe_fee_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Stripe processing fee for the payment (will be deducted from provider share).",
    )
    provider_net_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Provider net after Stripe fee deduction (provider_earnings_amount - stripe_fee_amount).",
    )
    stripe_charge_id = models.CharField(max_length=100, blank=True, null=True)
    stripe_balance_transaction_id = models.CharField(max_length=100, blank=True, null=True)
    stripe_transfer_id = models.CharField(max_length=100, blank=True, null=True)


    # --- Flutterwave bookkeeping (Africa gateway) ---
    payment_gateway = models.CharField(
        max_length=20,
        blank=True,
        default="",
        help_text="Payment gateway used for this booking (stripe|flutterwave|paystack).",
    )
    flutterwave_tx_ref = models.CharField(max_length=120, blank=True, null=True)
    flutterwave_transaction_id = models.CharField(max_length=64, blank=True, null=True)
    flutterwave_fee_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Flutterwave processing fee (if available).",
    )

    # --- Paystack bookkeeping (Ghana, Nigeria, South Africa, Kenya, Côte d'Ivoire) ---
    paystack_reference = models.CharField(
        max_length=120,
        blank=True,
        null=True,
        help_text="Paystack transaction reference.",
    )
    paystack_transaction_id = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="Paystack transaction ID.",
    )
    paystack_access_code = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="Paystack access code for payment page.",
    )
    paystack_fee_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Paystack processing fee.",
    )
    paystack_channel = models.CharField(
        max_length=30,
        blank=True,
        null=True,
        help_text="Paystack payment channel (card, bank, mobile_money, etc.).",
    )
    paystack_refund_id = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="Paystack refund ID if refunded.",
    )

    # Paystack tip fields
    tip_paystack_reference = models.CharField(
        max_length=120,
        blank=True,
        null=True,
        help_text="Paystack transaction reference for tip payment.",
    )
    tip_paystack_transaction_id = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text="Paystack transaction ID for tip payment.",
    )


    def __str__(self):
        provider_name = (
            self.service_provider.user.username
            if self.service_provider and self.service_provider.user
            else 'No provider yet'
        )
        return f"Request #{self.id} by {self.user.username} (provider: {provider_name})"

    def save(self, *args, **kwargs):
        """
        Set currency to user's preferred currency when creating booking.
        Auto-update status based on payment:
        - When payment is made, change status from 'pending' to 'open'
        """
        if not self.pk:
            self.currency = self.user.preferred_currency

        if self.payment_status == 'paid' and self.status == 'pending':
            self.status = 'open'

        super().save(*args, **kwargs)

    def is_chat_allowed(self) -> bool:
        if self.status in ('accepted', 'in_progress'):
            return True

        if self.status == 'completed' and self.completed_at:
            return timezone.now() <= self.completed_at + timedelta(days=1)

        return False

    def user_cancel_deadline(self):
        if not self.accepted_at:
            return None
        return self.accepted_at + timedelta(minutes=USER_FREE_CANCEL_BEFORE_MINUTES)

    def user_penalty_window_end(self):
        if not self.accepted_at:
            return None
        return self.accepted_at + timedelta(minutes=USER_FREE_CANCEL_AFTER_MINUTES)

    def can_user_cancel_without_penalty(self) -> bool:
        if self.status not in ('accepted', 'in_progress'):
            return True

        if not self.accepted_at:
            return True

        now = timezone.now()
        early_deadline = self.user_cancel_deadline()
        late_deadline = self.user_penalty_window_end()

        if early_deadline is None or late_deadline is None:
            return True

        if now <= early_deadline or now >= late_deadline:
            return True

        return False

    def is_within_free_cancel_period(self):
        """Check if current time is within 7 minutes of acceptance."""
        if not self.accepted_at:
            return True

        seven_minutes = timedelta(minutes=7)
        deadline = self.accepted_at + seven_minutes
        return timezone.now() <= deadline


class ServiceProviderPricing(models.Model):
    """Stores prices for different services offered by a provider"""
    provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='service_prices'
    )
    service_type = models.CharField(
        max_length=20,
        choices=SERVICE_TYPE_CHOICES,
    )
    price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0.00
    )
    offered = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['provider', 'service_type']

    def __str__(self):
        return f"{self.provider.user.username} - {self.service_type}: ${self.price}"


class Review(models.Model):
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='reviews'
    )
    service_request = models.ForeignKey(
        'ServiceRequest',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviews',
        help_text="The booking this review is for (optional for legacy reviews)"
    )

    service_provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='reviews'
    )
    rating = models.IntegerField(choices=[(i, i) for i in range(1, 6)])
    comment = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # Ensure one review per booking
        unique_together = [['user', 'service_request']]


    def __str__(self):
        return f"Review by {self.user.username} for {self.service_provider.user.username}"


class RequesterReview(models.Model):
    """
    Review of a requester (user) by a provider after completing a service.
    Helps providers know about requester behavior/reliability.
    """
    provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='requester_reviews_given'
    )
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='reviews_as_requester'
    )
    service_request = models.ForeignKey(
        'ServiceRequest',
        on_delete=models.CASCADE,
        related_name='requester_review',
        null=True,
        blank=True
    )
    rating = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        help_text="Rating from 1 to 5"
    )
    comment = models.TextField(
        blank=True,
        help_text="Optional comment about the requester"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        # Prevent duplicate reviews for same booking
        unique_together = ['provider', 'service_request']
        verbose_name = "Requester Review"
        verbose_name_plural = "Requester Reviews"
    
    def __str__(self):
        return f"{self.provider.user.username} → {self.user.username}: {self.rating}★"
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Update requester's average rating
        self._update_requester_rating()
    
    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)
        # Recalculate after deletion
        self._update_requester_rating()
    
    def _update_requester_rating(self):
        """Recalculate the requester's average rating."""
        from django.db.models import Avg, Count
        
        stats = RequesterReview.objects.filter(user=self.user).aggregate(
            avg_rating=Avg('rating'),
            count=Count('id')
        )
        
        self.user.requester_average_rating = stats['avg_rating']
        self.user.requester_review_count = stats['count'] or 0
        self.user.save(update_fields=['requester_average_rating', 'requester_review_count'])


class Notification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.message[:30]}"


class MFACode(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='mfa_codes'
    )
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    def is_valid(self):
        return (not self.used) and timezone.now() <= self.expires_at

    def __str__(self):
        return f"MFA for {self.user} - {self.code}"


class EmailVerificationCode(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='email_verification_codes'
    )
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    def is_valid(self):
        return (not self.used) and timezone.now() <= self.expires_at

    def __str__(self):
        return f"EmailVerify for {self.user} - {self.code}"


class PasswordResetCodeManager(models.Manager):
    """Custom manager for PasswordResetCode with common queries."""
    
    def create_for_user(self, user, expires_minutes: int = 15, ip_address: str = None, user_agent: str = None):
        """
        Create a new reset code for a user.
        Automatically generates code and sets expiry.
        """
        code = ''.join(random.choices(string.digits, k=6))
        expires_at = timezone.now() + timedelta(minutes=expires_minutes)
        
        return self.create(
            user=user,
            code=code,
            expires_at=expires_at,
            ip_address=ip_address or "",
            user_agent=user_agent or "",
        )
    
    def get_valid_code(self, user, code: str):
        """
        Get a valid (unused, not expired) code for a user.
        Returns None if not found or invalid.
        """
        reset_code = self.filter(
            user=user,
            code=code,
            used=False,
        ).order_by("-created_at").first()
        
        if reset_code and reset_code.is_valid():
            return reset_code
        return None
    
    def invalidate_all_for_user(self, user):
        """Mark all unused codes for a user as used."""
        return self.filter(user=user, used=False).update(
            used=True,
            used_at=timezone.now(),
        )
    
    def count_recent(self, user, hours: int = 1) -> int:
        """Count codes created in the last N hours for rate limiting."""
        since = timezone.now() - timedelta(hours=hours)
        return self.filter(user=user, created_at__gte=since).count()
    
    def cleanup_expired(self, days: int = 7) -> int:
        """Delete codes older than N days. Returns count deleted."""
        cutoff = timezone.now() - timedelta(days=days)
        deleted, _ = self.filter(created_at__lt=cutoff).delete()
        return deleted
    
    def get_recent_attempts(self, user, minutes: int = 30) -> int:
        """Count failed verification attempts in recent period."""
        since = timezone.now() - timedelta(minutes=minutes)
        return self.filter(
            user=user,
            created_at__gte=since,
            failed_attempts__gt=0,
        ).aggregate(total=models.Sum('failed_attempts'))['total'] or 0


class PasswordResetCode(models.Model):
    """
    Stores password reset codes sent via email.
    
    Features:
    - Automatic expiration
    - Rate limiting support
    - Failed attempt tracking
    - IP/User-Agent logging for security
    - Audit trail (created_at, used_at)
    """
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='password_reset_codes',
    )
    code = models.CharField(
        max_length=6,
        db_index=True,
        help_text="6-digit numeric reset code",
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        help_text="When this code expires",
    )
    used = models.BooleanField(
        default=False,
        db_index=True,
    )
    used_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the code was successfully used",
    )
    
    # Security tracking
    failed_attempts = models.PositiveSmallIntegerField(
        default=0,
        help_text="Number of failed verification attempts",
    )
    last_failed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp of last failed attempt",
    )
    
    # Request metadata (for security audit)
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP address that requested the reset",
    )
    user_agent = models.CharField(
        max_length=500,
        blank=True,
        default="",
        help_text="Browser/device info",
    )
    
    # Code used from (for additional security tracking)
    used_ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="IP address that used the code",
    )
    
    objects = PasswordResetCodeManager()

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "code"]),
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["created_at"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["used", "expires_at"]),
        ]
        verbose_name = "Password Reset Code"
        verbose_name_plural = "Password Reset Codes"

    def __str__(self):
        status = "used" if self.used else ("expired" if self.is_expired() else "valid")
        return f"PasswordReset for {self.user.email} - {self.code} ({status})"

    # -------------------------
    # Validation Methods
    # -------------------------
    
    def is_expired(self) -> bool:
        """Check if the code has expired."""
        return timezone.now() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if code is valid (not used, not expired, not locked)."""
        if self.used:
            return False
        if self.is_expired():
            return False
        if self.is_locked():
            return False
        return True
    
    def is_locked(self) -> bool:
        """
        Check if code is locked due to too many failed attempts.
        Locked after 5 failed attempts.
        """
        return self.failed_attempts >= 5
    
    def time_until_expiry(self) -> timedelta | None:
        """Returns time remaining until expiry, or None if expired."""
        if self.is_expired():
            return None
        return self.expires_at - timezone.now()
    
    def minutes_until_expiry(self) -> int:
        """Returns minutes until expiry, or 0 if expired."""
        remaining = self.time_until_expiry()
        if remaining is None:
            return 0
        return max(0, int(remaining.total_seconds() / 60))

    # -------------------------
    # Action Methods
    # -------------------------
    
    def mark_used(self, ip_address: str = None) -> None:
        """Mark the code as successfully used."""
        self.used = True
        self.used_at = timezone.now()
        if ip_address:
            self.used_ip_address = ip_address
        self.save(update_fields=["used", "used_at", "used_ip_address"])
    
    def record_failed_attempt(self) -> None:
        """Record a failed verification attempt."""
        self.failed_attempts += 1
        self.last_failed_at = timezone.now()
        self.save(update_fields=["failed_attempts", "last_failed_at"])
    
    def extend_expiry(self, minutes: int = 5) -> None:
        """Extend the expiry time (e.g., after a failed attempt message)."""
        if not self.used:
            self.expires_at = timezone.now() + timedelta(minutes=minutes)
            self.save(update_fields=["expires_at"])

    # -------------------------
    # Class Methods
    # -------------------------
    
    @classmethod
    def generate_code(cls) -> str:
        """Generate a random 6-digit code."""
        return ''.join(random.choices(string.digits, k=6))
    
    @classmethod
    def create_for_user(
        cls,
        user,
        expires_minutes: int = 15,
        ip_address: str = None,
        user_agent: str = None,
    ) -> 'PasswordResetCode':
        """
        Create a new reset code for a user.
        Convenience method that can also be accessed via the manager.
        """
        return cls.objects.create_for_user(
            user=user,
            expires_minutes=expires_minutes,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    
    @classmethod
    def can_request_new_code(cls, user, max_per_hour: int = 3) -> tuple[bool, str]:
        """
        Check if user can request a new code (rate limiting).
        Returns (allowed, reason).
        """
        recent_count = cls.objects.count_recent(user, hours=1)
        
        if recent_count >= max_per_hour:
            return False, f"Too many reset requests. Please try again later."
        
        return True, ""
    
    @classmethod
    def verify_code(
        cls,
        user,
        code: str,
        ip_address: str = None,
    ) -> tuple[bool, str, 'PasswordResetCode | None']:
        """
        Verify a reset code for a user.
        Returns (success, message, reset_code_object).
        
        Handles:
        - Invalid code
        - Expired code
        - Already used code
        - Too many failed attempts
        """
        # Find the code
        reset_code = cls.objects.filter(
            user=user,
            code=code,
        ).order_by("-created_at").first()
        
        if not reset_code:
            return False, "Invalid code.", None
        
        if reset_code.used:
            return False, "This code has already been used.", None
        
        if reset_code.is_expired():
            return False, "Code has expired. Please request a new one.", None
        
        if reset_code.is_locked():
            return False, "Too many failed attempts. Please request a new code.", None
        
        # Code is valid!
        return True, "Code verified.", reset_code

class ChatThread(models.Model):
    service_request = models.OneToOneField(
        ServiceRequest,
        on_delete=models.CASCADE,
        related_name='chat_thread',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ChatThread for request #{self.service_request_id}"


class ChatMessage(models.Model):
    thread = models.ForeignKey(
        ChatThread,
        on_delete=models.CASCADE,
        related_name='messages',
    )
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='sent_messages',
    )
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Msg #{self.id} in thread {self.thread_id} by {self.sender}"


class SupportThread(models.Model):
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='support_threads',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"SupportThread for {self.user.username}"


class SupportMessage(models.Model):
    thread = models.ForeignKey(
        SupportThread,
        on_delete=models.CASCADE,
        related_name='messages',
    )
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='support_messages',
    )
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"SupportMsg #{self.id} in thread {self.thread_id} by {self.sender}"


class LocationUpdate(models.Model):
    """Real-time location tracking for active bookings"""
    booking = models.ForeignKey(
        ServiceRequest,
        on_delete=models.CASCADE,
        related_name='location_updates'
    )
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='location_updates'
    )
    latitude = models.FloatField()
    longitude = models.FloatField()
    is_provider = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        role = "Provider" if self.is_provider else "User"
        return f"{role} location for Booking #{self.booking_id} at {self.timestamp}"


class StripePaymentIntent(models.Model):
    STATUS_CHOICES = (
        ('requires_payment_method', 'Requires Payment Method'),
        ('requires_confirmation', 'Requires Confirmation'),
        ('requires_action', 'Requires Action'),
        ('processing', 'Processing'),
        ('requires_capture', 'Requires Capture'),
        ('canceled', 'Canceled'),
        ('succeeded', 'Succeeded'),
    )

    service_request = models.OneToOneField(
        ServiceRequest,
        on_delete=models.CASCADE,
        related_name='stripe_payment'
    )
    payment_intent_id = models.CharField(max_length=100, unique=True)
    amount = models.IntegerField(help_text='Amount in cents')
    currency = models.CharField(max_length=3, default='usd')
    status = models.CharField(max_length=30, choices=STATUS_CHOICES)
    client_secret = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Payment {self.payment_intent_id} - ${self.amount / 100:.2f}"

class ProviderWallet(models.Model):
    """
    Wallet per provider per currency.
    We keep balances denormalized for fast reads, but every change is logged in WalletLedgerEntry.
    """
    provider = models.ForeignKey(ServiceProvider, on_delete=models.CASCADE, related_name="wallets")
    currency = models.CharField(max_length=3, default="USD")

    available_balance = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))
    pending_balance = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))

    lifetime_earnings = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))
    lifetime_payouts = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("provider", "currency")
        indexes = [
            models.Index(fields=["provider", "currency"]),
        ]

    def __str__(self):
        return f"Wallet(provider={self.provider_id}, {self.currency})"


class Payout(models.Model):
    METHOD_CHOICES = (
        ("weekly", "Weekly"),
        ("monthly", "Monthly"),
        ("instant", "Instant"),
        ("manual", "Manual"),
    )
    STATUS_CHOICES = (
        ("queued", "Queued"),
        ("processing", "Processing"),
        ("paid", "Paid"),
        ("failed", "Failed"),
        ("canceled", "Canceled"),
    )

    provider = models.ForeignKey(ServiceProvider, on_delete=models.CASCADE, related_name="payouts")
    currency = models.CharField(max_length=3, default="USD")

    gross_amount = models.DecimalField(max_digits=12, decimal_places=2)
    fee_amount = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))
    net_amount = models.DecimalField(max_digits=12, decimal_places=2)

    method = models.CharField(max_length=10, choices=METHOD_CHOICES, default="weekly")
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default="queued")

    stripe_transfer_id = models.CharField(max_length=100, blank=True, default="")

    # Flutterwave transfer tracking
    flutterwave_transfer_id = models.CharField(max_length=64, blank=True, default="")
    flutterwave_reference = models.CharField(max_length=128, blank=True, default="")
    flutterwave_status = models.CharField(max_length=32, blank=True, default="")
    failure_reason = models.TextField(blank=True, default="")

    # Paystack transfer tracking
    paystack_transfer_code = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="Paystack transfer code.",
    )
    paystack_transfer_id = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="Paystack transfer ID.",
    )
    paystack_reference = models.CharField(
        max_length=128,
        blank=True,
        default="",
        help_text="Paystack transfer reference.",
    )
    paystack_recipient_code = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="Paystack recipient code used for this transfer.",
    )
    paystack_status = models.CharField(
        max_length=32,
        blank=True,
        default="",
        help_text="Paystack transfer status.",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Payout#{self.id} provider={self.provider_id} {self.net_amount} {self.currency} ({self.status})"


class WalletLedgerEntry(models.Model):
    DIRECTION_CHOICES = (("credit", "Credit"), ("debit", "Debit"))
    STATUS_CHOICES = (
        ("pending", "Pending"),
        ("available", "Available"),
        ("paid", "Paid"),
        ("reversed", "Reversed"),
    )
    KIND_CHOICES = (
        ("earning", "Earning"),
        ("payout", "Payout"),
        ("fee", "Fee"),
        ("adjustment", "Adjustment"),
        ("refund", "Refund"),
    )

    wallet = models.ForeignKey(ProviderWallet, on_delete=models.CASCADE, related_name="entries")
    service_request = models.ForeignKey(ServiceRequest, on_delete=models.SET_NULL, null=True, blank=True, related_name="wallet_entries")
    payout = models.ForeignKey(Payout, on_delete=models.SET_NULL, null=True, blank=True, related_name="ledger_entries")

    direction = models.CharField(max_length=6, choices=DIRECTION_CHOICES)
    kind = models.CharField(max_length=12, choices=KIND_CHOICES)

    # Always store a positive amount. direction determines +/- effect.
    amount = models.DecimalField(max_digits=12, decimal_places=2)

    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    description = models.CharField(max_length=255, blank=True, default="")

    available_at = models.DateTimeField(null=True, blank=True)  # when pending becomes available
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["wallet", "created_at"]),
            models.Index(fields=["status", "available_at"]),
            models.Index(fields=["kind"]),
        ]

    def __str__(self):
        return f"LedgerEntry#{self.id} {self.direction} {self.amount} {self.wallet.currency} ({self.status})"

class AccountDeletionFeedback(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="account_deletion_feedback",
    )
    role = models.CharField(max_length=20, blank=True, default="")
    reasons = models.JSONField(default=list, blank=True)  # list of strings
    reason_text = models.TextField(blank=True, default="")
    suggestions = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"AccountDeletionFeedback #{self.id} user={self.user_id} role={self.role}"


class ProviderPayoutSettings(models.Model):
    FREQUENCY_CHOICES = (
        ("weekly", "Weekly"),
        ("monthly", "Monthly"),
    )
    
    # Only allow Tuesday (1), Thursday (3), Friday (4)
    PAYOUT_DAY_CHOICES = (
        (1, "Tuesday"),
        (3, "Thursday"),
        (4, "Friday"),
    )
    provider = models.OneToOneField(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name="payout_settings",
    )

    auto_payout_enabled = models.BooleanField(default=True)

    # Payout frequency: weekly or monthly
    payout_frequency = models.CharField(
        max_length=10,
        choices=FREQUENCY_CHOICES,
        default="weekly",
        help_text="How often automatic payouts are processed.",
    )

    # Provider chooses payout weekday (only Tue/Thu/Fri allowed for weekly)
    payout_weekday = models.PositiveSmallIntegerField(
        choices=PAYOUT_DAY_CHOICES,
        default=1,  # Tuesday
        help_text="Day of week for weekly payouts. Ignored for monthly.",
    )

    # Hour UTC when they want payout processed (0-23). Cron can run hourly/daily;
    # we use this as a preference gate.
    payout_hour_utc = models.PositiveSmallIntegerField(default=2)

    # Only auto-payout if available >= threshold (currency-specific wallets apply this threshold per wallet currency).
    minimum_payout_amount = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))

    # Provider can disable instant cashout
    instant_payout_enabled = models.BooleanField(default=True)

    last_auto_payout_at = models.DateTimeField(null=True, blank=True)

    # =============================================================================
    # INSTANT PAYOUT USAGE TRACKING
    # =============================================================================
    instant_payout_count_this_period = models.PositiveSmallIntegerField(
        default=0,
        help_text="Number of instant payouts used in current payout period.",
    )
    instant_payout_period_start = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Start of current instant payout tracking period.",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def get_instant_payout_limit(self) -> int:
        """
        Returns max instant payouts allowed per period.
        Now unlimited (-1 means no limit).
        """
        return -1

    def get_instant_payouts_remaining(self) -> int:
        """
        Returns remaining instant payouts. -1 means unlimited.
        """
        return -1

    def can_use_instant_payout(self) -> bool:
        """
        Returns True if provider can use instant payout.
        """
        if not self.instant_payout_enabled:
            return False
        return True

    def record_instant_payout_usage(self) -> None:
        """
        Increments the instant payout counter for this period.
        """
        self.instant_payout_count_this_period = (self.instant_payout_count_this_period or 0) + 1
        self.save(update_fields=["instant_payout_count_this_period", "updated_at"])

    def reset_instant_payout_counter(self) -> None:
        """
        Resets the instant payout counter (called when scheduled payout runs).
        """
        self.instant_payout_count_this_period = 0
        self.instant_payout_period_start = timezone.now()
        self.save(update_fields=["instant_payout_count_this_period", "instant_payout_period_start", "updated_at"])

    def get_next_scheduled_payout_date(self) -> datetime | None:
        """
        Calculates the next scheduled payout date for display purposes.
        """
        from django.utils import timezone
        from datetime import timedelta
        
        now = timezone.now()
        
        if self.payout_frequency == "monthly":
            # Next 1st of month
            if now.day == 1:
                # If it's the 1st but after payout hour, next month
                if now.hour >= self.payout_hour_utc:
                    if now.month == 12:
                        return now.replace(year=now.year + 1, month=1, day=1, hour=self.payout_hour_utc, minute=0, second=0, microsecond=0)
                    return now.replace(month=now.month + 1, day=1, hour=self.payout_hour_utc, minute=0, second=0, microsecond=0)
                return now.replace(hour=self.payout_hour_utc, minute=0, second=0, microsecond=0)
            else:
                if now.month == 12:
                    return now.replace(year=now.year + 1, month=1, day=1, hour=self.payout_hour_utc, minute=0, second=0, microsecond=0)
                return now.replace(month=now.month + 1, day=1, hour=self.payout_hour_utc, minute=0, second=0, microsecond=0)
        
        else:  # weekly
            # Find next occurrence of payout_weekday
            days_ahead = self.payout_weekday - now.weekday()
            if days_ahead < 0:  # Target day already happened this week
                days_ahead += 7
            elif days_ahead == 0:  # Today is the day
                if now.hour >= self.payout_hour_utc:
                    days_ahead = 7  # Already passed, next week
            
            next_date = now + timedelta(days=days_ahead)
            return next_date.replace(hour=self.payout_hour_utc, minute=0, second=0, microsecond=0)

    class Meta:
        indexes = [models.Index(fields=["auto_payout_enabled", "payout_weekday"])]

    def __str__(self):
        return f"PayoutSettings(provider={self.provider_id}, auto={self.auto_payout_enabled})"

    # payout routing: stripe for non-Africa, flutterwave for Africa (or provider preference)
    PAYOUT_GATEWAY_CHOICES = (
        ("stripe", "Stripe"),
        ("flutterwave", "Flutterwave"),
        ("paystack", "Paystack"),
    )
    payout_gateway = models.CharField(max_length=20, choices=PAYOUT_GATEWAY_CHOICES, default="stripe")

    # Flutterwave destination (minimal; expand per country needs)
    # method: "bank" or "mobile_money"
    flutterwave_method = models.CharField(max_length=30, blank=True, default="")
    flutterwave_currency = models.CharField(max_length=10, blank=True, default="")
    flutterwave_full_name = models.CharField(max_length=120, blank=True, default="")
    flutterwave_country_code = models.CharField(max_length=10, blank=True, default="")
    flutterwave_zip_code = models.CharField(max_length=20, blank=True, default="")
    flutterwave_bank_code = models.CharField(max_length=30, blank=True, default="")

    flutterwave_bank_name = models.CharField(
        max_length=100, 
        blank=True, 
        default="",
        help_text="Human readable bank name (e.g., GCB Bank, Ecobank)"
    )

    flutterwave_account_number = models.CharField(max_length=30, blank=True, default="")
    flutterwave_phone_number = models.CharField(max_length=30, blank=True, default="")

    flutterwave_mobile_network = models.CharField(
        max_length=50, 
        blank=True, 
        default="",
        help_text="Mobile money network code (e.g., mtn, vodafone, airtel)"
    )

    flutterwave_beneficiary_id = models.CharField(max_length=64, blank=True, default="")

    # =============================================================================
    # PAYSTACK PAYOUT SETTINGS (Ghana, Nigeria, South Africa, Kenya, Côte d'Ivoire)
    # =============================================================================
    paystack_recipient_code = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="Paystack transfer recipient code (created via API).",
    )
    paystack_bank_code = models.CharField(
        max_length=30,
        blank=True,
        default="",
        help_text="Paystack bank code.",
    )
    paystack_bank_name = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Human readable bank name for Paystack.",
    )
    paystack_account_number = models.CharField(
        max_length=30,
        blank=True,
        default="",
        help_text="Bank account number for Paystack payouts.",
    )
    paystack_account_name = models.CharField(
        max_length=120,
        blank=True,
        default="",
        help_text="Verified account name from Paystack.",
    )
    paystack_currency = models.CharField(
        max_length=10,
        blank=True,
        default="",
        help_text="Currency for Paystack payouts (NGN, GHS, ZAR, KES, XOF).",
    )
    paystack_recipient_type = models.CharField(
        max_length=30,
        blank=True,
        default="",
        help_text="Recipient type: nuban, ghipss, basa, mobile_money.",
    )

    class Meta:
         indexes = [models.Index(fields=["auto_payout_enabled", "payout_weekday"])]


# =============================================================================
# PROXY MODELS FOR ADMIN VIEWS
# =============================================================================

class PendingKYCProvider(ServiceProvider):
    """Proxy model to show only pending KYC verifications in admin"""
    class Meta:
        proxy = True
        verbose_name = "Pending KYC Verification"
        verbose_name_plural = "Pending KYC Verifications"

