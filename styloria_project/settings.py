# styloria_project/settings.py

"""Django settings for styloria_project project."""

import os
import dj_database_url
from pathlib import Path
from dotenv import load_dotenv
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / '.env')

# =============================================================================
# MICROSOFT GRAPH (Email)
# =============================================================================
MS_GRAPH_CLIENT_ID = os.getenv("MS_GRAPH_CLIENT_ID", "").strip()
MS_GRAPH_CLIENT_SECRET = os.environ.get('MS_GRAPH_CLIENT_SECRET', '')
MS_GRAPH_TENANT_ID = os.environ.get('MS_GRAPH_TENANT_ID', '')
MS_GRAPH_SENDER_EMAIL = os.environ.get('MS_GRAPH_SENDER_EMAIL', '')
MS_GRAPH_AUTHORITY = "https://login.microsoftonline.com/consumers"
MS_GRAPH_SCOPES = ["User.Read", "Mail.Send"]
MS_GRAPH_TOKEN_CACHE_PATH = BASE_DIR / "ms_graph_token_cache.bin"


# =============================================================================
# EMAIL SETTINGS
# =============================================================================
# SendGrid API Key (used by both API and SMTP)
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')

# Default from email
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'styloria_mdk303@outlook.com')

# SMTP settings (backup/local testing)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.sendgrid.net')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', 'apikey')
EMAIL_HOST_PASSWORD = os.environ.get('SENDGRID_API_KEY')
EMAIL_TIMEOUT = 30

# ============================================================================
# CORE DJANGO SETTINGS
# =============================================================================
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'dev-secret-key-change-me')
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

if DEBUG:
    ALLOWED_HOSTS = ['*']
else:
    raw_hosts = os.getenv('DJANGO_ALLOWED_HOSTS', '')
    ALLOWED_HOSTS = [h.strip() for h in raw_hosts.split(',') if h.strip()] + [
        '.railway.app',  # Railway's default domain
    ]

# =============================================================================
# INSTALLED APPS
# =============================================================================
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_extensions',

    # Third-party
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'channels',
    'whitenoise.runserver_nostatic',

    # Local
    'core.apps.CoreConfig',
]

# =============================================================================
# MIDDLEWARE
# =============================================================================
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# =============================================================================
# URL & TEMPLATE CONFIGURATION
# =============================================================================
ROOT_URLCONF = 'styloria_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'styloria_project.wsgi.application'
ASGI_APPLICATION = 'styloria_project.asgi.application'

# =============================================================================
# DATABASE
# =============================================================================
DATABASE_URL = os.environ.get('DATABASE_URL')
USE_REMOTE_DB = os.environ.get('USE_REMOTE_DB', 'False').lower() == 'true'
 
if DATABASE_URL:
    # Production: Railway provides DATABASE_URL automatically
    db_config = dj_database_url.config(
        default=DATABASE_URL,
        conn_max_age=0,  # Disable persistent connections
        conn_health_checks=True,
    )
    # Add OPTIONS after parsing
    db_config['OPTIONS'] = {
        'connect_timeout': 10,
    }
    DATABASES = {'default': db_config}
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.getenv('DB_NAME', 'styloria_db'),
            'USER': os.getenv('DB_USER', 'postgres'),
            'PASSWORD': os.getenv('DB_PASSWORD', ''),
            'HOST': os.getenv('DB_HOST', 'localhost'),
            'PORT': os.getenv('DB_PORT', '5432'),
            'CONN_MAX_AGE': 0,
            'OPTIONS': {
                'connect_timeout': 10,
            }
        }
    }

# =============================================================================
# AUTHENTICATION
# =============================================================================
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'core.password_validators.ComplexityValidator'},
]

AUTH_USER_MODEL = 'core.CustomUser'

# =============================================================================
# INTERNATIONALIZATION
# =============================================================================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# =============================================================================
# STATIC FILES
# =============================================================================
STATIC_URL = '/static/'
STATICFILES_DIRS = []

# Only add static dir if it exists (prevents errors during collectstatic)
_core_static = BASE_DIR / "core" / "static"
if _core_static.exists():
    STATICFILES_DIRS.append(_core_static)

STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = 'whitenoise.storage.CompressedStaticFilesStorage'

# Only set if the directory exists
_whitenoise_root = BASE_DIR / "core" / "static_root"
if _whitenoise_root.exists():
    WHITENOISE_ROOT = _whitenoise_root

# =============================================================================
# PROXY SETTINGS (for ngrok/reverse proxy)
# =============================================================================
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# =============================================================================
# DEFAULT AUTO FIELD
# =============================================================================
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# =============================================================================
# STRIPE SETTINGS
# =============================================================================
STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY', '')
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY', '')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET', '')

# Stripe Connect (used for account onboarding links)
STRIPE_CONNECT_RETURN_URL = os.getenv("STRIPE_CONNECT_RETURN_URL", "").strip()
STRIPE_CONNECT_REFRESH_URL = os.getenv("STRIPE_CONNECT_REFRESH_URL", "").strip()
STRIPE_DEFAULT_CONNECT_COUNTRY = os.getenv("STRIPE_DEFAULT_CONNECT_COUNTRY", "US").strip()

# Africa routing rule:
# Comma-separated country_name values, e.g. "South Africa,Egypt"
STRIPE_ALLOWED_AFRICAN_COUNTRIES = os.getenv("STRIPE_ALLOWED_AFRICAN_COUNTRIES", "South Africa")

# =============================================================================
# FLUTTERWAVE SETTINGS
# =============================================================================
FLUTTERWAVE_PUBLIC_KEY = os.environ.get("FLUTTERWAVE_PUBLIC_KEY", "")
FLUTTERWAVE_SECRET_KEY = os.environ.get("FLUTTERWAVE_SECRET_KEY", "")
FLUTTERWAVE_ENCRYPTION_KEY = os.environ.get("FLUTTERWAVE_ENCRYPTION_KEY", "")
FLUTTERWAVE_TEST_MODE = os.environ.get("FLUTTERWAVE_TEST_MODE", "True").lower() == "true"
FLUTTERWAVE_REDIRECT_URL = os.environ.get("FLUTTERWAVE_REDIRECT_URL", "")
FLUTTERWAVE_BASE_URL = 'https://api.flutterwave.com/v3'
FLUTTERWAVE_WEBHOOK_HASH = os.environ.get("FLUTTERWAVE_WEBHOOK_HASH", "")


# =============================================================================
# PAYSTACK SETTINGS
# =============================================================================
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "sk_test_xxx")
PAYSTACK_PUBLIC_KEY = os.environ.get("PAYSTACK_PUBLIC_KEY", "pk_test_xxx")
PAYSTACK_CALLBACK_URL = os.environ.get("PAYSTACK_CALLBACK_URL", "https://yourdomain.com/paystack/callback/")

# Ensure your PUBLIC_BASE_URL is set for callback URLs
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://api.yourdomain.com")


# ========================
# CELERY CONFIGURATION
# ========================

REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL

CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'

CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes

# Store task results for 24 hours
CELERY_RESULT_EXPIRES = 86400

# =============================================================================
# GOOGLE MAPS API (for Directions/ETA)
# =============================================================================
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "")

# =============================================================================
# DEV TUNNEL / PUBLIC URL
# =============================================================================
# Optional: use a dev tunnel base URL (ngrok) when running locally.
# Example: DEV_TUNNEL_URL=https://locally-sinistrodextral-raelene.ngrok-free.dev
DEV_TUNNEL_URL = os.getenv("DEV_TUNNEL_URL", "").strip()
if DEBUG and DEV_TUNNEL_URL:
    PUBLIC_BASE_URL = DEV_TUNNEL_URL

# Flutterwave URLs (built from PUBLIC_BASE_URL)
FLUTTERWAVE_WEBHOOK_URL = (f"{PUBLIC_BASE_URL.rstrip('/')}/api/flutterwave/webhook/") if PUBLIC_BASE_URL else ""
FLUTTERWAVE_REDIRECT_URL = (f"{PUBLIC_BASE_URL.rstrip('/')}/flutterwave/redirect/") if PUBLIC_BASE_URL else ""

# Deep link scheme for mobile app
APP_DEEPLINK_SCHEME = os.getenv("APP_DEEPLINK_SCHEME", "styloria").strip()

# =============================================================================
# CSRF TRUSTED ORIGINS (must come AFTER PUBLIC_BASE_URL is defined)
# =============================================================================
CSRF_TRUSTED_ORIGINS = [
    'https://*.flutterwave.com',
    'https://checkout.flutterwave.com',
    'https://*.railway.app',  # Railway's default domain
]
if PUBLIC_BASE_URL and PUBLIC_BASE_URL.startswith("https://"):
    CSRF_TRUSTED_ORIGINS.append(PUBLIC_BASE_URL)

# =============================================================================
# CORS SETTINGS
# =============================================================================
if DEBUG:
    CORS_ALLOW_ALL_ORIGINS = True

else:
    CORS_ALLOWED_ORIGINS = [
        # Add your Flutter web app domain if you have one
        # 'https://your-flutter-web.com',
    ]
    # Allow mobile apps (they don't send Origin header)
    CORS_ALLOW_ALL_ORIGINS = False
    CORS_ALLOW_CREDENTIALS = True

# =============================================================================
# PAYOUT / WALLET SETTINGS
# =============================================================================
PAYOUT_COOLDOWN_HOURS = int(os.getenv("PAYOUT_COOLDOWN_HOURS", "168"))  # 7 days

# Weekly payout schedule (run via cron/management command)
WEEKLY_PAYOUT_WEEKDAY = int(os.getenv("WEEKLY_PAYOUT_WEEKDAY", "0"))  # Monday=0
WEEKLY_PAYOUT_HOUR_UTC = int(os.getenv("WEEKLY_PAYOUT_HOUR_UTC", "2"))

# Instant payout fee (platform fee to monetize fast cash out)
INSTANT_PAYOUT_FEE_RATE = os.getenv("INSTANT_PAYOUT_FEE_RATE", "0.05")  # 5%
INSTANT_PAYOUT_MIN_FEE = os.getenv("INSTANT_PAYOUT_MIN_FEE", "0.50")     # $0.50
INSTANT_PAYOUT_MIN_AMOUNT = os.getenv("INSTANT_PAYOUT_MIN_AMOUNT", "5.00")

# Safety limits
INSTANT_PAYOUT_DAILY_MAX = os.getenv("INSTANT_PAYOUT_DAILY_MAX", "500.00")

# =============================================================================
# PLATFORM FEE SETTINGS
# =============================================================================
PLATFORM_FEE_PERCENT = os.getenv("PLATFORM_FEE_PERCENT", "0.20")  # 20%

# Cancellation penalty (applied when user cancels after 7 minutes)
CANCELLATION_PENALTY_PERCENT = os.getenv("CANCELLATION_PENALTY_PERCENT", "0.10")  # 10%


# =============================================================================
# MEDIA FILES (uploads)
# =============================================================================
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# =============================================================================
# CLOUD STORAGE (Cloudflare R2)
# =============================================================================
USE_CLOUD_STORAGE = os.environ.get('USE_CLOUD_STORAGE', 'False').lower() == 'true'

if USE_CLOUD_STORAGE:
    INSTALLED_APPS += ["storages"]
    
    # Cloudflare R2 Configuration
    AWS_ACCESS_KEY_ID = os.environ.get('R2_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('R2_SECRET_ACCESS_KEY')
    AWS_STORAGE_BUCKET_NAME = os.environ.get('R2_BUCKET_NAME', 'styloria-media')
    AWS_S3_ENDPOINT_URL = os.environ.get('R2_ENDPOINT_URL')
    AWS_S3_REGION_NAME = 'auto'
    
    # Storage settings
    AWS_DEFAULT_ACL = None
    AWS_S3_OBJECT_PARAMETERS = {'CacheControl': 'max-age=86400'}
    AWS_QUERYSTRING_AUTH = True
    AWS_S3_SIGNATURE_VERSION = "s3v4"
    AWS_S3_ADDRESSING_STYLE = 'path'
    AWS_S3_FILE_OVERWRITE = False
    
    # Custom domain (optional)
    R2_CUSTOM_DOMAIN = os.environ.get('R2_CUSTOM_DOMAIN', '')
    if R2_CUSTOM_DOMAIN:
        AWS_S3_CUSTOM_DOMAIN = R2_CUSTOM_DOMAIN
        MEDIA_URL = f'https://{R2_CUSTOM_DOMAIN}/'
    else:
        MEDIA_URL = f'{AWS_S3_ENDPOINT_URL}/{AWS_STORAGE_BUCKET_NAME}/'

    # USE OUR CUSTOM STORAGE BACKEND - NOT django-storages
    STORAGES = {
        "default": {"BACKEND": "core.storage_backends.CloudflareR2Storage"},
        "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
    }
    
    DEFAULT_FILE_STORAGE = 'core.storage_backends.CloudflareR2Storage'
    
    print("✅ Using CloudflareR2Storage for media files")  # Debug line - remove later
else:
    MEDIA_URL = '/media/'
    MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
    print("⚠️ Using local filesystem storage")  # Debug line - remove later

# =============================================================================
# FILE UPLOAD SETTINGS
# =============================================================================
# Certification document settings
CERTIFICATION_ALLOWED_EXTENSIONS = ['png', 'jpg', 'jpeg', 'pdf']
CERTIFICATION_MAX_SIZE_IMAGE = 5 * 1024 * 1024  # 5 MB for images
CERTIFICATION_MAX_SIZE_PDF = 10 * 1024 * 1024   # 10 MB for PDFs

# General file upload limits
DATA_UPLOAD_MAX_MEMORY_SIZE = 15 * 1024 * 1024  # 15 MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 15 * 1024 * 1024  # 15 MB


# =============================================================================
# REST FRAMEWORK
# =============================================================================
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_PARSER_CLASSES': (
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10,
}

# =============================================================================
# SIMPLE JWT
# =============================================================================
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
}

# =============================================================================
# CHANNEL LAYERS (WebSockets)
# =============================================================================
if REDIS_URL and not REDIS_URL.startswith('redis://localhost'):
    CHANNEL_LAYERS = {
        'default': {
            'BACKEND': 'channels_redis.core.RedisChannelLayer',
            'CONFIG': {'hosts': [REDIS_URL]},
        },
    }
else:
    CHANNEL_LAYERS = {'default': {'BACKEND': 'channels.layers.InMemoryChannelLayer'}}

# =============================================================================
# OTP / EMAIL SETTINGS
# =============================================================================
OTP_EMAIL = {
    'FROM_ADDRESS': 'no-reply@styloria.com',
    'SUBJECT': 'Your Styloria Login Verification Code',
}

# =============================================================================
# TWILIO (SMS)
# =============================================================================
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN', '')
TWILIO_FROM_NUMBER = os.getenv('TWILIO_FROM_NUMBER', '')


# =============================================================================
# PRODUCTION SECURITY SETTINGS
# =============================================================================
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True

# =============================================================================
# LOGGING (Production)
# =============================================================================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
            'propagate': False,
        },
        'django.request': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}