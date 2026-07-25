"""
Shared Django settings for VMS.

Environment-specific modules (dev.py / prod.py) import * from here and override.
Every secret and every deployment-specific value comes from the environment; see
.env.example for the full list.
"""

from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parent.parent.parent

env = environ.Env()

# Read .env when present. In Docker the values arrive via env_file instead, and
# real environment variables always win over the file.
_dotenv = BASE_DIR / ".env"
if _dotenv.exists():
    environ.Env.read_env(_dotenv)


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

SECRET_KEY = env("DJANGO_SECRET_KEY")
DEBUG = env.bool("DEBUG", default=False)
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=[])
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[])

# The bare domain tenant subdomains hang off of, e.g. "vms.example.ca" makes a
# tenant reachable at "firstoac.vms.example.ca".
VMS_BASE_DOMAIN = env("VMS_BASE_DOMAIN", default="localhost")

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# ---------------------------------------------------------------------------
# Applications — split across schemas by django-tenants
# ---------------------------------------------------------------------------
#
# SHARED_APPS live in the `public` schema. TENANT_APPS get their own copy of
# their tables inside every tenant schema.
#
# `accounts` and `django.contrib.auth` appear in BOTH lists on purpose: the
# platform super-admin lives in public, while each church's screening admins live
# inside that church's own schema. django-tenants sets search_path to
# "<tenant>,public", so from a tenant request the tenant's own user table wins.
# See BUILD_NOTES.md for the reasoning.

SHARED_APPS = [
    "django_tenants",
    "apps.tenants",
    # Auth stack, shared copy — backs the platform super-admin.
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "apps.accounts",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.admin",
    "django_htmx",
]

TENANT_APPS = [
    # Auth stack, per-tenant copy — backs that church's screening admins.
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "apps.accounts",
    # Church data. All of it is tenant-scoped.
    "apps.core",
    "apps.org",
    "apps.requirements",
    "apps.documents",
    "apps.notifications",
    "apps.reporting",
]

# Django needs each app listed exactly once; order follows SHARED_APPS then the
# tenant-only extras.
INSTALLED_APPS = SHARED_APPS + [a for a in TENANT_APPS if a not in SHARED_APPS]

TENANT_MODEL = "tenants.Tenant"
TENANT_DOMAIN_MODEL = "tenants.Domain"

# Requests whose hostname matches no Domain row get this response rather than a
# stack trace.
SHOW_PUBLIC_IF_NO_TENANT_FOUND = False

AUTH_USER_MODEL = "accounts.User"

# auth.E003 insists USERNAME_FIELD be unique. `User.email` is encrypted, and randomized
# ciphertext can never collide, so a unique constraint on that column would be
# meaningless. Uniqueness is enforced instead by `User.email_index` — a keyed hash of
# the normalised address that does carry a UNIQUE constraint — and the manager's
# get_by_natural_key() looks users up through it. See apps/core/blind_index.py.
SILENCED_SYSTEM_CHECKS = ["auth.E003"]


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

MIDDLEWARE = [
    # Must be first: resolves the hostname to a tenant and sets the search_path. Our
    # subclass adds one carve-out so the container health check answers on any hostname.
    "apps.core.middleware.VMSTenantMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django_htmx.middleware.HtmxMiddleware",
    # Records the acting user + request metadata for the audit trail.
    "apps.core.middleware.AuditContextMiddleware",
    # Forces a freshly provisioned tenant's admin through the DEK backup step.
    "apps.tenants.middleware.ForceKeyBackupMiddleware",
]

# Separate URLconfs: the public schema serves the super-admin console, tenant
# schemas serve the church app.
ROOT_URLCONF = "config.urls_tenant"
PUBLIC_SCHEMA_URLCONF = "config.urls_public"


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.core.context_processors.vms_context",
            ],
        },
    },
]


# ---------------------------------------------------------------------------
# Database — one Postgres database, one schema per tenant
# ---------------------------------------------------------------------------

DATABASES = {
    "default": {
        "ENGINE": "django_tenants.postgresql_backend",
        "NAME": env("POSTGRES_DB", default="vms"),
        "USER": env("POSTGRES_USER", default="vms"),
        "PASSWORD": env("POSTGRES_PASSWORD", default=""),
        "HOST": env("POSTGRES_HOST", default="db"),
        "PORT": env("POSTGRES_PORT", default="5432"),
        "CONN_MAX_AGE": env.int("POSTGRES_CONN_MAX_AGE", default=60),
    }
}

DATABASE_ROUTERS = ("django_tenants.routers.TenantSyncRouter",)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

# Argon2 first: every new/changed password is hashed with it, and existing hashes
# in the weaker schemes are upgraded transparently on next login.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/accounts/login/"

# WebAuthn Relying Party. The RP ID must be a registrable suffix of the origin
# the browser sees; using the base domain lets one passkey work across tenant
# subdomains.
WEBAUTHN_RP_ID = env("WEBAUTHN_RP_ID", default=VMS_BASE_DOMAIN)
WEBAUTHN_RP_NAME = env("WEBAUTHN_RP_NAME", default="Volunteer Management System")

# Failed logins allowed per (username, IP) before the form starts refusing.
LOGIN_RATELIMIT = env("LOGIN_RATELIMIT", default="10/5m")


# ---------------------------------------------------------------------------
# Sessions & security
# ---------------------------------------------------------------------------

SESSION_COOKIE_NAME = "vms_session"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_AGE = env.int("SESSION_COOKIE_AGE", default=60 * 60 * 12)

CSRF_COOKIE_HTTPONLY = False  # HTMX reads the token from the cookie.
CSRF_COOKIE_SAMESITE = "Lax"

X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"

# Nginx Proxy Manager terminates TLS and forwards the original scheme here.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

# 32 random bytes, base64-encoded. Wraps every per-tenant DEK.
PLATFORM_MASTER_KEY = env("PLATFORM_MASTER_KEY", default="")


# ---------------------------------------------------------------------------
# Static & media
# ---------------------------------------------------------------------------

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

# Per-upload ceiling, enforced in the document forms.
VMS_MAX_UPLOAD_MB = env.int("VMS_MAX_UPLOAD_MB", default=20)
VMS_MAX_UPLOAD_BYTES = VMS_MAX_UPLOAD_MB * 1024 * 1024

# Encrypted uploads are read into memory to be sealed, so never let Django spool
# a file larger than the ceiling we accept.
DATA_UPLOAD_MAX_MEMORY_SIZE = VMS_MAX_UPLOAD_BYTES + (1024 * 1024)
FILE_UPLOAD_MAX_MEMORY_SIZE = 2 * 1024 * 1024


# ---------------------------------------------------------------------------
# Internationalisation
# ---------------------------------------------------------------------------

LANGUAGE_CODE = "en-ca"
TIME_ZONE = env("TZ", default="America/Vancouver")
USE_I18N = True
USE_TZ = True


# ---------------------------------------------------------------------------
# Email — ACS SMTP behind a provider abstraction
# ---------------------------------------------------------------------------

EMAIL_PROVIDER = env("EMAIL_PROVIDER", default="console")
EMAIL_HOST = env("EMAIL_HOST", default="smtp.azurecomm.net")
EMAIL_PORT = env.int("EMAIL_PORT", default=587)
EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS", default=True)
EMAIL_HOST_USER = env("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", default="")
EMAIL_TIMEOUT = env.int("EMAIL_TIMEOUT", default=30)
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="no-reply@localhost")
SERVER_EMAIL = env("SERVER_EMAIL", default=DEFAULT_FROM_EMAIL)


# ---------------------------------------------------------------------------
# Celery
# ---------------------------------------------------------------------------

CELERY_BROKER_URL = env("REDIS_URL", default="redis://redis:6379/0")
CELERY_RESULT_BACKEND = None  # Fire-and-forget jobs; nothing reads results.
CELERY_TASK_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TIMEZONE = TIME_ZONE
CELERY_ENABLE_UTC = True
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_HIJACK_ROOT_LOGGER = False

# Hour of the night the compliance recompute + reminder digest runs.
VMS_NIGHTLY_HOUR = env.int("VMS_NIGHTLY_HOUR", default=2)


# ---------------------------------------------------------------------------
# Logging — deliberately excludes request bodies and PII
# ---------------------------------------------------------------------------

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "plain": {
            "format": "{asctime} {levelname} {name} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "plain",
        },
    },
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {
        "django.db.backends": {"level": "WARNING", "propagate": True},
        # Suppresses the noisy full-traceback email on SuspiciousOperation etc.
        "django.security": {"level": "WARNING", "propagate": True},
        "vms": {"level": env("VMS_LOG_LEVEL", default="INFO"), "propagate": True},
    },
}
