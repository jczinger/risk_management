"""Test settings — fast hashing, eager tasks, deterministic keys."""

import base64

from .base import *  # noqa: F401,F403
from .base import env

DEBUG = False

ALLOWED_HOSTS = ["*"]

# Fixed, obviously-fake key so encryption round-trip tests are reproducible.
PLATFORM_MASTER_KEY = base64.b64encode(b"vms-test-master-key-32-bytes--!!").decode()

CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

EMAIL_PROVIDER = "locmem"

WEBAUTHN_RP_ID = "testserver"
VMS_BASE_DOMAIN = "testserver"
VMS_LINK_SCHEME = "http"
VMS_LINK_HOST = "testserver"

SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}

# Serve static files straight from the app directories, so the suite does not need a
# collectstatic run first.
WHITENOISE_USE_FINDERS = True
WHITENOISE_AUTOREFRESH = True

# Rate limiting needs a real cache to be meaningful; tests assert on it directly.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "vms-test",
    }
}

POSTGRES_HOST = env("POSTGRES_HOST", default="localhost")
