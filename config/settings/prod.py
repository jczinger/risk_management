"""
Production settings.

Fails fast at import time rather than booting a misconfigured system that would
silently store recoverable plaintext or accept requests for any hostname.
"""

from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F401,F403
from .base import ALLOWED_HOSTS, EMAIL_PROVIDER, PLATFORM_MASTER_KEY, SECRET_KEY, env

DEBUG = False

# --- Refuse to start when something safety-critical is missing -------------

if not PLATFORM_MASTER_KEY:
    raise ImproperlyConfigured(
        "PLATFORM_MASTER_KEY is required in production. It wraps every tenant's "
        "data-encryption key. Generate one with `python manage.py generate_key` "
        "and store a copy in Keeper Security before going live."
    )

if not ALLOWED_HOSTS:
    raise ImproperlyConfigured("ALLOWED_HOSTS must be set in production.")

if SECRET_KEY.startswith("change-me") or len(SECRET_KEY) < 50:
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be a unique value of 50+ characters.")

if EMAIL_PROVIDER == "smtp" and not env("EMAIL_HOST_PASSWORD", default=""):
    raise ImproperlyConfigured("EMAIL_HOST_PASSWORD is required when EMAIL_PROVIDER=smtp.")


# --- Transport security ---------------------------------------------------
#
# Nginx Proxy Manager terminates TLS and sets X-Forwarded-Proto (honored via
# SECURE_PROXY_SSL_HEADER in base.py). HSTS is emitted by the proxy; leaving it
# on here too is harmless and covers a misconfigured proxy.

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = env.bool("SECURE_SSL_REDIRECT", default=True)
# Health checks arrive over plain http from inside the compose network.
SECURE_REDIRECT_EXEMPT = [r"^healthz/$"]

SECURE_HSTS_SECONDS = env.int("SECURE_HSTS_SECONDS", default=31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Mail unhandled-exception tracebacks to the operator when configured.
ADMINS = [("VMS operator", a) for a in env.list("DJANGO_ADMINS", default=[])]
