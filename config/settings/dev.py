"""Development settings. Never use for a real church's data."""

from .base import *  # noqa: F401,F403
from .base import env

DEBUG = env.bool("DEBUG", default=True)

# Tenant subdomains under .localhost resolve to 127.0.0.1 in every modern browser,
# so http://firstoac.localhost:8000/ reaches the tenant without editing /etc/hosts.
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["localhost", ".localhost", "127.0.0.1"])
CSRF_TRUSTED_ORIGINS = env.list(
    "CSRF_TRUSTED_ORIGINS",
    default=["http://localhost:8000", "http://*.localhost:8000"],
)

VMS_BASE_DOMAIN = env("VMS_BASE_DOMAIN", default="localhost")
WEBAUTHN_RP_ID = env("WEBAUTHN_RP_ID", default="localhost")
VMS_LINK_SCHEME = env("VMS_LINK_SCHEME", default="http")
# runserver's port, so an emailed link is clickable in development.
VMS_LINK_HOST = env("VMS_LINK_HOST", default="localhost:8000")

EMAIL_PROVIDER = env("EMAIL_PROVIDER", default="console")

# No TLS in front of runserver.
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# Un-hashed static files, served straight from the app directories, so collectstatic
# isn't a prerequisite for runserver.
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
}
WHITENOISE_USE_FINDERS = True
WHITENOISE_AUTOREFRESH = True

# Run scheduled jobs inline instead of needing a worker up.
CELERY_TASK_ALWAYS_EAGER = env.bool("CELERY_TASK_ALWAYS_EAGER", default=False)
CELERY_TASK_EAGER_PROPAGATES = True
