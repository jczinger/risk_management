"""
URLs served on the platform domain (``public`` schema).

This is the operator's surface: the super-admin console, sign-in, and the Django
admin. No church data is reachable here — the public schema holds no volunteer
records and has no data-encryption key.
"""

from django.contrib import admin
from django.urls import include, path

from apps.core.views import healthz

urlpatterns = [
    path("healthz/", healthz, name="healthz"),
    path("accounts/", include("apps.accounts.urls")),
    path("django-admin/", admin.site.urls),
    path("", include("apps.tenants.urls_console")),
]

handler403 = "apps.core.errors.permission_denied"
handler404 = "apps.core.errors.page_not_found"
handler500 = "apps.core.errors.server_error"
