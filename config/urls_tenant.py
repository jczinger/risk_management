"""
URLs served on a church's own hostname (its tenant schema).

This is the screening admin's surface. The Django admin is deliberately absent:
church staff work through the purpose-built screens, which is what enforces the
requirement engine's rules and writes the audit trail.
"""

from django.urls import include, path

from apps.core.views import healthz
from apps.reporting.views import dashboard

urlpatterns = [
    path("healthz/", healthz, name="healthz"),
    path("", dashboard, name="dashboard"),
    path("accounts/", include("apps.accounts.urls")),
    path("", include("apps.tenants.urls")),
    path("org/", include("apps.org.urls")),
    path("requirements/", include("apps.requirements.urls")),
    path("documents/", include("apps.documents.urls")),
    path("reports/", include("apps.reporting.urls")),
]

handler403 = "apps.core.errors.permission_denied"
handler404 = "apps.core.errors.page_not_found"
handler500 = "apps.core.errors.server_error"
