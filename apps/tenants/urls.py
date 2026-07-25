"""
Tenant-app URLs contributed by the tenants app.

Only the forced key-backup gate lives on the tenant side; the rest of this app is
the public-schema console, wired up in ``config/urls_public.py``.
"""

from django.urls import path

from . import views

app_name = "tenants"

urlpatterns = [
    path("key-backup/", views.key_backup, name="key_backup"),
    path("key-backup/download/", views.key_backup_download, name="key_backup_download"),
]
