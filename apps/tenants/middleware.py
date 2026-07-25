"""Gate that holds a new church at the encryption-key backup step."""

from django.conf import settings
from django.db import connection
from django.shortcuts import redirect
from django.urls import reverse


class ForceKeyBackupMiddleware:
    """
    Blocks a freshly provisioned church until its admin confirms a key backup.

    PRD §5 requires the church's own admin to be *forced* to take an offline copy of
    the data-encryption key before using the system — the whole no-data-loss
    guarantee rests on that copy existing. Rather than trusting a prompt they can
    dismiss, every authenticated request is redirected to the backup page until
    ``Tenant.key_backup_confirmed_at`` is set.

    Only a handful of paths stay reachable while pending: the backup page itself,
    sign-out, the health check, and static assets.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        tenant = getattr(connection, "tenant", None)

        # Public schema (super-admin console) has no DEK of its own to back up.
        if tenant is None or getattr(tenant, "schema_name", "public") == "public":
            return self.get_response(request)

        if not getattr(tenant, "key_backup_pending", False):
            return self.get_response(request)

        user = getattr(request, "user", None)
        if user is None or not user.is_authenticated:
            return self.get_response(request)

        if self._is_exempt(request.path):
            return self.get_response(request)

        return redirect(reverse("tenants:key_backup"))

    @staticmethod
    def _is_exempt(path: str) -> bool:
        exempt_prefixes = (
            settings.STATIC_URL or "/static/",
            "/healthz/",
            "/accounts/logout/",
            "/accounts/login/",
            "/accounts/webauthn/",
        )
        return path.startswith(exempt_prefixes) or path.startswith("/key-backup/")
