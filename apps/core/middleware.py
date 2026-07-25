"""Request-scoped audit context, and tenant routing with a health-check exemption."""

from django.http import JsonResponse
from django_tenants.middleware.main import TenantMainMiddleware

from .audit import actor_from_request, clear_actor, set_actor


class VMSTenantMiddleware(TenantMainMiddleware):
    """
    Tenant routing, with one carve-out for the health check.

    An unknown hostname must be refused — ``SHOW_PUBLIC_IF_NO_TENANT_FOUND`` is False so a
    stray DNS entry cannot expose the operator's console. But the container health check and
    the reverse proxy both probe over the internal network, where the Host header is
    ``localhost`` or a container name that will never have a Domain row. Without this, the
    health check 404s and Docker marks a perfectly healthy container unhealthy.

    So: the health-check path answers on any hostname, and everything else still 404s.
    """

    #: Kept in sync with the path in config/urls_*.py.
    HEALTH_PATH = "/healthz/"

    def no_tenant_found(self, request, hostname):
        if request.path == self.HEALTH_PATH:
            # Answer directly rather than binding the public schema and routing onward: the
            # probe needs a liveness signal, not access to anything.
            from django.db import connection

            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
            except Exception:  # noqa: BLE001
                return JsonResponse({"status": "error", "database": "unavailable"}, status=503)
            return JsonResponse({"status": "ok"})

        return super().no_tenant_found(request, hostname)


class AuditContextMiddleware:
    """
    Parks the acting user in the audit thread-local for the life of the request.

    Sits after AuthenticationMiddleware so ``request.user`` is resolved, and always
    clears on the way out so a pooled worker thread cannot attribute the next
    request's changes to the previous request's user.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        set_actor(actor_from_request(request))
        try:
            return self.get_response(request)
        finally:
            clear_actor()
