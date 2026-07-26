"""Request-scoped audit context, and tenant routing with a health-check exemption."""

from django.http import JsonResponse
from django_tenants.middleware.main import TenantMainMiddleware

from .audit import actor_from_request, clear_actor, set_actor


class VMSTenantMiddleware(TenantMainMiddleware):
    """
    Tenant routing: signed cookie first, hostname second, with a health-check carve-out.

    **Cookie first.** Every church shares one hostname, so the schema comes from the
    signed ``vms_tenant`` cookie that sign-in issues. See :mod:`apps.tenants.routing`
    for why that is safe — briefly, the cookie only *selects* a schema, and the session
    that actually authorises anything lives inside that schema, so pointing the cookie
    somewhere else logs you out rather than in.

    **Hostname second.** The cookie is host-only, so a request to a church's own
    subdomain never carries it and falls through to django-tenants' ordinary Domain
    lookup. Both routing schemes keep working, and neither can shadow the other.

    **Health check.** An unknown hostname must be refused — ``SHOW_PUBLIC_IF_NO_TENANT_FOUND``
    is False so a stray DNS entry cannot expose the operator's console. But the container
    health check and the reverse proxy both probe over the internal network, where the Host
    header is ``localhost`` or a container name that will never have a Domain row. Without
    the carve-out the probe 404s and Docker marks a healthy container unhealthy.
    """

    #: Kept in sync with the path in config/urls_*.py.
    HEALTH_PATH = "/healthz/"

    def process_request(self, request):
        from apps.tenants import routing

        if routing.TENANT_COOKIE_NAME in request.COOKIES:
            schema_name = routing.read_tenant_cookie(request)
            tenant = routing.resolve_tenant(schema_name) if schema_name else None
            if tenant is not None:
                routing.bind_tenant(request, tenant)
                return None
            # Present but unusable: forged, tampered with, or naming a church that has
            # been suspended or removed. Fall through to the hostname — which leaves the
            # visitor at sign-in rather than in a dead end — and drop the cookie so the
            # browser stops resending it on every request.
            request.vms_drop_tenant_cookie = True

        return super().process_request(request)

    def process_response(self, request, response):
        if getattr(request, "vms_drop_tenant_cookie", False):
            from apps.tenants.routing import clear_tenant_cookie

            clear_tenant_cookie(response)
        return response

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
