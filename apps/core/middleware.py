"""Tenant routing, request-scoped audit context, and the default-deny access gate."""

import logging

from django.core.exceptions import PermissionDenied
from django_tenants.middleware.main import TenantMainMiddleware

from .audit import actor_from_request, clear_actor, set_actor

logger = logging.getLogger("vms.core")


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
            # Answer with the health view directly rather than binding the public schema
            # and routing onward: the probe needs a liveness signal, not access to
            # anything, and this must keep working on a hostname that matches no church.
            from apps.core.views import healthz

            return healthz(request)

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


class AccessGateMiddleware:
    """
    Refuses any church-side view that never declared what capability it needs.

    This is the fail-closed half of the access-level design, and it exists because of a
    specific and very quiet failure mode. A future view written the way all sixty of
    them used to be written — ``@login_required`` and nothing else — works perfectly for
    everybody who can sign in, including a Department Admin who should not be able to
    reach it. Nothing errors. Nothing looks wrong. There is no test to fail unless
    somebody thought to write one, and the whole point is that they did not think about
    it.

    So the rule is inverted: a view is unreachable until it says what it needs.
    ``apps.core.access``'s three decorators each set an attribute — ``vms_capabilities``
    for a gated view, an empty ``vms_capabilities`` plus a written reason for one open to
    any signed-in admin, ``vms_public`` for one that needs no account. A view with none
    of them raises ``PermissionDenied`` here.

    ``process_view`` is the only hook that can do this, because it is the first place the
    resolved view function is available.

    A test (``apps.core.tests.test_access``) walks the URLconf and asserts the same
    thing, and the two are not redundant. The test names the offending view at review
    time, which is where you want to find out; this middleware covers views the test
    cannot see. Their weaknesses do not overlap.

    There is deliberately no path-prefix exemption list: ``/healthz/`` is a
    ``public_view``-decorated view like any other, and static files are answered by
    WhiteNoise during the request phase, before any ``process_view`` hook runs. An
    exemption list is itself somewhere for a mistake to hide.

    Two carve-outs, both load-bearing:

    * **The public schema is skipped entirely.** It serves the super-admin console,
      whose views are gated by ``platform_admin_required`` and set nothing this looks
      for — and ``core_accesslevel`` does not exist there to consult anyway. Without
      this, every console request would 403.
    * **The forced-step gates still win.** ``ForcePasskeyMiddleware`` and
      ``ForceKeyBackupMiddleware`` return their redirects during the request phase,
      which runs before any ``process_view`` hook. So a brand-new admin is sent to
      passkey enrolment rather than being handed a 403 they cannot act on. That
      ordering is deliberate; please do not "fix" it by moving this earlier.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        from apps.core.access import on_public_schema

        if on_public_schema():
            return None

        if getattr(view_func, "vms_public", False):
            return None
        if getattr(view_func, "vms_capabilities", None) is not None:
            # Declared. Whether the user *holds* it was already decided by the
            # decorator; this middleware only checks that somebody made a decision.
            return None

        logger.error(
            "Refused %s: the view %s.%s declares no capability. Decorate it with one of "
            "requires(), open_to_any_signed_in_user() or public_view() from "
            "apps.core.access.",
            request.path,
            getattr(view_func, "__module__", "?"),
            getattr(view_func, "__qualname__", getattr(view_func, "__name__", "?")),
        )
        raise PermissionDenied("That page is not available.")
