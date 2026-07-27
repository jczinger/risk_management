"""Template context shared by every page."""

from django.conf import settings
from django.db import connection


def vms_context(request):
    """
    Expose the current church and a few chrome-level flags.

    ``tenant`` is None on the public (super-admin) side, which templates use to
    switch between the console chrome and the church chrome.

    **Nothing identifying the church is exposed before sign-in.** The schema is bound
    from a cookie that outlives a session, so an anonymous visitor on a browser that was
    used earlier still resolves to a church — and without this the sign-in page would
    announce which one, in the heading, the header bar and the browser tab. On a shared
    or borrowed machine that tells a stranger which church uses this system and who to
    go looking for. The schema stays bound, because the second-factor step needs it to
    find the half-authenticated user; only the *display* is withheld.
    """
    tenant = getattr(connection, "tenant", None)
    is_public = tenant is None or getattr(tenant, "schema_name", "") == "public"

    user = getattr(request, "user", None)
    signed_in = user is not None and getattr(user, "is_authenticated", False)
    show_church = signed_in and not is_public

    return {
        "tenant": tenant if show_church else None,
        # Keeps reflecting the real schema whether or not anyone is signed in: it picks
        # the console chrome versus the church chrome, and getting that wrong would show
        # an anonymous visitor the operator's navigation.
        "is_public_schema": is_public,
        "church_name": getattr(tenant, "name", "") if show_church else "",
        "vms_base_domain": settings.VMS_BASE_DOMAIN,
        "vms_debug": settings.DEBUG,
        "nav": _nav_section(request),
    }


#: Maps (url namespace, url name prefix) to the nav tab that should look selected.
#: Longest prefix wins, so "volunteer_list" beats a bare "" fallback.
_NAV_RULES = {
    "org": (
        ("volunteer", "volunteers"),
        ("department", "departments"),
        ("role", "roles"),
        ("assignment", "volunteers"),
    ),
    "requirements": (("", "requirements"),),
    "documents": (("", "documents"),),
    "reporting": (
        ("audit", "audit"),
        ("email_log", "reports"),
        ("", "reports"),
    ),
    "accounts": (("admin_", "admins"),),
    "tenants": (
        ("church_create", "onboard"),
        ("", "churches"),
    ),
}


def _nav_section(request) -> str:
    """
    Work out which nav tab to highlight from the URL that matched.

    Derived rather than set per view: one rule table beats forty context dictionaries
    that drift out of step with the nav bar.
    """
    match = getattr(request, "resolver_match", None)
    if match is None:
        return ""

    if not match.namespace:
        return "dashboard" if match.url_name == "dashboard" else ""

    rules = _NAV_RULES.get(match.namespace, ())
    name = match.url_name or ""
    best = ""
    best_length = -1
    for prefix, section in rules:
        if name.startswith(prefix) and len(prefix) > best_length:
            best, best_length = section, len(prefix)
    return best
