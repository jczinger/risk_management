"""Template context shared by every page."""

import logging

from django.conf import settings
from django.db import connection
from django.utils.functional import SimpleLazyObject

logger = logging.getLogger("vms.core")


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
        "can": CapabilityFlags(request),
        # Lazy, so a render that never touches it — every HTMX partial swap — pays
        # no query at all. The nav in base.html is its only consumer.
        "review_backlog": SimpleLazyObject(
            lambda: _review_backlog(request, signed_in and not is_public)
        ),
    }


def _review_backlog(request, active: bool) -> dict:
    """
    Just enough for the navigation entry: how many entries are waiting, and whether this
    person has any of their own.

    One aggregate query, both counts indexed, and only for a signed-in church request —
    and only when the nav actually renders (see the lazy wrapper above). The dashboard
    tile and the digest use the fuller :func:`apps.review.services.pending_summary`;
    this stays deliberately small because the earlier draft of this feature put the
    whole summary here — a handful of queries on the sign-in page for a number that
    belongs on one screen.
    """
    if not active:
        return {}

    try:
        from django.db.models import Count, Q

        from apps.review.models import ReviewItem

        user = getattr(request, "user", None)
        return ReviewItem.objects.pending().aggregate(
            pending=Count("id"),
            mine=Count("id", filter=Q(recorded_by_user_id=getattr(user, "pk", None))),
        )
    except Exception:  # noqa: BLE001 - chrome must never take down a page
        logger.warning("Could not read the review backlog for the navigation", exc_info=True)
        return {}


class CapabilityFlags:
    """
    ``{% if can.view_volunteers %}`` for templates.

    Lives here rather than in a template tag for the reason ``_nav_section`` below gives
    about itself: one rule in one place beats the same decision repeated across forty
    context dictionaries. There is also no ``templatetags/`` directory anywhere in this
    project, and a custom tag would need ``{% load %}`` in every guarded template —
    forgetting which is a silent no-op in exactly the templates that matter.

    A misspelled guard raises ``KeyError``, which Django's template engine swallows into
    an empty string, so a typo **hides** the link. That is the right direction for
    navigation, and the URL-enumeration test catches the opposite mistake — a view
    reachable without a declaration.

    Resolution is lazy and the grant is cached on the user, so nine navigation guards on
    one page cost a single query, and a page with no guards costs none.
    """

    def __init__(self, request):
        self._user = getattr(request, "user", None)

    def __getitem__(self, capability: str) -> bool:
        # Django tries __getitem__ before attribute access, so `can.view_volunteers`
        # arrives here.
        from apps.core.access import Capability, has_capability, on_public_schema

        if capability not in Capability.values:
            raise KeyError(capability)
        # The console renders through this context processor too, and core_accesslevel
        # does not exist in the public schema. Checked before touching the database.
        if on_public_schema():
            return False
        return has_capability(self._user, capability)


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
    "accounts": (("admin_", "admins"), ("access_level", "admins")),
    "review": (("", "review"),),
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
