"""
Sign-in and account management.

There is one way to sign in — a passkey — and one way to get a passkey when you do not
have one yet: a single-use link, emailed. Nothing here takes a password.

Flows:

* **Passkey:** POST to ``webauthn_authenticate_begin`` → browser ceremony → POST to
  ``webauthn_authenticate_finish`` → signed in. One step, and no second factor: the
  authenticator has already proven possession of an unlocked device.
* **Link:** GET ``link_consume`` with a signed payload → signed in once, and held at
  passkey enrolment by :class:`~apps.accounts.middleware.ForcePasskeyMiddleware` until
  a passkey exists. Issued either when an account is created or on request from
  ``recover_request``.

See :mod:`apps.accounts.links` for how a link carries the church it belongs to, and
BUILD_NOTES §1.20 for why the password path went away.
"""

from __future__ import annotations

import json
import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.db.models import Count, Exists, OuterRef
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods, require_POST
from django_ratelimit.decorators import ratelimit
from django_tenants.utils import schema_context

from apps.core import audit
from apps.core.access import (
    Capability,
    access_snapshot,
    another_unscoped_admin_exists,
    grant_of,
    no_access_level,
    open_to_any_signed_in_user,
    own_review_backlog_unlocked_by_removing,
    public_view,
    requires,
    would_strand_the_church,
)
from apps.core.forms import AccessGrantForm, AccessLevelForm, apply_grant
from apps.core.models import (
    AccessLevel,
    AuditAction,
    UserAccessGrant,
    diff_summary,
)
from apps.org.models import Volunteer
from apps.tenants.routing import clear_tenant_cookie, find_login_targets, set_tenant_cookie

from . import links as link_service
from . import webauthn_service
from .forms import AdminInviteForm, AdminProfileForm, RecoveryRequestForm
from .services import attach_volunteer_files, file_for_new_admin, volunteer_from_request
from .models import LinkPurpose, Passkey, User
from .webauthn_service import WebAuthnError

logger = logging.getLogger("vms.accounts")


def _post_login_redirect(request) -> str:
    """
    Where to go after a successful sign-in.

    ``next`` is honored only when it is a local path, so the login page cannot be used
    as an open redirect.

    The keyword is ``require_https``. ``require_secure`` was its name on the old
    ``is_safe_url()``, removed in Django 3.0, and passing it raises ``TypeError`` —
    which only happens when a ``next`` value is actually present, so it hid until
    someone was redirected to the login page rather than going there directly.
    """

    candidate = request.POST.get("next") or request.GET.get("next") or ""
    if candidate and url_has_allowed_host_and_scheme(
        candidate, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return candidate
    return settings.LOGIN_REDIRECT_URL


def _apply_tenant_cookie(response, target):
    """
    Record on the response which schema this browser is now signed in to.

    ``target`` is None on the per-subdomain path, where the hostname already decides
    and no cookie should be involved. A public target clears the cookie rather than
    setting it — the operator's console *is* the no-cookie state, so leaving a stale
    church cookie behind would send the super-admin into a church on their next click.
    """
    if target is None:
        return response
    if target.is_public:
        return clear_tenant_cookie(response)
    return set_tenant_cookie(response, target.schema_name)


def _complete_login(request, user: User, method: str) -> HttpResponse:
    """Sign the user in, stamp last-login, and audit it."""
    auth_login(request, user)
    user.last_login_at = timezone.now()
    user.save(update_fields=["last_login_at"])

    # The actor thread-local was populated before authentication, so refresh it or the
    # login entry would be attributed to "anonymous".
    audit.set_actor(audit.actor_from_request(request))
    audit.record(
        AuditAction.LOGIN,
        "User",
        entity_id=user.pk,
        entity_label=user.display_name,
        summary=f"Signed in via {method}",
        detail={"method": method},
    )
    logger.info("Login user=%s method=%s", user.pk, method)
    return redirect(_post_login_redirect(request))


# ---------------------------------------------------------------------------
# Sign in / out
# ---------------------------------------------------------------------------


@public_view("signing in")
@never_cache
@ensure_csrf_cookie
@require_http_methods(["GET"])
def login_view(request):
    """
    The sign-in page: a passkey button, and a way to ask for a link.

    There is nothing to POST here. The passkey ceremony runs against the WebAuthn
    endpoints over fetch, and everything else happens at ``recover_request``.

    ``ensure_csrf_cookie`` is load-bearing and easy to lose. Django only sets the
    ``csrftoken`` cookie when something asks it to — historically ``{% csrf_token %}``
    inside this page's password form. Removing that form removed the cookie, and
    ``static/js/passkeys.js`` reads it to build the ``X-CSRFToken`` header, so every
    passkey sign-in was rejected with a 403 the browser could only report as "the server
    rejected that request". A page whose only interaction is a fetch still needs the
    cookie. Guarded by ``CsrfCookieOnSignInTests``.
    """
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)

    return render(request, "accounts/login.html", {"next": request.GET.get("next", "")})


def _audit_failed_login(request, reason: str) -> None:
    """
    Record a failed attempt without storing the address that was tried.

    Writing the attempted address would put an unverified, possibly-someone-else's
    email into the trail in plaintext-adjacent form; the IP is enough to spot a
    pattern.
    """
    audit.record(
        AuditAction.LOGIN_FAILED,
        "User",
        summary="Sign-in attempt failed",
        detail={"reason": reason},
    )


@public_view("signing out")
@require_POST
def logout_view(request):
    if request.user.is_authenticated:
        audit.record(
            AuditAction.LOGOUT,
            "User",
            entity_id=request.user.pk,
            entity_label=request.user.display_name,
            summary="Signed out",
        )
    auth_logout(request)
    messages.success(request, "You have been signed out.")
    # Drop the church selection too. Without this the next person at this browser
    # would reach the church's login page rather than the shared one, and the
    # previous user's church name would be visible in the page chrome.
    return clear_tenant_cookie(redirect("accounts:login"))


# ---------------------------------------------------------------------------
# Passkey ceremonies (fetch endpoints, JSON in/out)
# ---------------------------------------------------------------------------


def _passkey_rate(group, request):
    """
    Read the limit per request rather than at import.

    ``rate=settings.X`` freezes the value when the module loads, which quietly defeats
    both ``override_settings`` in a test and any attempt to retune it without a restart.
    django-ratelimit accepts a callable for exactly this.
    """
    return settings.LOGIN_RATELIMIT


def _recovery_rate(group, request):
    return settings.VMS_RECOVERY_RATELIMIT


@ratelimit(key="ip", rate=_passkey_rate, method="POST", block=False)
def _check_passkey_ratelimit(request) -> bool:
    """
    Meter the passkey endpoints per source IP.

    These used to be unlimited, which was defensible while a rate-limited password form
    stood beside them. They are now the only interactive way in, and a ``finish`` call
    carrying an unknown credential costs a scan across every church's schema
    (:func:`apps.tenants.routing.find_passkey_target`) plus a challenge row. Per IP only:
    a discoverable-credential ceremony sends no address, so there is no account to key a
    second limit on.
    """
    return getattr(request, "limited", False)


_RATE_LIMITED_JSON = {
    "error": "Too many sign-in attempts from this connection. Wait a few minutes and try again."
}


@public_view("the passkey sign-in ceremony")
@never_cache
@require_POST
def webauthn_authenticate_begin(request):
    """Issue an assertion challenge. No user needed — discoverable credentials."""
    if _check_passkey_ratelimit(request):
        return JsonResponse(_RATE_LIMITED_JSON, status=429)
    try:
        options = webauthn_service.begin_authentication(request)
    except WebAuthnError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    return HttpResponse(options, content_type="application/json")


@public_view("the passkey sign-in ceremony")
@never_cache
@require_POST
def webauthn_authenticate_finish(request):
    """Verify an assertion and sign the user in."""
    if _check_passkey_ratelimit(request):
        return JsonResponse(_RATE_LIMITED_JSON, status=429)

    body = request.body.decode("utf-8", errors="replace")
    if not body:
        return JsonResponse({"error": "No passkey response received."}, status=400)

    try:
        user = webauthn_service.finish_authentication(request, body)
    except WebAuthnError as exc:
        audit.record(
            AuditAction.LOGIN_FAILED,
            "User",
            summary="Passkey sign-in failed",
            detail={"reason": str(exc)},
        )
        return JsonResponse({"error": str(exc)}, status=400)

    _complete_login(request, user, method="passkey")

    # The ceremony may have resolved the church from the credential itself and
    # switched schemas; carry that choice forward in the cookie.
    response = JsonResponse({"ok": True, "redirect": _post_login_redirect(request)})
    return _apply_tenant_cookie(response, getattr(request, "vms_login_target", None))


@never_cache
@open_to_any_signed_in_user("enrolling your own passkey")
@require_POST
def webauthn_register_begin(request):
    """Issue a registration challenge for the signed-in user."""
    try:
        options = webauthn_service.begin_registration(request, request.user)
    except WebAuthnError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    return HttpResponse(options, content_type="application/json")


@never_cache
@open_to_any_signed_in_user("enrolling your own passkey")
@require_POST
def webauthn_register_finish(request):
    """
    Verify and store a new passkey.

    The body is ``{"credential": {…}, "label": "…"}``. The label used to ride in an
    ``X-Passkey-Label`` header, which quietly restricted device names to latin-1: a
    curly apostrophe — which a phone substitutes for a typed one on its own — made the
    browser refuse to send the request at all. Amended 2026-08-02.
    """
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        payload = None
    if not isinstance(payload, dict) or not isinstance(payload.get("credential"), dict):
        return HttpResponseBadRequest("No passkey response received.")

    label = payload.get("label")
    if not isinstance(label, str):
        label = ""

    try:
        passkey = webauthn_service.finish_registration(
            request, request.user, json.dumps(payload["credential"]), label=label
        )
    except WebAuthnError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    audit.record(
        AuditAction.UPDATE,
        "Passkey",
        entity_id=passkey.pk,
        entity_label=request.user.display_name,
        summary="Passkey registered",
    )
    return JsonResponse({"ok": True, "redirect": reverse("accounts:security")})


@open_to_any_signed_in_user("managing your own passkeys")
@require_POST
def passkey_remove(request, pk: int):
    try:
        webauthn_service.remove_passkey(request.user, pk)
    except ValidationError as exc:
        messages.error(request, "; ".join(exc.messages))
    else:
        audit.record(
            AuditAction.UPDATE,
            "Passkey",
            entity_id=pk,
            entity_label=request.user.display_name,
            summary="Passkey removed",
        )
        messages.success(request, "Passkey removed.")
    return redirect("accounts:security")


# ---------------------------------------------------------------------------
# Sign-in links
# ---------------------------------------------------------------------------


@public_view("spending a single-use sign-in link")
@never_cache
@require_http_methods(["GET", "POST"])
def link_consume(request, payload: str):
    """
    Confirm, then spend, a sign-in link.

    A GET used to spend it outright — the only thing a URL in an email could sensibly
    do. In production that let a link die before its recipient ever saw it: something
    with a browser-engine user agent (a chat app building a preview of the link before
    it was even sent, most likely) fetched it within seconds of issue, both times it
    happened. A GET here now only shows that the link still works; only a click —
    a POST — spends it. That stops anything that merely *fetches* the URL, which is
    every one of these prefetchers, none of which submit a form.
    """
    if request.method == "GET":
        try:
            user, link = link_service.verify_link(request, payload)
        except link_service.LinkError as exc:
            _audit_failed_login(request, "invalid_link")
            return render(request, "accounts/link_invalid.html", {"reason": str(exc)}, status=400)
        return render(
            request,
            "accounts/link_confirm.html",
            {
                "first_name": user.get_short_name(),
                "is_recovery": link.purpose == LinkPurpose.RECOVERY,
            },
        )

    if request.user.is_authenticated:
        auth_logout(request)

    try:
        user, link = link_service.consume_link(request, payload)
    except link_service.LinkError as exc:
        _audit_failed_login(request, "invalid_link")
        return render(request, "accounts/link_invalid.html", {"reason": str(exc)}, status=400)

    # The connection is now bound to the account's own schema. Start a clean session so
    # it is created *there* rather than carrying over a public-schema session key — the
    # same reasoning the passkey path relies on.
    request.session.flush()

    response = _complete_login(request, user, method="sign-in link")

    audit.record(
        AuditAction.LINK_USED,
        "User",
        entity_id=user.pk,
        entity_label=user.display_name,
        summary=f"{link.get_purpose_display()} link used",
        detail={"purpose": link.purpose},
    )

    if link.purpose == LinkPurpose.RECOVERY:
        told = link_service.notify_recovery_used(user)
        if told:
            messages.info(
                request,
                f"The other {'administrator' if told == 1 else 'administrators'} at your "
                "church have been told that an account was recovered.",
            )
        # A recovery link exists to fix or extend passkey access — replacing a lost
        # one, or (self-issued from the security page) adding one on a new device.
        # The dashboard would leave that a click away; land where it is done instead.
        response = redirect("accounts:security")
        messages.info(
            request,
            "You are signed in. Register a passkey on this device below if it does "
            "not have one yet.",
        )

    if not user.has_passkey:
        messages.info(
            request,
            "You are signed in for now. Set up a passkey to finish — it is how you will "
            "sign in from here on.",
        )

    return _apply_tenant_cookie(response, getattr(request, "vms_login_target", None))


@public_view("asking for a recovery link")
@never_cache
@require_http_methods(["GET", "POST"])
def recover_request(request):
    """
    Send a fresh sign-in link to whoever owns an address.

    The response is identical whether or not the address exists. That is the same
    enumeration guarantee the old password form carried, and it matters more now: this
    form is reachable by anyone, and a distinct "no such account" would map out who
    administers which church.
    """
    form = RecoveryRequestForm(request.POST or None)
    rate_limited = False

    if request.method == "POST":
        rate_limited = _check_recovery_ratelimit(request)

        if not rate_limited and form.is_valid():
            _send_recovery_links(form.cleaned_data["email"])
            return render(request, "accounts/recover_sent.html")

        if rate_limited:
            messages.error(
                request,
                "Too many requests. Wait a while before asking for another link — check "
                "your inbox and spam folder in the meantime.",
            )

    return render(
        request, "accounts/recover.html", {"form": form, "rate_limited": rate_limited}
    )


@ratelimit(key="post:email", rate=_recovery_rate, method="POST", block=False)
@ratelimit(key="ip", rate=_recovery_rate, method="POST", block=False)
def _check_recovery_ratelimit(request) -> bool:
    """
    Limit recovery requests per address and per source IP.

    Tighter than the passkey limit because each request that lands sends real mail to a
    real person; without the per-address half this form is a way to bury somebody's
    inbox, and without the per-IP half it is a way to bury several.
    """
    return getattr(request, "limited", False)


def _send_recovery_links(email: str) -> None:
    """
    Issue one link per schema holding this address.

    Somebody who administers two churches gets two emails, each naming its church. That
    is better than the password form managed: it resolved a duplicated address to the
    first church alphabetically and logged a warning, which left the second account
    quietly unreachable.
    """

    targets = find_login_targets(email)
    if not targets:
        logger.info("Recovery requested for an address with no account")
        return

    for target in targets:
        # One church failing — an unreadable key, a mail outage — must not stop the
        # others. Every branch below still renders the same page to the visitor, so a
        # failure here is invisible to them by design; the log is where it surfaces.
        try:
            with schema_context(target.schema_name):
                user = User.objects.filter(pk=target.user_pk, is_active=True).first()
                if user is None:
                    continue
                _, url = link_service.issue_link(user, LinkPurpose.RECOVERY)
                link_service.send_link(user, url, LinkPurpose.RECOVERY, church_name=target.label)
        except Exception:  # noqa: BLE001
            logger.exception("Could not issue a recovery link in schema %s", target.schema_name)


@open_to_any_signed_in_user("the forced passkey-enrolment step")
@never_cache
@ensure_csrf_cookie
def passkey_required(request):
    """
    The enrolment wall. Everything else redirects here until a passkey exists.

    Reached only through :class:`~apps.accounts.middleware.ForcePasskeyMiddleware`, or
    directly by someone who already has one — hence the redirect out.

    ``ensure_csrf_cookie`` for the same reason as :func:`login_view`: the registration
    ceremony is a fetch, and it needs the cookie. The sign-out form on this page happens
    to set it too, but depending on an unrelated form for that is precisely the
    fragility that broke sign-in once already.
    """
    if request.user.has_passkey:
        return redirect(settings.LOGIN_REDIRECT_URL)

    return render(request, "accounts/passkey_required.html")


# ---------------------------------------------------------------------------
# Account settings
# ---------------------------------------------------------------------------


@open_to_any_signed_in_user("your own account")
def security(request):
    """Passkeys — the whole of a person's sign-in setup, on one page."""
    return render(
        request,
        "accounts/security.html",
        {"passkeys": request.user.passkeys.filter(is_active=True)},
    )


def _link_issued_response(request, user, url, purpose, emailed, **flags):
    """The "here is the link" page every link-minting view ends on."""
    return render(
        request,
        "accounts/link_issued.html",
        {
            "target": user,
            "url": url,
            "emailed": emailed,
            "expires_in": link_service.describe_lifetime(purpose),
            "is_recovery": purpose == LinkPurpose.RECOVERY,
            **flags,
        },
    )


def _issue_and_show_link(request, user, **flags):
    """
    Mint a fresh sign-in link for ``user``, email it, and show it to the requester.

    The purpose follows what the account already has: no passkey yet is still a first
    sign-in, so this mints another :attr:`LinkPurpose.INVITE` — the seven-day window,
    no "account recovered" notice to the other admins, because nothing is being
    recovered. A passkey already on file makes this a :attr:`LinkPurpose.RECOVERY`,
    with the shorter window and the notice to colleagues that a working credential is
    being replaced.
    """
    purpose = LinkPurpose.RECOVERY if user.has_passkey else LinkPurpose.INVITE
    _, url = link_service.issue_link(user, purpose, issued_by=request.user)
    emailed = link_service.send_link(user, url, purpose, church_name=_church_name(request))
    return _link_issued_response(request, user, url, purpose, emailed, **flags)


@open_to_any_signed_in_user("adding a passkey on a different device")
@require_POST
def security_new_device_link(request):
    """
    Let the signed-in holder mint their own sign-in link, to open on a phone or
    another computer and register a passkey there — the self-service half of what
    :func:`admin_reissue_link` does on someone else's behalf.

    Reaching this view at all means the account already has a passkey somewhere
    (``ForcePasskeyMiddleware`` would have stopped it otherwise), so this is always a
    :attr:`LinkPurpose.RECOVERY` link in practice: the shorter window, and the notice
    to colleagues that a link-based sign-in happened. That notice matters just as much
    here as for an actual lost passkey — it is the same event, whoever asked for it.
    """
    return _issue_and_show_link(request, request.user, for_self=True)


@open_to_any_signed_in_user("your own account")
@require_http_methods(["GET", "POST"])
def profile(request):
    form = AdminProfileForm(request.POST or None, instance=request.user)

    if request.method == "POST" and form.is_valid():
        form.save()
        audit.record(
            AuditAction.UPDATE,
            "User",
            entity_id=request.user.pk,
            entity_label=request.user.display_name,
            summary="Own profile updated",
        )
        messages.success(request, "Your details have been updated.")
        return redirect("accounts:profile")

    return render(request, "accounts/profile.html", {"form": form})


# ---------------------------------------------------------------------------
# Managing the church's other admins
# ---------------------------------------------------------------------------


@requires(Capability.MANAGE_USERS)
def admin_list(request):
    """
    Every screening admin at this church, with the access level each one holds.

    Administrators are no longer all equal — see BUILD_NOTES §1.21 — so this page is
    where a church reads and changes who can do what.
    """


    if getattr(connection, "schema_name", "public") == "public":
        # The platform console manages churches, not church staff.
        messages.error(request, "Administrator management happens inside a church.")
        return redirect("/")

    # ``passkey_registered`` mirrors the ``has_passkey`` property without its
    # per-row EXISTS query — annotated here because this is the one page that
    # renders every administrator at once.
    admins = list(
        User.objects.annotate(
            passkey_registered=Exists(
                Passkey.objects.filter(user=OuterRef("pk"), is_active=True)
            )
        ).order_by("last_name", "first_name")
    )
    grants = {
        grant.user_id: grant
        for grant in UserAccessGrant.objects.select_related("access_level").prefetch_related(
            "departments"
        )
    }
    for admin in admins:
        admin.grant = grants.get(admin.pk)

    attach_volunteer_files(admins)

    return render(
        request,
        "accounts/admin_list.html",
        {
            "admins": admins,
            "levels": AccessLevel.objects.all(),
        },
    )


@requires(Capability.MANAGE_USERS)
@require_POST
def admin_link_volunteer(request, pk: int):
    """
    Attach an existing volunteer file to an administrator.

    **This is not a back door, and the guard below is what keeps it from being one.**
    The link is what makes "you may not screen yourself" enforceable, so being able to
    move your own link at will would be a way out of the rule: point it at a stranger's
    file and your own becomes fair game again. Choosing your own file is therefore
    refused while another church-wide administrator exists — the same escape hatch as
    everywhere else, so a single-administrator church is not stuck.

    There is deliberately no unlink. Detaching is the same escape by another name, and
    the honest fix for a wrong link is a second administrator correcting it.
    """

    subject = get_object_or_404(User, pk=pk)
    volunteer = get_object_or_404(Volunteer, pk=request.POST.get("volunteer"), user_id=None)

    if subject.pk == request.user.pk and another_unscoped_admin_exists(
        exclude_user_id=request.user.pk
    ):
        messages.error(
            request,
            "You cannot choose your own screening file. Ask another administrator with "
            "access to the whole church to link it for you.",
        )
        return redirect("accounts:admin_list")

    volunteer.user_id = subject.pk
    volunteer.save(update_fields=["user_id", "updated_at"])
    audit.record(
        AuditAction.UPDATE,
        "Volunteer",
        entity_id=volunteer.pk,
        entity_label=volunteer.full_name,
        summary=f"Linked to the administrator account for {subject.get_full_name()}",
    )
    messages.success(
        request,
        f"{volunteer.full_name}'s existing record is now {subject.get_full_name()}'s "
        "screening file.",
    )
    return redirect("accounts:admin_list")


@requires(Capability.MANAGE_USERS)
@require_POST
def admin_create_volunteer(request, pk: int):
    """Create a fresh screening file for an administrator who has none."""

    subject = get_object_or_404(User, pk=pk)
    if Volunteer.objects.filter(user_id=subject.pk).exists():
        messages.info(request, f"{subject.get_full_name()} already has a volunteer record.")
        return redirect("accounts:admin_list")

    volunteer = Volunteer.objects.create(
        first_name=subject.first_name,
        last_name=subject.last_name,
        email=subject.email,
        user_id=subject.pk,
    )
    audit.record(
        AuditAction.CREATE,
        "Volunteer",
        entity_id=volunteer.pk,
        entity_label=volunteer.full_name,
        summary="Volunteer record created for a screening administrator",
    )
    messages.success(
        request,
        f"Created a volunteer record for {subject.get_full_name()}. Give them a ministry "
        "role to start their screening.",
    )
    return redirect("org:volunteer_detail", pk=volunteer.pk)


@requires(Capability.MANAGE_USERS)
@require_http_methods(["GET", "POST"])
def admin_access(request, pk: int):
    """Change one administrator's access level and departments."""

    subject = get_object_or_404(User, pk=pk)
    grant = grant_of(subject)

    initial = {}
    if grant is not None:
        initial = {
            "access_level": grant.access_level_id,
            "departments": list(grant.departments.values_list("pk", flat=True)),
        }

    form = AccessGrantForm(
        request.POST or None,
        granting_user=request.user,
        subject=subject,
        initial=initial,
    )

    if request.method == "POST" and form.is_valid():
        level = form.cleaned_data["access_level"]
        departments = list(form.cleaned_data["departments"])

        blocked = would_strand_the_church(subject, level)
        if blocked:
            messages.error(request, blocked)
            return redirect("accounts:admin_list")

        before = access_snapshot(grant)
        apply_grant(
            subject,
            level,
            departments,
            granted_by=request.user,
            granted_by_display=request.user.display_name,
        )
        audit.record(
            AuditAction.ACCESS_CHANGED,
            "User",
            entity_id=subject.pk,
            entity_label=subject.get_full_name() or f"user #{subject.pk}",
            summary=f"Access level set to {level.name}"
            + (
                f" ({', '.join(sorted(d.name for d in departments))})"
                if level.is_scoped and departments
                else ""
            ),
            detail={"changed": diff_summary(before, access_snapshot(grant_of(subject)))},
        )

        if level.is_scoped and not departments:
            messages.warning(
                request,
                f"{subject.get_full_name()} is on a limited access level with no "
                "departments selected, so they will not see any volunteers.",
            )
        else:
            messages.success(request, f"{subject.get_full_name()} is now {level.name}.")
        return redirect("accounts:admin_list")

    return render(
        request,
        "accounts/admin_access.html",
        {"form": form, "subject": subject, "grant": grant},
    )


@requires(Capability.MANAGE_USERS)
@require_http_methods(["GET", "POST"])
def admin_invite(request):
    """
    Add another screening admin to this church, and mint their first sign-in link.

    The link is shown to the inviting admin as well as emailed. That is not only a
    workaround for email not being configured yet: a church may well want to hand it
    over in person, and an invite that silently fails to arrive is worse than one the
    sender can see.

    An administrator is also a person who serves, and Plan to Protect screens people who
    serve, so this also gives them a volunteer file — see
    :func:`apps.accounts.services.file_for_new_admin`.
    ``?volunteer=<pk>`` arrives from the "Make this person an administrator" button on an
    existing file and means "this is already them", which skips the guessing entirely.

    The whole thing is one transaction. It was not before, and could already leave a
    ``User`` behind with no access level if the grant failed; three writes made that
    worth fixing rather than documenting.
    """

    existing_file = volunteer_from_request(request)
    initial = {}
    if existing_file is not None:
        initial = {
            "first_name": existing_file.first_name,
            "last_name": existing_file.last_name,
            "email": existing_file.email,
        }

    form = AdminInviteForm(
        request.POST or None, granting_user=request.user, initial=initial
    )

    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        level = data["access_level"]
        departments = list(data["departments"])

        with transaction.atomic():
            user = User.objects.create_user(
                email=data["email"],
                first_name=data["first_name"],
                last_name=data["last_name"],
            )
            apply_grant(
                user,
                level,
                departments,
                granted_by=request.user,
                granted_by_display=request.user.display_name,
            )
            audit.record(
                AuditAction.CREATE,
                "User",
                entity_id=user.pk,
                entity_label=user.get_full_name(),
                summary=f"Screening administrator added ({level.name})",
            )
            file_note = file_for_new_admin(user, existing_file)

            _, url = link_service.issue_link(user, LinkPurpose.INVITE, issued_by=request.user)

        # Outside the transaction: sending mail is not something a rollback can undo, and
        # a provider timeout should not discard an administrator who was created fine.
        emailed = link_service.send_link(
            user, url, LinkPurpose.INVITE, church_name=_church_name(request)
        )
        if file_note:
            messages.warning(request, file_note)

        return _link_issued_response(
            request, user, url, LinkPurpose.INVITE, emailed, just_added=True
        )

    return render(
        request,
        "accounts/admin_invite.html",
        {"form": form, "existing_file": existing_file},
    )


def _church_name(request) -> str:
    return getattr(getattr(request, "tenant", None), "name", "") or ""


@requires(Capability.MANAGE_USERS)
@require_POST
def admin_toggle_active(request, pk: int):
    """
    Deactivate or reactivate another admin.

    Accounts are never deleted — the audit trail refers to them. The last active admin
    cannot be deactivated, and nobody can deactivate themselves.
    """
    user = get_object_or_404(User, pk=pk)

    if user.pk == request.user.pk:
        messages.error(request, "You cannot deactivate your own account.")
        return redirect("accounts:admin_list")

    deactivating = user.is_active
    if deactivating:
        # Three refusals, one per way a deactivation could paint the church into a
        # corner: no administrators at all; nobody left who can manage access (a gap
        # access levels reopened — "manage access church-wide" is a capability now,
        # not something every account has); and the actor freeing themselves to
        # affirm their own review backlog.
        if User.objects.filter(is_active=True).count() <= 1:
            refusal = (
                "This is the last active administrator. Add another before deactivating "
                "this one, or the church would lose access entirely."
            )
        else:
            refusal = would_strand_the_church(
                user, no_access_level()
            ) or own_review_backlog_unlocked_by_removing(request.user, user)
        if refusal:
            messages.error(request, refusal)
            return redirect("accounts:admin_list")

    user.is_active = not deactivating
    user.save(update_fields=["is_active"])

    audit.record(
        AuditAction.DEACTIVATE if deactivating else AuditAction.REACTIVATE,
        "User",
        entity_id=user.pk,
        entity_label=user.get_full_name(),
        summary="Administrator deactivated" if deactivating else "Administrator reactivated",
    )
    messages.success(
        request,
        f"{user.get_full_name()} has been "
        + ("deactivated." if deactivating else "reactivated."),
    )
    return redirect("accounts:admin_list")


@requires(Capability.MANAGE_USERS)
@require_POST
def admin_reissue_link(request, pk: int):
    """
    Mint a fresh sign-in link for an admin who never finished enrolling, or who has
    lost their passkey — the only gap the original invite link left: it works once,
    so a link consumed by anything other than its recipient (forwarded through a chat
    app that unfurls it, opened by an email scanner, or just clicked twice) leaves
    them with no way back in except asking whoever runs this console.

    How the purpose is chosen — and why — is :func:`_issue_and_show_link`.
    """
    user = get_object_or_404(User, pk=pk)

    if not user.is_active:
        messages.error(request, "Reactivate this administrator before issuing a new link.")
        return redirect("accounts:admin_list")

    return _issue_and_show_link(request, user)


# ---------------------------------------------------------------------------
# Access levels
# ---------------------------------------------------------------------------
#
# Lives in the accounts app rather than in core, where the models are, because this is
# the "Administrators" section of the church app and a church reads the two screens
# together. The models sit in core for a schema reason, not an organisational one — see
# UserAccessGrant's docstring.


@requires(Capability.MANAGE_USERS)
def access_level_list(request):
    """Every access level at this church, with how many administrators hold each."""


    levels = AccessLevel.objects.annotate(holders=Count("grants"))
    return render(request, "accounts/access_level_list.html", {"levels": levels})


@requires(Capability.MANAGE_USERS)
@require_http_methods(["GET", "POST"])
def access_level_create(request):

    form = AccessLevelForm(request.POST or None, user=request.user)
    if request.method == "POST" and form.is_valid():
        level = form.save()
        audit.record(
            AuditAction.ACCESS_CHANGED,
            "AccessLevel",
            entity_id=level.pk,
            entity_label=level.name,
            summary=f"Access level created ({'limited' if level.is_scoped else 'church-wide'})",
            detail={"capabilities": sorted(level.capabilities())},
        )
        messages.success(request, f"Access level '{level.name}' created.")
        return redirect("accounts:access_level_list")

    return render(request, "accounts/access_level_form.html", {"form": form, "level": None})


@requires(Capability.MANAGE_USERS)
@require_http_methods(["GET", "POST"])
def access_level_edit(request, pk: int):

    level = get_object_or_404(AccessLevel, pk=pk)
    before = _level_snapshot(level)

    form = AccessLevelForm(request.POST or None, instance=level, user=request.user)
    if request.method == "POST" and form.is_valid():
        form.save()
        after = _level_snapshot(level)
        audit.record(
            AuditAction.ACCESS_CHANGED,
            "AccessLevel",
            entity_id=level.pk,
            entity_label=level.name,
            summary="Access level changed",
            detail={"changed": diff_summary(before, after)},
        )
        if before != after:
            messages.info(
                request,
                "This takes effect on the next request from anyone holding this level.",
            )
        messages.success(request, f"'{level.name}' updated.")
        return redirect("accounts:access_level_list")

    return render(request, "accounts/access_level_form.html", {"form": form, "level": level})


def _level_snapshot(level) -> dict:
    """What the audit diff compares — the name, both flags, every capability."""
    return {
        "name": level.name,
        "is_scoped": level.is_scoped,
        "is_active": level.is_active,
        **{field: getattr(level, field) for field in AccessLevel.CAPABILITY_FIELDS},
    }
