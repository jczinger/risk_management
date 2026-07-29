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

import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods, require_POST
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited

from apps.core import audit
from apps.core.models import AuditAction
from apps.tenants.routing import clear_tenant_cookie, find_login_targets, set_tenant_cookie

from . import links as link_service
from . import webauthn_service
from .forms import AdminInviteForm, AdminProfileForm, PasskeyLabelForm, RecoveryRequestForm
from .models import LinkPurpose, User
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
    from django.utils.http import url_has_allowed_host_and_scheme

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
        entity_label=user.get_full_name() or "administrator",
        summary=f"Signed in via {method}",
        detail={"method": method},
    )
    logger.info("Login user=%s method=%s", user.pk, method)
    return redirect(_post_login_redirect(request))


# ---------------------------------------------------------------------------
# Sign in / out
# ---------------------------------------------------------------------------


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


@require_POST
def logout_view(request):
    if request.user.is_authenticated:
        audit.record(
            AuditAction.LOGOUT,
            "User",
            entity_id=request.user.pk,
            entity_label=request.user.get_full_name() or "administrator",
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


@never_cache
@require_POST
def webauthn_authenticate_begin(request):
    """Issue an assertion challenge. No user needed — discoverable credentials."""
    if _rate_limited(request):
        return JsonResponse(_RATE_LIMITED_JSON, status=429)
    try:
        options = webauthn_service.begin_authentication(request)
    except WebAuthnError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    return HttpResponse(options, content_type="application/json")


def _rate_limited(request) -> bool:
    try:
        return _check_passkey_ratelimit(request)
    except Ratelimited:
        return True


@never_cache
@require_POST
def webauthn_authenticate_finish(request):
    """Verify an assertion and sign the user in."""
    if _rate_limited(request):
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
@login_required
@require_POST
def webauthn_register_begin(request):
    """Issue a registration challenge for the signed-in user."""
    try:
        options = webauthn_service.begin_registration(request, request.user)
    except WebAuthnError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    return HttpResponse(options, content_type="application/json")


@never_cache
@login_required
@require_POST
def webauthn_register_finish(request):
    """Verify and store a new passkey."""
    label = request.headers.get("X-Passkey-Label", "")
    body = request.body.decode("utf-8", errors="replace")
    if not body:
        return HttpResponseBadRequest("No passkey response received.")

    try:
        passkey = webauthn_service.finish_registration(request, request.user, body, label=label)
    except WebAuthnError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    audit.record(
        AuditAction.UPDATE,
        "Passkey",
        entity_id=passkey.pk,
        entity_label=request.user.get_full_name() or "administrator",
        summary="Passkey registered",
    )
    return JsonResponse({"ok": True, "redirect": reverse("accounts:security")})


@login_required
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
            entity_label=request.user.get_full_name() or "administrator",
            summary="Passkey removed",
        )
        messages.success(request, "Passkey removed.")
    return redirect("accounts:security")


# ---------------------------------------------------------------------------
# Sign-in links
# ---------------------------------------------------------------------------


@never_cache
@require_http_methods(["GET"])
def link_consume(request, payload: str):
    """
    Spend a sign-in link: sign the holder in once, and send them to enrol a passkey.

    A GET, because this is a URL in an email and there is nothing else it could be.
    That normally deserves suspicion — a link that changes state can be spent by a
    scanner in the recipient's own mail chain, and by any prefetcher in between. It is
    accepted here for the same reason every other product accepts it: the alternative
    is an interstitial page whose only content is a button, which stops nothing that
    follows redirects. The exposure is bounded by the link being single-use and
    short-lived, and by the sign-in it grants leading nowhere except passkey enrolment.
    """
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
        entity_label=user.get_full_name() or "administrator",
        summary=f"{LinkPurpose(link.purpose).label} link used",
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

    if not user.has_passkey:
        messages.info(
            request,
            "You are signed in for now. Set up a passkey to finish — it is how you will "
            "sign in from here on.",
        )

    return _apply_tenant_cookie(response, getattr(request, "vms_login_target", None))


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
        try:
            rate_limited = _check_recovery_ratelimit(request)
        except Ratelimited:
            rate_limited = True

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
    from django_tenants.utils import schema_context

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


@login_required
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

    return render(request, "accounts/passkey_required.html", {"label_form": PasskeyLabelForm()})


# ---------------------------------------------------------------------------
# Account settings
# ---------------------------------------------------------------------------


@login_required
def security(request):
    """Passkeys — the whole of a person's sign-in setup, on one page."""
    return render(
        request,
        "accounts/security.html",
        {
            "passkeys": request.user.passkeys.filter(is_active=True),
            "label_form": PasskeyLabelForm(),
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def profile(request):
    form = AdminProfileForm(request.POST or None, instance=request.user)

    if request.method == "POST" and form.is_valid():
        form.save()
        audit.record(
            AuditAction.UPDATE,
            "User",
            entity_id=request.user.pk,
            entity_label=request.user.get_full_name() or "administrator",
            summary="Own profile updated",
        )
        messages.success(request, "Your details have been updated.")
        return redirect("accounts:profile")

    return render(request, "accounts/profile.html", {"form": form})


# ---------------------------------------------------------------------------
# Managing the church's other admins
# ---------------------------------------------------------------------------


@login_required
def admin_list(request):
    """Every screening admin at this church. All have equal permissions."""
    from django.db import connection

    if getattr(connection, "schema_name", "public") == "public":
        # The platform console manages churches, not church staff.
        messages.error(request, "Administrator management happens inside a church.")
        return redirect("/")

    return render(
        request,
        "accounts/admin_list.html",
        {"admins": User.objects.all().order_by("last_name", "first_name")},
    )


@login_required
@require_http_methods(["GET", "POST"])
def admin_invite(request):
    """
    Add another screening admin to this church, and mint their first sign-in link.

    The link is shown to the inviting admin as well as emailed. That is not only a
    workaround for email not being configured yet: a church may well want to hand it
    over in person, and an invite that silently fails to arrive is worse than one the
    sender can see.
    """
    form = AdminInviteForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        user = User.objects.create_user(
            email=data["email"],
            first_name=data["first_name"],
            last_name=data["last_name"],
        )
        audit.record(
            AuditAction.CREATE,
            "User",
            entity_id=user.pk,
            entity_label=user.get_full_name(),
            summary="Screening administrator added",
        )

        _, url = link_service.issue_link(user, LinkPurpose.INVITE, issued_by=request.user)
        emailed = link_service.send_link(
            user, url, LinkPurpose.INVITE, church_name=_church_name(request)
        )

        return render(
            request,
            "accounts/link_issued.html",
            {
                "target": user,
                "url": url,
                "emailed": emailed,
                "expires_in": link_service.describe_lifetime(LinkPurpose.INVITE),
                "is_recovery": False,
                "just_added": True,
            },
        )

    return render(request, "accounts/admin_invite.html", {"form": form})


def _church_name(request) -> str:
    return getattr(getattr(request, "tenant", None), "name", "") or ""


@login_required
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

    if user.is_active and User.objects.filter(is_active=True).count() <= 1:
        messages.error(
            request,
            "This is the last active administrator. Add another before deactivating "
            "this one, or the church would lose access entirely.",
        )
        return redirect("accounts:admin_list")

    user.is_active = not user.is_active
    user.save(update_fields=["is_active"])

    audit.record(
        AuditAction.DEACTIVATE if not user.is_active else AuditAction.REACTIVATE,
        "User",
        entity_id=user.pk,
        entity_label=user.get_full_name(),
        summary=("Administrator deactivated" if not user.is_active else "Administrator reactivated"),
    )
    messages.success(
        request,
        f"{user.get_full_name()} has been "
        + ("deactivated." if not user.is_active else "reactivated."),
    )
    return redirect("accounts:admin_list")


@login_required
@require_POST
def admin_reissue_link(request, pk: int):
    """
    Mint a fresh sign-in link for an admin who never finished enrolling, or who has
    lost their passkey — the only gap the original invite link left: it works once,
    so a link consumed by anything other than its recipient (forwarded through a chat
    app that unfurls it, opened by an email scanner, or just clicked twice) leaves
    them with no way back in except asking whoever runs this console.

    The purpose follows what the account already has: no passkey yet is still a first
    sign-in, so this mints another :attr:`LinkPurpose.INVITE` — same seven-day window,
    no "account recovered" notice to the other admins, because nothing is being
    recovered. A passkey already on file makes this a :attr:`LinkPurpose.RECOVERY`,
    the same as the self-service form, with that form's shorter window and the notice
    to colleagues that a working credential is being replaced.
    """
    user = get_object_or_404(User, pk=pk)

    if not user.is_active:
        messages.error(request, "Reactivate this administrator before issuing a new link.")
        return redirect("accounts:admin_list")

    purpose = LinkPurpose.RECOVERY if user.has_passkey else LinkPurpose.INVITE
    _, url = link_service.issue_link(user, purpose, issued_by=request.user)
    emailed = link_service.send_link(user, url, purpose, church_name=_church_name(request))

    return render(
        request,
        "accounts/link_issued.html",
        {
            "target": user,
            "url": url,
            "emailed": emailed,
            "expires_in": link_service.describe_lifetime(purpose),
            "is_recovery": purpose == LinkPurpose.RECOVERY,
        },
    )
