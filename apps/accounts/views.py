"""
Sign-in and account management.

The sign-in page leads with a passkey button and offers the password form behind a
disclosure — passkeys are the primary method, not an alternative (Build Spec §1).

Flows:

* **Passkey:** POST to ``webauthn_authenticate_begin`` → browser ceremony → POST to
  ``webauthn_authenticate_finish`` → signed in. One step, no second factor needed.
* **Password:** POST the password form → *not yet signed in*, held in a pending
  session slot → TOTP step → signed in. An account with a usable password but no
  confirmed TOTP is sent to enrolment before it can go anywhere else.
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
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_http_methods, require_POST
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited

from apps.core import audit
from apps.core.models import AuditAction
from apps.tenants.routing import clear_tenant_cookie, set_tenant_cookie

from . import totp as totp_service
from . import webauthn_service
from .forms import (
    AdminInviteForm,
    AdminProfileForm,
    EmailPasswordForm,
    PasskeyLabelForm,
    SetPasswordForm,
    TOTPEnrolForm,
    TOTPForm,
)
from .models import User
from .webauthn_service import WebAuthnError

logger = logging.getLogger("vms.accounts")


def _post_login_redirect(request) -> str:
    """
    Where to go after a successful sign-in.

    ``next`` is honored only when it is a local path, so the login page cannot be used
    as an open redirect.
    """
    from django.utils.http import url_has_allowed_host_and_scheme

    candidate = request.POST.get("next") or request.GET.get("next") or ""
    if candidate and url_has_allowed_host_and_scheme(
        candidate, allowed_hosts={request.get_host()}, require_secure=request.is_secure()
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
@sensitive_post_parameters("password")
@require_http_methods(["GET", "POST"])
def login_view(request):
    """Passkey-first sign-in, with the password fallback behind a disclosure."""
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)

    form = EmailPasswordForm(request)
    rate_limited = False

    if request.method == "POST":
        try:
            rate_limited = _check_login_ratelimit(request)
        except Ratelimited:
            rate_limited = True

        if rate_limited:
            messages.error(
                request,
                "Too many sign-in attempts. Wait a few minutes before trying again, "
                "or sign in with your passkey.",
            )
        else:
            form = EmailPasswordForm(request, request.POST)
            if form.is_valid():
                user = form.user

                # Validating the form may have switched schemas to the church this
                # address belongs to. Start a clean session so it is created *there*
                # rather than carrying over a public-schema session key.
                if form.target is not None:
                    request.session.flush()

                # Password accepted, but the user is NOT logged in yet — the fallback
                # path requires a second factor (Build Spec §1). The tenant cookie is
                # still set now, before the second factor: it only selects a schema,
                # and an unauthenticated session in that schema grants nothing.
                request.session[totp_service.PENDING_SESSION_KEY] = user.pk
                request.session[totp_service.PENDING_STARTED_KEY] = timezone.now().isoformat()

                if user.has_totp:
                    destination = (
                        f"{reverse('accounts:totp_verify')}?next={_post_login_redirect(request)}"
                    )
                else:
                    # No TOTP yet. Let them in only as far as enrolment, which is
                    # mandatory before the password path is usable for anything else.
                    messages.info(
                        request,
                        "Before you continue, set up an authenticator app. A password on "
                        "its own is not enough to protect volunteers' personal information.",
                    )
                    destination = reverse("accounts:totp_setup_required")

                return _apply_tenant_cookie(redirect(destination), form.target)
            else:
                _audit_failed_login(request, form)

    return render(
        request,
        "accounts/login.html",
        {
            "form": form,
            "next": request.GET.get("next", ""),
            "rate_limited": rate_limited,
        },
    )


@ratelimit(key="post:email", rate=settings.LOGIN_RATELIMIT, method="POST", block=False)
@ratelimit(key="ip", rate="30/5m", method="POST", block=False)
def _check_login_ratelimit(request) -> bool:
    """
    Apply the login rate limits.

    Limited per email *and* per IP: the first stops one account being ground down, the
    second stops one source spraying many accounts. Applied as a helper rather than a
    decorator on the view so a rate-limited attempt still renders the page with an
    explanation instead of a bare 403.
    """
    return getattr(request, "limited", False)


def _audit_failed_login(request, form) -> None:
    """
    Record a failed attempt without storing the address that was tried.

    Writing the attempted address would put an unverified, possibly-someone-else's
    email into the trail in plaintext-adjacent form; the IP is enough to spot a
    pattern.
    """
    if not form.errors:
        return
    audit.record(
        AuditAction.LOGIN_FAILED,
        "User",
        summary="Sign-in attempt failed",
        detail={"reason": next(iter(form.errors.keys()), "invalid")},
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


@never_cache
@require_POST
def webauthn_authenticate_begin(request):
    """Issue an assertion challenge. No user needed — discoverable credentials."""
    try:
        options = webauthn_service.begin_authentication(request)
    except WebAuthnError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    return HttpResponse(options, content_type="application/json")


@never_cache
@require_POST
def webauthn_authenticate_finish(request):
    """Verify an assertion and sign the user in."""
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
# TOTP
# ---------------------------------------------------------------------------


def _pending_user(request) -> User | None:
    """The half-authenticated user between the password and TOTP steps."""
    user_id = request.session.get(totp_service.PENDING_SESSION_KEY)
    started = request.session.get(totp_service.PENDING_STARTED_KEY)
    if not user_id or not started:
        return None

    try:
        age = (timezone.now() - timezone.datetime.fromisoformat(started)).total_seconds()
    except (TypeError, ValueError):
        return None

    if age > totp_service.PENDING_TIMEOUT_SECONDS:
        _clear_pending(request)
        return None

    return User.objects.filter(pk=user_id, is_active=True).first()


def _clear_pending(request) -> None:
    request.session.pop(totp_service.PENDING_SESSION_KEY, None)
    request.session.pop(totp_service.PENDING_STARTED_KEY, None)


@never_cache
@require_http_methods(["GET", "POST"])
def totp_verify(request):
    """The second-factor step. Reached only with a valid pending session."""
    user = _pending_user(request)
    if user is None:
        messages.error(request, "That sign-in attempt timed out. Please start again.")
        return redirect("accounts:login")

    form = TOTPForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        if totp_service.verify_code(user.totp_secret, form.cleaned_data["code"]):
            _clear_pending(request)
            return _complete_login(request, user, method="password + authenticator app")
        form.add_error("code", "That code was not accepted. Try the current code.")
        audit.record(
            AuditAction.LOGIN_FAILED,
            "User",
            entity_id=user.pk,
            summary="Authenticator code rejected",
        )

    return render(request, "accounts/totp_verify.html", {"form": form})


@never_cache
@require_http_methods(["GET", "POST"])
def totp_setup_required(request):
    """
    Mandatory TOTP enrolment for a password account that has none.

    Reached from the password step, so ``request.user`` is still anonymous here — the
    pending session slot identifies who is enrolling.
    """
    user = _pending_user(request)
    if user is None:
        messages.error(request, "That sign-in attempt timed out. Please start again.")
        return redirect("accounts:login")

    secret = request.session.get("vms_totp_new_secret")
    if not secret:
        secret = totp_service.generate_secret()
        request.session["vms_totp_new_secret"] = secret

    form = TOTPEnrolForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        try:
            totp_service.confirm_enrolment(user, secret, form.cleaned_data["code"])
        except ValidationError as exc:
            form.add_error("code", exc.messages[0])
        else:
            request.session.pop("vms_totp_new_secret", None)
            _clear_pending(request)
            audit.record(
                AuditAction.UPDATE,
                "User",
                entity_id=user.pk,
                entity_label=user.get_full_name() or "administrator",
                summary="Authenticator app enrolled",
                actor=audit.Actor(user_id=user.pk, display=user.get_full_name() or "administrator"),
            )
            messages.success(request, "Authenticator app set up. You are signed in.")
            return _complete_login(request, user, method="password + authenticator app")

    uri = totp_service.provisioning_uri(user, secret)
    return render(
        request,
        "accounts/totp_setup.html",
        {
            "form": form,
            "secret": secret,
            "qr": totp_service.qr_data_uri(uri),
            "mandatory": True,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def totp_setup(request):
    """Voluntary TOTP enrolment from account settings."""
    if request.user.has_totp:
        messages.info(request, "You already have an authenticator app set up.")
        return redirect("accounts:security")

    secret = request.session.get("vms_totp_new_secret")
    if not secret:
        secret = totp_service.generate_secret()
        request.session["vms_totp_new_secret"] = secret

    form = TOTPEnrolForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        try:
            totp_service.confirm_enrolment(request.user, secret, form.cleaned_data["code"])
        except ValidationError as exc:
            form.add_error("code", exc.messages[0])
        else:
            request.session.pop("vms_totp_new_secret", None)
            audit.record(
                AuditAction.UPDATE,
                "User",
                entity_id=request.user.pk,
                entity_label=request.user.get_full_name() or "administrator",
                summary="Authenticator app enrolled",
            )
            messages.success(request, "Authenticator app set up.")
            return redirect("accounts:security")

    uri = totp_service.provisioning_uri(request.user, secret)
    return render(
        request,
        "accounts/totp_setup.html",
        {
            "form": form,
            "secret": secret,
            "qr": totp_service.qr_data_uri(uri),
            "mandatory": False,
        },
    )


@login_required
@require_POST
def totp_disable(request):
    try:
        totp_service.disable_totp(request.user)
    except ValidationError as exc:
        messages.error(request, "; ".join(exc.messages))
    else:
        audit.record(
            AuditAction.UPDATE,
            "User",
            entity_id=request.user.pk,
            summary="Authenticator app removed",
        )
        messages.success(request, "Authenticator app removed.")
    return redirect("accounts:security")


# ---------------------------------------------------------------------------
# Account settings
# ---------------------------------------------------------------------------


@login_required
def security(request):
    """Passkeys, authenticator app, and password — one page."""
    return render(
        request,
        "accounts/security.html",
        {
            "passkeys": request.user.passkeys.filter(is_active=True),
            "label_form": PasskeyLabelForm(),
        },
    )


@login_required
@sensitive_post_parameters("new_password1", "new_password2")
@require_http_methods(["GET", "POST"])
def password_change(request):
    form = SetPasswordForm(request.user, request.POST or None)

    if request.method == "POST" and form.is_valid():
        form.save()
        # Changing the password rotates the session hash, so re-establish the session
        # rather than signing the user out mid-visit.
        from django.contrib.auth import update_session_auth_hash

        update_session_auth_hash(request, request.user)
        audit.record(
            AuditAction.UPDATE,
            "User",
            entity_id=request.user.pk,
            summary="Password changed",
        )
        if not request.user.has_totp:
            messages.warning(
                request,
                "Password set. You still need an authenticator app before the password "
                "route can be used to sign in.",
            )
            return redirect("accounts:totp_setup")
        messages.success(request, "Password changed.")
        return redirect("accounts:security")

    return render(request, "accounts/password_change.html", {"form": form})


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
    """Add another screening admin to this church."""
    form = AdminInviteForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        user = User.objects.create_user(
            email=data["email"],
            password=data["password"] or None,
            first_name=data["first_name"],
            last_name=data["last_name"],
        )
        audit.record(
            AuditAction.CREATE,
            "User",
            entity_id=user.pk,
            entity_label=user.get_full_name(),
            summary="Screening administrator added",
            detail={"passwordless": not data["password"]},
        )
        if data["password"]:
            messages.success(
                request,
                f"{user.get_full_name()} can now sign in. They will be required to set "
                "up an authenticator app on first sign-in.",
            )
        else:
            messages.success(
                request,
                f"{user.get_full_name()} has been added as a passkey-only account. They "
                "will need to register a passkey — ask another admin to help them do "
                "that on a trusted device.",
            )
        return redirect("accounts:admin_list")

    return render(request, "accounts/admin_invite.html", {"form": form})


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
