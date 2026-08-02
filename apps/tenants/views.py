"""
Super-admin console (public schema) plus the tenant-side key backup gate.

The console is intentionally small: onboard a church, list churches, adjust a
church's settings, and handle key escrow. It does **not** browse church data — that
is what the church's own admins do inside their own schema, and keeping the console
out of it means the public schema never needs a tenant DEK.
"""

from __future__ import annotations

import functools
import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.db import connection
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods

from apps.core import audit
from apps.core.access import (
    Capability,
    has_capability,
    open_to_any_signed_in_user,
    requires,
)
from apps.core.crypto import encode_key, unwrap_dek

from .forms import ChurchSettingsForm, KeyBackupConfirmForm, ProvisionChurchForm, RestoreKeyForm
from .models import Tenant
from .services import ProvisioningError, provision_church, rotate_key_from_escrow, set_document_mode

logger = logging.getLogger("vms.tenants")


def _is_platform_admin(user) -> bool:
    return user.is_authenticated and user.is_superuser


#: Guards every console view. The console lives in the public schema, so a church
#: admin's session (issued in a tenant schema) cannot reach it in any case — this
#: is the second layer.
platform_admin_required = user_passes_test(_is_platform_admin, login_url="/accounts/login/")


def _require_public_schema():
    if getattr(connection, "schema_name", "public") != "public":
        raise Http404("The super-admin console is only available on the platform domain.")


def console_view(view):
    """
    Both guards every console view needs, in one place: a platform admin, and the
    public schema. Composed so the schema check cannot be forgotten on the next view.
    """

    @functools.wraps(view)
    def wrapper(request, *args, **kwargs):
        _require_public_schema()
        return view(request, *args, **kwargs)

    return platform_admin_required(wrapper)


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------


@console_view
def church_list(request):
    # The public schema is the console itself, not a church — excluded here rather
    # than skipped row-by-row in the template, so it is never counted anywhere.
    churches = Tenant.objects.exclude(schema_name="public").prefetch_related("domains")
    return render(
        request,
        "tenants/church_list.html",
        {
            "churches": churches,
            "pending_backup": [c for c in churches if c.key_backup_pending],
        },
    )


@console_view
@require_http_methods(["GET", "POST"])
def church_create(request):
    form = ProvisionChurchForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        try:
            result = provision_church(
                name=data["name"],
                schema_name=data["schema_name"],
                domain_name=data["domain_name"],
                admin_email=data["admin_email"],
                admin_first_name=data["admin_first_name"],
                admin_last_name=data["admin_last_name"],
                document_mode=data["document_mode"],
                contact_name=data["contact_name"],
                contact_email=data["contact_email"],
                reminder_lead_days=data["reminder_lead_days"],
                seed_template=data["seed_template"],
            )
        except ProvisioningError as exc:
            form.add_error(None, str(exc))
        else:
            # The raw key and the invite link are both shown on the next page
            # only, and both travel in the session rather than the URL so they stay
            # out of proxy logs and browser history. Popped on first render.
            request.session["provisioned_key"] = {
                "tenant_id": result.tenant.pk,
                "dek_b64": result.dek_b64,
                "invite_url": result.invite_url,
                "admin_email": result.admin_email,
            }
            return redirect("tenants:church_key_shown", pk=result.tenant.pk)

    return render(
        request,
        "tenants/church_create.html",
        {"form": form, "base_domain": settings.VMS_BASE_DOMAIN},
    )


@console_view
def church_key_shown(request, pk: int):
    """
    One-time display of a newly provisioned church's key, for operator escrow.

    The church's own admin is separately forced through
    :func:`key_backup` at first sign-in.
    """
    church = get_object_or_404(Tenant, pk=pk)

    stashed = request.session.pop("provisioned_key", None)
    if not stashed or stashed.get("tenant_id") != church.pk:
        messages.info(
            request,
            "The key is no longer displayable from here. Use "
            "`manage.py export_tenant_key` to retrieve it for escrow.",
        )
        return redirect("tenants:church_detail", pk=church.pk)

    return render(
        request,
        "tenants/church_key_shown.html",
        {
            "church": church,
            "dek_b64": stashed["dek_b64"],
            "fingerprint": church.dek_fingerprint,
            "invite_url": stashed.get("invite_url", ""),
            "admin_email": stashed.get("admin_email", ""),
        },
    )


@console_view
def church_detail(request, pk: int):
    church = get_object_or_404(Tenant.objects.prefetch_related("domains"), pk=pk)
    return render(
        request,
        "tenants/church_detail.html",
        {"church": church, "restore_form": RestoreKeyForm()},
    )


@console_view
@require_http_methods(["GET", "POST"])
def church_settings(request, pk: int):
    church = get_object_or_404(Tenant, pk=pk)
    previous_mode = church.document_mode

    form = ChurchSettingsForm(request.POST or None, instance=church)
    if request.method == "POST" and form.is_valid():
        # Document mode changes are audited inside the church's own trail, so
        # route them through the service rather than saving the field directly.
        new_mode = form.cleaned_data["document_mode"]
        form.instance.document_mode = previous_mode
        form.save()
        if new_mode != previous_mode:
            set_document_mode(
                church, new_mode, actor_label=request.user.get_full_name() or "super-admin"
            )
        messages.success(request, f"Settings updated for {church.name}.")
        return redirect("tenants:church_detail", pk=church.pk)

    return render(request, "tenants/church_settings.html", {"church": church, "form": form})


@console_view
@require_http_methods(["POST"])
def church_restore_key(request, pk: int):
    """Re-wrap a church's DEK from the operator's escrow copy (break-glass)."""
    church = get_object_or_404(Tenant, pk=pk)
    form = RestoreKeyForm(request.POST)

    if not form.is_valid():
        messages.error(request, "Paste the escrowed key to continue.")
        return redirect("tenants:church_detail", pk=church.pk)

    try:
        rotate_key_from_escrow(church, form.cleaned_data["dek_b64"])
    except Exception as exc:  # noqa: BLE001 - surfaced verbatim to the operator
        messages.error(request, f"Key not accepted: {exc}")
    else:
        logger.warning(
            "Tenant key re-imported from escrow schema=%s fingerprint=%s",
            church.schema_name,
            church.dek_fingerprint,
        )
        messages.success(
            request,
            f"Key re-wrapped for {church.name} (fingerprint {church.dek_fingerprint}).",
        )

    return redirect("tenants:church_detail", pk=church.pk)


# ---------------------------------------------------------------------------
# Tenant-side: forced key backup
# ---------------------------------------------------------------------------


# The *page* is not gated on a capability, deliberately. ForceKeyBackupMiddleware
# redirects *every* authenticated user here until the church's key is backed up, so
# requiring a capability would trap a department admin on the one page they cannot open.
# The key itself is another matter — see ``may_hold_the_key`` below.
@open_to_any_signed_in_user("the forced key-backup step")
@require_http_methods(["GET", "POST"])
def key_backup(request):
    """
    The gate a new church passes through before using the app.

    ``ForceKeyBackupMiddleware`` redirects here until the admin confirms. The key is
    unwrapped for display — the app holds the master key, so it can always do this —
    and the confirmation is recorded on the church row and in its audit trail.

    Reaching this page and being shown the key are two different permissions. Anyone
    trapped here by the middleware needs to see *something*, or they are staring at a
    blank wall with no way forward and no idea why; but the key decrypts every volunteer
    record at the church, so only somebody who runs the church is shown it. Everyone
    else gets told who to ask. Amended 2026-08-02; see BUILD_NOTES §1.22.
    """
    church = getattr(connection, "tenant", None)
    if church is None or getattr(church, "schema_name", "public") == "public":
        raise Http404("No church in scope.")

    if not church.key_backup_pending:
        messages.info(request, "This church's encryption key has already been backed up.")
        return redirect("dashboard")

    may_hold_the_key = has_capability(request.user, Capability.MANAGE_USERS)
    dek_b64 = encode_key(unwrap_dek(bytes(church.dek_wrapped))) if may_hold_the_key else ""

    if request.method == "POST" and not may_hold_the_key:
        # The confirmation is a compliance record — "somebody at this church has their
        # own copy of the key". Somebody who was never shown the key cannot truthfully
        # make it, and the form would otherwise accept them: it checks the fingerprint,
        # which is on the page for everyone.
        messages.error(
            request,
            "Only an administrator who can manage this church's administrators can "
            "confirm the key backup. Ask them to sign in and complete this step.",
        )
        return redirect("tenants:key_backup")

    if request.method == "POST":
        form = KeyBackupConfirmForm(request.POST, expected_fingerprint=church.dek_fingerprint)
        if form.is_valid():
            from apps.core.models import AuditAction

            church.confirm_key_backup(by=request.user.get_full_name() or request.user.email)
            audit.record(
                AuditAction.KEY_BACKUP,
                "Church",
                entity_id=church.pk,
                entity_label=church.name,
                summary="Encryption key backup confirmed by admin",
                detail={"key_fingerprint": church.dek_fingerprint},
            )
            messages.success(
                request,
                "Thank you — key backup recorded. You now have full access to the system.",
            )
            return redirect("dashboard")
    else:
        form = KeyBackupConfirmForm(expected_fingerprint=church.dek_fingerprint)

    return render(
        request,
        "tenants/key_backup.html",
        {
            "church": church,
            "dek_b64": dek_b64,
            "fingerprint": church.dek_fingerprint,
            "form": form,
            "may_hold_the_key": may_hold_the_key,
        },
    )


@requires(Capability.MANAGE_USERS)
def key_backup_download(request):
    """
    Serve the key as a text file, so 'save it somewhere safe' is one click.

    Gated, and audited. It was neither until 2026-08-02, and the combination was the
    worst hole in the app: ``@open_to_any_signed_in_user`` meant *any* signed-in
    administrator — including a department admin holding not one capability — could GET
    this URL at any time, long after the backup step was done, and receive the key that
    decrypts every volunteer record at the church. Its sibling ``key_backup`` at least
    redirected away once the church had confirmed; this one had no state check at all.

    The missing audit entry is the part that made it invisible rather than merely
    permitted. ``docs/SECURITY.md`` promised that "every key export writes an entry into
    that church's own audit trail" — true of the operator console's export, and not true
    here. A church could have been drained and their own trail would show nothing.
    """
    church = getattr(connection, "tenant", None)
    if church is None or getattr(church, "schema_name", "public") == "public":
        raise Http404("No church in scope.")

    from apps.core.models import AuditAction

    dek_b64 = encode_key(unwrap_dek(bytes(church.dek_wrapped)))
    audit.record(
        AuditAction.KEY_BACKUP,
        "Church",
        entity_id=church.pk,
        entity_label=church.name,
        summary="Encryption key downloaded",
        detail={"key_fingerprint": church.dek_fingerprint},
    )
    body = (
        "VOLUNTEER MANAGEMENT SYSTEM — DATA ENCRYPTION KEY\n"
        "=================================================\n\n"
        f"Church:       {church.name}\n"
        f"Short code:   {church.schema_name}\n"
        f"Fingerprint:  {church.dek_fingerprint}\n\n"
        f"Key (base64): {dek_b64}\n\n"
        "KEEP THIS SAFE AND OFFLINE.\n"
        "This key decrypts your volunteers' personal information. Anyone holding\n"
        "both this key and a copy of the database can read that information, so\n"
        "store it the way you would store a master password — in a password\n"
        "manager or a locked cabinet, not in email and not on a shared drive.\n\n"
        "Without this key, your records cannot be recovered.\n"
    )
    response = HttpResponse(body, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = (
        f'attachment; filename="vms-encryption-key-{church.schema_name}.txt"'
    )
    # Never let a proxy or the browser retain the key.
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    return response
