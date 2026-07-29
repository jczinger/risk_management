"""
Super-admin console (public schema) plus the tenant-side key backup gate.

The console is intentionally small: onboard a church, list churches, adjust a
church's settings, and handle key escrow. It does **not** browse church data — that
is what the church's own admins do inside their own schema, and keeping the console
out of it means the public schema never needs a tenant DEK.
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db import connection
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods

from apps.core import audit
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


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------


@platform_admin_required
def church_list(request):
    _require_public_schema()
    churches = Tenant.objects.all().prefetch_related("domains")
    return render(
        request,
        "tenants/church_list.html",
        {
            "churches": churches,
            "pending_backup": [c for c in churches if c.key_backup_pending],
        },
    )


@platform_admin_required
@require_http_methods(["GET", "POST"])
def church_create(request):
    _require_public_schema()

    if request.method == "POST":
        form = ProvisionChurchForm(request.POST)
        if form.is_valid():
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
    else:
        form = ProvisionChurchForm()

    return render(
        request,
        "tenants/church_create.html",
        {"form": form, "base_domain": settings.VMS_BASE_DOMAIN},
    )


@platform_admin_required
def church_key_shown(request, pk: int):
    """
    One-time display of a newly provisioned church's key, for operator escrow.

    The church's own admin is separately forced through
    :func:`key_backup` at first sign-in.
    """
    _require_public_schema()
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


@platform_admin_required
def church_detail(request, pk: int):
    _require_public_schema()
    church = get_object_or_404(Tenant.objects.prefetch_related("domains"), pk=pk)
    return render(
        request,
        "tenants/church_detail.html",
        {"church": church, "restore_form": RestoreKeyForm()},
    )


@platform_admin_required
@require_http_methods(["GET", "POST"])
def church_settings(request, pk: int):
    _require_public_schema()
    church = get_object_or_404(Tenant, pk=pk)
    previous_mode = church.document_mode

    if request.method == "POST":
        form = ChurchSettingsForm(request.POST, instance=church)
        if form.is_valid():
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
    else:
        form = ChurchSettingsForm(instance=church)

    return render(request, "tenants/church_settings.html", {"church": church, "form": form})


@platform_admin_required
@require_http_methods(["POST"])
def church_restore_key(request, pk: int):
    """Re-wrap a church's DEK from the operator's escrow copy (break-glass)."""
    _require_public_schema()
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


@login_required
@require_http_methods(["GET", "POST"])
def key_backup(request):
    """
    The gate a new church passes through before using the app.

    ``ForceKeyBackupMiddleware`` redirects here until the admin confirms. The key is
    unwrapped for display — the app holds the master key, so it can always do this —
    and the confirmation is recorded on the church row and in its audit trail.
    """
    church = getattr(connection, "tenant", None)
    if church is None or getattr(church, "schema_name", "public") == "public":
        raise Http404("No church in scope.")

    if not church.key_backup_pending:
        messages.info(request, "This church's encryption key has already been backed up.")
        return redirect("dashboard")

    dek_b64 = encode_key(unwrap_dek(bytes(church.dek_wrapped)))

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
        },
    )


@login_required
def key_backup_download(request):
    """Serve the key as a text file, so 'save it somewhere safe' is one click."""
    church = getattr(connection, "tenant", None)
    if church is None or getattr(church, "schema_name", "public") == "public":
        raise Http404("No church in scope.")

    dek_b64 = encode_key(unwrap_dek(bytes(church.dek_wrapped)))
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
