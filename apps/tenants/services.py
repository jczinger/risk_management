"""
Church provisioning.

Creating a church is the one operation that spans both schemas, so it is kept in a
single function rather than spread across a view. The order matters:

1. Create the ``Tenant`` row **with its DEK already generated**, so the key exists
   before any encrypted row could be written.
2. django-tenants creates the Postgres schema and runs the tenant migrations.
3. Point a hostname at it.
4. Inside the new schema: create the first screening admin, seed the Plan to
   Protect requirement template, and write the opening audit entries.

The raw DEK is returned to the caller and never persisted. The caller — the
super-admin console — shows it exactly once and then relies on
``Tenant.key_backup_pending`` to force the church's admin through a confirmation
step before they can use the app.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from django.db import transaction
from django_tenants.utils import schema_context

from apps.core import audit
from apps.core.crypto import encode_key
from apps.core.keys import forget_cached_keys, override_key

from .models import Domain, DocumentMode, Tenant, validate_schema_name

logger = logging.getLogger("vms.tenants")


class ProvisioningError(Exception):
    """Provisioning could not complete. The transaction is rolled back."""


@dataclass
class ProvisionResult:
    """What the console needs after a successful provision."""

    tenant: Tenant
    #: None when the church is reached only through the shared platform address.
    domain: Domain | None
    admin_email: str
    #: Base64 DEK. Shown once, then dropped. Never written to a log or the database.
    dek_b64: str
    dek_fingerprint: str
    seeded_requirements: int


@transaction.atomic
def provision_church(
    *,
    name: str,
    schema_name: str,
    domain_name: str,
    admin_email: str,
    admin_first_name: str = "",
    admin_last_name: str = "",
    admin_password: str | None = None,
    document_mode: str = DocumentMode.STORE,
    contact_name: str = "",
    contact_email: str = "",
    reminder_lead_days: str = "60,30,7",
    seed_template: bool = True,
) -> ProvisionResult:
    """
    Create a church, its schema, its encryption key and its first admin.

    Raises :class:`ProvisioningError` on any conflict; nothing is left behind
    because the whole thing runs in one transaction.
    """
    # Imported here: these models live in the tenant schema and importing them at
    # module scope would create a circular dependency through apps.core.
    from apps.accounts.models import User
    from apps.core.models import AuditAction
    from apps.requirements.seed import seed_default_template

    schema_name = (schema_name or "").strip().lower()
    validate_schema_name(schema_name)

    # Optional. Blank means the church is reached through the shared platform address,
    # where sign-in resolves the schema from the address rather than DNS. A hostname is
    # only needed for a church that wants its own — which then costs a DNS record and a
    # certificate, and is why it is no longer the default.
    domain_name = (domain_name or "").strip().lower()

    if Tenant.objects.filter(schema_name=schema_name).exists():
        raise ProvisioningError(f"A church already uses the schema '{schema_name}'.")
    if domain_name and Domain.objects.filter(domain=domain_name).exists():
        raise ProvisioningError(f"The hostname '{domain_name}' is already in use.")

    tenant = Tenant(
        name=name.strip(),
        schema_name=schema_name,
        document_mode=document_mode,
        contact_name=contact_name.strip(),
        contact_email=contact_email.strip(),
        reminder_lead_days=reminder_lead_days,
    )
    dek = tenant.assign_new_dek()
    tenant.full_clean(exclude=["dek_wrapped", "dek_fingerprint"])
    # Saving creates the schema and runs every tenant migration against it.
    tenant.save()

    domain = (
        Domain.objects.create(domain=domain_name, tenant=tenant, is_primary=True)
        if domain_name
        else None
    )

    seeded = 0
    # The Tenant row is not yet committed, so connection.tenant cannot supply the
    # key; hand it over explicitly for the duration of the tenant-schema work.
    with schema_context(schema_name), override_key(dek):
        admin = User.objects.create_user(
            email=admin_email,
            password=admin_password,  # None ⇒ passkey-only account
            first_name=admin_first_name.strip(),
            last_name=admin_last_name.strip(),
            is_active=True,
        )

        if seed_template:
            seeded = seed_default_template()

        # Attribute the opening entries to the operator who ran the provision, so
        # the church's own audit trail starts with a truthful record of its origin.
        audit.record(
            AuditAction.CREATE,
            "Church",
            entity_id=tenant.pk,
            entity_label=tenant.name,
            summary=f"Church provisioned ({tenant.get_document_mode_display()})",
            detail={
                "schema": schema_name,
                "hostname": domain_name or "(shared platform address)",
                "document_mode": document_mode,
                "key_fingerprint": tenant.dek_fingerprint,
                "seeded_requirements": seeded,
            },
        )
        audit.record(
            AuditAction.CREATE,
            "User",
            entity_id=admin.pk,
            entity_label=admin.get_full_name() or "first admin",
            summary="First screening administrator created",
            detail={"passwordless": admin_password is None},
        )

    logger.info(
        "Provisioned church schema=%s hostname=%s key_fingerprint=%s seeded=%d",
        schema_name,
        domain_name or "shared",
        tenant.dek_fingerprint,
        seeded,
    )

    return ProvisionResult(
        tenant=tenant,
        domain=domain,
        admin_email=admin_email,
        dek_b64=encode_key(dek),
        dek_fingerprint=tenant.dek_fingerprint,
        seeded_requirements=seeded,
    )


def set_document_mode(tenant: Tenant, mode: str, *, actor_label: str = "super-admin") -> None:
    """
    Change a church's document storage mode.

    Only the platform super-admin can do this (Build Spec §5). Existing documents
    are left exactly as they are — switching to ``track`` does not delete files a
    church already entrusted to us, it only stops accepting new ones.
    """
    from apps.core.models import AuditAction

    if mode not in DocumentMode.values:
        raise ProvisioningError(f"'{mode}' is not a valid document mode.")

    previous = tenant.document_mode
    if previous == mode:
        return

    tenant.document_mode = mode
    tenant.save(update_fields=["document_mode"])

    with schema_context(tenant.schema_name):
        audit.record(
            AuditAction.UPDATE,
            "Church",
            entity_id=tenant.pk,
            entity_label=tenant.name,
            summary=f"Document storage mode changed to '{mode}'",
            detail={"before": {"document_mode": previous}, "after": {"document_mode": mode}},
            actor=audit.Actor.system(actor_label),
        )


def rotate_key_from_escrow(tenant: Tenant, dek_b64: str) -> None:
    """
    Re-wrap a tenant's DEK from an escrowed copy.

    This is the break-glass path (PRD §5): after a ``PLATFORM_MASTER_KEY`` rotation
    or a restore onto fresh infrastructure, the operator re-imports each church's
    key from Keeper Security. The key material itself does not change, so no data
    needs re-encrypting — only the wrapper.
    """
    from apps.core.crypto import decode_key, key_fingerprint, wrap_dek

    dek = decode_key(dek_b64)
    fingerprint = key_fingerprint(dek)

    # A fingerprint mismatch means the wrong escrow entry was pasted. Re-wrapping
    # anyway would render every encrypted value in that schema undecryptable.
    if tenant.dek_fingerprint and fingerprint != tenant.dek_fingerprint:
        raise ProvisioningError(
            f"Key fingerprint mismatch: this key is '{fingerprint}' but "
            f"'{tenant.name}' expects '{tenant.dek_fingerprint}'. Refusing to "
            "overwrite — check which escrow entry belongs to this church."
        )

    tenant.dek_wrapped = wrap_dek(dek)
    tenant.dek_fingerprint = fingerprint
    tenant.save(update_fields=["dek_wrapped", "dek_fingerprint"])
    forget_cached_keys(tenant.schema_name)
