"""
Public-schema models: the church registry.

Everything here lives in the ``public`` schema and is visible to the platform
super-admin only. A church's *data* never appears in this schema — only the fact
that the church exists, how to reach it, and its wrapped encryption key.
"""

from __future__ import annotations

import re

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django_tenants.models import DomainMixin, TenantMixin

from apps.core.crypto import generate_dek, key_fingerprint, wrap_dek

# Postgres identifier rules plus our own: lowercase, starts with a letter. Also
# doubles as the subdomain label, so no underscores.
SCHEMA_NAME_RE = re.compile(r"^[a-z][a-z0-9]{1,40}$")

# Reserved because they either collide with the platform's own hostnames or with
# Postgres' own schemas.
RESERVED_SCHEMA_NAMES = {
    "public",
    "information_schema",
    "pg_catalog",
    "pg_toast",
    "admin",
    "www",
    "api",
    "app",
    "mail",
    "smtp",
    "static",
    "media",
}


def validate_schema_name(value: str) -> None:
    if not SCHEMA_NAME_RE.match(value or ""):
        raise ValidationError(
            "Must be 2–41 characters, lowercase letters and digits only, starting "
            "with a letter. This becomes both the database schema and the subdomain."
        )
    if value in RESERVED_SCHEMA_NAMES:
        raise ValidationError(f"'{value}' is reserved and cannot be used.")


def validate_lead_days(value: str) -> None:
    """Validate a ``60,30,7``-style reminder schedule."""
    if not value.strip():
        raise ValidationError("Enter at least one lead time, or 0 for overdue-only.")
    seen = set()
    for part in value.split(","):
        part = part.strip()
        if not part.isdigit():
            raise ValidationError(f"'{part}' is not a whole number of days.")
        days = int(part)
        if not 0 <= days <= 365:
            raise ValidationError("Lead times must be between 0 and 365 days.")
        if days in seen:
            raise ValidationError(f"{days} is listed more than once.")
        seen.add(days)


class DocumentMode(models.TextChoices):
    """
    How a church handles clearance documents (Build Spec §5).

    Chosen per church at provisioning because it reflects that church's own
    practice — some want files held for them, some already have a document store,
    and some keep paper in a locked cabinet.
    """

    STORE = "store", "Store securely in-system (encrypted)"
    LINK = "link", "Track status and link to our own external store"
    TRACK = "track", "Track status and dates only (hard copy retained)"


class Tenant(TenantMixin):
    """
    One church.

    ``schema_name`` (from TenantMixin) is the Postgres schema holding all of this
    church's data, and is immutable once created — the encrypted-field layer, the
    media directory layout and the subdomain all key off it.
    """

    name = models.CharField(max_length=200, help_text="The church's full legal or common name.")

    # Contact for the church, for the super-admin's reference only. Kept plaintext
    # here deliberately: this is the operator's own registry, not volunteer data,
    # and the public schema has no DEK to encrypt with.
    contact_name = models.CharField(max_length=150, blank=True)
    contact_email = models.EmailField(blank=True)

    document_mode = models.CharField(
        max_length=8,
        choices=DocumentMode.choices,
        default=DocumentMode.STORE,
        help_text="Changeable later by the platform super-admin.",
    )

    # --- Encryption key custody (PRD §5) ---------------------------------
    #
    # The DEK is stored only in wrapped form, under PLATFORM_MASTER_KEY, which
    # lives in the environment and never in the database. A dump of this table
    # therefore yields no usable key.
    dek_wrapped = models.BinaryField(editable=False, default=b"")
    dek_fingerprint = models.CharField(
        max_length=32,
        blank=True,
        editable=False,
        help_text="Non-reversible key identifier, for confirming a restored key matches.",
    )
    key_backup_confirmed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Set when the church's admin confirmed they saved the key offline.",
    )
    key_backup_confirmed_by = models.CharField(max_length=150, blank=True)

    # --- Reminder preferences (Build Spec §7) ----------------------------
    notifications_enabled = models.BooleanField(default=True)
    reminder_lead_days = models.CharField(
        max_length=64,
        default="60,30,7",
        validators=[validate_lead_days],
        help_text="Days before expiry to email the church's admins, comma separated.",
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Inactive churches keep their data but are refused at the door.",
    )
    notes = models.TextField(blank=True, help_text="Operator notes. Not visible to the church.")

    created_on = models.DateField(auto_now_add=True)

    # Creating a Tenant row creates and migrates its schema. Dropping one does NOT
    # drop the schema — a church's records are permanent, and removing them is a
    # deliberate manual act by the operator.
    auto_create_schema = True
    auto_drop_schema = False

    class Meta:
        ordering = ("name",)
        verbose_name = "church"
        verbose_name_plural = "churches"

    def __str__(self):
        return self.name

    def clean(self):
        super().clean()
        validate_schema_name(self.schema_name)

    # -- Key custody helpers ---------------------------------------------

    def assign_new_dek(self) -> bytes:
        """
        Generate this church's DEK and store it wrapped.

        Returns the raw key so the caller can show it to the admin exactly once.
        The raw key is never persisted.
        """
        dek = generate_dek()
        self.dek_wrapped = wrap_dek(dek)
        self.dek_fingerprint = key_fingerprint(dek)
        return dek

    @property
    def key_backup_pending(self) -> bool:
        """
        True until the church's admin has confirmed an offline copy of the key.

        While pending, ``ForceKeyBackupMiddleware`` funnels that church's admins to
        the backup page instead of the app.
        """
        return self.key_backup_confirmed_at is None

    def confirm_key_backup(self, by: str = "") -> None:
        self.key_backup_confirmed_at = timezone.now()
        self.key_backup_confirmed_by = (by or "")[:150]
        self.save(update_fields=["key_backup_confirmed_at", "key_backup_confirmed_by"])

    # -- Reminder helpers ------------------------------------------------

    @property
    def lead_days(self) -> list[int]:
        """Reminder lead times, descending, e.g. ``[60, 30, 7]``."""
        try:
            values = {int(p.strip()) for p in self.reminder_lead_days.split(",") if p.strip()}
        except ValueError:
            values = {60, 30, 7}
        return sorted((d for d in values if d > 0), reverse=True)

    @property
    def primary_domain(self):
        return self.domains.filter(is_primary=True).first() or self.domains.first()

    @property
    def url(self) -> str:
        domain = self.primary_domain
        return f"https://{domain.domain}/" if domain else ""


class Domain(DomainMixin):
    """
    A hostname that routes to a church.

    django-tenants resolves the request's Host header against this table; an
    unmatched hostname is refused (SHOW_PUBLIC_IF_NO_TENANT_FOUND is False).
    """

    class Meta:
        ordering = ("domain",)
