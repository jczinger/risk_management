"""
Tenant-schema base models and the audit trail.

Two hard rules from the spec live here rather than in each app:

* **Volunteer data is never hard-deleted** (Build Spec §3, acceptance criterion
  "cannot be hard-deleted through any UI or ORM path"). ``NoDeleteModel`` removes
  the delete path at the model *and* queryset level, so a stray
  ``Volunteer.objects.filter(...).delete()`` raises instead of destroying records
  a church may be legally required to retain permanently.
* **The audit trail is append-only** (Build Spec §6). ``AuditEvent`` refuses
  updates and deletes through every ORM path.
"""

from __future__ import annotations

import json

from django.db import models
from django.utils import timezone

from .audit import get_actor
from .fields import EncryptedTextField


class ProtectedDeletionError(Exception):
    """Raised when something attempts to hard-delete a permanent record."""


# ---------------------------------------------------------------------------
# Abstract bases
# ---------------------------------------------------------------------------


class TimeStampedModel(models.Model):
    """Adds creation/modification stamps. Both are plaintext metadata."""

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        abstract = True


class NoDeleteQuerySet(models.QuerySet):
    """QuerySet whose bulk-delete path is closed off."""

    def delete(self):
        raise ProtectedDeletionError(
            f"{self.model.__name__} records are retained permanently and cannot be "
            "deleted. Deactivate the record instead."
        )

    def _raw_delete(self, using):
        raise ProtectedDeletionError(
            f"{self.model.__name__} records are retained permanently and cannot be "
            "deleted."
        )


class NoDeleteModel(models.Model):
    """
    A record that can be deactivated but never destroyed.

    Covers the volunteer file and everything hanging off it. Cascades are blocked
    too: related models use ``on_delete=PROTECT`` so removing a parent cannot take
    a volunteer's history with it.
    """

    objects = NoDeleteQuerySet.as_manager()

    class Meta:
        abstract = True

    def delete(self, *args, **kwargs):
        raise ProtectedDeletionError(
            f"{type(self).__name__} records are retained permanently and cannot be "
            "deleted. Deactivate the record instead."
        )

    def hard_delete_for_tests(self, *args, **kwargs):
        """
        Escape hatch used only by the test suite's own teardown.

        Named so that its presence in application code is obvious in review.
        """
        return models.Model.delete(self, *args, **kwargs)


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


class AuditAction(models.TextChoices):
    CREATE = "create", "Created"
    UPDATE = "update", "Updated"
    DEACTIVATE = "deactivate", "Deactivated"
    REACTIVATE = "reactivate", "Reactivated"
    STATUS_CHANGE = "status_change", "Status changed"
    WAIVE = "waive", "Waived"
    # Its own action rather than a generic status change: reversing a waiver is exactly
    # the thing someone filters the trail for.
    WAIVER_REVERSED = "waiver_reversed", "Waiver reversed"
    UPLOAD = "upload", "Document uploaded"
    DOWNLOAD = "download", "Document viewed"
    LOGIN = "login", "Signed in"
    LOGIN_FAILED = "login_failed", "Sign-in failed"
    LOGOUT = "logout", "Signed out"
    CRC_RECORDED = "crc_recorded", "Criminal record check recorded"
    DISQUALIFIED = "disqualified", "Permanently disqualified"
    OVERRIDE = "override", "Leadership override recorded"
    KEY_BACKUP = "key_backup", "Encryption key backed up"
    NOTIFY = "notify", "Notification sent"
    SEED = "seed", "Template seeded"


class AuditEventQuerySet(models.QuerySet):
    """
    Append-only queryset.

    ``update()`` and ``delete()`` raise, so there is no ORM path to rewriting
    history — which is the whole point of an audit trail an insurer might read.
    """

    def update(self, **kwargs):
        raise ProtectedDeletionError("The audit trail is append-only; entries cannot be edited.")

    def delete(self):
        raise ProtectedDeletionError("The audit trail is append-only; entries cannot be deleted.")

    def _raw_delete(self, using):
        raise ProtectedDeletionError("The audit trail is append-only; entries cannot be deleted.")


class AuditEvent(models.Model):
    """
    One immutable entry per mutating action.

    Plaintext (so the viewer can filter and an insurer can read it): timestamp,
    actor name, action, entity type/id/label, and a short human summary.

    Encrypted (because a before/after diff of a volunteer record can contain an
    address, a phone number or a note): the structured ``detail`` payload.
    """

    occurred_at = models.DateTimeField(default=timezone.now, editable=False, db_index=True)

    # Denormalised actor: kept as text so the entry stays readable even if the
    # admin account is later removed.
    actor_user_id = models.IntegerField(null=True, blank=True, db_index=True)
    actor_display = models.CharField(max_length=150, default="system")
    actor_ip = models.CharField(max_length=45, blank=True)
    actor_user_agent = models.CharField(max_length=200, blank=True)

    action = models.CharField(max_length=32, choices=AuditAction.choices, db_index=True)

    # Generic pointer to the affected row, without a ContentType dependency —
    # ContentType lives in the public schema and its ids are not tenant-stable.
    entity_type = models.CharField(max_length=64, db_index=True)
    entity_id = models.CharField(max_length=64, blank=True, db_index=True)
    entity_label = models.CharField(max_length=200, blank=True)

    # One-line, PII-free description, e.g. "Criminal record check: Cleared".
    summary = models.CharField(max_length=255, blank=True)

    # JSON blob: {"before": {...}, "after": {...}} plus any extra context.
    detail = EncryptedTextField(blank=True, default="")

    objects = AuditEventQuerySet.as_manager()

    class Meta:
        ordering = ("-occurred_at", "-id")
        indexes = [
            models.Index(fields=["entity_type", "entity_id"]),
            models.Index(fields=["-occurred_at", "action"]),
        ]
        verbose_name = "audit event"
        verbose_name_plural = "audit trail"

    def __str__(self):
        return f"{self.occurred_at:%Y-%m-%d %H:%M} {self.actor_display} {self.action} {self.entity_type}"

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise ProtectedDeletionError(
                "The audit trail is append-only; an existing entry cannot be saved again."
            )
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ProtectedDeletionError("The audit trail is append-only; entries cannot be deleted.")

    @property
    def detail_data(self) -> dict:
        """Parsed ``detail``, or ``{}`` when absent/unparseable."""
        if not self.detail:
            return {}
        try:
            return json.loads(self.detail)
        except (ValueError, TypeError):
            return {}


# `record()` and `diff_summary()` live in apps.core.audit, alongside the actor
# context they depend on. They are re-exported here because this is where the
# AuditEvent model is, and callers reasonably look for them next to it.
from .audit import diff_summary, record  # noqa: E402,F401  (re-export)
