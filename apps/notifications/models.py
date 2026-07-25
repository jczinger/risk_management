"""
Renewal reminders.

Build Spec §7: admins (never volunteers) get an email at each configured lead time
before a requirement expires, plus one when it goes overdue. Everything is batched
into a single daily digest per church, and every send is logged.

:class:`ReminderLog` is what makes "every send logged" true and what makes the
scheduler idempotent — the nightly job asks "have we already sent this reminder for
this instance at this lead time?" rather than tracking state elsewhere. So a job that
runs twice, or a worker that retries, does not re-mail anybody.
"""

from __future__ import annotations

from django.db import models
from django.utils import timezone

from apps.core.fields import EncryptedTextField
from apps.requirements.models import RequirementInstance


class ReminderKind(models.TextChoices):
    LEAD_TIME = "lead_time", "Approaching expiry"
    OVERDUE = "overdue", "Overdue"
    TURNING_18 = "turning_18", "Criminal record check due on turning 18"


class NotificationStatus(models.TextChoices):
    QUEUED = "queued", "Queued"
    SENT = "sent", "Sent"
    FAILED = "failed", "Failed"


class ReminderLog(models.Model):
    """
    One row per (requirement instance, reminder kind, lead time) ever raised.

    The unique constraint is the deduplication: a given reminder for a given
    requirement at a given lead time can only exist once. When a requirement is
    renewed its expiry moves, so the next cycle's reminders are distinguished by
    ``expiry_at_send`` and go out normally.
    """

    instance = models.ForeignKey(
        RequirementInstance, on_delete=models.CASCADE, related_name="reminders"
    )
    kind = models.CharField(max_length=16, choices=ReminderKind.choices)
    #: Days before expiry this reminder represents. 0 for the overdue notice.
    lead_days = models.PositiveSmallIntegerField(default=0)
    #: The expiry (or deadline) in force when the reminder was raised. Part of the
    #: uniqueness key so a renewed requirement starts a fresh reminder cycle.
    expiry_at_send = models.DateField(null=True, blank=True)

    raised_on = models.DateField(default=timezone.localdate, db_index=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        ordering = ("-created_at",)
        constraints = [
            models.UniqueConstraint(
                fields=["instance", "kind", "lead_days", "expiry_at_send"],
                name="unique_reminder_per_cycle",
            )
        ]
        indexes = [models.Index(fields=["raised_on", "kind"])]

    def __str__(self):
        return f"{self.get_kind_display()} ({self.lead_days}d) for instance {self.instance_id}"


class EmailLog(models.Model):
    """
    Every message the system attempted to send.

    The recipient address and the body are encrypted — a dump must not reveal who was
    emailed or what was said. The *metadata* (when, what kind, how many items,
    success or failure) is plaintext so an admin can see the delivery history and
    diagnose a problem without decrypting anything.
    """

    sent_at = models.DateTimeField(default=timezone.now, db_index=True)
    status = models.CharField(
        max_length=8, choices=NotificationStatus.choices, default=NotificationStatus.QUEUED
    )

    # Encrypted — a recipient list is personal information (PRD §5).
    recipients = EncryptedTextField(default="", help_text="Comma-separated. Encrypted.")
    subject = EncryptedTextField(default="", help_text="Encrypted.")
    body = EncryptedTextField(default="", help_text="Encrypted.")

    # Plaintext metadata.
    recipient_count = models.PositiveSmallIntegerField(default=0)
    item_count = models.PositiveSmallIntegerField(
        default=0, help_text="How many requirements this digest covered."
    )
    provider = models.CharField(max_length=32, blank=True)
    error = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ("-sent_at",)
        verbose_name = "email log entry"
        verbose_name_plural = "email log"

    def __str__(self):
        return f"{self.sent_at:%Y-%m-%d %H:%M} {self.get_status_display()} ({self.recipient_count} recipients)"

    def mark_sent(self, provider: str = "") -> None:
        self.status = NotificationStatus.SENT
        self.provider = provider
        self.sent_at = timezone.now()
        self.save(update_fields=["status", "provider", "sent_at"])

    def mark_failed(self, error: str, provider: str = "") -> None:
        self.status = NotificationStatus.FAILED
        self.provider = provider
        self.error = (error or "")[:500]
        self.save(update_fields=["status", "provider", "error"])
