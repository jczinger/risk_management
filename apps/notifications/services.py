"""
Renewal reminders: what to raise, and the digest that carries them.

Build Spec §7 in full:

* Reminders go to the church's **admins**, never to volunteers.
* One email per church per day, batching everything due — three separate emails
  landing the same morning trains people to ignore them.
* At each configured lead time before expiry (60/30/7 by default, per-church
  configurable), plus once when something goes overdue.
* Every send is logged.

Idempotence comes from :class:`~apps.notifications.models.ReminderLog`: a reminder is
"raised" by inserting a row keyed on (instance, kind, lead days, expiry). If the row
already exists the reminder has been sent, so a job that runs twice mails nobody twice.
The expiry is part of the key, so renewing a requirement legitimately starts a fresh
cycle.
"""

from __future__ import annotations

import datetime
import logging

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.template.loader import render_to_string
from django.utils import timezone

from apps.core import audit
from apps.core.models import AuditAction
from apps.requirements.models import RequirementInstance, RequirementStatus

from .models import EmailLog, NotificationStatus, ReminderKind, ReminderLog
from .providers import EmailSendError, Message, get_provider

logger = logging.getLogger("vms.notifications")


# ---------------------------------------------------------------------------
# Choosing what to remind about
# ---------------------------------------------------------------------------


def find_due_reminders(tenant, as_of: datetime.date | None = None) -> list[dict]:
    """
    Work out which reminders are owed today for the current tenant schema.

    Returns dicts of ``{instance, kind, lead_days, due_date}``. Nothing is sent or
    recorded here — :func:`raise_reminder` does that — so this is safe to call from a
    preview screen.
    """
    as_of = as_of or timezone.localdate()
    lead_days = tenant.lead_days
    found: list[dict] = []

    # Only active volunteers matter. Someone who has stopped serving does not need
    # their lapsed refresher training chased.
    base = (
        RequirementInstance.objects.select_related("volunteer", "definition")
        .filter(volunteer__is_active=True, definition__is_active=True)
        .exclude(status__in=[RequirementStatus.NOT_APPLICABLE, RequirementStatus.WAIVED])
    )

    # --- Approaching expiry -------------------------------------------------
    #
    # One query for every lead time rather than one per lead time: each target date
    # maps back to the lead that produced it, and an instance can only ever land on
    # one target (a row has a single expiry or due date).
    targets = {as_of + datetime.timedelta(days=days): days for days in lead_days}
    approaching = base.filter(
        Q(status=RequirementStatus.COMPLETE, expires_on__in=targets)
        | Q(
            status__in=[RequirementStatus.NOT_STARTED, RequirementStatus.IN_PROGRESS],
            due_on__in=targets,
        )
    )
    for instance in approaching:
        matched = (
            instance.expires_on
            if instance.status == RequirementStatus.COMPLETE
            else instance.due_on
        )
        found.append(
            {
                "instance": instance,
                "kind": (
                    ReminderKind.TURNING_18
                    if instance.due_reason.startswith("Turned 18")
                    else ReminderKind.LEAD_TIME
                ),
                "lead_days": targets[matched],
                "due_date": instance.effective_due_date,
            }
        )

    # --- Just went overdue --------------------------------------------------
    #
    # Raised on the first day past the deadline only. The dashboard is what carries an
    # ongoing overdue item; re-mailing daily would be noise.
    yesterday = as_of - datetime.timedelta(days=1)
    newly_overdue = base.filter(
        Q(expires_on=yesterday) | Q(due_on=yesterday)
    ).exclude(status=RequirementStatus.COMPLETE, expires_on__gte=as_of)

    for instance in newly_overdue:
        found.append(
            {
                "instance": instance,
                "kind": ReminderKind.OVERDUE,
                "lead_days": 0,
                "due_date": instance.effective_due_date,
            }
        )

    return found


def raise_reminder(entry: dict) -> ReminderLog | None:
    """
    Claim a reminder, returning None if it was already raised.

    The unique constraint does the deduplication, so two workers racing on the same
    reminder cannot both send it.
    """
    instance = entry["instance"]
    try:
        with transaction.atomic():
            return ReminderLog.objects.create(
                instance=instance,
                kind=entry["kind"],
                lead_days=entry["lead_days"],
                expiry_at_send=entry["due_date"],
            )
    except IntegrityError:
        return None


# ---------------------------------------------------------------------------
# The digest
# ---------------------------------------------------------------------------


def admin_recipients() -> list[str]:
    """
    Every active **church-wide** admin's email address in the current schema.

    Addresses are encrypted at rest, so this decrypts them — the one moment they are in
    the clear, at send time, exactly as PRD §5 specifies.

    Restricted to unscoped administrators when access levels came in (2026-07-29), and
    that was a leak rather than a preference. The digest is *one shared body* built from a
    church-wide query, so left alone it would have mailed every department admin a list
    naming every volunteer at the church with anything overdue — straight through the new
    boundary, invisible in the UI, and recorded permanently in ``EmailLog``.

    The owner chose this over per-admin scoped digests. The cost is that a department
    admin gets no unprompted nudge and has to look at their dashboard; the benefit is that
    the reminder de-duplication key stays untouched. That key is
    ``(instance, kind, lead_days, expiry_at_send)``, so a volunteer serving in two
    departments would have been claimed once and silently reported to only one of the two
    admins who needed to know — a subtle wrong answer in place of a plain absence.
    """
    from apps.accounts.models import User
    from apps.core.models import UserAccessGrant

    unscoped = UserAccessGrant.objects.filter(
        access_level__is_scoped=False, access_level__is_active=True
    ).values_list("user_id", flat=True)

    return [
        u.email
        for u in User.objects.filter(is_active=True, pk__in=list(unscoped))
        if u.email
    ]


def send_digest(
    tenant,
    entries: list[dict],
    *,
    as_of: datetime.date | None = None,
    review_backlog: dict | None = None,
) -> EmailLog | None:
    """
    Send one church's daily reminder digest and log it.

    Returns the :class:`EmailLog` row, or None when there was nothing to send or the
    church has notifications turned off.

    ``review_backlog`` carries the count of entries awaiting a primary admin's
    affirmation. It changes the early return below: a church with nothing due but a
    month-old backlog gets no reminders and *would* therefore get no email at all — which
    is exactly the church that needs an unprompted nudge, because an unaffirmed entry
    already counts as compliant and so shows up nowhere else.
    """
    as_of = as_of or timezone.localdate()
    review_backlog = review_backlog or {}

    if not entries and not review_backlog.get("stale"):
        return None
    if not tenant.notifications_enabled:
        logger.info("Notifications disabled for %s; skipping digest", tenant.schema_name)
        return None

    recipients = admin_recipients()
    if not recipients:
        logger.warning("No active admin addresses for %s; digest not sent", tenant.schema_name)
        return None

    overdue = [e for e in entries if e["kind"] == ReminderKind.OVERDUE]
    upcoming = sorted(
        (e for e in entries if e["kind"] != ReminderKind.OVERDUE),
        key=lambda e: (e["lead_days"], e["instance"].volunteer.sort_name),
    )

    context = {
        "church_name": tenant.name,
        "as_of": as_of,
        "overdue": overdue,
        "upcoming": upcoming,
        "total": len(entries),
        "dashboard_url": tenant.url,
        "review": review_backlog,
    }
    subject = _subject(
        tenant,
        overdue_count=len(overdue),
        upcoming_count=len(upcoming),
        review_count=review_backlog.get("pending", 0),
    )
    body_text = render_to_string("notifications/digest.txt", context)
    body_html = render_to_string("notifications/digest.html", context)

    log = EmailLog.objects.create(
        recipients=", ".join(recipients),
        subject=subject,
        body=body_text,
        recipient_count=len(recipients),
        # Still the reminder count, so the email log keeps meaning what it always has. The
        # review backlog is a line in the body, not another kind of item.
        item_count=len(entries),
        status=NotificationStatus.QUEUED,
    )

    provider = get_provider()
    try:
        provider.send(
            Message(
                subject=subject,
                body_text=body_text,
                body_html=body_html,
                recipients=recipients,
            )
        )
    except EmailSendError as exc:
        log.mark_failed(str(exc), provider=provider.name)
        logger.error("Digest send failed for %s: %s", tenant.schema_name, exc)
        audit.record(
            AuditAction.NOTIFY,
            "EmailLog",
            entity_id=log.pk,
            summary=f"Reminder digest FAILED ({len(entries)} items)",
            detail={"error": str(exc), "provider": provider.name},
            actor=audit.Actor.system("reminder job"),
        )
        return log

    log.mark_sent(provider=provider.name)
    audit.record(
        AuditAction.NOTIFY,
        "EmailLog",
        entity_id=log.pk,
        summary=(
            f"Reminder digest sent to {len(recipients)} administrator(s) "
            f"covering {len(entries)} requirement(s)"
        ),
        detail={
            "provider": provider.name,
            "overdue": len(overdue),
            "upcoming": len(upcoming),
        },
        actor=audit.Actor.system("reminder job"),
    )
    logger.info(
        "Digest sent schema=%s recipients=%d items=%d",
        tenant.schema_name,
        len(recipients),
        len(entries),
    )
    return log


def _subject(tenant, *, overdue_count: int, upcoming_count: int, review_count: int = 0) -> str:
    """A subject line that says what is inside, so it survives a crowded inbox."""
    parts = []
    if overdue_count:
        parts.append(f"{overdue_count} overdue")
    if upcoming_count:
        parts.append(f"{upcoming_count} coming due")
    # Named rather than left to fall through to "update": when the backlog is the only
    # reason this email exists, a subject saying "update" buries the one thing it is for.
    if review_count and not parts:
        parts.append(f"{review_count} awaiting your review")
    detail = ", ".join(parts) or "update"
    return f"[{tenant.name}] Volunteer screening: {detail}"


def process_tenant_reminders(tenant, as_of: datetime.date | None = None) -> dict:
    """
    The nightly reminder pass for one church.

    Finds what is owed, claims each reminder, and sends a single digest for whatever was
    newly claimed.
    """
    as_of = as_of or timezone.localdate()
    candidates = find_due_reminders(tenant, as_of)

    claimed = []
    for entry in candidates:
        if raise_reminder(entry) is not None:
            claimed.append(entry)

    from apps.review.services import pending_summary

    backlog = pending_summary()
    log = send_digest(tenant, claimed, as_of=as_of, review_backlog=backlog)

    return {
        "candidates": len(candidates),
        "claimed": len(claimed),
        "review_pending": backlog["pending"],
        "sent": bool(log and log.status == NotificationStatus.SENT),
        "email_log_id": log.pk if log else None,
    }
