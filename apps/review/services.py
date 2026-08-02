"""
Affirming an entry, or sending it back.

Unlike :mod:`apps.review.recording`, this module *may* import from
:mod:`apps.requirements` and :mod:`apps.documents` — reverting an entry means calling back
into the code that made it. Keeping the two modules apart is what stops that becoming a
cycle: the writers import ``recording``, and only ``recording``.

Two rules run before either decision:

1. The item must still be open.
2. The reviewer must hold access to the whole church. A department admin cannot affirm
   their own work, and cannot affirm a colleague's either — the point is a second pair of
   eyes with wider responsibility.

Then, on a send-back, **each kind checks for itself whether the record has moved on**, and
skips the revert if it has. That check cannot be shared, because "moved on" means something
different every time: a completion should still read complete, a waiver still waived, a
document still current, a check still un-superseded. It matters because without it a
send-back clicked after somebody else changed the record would roll back state the rejected
entry no longer owns.

What send-back *cannot* do is as important as what it can. A recorded document survives; a
permanent disqualification survives; an override survives. Each is permanent by design
elsewhere in this codebase, and a review gate does not get to quietly reverse them. So
every handler returns a ``kept`` list naming what still stands, and the screen says it —
rather than leaving a reviewer to assume a rollback that did not happen.
"""

from __future__ import annotations

import logging

from django.core.exceptions import ValidationError
from django.db import transaction

from apps.core import audit
from apps.core.access import is_unscoped
from apps.core.models import AuditAction

from .models import ReviewItem, ReviewKind

logger = logging.getLogger("vms.review")


class ReviewError(ValidationError):
    """Something about this review cannot proceed."""


# ---------------------------------------------------------------------------
# Who may review
# ---------------------------------------------------------------------------


def may_review(user, item: ReviewItem) -> tuple[bool, str]:
    """
    Whether ``user`` may decide ``item``, and why not if they may not.

    Two rules, and the second has an escape hatch that needs stating. Self-review is
    refused — but only *while somebody else could do it*. A department admin promoted to
    Primary Admin keeps their pending items, deliberately (auto-affirming a backlog
    because somebody changed job title would defeat the whole feature), and if they are now
    the only unscoped admin left then refusing would deadlock the church with no way to
    clear its own queue. So in that one case it is allowed and the audit entry says so.
    """
    if not is_unscoped(user):
        return False, "Only an administrator with access to the whole church can review an entry."

    if item.recorded_by_user_id and item.recorded_by_user_id == getattr(user, "pk", None):
        if _another_reviewer_exists(exclude_user_id=user.pk):
            return False, "You cannot affirm an entry you recorded yourself."
        # Reachable only via promotion. Allowed, and recorded as such.
        return True, ""

    return True, ""


def _another_reviewer_exists(*, exclude_user_id) -> bool:
    """
    Whether somebody else could affirm this.

    Moved to :func:`apps.core.access.another_unscoped_admin_exists` on 2026-08-02 and
    kept here as a name, because the self-screening rule asks the identical question
    and two copies of "is there another responsible adult" would eventually answer
    differently.
    """
    from apps.core.access import another_unscoped_admin_exists

    return another_unscoped_admin_exists(exclude_user_id=exclude_user_id)


def _require_reviewer(user, item):
    allowed, why = may_review(user, item)
    if not allowed:
        raise ReviewError(why)
    if not item.is_open:
        raise ReviewError(
            f"This entry was already {item.get_status_display().lower()}."
        )


# ---------------------------------------------------------------------------
# Affirm
# ---------------------------------------------------------------------------


@transaction.atomic
def affirm(item: ReviewItem, *, by) -> ReviewItem:
    """Confirm the entry is correct. Changes no data — only the sign-off."""
    _require_reviewer(by, item)

    self_affirmed = item.recorded_by_user_id == getattr(by, "pk", None)
    item.affirm(by=by)

    audit.record(
        AuditAction.REVIEW_AFFIRMED,
        item.entity_type,
        entity_id=item.entity_id,
        entity_label=item.entity_label,
        summary=(
            "Affirmed by the recording administrator; no other church-wide "
            "administrator exists"
            if self_affirmed
            else f"Affirmed ({item.get_kind_display()})"
        ),
    )
    logger.info("Review affirmed item=%s by=%s", item.pk, getattr(by, "pk", None))
    return item


# ---------------------------------------------------------------------------
# Send back
# ---------------------------------------------------------------------------


@transaction.atomic
def send_back(item: ReviewItem, *, by, reason: str) -> dict:
    """
    Reject the entry, and undo what can honestly be undone.

    Returns ``{"reverted": bool, "kept": [str, ...]}`` — ``kept`` naming anything the
    send-back could not reverse, so the caller can tell the reviewer plainly rather than
    letting them assume it was all rolled back.
    """
    _require_reviewer(by, item)
    if not (reason or "").strip():
        raise ReviewError({"reason": "Say why this entry is being sent back."})

    handler = {
        ReviewKind.REQUIREMENT_COMPLETION: _send_back_completion,
        ReviewKind.DOCUMENT: _send_back_document,
        ReviewKind.CRC: _send_back_crc,
        ReviewKind.WAIVER: _send_back_waiver,
        ReviewKind.OVERRIDE: _send_back_override,
    }[item.kind]

    outcome = handler(item, by=by, reason=reason)

    item.send_back(by=by, reason=reason)
    audit.record(
        AuditAction.REVIEW_SENT_BACK,
        item.entity_type,
        entity_id=item.entity_id,
        entity_label=item.entity_label,
        # The reason goes in the summary, not only the detail. The detail is stored but
        # never displayed, so a reason kept only there would be invisible to the very
        # person it is written for. Same reasoning as reverse_waiver.
        summary=f"Sent back: {reason}"[:255],
        detail={"reason": reason, "kept": outcome.get("kept", [])},
    )
    logger.info("Review sent back item=%s by=%s", item.pk, getattr(by, "pk", None))
    return outcome


def _instance_from(item: ReviewItem):
    """The requirement instance this item covers, directly or through ``affected``."""
    from apps.requirements.models import RequirementInstance

    for entity_type, entity_id in (
        (item.entity_type, item.entity_id),
        (item.affected_entity_type, item.affected_entity_id),
    ):
        if entity_type == "RequirementInstance" and entity_id:
            return RequirementInstance.objects.filter(pk=entity_id).first()
    return None


def _restore_from_snapshot(instance, item) -> None:
    """
    Put the dates back, then let the existing rules decide the status.

    Order matters and mirrors ``reverse_waiver``: restore what was recorded, then
    ``recompute()``, then ``refresh_dependents()``. Never write a status from the snapshot
    verbatim — the nightly sweep may have moved the requirement to overdue while the entry
    sat unverified, and the engine's own rules are what should decide.
    """
    import datetime

    from apps.requirements.services import _status_after_reversal, refresh_dependents

    def as_date(value):
        return datetime.date.fromisoformat(value) if value else None

    snapshot = item.before_state or {}
    instance.completed_on = as_date(snapshot.get("completed_on"))
    instance.expires_on = as_date(snapshot.get("expires_on"))
    instance.due_on = as_date(snapshot.get("due_on"))
    instance.due_reason = snapshot.get("due_reason", "")
    instance.started_on = as_date(snapshot.get("started_on")) or instance.started_on

    # Derived from what survived, not assumed to be "in progress". The button reads
    # "Renew" on an already-complete recurring requirement, so a naive drop to IN_PROGRESS
    # would destroy the *earlier valid* completion rather than the rejected renewal.
    instance.status = _status_after_reversal(instance)
    instance.save(
        update_fields=[
            "status",
            "started_on",
            "completed_on",
            "expires_on",
            "due_on",
            "due_reason",
            "updated_at",
        ]
    )
    instance.recompute()
    refresh_dependents(instance)


def _send_back_completion(item, *, by, reason) -> dict:
    from apps.requirements.models import RequirementStatus

    instance = _instance_from(item)
    if instance is None:
        return {"reverted": False, "kept": ["the requirement could not be found"]}

    # Staleness check. Every handler in this module makes its own, because "has this moved
    # on?" means something different for each: a completion should still read complete, a
    # waiver still waived, a document still current, a check still un-superseded. Skipping
    # the revert here is what stops a send-back rolling back state the rejected entry no
    # longer owns.
    if instance.status != RequirementStatus.COMPLETE:
        return {
            "reverted": False,
            "kept": ["the requirement has already changed since this entry was recorded"],
        }

    _restore_from_snapshot(instance, item)
    return {"reverted": True, "kept": []}


def _send_back_document(item, *, by, reason) -> dict:
    """
    The document survives; the completion it caused does not.

    ``Document`` is a ``NoDeleteModel`` and the bytes are permanent by design — the record
    that a piece of paper was presented is itself part of the trail. So it stops being
    *current*, which takes it off the working page (which filters on ``is_current``) while
    leaving it in the printed file (which does not). That pair of behaviours is the right
    one: the day-to-day screen should not present rejected evidence, and the audit record
    should not lose it.
    """
    from apps.documents.models import Document

    kept = []
    document = Document.objects.filter(pk=item.entity_id).first()
    if document is not None and document.is_current:
        document.is_current = False
        document.save(update_fields=["is_current", "updated_at"])
        kept.append("the document itself is retained, marked as not current")

    instance = _instance_from(item)
    reverted = False
    if instance is not None:
        _restore_from_snapshot(instance, item)
        reverted = True

    return {"reverted": reverted, "kept": kept}


def _send_back_crc(item, *, by, reason) -> dict:
    """
    A retraction, never a reversal — and only of a clearance.

    Every door this could try to open is already bolted elsewhere, deliberately:
    ``set_screening_block`` refuses to move off ``DISQUALIFIED``;
    ``DisqualifyingConviction.delete()`` raises; ``DiscretionaryOverride.save()`` raises on
    any second write; ``RoleAssignment.end()`` has no inverse. So the rule is two-tier.

    **Allowed** — retract a clearance, when the check is still the current one and carries
    no convictions and no overrides. That is the wrong-volunteer correction, and it is
    reversible without touching anything permanent.

    **Refused** — anything involving a disqualification, a conviction or an override. The
    owner accepted this consequence explicitly when they chose to let a department admin
    record a disqualification: affirmation cannot be honoured there, and sending it back
    records a dispute rather than undoing anything. What the caller gets back is the list
    of things that stand, so the screen can say so instead of implying a rollback.
    """
    from apps.org.models import ScreeningBlock
    from apps.requirements.models import CRCRecord

    kept = []

    if item.entity_type == "DisqualifyingConviction":
        ended = (item.before_state or {}).get("ended_assignments") or []
        kept.append("the convictions are permanently retained and cannot be removed")
        # The volunteer's state *now*, not what it was before the entry — the question is
        # what still stands, not what changed.
        if item.volunteer.screening_block == ScreeningBlock.DISQUALIFIED:
            kept.append(
                "the permanent disqualification stands — the Plan to Protect policy "
                "provides no route back, here or anywhere"
            )
        if ended:
            kept.append(
                f"{len(ended)} role assignment(s) ended by this decision "
                f"({', '.join(ended)}) must be re-created by hand if it was wrong"
            )
        return {"reverted": False, "kept": kept}

    record = CRCRecord.objects.filter(pk=item.entity_id).first()
    if record is None:
        return {"reverted": False, "kept": ["the check could not be found"]}

    if record.convictions.exists() or record.overrides.exists():
        return {
            "reverted": False,
            "kept": [
                "this check carries recorded convictions or a leadership decision, so it "
                "cannot be retracted — record a corrective check instead"
            ],
        }
    if record.superseded_by_id is not None:
        return {
            "reverted": False,
            "kept": ["a later check has already replaced this one"],
        }

    volunteer = record.volunteer
    instance = _instance_from(item)
    if instance is not None:
        _restore_from_snapshot(instance, item)

    # Put the previous check back as the operative one, so the file reads truthfully about
    # which check is current rather than showing none at all.
    previous_id = item.before_state.get("superseded_by_id")
    if previous_id:
        CRCRecord.objects.filter(pk=previous_id).update(superseded_by=None)

    # Only a block this record set, and never a disqualification (the model refuses that
    # anyway).
    if volunteer.screening_block == ScreeningBlock.CRC_NOT_CLEAR:
        volunteer.set_screening_block(ScreeningBlock.NONE)

    audit.record(
        AuditAction.CRC_NOT_AFFIRMED,
        "CRCRecord",
        entity_id=record.pk,
        entity_label=volunteer.display_name,
        summary=f"Criminal record check retracted on review: {reason}"[:255],
        detail={"reason": reason, "result": record.result},
    )
    kept.append("the check itself is retained, marked as retracted")
    return {"reverted": True, "kept": kept}


def _send_back_waiver(item, *, by, reason) -> dict:
    """
    Reuses ``reverse_waiver``, which already does almost all of this.

    It requires a reason, clears the waiver fields, derives the status from what survived,
    recomputes, refreshes dependents, and writes ``WAIVER_REVERSED`` with the reason in the
    summary. Two audit rows result — one per question the trail is asked — which is this
    codebase's stated precedent rather than duplication.
    """
    import datetime

    from apps.requirements.services import reverse_waiver

    instance = _instance_from(item)
    if instance is None:
        return {"reverted": False, "kept": ["the requirement could not be found"]}

    from apps.requirements.models import RequirementStatus

    if instance.status != RequirementStatus.WAIVED:
        return {
            "reverted": False,
            "kept": ["the waiver has already been reversed or replaced"],
        }

    snapshot = item.before_state or {}
    due_on = snapshot.get("due_on")
    restore_due = (
        (datetime.date.fromisoformat(due_on) if due_on else None, snapshot.get("due_reason", ""))
        if snapshot
        else None
    )

    reverse_waiver(
        instance,
        reason=reason,
        reversed_by=by.display_name if by else "administrator",
        restore_due=restore_due,
    )
    return {"reverted": True, "kept": []}


def _send_back_override(item, *, by, reason) -> dict:
    """
    An override cannot be erased — its own error message says so: "Record a new decision
    instead."

    So sending one back records the dispute and hands the decision to the reviewer, who
    must record their own. Deliberately does **not** auto-restore the assignments a
    declined decision ended: ``RoleAssignment.end()`` has no inverse, and silently
    re-creating rows would be inventing history. They are named instead.
    """
    kept = ["the recorded decision is permanently retained — record your own to supersede it"]
    ended = (item.before_state or {}).get("ended_assignments") or []
    if ended:
        kept.append(
            f"{len(ended)} role assignment(s) ended by this decision "
            f"({', '.join(ended)}) must be re-created by hand if it was wrong"
        )
    return {"reverted": False, "kept": kept}


# ---------------------------------------------------------------------------
# Queue reads
# ---------------------------------------------------------------------------


def pending_summary() -> dict:
    """
    Counts for the dashboard tile and the digest line.

    Deliberately not in the context processor: that would be a query on every page render,
    including the sign-in page, for a number that belongs on one screen.
    """
    from apps.core.models import AccessLevel

    pending = ReviewItem.objects.pending()
    return {
        "pending": pending.count(),
        "stale": ReviewItem.objects.stale().count(),
        "oldest": pending.order_by("created_at").values_list("created_at", flat=True).first(),
        # A church with nobody on a limited level can never have anything pending, so the
        # tile should not sit there reading zero forever.
        "has_scoped_admins": AccessLevel.objects.filter(
            is_scoped=True, is_active=True, grants__isnull=False
        ).exists(),
    }
