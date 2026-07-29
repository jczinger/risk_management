"""
Requirement engine operations.

Views and the nightly job both go through here, so the policy rules exist in exactly
one place. The rules that matter most:

* A requirement's applicability is recomputed from the volunteer's *current* roles
  and age, but an instance is never deleted — it becomes ``not_applicable`` with a
  stated reason, so "this was once required and satisfied" survives a role change.
* The under-18 exemption and the turning-18 activation are two halves of one rule and
  share :meth:`Volunteer.is_adult_on`, so they cannot disagree.
* An **automatic disqualifier is terminal**. :func:`record_convictions` is the only
  thing that sets it, and nothing anywhere reverses it.
"""

from __future__ import annotations

import datetime
import logging

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from apps.core import audit
from apps.core.models import AuditAction
from apps.org.models import ScreeningBlock, Volunteer

from .models import (
    TURNING_18_CRC_DEADLINE_MONTHS,
    AgeRule,
    CRCNotClearOutcome,
    CRCRecord,
    CRCResult,
    DisqualifyingConviction,
    DiscretionaryOverride,
    RequirementDefinition,
    RequirementInstance,
    RequirementStatus,
    add_months_to,
)

logger = logging.getLogger("vms.requirements")

REASON_NO_ROLE = "No current role requires this"
REASON_UNDER_18 = "Under 18 — no criminal record check required"
REASON_NO_BIRTH_DATE = "Date of birth not recorded — age rule cannot be applied"
REASON_PREREQUISITE = "Not required until {name} is complete"


# ---------------------------------------------------------------------------
# Keeping a volunteer's requirement list correct
# ---------------------------------------------------------------------------


@transaction.atomic
def sync_volunteer_requirements(
    volunteer: Volunteer,
    *,
    as_of: datetime.date | None = None,
    quiet: bool = False,
) -> dict:
    """
    Reconcile one volunteer's requirement instances with what currently applies.

    Called after a role assignment changes, after a date of birth is recorded, and
    nightly for everyone. Idempotent: running it twice changes nothing the second
    time.

    ``quiet`` suppresses audit entries — used by the nightly sweep, which would
    otherwise write an entry per volunteer per night for no change.
    """
    as_of = as_of or timezone.localdate()
    roles = list(volunteer.active_roles)
    definitions = (
        RequirementDefinition.objects.active()
        .select_related("must_follow")
        .prefetch_related("roles")
    )
    existing = {i.definition_id: i for i in volunteer.requirement_instances.all()}

    created, updated, retired = 0, 0, 0

    for definition in definitions:
        instance = existing.get(definition.pk)
        applies = definition.applies_to_volunteer(volunteer, roles=roles)

        if not applies:
            # Stopped applying. Keep any completed history untouched; retire anything
            # still outstanding so it stops showing as owed.
            if instance and instance.status in RequirementStatus.outstanding_values():
                instance.status = RequirementStatus.NOT_APPLICABLE
                instance.not_applicable_reason = REASON_NO_ROLE
                instance.due_on = None
                instance.due_reason = ""
                instance.save(
                    update_fields=[
                        "status",
                        "not_applicable_reason",
                        "due_on",
                        "due_reason",
                        "updated_at",
                    ]
                )
                retired += 1
            continue

        age_exempt = definition.is_age_exempt(volunteer, as_of)
        # Age exemption takes precedence: it is a rule about the person, the gate is a
        # rule about the paperwork. An under-18 reads "Applies to adults (18+) only",
        # which is the more useful thing to be told.
        blocked_by = None if age_exempt else definition.unmet_prerequisite(volunteer)

        if instance is None:
            instance = RequirementInstance(volunteer=volunteer, definition=definition)
            if age_exempt:
                instance.status = RequirementStatus.NOT_APPLICABLE
                instance.not_applicable_reason = _age_exempt_reason(volunteer, definition)
            elif blocked_by is not None:
                instance.status = RequirementStatus.NOT_APPLICABLE
                instance.not_applicable_reason = _prerequisite_reason(blocked_by)
            instance.save()
            created += 1
            if not quiet:
                audit.record(
                    AuditAction.CREATE,
                    "RequirementInstance",
                    entity_id=instance.pk,
                    entity_label=f"{volunteer.display_name} — {definition.name}",
                    summary=f"Requirement added: {instance.get_status_display()}",
                    detail={"reason": instance.not_applicable_reason or "role requires it"},
                )
            continue

        changed = _reconcile_existing(
            instance, volunteer, definition, age_exempt, blocked_by, as_of, quiet
        )
        updated += int(changed)

    return {"created": created, "updated": updated, "retired": retired}


def _age_exempt_reason(volunteer: Volunteer, definition: RequirementDefinition) -> str:
    if not volunteer.has_birth_date:
        return REASON_NO_BIRTH_DATE
    return REASON_UNDER_18 if definition.is_crc else "Applies to adults (18+) only"


def _prerequisite_reason(blocked_by: RequirementInstance) -> str:
    """Why a gated requirement is not applicable yet. Truncated to the column."""
    return REASON_PREREQUISITE.format(name=blocked_by.definition.name)[:200]


def _prerequisite_deadline(
    volunteer: Volunteer, definition: RequirementDefinition
) -> tuple[datetime.date | None, str]:
    """
    When a gated requirement falls due, counted from its prerequisite's completion.

    Returns ``(None, "")`` when there is no date to count from. That happens when the
    prerequisite was waived or ruled not applicable rather than completed, and when the
    dependent has no interval of its own and no explicit offset. No date is invented in
    either case — the requirement simply becomes outstanding with no deadline, which is
    how most onboarding requirements already behave.
    """
    months = definition.prerequisite_offset_months
    if not months:
        return None, ""

    prior = (
        volunteer.requirement_instances.select_related("definition")
        .filter(definition_id=definition.must_follow_id)
        .first()
    )
    if prior is None or not prior.completed_on:
        return None, ""

    due_on = add_months_to(prior.completed_on, months)
    reason = (
        f"{prior.definition.name} was completed on {prior.completed_on:%-d %b %Y}; "
        f"this falls due {months} months later."
    )
    return due_on, reason[:200]


def _hold_not_applicable(
    instance: RequirementInstance,
    reason: str,
) -> bool:
    """Park an outstanding instance as not-applicable, clearing any deadline with it."""
    instance.status = RequirementStatus.NOT_APPLICABLE
    instance.not_applicable_reason = reason
    instance.due_on = None
    instance.due_reason = ""
    instance.save(
        update_fields=[
            "status",
            "not_applicable_reason",
            "due_on",
            "due_reason",
            "updated_at",
        ]
    )
    return True


def _reconcile_existing(
    instance: RequirementInstance,
    volunteer: Volunteer,
    definition: RequirementDefinition,
    age_exempt: bool,
    blocked_by: RequirementInstance | None,
    as_of: datetime.date,
    quiet: bool,
) -> bool:
    """Move an existing instance between applicable and not-applicable states."""
    # Newly exempt (age recorded for the first time, revealing they are a minor).
    if age_exempt and instance.status in RequirementStatus.outstanding_values():
        return _hold_not_applicable(instance, _age_exempt_reason(volunteer, definition))

    # Newly gated — the prerequisite was un-completed, or the dependency was only just
    # configured. Completed history is left alone, as with the age rule.
    if blocked_by is not None and instance.status in RequirementStatus.outstanding_values():
        return _hold_not_applicable(instance, _prerequisite_reason(blocked_by))

    # Still waiting on a prerequisite. Without this the branch below would treat a
    # gated instance as merely age-exempt-no-longer and switch it straight on.
    if blocked_by is not None:
        return False

    # No longer exempt: they have turned 18, a role now requires this after all, or the
    # prerequisite has been satisfied.
    if not age_exempt and instance.status == RequirementStatus.NOT_APPLICABLE:
        return _activate(instance, volunteer, definition, as_of, quiet)

    # Already active and applicable. Nothing structural to change, but a gated
    # requirement's deadline is *derived* from the prerequisite's completion date, and
    # a derived value goes stale when its source is corrected. Re-deriving here means a
    # fixed-up orientation date reaches the refresher on the next sync rather than
    # leaving a deadline nobody can explain.
    if (
        definition.is_gated
        and not instance.completed_on
        and instance.status in RequirementStatus.outstanding_values()
    ):
        return _refresh_prerequisite_deadline(instance, volunteer, definition)

    # The nightly recompute handles the date-driven status transitions.
    return False


def _refresh_prerequisite_deadline(
    instance: RequirementInstance,
    volunteer: Volunteer,
    definition: RequirementDefinition,
) -> bool:
    """Keep a released gate's deadline in step with the date it was derived from."""
    deadline, reason = _prerequisite_deadline(volunteer, definition)
    if deadline is None or deadline == instance.due_on:
        return False

    # A requirement can be under two clocks — a turning-18 deadline as well as this
    # one. The earlier governs, which is what effective_due_date already assumes.
    if instance.due_on and instance.due_on < deadline:
        return False

    instance.due_on = deadline
    instance.due_reason = reason
    instance.save(update_fields=["due_on", "due_reason", "updated_at"])
    return True


def _activate(
    instance: RequirementInstance,
    volunteer: Volunteer,
    definition: RequirementDefinition,
    as_of: datetime.date,
    quiet: bool,
) -> bool:
    """
    Turn a not-applicable requirement back on.

    For the criminal record check on turning 18 this attaches the policy's three-month
    deadline, counted from the 1st of the birth month of their 18th year
    (Build Spec §4.4).

    For a gated requirement it attaches a deadline counted from the *prerequisite's*
    completion — refresher training a year after the orientation, not a year after the
    gate happened to open.
    """
    instance.status = RequirementStatus.NOT_STARTED
    previous_reason = instance.not_applicable_reason
    instance.not_applicable_reason = ""

    summary = "Requirement now applies"
    if definition.is_crc and definition.age_rule == AgeRule.ADULTS_ONLY:
        trigger = volunteer.eighteenth_birthday_trigger_date()
        if trigger:
            instance.due_on = add_months_to(trigger, TURNING_18_CRC_DEADLINE_MONTHS)
            instance.due_reason = (
                f"Turned 18 (from {trigger:%B %Y}); the policy allows three months to "
                "submit a criminal record check."
            )
            summary = f"Criminal record check activated on turning 18 — due {instance.due_on}"
    elif definition.is_gated:
        deadline, reason = _prerequisite_deadline(volunteer, definition)
        if deadline:
            instance.due_on = deadline
            instance.due_reason = reason
            summary = f"{definition.must_follow.name} completed — due {deadline}"
        else:
            summary = f"{definition.must_follow.name} satisfied — requirement now applies"

    instance.save(
        update_fields=[
            "status",
            "not_applicable_reason",
            "due_on",
            "due_reason",
            "updated_at",
        ]
    )

    if not quiet:
        audit.record(
            AuditAction.STATUS_CHANGE,
            "RequirementInstance",
            entity_id=instance.pk,
            entity_label=f"{volunteer.display_name} — {definition.name}",
            summary=summary,
            detail={
                "before": {"status": RequirementStatus.NOT_APPLICABLE, "reason": previous_reason},
                "after": {"status": instance.status, "due_on": str(instance.due_on or "")},
            },
        )
    return True


# ---------------------------------------------------------------------------
# Recording progress
# ---------------------------------------------------------------------------


@transaction.atomic
def mark_requirement_complete(
    instance: RequirementInstance,
    completed_on: datetime.date,
    *,
    notes: str = "",
) -> RequirementInstance:
    """Record a requirement as satisfied and set the next renewal date."""
    if instance.status == RequirementStatus.BLOCKED:
        raise ValidationError(
            "This requirement is blocked pending the outcome of a criminal record "
            "check and cannot be marked complete."
        )
    if completed_on > timezone.localdate():
        raise ValidationError({"completed_on": "Cannot be in the future."})

    before = _snapshot(instance)
    instance.mark_complete(completed_on, notes=notes)

    audit.record(
        AuditAction.STATUS_CHANGE,
        "RequirementInstance",
        entity_id=instance.pk,
        entity_label=f"{instance.volunteer.display_name} — {instance.definition.name}",
        summary=f"Marked complete ({completed_on})"
        + (f", expires {instance.expires_on}" if instance.expires_on else ", no expiry"),
        detail={"changed": _diff(before, _snapshot(instance))},
    )
    refresh_dependents(instance)
    return instance


@transaction.atomic
def start_requirement(instance: RequirementInstance, started_on: datetime.date | None = None):
    """Mark a requirement as under way. Used to time the three-month onboarding window."""
    if instance.status not in (RequirementStatus.NOT_STARTED, RequirementStatus.OVERDUE):
        return instance

    before = _snapshot(instance)
    instance.started_on = started_on or timezone.localdate()
    if instance.status == RequirementStatus.NOT_STARTED:
        instance.status = RequirementStatus.IN_PROGRESS
    instance.save(update_fields=["started_on", "status", "updated_at"])

    audit.record(
        AuditAction.STATUS_CHANGE,
        "RequirementInstance",
        entity_id=instance.pk,
        entity_label=f"{instance.volunteer.display_name} — {instance.definition.name}",
        summary="Marked in progress",
        detail={"changed": _diff(before, _snapshot(instance))},
    )
    return instance


@transaction.atomic
def waive_requirement(
    instance: RequirementInstance,
    *,
    reason: str,
    waived_by: str,
) -> RequirementInstance:
    """
    Waive a requirement.

    A waiver needs a reason, which goes to the audit trail (Build Spec §4.1). The
    criminal record check is deliberately **not** waivable: the policy has an age
    exemption and a Not Clear process, but no route to simply skipping the check for
    an adult in a position of trust.
    """
    if not (reason or "").strip():
        raise ValidationError({"reason": "A waiver must record why it was granted."})
    if instance.definition.is_crc:
        raise ValidationError(
            "A criminal record check cannot be waived. Volunteers under 18 are exempt "
            "automatically; adults in a position of trust must have a current check."
        )

    before = _snapshot(instance)
    instance.status = RequirementStatus.WAIVED
    instance.waived_reason = reason
    instance.waived_by = waived_by[:150]
    instance.waived_on = timezone.localdate()
    instance.due_on = None
    instance.due_reason = ""
    instance.save(
        update_fields=[
            "status",
            "waived_reason",
            "waived_by",
            "waived_on",
            "due_on",
            "due_reason",
            "updated_at",
        ]
    )

    audit.record(
        AuditAction.WAIVE,
        "RequirementInstance",
        entity_id=instance.pk,
        entity_label=f"{instance.volunteer.display_name} — {instance.definition.name}",
        summary=f"Waived by {waived_by}",
        # The reason is encrypted in the instance and again here in the audit detail.
        detail={"reason": reason, "changed": _diff(before, _snapshot(instance))},
    )
    # A waiver counts as the prerequisite being met, so it can open a gate behind it.
    refresh_dependents(instance)
    return instance


def refresh_dependents(instance: RequirementInstance, *, quiet: bool = True) -> int:
    """
    Re-derive anything gated behind ``instance`` for this volunteer.

    A gate stores nothing — it is derived from the prerequisite's current state every
    time ``sync_volunteer_requirements`` runs — so reacting to a change is simply
    running the sync again. The ``exists()`` guard keeps the overwhelmingly common case
    (nothing depends on this) to one indexed query.

    Called explicitly from each path that changes a prerequisite's state rather than
    from a ``post_save`` signal: the sync saves instances itself, so a signal would be
    re-entrant, and ``signals.py`` is by convention the bridge from the org models, not
    a home for requirement rules.

    Missing a call is not a correctness problem, only a latency one — the nightly sweep
    re-syncs every volunteer, so a gate is right within a day either way.
    """
    from .models import DependencyMode

    has_dependents = instance.definition.followed_by.filter(
        dependency_mode=DependencyMode.GATE, is_active=True
    ).exists()
    if not has_dependents:
        return 0
    return sync_volunteer_requirements(instance.volunteer, quiet=quiet)["updated"]


def _status_after_reversal(instance: RequirementInstance) -> str:
    """
    Where a reversed waiver puts the requirement back.

    Derived from what survived the waiver rather than assumed, so the row ends up
    reflecting what actually happened: something completed before it was waived returns
    to complete, something started returns to in progress, anything else to not started.
    """
    if instance.completed_on:
        return RequirementStatus.COMPLETE
    if instance.started_on:
        return RequirementStatus.IN_PROGRESS
    return RequirementStatus.NOT_STARTED


@transaction.atomic
def reverse_waiver(
    instance: RequirementInstance,
    *,
    reason: str,
    reversed_by: str,
) -> RequirementInstance:
    """
    Undo a waiver, and record why.

    A waiver is a judgement, and judgements can be wrong — someone confuses two
    volunteers, or mis-clicks. Nothing in the policy makes one permanent: Build Spec
    §4.1 asks only that a waiver carry a reason and reach the audit trail. That is a
    different thing from an automatic disqualification or a leadership override, both of
    which are deliberately immutable and have tests hunting for a way back.

    So this exists, and it leaves a trail of its own. The waiver fields are cleared, so
    the record does not show waiver details on a requirement that is no longer waived,
    and the history lives in the audit trail.

    The requirement genuinely returns to play: it becomes outstanding again, the nightly
    sweep and the reminder digests both start acting on it again, and it may show as
    overdue straight away.

    One thing is not restored. ``waive_requirement`` nulls ``due_on``/``due_reason`` and
    they are not recoverable from the row. In practice that is close to harmless — the
    criminal record check is the main user of hard deadlines and cannot be waived at all
    — so this does not carry a shadow copy around for it.
    """
    if instance.status != RequirementStatus.WAIVED:
        raise ValidationError("This requirement is not waived, so there is nothing to reverse.")
    if not (reason or "").strip():
        raise ValidationError({"reason": "Say why this waiver is being reversed."})

    before = _snapshot(instance)
    cleared = {
        "waived_by": instance.waived_by,
        "waived_on": str(instance.waived_on or ""),
        "waived_reason": instance.waived_reason,
    }

    instance.status = _status_after_reversal(instance)
    instance.waived_reason = ""
    instance.waived_by = ""
    instance.waived_on = None
    instance.save(
        update_fields=[
            "status",
            "waived_reason",
            "waived_by",
            "waived_on",
            "updated_at",
        ]
    )
    # Moves it to overdue if a renewal date passed while it sat waived.
    instance.recompute()

    audit.record(
        AuditAction.WAIVER_REVERSED,
        "RequirementInstance",
        entity_id=instance.pk,
        entity_label=f"{instance.volunteer.display_name} — {instance.definition.name}",
        # The comment goes in the summary, not only the detail. The audit entry's detail
        # is recorded but not displayed, so a reason kept only there would be invisible
        # to the very reader it is written for. The form caps the comment so it fits.
        summary=f"Waiver reversed by {reversed_by}: {reason}"[:255],
        detail={
            "reason": reason,
            "cleared_waiver": cleared,
            "changed": _diff(before, _snapshot(instance)),
        },
    )
    # And reversing it puts the prerequisite back in play, re-imposing any gate.
    refresh_dependents(instance)
    return instance


# ---------------------------------------------------------------------------
# Criminal record checks
# ---------------------------------------------------------------------------


@transaction.atomic
def record_crc(
    volunteer: Volunteer,
    *,
    result: str,
    report_date: datetime.date,
    includes_vulnerable_sector: bool = True,
    is_fingerprint_verified: bool = False,
    issuing_body: str = "",
    notes: str = "",
) -> CRCRecord:
    """
    Record a criminal record check result.

    A ``Cleared`` result satisfies the requirement and starts a three-year clock from
    the **report date** (Build Spec §4.3). A ``Not Clear`` result blocks the volunteer
    pending one of the two outcomes the policy allows.
    """
    if report_date > timezone.localdate():
        raise ValidationError({"report_date": "Cannot be in the future."})
    if volunteer.is_permanently_disqualified:
        raise ValidationError(
            "This volunteer is permanently disqualified under the Plan to Protect "
            "policy. No further criminal record check can change that."
        )

    instance = _crc_instance(volunteer)

    record = CRCRecord(
        volunteer=volunteer,
        instance=instance,
        result=result,
        report_date=report_date,
        includes_vulnerable_sector=includes_vulnerable_sector,
        is_fingerprint_verified=is_fingerprint_verified,
        issuing_body=issuing_body,
        notes=notes,
        not_clear_outcome=(
            CRCNotClearOutcome.PENDING if result == CRCResult.NOT_CLEAR else ""
        ),
    )
    record.full_clean(exclude=["instance"])
    record.save()

    # Supersede the previous check so the file reads as a history, not a pile.
    previous = (
        CRCRecord.objects.filter(volunteer=volunteer, superseded_by__isnull=True)
        .exclude(pk=record.pk)
        .order_by("-report_date")
        .first()
    )
    if previous:
        previous.superseded_by = record
        previous.save(update_fields=["superseded_by", "updated_at"])

    if result == CRCResult.CLEARED:
        if instance:
            instance.completed_on = report_date
            instance.expires_on = add_months_to(report_date, 36)
            instance.status = RequirementStatus.COMPLETE
            instance.due_on = None
            instance.due_reason = ""
            instance.save(
                update_fields=[
                    "completed_on",
                    "expires_on",
                    "status",
                    "due_on",
                    "due_reason",
                    "updated_at",
                ]
            )
            # record_crc completes the instance inline rather than through
            # mark_requirement_complete, so the dependency hook has to be repeated here.
            refresh_dependents(instance)
        # A cleared check resolves a previous Not Clear block, but never a permanent
        # disqualification (guarded above and in set_screening_block).
        if volunteer.screening_block == ScreeningBlock.CRC_NOT_CLEAR:
            volunteer.set_screening_block(ScreeningBlock.NONE)
        summary = f"Criminal record check: Cleared ({report_date}), expires {add_months_to(report_date, 36)}"
    else:
        if instance:
            instance.status = RequirementStatus.BLOCKED
            instance.completed_on = None
            instance.expires_on = None
            instance.save(
                update_fields=["status", "completed_on", "expires_on", "updated_at"]
            )
            # Not Clear nulls the completion date, so anything gated behind this check
            # is held again.
            refresh_dependents(instance)
        volunteer.set_screening_block(ScreeningBlock.CRC_NOT_CLEAR)
        summary = f"Criminal record check: NOT CLEAR ({report_date}) — volunteer blocked"

    audit.record(
        AuditAction.CRC_RECORDED,
        "CRCRecord",
        entity_id=record.pk,
        entity_label=volunteer.display_name,
        summary=summary,
        detail={
            "result": result,
            "report_date": str(report_date),
            "vulnerable_sector": includes_vulnerable_sector,
            "fingerprint_verified": is_fingerprint_verified,
            "issuing_body": issuing_body,
        },
    )
    logger.info(
        "CRC recorded volunteer=%s result=%s report_date=%s", volunteer.pk, result, report_date
    )
    return record


def _crc_instance(volunteer: Volunteer) -> RequirementInstance | None:
    """The volunteer's criminal-record-check requirement instance, if they have one."""
    from .models import RequirementType

    return (
        volunteer.requirement_instances.filter(
            definition__requirement_type=RequirementType.CRIMINAL_RECORD_CHECK,
            definition__is_active=True,
        )
        .order_by("definition__sequence")
        .first()
    )


@transaction.atomic
def record_convictions(crc_record: CRCRecord, entries: list[dict]) -> dict:
    """
    Attach convictions to a Not Clear check.

    ``entries`` items are ``{"category": str, "is_automatic_disqualifier": bool,
    "description": str, "conviction_date": date|None}``.

    **If any entry is an automatic disqualifier, the volunteer is permanently barred
    from all positions of trust.** Their current trust assignments are ended and the
    block is set to ``DISQUALIFIED``, which
    :meth:`Volunteer.set_screening_block` will not later allow to be lifted. There is
    no override — not here, not in the views, not anywhere (Build Spec §4.3).
    """
    if crc_record.result != CRCResult.NOT_CLEAR:
        raise ValidationError("Convictions are only recorded against a 'Not Clear' result.")

    volunteer = crc_record.volunteer
    created, automatic = [], False

    for entry in entries:
        conviction = DisqualifyingConviction(
            crc_record=crc_record,
            category=(entry.get("category") or "").strip()[:100],
            is_automatic_disqualifier=bool(entry.get("is_automatic_disqualifier")),
            description=entry.get("description") or "",
            conviction_date=entry.get("conviction_date"),
            recorded_by=entry.get("recorded_by", "")[:150],
        )
        if not conviction.category:
            raise ValidationError("Each conviction needs a policy category.")
        conviction.full_clean(exclude=["crc_record"])
        conviction.save()
        created.append(conviction)
        automatic = automatic or conviction.is_automatic_disqualifier

    if automatic:
        _apply_permanent_disqualification(volunteer, crc_record, created)
    else:
        audit.record(
            AuditAction.CRC_RECORDED,
            "CRCRecord",
            entity_id=crc_record.pk,
            entity_label=volunteer.display_name,
            summary=(
                f"{len(created)} discretionary red flag(s) recorded — awaiting a "
                "documented leadership decision"
            ),
            detail={"categories": [c.category for c in created], "automatic": False},
        )

    return {
        "convictions": created,
        "automatic_disqualifier": automatic,
        "requires_leadership_decision": bool(created) and not automatic,
    }


def _apply_permanent_disqualification(
    volunteer: Volunteer, crc_record: CRCRecord, convictions: list
) -> None:
    """
    Enact an automatic disqualification. Irreversible by design.

    Ends every current assignment and sets the permanent block. Every role is a position
    of trust, so there is nothing left they could be moved sideways into.
    """
    ended = []
    for assignment in volunteer.assignments.filter(is_active=True).select_related("role"):
        assignment.end()
        ended.append(assignment.role.name)

    volunteer.screening_block = ScreeningBlock.DISQUALIFIED
    volunteer.screening_block_recorded_at = timezone.now()
    volunteer.save(
        update_fields=["screening_block", "screening_block_recorded_at", "updated_at"]
    )

    for instance in volunteer.requirement_instances.filter(
        status__in=RequirementStatus.outstanding_values()
    ):
        instance.status = RequirementStatus.BLOCKED
        instance.save(update_fields=["status", "updated_at"])

    categories = [c.category for c in convictions if c.is_automatic_disqualifier]

    audit.record(
        AuditAction.DISQUALIFIED,
        "Volunteer",
        entity_id=volunteer.pk,
        entity_label=volunteer.display_name,
        summary=(
            "PERMANENTLY DISQUALIFIED from all positions of trust — automatic "
            "disqualifier under the Plan to Protect policy. No override is available."
        ),
        detail={
            "crc_record_id": crc_record.pk,
            "automatic_categories": categories,
            "assignments_ended": ended,
        },
    )
    logger.warning(
        "Volunteer %s permanently disqualified (automatic disqualifier); %d assignment(s) ended",
        volunteer.pk,
        len(ended),
    )


@transaction.atomic
def record_discretionary_override(
    crc_record: CRCRecord,
    *,
    conviction: DisqualifyingConviction | None,
    decision: str,
    decided_by: str,
    reasoning: str,
    mitigation_steps: str,
    decided_on: datetime.date | None = None,
) -> DiscretionaryOverride:
    """
    Record a leadership decision on a discretionary red flag.

    Refuses outright if the conviction is an automatic disqualifier, or if the
    volunteer is already permanently disqualified. Reasoning and mitigation steps are
    mandatory and permanently retained (Build Spec §4.3).
    """
    if conviction and conviction.is_automatic_disqualifier:
        raise ValidationError(
            "Automatic disqualifiers under the Plan to Protect policy cannot be "
            "overridden."
        )
    if crc_record.volunteer.is_permanently_disqualified:
        raise ValidationError(
            "This volunteer is permanently disqualified. That determination cannot be "
            "overridden."
        )

    override = DiscretionaryOverride(
        crc_record=crc_record,
        conviction=conviction,
        decision=decision,
        decided_by=decided_by[:150],
        reasoning=reasoning,
        mitigation_steps=mitigation_steps,
        decided_on=decided_on or timezone.localdate(),
    )
    override.save()  # full_clean() runs inside save() for this model.

    volunteer = crc_record.volunteer
    if decision == DiscretionaryOverride.Decision.DECLINED:
        volunteer.set_screening_block(ScreeningBlock.WITHDRAWN)
        for assignment in volunteer.assignments.filter(is_active=True):
            assignment.end()
    else:
        # Approved: lift the Not Clear block. The check itself still has to be
        # recorded as cleared or fingerprint-verified to satisfy the requirement.
        if volunteer.screening_block == ScreeningBlock.CRC_NOT_CLEAR:
            volunteer.set_screening_block(ScreeningBlock.NONE)

    audit.record(
        AuditAction.OVERRIDE,
        "DiscretionaryOverride",
        entity_id=override.pk,
        entity_label=volunteer.display_name,
        summary=f"Leadership decision: {override.get_decision_display()} (by {decided_by})",
        detail={
            "decision": decision,
            "decided_by": decided_by,
            "decided_on": str(override.decided_on),
            "conviction_category": conviction.category if conviction else None,
            "reasoning": reasoning,
            "mitigation_steps": mitigation_steps,
        },
    )
    return override


@transaction.atomic
def resolve_not_clear(
    crc_record: CRCRecord,
    *,
    outcome: str,
    notes: str = "",
) -> CRCRecord:
    """
    Record how a Not Clear result was resolved (Build Spec §4.3).

    Two outcomes exist in the policy: a fingerprint-verified check is submitted with
    the convictions disclosed and verified, or the volunteer withdraws.
    """
    if crc_record.result != CRCResult.NOT_CLEAR:
        raise ValidationError("Only a 'Not Clear' result needs an outcome recorded.")
    if outcome not in CRCNotClearOutcome.values:
        raise ValidationError({"outcome": "Not a recognised outcome."})

    volunteer = crc_record.volunteer
    crc_record.not_clear_outcome = outcome
    if notes:
        crc_record.notes = f"{crc_record.notes}\n{notes}".strip()
    crc_record.save(update_fields=["not_clear_outcome", "notes", "updated_at"])

    if outcome == CRCNotClearOutcome.WITHDREW:
        volunteer.set_screening_block(ScreeningBlock.WITHDRAWN)
        for assignment in volunteer.assignments.filter(is_active=True):
            assignment.end()
        summary = "Not Clear resolved: volunteer withdrew; all assignments ended"
    else:
        summary = (
            "Not Clear resolved: fingerprint-verified check to be submitted with "
            "convictions disclosed"
        )

    audit.record(
        AuditAction.CRC_RECORDED,
        "CRCRecord",
        entity_id=crc_record.pk,
        entity_label=volunteer.display_name,
        summary=summary,
        detail={"outcome": outcome},
    )
    return crc_record


# ---------------------------------------------------------------------------
# Nightly work
# ---------------------------------------------------------------------------


def recompute_all_statuses(as_of: datetime.date | None = None) -> int:
    """
    Refresh every requirement instance's status against today's date.

    Returns how many changed. Iterated rather than done in one UPDATE because the
    transition rules live on the model and are worth keeping readable — and because
    a church has hundreds of instances, not millions.
    """
    as_of = as_of or timezone.localdate()
    changed = 0
    queryset = RequirementInstance.objects.select_related("definition", "volunteer").filter(
        volunteer__is_active=True
    )
    for instance in queryset.iterator(chunk_size=500):
        if instance.recompute(as_of):
            changed += 1
    if changed:
        logger.info("Recomputed statuses: %d instance(s) changed", changed)
    return changed


def activate_turning_18_checks(as_of: datetime.date | None = None) -> list[RequirementInstance]:
    """
    Activate the criminal record check for anyone who has now turned 18.

    Finds volunteers whose criminal record check sits at ``not_applicable`` on age
    grounds but who are 18 as of ``as_of``, and switches it on with the policy's
    three-month deadline. Runs nightly; the activation date is the 1st of the birth
    month, so it fires at most a month early and never late (Build Spec §4.4).
    """
    as_of = as_of or timezone.localdate()
    activated = []

    candidates = (
        RequirementInstance.objects.select_related("volunteer", "definition")
        .filter(
            status=RequirementStatus.NOT_APPLICABLE,
            definition__age_rule=AgeRule.ADULTS_ONLY,
            definition__is_active=True,
            volunteer__is_active=True,
            volunteer__birth_year__isnull=False,
            volunteer__birth_month__isnull=False,
        )
    )

    for instance in candidates:
        volunteer = instance.volunteer
        if not volunteer.is_adult_on(as_of):
            continue
        # Only re-activate if a role still requires it.
        if not instance.definition.applies_to_volunteer(volunteer):
            continue
        # Turning 18 lifts the age exemption; it does not lift a prerequisite gate.
        # Without this the nightly age scan would switch on a requirement that
        # sync_volunteer_requirements is deliberately holding.
        if instance.definition.unmet_prerequisite(volunteer) is not None:
            continue
        _activate(instance, volunteer, instance.definition, as_of, quiet=False)
        activated.append(instance)

    if activated:
        logger.info("Activated %d criminal record check(s) on turning 18", len(activated))
    return activated


def onboarding_window_breached(volunteer: Volunteer, as_of: datetime.date | None = None) -> bool:
    """
    Whether onboarding has run past the policy's three-month window.

    Measured from the earliest started/completed onboarding requirement to today,
    while leadership approval is still outstanding (Build Spec §4.2 item 8). Surfaced
    as a warning on the volunteer's record, not as a block.
    """
    as_of = as_of or timezone.localdate()
    onboarding = volunteer.requirement_instances.filter(
        definition__is_onboarding=True, definition__is_active=True
    ).select_related("definition")

    if not onboarding:
        return False

    approval = [
        i
        for i in onboarding
        if i.definition.requirement_type == "leadership_approval"
    ]
    if approval and all(i.status in RequirementStatus.satisfied_values() for i in approval):
        return False

    dates = [
        d
        for i in onboarding
        for d in (i.started_on, i.completed_on)
        if d
    ]
    if not dates:
        return False

    return min(dates) < add_months_to(as_of, -3)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snapshot(instance: RequirementInstance) -> dict:
    """Plaintext-only field snapshot for the audit diff."""
    return {
        "status": instance.status,
        "started_on": str(instance.started_on or ""),
        "completed_on": str(instance.completed_on or ""),
        "expires_on": str(instance.expires_on or ""),
        "due_on": str(instance.due_on or ""),
    }


def _diff(before: dict, after: dict) -> dict:
    from apps.core.models import diff_summary

    return diff_summary(before, after)
