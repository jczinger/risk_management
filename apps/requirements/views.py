"""
Requirement management and the criminal-record-check flows.

The CRC screens are where the policy's hardest rules become interface decisions:

* Recording an **automatic disqualifier** takes an explicit acknowledgement, then
  permanently blocks the volunteer. No view offers a route back — there is no
  "un-disqualify" URL to find, guess or forge.
* A **discretionary** flag routes to a leadership decision that will not save without
  reasoning and mitigation steps.
"""

from __future__ import annotations

import logging
from collections import Counter

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST, require_http_methods

from apps.core import audit
from apps.core.access import (
    Capability,
    may_record_against,
    require_own_record_not_touched,
    requires,
    scope_crc_records,
    scope_instances,
    scope_volunteers,
)
from apps.core.models import AuditAction, diff_summary
from apps.org.models import Volunteer

from .forms import (
    ConvictionForm,
    CRCRecordForm,
    DiscretionaryOverrideForm,
    NotClearOutcomeForm,
    RequirementCompleteForm,
    RequirementDefinitionForm,
    RequirementWaiveForm,
    WaiverReversalForm,
)
from .models import (
    CRCNotClearOutcome,
    CRCRecord,
    CRCResult,
    RequirementDefinition,
    RequirementInstance,
    RequirementStatus,
)
from .seed import seed_default_template
from .services import (
    crc_instance_for,
    mark_requirement_complete,
    record_convictions,
    record_crc,
    record_discretionary_override,
    resolve_not_clear,
    reverse_waiver,
    start_requirement,
    waive_requirement,
)

logger = logging.getLogger("vms.requirements")


# ---------------------------------------------------------------------------
# Scoped lookups
# ---------------------------------------------------------------------------
#
# A requirement, a check or a conviction belongs to a volunteer, and a volunteer belongs
# to departments. Every view below reaches its subject through one of these so that a
# record outside the caller's departments 404s rather than 403s — see
# :mod:`apps.core.access` for why the distinction matters.


def _instance_or_404(request, pk: int):
    return get_object_or_404(
        scope_instances(
            RequirementInstance.objects.select_related("volunteer", "definition"), request.user
        ),
        pk=pk,
    )


def _crc_or_404(request, pk: int, queryset=None):
    queryset = CRCRecord.objects.select_related("volunteer") if queryset is None else queryset
    return get_object_or_404(scope_crc_records(queryset, request.user), pk=pk)


def _volunteer_or_404(request, pk: int):
    return get_object_or_404(scope_volunteers(Volunteer.objects.all(), request.user), pk=pk)


# The writable twins. A view that records something reaches for one of these instead, so
# the "not your own file" refusal arrives with the record rather than as a separate line
# somebody can forget. 403, not 404 — they can already see it. See
# :func:`apps.core.access.may_record_against`.


def _writable_instance_or_404(request, pk: int):
    instance = _instance_or_404(request, pk)
    require_own_record_not_touched(request.user, instance.volunteer)
    return instance


def _writable_crc_or_404(request, pk: int, queryset=None):
    record = _crc_or_404(request, pk, queryset)
    require_own_record_not_touched(request.user, record.volunteer)
    return record


def _writable_volunteer_or_404(request, pk: int):
    volunteer = _volunteer_or_404(request, pk)
    require_own_record_not_touched(request.user, volunteer)
    return volunteer


def _flash_errors(request, exc: ValidationError) -> None:
    """Every message from a service-layer refusal, as its own flash line."""
    for error in exc.messages:
        messages.error(request, error)


def _annotate_review(instance):
    """
    Hang the "unverified" flag on one instance.

    Small, and the only way the flag is ever set on a single row — which is the point.
    Every render path has to use it, or a page shows a badge that another page does not.
    """
    from apps.review.recording import open_review_index

    open_review_index(volunteer=instance.volunteer).annotate(
        [instance], entity_type="RequirementInstance"
    )
    return instance


# ---------------------------------------------------------------------------
# Definitions — the church's own requirement list
# ---------------------------------------------------------------------------


@requires(Capability.MANAGE_REQUIREMENTS)
def definition_list(request):
    definitions = RequirementDefinition.objects.prefetch_related("roles").order_by(
        "-is_active", "sequence", "name"
    )
    return render(
        request,
        "requirements/definition_list.html",
        {
            "onboarding": [d for d in definitions if d.is_onboarding],
            "recurring": [d for d in definitions if not d.is_onboarding],
            "any_active": any(d.is_active for d in definitions),
            "total": len(definitions),
        },
    )


@requires(Capability.MANAGE_REQUIREMENTS)
@require_http_methods(["GET", "POST"])
def definition_create(request):
    form = RequirementDefinitionForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        definition = form.save()
        audit.record(
            AuditAction.CREATE,
            "RequirementDefinition",
            entity_id=definition.pk,
            entity_label=definition.name,
            summary=f"Requirement created ({definition.cadence_display})",
            detail={
                "type": definition.requirement_type,
                "applies_to": definition.applies_to,
                "age_rule": definition.age_rule,
            },
        )
        messages.success(
            request,
            f"'{definition.name}' created. It will apply to volunteers as their "
            "requirements are next recalculated.",
        )
        return redirect("requirements:definition_detail", pk=definition.pk)

    return render(request, "requirements/definition_form.html", {"form": form, "definition": None})


@requires(Capability.MANAGE_REQUIREMENTS)
def definition_detail(request, pk: int):
    definition = get_object_or_404(
        RequirementDefinition.objects.prefetch_related("roles"), pk=pk
    )
    # Unscoped, deliberately. A requirement definition is church-wide configuration, not
    # a volunteer's record, and MANAGE_REQUIREMENTS is not granted to any limited access
    # level — the model refuses to combine the two for the audit trail and the same
    # reasoning applies here: "how many volunteers have satisfied this requirement?" is a
    # church-wide question that cannot be answered a department at a time.
    counts = Counter(
        definition.instances.filter(volunteer__is_active=True).values_list("status", flat=True)
    )

    return render(
        request,
        "requirements/definition_detail.html",
        {
            "definition": definition,
            "status_counts": [
                (RequirementStatus(status).label, count) for status, count in sorted(counts.items())
            ],
            "instance_total": sum(counts.values()),
        },
    )


@requires(Capability.MANAGE_REQUIREMENTS)
@require_http_methods(["GET", "POST"])
def definition_edit(request, pk: int):
    definition = get_object_or_404(RequirementDefinition, pk=pk)
    before = _definition_snapshot(definition)

    form = RequirementDefinitionForm(request.POST or None, instance=definition)
    if request.method == "POST" and form.is_valid():
        form.save()
        audit.record(
            AuditAction.UPDATE,
            "RequirementDefinition",
            entity_id=definition.pk,
            entity_label=definition.name,
            summary="Requirement updated",
            detail={"changed": diff_summary(before, _definition_snapshot(definition))},
        )
        messages.success(
            request,
            "Requirement updated. The change applies going forward; requirements "
            "already completed keep their recorded dates.",
        )
        return redirect("requirements:definition_detail", pk=definition.pk)

    return render(
        request, "requirements/definition_form.html", {"form": form, "definition": definition}
    )


def _definition_snapshot(definition: RequirementDefinition) -> dict:
    return {
        "name": definition.name,
        "requirement_type": definition.requirement_type,
        "cadence": definition.cadence,
        "cadence_months": definition.cadence_months,
        "applies_to": definition.applies_to,
        "age_rule": definition.age_rule,
        "sequence": definition.sequence,
        "requires_document": definition.requires_document,
        "is_active": definition.is_active,
    }


@requires(Capability.MANAGE_REQUIREMENTS)
@require_POST
def definition_toggle_active(request, pk: int):
    """
    Deactivate or reactivate a requirement.

    Never a deletion: a requirement with completed instances behind it is part of the
    church's screening history.
    """
    definition = get_object_or_404(RequirementDefinition, pk=pk)
    definition.is_active = not definition.is_active
    definition.save(update_fields=["is_active", "updated_at"])

    audit.record(
        AuditAction.DEACTIVATE if not definition.is_active else AuditAction.REACTIVATE,
        "RequirementDefinition",
        entity_id=definition.pk,
        entity_label=definition.name,
        summary=("Requirement deactivated" if not definition.is_active else "Requirement reactivated"),
    )
    messages.success(
        request,
        f"'{definition.name}' "
        + (
            "deactivated. Completed records are kept."
            if not definition.is_active
            else "reactivated."
        ),
    )
    return redirect("requirements:definition_detail", pk=definition.pk)


@requires(Capability.MANAGE_REQUIREMENTS)
@require_POST
def definition_seed(request):
    """Add any missing items from the Plan to Protect starter template."""
    created = seed_default_template()
    audit.record(
        AuditAction.SEED,
        "RequirementDefinition",
        summary=f"Plan to Protect template applied ({created} added)",
        detail={"created": created},
    )
    if created:
        messages.success(request, f"{created} requirement(s) added from the template.")
    else:
        messages.info(
            request,
            "Nothing to add — every template requirement already exists here. Your own "
            "edits were left untouched.",
        )
    return redirect("requirements:definition_list")


# ---------------------------------------------------------------------------
# Instances — one volunteer's progress
# ---------------------------------------------------------------------------


@requires(Capability.RECORD_SCREENING)
@require_http_methods(["GET", "POST"])
def instance_complete(request, pk: int):
    """
    Record a requirement as satisfied.

    Refused where no screen offers the action, so reaching the URL directly cannot do
    what the interface declines to. The waiver case is the one that matters: a waiver is
    already a recorded decision that the requirement is met, with a reason and an audit
    entry, and completing over the top of it would leave a row that reads complete while
    still carrying someone's waiver.
    """
    instance = _writable_instance_or_404(request, pk)

    if not instance.can_mark_complete:
        messages.error(request, _why_completion_is_refused(instance))
        return redirect("requirements:instance_detail", pk=instance.pk)

    form = RequirementCompleteForm(request.POST or None)
    dependency = _unmet_dependency(instance)

    if request.method == "POST" and form.is_valid():
        try:
            mark_requirement_complete(
                instance,
                form.cleaned_data["completed_on"],
                notes=form.cleaned_data["notes"],
            )
        except ValidationError as exc:
            _flash_errors(request, exc)
        else:
            note = ""
            if instance.expires_on:
                note = f" Next due {instance.expires_on:%d %b %Y}."
            messages.success(request, f"'{instance.definition.name}' marked complete.{note}")
            return redirect("org:volunteer_detail", pk=instance.volunteer.pk)

    return render(
        request,
        "requirements/instance_complete.html",
        {"form": form, "instance": instance, "dependency": dependency},
    )


def _why_completion_is_refused(instance: RequirementInstance) -> str:
    """A specific reason, so the admin knows what to do instead."""
    if instance.definition.is_crc:
        return (
            "A criminal record check is completed by recording the check itself, so the "
            "clearance date and the three-year renewal are captured."
        )
    if instance.definition.requires_document:
        return (
            f"'{instance.definition.name}' is completed by recording its document — "
            "that is the evidence behind it. Use 'Add document'."
        )
    if instance.status == RequirementStatus.WAIVED:
        return (
            f"'{instance.definition.name}' was waived by {instance.waived_by or 'an administrator'}, "
            "which already satisfies it. To record it as completed instead, use "
            "'Reverse waiver' first — that keeps both decisions in the audit trail."
        )
    if instance.status == RequirementStatus.NOT_APPLICABLE:
        return f"'{instance.definition.name}' does not apply to this volunteer."
    return (
        f"'{instance.definition.name}' is blocked pending the outcome of a criminal "
        "record check and cannot be marked complete."
    )


def _unmet_dependency(instance: RequirementInstance) -> RequirementInstance | None:
    """
    The prerequisite this requirement is meant to follow, if it is not yet satisfied.

    Surfaced as a warning rather than a block: the policy's ordering rule (liability
    release before references) matters, but an admin recording historical paperwork
    out of order should not be stopped — they should be told.
    """
    if instance.definition.is_gated:
        # The gating half of the rule speaks for itself: the requirement is sitting at
        # not-applicable with the prerequisite named in its reason, and completion is
        # already refused. A second callout would read as a warning about something the
        # admin could push past, which is the opposite of what a gate is.
        return None

    predecessor = instance.definition.must_follow
    if predecessor is None:
        return None
    prior = instance.volunteer.requirement_instances.filter(definition=predecessor).first()
    if prior is None or prior.status in RequirementStatus.satisfied_values():
        return None
    return prior


@requires(Capability.RECORD_SCREENING)
@require_POST
def instance_start(request, pk: int):
    """
    Move a requirement to in progress.

    Over htmx this swaps the single row back in place — the admin is working down a list
    of eight, and bouncing them to the top of the volunteer's file after each click made
    the button read as navigation rather than as a status change. A plain POST still
    redirects, so the button works with JavaScript unavailable.
    """
    instance = _writable_instance_or_404(request, pk)
    start_requirement(instance)
    # Re-annotate before re-rendering the row. Without this the swapped-in fragment loses
    # its "unverified" badge and the page starts disagreeing with itself.
    _annotate_review(instance)

    if request.headers.get("HX-Request"):
        instance.refresh_from_db()
        return render(
            request,
            "requirements/_instance_row.html",
            {
                "instance": instance,
                "volunteer": instance.volunteer,
                # True by construction — the writable lookup above would have refused
                # otherwise — but passed rather than assumed, because the partial hides
                # its buttons when this is missing and a swapped-in row that silently
                # lost its actions is the same class of bug as one that lost its badge.
                "may_record": may_record_against(request.user, instance.volunteer)[0],
            },
        )

    messages.success(request, f"'{instance.definition.name}' marked as in progress.")
    return redirect("org:volunteer_detail", pk=instance.volunteer.pk)


@requires(Capability.RECORD_SCREENING)
@require_http_methods(["GET", "POST"])
def instance_waive(request, pk: int):
    """
    Waive a requirement.

    The criminal record check is not waivable; the form is refused for it, and the
    service layer refuses too.
    """
    instance = _writable_instance_or_404(request, pk)

    if instance.definition.is_crc:
        messages.error(
            request,
            "A criminal record check cannot be waived. Under-18s are exempt "
            "automatically; adults in a position of trust must have a current check.",
        )
        return redirect("org:volunteer_detail", pk=instance.volunteer.pk)

    form = RequirementWaiveForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            waive_requirement(
                instance,
                reason=form.cleaned_data["reason"],
                waived_by=form.cleaned_data["waived_by"],
            )
        except ValidationError as exc:
            _flash_errors(request, exc)
        else:
            messages.success(request, f"'{instance.definition.name}' waived.")
            return redirect("org:volunteer_detail", pk=instance.volunteer.pk)

    return render(request, "requirements/instance_waive.html", {"form": form, "instance": instance})


@requires(Capability.RECORD_SCREENING)
@require_http_methods(["GET", "POST"])
def instance_reverse_waiver(request, pk: int):
    """
    Undo a waiver, with a mandatory comment.

    A waiver is a judgement and judgements can be wrong. This is deliberately *not* the
    same kind of thing as lifting a disqualification, which has no route at all — see
    the note at the top of urls.py.
    """
    instance = _writable_instance_or_404(request, pk)

    if instance.status != RequirementStatus.WAIVED:
        messages.error(
            request,
            f"'{instance.definition.name}' is not waived, so there is nothing to reverse.",
        )
        return redirect("requirements:instance_detail", pk=instance.pk)

    form = WaiverReversalForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        try:
            reverse_waiver(
                instance,
                reason=form.cleaned_data["reason"],
                reversed_by=form.cleaned_data["reversed_by"],
            )
        except ValidationError as exc:
            _flash_errors(request, exc)
        else:
            instance.refresh_from_db()
            messages.success(
                request,
                f"The waiver on '{instance.definition.name}' has been reversed. It is "
                f"now {instance.get_status_display().lower()} and will be chased again.",
            )
            return redirect("org:volunteer_detail", pk=instance.volunteer.pk)

    return render(
        request,
        "requirements/instance_unwaive.html",
        {"form": form, "instance": instance},
    )


@requires(Capability.VIEW_VOLUNTEERS)
def instance_detail(request, pk: int):
    instance = _instance_or_404(request, pk)
    _annotate_review(instance)
    return render(
        request,
        "requirements/instance_detail.html",
        {
            "instance": instance,
            "documents": instance.documents.all(),
            "dependency": _unmet_dependency(instance),
        },
    )


# ---------------------------------------------------------------------------
# Criminal record checks
# ---------------------------------------------------------------------------


@requires(Capability.RECORD_CRC)
@require_http_methods(["GET", "POST"])
def crc_record_create(request, volunteer_pk: int):
    """
    Record a criminal record check.

    A Cleared result satisfies the requirement and sets a three-year expiry. A Not Clear
    result blocks the volunteer and sends the admin on to record the convictions.
    """
    volunteer = _writable_volunteer_or_404(request, volunteer_pk)

    if volunteer.is_permanently_disqualified:
        messages.error(
            request,
            "This volunteer is permanently disqualified under the Plan to Protect "
            "policy. No further criminal record check can change that determination.",
        )
        return redirect("org:volunteer_detail", pk=volunteer.pk)

    form = CRCRecordForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        try:
            record = record_crc(
                volunteer,
                result=data["result"],
                report_date=data["report_date"],
                includes_vulnerable_sector=data["includes_vulnerable_sector"],
                is_fingerprint_verified=data["is_fingerprint_verified"],
                issuing_body=data["issuing_body"],
                notes=data["notes"],
            )
        except ValidationError as exc:
            _flash_errors(request, exc)
        else:
            if record.result == CRCResult.CLEARED:
                messages.success(
                    request,
                    f"Criminal record check recorded as Cleared. Next check due "
                    f"{record.expires_on:%d %b %Y}.",
                )
                return redirect("org:volunteer_detail", pk=volunteer.pk)

            messages.warning(
                request,
                f"{volunteer.display_name} is blocked from serving pending resolution "
                "of this result. Record the conviction(s) next.",
            )
            return redirect("requirements:crc_conviction_add", pk=record.pk)

    return render(
        request,
        "requirements/crc_form.html",
        {"form": form, "volunteer": volunteer, "crc_instance": crc_instance_for(volunteer)},
    )


@requires(Capability.RECORD_CRC)
def crc_detail(request, pk: int):
    record = _crc_or_404(
        request,
        pk,
        CRCRecord.objects.select_related("volunteer").prefetch_related(
            "convictions", "overrides", "documents"
        ),
    )
    # Partition the prefetched rows in Python — re-filtering would bypass the
    # prefetch and cost four queries for lists the page already holds.
    convictions = list(record.convictions.all())
    automatic = [c for c in convictions if c.is_automatic_disqualifier]
    discretionary = [c for c in convictions if not c.is_automatic_disqualifier]

    return render(
        request,
        "requirements/crc_detail.html",
        {
            "record": record,
            "volunteer": record.volunteer,
            "automatic_convictions": automatic,
            "discretionary_convictions": discretionary,
            # Only offered when there is a discretionary flag and no automatic one.
            # An automatic disqualifier removes the override option entirely.
            "can_record_override": bool(discretionary) and not automatic,
            "needs_outcome": (
                record.result == CRCResult.NOT_CLEAR
                and record.not_clear_outcome == CRCNotClearOutcome.PENDING
            ),
        },
    )


@requires(Capability.RECORD_CRC)
@require_http_methods(["GET", "POST"])
def crc_conviction_add(request, pk: int):
    """
    Record a conviction against a Not Clear result.

    Choosing an automatic category, and confirming the acknowledgement, permanently
    disqualifies the volunteer. There is no undo — the confirmation checkbox exists
    because of that.
    """
    record = _writable_crc_or_404(request, pk)

    if record.result != CRCResult.NOT_CLEAR:
        messages.error(request, "Convictions are only recorded against a 'Not Clear' result.")
        return redirect("requirements:crc_detail", pk=record.pk)

    form = ConvictionForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        try:
            with transaction.atomic():
                outcome = record_convictions(
                    record,
                    [
                        {
                            "category": data["category"],
                            "is_automatic_disqualifier": data["is_automatic_disqualifier"],
                            "description": data["description"],
                            "conviction_date": data["conviction_date"],
                            "recorded_by": request.user.display_name,
                        }
                    ],
                )
        except ValidationError as exc:
            _flash_errors(request, exc)
        else:
            if outcome["automatic_disqualifier"]:
                messages.error(
                    request,
                    f"{record.volunteer.display_name} is now permanently disqualified "
                    "from all positions of trust. Any current assignments have been "
                    "ended. This determination is permanent and cannot be overridden.",
                )
            else:
                messages.warning(
                    request,
                    "Discretionary red flag recorded. A leadership decision with "
                    "documented reasoning and mitigation steps is required before this "
                    "volunteer can serve.",
                )
            return redirect("requirements:crc_detail", pk=record.pk)

    return render(
        request,
        "requirements/crc_conviction_form.html",
        {
            "form": form,
            "record": record,
            "volunteer": record.volunteer,
            "automatic_categories": form.AUTOMATIC_CHOICES,
        },
    )


@requires(Capability.RECORD_CRC)
@require_http_methods(["GET", "POST"])
def crc_override(request, pk: int):
    """
    Record a leadership decision on a discretionary red flag.

    Refuses outright if the volunteer is permanently disqualified — that state has no
    override path, and this view will not pretend otherwise.
    """
    record = _writable_crc_or_404(request, pk)
    volunteer = record.volunteer

    if volunteer.is_permanently_disqualified:
        messages.error(
            request,
            "This volunteer is permanently disqualified under an automatic "
            "disqualifier. That determination cannot be overridden.",
        )
        return redirect("requirements:crc_detail", pk=record.pk)

    if not record.convictions.filter(is_automatic_disqualifier=False).exists():
        messages.error(request, "There is no discretionary flag on this check to decide on.")
        return redirect("requirements:crc_detail", pk=record.pk)

    form = DiscretionaryOverrideForm(request.POST or None, crc_record=record)

    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        try:
            record_discretionary_override(
                record,
                conviction=data["conviction"],
                decision=data["decision"],
                decided_by=data["decided_by"],
                reasoning=data["reasoning"],
                mitigation_steps=data["mitigation_steps"],
                decided_on=data["decided_on"],
            )
        except ValidationError as exc:
            _flash_errors(request, exc)
        else:
            messages.success(
                request,
                "Leadership decision recorded. It is retained permanently and appears "
                "in the audit trail and this volunteer's file.",
            )
            return redirect("requirements:crc_detail", pk=record.pk)

    return render(
        request,
        "requirements/crc_override_form.html",
        {"form": form, "record": record, "volunteer": volunteer},
    )


@requires(Capability.RECORD_CRC)
@require_http_methods(["GET", "POST"])
def crc_resolve_not_clear(request, pk: int):
    """Record which of the two policy outcomes resolved a Not Clear result."""
    record = _writable_crc_or_404(request, pk)

    if record.result != CRCResult.NOT_CLEAR:
        messages.error(request, "Only a 'Not Clear' result needs an outcome recorded.")
        return redirect("requirements:crc_detail", pk=record.pk)

    form = NotClearOutcomeForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        try:
            resolve_not_clear(
                record,
                outcome=form.cleaned_data["outcome"],
                notes=form.cleaned_data["notes"],
            )
        except ValidationError as exc:
            _flash_errors(request, exc)
        else:
            messages.success(request, "Outcome recorded.")
            return redirect("requirements:crc_detail", pk=record.pk)

    return render(
        request,
        "requirements/crc_resolve_form.html",
        {"form": form, "record": record, "volunteer": record.volunteer},
    )
