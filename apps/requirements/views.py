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

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST, require_http_methods

from apps.core import audit
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
    mark_requirement_complete,
    record_convictions,
    record_crc,
    record_discretionary_override,
    resolve_not_clear,
    start_requirement,
    sync_volunteer_requirements,
    waive_requirement,
)

logger = logging.getLogger("vms.requirements")


# ---------------------------------------------------------------------------
# Definitions — the church's own requirement list
# ---------------------------------------------------------------------------


@login_required
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


@login_required
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


@login_required
def definition_detail(request, pk: int):
    definition = get_object_or_404(
        RequirementDefinition.objects.prefetch_related("roles"), pk=pk
    )
    instances = definition.instances.select_related("volunteer").filter(volunteer__is_active=True)
    counts: dict[str, int] = {}
    for instance in instances:
        counts[instance.status] = counts.get(instance.status, 0) + 1

    return render(
        request,
        "requirements/definition_detail.html",
        {
            "definition": definition,
            "status_counts": [
                (RequirementStatus(status).label, count) for status, count in sorted(counts.items())
            ],
            "instance_total": len(instances),
        },
    )


@login_required
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


@login_required
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


@login_required
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


@login_required
@require_http_methods(["GET", "POST"])
def instance_complete(request, pk: int):
    """Record a requirement as satisfied."""
    instance = get_object_or_404(
        RequirementInstance.objects.select_related("volunteer", "definition"), pk=pk
    )

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
            for error in exc.messages:
                messages.error(request, error)
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


def _unmet_dependency(instance: RequirementInstance) -> RequirementInstance | None:
    """
    The prerequisite this requirement is meant to follow, if it is not yet satisfied.

    Surfaced as a warning rather than a block: the policy's ordering rule (liability
    release before references) matters, but an admin recording historical paperwork
    out of order should not be stopped — they should be told.
    """
    predecessor = instance.definition.must_follow
    if predecessor is None:
        return None
    prior = instance.volunteer.requirement_instances.filter(definition=predecessor).first()
    if prior is None or prior.status in RequirementStatus.satisfied_values():
        return None
    return prior


@login_required
@require_POST
def instance_start(request, pk: int):
    instance = get_object_or_404(
        RequirementInstance.objects.select_related("volunteer", "definition"), pk=pk
    )
    start_requirement(instance)
    messages.success(request, f"'{instance.definition.name}' marked as in progress.")
    return redirect("org:volunteer_detail", pk=instance.volunteer.pk)


@login_required
@require_http_methods(["GET", "POST"])
def instance_waive(request, pk: int):
    """
    Waive a requirement.

    The criminal record check is not waivable; the form is refused for it, and the
    service layer refuses too.
    """
    instance = get_object_or_404(
        RequirementInstance.objects.select_related("volunteer", "definition"), pk=pk
    )

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
            for error in exc.messages:
                messages.error(request, error)
        else:
            messages.success(request, f"'{instance.definition.name}' waived.")
            return redirect("org:volunteer_detail", pk=instance.volunteer.pk)

    return render(request, "requirements/instance_waive.html", {"form": form, "instance": instance})


@login_required
def instance_detail(request, pk: int):
    instance = get_object_or_404(
        RequirementInstance.objects.select_related("volunteer", "definition"), pk=pk
    )
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


@login_required
@require_http_methods(["GET", "POST"])
def crc_record_create(request, volunteer_pk: int):
    """
    Record a criminal record check.

    A Cleared result satisfies the requirement and sets a three-year expiry. A Not Clear
    result blocks the volunteer and sends the admin on to record the convictions.
    """
    volunteer = get_object_or_404(Volunteer, pk=volunteer_pk)

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
            for error in exc.messages:
                messages.error(request, error)
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
        {"form": form, "volunteer": volunteer, "crc_instance": _crc_instance_for(volunteer)},
    )


def _crc_instance_for(volunteer: Volunteer):
    from .models import RequirementType

    return volunteer.requirement_instances.filter(
        definition__requirement_type=RequirementType.CRIMINAL_RECORD_CHECK
    ).first()


@login_required
def crc_detail(request, pk: int):
    record = get_object_or_404(
        CRCRecord.objects.select_related("volunteer").prefetch_related(
            "convictions", "overrides", "documents"
        ),
        pk=pk,
    )
    discretionary = record.convictions.filter(is_automatic_disqualifier=False)
    automatic = record.convictions.filter(is_automatic_disqualifier=True)

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
            "can_record_override": discretionary.exists() and not automatic.exists(),
            "needs_outcome": (
                record.result == CRCResult.NOT_CLEAR
                and record.not_clear_outcome == CRCNotClearOutcome.PENDING
            ),
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def crc_conviction_add(request, pk: int):
    """
    Record a conviction against a Not Clear result.

    Choosing an automatic category, and confirming the acknowledgement, permanently
    disqualifies the volunteer. There is no undo — the confirmation checkbox exists
    because of that.
    """
    record = get_object_or_404(CRCRecord.objects.select_related("volunteer"), pk=pk)

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
                            "recorded_by": request.user.get_full_name() or "administrator",
                        }
                    ],
                )
        except ValidationError as exc:
            for error in exc.messages:
                messages.error(request, error)
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


@login_required
@require_http_methods(["GET", "POST"])
def crc_override(request, pk: int):
    """
    Record a leadership decision on a discretionary red flag.

    Refuses outright if the volunteer is permanently disqualified — that state has no
    override path, and this view will not pretend otherwise.
    """
    record = get_object_or_404(CRCRecord.objects.select_related("volunteer"), pk=pk)
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
            for error in exc.messages:
                messages.error(request, error)
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


@login_required
@require_http_methods(["GET", "POST"])
def crc_resolve_not_clear(request, pk: int):
    """Record which of the two policy outcomes resolved a Not Clear result."""
    record = get_object_or_404(CRCRecord.objects.select_related("volunteer"), pk=pk)

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
            for error in exc.messages:
                messages.error(request, error)
        else:
            messages.success(request, "Outcome recorded.")
            return redirect("requirements:crc_detail", pk=record.pk)

    return render(
        request,
        "requirements/crc_resolve_form.html",
        {"form": form, "record": record, "volunteer": record.volunteer},
    )
