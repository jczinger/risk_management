"""
Departments, roles and volunteer records.

Deactivation everywhere, deletion nowhere: the model layer refuses a hard delete, and
these views only ever offer a deactivate action. That is a policy requirement, not a
UI preference — a church may be legally required to retain a volunteer's file
permanently, particularly where minors are involved.
"""

from __future__ import annotations

import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Prefetch, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST, require_http_methods

from apps.core import audit
from apps.core.models import AuditAction, diff_summary
from apps.requirements.models import RequirementInstance, RequirementStatus
from apps.requirements.services import onboarding_window_breached, sync_volunteer_requirements

from .forms import (
    DepartmentForm,
    RoleAssignmentEndForm,
    RoleAssignmentForm,
    RoleForm,
    VolunteerDeactivateForm,
    VolunteerFilterForm,
    VolunteerForm,
)
from .models import Department, Role, RoleAssignment, ScreeningBlock, Volunteer

logger = logging.getLogger("vms.org")

PAGE_SIZE = 25


# ---------------------------------------------------------------------------
# Departments
# ---------------------------------------------------------------------------


@login_required
def department_list(request):
    departments = Department.objects.annotate(
        role_count=Count("roles", filter=Q(roles__is_active=True), distinct=True)
    )
    return render(request, "org/department_list.html", {"departments": departments})


@login_required
@require_http_methods(["GET", "POST"])
def department_create(request):
    form = DepartmentForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        department = form.save()
        audit.record(
            AuditAction.CREATE,
            "Department",
            entity_id=department.pk,
            entity_label=department.name,
            summary="Department created",
        )
        messages.success(request, f"Department '{department.name}' created.")
        return redirect("org:department_detail", pk=department.pk)
    return render(request, "org/department_form.html", {"form": form, "department": None})


@login_required
def department_detail(request, pk: int):
    department = get_object_or_404(Department, pk=pk)
    roles = department.roles.annotate(
        holders=Count("assignments", filter=Q(assignments__is_active=True), distinct=True)
    )
    return render(
        request,
        "org/department_detail.html",
        {"department": department, "roles": roles},
    )


@login_required
@require_http_methods(["GET", "POST"])
def department_edit(request, pk: int):
    department = get_object_or_404(Department, pk=pk)
    before = {"name": department.name, "is_active": department.is_active}

    form = DepartmentForm(request.POST or None, instance=department)
    if request.method == "POST" and form.is_valid():
        form.save()
        audit.record(
            AuditAction.UPDATE,
            "Department",
            entity_id=department.pk,
            entity_label=department.name,
            summary="Department updated",
            detail={
                "changed": diff_summary(
                    before, {"name": department.name, "is_active": department.is_active}
                )
            },
        )
        messages.success(request, "Department updated.")
        return redirect("org:department_detail", pk=department.pk)

    return render(request, "org/department_form.html", {"form": form, "department": department})


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


@login_required
def role_list(request):
    roles = (
        Role.objects.select_related("department")
        .annotate(holders=Count("assignments", filter=Q(assignments__is_active=True), distinct=True))
        .order_by("department__name", "name")
    )
    return render(request, "org/role_list.html", {"roles": roles})


@login_required
@require_http_methods(["GET", "POST"])
def role_create(request):
    initial = {}
    department_id = request.GET.get("department")
    if department_id:
        initial["department"] = department_id

    form = RoleForm(request.POST or None, initial=initial)
    if request.method == "POST" and form.is_valid():
        role = form.save()
        audit.record(
            AuditAction.CREATE,
            "Role",
            entity_id=role.pk,
            entity_label=str(role),
            summary=f"Role created in {role.department.name}",
            detail={
                "leadership": role.leadership,
                "position_of_trust": role.is_position_of_trust,
                "handles_personal_info": role.handles_personal_info,
            },
        )
        messages.success(request, f"Role '{role.name}' created.")
        return redirect("org:role_detail", pk=role.pk)

    return render(request, "org/role_form.html", {"form": form, "role": None})


@login_required
def role_detail(request, pk: int):
    role = get_object_or_404(Role.objects.select_related("department"), pk=pk)
    assignments = (
        role.assignments.select_related("volunteer")
        .filter(is_active=True)
        .order_by("volunteer__last_name")
    )
    requirements = role.requirement_definitions.filter(is_active=True)
    # Requirements that reach this role by flag rather than by explicit selection.
    from apps.requirements.models import RequirementDefinition

    applicable = RequirementDefinition.objects.active().for_role(role)

    return render(
        request,
        "org/role_detail.html",
        {
            "role": role,
            "assignments": assignments,
            "explicit_requirements": requirements,
            "applicable_requirements": applicable,
        },
    )


@login_required
@require_http_methods(["GET", "POST"])
def role_edit(request, pk: int):
    role = get_object_or_404(Role, pk=pk)
    before = {
        "name": role.name,
        "leadership": role.leadership,
        "is_position_of_trust": role.is_position_of_trust,
        "handles_personal_info": role.handles_personal_info,
        "is_active": role.is_active,
    }

    form = RoleForm(request.POST or None, instance=role)
    if request.method == "POST" and form.is_valid():
        form.save()
        after = {
            "name": role.name,
            "leadership": role.leadership,
            "is_position_of_trust": role.is_position_of_trust,
            "handles_personal_info": role.handles_personal_info,
            "is_active": role.is_active,
        }
        audit.record(
            AuditAction.UPDATE,
            "Role",
            entity_id=role.pk,
            entity_label=str(role),
            summary="Role updated",
            detail={"changed": diff_summary(before, after)},
        )
        # Flag changes alter who needs what; the signal handles the resync, this is
        # just to tell the admin it happened.
        if before != after:
            messages.info(
                request,
                "Requirements for everyone in this role have been recalculated.",
            )
        messages.success(request, "Role updated.")
        return redirect("org:role_detail", pk=role.pk)

    return render(request, "org/role_form.html", {"form": form, "role": role})


# ---------------------------------------------------------------------------
# Volunteers
# ---------------------------------------------------------------------------


@login_required
def volunteer_list(request):
    """
    The volunteer list, filtered on plaintext columns only.

    Names, departments, roles and statuses are all plaintext by design (PRD §5), which
    is what makes this page searchable at all — an encrypted name column would force a
    full decrypt of every row to answer "is there a Smith?".
    """
    form = VolunteerFilterForm(request.GET or None)
    volunteers = Volunteer.objects.all()

    status = ""
    if form.is_valid():
        status = form.cleaned_data.get("status") or ""
        term = form.cleaned_data.get("q")
        department = form.cleaned_data.get("department")
        role = form.cleaned_data.get("role")

        if term:
            volunteers = volunteers.search_by_name(term)
        if role:
            volunteers = volunteers.filter(
                assignments__role=role, assignments__is_active=True
            ).distinct()
        elif department:
            volunteers = volunteers.in_department(department)

        if status == "all":
            pass
        elif status == "inactive":
            volunteers = volunteers.filter(is_active=False)
        elif status == "unassigned":
            volunteers = volunteers.active().exclude(assignments__is_active=True)
        elif status == "blocked":
            volunteers = volunteers.blocked()
        elif status == "minors":
            today = timezone.localdate()
            # Under 18 by the same 1st-of-birth-month convention the age rules use.
            volunteers = volunteers.active().filter(
                Q(birth_year__gt=today.year - 18)
                | Q(birth_year=today.year - 18, birth_month__gt=today.month)
            )
        else:
            volunteers = volunteers.serving()

    volunteers = volunteers.prefetch_related(
        Prefetch(
            "assignments",
            queryset=RoleAssignment.objects.filter(is_active=True).select_related(
                "role", "role__department"
            ),
            to_attr="current_assignments",
        )
    ).annotate(
        outstanding=Count(
            "requirement_instances",
            filter=Q(requirement_instances__status__in=RequirementStatus.outstanding_values()),
            distinct=True,
        )
    )

    # Ordering has to be explicit here. Several of the filters above use distinct(), which
    # drops the model's Meta ordering, and paginating an unordered queryset means a row can
    # appear on two pages or on none.
    volunteers = volunteers.order_by("last_name", "first_name", "pk")

    paginator = Paginator(volunteers, PAGE_SIZE)
    page = paginator.get_page(request.GET.get("page"))

    context = {
        "form": form,
        "page": page,
        "volunteers": page.object_list,
        "total": paginator.count,
        "status": status,
    }
    # HTMX requests re-render just the table, so filtering feels instant.
    template = "org/_volunteer_table.html" if request.htmx else "org/volunteer_list.html"
    return render(request, template, context)


@login_required
@require_http_methods(["GET", "POST"])
def volunteer_create(request):
    form = VolunteerForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            volunteer = form.save()
            audit.record(
                AuditAction.CREATE,
                "Volunteer",
                entity_id=volunteer.pk,
                entity_label=volunteer.full_name,
                summary="Volunteer record created",
                # Only non-sensitive facts in the summary detail; the encrypted fields
                # are already stored encrypted on the record itself.
                detail={
                    "birth_year": volunteer.birth_year,
                    "birth_month": volunteer.birth_month,
                    "is_transfer": volunteer.is_transfer,
                },
            )
        messages.success(
            request,
            f"{volunteer.display_name} added. Assign a role to start their screening.",
        )
        return redirect("org:volunteer_detail", pk=volunteer.pk)

    return render(request, "org/volunteer_form.html", {"form": form, "volunteer": None})


@login_required
def volunteer_detail(request, pk: int):
    """
    The Ministry Personnel file.

    This is the one page that decrypts a volunteer's personal fields, so it is also the
    only place ``exact_age`` is used.
    """
    volunteer = get_object_or_404(Volunteer, pk=pk)

    instances = (
        volunteer.requirement_instances.select_related("definition")
        .order_by("definition__sequence", "definition__name")
    )
    onboarding = [i for i in instances if i.definition.is_onboarding]
    recurring = [i for i in instances if not i.definition.is_onboarding]

    assignments = volunteer.assignments.select_related("role", "role__department").order_by(
        "-is_active", "-started_on"
    )

    return render(
        request,
        "org/volunteer_detail.html",
        {
            "volunteer": volunteer,
            "onboarding": onboarding,
            "recurring": recurring,
            "assignments": assignments,
            "crc_records": volunteer.crc_records.prefetch_related("convictions", "overrides"),
            "documents": volunteer.documents.filter(is_current=True),
            "assignment_form": RoleAssignmentForm(volunteer=volunteer),
            "onboarding_overdue": onboarding_window_breached(volunteer),
            "buckets": _bucket_counts(instances),
        },
    )


def _bucket_counts(instances) -> dict:
    counts = {"overdue": 0, "due_soon": 0, "outstanding": 0, "satisfied": 0}
    for instance in instances:
        counts[instance.bucket] = counts.get(instance.bucket, 0) + 1
    return counts


@login_required
@require_http_methods(["GET", "POST"])
def volunteer_edit(request, pk: int):
    volunteer = get_object_or_404(Volunteer, pk=pk)
    before = _volunteer_snapshot(volunteer)

    form = VolunteerForm(request.POST or None, instance=volunteer)
    if request.method == "POST" and form.is_valid():
        form.save()
        audit.record(
            AuditAction.UPDATE,
            "Volunteer",
            entity_id=volunteer.pk,
            entity_label=volunteer.full_name,
            summary="Volunteer record updated",
            detail={"changed": diff_summary(before, _volunteer_snapshot(volunteer))},
        )
        messages.success(request, "Record updated.")
        return redirect("org:volunteer_detail", pk=volunteer.pk)

    return render(request, "org/volunteer_form.html", {"form": form, "volunteer": volunteer})


def _volunteer_snapshot(volunteer: Volunteer) -> dict:
    """
    Audit snapshot listing *which* fields changed, not their contents.

    Recording that the home address changed is useful; recording the old and new
    addresses would copy personal data into a second place. Only non-sensitive
    fields carry their values.
    """
    return {
        "first_name": volunteer.first_name,
        "last_name": volunteer.last_name,
        "preferred_name": volunteer.preferred_name,
        "birth_year": volunteer.birth_year,
        "birth_month": volunteer.birth_month,
        "attendance_since": str(volunteer.attendance_since or ""),
        "is_transfer": volunteer.is_transfer,
        "is_active": volunteer.is_active,
        # Presence only, deliberately.
        "has_email": bool(volunteer.email),
        "has_phone": bool(volunteer.phone),
        "has_address": bool(volunteer.address),
        "has_emergency_contact": bool(volunteer.emergency_contact),
        "has_medical_notes": bool(volunteer.medical_notes),
    }


@login_required
@require_http_methods(["GET", "POST"])
def volunteer_deactivate(request, pk: int):
    """
    Take a volunteer out of service. Never a deletion.

    The form makes the retention explicit on screen so nobody goes looking for a delete
    button that does not exist.
    """
    volunteer = get_object_or_404(Volunteer, pk=pk)

    if not volunteer.is_active:
        messages.info(request, f"{volunteer.display_name} is already marked as not serving.")
        return redirect("org:volunteer_detail", pk=volunteer.pk)

    form = VolunteerDeactivateForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            volunteer.is_active = False
            volunteer.stopped_serving_on = form.cleaned_data["stopped_serving_on"]
            volunteer.save(update_fields=["is_active", "stopped_serving_on", "updated_at"])

            ended = []
            if form.cleaned_data["end_assignments"]:
                for assignment in volunteer.assignments.filter(is_active=True).select_related("role"):
                    assignment.end(form.cleaned_data["stopped_serving_on"])
                    ended.append(assignment.role.name)

            audit.record(
                AuditAction.DEACTIVATE,
                "Volunteer",
                entity_id=volunteer.pk,
                entity_label=volunteer.full_name,
                summary=f"Marked as no longer serving ({volunteer.stopped_serving_on})",
                detail={
                    "reason": form.cleaned_data["reason"],
                    "assignments_ended": ended,
                    "record_retained": True,
                },
            )

        messages.success(
            request,
            f"{volunteer.display_name} is marked as no longer serving. Their file is "
            "retained permanently.",
        )
        return redirect("org:volunteer_detail", pk=volunteer.pk)

    return render(request, "org/volunteer_deactivate.html", {"form": form, "volunteer": volunteer})


@login_required
@require_POST
def volunteer_reactivate(request, pk: int):
    """Bring a volunteer back into service, unless permanently disqualified."""
    volunteer = get_object_or_404(Volunteer, pk=pk)

    if volunteer.is_permanently_disqualified:
        messages.error(
            request,
            "This volunteer is permanently disqualified from positions of trust under "
            "the Plan to Protect policy and cannot be reactivated into one.",
        )
        return redirect("org:volunteer_detail", pk=volunteer.pk)

    volunteer.is_active = True
    volunteer.stopped_serving_on = None
    volunteer.save(update_fields=["is_active", "stopped_serving_on", "updated_at"])

    audit.record(
        AuditAction.REACTIVATE,
        "Volunteer",
        entity_id=volunteer.pk,
        entity_label=volunteer.full_name,
        summary="Returned to active service",
    )
    messages.success(
        request,
        f"{volunteer.display_name} is active again. Assign a role to restart screening.",
    )
    return redirect("org:volunteer_detail", pk=volunteer.pk)


# ---------------------------------------------------------------------------
# Role assignments
# ---------------------------------------------------------------------------


@login_required
@require_POST
def assignment_create(request, pk: int):
    """
    Place a volunteer in a role.

    Assigning a role is what makes requirements apply, so the resync runs immediately
    (via the post_save signal) and the resulting count is reported back.
    """
    volunteer = get_object_or_404(Volunteer, pk=pk)
    form = RoleAssignmentForm(request.POST, volunteer=volunteer)

    if not form.is_valid():
        for error in form.errors.values():
            messages.error(request, "; ".join(error))
        return redirect("org:volunteer_detail", pk=volunteer.pk)

    assignment = form.save()
    # The signal syncs on commit; call it directly too so the count below is accurate
    # for the message shown on this response. Sync is idempotent.
    result = sync_volunteer_requirements(volunteer)

    audit.record(
        AuditAction.CREATE,
        "RoleAssignment",
        entity_id=assignment.pk,
        entity_label=f"{volunteer.full_name} → {assignment.role}",
        summary=f"Assigned to {assignment.role.name} ({assignment.role.department.name})",
        detail={"started_on": str(assignment.started_on), "requirements": result},
    )
    messages.success(
        request,
        f"{volunteer.display_name} assigned to {assignment.role.name}."
        + (
            f" {result['created']} requirement(s) now apply."
            if result["created"]
            else ""
        ),
    )
    return redirect("org:volunteer_detail", pk=volunteer.pk)


@login_required
@require_POST
def assignment_end(request, pk: int):
    """End an assignment, keeping the historical row."""
    assignment = get_object_or_404(
        RoleAssignment.objects.select_related("volunteer", "role"), pk=pk, is_active=True
    )
    form = RoleAssignmentEndForm(request.POST)
    ended_on = form.cleaned_data["ended_on"] if form.is_valid() else timezone.localdate()

    assignment.end(ended_on)
    result = sync_volunteer_requirements(assignment.volunteer)

    audit.record(
        AuditAction.UPDATE,
        "RoleAssignment",
        entity_id=assignment.pk,
        entity_label=f"{assignment.volunteer.full_name} → {assignment.role}",
        summary=f"Assignment ended ({ended_on})",
        detail={"ended_on": str(ended_on), "requirements": result},
    )
    messages.success(
        request,
        f"{assignment.volunteer.display_name} no longer serves as {assignment.role.name}."
        + (
            f" {result['retired']} requirement(s) no longer apply."
            if result["retired"]
            else ""
        ),
    )
    return redirect("org:volunteer_detail", pk=assignment.volunteer.pk)


@login_required
@require_POST
def volunteer_resync(request, pk: int):
    """
    Recalculate a volunteer's requirements on demand.

    The nightly job does this for everyone; this button exists for an admin who has
    just changed something and wants to see the effect now.
    """
    volunteer = get_object_or_404(Volunteer, pk=pk)
    try:
        result = sync_volunteer_requirements(volunteer)
    except ValidationError as exc:
        messages.error(request, "; ".join(exc.messages))
    else:
        messages.success(
            request,
            "Requirements recalculated: "
            f"{result['created']} added, {result['updated']} updated, "
            f"{result['retired']} no longer applicable.",
        )
    return redirect("org:volunteer_detail", pk=volunteer.pk)
