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
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Prefetch, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST, require_http_methods

from apps.core import audit
from apps.core.access import (
    Capability,
    may_record_against,
    require_own_record_not_touched,
    requires,
    scope_assignments,
    scope_departments,
    scope_roles,
    scope_volunteers,
)
from apps.core.models import AuditAction, diff_summary
from apps.requirements.models import RequirementStatus
from apps.requirements.services import onboarding_window_breached, sync_volunteer_requirements
from apps.reporting.services import volunteer_file_core

from .forms import (
    DepartmentForm,
    RoleAssignmentEndForm,
    RoleAssignmentForm,
    RoleForm,
    VolunteerDeactivateForm,
    VolunteerFilterForm,
    VolunteerForm,
)
from .models import Department, Role, RoleAssignment, Volunteer

logger = logging.getLogger("vms.org")

PAGE_SIZE = 25


# ---------------------------------------------------------------------------
# Scoped lookups
# ---------------------------------------------------------------------------
#
# Every detail view fetches its subject through one of these rather than through a bare
# ``get_object_or_404(Model, pk=pk)``. Two reasons, and the second is the important one:
#
# * A record outside the caller's departments must 404, not 403 — a 403 would confirm
#   that this church has a volunteer with that id and that they are in some *other*
#   department, which walked over the id range is a membership list. See
#   :mod:`apps.core.access`.
# * Narrowing the queryset means the check cannot be forgotten separately from the
#   fetch. A trailing ``if`` is a second statement, and the version of this code with
#   the ``if`` missing looks fine and fails open.


def _volunteer_or_404(request, pk: int, queryset=None):
    queryset = Volunteer.objects.all() if queryset is None else queryset
    return get_object_or_404(scope_volunteers(queryset, request.user), pk=pk)


def _writable_volunteer_or_404(request, pk: int, queryset=None):
    """
    The same lookup, for a view that is about to *change* something.

    Two refusals stacked in one call, for the same reason the scoping lives inside the
    fetch: a caller cannot take the record without also taking both checks. Out of
    scope still 404s; your own screening file 403s, because you can already see it and
    a vanishing act would be a lie. See :mod:`apps.core.access`.
    """
    volunteer = _volunteer_or_404(request, pk, queryset)
    require_own_record_not_touched(request.user, volunteer)
    return volunteer


def _department_or_404(request, pk: int, queryset=None):
    queryset = Department.objects.all() if queryset is None else queryset
    return get_object_or_404(scope_departments(queryset, request.user), pk=pk)


def _role_or_404(request, pk: int, queryset=None):
    queryset = Role.objects.all() if queryset is None else queryset
    return get_object_or_404(scope_roles(queryset, request.user), pk=pk)


# ---------------------------------------------------------------------------
# Departments
# ---------------------------------------------------------------------------


@requires(Capability.VIEW_VOLUNTEERS)
def department_list(request):
    departments = scope_departments(Department.objects.all(), request.user).annotate(
        role_count=Count("roles", filter=Q(roles__is_active=True), distinct=True),
        volunteer_count=Count(
            "roles__assignments__volunteer",
            filter=Q(
                roles__assignments__is_active=True,
                roles__assignments__volunteer__is_active=True,
            ),
            distinct=True,
        ),
    )
    return render(request, "org/department_list.html", {"departments": departments})


@requires(Capability.MANAGE_ORG)
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


@requires(Capability.VIEW_VOLUNTEERS)
def department_detail(request, pk: int):
    department = _department_or_404(request, pk)
    roles = department.roles.annotate(
        holders=Count("assignments", filter=Q(assignments__is_active=True), distinct=True)
    )
    return render(
        request,
        "org/department_detail.html",
        {"department": department, "roles": roles},
    )


@requires(Capability.MANAGE_ORG)
@require_http_methods(["GET", "POST"])
def department_edit(request, pk: int):
    department = _department_or_404(request, pk)
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


@requires(Capability.VIEW_VOLUNTEERS)
def role_list(request):
    roles = (
        scope_roles(Role.objects.all(), request.user)
        .select_related("department")
        .annotate(holders=Count("assignments", filter=Q(assignments__is_active=True), distinct=True))
        .order_by("department__name", "name")
    )
    return render(request, "org/role_list.html", {"roles": roles})


@requires(Capability.MANAGE_ORG)
@require_http_methods(["GET", "POST"])
def role_create(request):
    initial = {}
    department_id = request.GET.get("department")
    if department_id:
        initial["department"] = department_id

    form = RoleForm(request.POST or None, initial=initial, user=request.user)
    if request.method == "POST" and form.is_valid():
        role = form.save()
        audit.record(
            AuditAction.CREATE,
            "Role",
            entity_id=role.pk,
            entity_label=str(role),
            summary=f"Role created in {role.department.name}",
            detail={
                "leadership": role.is_leadership,
            },
        )
        messages.success(request, f"Role '{role.name}' created.")
        return redirect("org:role_detail", pk=role.pk)

    return render(request, "org/role_form.html", {"form": form, "role": None})


@requires(Capability.VIEW_VOLUNTEERS)
def role_detail(request, pk: int):
    role = _role_or_404(request, pk, Role.objects.select_related("department"))
    # The holders of a role in a department the caller administers are in scope by
    # construction — they hold a role in that department — so this list needs no
    # scoping of its own.
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


@requires(Capability.MANAGE_ORG)
@require_http_methods(["GET", "POST"])
def role_edit(request, pk: int):
    role = _role_or_404(request, pk)
    before = {
        "name": role.name,
        "leadership": role.is_leadership,
        "is_active": role.is_active,
    }

    form = RoleForm(request.POST or None, instance=role, user=request.user)
    if request.method == "POST" and form.is_valid():
        form.save()
        after = {
            "name": role.name,
            "leadership": role.is_leadership,
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


@requires(Capability.VIEW_VOLUNTEERS)
def volunteer_list(request):
    """
    The volunteer list, filtered on plaintext columns only.

    Names, departments, roles and statuses are all plaintext by design (PRD §5), which
    is what makes this page searchable at all — an encrypted name column would force a
    full decrypt of every row to answer "is there a Smith?".
    """
    form = VolunteerFilterForm(request.GET or None, user=request.user)
    # Scoped **first**, before any of the filter branches below. Two reasons: a filter
    # must only ever narrow what the caller may already see, and putting it here means
    # there is one line to check rather than one per branch.
    volunteers = scope_volunteers(Volunteer.objects.all(), request.user)

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
    #
    # Access scoping is now a third source of distinct(), and the one that applies to
    # *every* request rather than only to a filtered one: scope_volunteers joins through
    # assignments, so a volunteer holding two roles in the same scoped department would
    # otherwise be returned twice. The `outstanding` annotation above counts a different
    # relation with distinct=True and so stays correct either way — which is exactly why
    # a test pins the two-roles-one-department case, since it is invisible until a real
    # church has one.
    volunteers = volunteers.order_by("last_name", "first_name", "pk")

    paginator = Paginator(volunteers, PAGE_SIZE)
    page = paginator.get_page(request.GET.get("page"))

    # The pager links must carry the active filters, or paging silently resets them.
    filter_params = request.GET.copy()
    filter_params.pop("page", None)

    context = {
        "form": form,
        "page": page,
        "volunteers": page.object_list,
        "total": paginator.count,
        "status": status,
        "filter_query": filter_params.urlencode(),
    }
    # HTMX requests re-render just the table, so filtering feels instant.
    template = "org/_volunteer_table.html" if request.htmx else "org/volunteer_list.html"
    return render(request, template, context)


@requires(Capability.EDIT_VOLUNTEERS)
@require_http_methods(["GET", "POST"])
def volunteer_create(request):
    """
    Add a volunteer, and put them in a ministry role in the same step.

    The starting role is required, and that is a consequence of department scoping
    rather than a preference. A volunteer reaches a department only through a role
    assignment, so a volunteer created without one belongs to no department — and the
    department admin who just created them would immediately lose sight of them. Asking
    for the role here means there is no such state to explain, and no second visibility
    rule to write.

    A scoped admin may only choose roles in their own departments, so they cannot use
    intake to place someone outside their scope. See ``VolunteerForm``.
    """
    form = VolunteerForm(request.POST or None, user=request.user)

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
            role = form.cleaned_data["starting_role"]
            # Inside the same transaction: RoleAssignment.clean() refuses a disqualified
            # volunteer, and a create that half-succeeded would leave a volunteer in the
            # very department-less state this form exists to prevent.
            assignment = RoleAssignment(volunteer=volunteer, role=role)
            assignment.full_clean()
            assignment.save()
            audit.record(
                AuditAction.CREATE,
                "RoleAssignment",
                entity_id=assignment.pk,
                entity_label=f"{volunteer.full_name} → {role}",
                summary=f"Assigned to {role} on creation",
            )
            sync_volunteer_requirements(volunteer)

        messages.success(
            request,
            f"{volunteer.display_name} added as {role}. Their screening requirements are ready.",
        )
        return redirect("org:volunteer_detail", pk=volunteer.pk)

    return render(request, "org/volunteer_form.html", {"form": form, "volunteer": None})


@requires(Capability.VIEW_VOLUNTEERS)
def volunteer_detail(request, pk: int):
    """
    The Ministry Personnel file.

    This is the one page that decrypts a volunteer's personal fields, so it is also the
    only place ``exact_age`` is used.

    A department admin sees the whole record, same as a Primary Admin — the boundary is
    *which* volunteers they can open, not how much of each. That was the owner's
    decision; see BUILD_NOTES §1.21.
    """
    volunteer = _volunteer_or_404(request, pk)

    # The requirement list, its "unverified" badges and the bucket counts are shared
    # with the printed file (Build Spec §8) — one assembler, so the two cannot drift.
    core = volunteer_file_core(volunteer)

    assignments = volunteer.assignments.select_related("role", "role__department").order_by(
        "-is_active", "-started_on"
    )

    may_record, refusal = may_record_against(request.user, volunteer)

    return render(
        request,
        "org/volunteer_detail.html",
        {
            "volunteer": volunteer,
            "onboarding": core["onboarding"],
            "recurring": core["recurring"],
            "assignments": assignments,
            "crc_records": volunteer.crc_records.prefetch_related("convictions", "overrides"),
            "documents": volunteer.documents.filter(is_current=True),
            "assignment_form": RoleAssignmentForm(volunteer=volunteer, user=request.user),
            "onboarding_overdue": onboarding_window_breached(volunteer),
            "buckets": core["buckets"],
            "unverified_count": len(core["review_index"]),
            # Reading is never refused; only writing is. The template hides the action
            # buttons and says why, because a visible button that 403s is a support call
            # per click — and here the reason is one the person needs to understand
            # rather than work around.
            "may_record": may_record,
            "may_record_refusal": refusal,
        },
    )


@requires(Capability.EDIT_VOLUNTEERS)
@require_http_methods(["GET", "POST"])
def volunteer_edit(request, pk: int):
    volunteer = _writable_volunteer_or_404(request, pk)
    before = _volunteer_snapshot(volunteer)

    # No ``starting_role`` on an edit: this volunteer already has assignments, and the
    # form drops the field when it has an instance. See VolunteerForm.
    form = VolunteerForm(request.POST or None, instance=volunteer, user=request.user)
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


@requires(Capability.EDIT_VOLUNTEERS)
@require_http_methods(["GET", "POST"])
def volunteer_deactivate(request, pk: int):
    """
    Take a volunteer out of service. Never a deletion.

    The form makes the retention explicit on screen so nobody goes looking for a delete
    button that does not exist.
    """
    volunteer = _writable_volunteer_or_404(request, pk)

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


@requires(Capability.EDIT_VOLUNTEERS)
@require_POST
def volunteer_reactivate(request, pk: int):
    """Bring a volunteer back into service, unless permanently disqualified."""
    volunteer = _writable_volunteer_or_404(request, pk)

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


@requires(Capability.MANAGE_ASSIGNMENTS)
@require_POST
def assignment_create(request, pk: int):
    """
    Place a volunteer in a role.

    Assigning a role is what makes requirements apply, so the resync runs immediately
    (via the post_save signal) and the resulting count is reported back.

    Worth being explicit about one consequence for a scoped admin: because scope is
    "ever held a role here", assigning somebody permanently adds them to what this
    admin can see, and ending the assignment later does not take it away. They can only
    do it through their *own* departments — both the volunteer lookup and the form's
    role choices are scoped — but within those, this is how someone enters their view.
    That is intended; see BUILD_NOTES §1.21.
    """
    volunteer = _writable_volunteer_or_404(request, pk)
    form = RoleAssignmentForm(request.POST, volunteer=volunteer, user=request.user)

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


@requires(Capability.MANAGE_ASSIGNMENTS)
@require_POST
def assignment_end(request, pk: int):
    """
    End an assignment, keeping the historical row.

    Scoped by the assignment's **own** department, not by its volunteer's. The
    difference is a real hole rather than a nicety: a volunteer serving in both Youth
    and Music is in a Youth admin's scope, so scoping by volunteer would let that admin
    end the Music assignment — turning "end an assignment" into a way of reaching into
    a department they do not administer.

    Ending someone's last active assignment also marks them as no longer serving. A
    volunteer must always belong to a department, and the ended assignment is what keeps
    that true: it stays on the record, so the department's admin can still open the file
    of somebody they screened. That is why scope is "ever held a role" rather than
    "holds one now".
    """
    assignment = get_object_or_404(
        scope_assignments(
            RoleAssignment.objects.select_related("volunteer", "role"), request.user
        ),
        pk=pk,
        is_active=True,
    )
    # Ending your own assignment changes which requirements apply to you, so it is a
    # write against your own screening file by another name.
    require_own_record_not_touched(request.user, assignment.volunteer)

    form = RoleAssignmentEndForm(request.POST)
    ended_on = form.cleaned_data["ended_on"] if form.is_valid() else timezone.localdate()

    volunteer = assignment.volunteer
    with transaction.atomic():
        assignment.end(ended_on)
        # Counted after ending this one, so it answers "any left?" rather than "any
        # besides this?".
        still_serving = volunteer.assignments.filter(is_active=True).exists()
        if not still_serving and volunteer.is_active:
            volunteer.is_active = False
            volunteer.stopped_serving_on = ended_on
            volunteer.save(update_fields=["is_active", "stopped_serving_on", "updated_at"])
            audit.record(
                AuditAction.DEACTIVATE,
                "Volunteer",
                entity_id=volunteer.pk,
                entity_label=volunteer.full_name,
                summary=f"No longer serving — last assignment ended ({ended_on})",
            )
        result = sync_volunteer_requirements(volunteer)

    audit.record(
        AuditAction.UPDATE,
        "RoleAssignment",
        entity_id=assignment.pk,
        entity_label=f"{volunteer.full_name} → {assignment.role}",
        summary=f"Assignment ended ({ended_on})",
        detail={"ended_on": str(ended_on), "requirements": result},
    )
    messages.success(
        request,
        f"{volunteer.display_name} no longer serves as {assignment.role.name}."
        + ("" if still_serving else " They are now marked as no longer serving.")
        + (
            f" {result['retired']} requirement(s) no longer apply."
            if result["retired"]
            else ""
        ),
    )
    return redirect("org:volunteer_detail", pk=volunteer.pk)


@requires(Capability.EDIT_VOLUNTEERS)
@require_POST
def volunteer_resync(request, pk: int):
    """
    Recalculate a volunteer's requirements on demand.

    The nightly job does this for everyone; this button exists for an admin who has
    just changed something and wants to see the effect now.
    """
    volunteer = _writable_volunteer_or_404(request, pk)
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
