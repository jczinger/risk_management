"""
Report assembly.

Everything here works from the **plaintext** columns — names, department, role,
requirement type, status, dates. That is what makes a compliance report over hundreds
of volunteers a handful of queries rather than hundreds of decryptions, and it is why
the plaintext/encrypted split in PRD §5 was drawn where it was.

The one exception is the individual volunteer file, which decrypts one person's fields
by design.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from django.db.models import Count, Prefetch, Q
from django.utils import timezone

from apps.org.models import Department, Role, RoleAssignment, Volunteer
from apps.requirements.models import (
    DUE_SOON_DAYS,
    RequirementDefinition,
    RequirementInstance,
    RequirementStatus,
)


@dataclass
class Buckets:
    """The dashboard's three columns, plus outstanding onboarding work."""

    overdue: list = field(default_factory=list)
    due_soon: list = field(default_factory=list)
    outstanding: list = field(default_factory=list)
    satisfied: list = field(default_factory=list)

    @property
    def counts(self) -> dict:
        return {
            "overdue": len(self.overdue),
            "due_soon": len(self.due_soon),
            "outstanding": len(self.outstanding),
            "satisfied": len(self.satisfied),
        }

    @property
    def action_needed(self) -> int:
        return len(self.overdue) + len(self.due_soon) + len(self.outstanding)


def instance_queryset(
    *,
    department: Department | None = None,
    role: Role | None = None,
    requirement_type: str = "",
    include_inactive_volunteers: bool = False,
):
    """The filtered instance queryset every report and the dashboard share."""
    queryset = RequirementInstance.objects.select_related(
        "volunteer", "definition"
    ).filter(definition__is_active=True)

    if not include_inactive_volunteers:
        queryset = queryset.filter(volunteer__is_active=True)

    if role is not None:
        queryset = queryset.filter(
            volunteer__assignments__role=role, volunteer__assignments__is_active=True
        ).distinct()
    elif department is not None:
        queryset = queryset.filter(
            volunteer__assignments__role__department=department,
            volunteer__assignments__is_active=True,
        ).distinct()

    if requirement_type:
        queryset = queryset.filter(definition__requirement_type=requirement_type)

    return queryset


def build_buckets(
    *,
    department: Department | None = None,
    role: Role | None = None,
    requirement_type: str = "",
    as_of: datetime.date | None = None,
) -> Buckets:
    """
    Sort every relevant requirement into the dashboard's buckets.

    Bucketing happens in Python via :attr:`RequirementInstance.bucket` rather than in
    SQL: the rule combines two independent clocks (renewal expiry and one-off deadline)
    and the blocked state, and expressing that as a CASE expression would put the same
    logic in two places.
    """
    as_of = as_of or timezone.localdate()
    buckets = Buckets()

    for instance in instance_queryset(
        department=department, role=role, requirement_type=requirement_type
    ):
        getattr(buckets, instance.bucket).append(instance)

    buckets.overdue.sort(key=lambda i: (i.effective_due_date or as_of, i.volunteer.sort_name))
    buckets.due_soon.sort(key=lambda i: (i.effective_due_date or as_of, i.volunteer.sort_name))
    buckets.outstanding.sort(key=lambda i: (i.volunteer.sort_name, i.definition.sequence))
    return buckets


@dataclass
class VolunteerRow:
    """One row of the compliance report: a volunteer and their standing."""

    volunteer: Volunteer
    instances: list
    roles: list

    @property
    def overdue_count(self) -> int:
        return sum(1 for i in self.instances if i.bucket == "overdue")

    @property
    def due_soon_count(self) -> int:
        return sum(1 for i in self.instances if i.bucket == "due_soon")

    @property
    def outstanding_count(self) -> int:
        return sum(1 for i in self.instances if i.bucket == "outstanding")

    @property
    def is_compliant(self) -> bool:
        """
        Compliant means nothing is owed *right now*.

        Coming-due items do not break compliance — they are the warning that it is
        about to break.
        """
        return self.overdue_count == 0 and self.outstanding_count == 0

    @property
    def status_label(self) -> str:
        if self.volunteer.is_permanently_disqualified:
            return "Disqualified"
        if self.volunteer.is_blocked:
            return "Blocked"
        if self.overdue_count:
            return "Overdue"
        if self.outstanding_count:
            return "In progress"
        if self.due_soon_count:
            return "Coming due"
        return "Compliant"


def build_compliance_report(
    *,
    department: Department | None = None,
    requirement_type: str = "",
    include_inactive: bool = False,
    as_of: datetime.date | None = None,
) -> dict:
    """
    The compliance report: every volunteer × every requirement that applies to them.

    Shaped for handing to an insurer or a board — a per-volunteer verdict with the
    detail behind it, scoped church-wide or to one department (Build Spec §8).
    """
    as_of = as_of or timezone.localdate()

    volunteers = Volunteer.objects.all()
    if not include_inactive:
        volunteers = volunteers.active()
    if department is not None:
        volunteers = volunteers.in_department(department)

    instance_prefetch = RequirementInstance.objects.select_related("definition").filter(
        definition__is_active=True
    )
    if requirement_type:
        instance_prefetch = instance_prefetch.filter(
            definition__requirement_type=requirement_type
        )

    volunteers = volunteers.prefetch_related(
        Prefetch("requirement_instances", queryset=instance_prefetch, to_attr="report_instances"),
        Prefetch(
            "assignments",
            queryset=RoleAssignment.objects.filter(is_active=True).select_related(
                "role", "role__department"
            ),
            to_attr="report_assignments",
        ),
    ).order_by("last_name", "first_name")

    rows = [
        VolunteerRow(
            volunteer=volunteer,
            instances=sorted(
                volunteer.report_instances,
                key=lambda i: (i.definition.sequence, i.definition.name),
            ),
            roles=[a.role for a in volunteer.report_assignments],
        )
        for volunteer in volunteers
    ]

    compliant = [r for r in rows if r.is_compliant]
    non_compliant = [r for r in rows if not r.is_compliant]

    return {
        "as_of": as_of,
        "department": department,
        "requirement_type": requirement_type,
        "rows": rows,
        "compliant": compliant,
        "non_compliant": non_compliant,
        "total": len(rows),
        "compliant_count": len(compliant),
        "non_compliant_count": len(non_compliant),
        "compliance_rate": round(100 * len(compliant) / len(rows)) if rows else None,
        "definitions": RequirementDefinition.objects.active(),
        "due_soon_days": DUE_SOON_DAYS,
    }


def build_department_summary(as_of: datetime.date | None = None) -> list[dict]:
    """Per-department roll-up for the dashboard and the report's header."""
    as_of = as_of or timezone.localdate()
    summary = []

    for department in Department.objects.filter(is_active=True):
        instances = list(
            RequirementInstance.objects.select_related("definition", "volunteer")
            .filter(
                definition__is_active=True,
                volunteer__is_active=True,
                volunteer__assignments__role__department=department,
                volunteer__assignments__is_active=True,
            )
            .distinct()
        )
        counts = {"overdue": 0, "due_soon": 0, "outstanding": 0, "satisfied": 0}
        for instance in instances:
            counts[instance.bucket] += 1

        volunteer_count = (
            Volunteer.objects.filter(
                assignments__role__department=department,
                assignments__is_active=True,
                is_active=True,
            )
            .distinct()
            .count()
        )

        summary.append(
            {
                "department": department,
                "volunteers": volunteer_count,
                "requirements": len(instances),
                **counts,
                "needs_action": counts["overdue"] + counts["outstanding"],
            }
        )

    return summary


def build_volunteer_file(volunteer: Volunteer, as_of: datetime.date | None = None) -> dict:
    """
    The complete Ministry Personnel file for one person (Build Spec §8).

    This is the one report that decrypts personal fields — it is a single volunteer's
    own file, printed for their record or for an audit.
    """
    as_of = as_of or timezone.localdate()

    instances = list(
        volunteer.requirement_instances.select_related("definition").order_by(
            "definition__sequence", "definition__name"
        )
    )

    return {
        "volunteer": volunteer,
        "as_of": as_of,
        "onboarding": [i for i in instances if i.definition.is_onboarding],
        "recurring": [i for i in instances if not i.definition.is_onboarding],
        "assignments": volunteer.assignments.select_related("role", "role__department").order_by(
            "-is_active", "-started_on"
        ),
        "crc_records": volunteer.crc_records.prefetch_related(
            "convictions", "overrides"
        ).order_by("-report_date"),
        "documents": volunteer.documents.order_by("-document_date", "-created_at"),
        "buckets": {
            key: sum(1 for i in instances if i.bucket == key)
            for key in ("overdue", "due_soon", "outstanding", "satisfied")
        },
    }


def dashboard_headline(as_of: datetime.date | None = None) -> dict:
    """Counts for the dashboard's summary tiles."""
    as_of = as_of or timezone.localdate()

    volunteers = Volunteer.objects.active()
    return {
        "active_volunteers": volunteers.count(),
        "serving": volunteers.filter(assignments__is_active=True).distinct().count(),
        "unassigned": volunteers.exclude(assignments__is_active=True).count(),
        "blocked": Volunteer.objects.blocked().count(),
        "departments": Department.objects.filter(is_active=True).count(),
        "roles": Role.objects.filter(is_active=True).count(),
        "minors": volunteers.filter(
            Q(birth_year__gt=as_of.year - 18)
            | Q(birth_year=as_of.year - 18, birth_month__gt=as_of.month)
        ).count(),
    }
