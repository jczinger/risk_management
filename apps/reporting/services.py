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
from collections import defaultdict
from dataclasses import dataclass, field

from django.db.models import Count, F, Prefetch, Q
from django.utils import timezone

from apps.core.access import (
    scope_departments,
    scope_instances,
    scope_roles,
    scope_volunteers,
)
from apps.org.models import Department, Role, RoleAssignment, Volunteer
from apps.requirements.models import DUE_SOON_DAYS, RequirementInstance


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

def instance_queryset(
    *,
    department: Department | None = None,
    role: Role | None = None,
    requirement_type: str = "",
    user=None,
):
    """
    The dashboard's filtered instance queryset (see :func:`build_buckets`).

    ``user`` is the **access scope** and is applied first; ``department`` and ``role`` are
    the reader's chosen *filters* and narrow it further. Keeping them separate matters,
    because they ask different questions and use different rules: a filter on a
    department means "who serves there now", while the scope means "whose file belongs to
    my departments, now or in the past". Passing ``user=None`` scopes nothing, which is
    what the nightly job and the seeders want.
    """
    queryset = RequirementInstance.objects.select_related(
        "volunteer", "definition"
    ).filter(definition__is_active=True, volunteer__is_active=True)

    queryset = scope_instances(queryset, user)

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
    user=None,
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
        department=department, role=role, requirement_type=requirement_type, user=user
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
    user=None,
) -> dict:
    """
    The compliance report: every volunteer × every requirement that applies to them.

    Shaped for handing to an insurer or a board — a per-volunteer verdict with the
    detail behind it, scoped church-wide or to one department (Build Spec §8).

    Note the two department filters below, which look redundant and are not.
    ``scope_volunteers`` applies the caller's *access* — volunteers who have ever served
    in their departments — and ``in_department`` applies the reader's chosen *filter*,
    which asks who serves there now. Both have to be present: dropping the first leaks,
    and dropping the second changes what the report means.
    """
    as_of = as_of or timezone.localdate()

    volunteers = scope_volunteers(Volunteer.objects.all(), user)
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

    # A count, not a flag: the report needs to say how many of its figures rest on
    # unaffirmed evidence. ``is_compliant`` and ``status_label`` are deliberately left
    # alone — a pending entry counts as compliant, which was the owner's decision, and
    # this note is what keeps that honest for whoever reads the report.
    from apps.review.models import ReviewItem

    unverified = ReviewItem.objects.pending().filter(
        volunteer__in=[row.volunteer.pk for row in rows]
    )
    unverified_count = unverified.count()
    oldest = unverified.order_by("created_at").values_list("created_at", flat=True).first()

    return {
        "as_of": as_of,
        "department": department,
        "requirement_type": requirement_type,
        "unverified_count": unverified_count,
        "unverified_volunteers": unverified.values("volunteer_id").distinct().count(),
        "unverified_oldest_days": (timezone.now() - oldest).days if oldest else None,
        "rows": rows,
        "compliant": compliant,
        "non_compliant": non_compliant,
        "total": len(rows),
        "compliant_count": len(compliant),
        "non_compliant_count": len(non_compliant),
        "compliance_rate": round(100 * len(compliant) / len(rows)) if rows else None,
        "due_soon_days": DUE_SOON_DAYS,
    }


def bucket_counts(instances) -> dict:
    """How many of these instances fall in each dashboard bucket."""
    counts = {"overdue": 0, "due_soon": 0, "outstanding": 0, "satisfied": 0}
    for instance in instances:
        counts[instance.bucket] += 1
    return counts


def volunteer_file_core(volunteer: Volunteer) -> dict:
    """
    The queries the volunteer's detail page and printed file share: the ordered
    requirement list with its "unverified" annotations, the onboarding/recurring
    split, and the bucket counts.

    The annotation is one indexed query for the whole page, then plain attributes.
    There is no relation to prefetch — a review item points at its subject with a
    pair of strings — so the alternative would be a query per rendered row. Every
    render path that shows a requirement row has to come through here, or a page
    quietly loses its "unverified" badge.
    """
    from apps.review.recording import open_review_index

    instances = list(
        volunteer.requirement_instances.select_related("definition").order_by(
            "definition__sequence", "definition__name"
        )
    )
    index = open_review_index(volunteer=volunteer)
    index.annotate(instances, entity_type="RequirementInstance")

    return {
        "instances": instances,
        "review_index": index,
        "onboarding": [i for i in instances if i.definition.is_onboarding],
        "recurring": [i for i in instances if not i.definition.is_onboarding],
        "buckets": bucket_counts(instances),
    }


def build_department_summary(as_of: datetime.date | None = None, user=None) -> list[dict]:
    """
    Per-department roll-up for the dashboard and the report's header.

    Scoped, and this is the sort of leak that survives a per-row test: none of the
    numbers here is a name, so "can a department admin open volunteer X?" passes while
    the dashboard quietly lists every department at the church with its volunteer count
    and how many of them are behind.
    """
    as_of = as_of or timezone.localdate()

    departments = list(
        scope_departments(Department.objects.filter(is_active=True), user).annotate(
            volunteer_count=Count(
                "roles__assignments__volunteer",
                filter=Q(
                    roles__assignments__is_active=True,
                    roles__assignments__volunteer__is_active=True,
                ),
                distinct=True,
            )
        )
    )

    # One instances query for every department, grouped in Python — this used to be two
    # queries per department. The join through active assignments fans out one row per
    # (instance, department served), which is the grouping the summary wants: an
    # instance legitimately counts in every department its volunteer serves. The same
    # volunteer holding two roles in ONE department would fan out twice, so rows are
    # deduplicated per (department, instance).
    instances = (
        RequirementInstance.objects.select_related("definition", "volunteer")
        .filter(
            definition__is_active=True,
            volunteer__is_active=True,
            volunteer__assignments__is_active=True,
            volunteer__assignments__role__department__in=departments,
        )
        .annotate(served_department_id=F("volunteer__assignments__role__department"))
    )

    grouped: dict[int, list] = defaultdict(list)
    seen: set[tuple[int, int]] = set()
    for instance in instances:
        key = (instance.served_department_id, instance.pk)
        if key in seen:
            continue
        seen.add(key)
        grouped[instance.served_department_id].append(instance)

    summary = []
    for department in departments:
        instances_here = grouped.get(department.pk, [])
        counts = bucket_counts(instances_here)
        summary.append(
            {
                "department": department,
                "volunteers": department.volunteer_count,
                "requirements": len(instances_here),
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
    core = volunteer_file_core(volunteer)

    crc_records = list(
        volunteer.crc_records.prefetch_related("convictions", "overrides").order_by(
            "-report_date"
        )
    )
    documents = list(volunteer.documents.order_by("-document_date", "-created_at"))

    return {
        "volunteer": volunteer,
        "as_of": as_of,
        "onboarding": core["onboarding"],
        "recurring": core["recurring"],
        "assignments": volunteer.assignments.select_related("role", "role__department").order_by(
            "-is_active", "-started_on"
        ),
        "crc_records": crc_records,
        "documents": documents,
        "buckets": core["buckets"],
    }


def dashboard_headline(as_of: datetime.date | None = None, user=None) -> dict:
    """
    Counts for the dashboard's summary tiles.

    Every one of these is scoped, including the three that are easiest to overlook
    because they name nobody: ``blocked`` and ``minors`` are counts of sensitive
    categories, and ``departments``/``roles`` describe the shape of the whole church. A
    scoped admin's tiles should describe their own departments, not the church's.
    """
    as_of = as_of or timezone.localdate()

    volunteers = scope_volunteers(Volunteer.objects.all(), user).active()
    active_volunteers = volunteers.count()
    serving = volunteers.filter(assignments__is_active=True).distinct().count()
    return {
        "active_volunteers": active_volunteers,
        "serving": serving,
        # Everyone active either serves or does not — derived, not a third query.
        "unassigned": active_volunteers - serving,
        "blocked": scope_volunteers(Volunteer.objects.all(), user).blocked().count(),
        "departments": scope_departments(
            Department.objects.filter(is_active=True), user
        ).count(),
        "roles": scope_roles(Role.objects.filter(is_active=True), user).count(),
        "minors": volunteers.filter(
            Q(birth_year__gt=as_of.year - 18)
            | Q(birth_year=as_of.year - 18, birth_month__gt=as_of.month)
        ).count(),
    }
