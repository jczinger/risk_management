"""
Dashboard, compliance reports and the audit trail viewer.

PDF export uses WeasyPrint when it is available and falls back to the print-optimised
HTML otherwise — the import can fail at runtime if the system's Pango/Cairo libraries
are missing, and a missing PDF button is a better outcome than a 500 on a report an
admin needs.
"""

from __future__ import annotations

import datetime
import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.utils import timezone

from apps.core.models import AuditAction, AuditEvent
from apps.org.models import Department, Role, Volunteer
from apps.requirements.forms import RequirementFilterForm

from .services import (
    build_buckets,
    build_compliance_report,
    build_department_summary,
    build_volunteer_file,
    dashboard_headline,
)

logger = logging.getLogger("vms.reporting")

AUDIT_PAGE_SIZE = 50


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@login_required
def dashboard(request):
    """
    The screening admin's home page.

    Three buckets — overdue, coming due within 60 days, compliant — filterable by
    department, role and requirement type (Build Spec §7).
    """
    form = RequirementFilterForm(request.GET or None)
    department = role = None
    requirement_type = ""

    if form.is_valid():
        department = form.cleaned_data.get("department")
        role = form.cleaned_data.get("role")
        requirement_type = form.cleaned_data.get("requirement_type") or ""

    buckets = build_buckets(
        department=department, role=role, requirement_type=requirement_type
    )

    context = {
        "form": form,
        "buckets": buckets,
        "counts": buckets.counts,
        "headline": dashboard_headline(),
        "departments": build_department_summary(),
        "today": timezone.localdate(),
        "selected_department": department,
        "selected_role": role,
    }

    # HTMX swaps just the bucket panel, so filtering does not reload the page.
    template = "reporting/_dashboard_buckets.html" if request.htmx else "reporting/dashboard.html"
    return render(request, template, context)


# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------


@login_required
def compliance_report(request):
    """Per-department or church-wide compliance report."""
    department = _department_from_request(request)
    requirement_type = request.GET.get("requirement_type", "")
    include_inactive = request.GET.get("include_inactive") == "1"

    report = build_compliance_report(
        department=department,
        requirement_type=requirement_type,
        include_inactive=include_inactive,
    )
    report.update(
        {
            "departments": Department.objects.filter(is_active=True),
            "include_inactive": include_inactive,
            "print_view": request.GET.get("print") == "1",
        }
    )

    if request.GET.get("format") == "pdf":
        return _pdf_response(
            request,
            "reporting/compliance_report_print.html",
            report,
            filename=_report_filename("compliance", department),
        )

    template = (
        "reporting/compliance_report_print.html"
        if report["print_view"]
        else "reporting/compliance_report.html"
    )
    return render(request, template, report)


def _department_from_request(request) -> Department | None:
    department_id = request.GET.get("department")
    if not department_id:
        return None
    return Department.objects.filter(pk=department_id).first()


def _report_filename(prefix: str, department: Department | None) -> str:
    stamp = timezone.localdate().isoformat()
    scope = _slug(department.name) if department else "all-departments"
    return f"{prefix}-{scope}-{stamp}.pdf"


def _slug(value: str) -> str:
    from django.utils.text import slugify

    return slugify(value) or "report"


# ---------------------------------------------------------------------------
# Individual volunteer file
# ---------------------------------------------------------------------------


@login_required
def volunteer_file(request, pk: int):
    """The complete Ministry Personnel file, printable."""
    volunteer = get_object_or_404(Volunteer, pk=pk)
    context = build_volunteer_file(volunteer)
    context["print_view"] = request.GET.get("print") == "1"

    if request.GET.get("format") == "pdf":
        return _pdf_response(
            request,
            "reporting/volunteer_file_print.html",
            context,
            filename=(
                f"volunteer-file-{_slug(volunteer.full_name)}-"
                f"{timezone.localdate().isoformat()}.pdf"
            ),
        )

    return render(request, "reporting/volunteer_file_print.html", context)


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


@login_required
def audit_trail(request):
    """
    Read-only, filterable audit trail.

    Append-only at the model layer, and there is no edit or delete view here — the
    viewer can only read.
    """
    events = AuditEvent.objects.all()

    action = request.GET.get("action", "")
    entity_type = request.GET.get("entity_type", "")
    entity_id = request.GET.get("entity_id", "")
    actor_id = request.GET.get("actor", "")
    since = request.GET.get("since", "")
    until = request.GET.get("until", "")

    if action:
        events = events.filter(action=action)
    if entity_type:
        events = events.filter(entity_type=entity_type)
    if entity_id:
        events = events.filter(entity_id=entity_id)
    if actor_id.isdigit():
        events = events.filter(actor_user_id=int(actor_id))

    for value, lookup in ((since, "occurred_at__date__gte"), (until, "occurred_at__date__lte")):
        if value:
            try:
                events = events.filter(**{lookup: datetime.date.fromisoformat(value)})
            except ValueError:
                messages.warning(request, f"Ignored an unreadable date: '{value}'.")

    paginator = Paginator(events, AUDIT_PAGE_SIZE)
    page = paginator.get_page(request.GET.get("page"))

    context = {
        "page": page,
        "events": page.object_list,
        "total": paginator.count,
        "actions": AuditAction.choices,
        "entity_types": (
            AuditEvent.objects.values_list("entity_type", flat=True).distinct().order_by("entity_type")
        ),
        "filters": {
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "actor": actor_id,
            "since": since,
            "until": until,
        },
    }

    template = "reporting/_audit_rows.html" if request.htmx else "reporting/audit_trail.html"
    return render(request, template, context)


@login_required
def audit_event_detail(request, pk: int):
    """One audit entry, with its decrypted before/after detail."""
    event = get_object_or_404(AuditEvent, pk=pk)
    return render(
        request,
        "reporting/audit_event_detail.html",
        {"event": event, "detail": event.detail_data},
    )


# ---------------------------------------------------------------------------
# Email log
# ---------------------------------------------------------------------------


@login_required
def email_log(request):
    """
    Delivery history for reminder digests.

    Recipients and bodies are encrypted; the metadata shown here is enough to confirm
    reminders are going out and to diagnose a provider failure.
    """
    from apps.notifications.models import EmailLog

    logs = EmailLog.objects.all()
    paginator = Paginator(logs, AUDIT_PAGE_SIZE)
    page = paginator.get_page(request.GET.get("page"))
    return render(
        request,
        "reporting/email_log.html",
        {"page": page, "logs": page.object_list, "total": paginator.count},
    )


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


def _pdf_response(request, template: str, context: dict, *, filename: str) -> HttpResponse:
    """
    Render a template to PDF, falling back to print-ready HTML.

    WeasyPrint needs Pango/Cairo present at runtime. They are installed in the app
    image, but if a deployment lacks them the import raises — so the failure is caught
    and the admin gets the printable page plus an explanation rather than an error.
    """
    context = {**context, "print_view": True, "pdf": True}
    html = render_to_string(template, context, request=request)

    try:
        from weasyprint import HTML
    except Exception as exc:  # noqa: BLE001 - OSError from missing system libraries
        logger.warning("PDF export unavailable, serving printable HTML instead: %s", exc)
        response = HttpResponse(html)
        response["X-VMS-PDF-Fallback"] = "weasyprint-unavailable"
        return response

    try:
        pdf = HTML(string=html, base_url=request.build_absolute_uri("/")).write_pdf()
    except Exception:  # noqa: BLE001
        logger.exception("PDF rendering failed for %s", template)
        return HttpResponse(html)

    response = HttpResponse(pdf, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    # A compliance report lists names against screening status; keep it out of caches.
    response["Cache-Control"] = "no-store, private"
    return response
