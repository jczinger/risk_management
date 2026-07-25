"""
Dashboard, reporting and audit-viewer tests (Build Spec §7, §8, §10).

Acceptance criteria covered:

* "Volunteer onboarded end-to-end; compliance status correct at each step."
* "Compliance report, individual file, and audit trail render and print correctly."

Also a broad render sweep: every page in the app returns 200 for a signed-in admin and
redirects an anonymous one. That is cheap to maintain and catches the class of mistake — a
renamed field, a typo'd URL name in a template — that unit tests on services never see.
"""

from __future__ import annotations

import datetime

from django.urls import reverse
from django.utils import timezone

from apps.core.tests.base import TenantTestCase
from apps.org.models import LeadershipFlag
from apps.requirements.models import CRCResult, RequirementStatus, RequirementType
from apps.requirements.services import (
    mark_requirement_complete,
    record_crc,
    sync_volunteer_requirements,
)
from apps.reporting.services import (
    build_compliance_report,
    build_buckets,
    build_volunteer_file,
    dashboard_headline,
)


class ReportingBase(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.seed()
        self.admin = self.make_admin()
        self.client = self.signed_in_client(self.admin)

        self.children = self.make_department("Children's Ministry")
        self.youth = self.make_department("Youth")
        self.teacher = self.make_role(self.children, "Sunday School Teacher")
        self.director = self.make_role(
            self.children, "Director", leadership=LeadershipFlag.DIRECTOR
        )
        self.youth_leader = self.make_role(self.youth, "Youth Leader")

    def onboard(self, volunteer, role=None, complete_all=False):
        self.assign(volunteer, role or self.teacher)
        sync_volunteer_requirements(volunteer)
        if complete_all:
            for instance in volunteer.requirement_instances.filter(
                status__in=RequirementStatus.outstanding_values()
            ):
                if instance.definition.is_crc:
                    record_crc(
                        volunteer,
                        result=CRCResult.CLEARED,
                        report_date=timezone.localdate(),
                    )
                else:
                    mark_requirement_complete(instance, timezone.localdate())
        return volunteer


class EndToEndOnboardingTests(ReportingBase):
    """
    One volunteer, all the way through, checking compliance at each step.

    This is the acceptance criterion "volunteer onboarded end-to-end; compliance status
    correct at each step" done literally.
    """

    def test_compliance_tracks_each_step(self):
        volunteer = self.make_volunteer(first_name="Jordan", last_name="Blake", age=34)

        # Step 1 — a record with no role owes nothing, because nothing applies yet.
        report = build_compliance_report()
        row = next(r for r in report["rows"] if r.volunteer.pk == volunteer.pk)
        self.assertEqual(row.instances, [])
        self.assertTrue(row.is_compliant)

        # Step 2 — assigning a role is what makes requirements apply.
        self.assign(volunteer, self.teacher)
        sync_volunteer_requirements(volunteer)

        report = build_compliance_report()
        row = next(r for r in report["rows"] if r.volunteer.pk == volunteer.pk)
        self.assertEqual(len(row.instances), 13)  # 14 seeded, minus the confidentiality one
        self.assertFalse(row.is_compliant)
        self.assertEqual(row.status_label, "In progress")
        self.assertGreater(row.outstanding_count, 0)

        # Step 3 — part-way through, still not compliant.
        application = volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.APPLICATION_FORM
        )
        mark_requirement_complete(application, timezone.localdate())

        row = next(
            r for r in build_compliance_report()["rows"] if r.volunteer.pk == volunteer.pk
        )
        self.assertFalse(row.is_compliant)

        # Step 4 — everything else except the criminal record check.
        for instance in volunteer.requirement_instances.filter(
            status__in=RequirementStatus.outstanding_values()
        ).exclude(definition__requirement_type=RequirementType.CRIMINAL_RECORD_CHECK):
            mark_requirement_complete(instance, timezone.localdate())

        row = next(
            r for r in build_compliance_report()["rows"] if r.volunteer.pk == volunteer.pk
        )
        self.assertFalse(row.is_compliant, "the outstanding criminal record check must count")
        self.assertEqual(row.outstanding_count, 1)

        # Step 5 — the check clears, and the volunteer is compliant.
        record_crc(volunteer, result=CRCResult.CLEARED, report_date=timezone.localdate())

        row = next(
            r for r in build_compliance_report()["rows"] if r.volunteer.pk == volunteer.pk
        )
        self.assertTrue(row.is_compliant)
        self.assertEqual(row.status_label, "Compliant")
        self.assertEqual(row.overdue_count, 0)
        self.assertEqual(row.outstanding_count, 0)

        # Step 6 — a year passes and the annual agreements lapse.
        code_of_conduct = volunteer.requirement_instances.get(
            definition__name="Code of Conduct"
        )
        mark_requirement_complete(
            code_of_conduct, timezone.localdate() - datetime.timedelta(days=400)
        )
        from apps.requirements.services import recompute_all_statuses

        recompute_all_statuses()

        row = next(
            r for r in build_compliance_report()["rows"] if r.volunteer.pk == volunteer.pk
        )
        self.assertFalse(row.is_compliant)
        self.assertEqual(row.status_label, "Overdue")
        self.assertEqual(row.overdue_count, 1)

    def test_a_minor_can_be_fully_compliant_without_a_criminal_record_check(self):
        """
        The under-18 exemption has to actually let someone reach compliance, or the rule is
        cosmetic.
        """
        minor = self.make_volunteer(first_name="Sam", last_name="Young", age=16)
        self.onboard(minor, complete_all=True)

        row = next(r for r in build_compliance_report()["rows"] if r.volunteer.pk == minor.pk)
        self.assertTrue(row.is_compliant)

        crc = minor.requirement_instances.get(
            definition__requirement_type=RequirementType.CRIMINAL_RECORD_CHECK
        )
        self.assertEqual(crc.status, RequirementStatus.NOT_APPLICABLE)


class DashboardTests(ReportingBase):
    """The three-bucket renewal view."""

    def test_dashboard_renders(self):
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Compliance dashboard")

    def test_buckets_separate_overdue_due_soon_and_compliant(self):
        overdue_person = self.onboard(self.make_volunteer(first_name="Over", last_name="Due"))
        soon_person = self.onboard(self.make_volunteer(first_name="Soon", last_name="Due"))
        fine_person = self.onboard(
            self.make_volunteer(first_name="All", last_name="Fine"), complete_all=True
        )

        overdue_instance = overdue_person.requirement_instances.get(
            definition__name="Code of Conduct"
        )
        mark_requirement_complete(
            overdue_instance, timezone.localdate() - datetime.timedelta(days=400)
        )
        soon_instance = soon_person.requirement_instances.get(definition__name="Code of Conduct")
        mark_requirement_complete(
            soon_instance, timezone.localdate() - datetime.timedelta(days=330)
        )

        from apps.requirements.services import recompute_all_statuses

        recompute_all_statuses()

        buckets = build_buckets()
        overdue_ids = {i.pk for i in buckets.overdue}
        due_soon_ids = {i.pk for i in buckets.due_soon}

        self.assertIn(overdue_instance.pk, overdue_ids)
        self.assertIn(soon_instance.pk, due_soon_ids)
        self.assertGreater(len(buckets.satisfied), 0)
        self.assertEqual(overdue_ids & due_soon_ids, set())

    def test_dashboard_can_be_filtered_by_department(self):
        in_children = self.onboard(self.make_volunteer(first_name="Chi", last_name="Ld"))
        in_youth = self.onboard(
            self.make_volunteer(first_name="You", last_name="Th"), role=self.youth_leader
        )

        filtered = build_buckets(department=self.children)
        volunteer_ids = {i.volunteer_id for i in filtered.outstanding}

        self.assertIn(in_children.pk, volunteer_ids)
        self.assertNotIn(in_youth.pk, volunteer_ids)

    def test_dashboard_can_be_filtered_by_requirement_type(self):
        self.onboard(self.make_volunteer())
        filtered = build_buckets(requirement_type=RequirementType.INTERVIEW)

        types = {i.definition.requirement_type for i in filtered.outstanding}
        self.assertEqual(types, {RequirementType.INTERVIEW})

    def test_htmx_request_returns_only_the_bucket_panel(self):
        self.onboard(self.make_volunteer())
        response = self.client.get(reverse("dashboard"), HTTP_HX_REQUEST="true")

        self.assertEqual(response.status_code, 200)
        # The partial, not the whole page.
        self.assertNotContains(response, "<!doctype html>")
        self.assertContains(response, "Overdue")

    def test_headline_counts(self):
        self.onboard(self.make_volunteer(first_name="Serving", last_name="Person"))
        self.make_volunteer(first_name="No", last_name="Role")
        self.make_volunteer(first_name="Young", last_name="Person", age=15)

        headline = dashboard_headline()
        self.assertEqual(headline["serving"], 1)
        self.assertEqual(headline["unassigned"], 2)
        self.assertEqual(headline["minors"], 1)
        self.assertEqual(headline["departments"], 2)


class ComplianceReportTests(ReportingBase):
    """Per-department and church-wide reporting."""

    def setUp(self):
        super().setUp()
        self.compliant = self.onboard(
            self.make_volunteer(first_name="Ada", last_name="Clear"), complete_all=True
        )
        self.pending = self.onboard(self.make_volunteer(first_name="Ben", last_name="Pending"))
        self.other_dept = self.onboard(
            self.make_volunteer(first_name="Cy", last_name="Youth"), role=self.youth_leader
        )

    def test_report_renders_church_wide(self):
        response = self.client.get(reverse("reporting:compliance"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Compliance report")
        self.assertContains(response, "Clear, Ada")
        self.assertContains(response, "Pending, Ben")
        self.assertContains(response, "Youth, Cy")

    def test_report_can_be_scoped_to_one_department(self):
        response = self.client.get(
            reverse("reporting:compliance"), {"department": self.children.pk}
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Clear, Ada")
        self.assertNotContains(response, "Youth, Cy")

    def test_counts_and_rate_are_computed(self):
        report = build_compliance_report()

        self.assertEqual(report["total"], 3)
        self.assertEqual(report["compliant_count"], 1)
        self.assertEqual(report["non_compliant_count"], 2)
        self.assertEqual(report["compliance_rate"], 33)

    def test_past_volunteers_are_excluded_unless_asked_for(self):
        self.pending.is_active = False
        self.pending.stopped_serving_on = timezone.localdate()
        self.pending.save()

        self.assertEqual(build_compliance_report()["total"], 2)
        self.assertEqual(build_compliance_report(include_inactive=True)["total"], 3)

    def test_printable_view_renders(self):
        response = self.client.get(reverse("reporting:compliance"), {"print": "1"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Volunteer screening compliance report")
        self.assertContains(response, "print-head")
        self.assertTrue(response.context["print_view"])

    def test_printable_view_includes_the_per_volunteer_detail(self):
        response = self.client.get(reverse("reporting:compliance"), {"print": "1"})
        self.assertContains(response, "Detail by volunteer")
        self.assertContains(response, "Criminal Record Check")

    def test_pdf_export_returns_a_pdf(self):
        response = self.client.get(reverse("reporting:compliance"), {"format": "pdf"})

        self.assertEqual(response.status_code, 200)
        if response["Content-Type"] == "application/pdf":
            self.assertTrue(response.content.startswith(b"%PDF"))
            self.assertIn("attachment", response["Content-Disposition"])
            self.assertIn("no-store", response["Cache-Control"])
        else:
            # WeasyPrint's system libraries are absent; the printable HTML is served
            # instead rather than erroring.
            self.assertEqual(response["X-VMS-PDF-Fallback"], "weasyprint-unavailable")

    def test_the_report_shows_no_personal_details_beyond_names_and_roles(self):
        """
        A report handed to an insurer should carry the verdict, not a volunteer's address or
        medical notes.
        """
        self.compliant.address = "42 Private Road, Victoria"
        self.compliant.medical_notes = "Severe nut allergy"
        self.compliant.phone = "250-555-3333"
        self.compliant.save()

        response = self.client.get(reverse("reporting:compliance"))
        body = response.content.decode()

        self.assertNotIn("Private Road", body)
        self.assertNotIn("nut allergy", body)
        self.assertNotIn("250-555-3333", body)


class VolunteerFileTests(ReportingBase):
    """The complete Ministry Personnel file."""

    def setUp(self):
        super().setUp()
        self.volunteer = self.onboard(
            self.make_volunteer(
                first_name="Dana",
                last_name="Reed",
                age=41,
                phone="250-555-1212",
                address="7 Cedar Way\nVictoria BC",
                emergency_contact="Kim Reed, spouse, 250 555 9090",
                medical_notes="Asthma — inhaler in the office",
            ),
            complete_all=True,
        )

    def test_the_file_renders_with_the_full_record(self):
        response = self.client.get(reverse("reporting:volunteer_file", args=[self.volunteer.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Ministry Personnel file")
        self.assertContains(response, "Dana Reed")
        # This one report is meant to show the personal details.
        self.assertContains(response, "250-555-1212")
        self.assertContains(response, "Cedar Way")
        self.assertContains(response, "Kim Reed")
        self.assertContains(response, "Asthma")

    def test_the_file_lists_roles_requirements_and_checks(self):
        response = self.client.get(reverse("reporting:volunteer_file", args=[self.volunteer.pk]))

        self.assertContains(response, "Sunday School Teacher")
        self.assertContains(response, "Criminal Record Check")
        self.assertContains(response, "Code of Conduct")
        self.assertContains(response, "Screening requirements")

    def test_the_file_warns_before_printing_personal_information(self):
        response = self.client.get(reverse("reporting:volunteer_file", args=[self.volunteer.pk]))
        self.assertContains(response, "no longer protected by this system")

    def test_a_disqualification_is_stated_prominently_in_the_file(self):
        from apps.requirements.services import record_convictions

        record = record_crc(
            self.volunteer,
            result=CRCResult.NOT_CLEAR,
            report_date=timezone.localdate(),
        )
        record_convictions(
            record, [{"category": "Child abuse", "is_automatic_disqualifier": True}]
        )

        response = self.client.get(reverse("reporting:volunteer_file", args=[self.volunteer.pk]))
        self.assertContains(response, "PERMANENTLY DISQUALIFIED")
        self.assertContains(response, "no override available")

    def test_pdf_export_of_the_file(self):
        response = self.client.get(
            reverse("reporting:volunteer_file", args=[self.volunteer.pk]), {"format": "pdf"}
        )
        self.assertEqual(response.status_code, 200)

    def test_the_builder_returns_every_section(self):
        data = build_volunteer_file(self.volunteer)

        for key in ("onboarding", "recurring", "assignments", "crc_records", "documents", "buckets"):
            self.assertIn(key, data)
        self.assertGreater(len(data["onboarding"]), 0)
        self.assertEqual(len(data["crc_records"]), 1)


class AuditViewerTests(ReportingBase):
    """The read-only audit trail."""

    def setUp(self):
        super().setUp()
        self.volunteer = self.onboard(self.make_volunteer(first_name="Ada", last_name="Clear"))

    def test_the_viewer_renders(self):
        response = self.client.get(reverse("reporting:audit_trail"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Audit trail")
        self.assertContains(response, "append-only")

    def test_entries_can_be_filtered_by_action(self):
        from apps.core.models import AuditAction

        response = self.client.get(
            reverse("reporting:audit_trail"), {"action": AuditAction.CREATE}
        )
        self.assertEqual(response.status_code, 200)
        for event in response.context["events"]:
            self.assertEqual(event.action, AuditAction.CREATE)

    def test_entries_can_be_filtered_by_record(self):
        response = self.client.get(
            reverse("reporting:audit_trail"),
            {"entity_type": "Volunteer", "entity_id": str(self.volunteer.pk)},
        )
        self.assertEqual(response.status_code, 200)
        for event in response.context["events"]:
            self.assertEqual(event.entity_type, "Volunteer")
            self.assertEqual(event.entity_id, str(self.volunteer.pk))

    def test_an_unreadable_date_filter_is_ignored_not_fatal(self):
        response = self.client.get(reverse("reporting:audit_trail"), {"since": "not-a-date"})
        self.assertEqual(response.status_code, 200)

    def test_the_detail_page_shows_the_decrypted_diff(self):
        from apps.core.models import AuditEvent

        self.volunteer.address = "New address"
        self.volunteer.save()
        self.client.post(
            reverse("org:volunteer_edit", args=[self.volunteer.pk]),
            {
                "first_name": "Adaline",
                "last_name": "Clear",
                "preferred_name": "",
                "email": "",
                "phone": "",
                "address": "",
                "emergency_contact": "",
                "medical_notes": "",
                "notes": "",
                "attendance_since": "",
            },
        )

        event = AuditEvent.objects.filter(entity_type="Volunteer", action="update").first()
        self.assertIsNotNone(event)

        response = self.client.get(reverse("reporting:audit_event_detail", args=[event.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Detail")

    def test_the_viewer_offers_no_way_to_edit_or_delete(self):
        from django.urls import NoReverseMatch

        for name in ("audit_delete", "audit_edit", "audit_purge"):
            with self.subTest(name=name), self.assertRaises(NoReverseMatch):
                reverse(f"reporting:{name}", args=[1])

    def test_htmx_request_returns_only_the_rows(self):
        response = self.client.get(reverse("reporting:audit_trail"), HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "<!doctype html>")


class EmailLogViewTests(ReportingBase):
    def test_it_renders(self):
        response = self.client.get(reverse("reporting:email_log"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Reminder emails")


class PageRenderSweep(ReportingBase):
    """
    Every page renders for a signed-in admin, and none of them for an anonymous visitor.

    A cheap net for the mistakes that only show up at render time: a template referencing a
    field that was renamed, or a URL name that no longer exists.
    """

    def setUp(self):
        super().setUp()
        self.volunteer = self.onboard(self.make_volunteer(first_name="Ada", last_name="Clear"))
        self.instance = self.volunteer.requirement_instances.first()
        self.crc = record_crc(
            self.volunteer, result=CRCResult.CLEARED, report_date=timezone.localdate()
        )
        self.definition = self.instance.definition

    def _urls(self):
        return [
            reverse("dashboard"),
            reverse("org:volunteer_list"),
            reverse("org:volunteer_create"),
            reverse("org:volunteer_detail", args=[self.volunteer.pk]),
            reverse("org:volunteer_edit", args=[self.volunteer.pk]),
            reverse("org:volunteer_deactivate", args=[self.volunteer.pk]),
            reverse("org:department_list"),
            reverse("org:department_create"),
            reverse("org:department_detail", args=[self.children.pk]),
            reverse("org:department_edit", args=[self.children.pk]),
            reverse("org:role_list"),
            reverse("org:role_create"),
            reverse("org:role_detail", args=[self.teacher.pk]),
            reverse("org:role_edit", args=[self.teacher.pk]),
            reverse("requirements:definition_list"),
            reverse("requirements:definition_create"),
            reverse("requirements:definition_detail", args=[self.definition.pk]),
            reverse("requirements:definition_edit", args=[self.definition.pk]),
            reverse("requirements:instance_detail", args=[self.instance.pk]),
            reverse("requirements:instance_complete", args=[self.instance.pk]),
            reverse("requirements:instance_waive", args=[self.instance.pk]),
            reverse("requirements:crc_create", args=[self.volunteer.pk]),
            reverse("requirements:crc_detail", args=[self.crc.pk]),
            reverse("documents:list"),
            reverse("documents:create", args=[self.volunteer.pk]),
            reverse("reporting:compliance"),
            reverse("reporting:volunteer_file", args=[self.volunteer.pk]),
            reverse("reporting:audit_trail"),
            reverse("reporting:email_log"),
            reverse("accounts:security"),
            reverse("accounts:profile"),
            reverse("accounts:password_change"),
            reverse("accounts:totp_setup"),
            reverse("accounts:admin_list"),
            reverse("accounts:admin_invite"),
        ]

    def test_every_page_renders_for_an_admin(self):
        for url in self._urls():
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200, f"{url} returned {response.status_code}")

    def test_no_page_is_reachable_anonymously(self):
        from django.test import Client

        anonymous = Client(HTTP_HOST=self.TEST_DOMAIN)
        for url in self._urls():
            with self.subTest(url=url):
                response = anonymous.get(url)
                self.assertIn(
                    response.status_code, (302, 403), f"{url} returned {response.status_code}"
                )
                if response.status_code == 302:
                    self.assertIn("/accounts/login/", response["Location"])

    def test_the_health_check_needs_no_authentication(self):
        from django.test import Client

        response = Client(HTTP_HOST=self.TEST_DOMAIN).get("/healthz/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_the_health_check_reveals_nothing_about_the_deployment(self):
        from django.test import Client

        payload = Client(HTTP_HOST=self.TEST_DOMAIN).get("/healthz/").json()
        self.assertEqual(set(payload), {"status"})
