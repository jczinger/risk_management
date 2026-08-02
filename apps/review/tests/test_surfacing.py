"""
Where an unaffirmed entry shows up.

An entry that counts as compliant but is flagged nowhere is the worst of both worlds, so
these tests are mostly about visibility: the badge on every render path, the queue, the
dashboard tile, the report note, and the digest line.

The htmx test is the one that earns its place most often. A swapped-in fragment that has
lost its badge makes the page disagree with itself, and nothing about the page looks broken.
"""

from __future__ import annotations

from django.urls import reverse
from django.utils import timezone

from apps.core import audit
from apps.core.tests.base import TenantTestCase
from apps.notifications.models import EmailLog
from apps.requirements.services import mark_requirement_complete, sync_volunteer_requirements
from apps.review.models import REVIEW_STALE_DAYS, ReviewItem, ReviewStatus


class SurfacingCase(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.seed()
        self.childrens = self.make_department("Children's Ministry")
        self.role = self.make_role(self.childrens, name="Sunday School Teacher")
        self.volunteer = self.make_volunteer(first_name="Jane", last_name="Doe")
        self.assign(self.volunteer, self.role)
        sync_volunteer_requirements(self.volunteer)

        self.primary = self.make_admin(email="primary@test.ca")
        self.make_passkey(self.primary)
        self.dept_admin = self.make_department_admin(
            email="dept@test.ca", departments=[self.childrens]
        )

    def acting_as(self, user):
        from django.test import RequestFactory

        request = RequestFactory().get("/")
        request.user = user
        return audit.acting_as(audit.actor_from_request(request))

    def a_pending_completion(self, name="Interview"):
        instance = self.volunteer.requirement_instances.select_related("definition").get(
            definition__name__icontains=name
        )
        with self.acting_as(self.dept_admin):
            mark_requirement_complete(instance, timezone.localdate())
        return ReviewItem.objects.pending().get(), instance


class BadgeTests(SurfacingCase):
    def test_the_volunteer_file_shows_the_badge(self):
        self.a_pending_completion()
        client = self.signed_in_client(self.primary)

        body = client.get(
            reverse("org:volunteer_detail", args=[self.volunteer.pk])
        ).content.decode()
        self.assertIn("Unverified", body)

    def test_the_printable_file_shows_it_too(self):
        """
        Unlike the action buttons, which are hidden in print. An unverified figure is
        material to whoever reads the printed file, and a print more confident than the
        screen it came from would be a worse document.
        """
        self.a_pending_completion()
        client = self.signed_in_client(self.primary)

        body = client.get(
            reverse("reporting:volunteer_file", args=[self.volunteer.pk])
        ).content.decode().lower()
        self.assertIn("unverified", body)

    def test_the_instance_detail_page_shows_it(self):
        _, instance = self.a_pending_completion()
        client = self.signed_in_client(self.primary)

        body = client.get(
            reverse("requirements:instance_detail", args=[instance.pk])
        ).content.decode()
        self.assertIn("Unverified", body)

    def test_the_htmx_row_swap_keeps_the_badge(self):
        """
        The regression this exists to catch.

        ``instance_start`` re-renders a single row and swaps it in. Miss the annotation
        there and the badge silently disappears from a page that had it a moment ago —
        nothing errors, and the page simply starts lying.
        """
        # A second requirement, still outstanding, so "mark as in progress" applies to it.
        other = (
            self.volunteer.requirement_instances.select_related("definition")
            .exclude(definition__name__icontains="Interview")
            .filter(status="not_started")
            .first()
        )
        self.assertIsNotNone(other)

        # Make *that* one the unverified entry, so the swapped row is the one carrying it.
        with self.acting_as(self.dept_admin):
            mark_requirement_complete(other, timezone.localdate())

        client = self.signed_in_client(self.primary)
        response = client.post(
            reverse("requirements:instance_start", args=[other.pk]),
            HTTP_HX_REQUEST="true",
        )
        # start_requirement is a no-op on a complete requirement, but the row still renders
        # — and it must still carry the badge.
        self.assertIn("Unverified", response.content.decode())

    def test_no_badge_when_nothing_is_pending(self):
        client = self.signed_in_client(self.primary)
        body = client.get(
            reverse("org:volunteer_detail", args=[self.volunteer.pk])
        ).content.decode()
        self.assertNotIn("Unverified", body)


class QueueTests(SurfacingCase):
    def test_the_queue_lists_the_entry(self):
        self.a_pending_completion()
        client = self.signed_in_client(self.primary)

        body = client.get(reverse("review:queue")).content.decode()
        self.assertIn("Doe", body)
        self.assertIn("Affirm", body)

    def test_a_department_admin_sees_the_queue_but_no_buttons(self):
        """
        They can see what of their own work is waiting — the alternative is their sent-back
        entries being invisible to them — but they cannot decide anything.
        """
        self.a_pending_completion()
        client = self.signed_in_client(self.dept_admin)

        body = client.get(reverse("review:queue")).content.decode()
        self.assertIn("Doe", body)
        self.assertNotIn("Affirm</button>", body)

    def test_affirming_over_htmx_swaps_the_row(self):
        item, _ = self.a_pending_completion()
        client = self.signed_in_client(self.primary)

        response = client.post(
            reverse("review:affirm", args=[item.pk]), HTTP_HX_REQUEST="true"
        )

        item.refresh_from_db()
        self.assertEqual(item.status, ReviewStatus.AFFIRMED)
        self.assertIn("Affirmed", response.content.decode())

    def test_affirming_without_javascript_redirects(self):
        item, _ = self.a_pending_completion()
        client = self.signed_in_client(self.primary)

        response = client.post(reverse("review:affirm", args=[item.pk]))

        self.assertEqual(response.status_code, 302)
        item.refresh_from_db()
        self.assertEqual(item.status, ReviewStatus.AFFIRMED)

    def test_the_send_back_page_says_what_it_cannot_undo(self):
        """Before the click, not after — for a disqualification, "after" is far too late."""
        from apps.requirements.services import record_convictions, record_crc

        with self.acting_as(self.dept_admin):
            record = record_crc(
                self.volunteer, result="not_clear", report_date=timezone.localdate()
            )
            record_convictions(
                record,
                [{"category": "Offence against a child", "is_automatic_disqualifier": True}],
            )
        item = ReviewItem.objects.pending().filter(entity_type="DisqualifyingConviction").get()

        client = self.signed_in_client(self.primary)
        body = client.get(reverse("review:send_back", args=[item.pk])).content.decode()

        self.assertIn("What this will not undo", body)
        self.assertIn("no route back", body)

    def test_sending_back_needs_a_reason(self):
        item, _ = self.a_pending_completion()
        client = self.signed_in_client(self.primary)

        response = client.post(reverse("review:send_back", args=[item.pk]), {"reason": ""})

        self.assertEqual(response.status_code, 200)
        item.refresh_from_db()
        self.assertEqual(item.status, ReviewStatus.PENDING)


class NavigationAndTileTests(SurfacingCase):
    def test_the_nav_shows_the_queue_when_something_is_waiting(self):
        self.a_pending_completion()
        client = self.signed_in_client(self.primary)

        body = client.get(reverse("org:volunteer_list")).content.decode()
        self.assertIn("Review (1)", body)

    def test_the_nav_hides_the_queue_when_nothing_is(self):
        client = self.signed_in_client(self.primary)
        body = client.get(reverse("org:volunteer_list")).content.decode()
        self.assertNotIn("review/", body)

    def test_the_dashboard_tile_appears(self):
        self.a_pending_completion()
        client = self.signed_in_client(self.primary)

        body = client.get(reverse("dashboard")).content.decode()
        self.assertIn("Awaiting review", body)

    def test_no_tile_for_a_church_with_no_limited_admins(self):
        """
        A single-administrator church should not carry a permanent "0 awaiting" ornament
        for a feature it does not use.
        """
        client = self.signed_in_client(self.primary)
        body = client.get(reverse("dashboard")).content.decode()
        self.assertNotIn("Awaiting review", body)


class ReportNoteTests(SurfacingCase):
    def test_the_compliance_report_says_how_many_figures_are_unaffirmed(self):
        self.a_pending_completion()
        client = self.signed_in_client(self.primary)

        body = client.get(reverse("reporting:compliance")).content.decode()
        self.assertIn("not yet affirmed", body)

    def test_the_volunteer_still_counts_as_compliant(self):
        """
        The owner's decision, and the reason the note above has to exist.

        ``is_compliant`` is deliberately untouched by the review gate.
        """
        from apps.reporting.services import build_compliance_report

        self.a_pending_completion()
        report = build_compliance_report()
        row = next(r for r in report["rows"] if r.volunteer.pk == self.volunteer.pk)
        # The interview is complete as far as compliance is concerned.
        self.assertEqual(row.overdue_count, 0)
        self.assertEqual(report["unverified_count"], 1)


class DigestTests(SurfacingCase):
    def test_the_digest_never_reaches_a_department_admin(self):
        """
        The leak this closes. The digest is one shared body built from a church-wide query,
        so mailing it to a department admin would name every volunteer at the church with
        anything overdue — invisible in the UI, and permanent in ``EmailLog``.
        """
        from apps.notifications.services import admin_recipients

        recipients = admin_recipients()
        self.assertIn(self.primary.email, recipients)
        self.assertNotIn(self.dept_admin.email, recipients)

    def test_a_stale_backlog_alone_still_sends_an_email(self):
        """
        Otherwise the church with the worst backlog is the one that hears nothing: no
        reminders due means no digest, and an unaffirmed entry shows up nowhere else.
        """
        from apps.notifications.services import send_digest

        item, _ = self.a_pending_completion()
        ReviewItem.objects.filter(pk=item.pk).update(
            created_at=timezone.now() - timezone.timedelta(days=REVIEW_STALE_DAYS + 5)
        )

        log = send_digest(self.tenant, [], review_backlog={"pending": 1, "stale": 1})

        self.assertIsNotNone(log)
        self.assertIn("awaiting your review", log.subject.lower())
        self.assertIn("waiting to be affirmed", log.body)

    def test_no_email_when_there_is_nothing_due_and_no_stale_backlog(self):
        from apps.notifications.services import send_digest

        self.assertIsNone(send_digest(self.tenant, [], review_backlog={"pending": 1, "stale": 0}))

    def test_the_email_log_item_count_still_means_reminders(self):
        from apps.notifications.services import send_digest

        item, _ = self.a_pending_completion()
        ReviewItem.objects.filter(pk=item.pk).update(
            created_at=timezone.now() - timezone.timedelta(days=REVIEW_STALE_DAYS + 5)
        )

        send_digest(self.tenant, [], review_backlog={"pending": 1, "stale": 1})

        log = EmailLog.objects.order_by("-id").first()
        self.assertEqual(log.item_count, 0)
