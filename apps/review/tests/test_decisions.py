"""
Affirming and sending back.

The send-back tests are where this feature is either honest or not, so most of them are
about what send-back **refuses** to undo: a permanent disqualification, a recorded
document's existence, a leadership decision. Each of those is immutable by design
elsewhere, and the failure mode worth testing for is a review gate quietly reversing one.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.core import audit
from apps.core.models import AuditAction, AuditEvent
from apps.core.tests.base import TenantTestCase
from apps.org.models import ScreeningBlock
from apps.requirements.models import RequirementStatus
from apps.requirements.services import (
    mark_requirement_complete,
    record_convictions,
    record_crc,
    record_discretionary_override,
    sync_volunteer_requirements,
    waive_requirement,
)
from apps.review.models import ReviewItem, ReviewStatus
from apps.review.services import ReviewError, affirm, may_review, send_back


class DecisionCase(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.seed()
        self.childrens = self.make_department("Children's Ministry")
        self.role = self.make_role(self.childrens, name="Sunday School Teacher")
        self.volunteer = self.make_volunteer(first_name="Jane", last_name="Doe")
        self.assign(self.volunteer, self.role)
        sync_volunteer_requirements(self.volunteer)

        self.primary = self.make_admin(email="primary@test.ca")
        self.dept_admin = self.make_department_admin(
            email="dept@test.ca", departments=[self.childrens]
        )

    def acting_as(self, user):
        from django.test import RequestFactory

        request = RequestFactory().get("/")
        request.user = user
        return audit.acting_as(audit.actor_from_request(request))

    def an_instance(self, name="Interview"):
        return self.volunteer.requirement_instances.select_related("definition").get(
            definition__name__icontains=name
        )

    def a_pending_completion(self):
        instance = self.an_instance()
        with self.acting_as(self.dept_admin):
            mark_requirement_complete(instance, timezone.localdate())
        return ReviewItem.objects.pending().get(), instance


class WhoMayReviewTests(DecisionCase):
    def test_a_primary_admin_may_review(self):
        item, _ = self.a_pending_completion()
        allowed, _ = may_review(self.primary, item)
        self.assertTrue(allowed)

    def test_a_department_admin_may_not(self):
        item, _ = self.a_pending_completion()
        allowed, why = may_review(self.dept_admin, item)
        self.assertFalse(allowed)
        self.assertIn("whole church", why)

    def test_a_second_department_admin_may_not_either(self):
        """The point is a wider pair of eyes, not merely a different pair."""
        other = self.make_department_admin(
            email="other-dept@test.ca", departments=[self.childrens]
        )
        item, _ = self.a_pending_completion()
        allowed, _ = may_review(other, item)
        self.assertFalse(allowed)

    def test_nobody_may_affirm_their_own_entry_while_somebody_else_could(self):
        item, _ = self.a_pending_completion()
        # Promote the recorder. Their pending items deliberately stay pending — auto-
        # affirming a backlog because somebody changed job title would defeat the feature.
        self.grant_access(self.dept_admin, self.primary_level())

        allowed, why = may_review(self.dept_admin, item)
        self.assertFalse(allowed)
        self.assertIn("recorded yourself", why)

    def test_they_may_affirm_their_own_entry_when_no_other_reviewer_is_left(self):
        """
        Otherwise the church deadlocks with a queue it cannot clear.

        Reachable only through exactly this promotion, and the audit summary says so.
        """
        item, _ = self.a_pending_completion()
        self.grant_access(self.dept_admin, self.primary_level())
        self.primary.is_active = False
        self.primary.save(update_fields=["is_active"])

        allowed, _ = may_review(self.dept_admin, item)
        self.assertTrue(allowed)

        affirm(item, by=self.dept_admin)
        entry = AuditEvent.objects.filter(action=AuditAction.REVIEW_AFFIRMED).first()
        self.assertIn("no other church-wide administrator", entry.summary)

    def primary_level(self):
        from apps.core.models import AccessLevel

        return AccessLevel.objects.get(slug=AccessLevel.PRIMARY_ADMIN)


class AffirmTests(DecisionCase):
    def test_affirming_closes_the_item_and_changes_no_data(self):
        item, instance = self.a_pending_completion()
        completed_on = instance.completed_on

        affirm(item, by=self.primary)

        item.refresh_from_db()
        instance.refresh_from_db()
        self.assertEqual(item.status, ReviewStatus.AFFIRMED)
        self.assertIsNotNone(item.reviewed_at)
        self.assertEqual(item.reviewed_by_user_id, self.primary.pk)
        self.assertEqual(instance.status, RequirementStatus.COMPLETE)
        self.assertEqual(instance.completed_on, completed_on)

    def test_a_review_cannot_be_reopened(self):
        item, _ = self.a_pending_completion()
        affirm(item, by=self.primary)

        with self.assertRaises(ValidationError):
            affirm(item, by=self.primary)

    def test_affirming_writes_its_own_audit_action(self):
        item, _ = self.a_pending_completion()
        affirm(item, by=self.primary)
        self.assertTrue(
            AuditEvent.objects.filter(action=AuditAction.REVIEW_AFFIRMED).exists()
        )


class SendBackCompletionTests(DecisionCase):
    def test_a_reason_is_required(self):
        item, _ = self.a_pending_completion()
        with self.assertRaises(ReviewError):
            send_back(item, by=self.primary, reason="   ")

    def test_the_requirement_returns_to_in_progress(self):
        item, instance = self.a_pending_completion()
        send_back(item, by=self.primary, reason="Interview notes name only one interviewer.")

        instance.refresh_from_db()
        self.assertNotEqual(instance.status, RequirementStatus.COMPLETE)
        self.assertIsNone(instance.completed_on)
        self.assertIsNone(instance.expires_on)

    def test_the_reason_reaches_the_audit_summary_where_it_can_be_read(self):
        """
        The audit ``detail`` is stored but never displayed, so a reason kept only there
        would be invisible to the department admin it is written for.
        """
        item, _ = self.a_pending_completion()
        send_back(item, by=self.primary, reason="Needs the second interviewer named.")

        entry = AuditEvent.objects.filter(action=AuditAction.REVIEW_SENT_BACK).first()
        self.assertIn("second interviewer", entry.summary)

    def test_a_restored_deadline_survives_the_round_trip(self):
        """
        ``mark_complete`` nulls ``due_on``/``due_reason`` irrecoverably. Without the
        snapshot, sending an entry back would silently drop a real deadline.
        """
        instance = self.an_instance()
        instance.due_on = timezone.localdate()
        instance.due_reason = "Turned 18 — check due within 3 months"
        instance.save(update_fields=["due_on", "due_reason"])

        with self.acting_as(self.dept_admin):
            mark_requirement_complete(instance, timezone.localdate())
        item = ReviewItem.objects.pending().get()

        send_back(item, by=self.primary, reason="Wrong volunteer.")

        instance.refresh_from_db()
        self.assertEqual(instance.due_reason, "Turned 18 — check due within 3 months")
        self.assertIsNotNone(instance.due_on)

    def test_a_send_back_does_not_revert_a_record_that_already_moved_on(self):
        """
        The staleness check. Reverting here would roll back state this entry no longer owns.
        """
        item, instance = self.a_pending_completion()
        # Somebody else takes it back to in progress in the meantime.
        instance.status = RequirementStatus.IN_PROGRESS
        instance.completed_on = None
        instance.save(update_fields=["status", "completed_on"])

        outcome = send_back(item, by=self.primary, reason="Disputed.")

        self.assertFalse(outcome["reverted"])
        self.assertTrue(outcome["kept"])
        item.refresh_from_db()
        self.assertEqual(item.status, ReviewStatus.SENT_BACK)


class SendBackWaiverTests(DecisionCase):
    def test_a_waiver_is_reversed_through_the_existing_path(self):
        instance = self.an_instance()
        with self.acting_as(self.dept_admin):
            waive_requirement(instance, reason="Covered elsewhere", waived_by="Bob")
        item = ReviewItem.objects.pending().get()

        outcome = send_back(item, by=self.primary, reason="Not an acceptable basis.")

        instance.refresh_from_db()
        self.assertTrue(outcome["reverted"])
        self.assertNotEqual(instance.status, RequirementStatus.WAIVED)
        self.assertEqual(instance.waived_reason, "")
        # Two audit rows, one per question the trail is asked.
        self.assertTrue(AuditEvent.objects.filter(action=AuditAction.WAIVER_REVERSED).exists())
        self.assertTrue(AuditEvent.objects.filter(action=AuditAction.REVIEW_SENT_BACK).exists())


class SendBackDocumentTests(DecisionCase):
    def setUp(self):
        super().setUp()
        from apps.tenants.models import DocumentMode

        self.tenant.document_mode = DocumentMode.TRACK
        self.tenant.save(update_fields=["document_mode"])

    def a_pending_document(self):
        from apps.documents.services import store_document

        instance = (
            self.volunteer.requirement_instances.select_related("definition")
            .filter(definition__requires_document=True, definition__is_onboarding=True)
            .exclude(definition__requirement_type="criminal_record_check")
            .first()
        )
        with self.acting_as(self.dept_admin):
            document = store_document(
                volunteer=self.volunteer,
                title="Application form",
                kind="application",
                physical_location="Binder 3",
                document_date=timezone.localdate(),
                requirement_instance=instance,
                uploaded_by="Bob",
            )
        return ReviewItem.objects.pending().get(), document, instance

    def test_the_document_survives_but_stops_being_current(self):
        """
        ``Document`` is a NoDeleteModel and the record that paper was presented is part of
        the trail. It leaves the working page and stays in the printed file.
        """
        item, document, _ = self.a_pending_document()

        outcome = send_back(item, by=self.primary, reason="Wrong form.")

        document.refresh_from_db()
        self.assertFalse(document.is_current)
        self.assertTrue(
            any("retained" in note for note in outcome["kept"]),
            outcome["kept"],
        )

    def test_the_requirement_the_document_completed_is_reverted(self):
        item, _, instance = self.a_pending_document()
        self.assertEqual(instance.status, RequirementStatus.COMPLETE)

        send_back(item, by=self.primary, reason="Wrong form.")

        instance.refresh_from_db()
        self.assertNotEqual(instance.status, RequirementStatus.COMPLETE)


class SendBackCrcTests(DecisionCase):
    def test_a_clearance_can_be_retracted(self):
        with self.acting_as(self.dept_admin):
            record_crc(self.volunteer, result="cleared", report_date=timezone.localdate())
        item = ReviewItem.objects.pending().get()

        outcome = send_back(item, by=self.primary, reason="Recorded against the wrong volunteer.")

        self.assertTrue(outcome["reverted"])
        crc_instance = self.volunteer.requirement_instances.get(
            definition__requirement_type="criminal_record_check"
        )
        self.assertNotEqual(crc_instance.status, RequirementStatus.COMPLETE)
        self.assertTrue(
            AuditEvent.objects.filter(action=AuditAction.CRC_NOT_AFFIRMED).exists()
        )

    def test_a_not_clear_block_set_by_this_check_is_lifted(self):
        with self.acting_as(self.dept_admin):
            record_crc(self.volunteer, result="not_clear", report_date=timezone.localdate())
        item = ReviewItem.objects.pending().get()
        self.volunteer.refresh_from_db()
        self.assertEqual(self.volunteer.screening_block, ScreeningBlock.CRC_NOT_CLEAR)

        send_back(item, by=self.primary, reason="Wrong volunteer.")

        self.volunteer.refresh_from_db()
        self.assertEqual(self.volunteer.screening_block, ScreeningBlock.NONE)

    def test_a_disqualification_is_never_undone(self):
        """
        The owner accepted this when they chose to let a department admin record a
        disqualification. Affirmation cannot be honoured here: the block cannot be lifted,
        the convictions cannot be deleted, and the ended assignments have no inverse. Send-
        back records a dispute and names what stands.
        """
        with self.acting_as(self.dept_admin):
            record = record_crc(
                self.volunteer, result="not_clear", report_date=timezone.localdate()
            )
            record_convictions(
                record,
                [{"category": "Offence against a child", "is_automatic_disqualifier": True}],
            )
        item = ReviewItem.objects.pending().filter(entity_type="DisqualifyingConviction").get()

        outcome = send_back(item, by=self.primary, reason="Believed to be the wrong person.")

        self.volunteer.refresh_from_db()
        self.assertFalse(outcome["reverted"])
        self.assertEqual(self.volunteer.screening_block, ScreeningBlock.DISQUALIFIED)
        self.assertTrue(
            any("disqualification stands" in note for note in outcome["kept"]),
            outcome["kept"],
        )

    def test_the_send_back_names_the_assignments_it_could_not_restore(self):
        with self.acting_as(self.dept_admin):
            record = record_crc(
                self.volunteer, result="not_clear", report_date=timezone.localdate()
            )
            record_convictions(
                record,
                [{"category": "Offence against a child", "is_automatic_disqualifier": True}],
            )
        item = ReviewItem.objects.pending().filter(entity_type="DisqualifyingConviction").get()

        outcome = send_back(item, by=self.primary, reason="Disputed.")

        self.assertTrue(
            any("Sunday School Teacher" in note for note in outcome["kept"]),
            outcome["kept"],
        )

    def test_a_check_carrying_convictions_cannot_be_retracted(self):
        with self.acting_as(self.dept_admin):
            record = record_crc(
                self.volunteer, result="not_clear", report_date=timezone.localdate()
            )
            record_convictions(
                record,
                [{"category": "Assault", "is_automatic_disqualifier": False}],
            )
        item = ReviewItem.objects.pending().filter(entity_type="CRCRecord").get()

        outcome = send_back(item, by=self.primary, reason="Disputed.")

        self.assertFalse(outcome["reverted"])
        self.assertTrue(
            any("corrective check" in note for note in outcome["kept"]), outcome["kept"]
        )


class SendBackOverrideTests(DecisionCase):
    def test_an_override_cannot_be_erased(self):
        """Its own model says so: "Record a new decision instead.\""""
        with self.acting_as(self.dept_admin):
            record = record_crc(
                self.volunteer, result="not_clear", report_date=timezone.localdate()
            )
            result = record_convictions(
                record, [{"category": "Assault", "is_automatic_disqualifier": False}]
            )
            record_discretionary_override(
                record,
                conviction=result["convictions"][0],
                decision="approved",
                decided_by="Bob",
                reasoning="Twenty years ago, unrelated to the role.",
                mitigation_steps="Never alone with children.",
            )
        item = ReviewItem.objects.pending().filter(entity_type="DiscretionaryOverride").get()

        outcome = send_back(item, by=self.primary, reason="Not leadership's decision to make.")

        self.assertFalse(outcome["reverted"])
        self.assertTrue(
            any("permanently retained" in note for note in outcome["kept"]), outcome["kept"]
        )


class SupersedeTests(DecisionCase):
    def test_re_recording_supersedes_the_earlier_unreviewed_entry(self):
        """
        Otherwise two open items exist for one row, and the partial unique index would
        refuse the second write outright.
        """
        item, instance = self.a_pending_completion()

        with self.acting_as(self.dept_admin):
            mark_requirement_complete(instance, timezone.localdate())

        item.refresh_from_db()
        self.assertEqual(item.status, ReviewStatus.SUPERSEDED)
        self.assertEqual(ReviewItem.objects.pending().count(), 1)
        self.assertIsNotNone(item.superseded_by)

    def test_the_supersession_is_recorded_in_the_trail(self):
        """
        "Which unverified entries were never reviewed because they were overwritten" is a
        gap in the sign-off record, so it is a question the trail should answer.
        """
        _, instance = self.a_pending_completion()
        with self.acting_as(self.dept_admin):
            mark_requirement_complete(instance, timezone.localdate())

        self.assertTrue(
            AuditEvent.objects.filter(action=AuditAction.REVIEW_SUPERSEDED).exists()
        )
