"""
What gets queued for review, and — just as important — what does not.

The tests that matter most here are the negative ones. A review item opened where none
was wanted is visible and annoying; a review item *missing* where one was wanted reads as
"somebody checked this" and is not visible at all.
"""

from __future__ import annotations

from apps.core import audit
from apps.core.tests.base import TenantTestCase
from apps.documents.services import store_document
from apps.requirements.models import RequirementStatus
from apps.requirements.services import (
    mark_requirement_complete,
    record_crc,
    start_requirement,
    sync_volunteer_requirements,
    waive_requirement,
)
from apps.review.models import ReviewItem, ReviewKind, ReviewStatus
from apps.review.recording import clean_snapshot, needs_review
from django.utils import timezone


class ReviewRecordingCase(TenantTestCase):
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
        """Set the ambient actor the way a request would."""
        from django.test import RequestFactory

        request = RequestFactory().get("/")
        request.user = user
        return audit.acting_as(audit.actor_from_request(request))

    def an_instance(self, *, name="Interview"):
        return self.volunteer.requirement_instances.select_related("definition").get(
            definition__name__icontains=name
        )


class WhoNeedsReviewTests(ReviewRecordingCase):
    def test_a_department_admin_needs_review(self):
        with self.acting_as(self.dept_admin):
            self.assertTrue(needs_review())

    def test_a_primary_admin_does_not(self):
        with self.acting_as(self.primary):
            self.assertFalse(needs_review())

    def test_the_system_actor_does_not(self):
        """
        The nightly sweep, the seeders and every management command.

        Safe only because none of the reviewed writers is reachable from the sweep —
        asserted below rather than assumed.
        """
        with audit.acting_as(audit.Actor.system("nightly job")):
            self.assertFalse(needs_review())


class CompletionTests(ReviewRecordingCase):
    def test_a_department_admins_completion_is_queued(self):
        instance = self.an_instance()
        with self.acting_as(self.dept_admin):
            mark_requirement_complete(instance, timezone.localdate())

        item = ReviewItem.objects.get()
        self.assertEqual(item.kind, ReviewKind.REQUIREMENT_COMPLETION)
        self.assertEqual(item.status, ReviewStatus.PENDING)
        self.assertEqual(item.entity_type, "RequirementInstance")
        self.assertEqual(item.entity_id, str(instance.pk))
        self.assertEqual(item.recorded_by_user_id, self.dept_admin.pk)
        self.assertEqual(item.department, self.childrens)

    def test_the_requirement_is_complete_immediately(self):
        """
        The owner's decision: a pending entry counts as compliant at once.

        The honest cost is that a report can say "compliant" on evidence nobody has
        confirmed, which is why the backlog is surfaced in four places.
        """
        instance = self.an_instance()
        with self.acting_as(self.dept_admin):
            mark_requirement_complete(instance, timezone.localdate())

        instance.refresh_from_db()
        self.assertEqual(instance.status, RequirementStatus.COMPLETE)

    def test_a_primary_admins_completion_is_not_queued(self):
        instance = self.an_instance()
        with self.acting_as(self.primary):
            mark_requirement_complete(instance, timezone.localdate())

        self.assertEqual(ReviewItem.objects.count(), 0)

    def test_marking_in_progress_is_not_queued(self):
        """In-progress is not a satisfied status, so it moves no compliance figure."""
        instance = self.an_instance()
        with self.acting_as(self.dept_admin):
            start_requirement(instance)

        self.assertEqual(ReviewItem.objects.count(), 0)

    def test_the_snapshot_carries_the_deadline_that_completion_destroys(self):
        """
        ``mark_complete`` nulls ``due_on`` and ``due_reason`` and neither is recoverable.

        Without the snapshot a reverted completion would silently drop a real deadline —
        the criminal-record-check date a volunteer acquires on turning 18, for instance.
        """
        instance = self.an_instance()
        instance.due_on = timezone.localdate()
        instance.due_reason = "Turned 18"
        instance.save(update_fields=["due_on", "due_reason"])

        with self.acting_as(self.dept_admin):
            mark_requirement_complete(instance, timezone.localdate())

        item = ReviewItem.objects.get()
        self.assertEqual(item.before_state["due_reason"], "Turned 18")
        self.assertTrue(item.before_state["due_on"])


class WaiverTests(ReviewRecordingCase):
    def test_a_waiver_is_queued(self):
        instance = self.an_instance()
        with self.acting_as(self.dept_admin):
            waive_requirement(instance, reason="Interviewed at the previous church", waived_by="Bob")

        item = ReviewItem.objects.get()
        self.assertEqual(item.kind, ReviewKind.WAIVER)


class CrcTests(ReviewRecordingCase):
    def test_a_crc_is_queued_and_takes_effect_at_once(self):
        with self.acting_as(self.dept_admin):
            record_crc(self.volunteer, result="cleared", report_date=timezone.localdate())

        item = ReviewItem.objects.get()
        self.assertEqual(item.kind, ReviewKind.CRC)
        self.assertEqual(item.entity_type, "CRCRecord")
        # The clearance is live, flagged unverified — the owner's decision.
        crc_instance = self.volunteer.requirement_instances.get(
            definition__requirement_type="criminal_record_check"
        )
        self.assertEqual(crc_instance.status, RequirementStatus.COMPLETE)

    def test_the_item_points_at_the_requirement_as_well(self):
        """So the requirement's row is what reads "unverified" — that is the row on screen."""
        with self.acting_as(self.dept_admin):
            record_crc(self.volunteer, result="cleared", report_date=timezone.localdate())

        item = ReviewItem.objects.get()
        self.assertEqual(item.affected_entity_type, "RequirementInstance")


class DocumentTests(ReviewRecordingCase):
    def test_recording_a_document_opens_exactly_one_item(self):
        """
        One recorded action, one thing to affirm.

        A document completes the requirement it backs, which is two writes. Two queue rows
        would mean two clicks and would let the pair be affirmed separately — the "file
        disagrees with itself" failure BUILD_NOTES §1.15 exists to close.
        """
        instance = self.volunteer.requirement_instances.select_related("definition").filter(
            definition__requires_document=True, definition__is_onboarding=True
        ).exclude(definition__requirement_type="criminal_record_check").first()
        self.assertIsNotNone(instance, "expected a document-backed onboarding requirement")

        # Track mode keeps only the fact and the dates, which is the cheapest of the three
        # for a test that is about the review item rather than about storage.
        from apps.tenants.models import DocumentMode

        self.tenant.document_mode = DocumentMode.TRACK
        self.tenant.save(update_fields=["document_mode"])

        with self.acting_as(self.dept_admin):
            store_document(
                volunteer=self.volunteer,
                title="Application form",
                kind="application",
                physical_location="Binder 3",
                document_date=timezone.localdate(),
                requirement_instance=instance,
                uploaded_by="Bob",
            )

        self.assertEqual(ReviewItem.objects.count(), 1)
        item = ReviewItem.objects.get()
        self.assertEqual(item.kind, ReviewKind.DOCUMENT)
        self.assertEqual(item.entity_type, "Document")
        # And it covers the requirement it completed.
        self.assertEqual(item.affected_entity_type, "RequirementInstance")
        self.assertEqual(item.affected_entity_id, str(instance.pk))


class NightlySweepTests(ReviewRecordingCase):
    def test_the_nightly_sweep_queues_nothing(self):
        """
        ``Actor.system()`` answers False to ``needs_review``, which is only safe because
        no reviewed writer is reachable from the sweep. This is the assertion that keeps
        that true.
        """
        from apps.core.tasks import sweep_tenant

        with self.acting_as(self.dept_admin):
            mark_requirement_complete(self.an_instance(), timezone.localdate())
        before = ReviewItem.objects.count()

        sweep_tenant(self.tenant)

        self.assertEqual(ReviewItem.objects.count(), before)


class SnapshotSafetyTests(TenantTestCase):
    """``before_state`` is an unencrypted JSON column, so what goes in it is policed."""

    def test_anything_off_the_allowlist_is_dropped(self):
        cleaned = clean_snapshot(
            {"status": "complete", "medical_notes": "nut allergy", "address": "1 Main St"}
        )
        self.assertEqual(cleaned, {"status": "complete"})

    def test_no_encrypted_field_name_is_on_the_allowlist(self):
        """
        Walks the reviewable models and fails if an encrypted column could ever land here.

        PRD §5 draws the line between what is queryable and what is encrypted; a snapshot
        copying an encrypted value into plain JSON would step straight over it.
        """
        from apps.core.fields import EncryptedCharField, EncryptedEmailField, EncryptedTextField
        from apps.documents.models import Document
        from apps.org.models import Volunteer
        from apps.requirements.models import CRCRecord, RequirementInstance
        from apps.review.recording import SNAPSHOT_KEYS

        encrypted_types = (EncryptedCharField, EncryptedEmailField, EncryptedTextField)
        for model in (Volunteer, RequirementInstance, CRCRecord, Document):
            for field in model._meta.get_fields():
                if isinstance(field, encrypted_types):
                    self.assertNotIn(
                        field.name,
                        SNAPSHOT_KEYS,
                        f"{model.__name__}.{field.name} is encrypted and must never be "
                        "snapshotted into before_state",
                    )
