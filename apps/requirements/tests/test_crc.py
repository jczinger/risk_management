"""
Criminal record check tests (Build Spec §4.3).

The rules with teeth:

* **Cleared** satisfies the requirement and starts a three-year clock from the report date.
* **Not Clear** blocks the volunteer, pending one of the two outcomes the policy allows.
* An **automatic disqualifier is permanent with no override** — the tests here go looking
  for a way back and assert that every route is closed, including direct service calls and
  the URL space.
* A **discretionary** flag requires a documented leadership decision, with reasoning and
  mitigation steps, and that record is immutable.
"""

from __future__ import annotations

import datetime

from django.core.exceptions import ValidationError
from django.urls import NoReverseMatch, reverse
from django.utils import timezone

from apps.core.models import AuditAction, AuditEvent, ProtectedDeletionError
from apps.core.tests.base import TenantTestCase
from apps.org.models import ScreeningBlock
from apps.requirements.models import (
    CRCNotClearOutcome,
    CRCRecord,
    CRCResult,
    DisqualifyingConviction,
    DiscretionaryOverride,
    RequirementStatus,
    RequirementType,
)
from apps.requirements.services import (
    record_convictions,
    record_crc,
    record_discretionary_override,
    resolve_not_clear,
    sync_volunteer_requirements,
)


class CRCBase(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.seed()
        self.department = self.make_department()
        self.role = self.make_role(self.department, "Sunday School Teacher")
        self.volunteer = self.make_volunteer(first_name="Robin", last_name="Doe", age=35)
        self.assign(self.volunteer, self.role)
        sync_volunteer_requirements(self.volunteer)

    def crc_instance(self):
        return self.volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.CRIMINAL_RECORD_CHECK
        )


class ClearedResultTests(CRCBase):
    def test_cleared_satisfies_the_requirement_with_a_three_year_expiry(self):
        report_date = datetime.date(2026, 3, 15)
        record = record_crc(
            self.volunteer, result=CRCResult.CLEARED, report_date=report_date
        )

        self.assertTrue(record.is_cleared)
        self.assertEqual(record.expires_on, datetime.date(2029, 3, 15))

        instance = self.crc_instance()
        self.assertEqual(instance.status, RequirementStatus.COMPLETE)
        self.assertEqual(instance.completed_on, report_date)
        self.assertEqual(instance.expires_on, datetime.date(2029, 3, 15))

    def test_clock_runs_from_the_report_date_not_today(self):
        """The date on the clearance letter governs, not the date it was filed."""
        report_date = timezone.localdate() - datetime.timedelta(days=200)
        record_crc(self.volunteer, result=CRCResult.CLEARED, report_date=report_date)

        instance = self.crc_instance()
        from apps.requirements.models import add_months_to

        self.assertEqual(instance.expires_on, add_months_to(report_date, 36))

    def test_future_report_date_is_refused(self):
        with self.assertRaises(ValidationError):
            record_crc(
                self.volunteer,
                result=CRCResult.CLEARED,
                report_date=timezone.localdate() + datetime.timedelta(days=1),
            )

    def test_a_new_check_supersedes_the_previous_one(self):
        first = record_crc(
            self.volunteer, result=CRCResult.CLEARED, report_date=datetime.date(2023, 1, 10)
        )
        second = record_crc(
            self.volunteer, result=CRCResult.CLEARED, report_date=datetime.date(2026, 1, 10)
        )

        first.refresh_from_db()
        self.assertEqual(first.superseded_by_id, second.pk)
        self.assertIsNone(second.superseded_by_id)
        # Both are retained — the history is part of the file.
        self.assertEqual(CRCRecord.objects.count(), 2)

    def test_the_result_flag_and_report_date_stay_plaintext(self):
        """
        Deliberately queryable (PRD §5): the compliance report shows the flag and the
        renewal clock runs off the date.
        """
        from django.db import connection

        record = record_crc(
            self.volunteer, result=CRCResult.CLEARED, report_date=datetime.date(2026, 3, 15)
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT result, report_date FROM requirements_crcrecord WHERE id = %s", [record.pk]
            )
            result, report_date = cursor.fetchone()

        self.assertEqual(result, "cleared")
        self.assertEqual(report_date, datetime.date(2026, 3, 15))

    def test_notes_are_encrypted(self):
        from django.db import connection

        record = record_crc(
            self.volunteer,
            result=CRCResult.CLEARED,
            report_date=timezone.localdate(),
            notes="Spoke to the RCMP detachment about the delay",
        )
        with connection.cursor() as cursor:
            cursor.execute("SELECT notes FROM requirements_crcrecord WHERE id = %s", [record.pk])
            (notes,) = cursor.fetchone()

        self.assertTrue(notes.startswith("v1."))
        self.assertNotIn("RCMP", notes)

    def test_audit_entry_is_written(self):
        record_crc(self.volunteer, result=CRCResult.CLEARED, report_date=timezone.localdate())
        event = AuditEvent.objects.filter(action=AuditAction.CRC_RECORDED).first()
        self.assertIsNotNone(event)
        self.assertIn("Cleared", event.summary)


class NotClearResultTests(CRCBase):
    def test_not_clear_blocks_the_volunteer_and_the_requirement(self):
        record_crc(self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate())

        self.volunteer.refresh_from_db()
        self.assertEqual(self.volunteer.screening_block, ScreeningBlock.CRC_NOT_CLEAR)
        self.assertTrue(self.volunteer.is_blocked)
        self.assertFalse(self.volunteer.is_permanently_disqualified)

        instance = self.crc_instance()
        self.assertEqual(instance.status, RequirementStatus.BLOCKED)
        self.assertIsNone(instance.completed_on)
        self.assertIsNone(instance.expires_on)

    def test_blocked_requirement_cannot_be_marked_complete(self):
        from apps.requirements.services import mark_requirement_complete

        record_crc(self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate())
        with self.assertRaises(ValidationError):
            mark_requirement_complete(self.crc_instance(), timezone.localdate())

    def test_not_clear_starts_as_awaiting_an_outcome(self):
        record = record_crc(
            self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate()
        )
        self.assertEqual(record.not_clear_outcome, CRCNotClearOutcome.PENDING)

    def test_withdrawal_ends_every_assignment(self):
        record = record_crc(
            self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate()
        )
        resolve_not_clear(record, outcome=CRCNotClearOutcome.WITHDREW)

        self.volunteer.refresh_from_db()
        self.assertEqual(self.volunteer.screening_block, ScreeningBlock.WITHDRAWN)
        self.assertEqual(self.volunteer.assignments.filter(is_active=True).count(), 0)

    def test_fingerprint_verified_route_is_recordable(self):
        record = record_crc(
            self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate()
        )
        resolve_not_clear(record, outcome=CRCNotClearOutcome.FINGERPRINT_SUBMITTED)
        record.refresh_from_db()
        self.assertEqual(record.not_clear_outcome, CRCNotClearOutcome.FINGERPRINT_SUBMITTED)

    def test_a_later_cleared_check_lifts_a_not_clear_block(self):
        record_crc(
            self.volunteer,
            result=CRCResult.NOT_CLEAR,
            report_date=timezone.localdate() - datetime.timedelta(days=60),
        )
        self.volunteer.refresh_from_db()
        self.assertTrue(self.volunteer.is_blocked)

        record_crc(
            self.volunteer,
            result=CRCResult.CLEARED,
            report_date=timezone.localdate(),
            is_fingerprint_verified=True,
        )
        self.volunteer.refresh_from_db()
        self.assertEqual(self.volunteer.screening_block, ScreeningBlock.NONE)
        self.assertFalse(self.volunteer.is_blocked)
        self.assertEqual(self.crc_instance().status, RequirementStatus.COMPLETE)

    def test_convictions_only_attach_to_a_not_clear_result(self):
        record = record_crc(
            self.volunteer, result=CRCResult.CLEARED, report_date=timezone.localdate()
        )
        with self.assertRaises(ValidationError):
            record_convictions(record, [{"category": "Theft or fraud", "is_automatic_disqualifier": False}])


class AutomaticDisqualifierTests(CRCBase):
    """
    The one irreversible state in the system.

    Build Spec §4.3: automatic disqualifiers are hard-fail with **no override**. These tests
    exist to fail loudly if anyone ever adds one.
    """

    def _disqualify(self, category="Sexual assault"):
        record = record_crc(
            self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate()
        )
        outcome = record_convictions(
            record,
            [{"category": category, "is_automatic_disqualifier": True, "description": "Disclosed"}],
        )
        self.volunteer.refresh_from_db()
        return record, outcome

    def test_every_policy_category_is_offered(self):
        """The list must match the policy, so a screener is never left guessing."""
        for category in (
            "Violent crime involving a weapon",
            "Crime against a child or youth",
            "Crime against a vulnerable adult",
            "Child abuse",
            "Abduction",
            "Murder or manslaughter",
            "Incest",
            "Rape",
            "Sexual assault",
        ):
            self.assertIn(category, DisqualifyingConviction.AUTOMATIC_CATEGORIES)

    def test_recording_one_permanently_disqualifies(self):
        _, outcome = self._disqualify()

        self.assertTrue(outcome["automatic_disqualifier"])
        self.assertFalse(outcome["requires_leadership_decision"])
        self.assertEqual(self.volunteer.screening_block, ScreeningBlock.DISQUALIFIED)
        self.assertTrue(self.volunteer.is_permanently_disqualified)
        self.assertIsNotNone(self.volunteer.screening_block_recorded_at)

    def test_current_positions_of_trust_are_ended_immediately(self):
        self._disqualify()
        self.assertEqual(self.volunteer.assignments.filter(is_active=True).count(), 0)

    def test_the_model_layer_refuses_to_lift_the_block(self):
        """
        The last line of defence: even a direct call cannot move off DISQUALIFIED.
        """
        self._disqualify()
        for target in (ScreeningBlock.NONE, ScreeningBlock.CRC_NOT_CLEAR, ScreeningBlock.WITHDRAWN):
            with self.subTest(target=target):
                with self.assertRaises(ValidationError):
                    self.volunteer.set_screening_block(target)

        self.volunteer.refresh_from_db()
        self.assertTrue(self.volunteer.is_permanently_disqualified)

    def test_a_later_cleared_check_cannot_undo_it(self):
        self._disqualify()
        with self.assertRaises(ValidationError):
            record_crc(
                self.volunteer, result=CRCResult.CLEARED, report_date=timezone.localdate()
            )

        self.volunteer.refresh_from_db()
        self.assertTrue(self.volunteer.is_permanently_disqualified)

    def test_no_override_can_be_recorded_against_it(self):
        record, _ = self._disqualify()
        conviction = record.convictions.get()

        with self.assertRaises(ValidationError):
            record_discretionary_override(
                record,
                conviction=conviction,
                decision=DiscretionaryOverride.Decision.APPROVED,
                decided_by="Board",
                reasoning="x" * 40,
                mitigation_steps="y" * 40,
            )
        self.assertEqual(DiscretionaryOverride.objects.count(), 0)

    def test_no_override_even_without_naming_the_conviction(self):
        """Closing the side door: an override attached to the check as a whole is refused too."""
        record, _ = self._disqualify()
        with self.assertRaises(ValidationError):
            record_discretionary_override(
                record,
                conviction=None,
                decision=DiscretionaryOverride.Decision.APPROVED,
                decided_by="Board",
                reasoning="x" * 40,
                mitigation_steps="y" * 40,
            )

    def test_the_conviction_cannot_be_deleted(self):
        record, _ = self._disqualify()
        conviction = record.convictions.get()
        with self.assertRaises(ProtectedDeletionError):
            conviction.delete()

    def test_cannot_be_assigned_to_a_position_of_trust(self):
        from apps.org.models import RoleAssignment

        self._disqualify()
        another_trust_role = self.make_role(self.department, "Nursery Helper")

        assignment = RoleAssignment(volunteer=self.volunteer, role=another_trust_role)
        with self.assertRaises(ValidationError):
            assignment.full_clean()

    def test_can_still_hold_a_role_that_is_not_a_position_of_trust(self):
        """
        The bar is on positions of trust specifically, not on every conceivable involvement.
        """
        from apps.org.models import RoleAssignment

        self._disqualify()
        greeter = self.make_role(self.department, "Bulletin Folder", is_position_of_trust=False)

        assignment = RoleAssignment(volunteer=self.volunteer, role=greeter)
        assignment.full_clean()  # must not raise

    def test_cannot_be_reactivated_into_service_through_the_view(self):
        self._disqualify()
        self.volunteer.is_active = False
        self.volunteer.stopped_serving_on = timezone.localdate()
        self.volunteer.save()

        client = self.signed_in_client()
        client.post(reverse("org:volunteer_reactivate", args=[self.volunteer.pk]))

        self.volunteer.refresh_from_db()
        self.assertFalse(self.volunteer.is_active)

    def test_there_is_no_url_that_lifts_a_disqualification(self):
        """
        A structural check: no route name in the requirements namespace suggests undoing a
        disqualification. Guards against a well-meaning future addition.
        """
        for name in (
            "crc_undisqualify",
            "crc_clear_block",
            "volunteer_undisqualify",
            "crc_remove_conviction",
        ):
            with self.subTest(name=name):
                with self.assertRaises(NoReverseMatch):
                    reverse(f"requirements:{name}", args=[1])

    def test_the_audit_trail_records_it_unmistakably(self):
        self._disqualify()
        event = AuditEvent.objects.filter(action=AuditAction.DISQUALIFIED).first()

        self.assertIsNotNone(event)
        self.assertIn("PERMANENTLY DISQUALIFIED", event.summary)
        self.assertIn("No override", event.summary)
        self.assertIn("Sexual assault", event.detail_data["automatic_categories"])

    def test_outstanding_requirements_are_blocked(self):
        self._disqualify()
        statuses = set(
            self.volunteer.requirement_instances.values_list("status", flat=True)
        )
        self.assertNotIn(RequirementStatus.NOT_STARTED, statuses)
        self.assertIn(RequirementStatus.BLOCKED, statuses)


class DiscretionaryOverrideTests(CRCBase):
    """Discretionary flags: a decision is allowed, but only a documented one."""

    def _flag(self, category="Theft or fraud"):
        record = record_crc(
            self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate()
        )
        outcome = record_convictions(
            record,
            [
                {
                    "category": category,
                    "is_automatic_disqualifier": False,
                    "description": "Disclosed at interview; 2011.",
                }
            ],
        )
        self.volunteer.refresh_from_db()
        return record, outcome

    def test_discretionary_flag_does_not_permanently_disqualify(self):
        _, outcome = self._flag()
        self.assertFalse(outcome["automatic_disqualifier"])
        self.assertTrue(outcome["requires_leadership_decision"])
        self.assertFalse(self.volunteer.is_permanently_disqualified)
        # Still blocked pending the decision, though.
        self.assertTrue(self.volunteer.is_blocked)

    def test_override_requires_reasoning_and_mitigation(self):
        record, _ = self._flag()
        conviction = record.convictions.get()

        for kwargs in (
            {"reasoning": "", "mitigation_steps": "Supervised at all times, reviewed yearly."},
            {"reasoning": "Long ago and disclosed openly.", "mitigation_steps": ""},
            {"reasoning": "   ", "mitigation_steps": "   "},
        ):
            with self.subTest(**kwargs):
                with self.assertRaises(ValidationError):
                    record_discretionary_override(
                        record,
                        conviction=conviction,
                        decision=DiscretionaryOverride.Decision.APPROVED,
                        decided_by="Board",
                        **kwargs,
                    )

    def test_override_requires_a_named_decision_maker(self):
        record, _ = self._flag()
        with self.assertRaises(ValidationError):
            record_discretionary_override(
                record,
                conviction=record.convictions.get(),
                decision=DiscretionaryOverride.Decision.APPROVED,
                decided_by="",
                reasoning="Disclosed at interview, offence was in 2011.",
                mitigation_steps="Never alone with children; reviewed each September.",
            )

    def test_approved_override_records_the_full_trail_and_lifts_the_block(self):
        record, _ = self._flag()
        override = record_discretionary_override(
            record,
            conviction=record.convictions.get(),
            decision=DiscretionaryOverride.Decision.APPROVED_WITH_CONDITIONS,
            decided_by="Board of Elders",
            reasoning="Single offence in 2011, disclosed voluntarily at interview.",
            mitigation_steps="Never alone with children; paired with a senior leader; reviewed each September.",
        )

        self.volunteer.refresh_from_db()
        self.assertEqual(self.volunteer.screening_block, ScreeningBlock.NONE)
        self.assertEqual(override.decided_by, "Board of Elders")
        self.assertIn("2011", override.reasoning)
        self.assertIn("senior leader", override.mitigation_steps)

    def test_declined_override_ends_positions_of_trust(self):
        record, _ = self._flag()
        record_discretionary_override(
            record,
            conviction=record.convictions.get(),
            decision=DiscretionaryOverride.Decision.DECLINED,
            decided_by="Board of Elders",
            reasoning="The offence is too recent for the board to be comfortable.",
            mitigation_steps="No mitigation is sufficient for a children's ministry role.",
        )

        self.volunteer.refresh_from_db()
        self.assertEqual(self.volunteer.screening_block, ScreeningBlock.WITHDRAWN)
        self.assertEqual(self.volunteer.assignments.filter(is_active=True).count(), 0)

    def test_an_override_cannot_be_edited(self):
        record, _ = self._flag()
        override = record_discretionary_override(
            record,
            conviction=record.convictions.get(),
            decision=DiscretionaryOverride.Decision.APPROVED,
            decided_by="Board",
            reasoning="Disclosed at interview, offence was in 2011 and unrelated.",
            mitigation_steps="Never alone with children; reviewed each September by the board.",
        )

        override.reasoning = "Actually, we changed our minds"
        with self.assertRaises(ProtectedDeletionError):
            override.save()

    def test_an_override_cannot_be_deleted(self):
        record, _ = self._flag()
        override = record_discretionary_override(
            record,
            conviction=record.convictions.get(),
            decision=DiscretionaryOverride.Decision.APPROVED,
            decided_by="Board",
            reasoning="Disclosed at interview, offence was in 2011 and unrelated.",
            mitigation_steps="Never alone with children; reviewed each September by the board.",
        )
        with self.assertRaises(ProtectedDeletionError):
            override.delete()

    def test_the_reasoning_is_encrypted(self):
        from django.db import connection

        record, _ = self._flag()
        override = record_discretionary_override(
            record,
            conviction=record.convictions.get(),
            decision=DiscretionaryOverride.Decision.APPROVED,
            decided_by="Board",
            reasoning="Shoplifting conviction in 2011, disclosed at interview.",
            mitigation_steps="Never alone with children; reviewed each September by the board.",
        )

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT reasoning, mitigation_steps FROM requirements_discretionaryoverride "
                "WHERE id = %s",
                [override.pk],
            )
            reasoning, mitigation = cursor.fetchone()

        self.assertTrue(reasoning.startswith("v1."))
        self.assertNotIn("Shoplifting", reasoning)
        self.assertTrue(mitigation.startswith("v1."))

    def test_override_is_audited(self):
        record, _ = self._flag()
        record_discretionary_override(
            record,
            conviction=record.convictions.get(),
            decision=DiscretionaryOverride.Decision.APPROVED,
            decided_by="Board of Elders",
            reasoning="Disclosed at interview, offence was in 2011 and unrelated.",
            mitigation_steps="Never alone with children; reviewed each September by the board.",
        )

        event = AuditEvent.objects.filter(action=AuditAction.OVERRIDE).first()
        self.assertIsNotNone(event)
        self.assertIn("Board of Elders", event.summary)
        self.assertIn("mitigation_steps", event.detail_data)


class CRCViewTests(CRCBase):
    """
    The interface must not offer what the policy forbids.

    Build Spec §4.3: "The UI must not offer an override path."
    """

    def setUp(self):
        super().setUp()
        self.client = self.signed_in_client()

    def test_override_page_is_refused_for_an_automatic_disqualifier(self):
        record = record_crc(
            self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate()
        )
        record_convictions(
            record, [{"category": "Child abuse", "is_automatic_disqualifier": True}]
        )

        response = self.client.get(reverse("requirements:crc_override", args=[record.pk]))
        self.assertEqual(response.status_code, 302)  # bounced back to the check

        response = self.client.post(
            reverse("requirements:crc_override", args=[record.pk]),
            {
                "decision": DiscretionaryOverride.Decision.APPROVED,
                "decided_by": "Board",
                "decided_on": timezone.localdate().isoformat(),
                "reasoning": "x" * 40,
                "mitigation_steps": "y" * 40,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(DiscretionaryOverride.objects.count(), 0)

    def test_crc_detail_hides_the_override_action_when_disqualified(self):
        record = record_crc(
            self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate()
        )
        record_convictions(record, [{"category": "Abduction", "is_automatic_disqualifier": True}])

        response = self.client.get(reverse("requirements:crc_detail", args=[record.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context["can_record_override"])
        self.assertNotContains(response, reverse("requirements:crc_override", args=[record.pk]))
        self.assertContains(response, "no override", status_code=200, msg_prefix="", html=False)

    def test_crc_detail_offers_the_override_for_a_discretionary_flag(self):
        record = record_crc(
            self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate()
        )
        record_convictions(
            record, [{"category": "Theft or fraud", "is_automatic_disqualifier": False}]
        )

        response = self.client.get(reverse("requirements:crc_detail", args=[record.pk]))
        self.assertTrue(response.context["can_record_override"])
        self.assertContains(response, reverse("requirements:crc_override", args=[record.pk]))

    def test_recording_a_new_check_is_refused_once_disqualified(self):
        record = record_crc(
            self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate()
        )
        record_convictions(record, [{"category": "Rape", "is_automatic_disqualifier": True}])

        response = self.client.get(reverse("requirements:crc_create", args=[self.volunteer.pk]))
        self.assertEqual(response.status_code, 302)

    def test_conviction_form_requires_the_permanence_acknowledgement(self):
        record = record_crc(
            self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate()
        )
        response = self.client.post(
            reverse("requirements:crc_conviction_add", args=[record.pk]),
            {"category": "Murder or manslaughter", "description": "Disclosed"},
        )

        self.assertEqual(response.status_code, 200)  # re-rendered with the error
        self.assertEqual(DisqualifyingConviction.objects.count(), 0)
        self.volunteer.refresh_from_db()
        self.assertFalse(self.volunteer.is_permanently_disqualified)

    def test_conviction_form_works_with_the_acknowledgement(self):
        record = record_crc(
            self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate()
        )
        response = self.client.post(
            reverse("requirements:crc_conviction_add", args=[record.pk]),
            {
                "category": "Murder or manslaughter",
                "description": "Disclosed",
                "acknowledge_permanent": "on",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.volunteer.refresh_from_db()
        self.assertTrue(self.volunteer.is_permanently_disqualified)

    def test_discretionary_conviction_needs_no_acknowledgement(self):
        record = record_crc(
            self.volunteer, result=CRCResult.NOT_CLEAR, report_date=timezone.localdate()
        )
        response = self.client.post(
            reverse("requirements:crc_conviction_add", args=[record.pk]),
            {"category": "Impaired driving", "description": "2019, disclosed"},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(DisqualifyingConviction.objects.count(), 1)
        self.volunteer.refresh_from_db()
        self.assertFalse(self.volunteer.is_permanently_disqualified)
