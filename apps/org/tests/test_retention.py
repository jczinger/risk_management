"""
Retention tests.

Build Spec §10: "Volunteer records cannot be hard-deleted through any UI or ORM path."

That is a legal requirement as much as a policy one — permanent retention for records
involving minors (PRD §6). These tests go looking for a delete, at every layer, and assert
each one is closed.
"""

from __future__ import annotations

import datetime

from django.core.exceptions import ValidationError
from django.urls import NoReverseMatch, reverse
from django.utils import timezone

from apps.core.models import AuditAction, AuditEvent, ProtectedDeletionError
from apps.core.tests.base import TenantTestCase
from apps.org.models import Department, Role, RoleAssignment, Volunteer


class NoHardDeleteTests(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.seed()
        self.department = self.make_department()
        self.role = self.make_role(self.department, "Teacher")
        self.volunteer = self.make_volunteer()
        self.assignment = self.assign(self.volunteer, self.role)

    def test_instance_delete_is_refused(self):
        with self.assertRaises(ProtectedDeletionError):
            self.volunteer.delete()
        self.assertTrue(Volunteer.objects.filter(pk=self.volunteer.pk).exists())

    def test_queryset_delete_is_refused(self):
        with self.assertRaises(ProtectedDeletionError):
            Volunteer.objects.all().delete()
        self.assertTrue(Volunteer.objects.filter(pk=self.volunteer.pk).exists())

    def test_filtered_queryset_delete_is_refused(self):
        with self.assertRaises(ProtectedDeletionError):
            Volunteer.objects.filter(last_name="Taylor").delete()
        self.assertTrue(Volunteer.objects.filter(pk=self.volunteer.pk).exists())

    def test_raw_delete_path_is_refused(self):
        """Closing the back door: ``_raw_delete`` bypasses ``delete()`` in normal Django."""
        with self.assertRaises(ProtectedDeletionError):
            Volunteer.objects.all()._raw_delete(using="default")

    def test_departments_roles_and_assignments_are_protected_too(self):
        for obj in (self.department, self.role, self.assignment):
            with self.subTest(model=type(obj).__name__):
                with self.assertRaises(ProtectedDeletionError):
                    obj.delete()

    def test_deleting_a_department_cannot_cascade_away_a_volunteers_history(self):
        """
        Even if a department delete were somehow forced, PROTECT on the foreign keys stops
        the cascade reaching a volunteer's records.
        """
        from django.db.models import ProtectedError
        from django.db.models import Model

        with self.assertRaises((ProtectedError, ProtectedDeletionError)):
            Model.delete(self.department)

    def test_requirement_instances_are_protected(self):
        from apps.requirements.services import sync_volunteer_requirements

        sync_volunteer_requirements(self.volunteer)
        instance = self.volunteer.requirement_instances.first()

        with self.assertRaises(ProtectedDeletionError):
            instance.delete()

    def test_crc_records_are_protected(self):
        from apps.requirements.models import CRCResult
        from apps.requirements.services import record_crc, sync_volunteer_requirements

        sync_volunteer_requirements(self.volunteer)
        record = record_crc(
            self.volunteer, result=CRCResult.CLEARED, report_date=timezone.localdate()
        )
        with self.assertRaises(ProtectedDeletionError):
            record.delete()

    def test_there_is_no_delete_url_for_a_volunteer(self):
        for name in ("volunteer_delete", "volunteer_remove", "volunteer_destroy", "volunteer_purge"):
            with self.subTest(name=name):
                with self.assertRaises(NoReverseMatch):
                    reverse(f"org:{name}", args=[self.volunteer.pk])

    def test_deactivation_is_the_supported_route_and_keeps_the_record(self):
        client = self.signed_in_client()
        response = client.post(
            reverse("org:volunteer_deactivate", args=[self.volunteer.pk]),
            {
                "stopped_serving_on": timezone.localdate().isoformat(),
                "end_assignments": "on",
                "reason": "Moved away",
            },
        )
        self.assertEqual(response.status_code, 302)

        self.volunteer.refresh_from_db()
        self.assertFalse(self.volunteer.is_active)
        self.assertEqual(self.volunteer.stopped_serving_on, timezone.localdate())
        # Still there, with its history.
        self.assertTrue(Volunteer.objects.filter(pk=self.volunteer.pk).exists())
        self.assertEqual(self.volunteer.assignments.count(), 1)
        self.assertEqual(self.volunteer.assignments.filter(is_active=True).count(), 0)

    def test_deactivation_is_audited_as_retained(self):
        client = self.signed_in_client()
        client.post(
            reverse("org:volunteer_deactivate", args=[self.volunteer.pk]),
            {"stopped_serving_on": timezone.localdate().isoformat(), "end_assignments": "on"},
        )

        event = AuditEvent.objects.filter(
            action=AuditAction.DEACTIVATE, entity_type="Volunteer"
        ).first()
        self.assertIsNotNone(event)
        self.assertTrue(event.detail_data.get("record_retained"))

    def test_a_deactivated_volunteer_can_return_to_service(self):
        self.volunteer.is_active = False
        self.volunteer.stopped_serving_on = timezone.localdate()
        self.volunteer.save()

        client = self.signed_in_client()
        client.post(reverse("org:volunteer_reactivate", args=[self.volunteer.pk]))

        self.volunteer.refresh_from_db()
        self.assertTrue(self.volunteer.is_active)
        self.assertIsNone(self.volunteer.stopped_serving_on)

    def test_ending_an_assignment_keeps_the_historical_row(self):
        self.assignment.end(datetime.date(2026, 6, 30))

        self.assignment.refresh_from_db()
        self.assertFalse(self.assignment.is_active)
        self.assertEqual(self.assignment.ended_on, datetime.date(2026, 6, 30))
        self.assertEqual(RoleAssignment.objects.count(), 1)

    def test_a_volunteer_can_serve_again_in_a_role_they_left(self):
        """
        The unique constraint is on *active* assignments only, so someone can leave and come
        back without the history getting in the way.
        """
        self.assignment.end()
        second = self.assign(self.volunteer, self.role)

        self.assertEqual(RoleAssignment.objects.count(), 2)
        self.assertTrue(second.is_active)

    def test_two_active_assignments_to_the_same_role_are_refused(self):
        from django.db.utils import IntegrityError

        with self.assertRaises(IntegrityError):
            RoleAssignment.objects.create(volunteer=self.volunteer, role=self.role)


class AuditTrailImmutabilityTests(TenantTestCase):
    """The audit trail is append-only (Build Spec §6)."""

    def _event(self):
        from apps.core import audit

        return audit.record(
            AuditAction.CREATE, "Volunteer", entity_id=1, entity_label="A Person",
            summary="Created", detail={"before": {}, "after": {"x": 1}},
        )

    def test_an_entry_cannot_be_edited(self):
        event = self._event()
        event.summary = "Something else"
        with self.assertRaises(ProtectedDeletionError):
            event.save()

    def test_an_entry_cannot_be_deleted(self):
        event = self._event()
        with self.assertRaises(ProtectedDeletionError):
            event.delete()

    def test_queryset_update_is_refused(self):
        self._event()
        with self.assertRaises(ProtectedDeletionError):
            AuditEvent.objects.all().update(summary="rewritten")

    def test_queryset_delete_is_refused(self):
        self._event()
        with self.assertRaises(ProtectedDeletionError):
            AuditEvent.objects.all().delete()

    def test_raw_delete_is_refused(self):
        self._event()
        with self.assertRaises(ProtectedDeletionError):
            AuditEvent.objects.all()._raw_delete(using="default")

    def test_the_detail_payload_is_encrypted(self):
        from django.db import connection

        from apps.core import audit

        audit.record(
            AuditAction.UPDATE,
            "Volunteer",
            entity_id=7,
            summary="Address changed",
            detail={"changed": {"address": {"before": "1 Old Road", "after": "2 New Road"}}},
        )

        with connection.cursor() as cursor:
            cursor.execute("SELECT detail FROM core_auditevent ORDER BY id DESC LIMIT 1")
            (detail,) = cursor.fetchone()

        self.assertTrue(detail.startswith("v1."))
        self.assertNotIn("Old Road", detail)
        self.assertNotIn("New Road", detail)

    def test_metadata_stays_plaintext_so_the_viewer_can_filter(self):
        from django.db import connection

        self._event()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT action, entity_type, actor_display FROM core_auditevent "
                "ORDER BY id DESC LIMIT 1"
            )
            action, entity_type, actor = cursor.fetchone()

        self.assertEqual(action, AuditAction.CREATE)
        self.assertEqual(entity_type, "Volunteer")
        self.assertTrue(actor)

    def test_the_actor_is_recorded_from_the_request(self):
        client = self.signed_in_client(self.make_admin(email="acting@test.ca"))
        client.post(
            reverse("org:department_create"),
            {"name": "Youth", "description": "", "is_active": "on"},
        )

        event = AuditEvent.objects.filter(entity_type="Department").first()
        self.assertIsNotNone(event)
        self.assertEqual(event.actor_display, "Test Admin")
        self.assertIsNotNone(event.actor_user_id)


class VolunteerValidationTests(TenantTestCase):
    """Model-level guards on the volunteer record."""

    def test_birth_year_and_month_must_agree_with_the_full_date(self):
        volunteer = Volunteer(
            first_name="A",
            last_name="B",
            date_of_birth=datetime.date(1990, 5, 10),
            birth_year=1985,
            birth_month=5,
        )
        with self.assertRaises(ValidationError):
            volunteer.full_clean()

    def test_saving_derives_year_and_month_from_the_full_date(self):
        volunteer = self.make_volunteer(date_of_birth=datetime.date(1990, 5, 10), age=None)
        self.assertEqual(volunteer.birth_year, 1990)
        self.assertEqual(volunteer.birth_month, 5)

    def test_birth_year_alone_is_refused(self):
        volunteer = Volunteer(first_name="A", last_name="B", birth_year=1990)
        with self.assertRaises(ValidationError):
            volunteer.full_clean()

    def test_future_birth_year_is_refused(self):
        volunteer = Volunteer(
            first_name="A", last_name="B", birth_year=timezone.localdate().year + 1, birth_month=1
        )
        with self.assertRaises(ValidationError):
            volunteer.full_clean()

    def test_deactivating_requires_a_date(self):
        volunteer = self.make_volunteer()
        volunteer.is_active = False
        with self.assertRaises(ValidationError):
            volunteer.full_clean()

    def test_assignment_end_date_cannot_precede_the_start(self):
        volunteer = self.make_volunteer()
        role = self.make_role()
        assignment = RoleAssignment(
            volunteer=volunteer,
            role=role,
            started_on=datetime.date(2026, 6, 1),
            ended_on=datetime.date(2026, 5, 1),
            is_active=False,
        )
        with self.assertRaises(ValidationError):
            assignment.full_clean()

    def test_role_names_are_unique_within_a_department_only(self):
        from django.db.utils import IntegrityError

        first = self.make_department("Children")
        second = self.make_department("Youth")

        Role.objects.create(department=first, name="Helper")
        # Same name in a different department is fine.
        Role.objects.create(department=second, name="Helper")

        with self.assertRaises(IntegrityError):
            Role.objects.create(department=first, name="Helper")

    def test_waiting_period_needs_six_months_or_a_transfer(self):
        recent = self.make_volunteer(
            attendance_since=timezone.localdate() - datetime.timedelta(days=60)
        )
        self.assertFalse(recent.waiting_period_satisfied)

        settled = self.make_volunteer(
            attendance_since=timezone.localdate() - datetime.timedelta(days=200)
        )
        self.assertTrue(settled.waiting_period_satisfied)

        transfer = self.make_volunteer(is_transfer=True)
        self.assertTrue(transfer.waiting_period_satisfied)

    def test_display_name_prefers_the_preferred_name(self):
        volunteer = self.make_volunteer(
            first_name="Jonathan", last_name="Smith", preferred_name="Jonny"
        )
        self.assertEqual(volunteer.display_name, "Jonny Smith")
        self.assertEqual(volunteer.full_name, "Jonathan Smith")
        self.assertEqual(volunteer.sort_name, "Smith, Jonathan")
