"""
Age rule tests (Build Spec §4.4).

The rules under test:

* Under 18 — screened the same way as an adult, but **no criminal record check**.
* On turning 18 — the check is activated automatically, with three months to submit it.
* The activation date is the **1st of the birth month** of the 18th year, so it fires up to
  a month early and never late.

Everything is computed from the plaintext ``birth_year``/``birth_month`` columns, because
the nightly job has to be able to *query* for who is turning 18 — which an encrypted date
of birth could not support.
"""

from __future__ import annotations

import datetime

from django.utils import timezone

from apps.core.tests.base import TenantTestCase
from apps.org.models import Volunteer
from apps.requirements.models import RequirementStatus, RequirementType
from apps.requirements.services import (
    REASON_NO_BIRTH_DATE,
    REASON_UNDER_18,
    activate_turning_18_checks,
    sync_volunteer_requirements,
)


class AgeComputationTests(TenantTestCase):
    """
    Age from year and month alone.

    VMS treats the birthday as the 1st of the birth month. One convention, applied
    everywhere, so the exemption and the activation cannot disagree.
    """

    def _volunteer(self, year, month):
        return Volunteer(first_name="A", last_name="B", birth_year=year, birth_month=month)

    def test_age_on_the_first_of_the_birth_month(self):
        volunteer = self._volunteer(2008, 5)
        self.assertEqual(volunteer.age_on(datetime.date(2026, 5, 1)), 18)

    def test_age_the_day_before_the_birth_month(self):
        volunteer = self._volunteer(2008, 5)
        self.assertEqual(volunteer.age_on(datetime.date(2026, 4, 30)), 17)

    def test_age_later_in_the_birth_month(self):
        volunteer = self._volunteer(2008, 5)
        self.assertEqual(volunteer.age_on(datetime.date(2026, 5, 31)), 18)

    def test_age_in_a_later_month(self):
        volunteer = self._volunteer(2008, 5)
        self.assertEqual(volunteer.age_on(datetime.date(2026, 12, 1)), 18)

    def test_january_birth_month_across_the_year_boundary(self):
        volunteer = self._volunteer(2008, 1)
        self.assertEqual(volunteer.age_on(datetime.date(2025, 12, 31)), 17)
        self.assertEqual(volunteer.age_on(datetime.date(2026, 1, 1)), 18)

    def test_december_birth_month(self):
        volunteer = self._volunteer(2008, 12)
        self.assertEqual(volunteer.age_on(datetime.date(2026, 11, 30)), 17)
        self.assertEqual(volunteer.age_on(datetime.date(2026, 12, 1)), 18)

    def test_adulthood_flips_exactly_when_the_trigger_date_arrives(self):
        """
        The single most important consistency property: ``is_adult_on`` must become True on
        precisely the date the criminal record check is activated. If these ever diverge,
        the nightly job and the applicability check fight each other.
        """
        volunteer = self._volunteer(2008, 7)
        trigger = volunteer.eighteenth_birthday_trigger_date()

        self.assertEqual(trigger, datetime.date(2026, 7, 1))
        self.assertFalse(volunteer.is_adult_on(trigger - datetime.timedelta(days=1)))
        self.assertTrue(volunteer.is_adult_on(trigger))

    def test_unknown_date_of_birth_is_treated_as_a_minor(self):
        volunteer = Volunteer(first_name="A", last_name="B")
        self.assertIsNone(volunteer.age)
        self.assertFalse(volunteer.is_adult)
        self.assertFalse(volunteer.is_minor)  # unknown, not known-to-be-a-minor
        self.assertIsNone(volunteer.eighteenth_birthday_trigger_date())

    def test_exact_age_uses_the_encrypted_full_date(self):
        today = timezone.localdate()
        dob = datetime.date(today.year - 30, today.month, 28)
        volunteer = self.make_volunteer(date_of_birth=dob, age=None)

        # The coarse rule says 30 from the 1st of the month; the exact one accounts for the
        # day, so on the 1st it may still read 29.
        self.assertEqual(volunteer.age, 30)
        self.assertIn(volunteer.exact_age, (29, 30))


class Under18ExemptionTests(TenantTestCase):
    """Under-18s are screened identically, minus the criminal record check."""

    def setUp(self):
        super().setUp()
        self.seed()
        self.role = self.make_role(name="Youth Helper")

    def _crc_instance(self, volunteer):
        return volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.CRIMINAL_RECORD_CHECK
        )

    def test_minor_gets_crc_marked_not_applicable_with_a_stated_reason(self):
        volunteer = self.make_volunteer(age=16)
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer)

        instance = self._crc_instance(volunteer)
        self.assertEqual(instance.status, RequirementStatus.NOT_APPLICABLE)
        self.assertEqual(instance.not_applicable_reason, REASON_UNDER_18)

    def test_minor_still_gets_every_other_requirement(self):
        volunteer = self.make_volunteer(age=16)
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer)

        outstanding = volunteer.requirement_instances.filter(
            status=RequirementStatus.NOT_STARTED
        ).values_list("definition__requirement_type", flat=True)

        for required in (
            RequirementType.APPLICATION_FORM,
            RequirementType.DECLARATION_OF_FAITH,
            RequirementType.LIABILITY_RELEASE,
            RequirementType.REFERENCE_CHECKS,
            RequirementType.INTERVIEW,
            RequirementType.POLICY_AGREEMENT,
            RequirementType.LEADERSHIP_APPROVAL,
            RequirementType.TRAINING_ORIENTATION,
        ):
            self.assertIn(required, outstanding, f"minor should still need {required}")

    def test_adult_gets_the_crc_as_outstanding(self):
        volunteer = self.make_volunteer(age=25)
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer)

        self.assertEqual(self._crc_instance(volunteer).status, RequirementStatus.NOT_STARTED)

    def test_volunteer_with_no_date_of_birth_is_exempted_with_a_visible_reason(self):
        """
        Erring toward not_applicable is the safe direction — the alternative would record a
        check as satisfied for someone whose age was never captured. The reason names the
        gap so it is not silently lost.
        """
        volunteer = self.make_volunteer(age=None)
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer)

        instance = self._crc_instance(volunteer)
        self.assertEqual(instance.status, RequirementStatus.NOT_APPLICABLE)
        self.assertEqual(instance.not_applicable_reason, REASON_NO_BIRTH_DATE)
        self.assertFalse(volunteer.has_birth_date)

    def test_recording_a_date_of_birth_activates_the_check_for_an_adult(self):
        volunteer = self.make_volunteer(age=None)
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer)
        self.assertEqual(self._crc_instance(volunteer).status, RequirementStatus.NOT_APPLICABLE)

        today = timezone.localdate()
        volunteer.date_of_birth = datetime.date(today.year - 40, today.month, 10)
        volunteer.save()
        sync_volunteer_requirements(volunteer)

        self.assertEqual(self._crc_instance(volunteer).status, RequirementStatus.NOT_STARTED)


class Turning18Tests(TenantTestCase):
    """The nightly activation on turning 18, with the policy's three-month deadline."""

    def setUp(self):
        super().setUp()
        self.seed()
        self.role = self.make_role(name="Youth Helper")

    def _crc_instance(self, volunteer):
        return volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.CRIMINAL_RECORD_CHECK
        )

    def _minor_turning_18_in(self, months_from_now: int):
        """A volunteer whose 18th birth month is ``months_from_now`` months away."""
        today = timezone.localdate()
        target_month_index = today.month - 1 + months_from_now
        year = today.year + target_month_index // 12
        month = target_month_index % 12 + 1

        volunteer = self.make_volunteer(
            first_name="Alex", last_name="Young", date_of_birth=datetime.date(year - 18, month, 20), age=None
        )
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer)
        return volunteer

    def test_nothing_activates_while_still_under_18(self):
        volunteer = self._minor_turning_18_in(6)
        self.assertEqual(self._crc_instance(volunteer).status, RequirementStatus.NOT_APPLICABLE)

        activated = activate_turning_18_checks()
        self.assertEqual(activated, [])
        self.assertEqual(self._crc_instance(volunteer).status, RequirementStatus.NOT_APPLICABLE)

    def test_check_activates_on_the_first_of_the_birth_month(self):
        volunteer = self.make_volunteer(
            first_name="Alex",
            last_name="Young",
            date_of_birth=datetime.date(2008, 6, 25),
            age=None,
        )
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer, as_of=datetime.date(2026, 5, 20))
        self.assertEqual(self._crc_instance(volunteer).status, RequirementStatus.NOT_APPLICABLE)

        # The day before the birth month: still exempt.
        self.assertEqual(activate_turning_18_checks(datetime.date(2026, 5, 31)), [])
        self.assertEqual(self._crc_instance(volunteer).status, RequirementStatus.NOT_APPLICABLE)

        # The 1st of the birth month: activated, even though the actual birthday is the 25th.
        activated = activate_turning_18_checks(datetime.date(2026, 6, 1))
        self.assertEqual(len(activated), 1)

        instance = self._crc_instance(volunteer)
        self.assertEqual(instance.status, RequirementStatus.NOT_STARTED)
        self.assertEqual(instance.due_on, datetime.date(2026, 9, 1))
        self.assertIn("18", instance.due_reason)

    def test_activation_is_early_never_late(self):
        """
        Someone born on the 25th is activated on the 1st — up to a month early. Early is
        compliance-safe; late would mean an 18-year-old serving without a check.
        """
        volunteer = self.make_volunteer(
            date_of_birth=datetime.date(2008, 6, 25), age=None
        )
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer, as_of=datetime.date(2026, 5, 1))

        activate_turning_18_checks(datetime.date(2026, 6, 1))
        instance = self._crc_instance(volunteer)

        actual_birthday = datetime.date(2026, 6, 25)
        self.assertLess(instance.due_on - datetime.timedelta(days=92), actual_birthday)

    def test_deadline_is_three_months_from_activation(self):
        volunteer = self.make_volunteer(date_of_birth=datetime.date(2008, 11, 4), age=None)
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer, as_of=datetime.date(2026, 10, 1))

        activate_turning_18_checks(datetime.date(2026, 11, 1))
        self.assertEqual(self._crc_instance(volunteer).due_on, datetime.date(2027, 2, 1))

    def test_activation_is_idempotent(self):
        volunteer = self.make_volunteer(date_of_birth=datetime.date(2008, 6, 25), age=None)
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer, as_of=datetime.date(2026, 5, 1))

        self.assertEqual(len(activate_turning_18_checks(datetime.date(2026, 6, 1))), 1)
        # Already active, so a second pass must not touch it or reset the deadline.
        self.assertEqual(activate_turning_18_checks(datetime.date(2026, 6, 2)), [])

    def test_missing_the_deadline_makes_it_overdue(self):
        from apps.requirements.services import recompute_all_statuses

        volunteer = self.make_volunteer(date_of_birth=datetime.date(2008, 6, 25), age=None)
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer, as_of=datetime.date(2026, 5, 1))
        activate_turning_18_checks(datetime.date(2026, 6, 1))

        # One day past the three-month deadline.
        recompute_all_statuses(datetime.date(2026, 9, 2))

        instance = self._crc_instance(volunteer)
        self.assertEqual(instance.status, RequirementStatus.OVERDUE)

    def test_activation_skips_volunteers_whose_role_no_longer_requires_it(self):
        volunteer = self.make_volunteer(date_of_birth=datetime.date(2008, 6, 25), age=None)
        assignment = self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer, as_of=datetime.date(2026, 5, 1))

        assignment.end()
        self.assertEqual(activate_turning_18_checks(datetime.date(2026, 6, 1)), [])

    def test_activation_skips_inactive_volunteers(self):
        volunteer = self.make_volunteer(date_of_birth=datetime.date(2008, 6, 25), age=None)
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer, as_of=datetime.date(2026, 5, 1))

        volunteer.is_active = False
        volunteer.stopped_serving_on = datetime.date(2026, 5, 20)
        volunteer.save()

        self.assertEqual(activate_turning_18_checks(datetime.date(2026, 6, 1)), [])

    def test_recording_the_check_clears_the_deadline(self):
        from apps.requirements.models import CRCResult
        from apps.requirements.services import record_crc

        volunteer = self.make_volunteer(date_of_birth=datetime.date(2008, 6, 25), age=None)
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer, as_of=datetime.date(2026, 5, 1))
        activate_turning_18_checks(datetime.date(2026, 6, 1))

        record_crc(volunteer, result=CRCResult.CLEARED, report_date=timezone.localdate())

        instance = self._crc_instance(volunteer)
        self.assertEqual(instance.status, RequirementStatus.COMPLETE)
        self.assertIsNone(instance.due_on)
