"""
Requirement engine tests.

Covers the mechanics: which requirements attach to whom, how expiry is computed from
cadence, what happens when roles change, and the waiver rules.
"""

from __future__ import annotations

import datetime

from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.core.tests.base import TenantTestCase
from apps.org.models import ScreeningBlock
from apps.requirements.models import (
    AgeRule,
    AppliesTo,
    Cadence,
    RequirementDefinition,
    RequirementStatus,
    RequirementType,
    add_months_to,
)
from apps.requirements.seed import SEED_TEMPLATE, seed_default_template
from apps.requirements.services import (
    mark_requirement_complete,
    onboarding_window_breached,
    recompute_all_statuses,
    sync_volunteer_requirements,
    waive_requirement,
)


class AddMonthsTests(TenantTestCase):
    """Date arithmetic for renewal dates. Month-end clamping is the interesting case."""

    def test_simple_addition(self):
        self.assertEqual(add_months_to(datetime.date(2026, 1, 15), 12), datetime.date(2027, 1, 15))
        self.assertEqual(add_months_to(datetime.date(2026, 1, 15), 36), datetime.date(2029, 1, 15))

    def test_month_end_is_clamped_not_overflowed(self):
        # 31 Jan + 1 month is the end of February, not 3 March.
        self.assertEqual(add_months_to(datetime.date(2026, 1, 31), 1), datetime.date(2026, 2, 28))
        self.assertEqual(add_months_to(datetime.date(2024, 1, 31), 1), datetime.date(2024, 2, 29))

    def test_leap_day_plus_one_year(self):
        self.assertEqual(add_months_to(datetime.date(2024, 2, 29), 12), datetime.date(2025, 2, 28))

    def test_year_boundary(self):
        self.assertEqual(add_months_to(datetime.date(2026, 12, 15), 1), datetime.date(2027, 1, 15))

    def test_negative_months(self):
        self.assertEqual(add_months_to(datetime.date(2026, 1, 15), -3), datetime.date(2025, 10, 15))


class CadenceTests(TenantTestCase):
    """Expiry follows from the cadence and the completion date."""

    def test_one_time_never_expires(self):
        definition = RequirementDefinition.objects.create(
            name="One time thing",
            requirement_type=RequirementType.CUSTOM,
            cadence=Cadence.ONE_TIME,
        )
        self.assertIsNone(definition.expiry_for(datetime.date(2026, 5, 1)))
        self.assertFalse(definition.is_recurring)

    def test_annual_expires_in_twelve_months(self):
        definition = RequirementDefinition.objects.create(
            name="Annual thing",
            requirement_type=RequirementType.SIGNED_AGREEMENT,
            cadence=Cadence.ANNUAL,
        )
        self.assertEqual(definition.expiry_for(datetime.date(2026, 5, 1)), datetime.date(2027, 5, 1))

    def test_three_years_expires_in_thirty_six_months(self):
        definition = RequirementDefinition.objects.create(
            name="CRC-like",
            requirement_type=RequirementType.CRIMINAL_RECORD_CHECK,
            cadence=Cadence.EVERY_3_YEARS,
        )
        self.assertEqual(definition.expiry_for(datetime.date(2026, 5, 1)), datetime.date(2029, 5, 1))

    def test_custom_months(self):
        definition = RequirementDefinition.objects.create(
            name="Every 18 months",
            requirement_type=RequirementType.CUSTOM,
            cadence=Cadence.CUSTOM_MONTHS,
            cadence_months=18,
        )
        self.assertEqual(definition.expiry_for(datetime.date(2026, 1, 1)), datetime.date(2027, 7, 1))

    def test_custom_cadence_requires_a_month_count(self):
        definition = RequirementDefinition(
            name="Broken custom",
            requirement_type=RequirementType.CUSTOM,
            cadence=Cadence.CUSTOM_MONTHS,
        )
        with self.assertRaises(ValidationError):
            definition.full_clean()


class SeedTemplateTests(TenantTestCase):
    """The starter template every new church receives (Build Spec §4.2)."""

    def test_seeding_creates_fourteen_requirements(self):
        self.assertEqual(seed_default_template(), 14)
        self.assertEqual(RequirementDefinition.objects.count(), 14)

    def test_template_matches_the_spec_shape(self):
        seed_default_template()

        crc = RequirementDefinition.objects.get(
            requirement_type=RequirementType.CRIMINAL_RECORD_CHECK
        )
        self.assertEqual(crc.cadence, Cadence.EVERY_3_YEARS)
        self.assertEqual(crc.age_rule, AgeRule.ADULTS_ONLY)
        # Everyone: every role is a position of trust (BUILD_NOTES.md §1.14).
        self.assertEqual(crc.applies_to, AppliesTo.ALL_ROLES)

        refresher = RequirementDefinition.objects.get(
            requirement_type=RequirementType.TRAINING_REFRESHER
        )
        self.assertEqual(refresher.cadence, Cadence.ANNUAL)

        orientation = RequirementDefinition.objects.get(
            requirement_type=RequirementType.TRAINING_ORIENTATION
        )
        self.assertEqual(orientation.cadence, Cadence.ONE_TIME)

        confidentiality = RequirementDefinition.objects.get(name="Confidentiality Agreement")
        self.assertEqual(confidentiality.applies_to, AppliesTo.ALL_ROLES)
        self.assertEqual(confidentiality.cadence, Cadence.ONE_TIME)

        for name in ("Code of Conduct", "Covenant of Care"):
            self.assertEqual(RequirementDefinition.objects.get(name=name).cadence, Cadence.ANNUAL)

    def test_liability_release_precedes_reference_checks(self):
        """The one ordering rule the policy specifies (Build Spec §4.2 item 4)."""
        seed_default_template()
        references = RequirementDefinition.objects.get(
            requirement_type=RequirementType.REFERENCE_CHECKS
        )
        self.assertIsNotNone(references.must_follow)
        self.assertEqual(
            references.must_follow.requirement_type, RequirementType.LIABILITY_RELEASE
        )

    def test_seeding_is_idempotent_and_preserves_edits(self):
        seed_default_template()
        interview = RequirementDefinition.objects.get(requirement_type=RequirementType.INTERVIEW)
        interview.name = "Interview — renamed by this church"
        interview.cadence = Cadence.ANNUAL
        interview.save()

        # The renamed one no longer matches the template name, so re-seeding re-adds the
        # template item; the church's edited copy is left alone either way.
        seed_default_template()
        interview.refresh_from_db()
        self.assertEqual(interview.name, "Interview — renamed by this church")
        self.assertEqual(interview.cadence, Cadence.ANNUAL)

    def test_reseeding_unchanged_template_adds_nothing(self):
        seed_default_template()
        self.assertEqual(seed_default_template(), 0)
        self.assertEqual(RequirementDefinition.objects.count(), 14)

    def test_template_contains_no_policy_prose(self):
        """
        Guard on the licensing constraint (Build Spec §0): the template may carry names,
        cadences and appendix references only. Descriptions are our own instructions, so
        they should read as guidance for an admin, not as quoted policy.
        """
        for entry in SEED_TEMPLATE:
            description = entry.get("description", "")
            self.assertNotIn("©", description)
            self.assertNotIn("Copyright", description)
            # Appendix pointers belong in their own field, not embedded in prose.
            self.assertLess(len(description), 700, entry["name"])

    def test_admin_can_deactivate_a_seeded_requirement(self):
        seed_default_template()
        definition = RequirementDefinition.objects.get(name="Covenant of Care")
        definition.is_active = False
        definition.save()

        self.assertEqual(RequirementDefinition.objects.active().count(), 13)


class ApplicabilityTests(TenantTestCase):
    """Which requirements attach to which volunteer, via role flags."""

    def setUp(self):
        super().setUp()
        self.department = self.make_department()
        self.helper = self.make_role(self.department, "Helper")
        self.director = self.make_role(
            self.department, "Director", is_leadership=True
        )
        self.registrar = self.make_role(self.department, "Registrar")
        self.greeter = self.make_role(self.department, "Greeter")

    def test_all_roles_requirement_applies_to_everyone(self):
        definition = RequirementDefinition.objects.create(
            name="Everyone", requirement_type=RequirementType.CUSTOM, applies_to=AppliesTo.ALL_ROLES
        )
        for role in (self.helper, self.director, self.registrar, self.greeter):
            self.assertTrue(definition.applies_to_role(role), role.name)

    def test_leadership_requirement_applies_only_to_flagged_roles(self):
        definition = RequirementDefinition.objects.create(
            name="Leaders only",
            requirement_type=RequirementType.CUSTOM,
            applies_to=AppliesTo.LEADERSHIP,
        )
        self.assertTrue(definition.applies_to_role(self.director))
        self.assertFalse(definition.applies_to_role(self.helper))

    def test_the_retired_targets_are_no_longer_offered(self):
        """
        "Handles personal information" and "Positions of trust" are gone.

        Every role is both, so a requirement that would have used either applies to
        everyone. Asserted on the choices themselves: leaving a dead option in the
        dropdown would let an admin build a requirement that silently matches nobody.
        """
        offered = {value for value, _ in AppliesTo.choices}
        self.assertEqual(offered, {"all", "specific", "leadership"})

    def test_the_confidentiality_agreement_reaches_every_volunteer(self):
        """The reason the personal-information flag was removed, stated as behaviour."""
        seed_default_template()
        confidentiality = RequirementDefinition.objects.get(name="Confidentiality Agreement")

        for role in (self.helper, self.director, self.registrar, self.greeter):
            self.assertTrue(confidentiality.applies_to_role(role), role.name)

    def test_specific_roles_requirement_matches_only_the_selection(self):
        definition = RequirementDefinition.objects.create(
            name="Just the registrar",
            requirement_type=RequirementType.CUSTOM,
            applies_to=AppliesTo.SPECIFIC_ROLES,
        )
        definition.roles.add(self.registrar)
        self.assertTrue(definition.applies_to_role(self.registrar))
        self.assertFalse(definition.applies_to_role(self.helper))

    def test_directors_are_screened_like_anyone_else(self):
        """
        Build Spec §3: leadership is a flag, not a lighter screening path. A director must
        pick up every all-roles requirement too.
        """
        seed_default_template()
        volunteer = self.make_volunteer()
        self.assign(volunteer, self.director)
        sync_volunteer_requirements(volunteer)

        names = set(
            volunteer.requirement_instances.values_list("definition__name", flat=True)
        )
        self.assertIn("Ministry Personnel Application Form", names)
        self.assertIn("Criminal Record Check + Vulnerable Sector Search", names)
        self.assertIn("Plan to Protect policy agreement", names)


class SyncTests(TenantTestCase):
    """Reconciling a volunteer's instances with their current roles."""

    def setUp(self):
        super().setUp()
        self.seed()
        self.department = self.make_department()
        self.role = self.make_role(self.department, "Sunday School Teacher")
        self.registrar = self.make_role(self.department, "Registrar")

    def test_no_roles_means_no_requirements(self):
        volunteer = self.make_volunteer()
        result = sync_volunteer_requirements(volunteer)
        self.assertEqual(result["created"], 0)
        self.assertEqual(volunteer.requirement_instances.count(), 0)

    def test_assigning_a_role_creates_instances(self):
        volunteer = self.make_volunteer()
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer)

        # All 14 seeded items. Nothing in the template targets a role flag any more —
        # the Confidentiality Agreement used to be conditional and is now universal.
        self.assertEqual(volunteer.requirement_instances.count(), 14)
        self.assertTrue(
            volunteer.requirement_instances.filter(
                definition__name="Confidentiality Agreement"
            ).exists()
        )

    def test_an_ordinary_role_owes_the_criminal_record_check(self):
        """Also no longer conditional: every role is a position of trust."""
        volunteer = self.make_volunteer(age=34)
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer)

        self.assertTrue(
            volunteer.requirement_instances.filter(
                definition__requirement_type=RequirementType.CRIMINAL_RECORD_CHECK
            ).exists()
        )

    def test_sync_is_idempotent(self):
        volunteer = self.make_volunteer()
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer)
        before = volunteer.requirement_instances.count()

        second = sync_volunteer_requirements(volunteer)
        self.assertEqual(second["created"], 0)
        self.assertEqual(second["updated"], 0)
        self.assertEqual(volunteer.requirement_instances.count(), before)

    def test_ending_a_role_retires_outstanding_requirements_but_keeps_completed_ones(self):
        """
        A requirement that stops applying becomes not_applicable, never deleted — the record
        that it was once satisfied is part of the volunteer's history.
        """
        volunteer = self.make_volunteer()
        assignment = self.assign(volunteer, self.registrar)
        sync_volunteer_requirements(volunteer)

        confidentiality = volunteer.requirement_instances.get(
            definition__name="Confidentiality Agreement"
        )
        mark_requirement_complete(confidentiality, timezone.localdate())

        interview = volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.INTERVIEW
        )
        self.assertEqual(interview.status, RequirementStatus.NOT_STARTED)

        assignment.end()
        sync_volunteer_requirements(volunteer)

        confidentiality.refresh_from_db()
        interview.refresh_from_db()
        # Completed history survives untouched...
        self.assertEqual(confidentiality.status, RequirementStatus.COMPLETE)
        # ...while what was still owed stops being owed.
        self.assertEqual(interview.status, RequirementStatus.NOT_APPLICABLE)
        self.assertEqual(volunteer.requirement_instances.count(), 14)

    def test_flagging_a_role_as_leadership_requires_it_of_current_holders(self):
        """
        Changing a role's flag must flow through to everyone already serving in it.

        Previously written against ``handles_personal_info``; ``is_leadership`` is the
        only role flag left, and the propagation behaviour is what matters here.
        """
        covenant = RequirementDefinition.objects.create(
            name="Ministry Leader Covenant",
            requirement_type=RequirementType.SIGNED_AGREEMENT,
            applies_to=AppliesTo.LEADERSHIP,
        )

        volunteer = self.make_volunteer()
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer)
        self.assertFalse(
            volunteer.requirement_instances.filter(
                definition=covenant,
                status__in=RequirementStatus.outstanding_values(),
            ).exists()
        )

        self.role.is_leadership = True
        self.role.save()
        sync_volunteer_requirements(volunteer)

        self.assertTrue(
            volunteer.requirement_instances.filter(
                definition=covenant,
                status=RequirementStatus.NOT_STARTED,
            ).exists()
        )

    def test_deactivated_definitions_are_not_created(self):
        RequirementDefinition.objects.filter(
            requirement_type=RequirementType.INTERVIEW
        ).update(is_active=False)

        volunteer = self.make_volunteer()
        self.assign(volunteer, self.role)
        sync_volunteer_requirements(volunteer)

        self.assertFalse(
            volunteer.requirement_instances.filter(
                definition__requirement_type=RequirementType.INTERVIEW
            ).exists()
        )


class CompletionAndExpiryTests(TenantTestCase):
    """Recording completion, and the status transitions that follow from dates."""

    def setUp(self):
        super().setUp()
        self.seed()
        self.role = self.make_role(name="Teacher")
        self.volunteer = self.make_volunteer()
        self.assign(self.volunteer, self.role)
        sync_volunteer_requirements(self.volunteer)

    def _instance(self, requirement_type):
        return self.volunteer.requirement_instances.get(
            definition__requirement_type=requirement_type
        )

    def test_completing_an_annual_requirement_sets_a_one_year_expiry(self):
        instance = self.volunteer.requirement_instances.get(definition__name="Code of Conduct")
        completed = datetime.date(2026, 3, 10)
        mark_requirement_complete(instance, completed)
        instance.refresh_from_db()

        self.assertEqual(instance.status, RequirementStatus.COMPLETE)
        self.assertEqual(instance.completed_on, completed)
        self.assertEqual(instance.expires_on, datetime.date(2027, 3, 10))

    def test_completing_a_one_time_requirement_leaves_no_expiry(self):
        instance = self._instance(RequirementType.INTERVIEW)
        mark_requirement_complete(instance, timezone.localdate())
        instance.refresh_from_db()

        self.assertEqual(instance.status, RequirementStatus.COMPLETE)
        self.assertIsNone(instance.expires_on)

    def test_future_completion_date_is_refused(self):
        instance = self._instance(RequirementType.INTERVIEW)
        with self.assertRaises(ValidationError):
            mark_requirement_complete(instance, timezone.localdate() + datetime.timedelta(days=1))

    def test_expired_requirement_becomes_overdue_on_recompute(self):
        instance = self.volunteer.requirement_instances.get(definition__name="Code of Conduct")
        mark_requirement_complete(instance, timezone.localdate() - datetime.timedelta(days=400))
        instance.refresh_from_db()
        self.assertEqual(instance.status, RequirementStatus.COMPLETE)
        self.assertTrue(instance.is_expired)

        recompute_all_statuses()
        instance.refresh_from_db()
        self.assertEqual(instance.status, RequirementStatus.OVERDUE)

    def test_renewing_an_overdue_requirement_restores_compliance(self):
        instance = self.volunteer.requirement_instances.get(definition__name="Code of Conduct")
        mark_requirement_complete(instance, timezone.localdate() - datetime.timedelta(days=400))
        recompute_all_statuses()
        instance.refresh_from_db()
        self.assertEqual(instance.status, RequirementStatus.OVERDUE)

        mark_requirement_complete(instance, timezone.localdate())
        instance.refresh_from_db()
        self.assertEqual(instance.status, RequirementStatus.COMPLETE)
        self.assertFalse(instance.is_expired)

    def test_bucket_reflects_the_renewal_window(self):
        instance = self.volunteer.requirement_instances.get(definition__name="Code of Conduct")

        # Just completed: comfortably compliant.
        mark_requirement_complete(instance, timezone.localdate())
        instance.refresh_from_db()
        self.assertEqual(instance.bucket, "satisfied")

        # Completed 11 months ago: inside the 60-day warning window.
        mark_requirement_complete(instance, timezone.localdate() - datetime.timedelta(days=330))
        instance.refresh_from_db()
        self.assertEqual(instance.bucket, "due_soon")

        # Completed 13 months ago: lapsed.
        mark_requirement_complete(instance, timezone.localdate() - datetime.timedelta(days=400))
        instance.refresh_from_db()
        self.assertEqual(instance.bucket, "overdue")

    def test_recompute_never_invents_a_completion(self):
        instance = self._instance(RequirementType.INTERVIEW)
        recompute_all_statuses()
        instance.refresh_from_db()
        self.assertEqual(instance.status, RequirementStatus.NOT_STARTED)
        self.assertIsNone(instance.completed_on)


class WaiverTests(TenantTestCase):
    """Waivers need a reason, and the criminal record check cannot be waived at all."""

    def setUp(self):
        super().setUp()
        self.seed()
        self.role = self.make_role(name="Teacher")
        self.volunteer = self.make_volunteer()
        self.assign(self.volunteer, self.role)
        sync_volunteer_requirements(self.volunteer)

    def test_waiving_records_the_reason_and_authoriser(self):
        instance = self.volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.INTERVIEW
        )
        waive_requirement(
            instance,
            reason="Interviewed by the district in 2024; record held at district office.",
            waived_by="Pastor Lee",
        )
        instance.refresh_from_db()

        self.assertEqual(instance.status, RequirementStatus.WAIVED)
        self.assertEqual(instance.waived_by, "Pastor Lee")
        self.assertIn("district", instance.waived_reason)
        self.assertIsNotNone(instance.waived_on)

    def test_waiver_reason_is_mandatory(self):
        instance = self.volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.INTERVIEW
        )
        with self.assertRaises(ValidationError):
            waive_requirement(instance, reason="   ", waived_by="Pastor Lee")

    def test_criminal_record_check_cannot_be_waived(self):
        """
        The policy has an age exemption and a Not Clear process, but no route to skipping
        the check for an adult in a position of trust.
        """
        instance = self.volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.CRIMINAL_RECORD_CHECK
        )
        with self.assertRaises(ValidationError):
            waive_requirement(instance, reason="Known to us for years", waived_by="Pastor Lee")

        instance.refresh_from_db()
        self.assertNotEqual(instance.status, RequirementStatus.WAIVED)

    def test_waived_requirements_count_as_satisfied(self):
        instance = self.volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.INTERVIEW
        )
        waive_requirement(instance, reason="Recorded elsewhere, see file.", waived_by="Pastor Lee")
        instance.refresh_from_db()
        self.assertEqual(instance.bucket, "satisfied")


class OnboardingWindowTests(TenantTestCase):
    """The policy's three-month onboarding window (Build Spec §4.2 item 8)."""

    def setUp(self):
        super().setUp()
        self.seed()
        self.role = self.make_role(name="Teacher")
        self.volunteer = self.make_volunteer()
        self.assign(self.volunteer, self.role)
        sync_volunteer_requirements(self.volunteer)

    def test_no_warning_before_anything_starts(self):
        self.assertFalse(onboarding_window_breached(self.volunteer))

    def test_no_warning_inside_three_months(self):
        instance = self.volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.APPLICATION_FORM
        )
        mark_requirement_complete(instance, timezone.localdate() - datetime.timedelta(days=30))
        self.assertFalse(onboarding_window_breached(self.volunteer))

    def test_warning_once_past_three_months_with_approval_outstanding(self):
        instance = self.volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.APPLICATION_FORM
        )
        mark_requirement_complete(instance, timezone.localdate() - datetime.timedelta(days=150))
        self.assertTrue(onboarding_window_breached(self.volunteer))

    def test_no_warning_once_leadership_approval_is_recorded(self):
        application = self.volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.APPLICATION_FORM
        )
        mark_requirement_complete(application, timezone.localdate() - datetime.timedelta(days=150))

        approval = self.volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.LEADERSHIP_APPROVAL
        )
        mark_requirement_complete(approval, timezone.localdate())

        self.assertFalse(onboarding_window_breached(self.volunteer))
