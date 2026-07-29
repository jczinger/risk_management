"""
Requirement engine tests.

Covers the mechanics: which requirements attach to whom, how expiry is computed from
cadence, what happens when roles change, and the waiver rules.
"""

from __future__ import annotations

import datetime

from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.core.models import AuditAction
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
from apps.requirements.forms import WaiverReversalForm
from apps.requirements.seed import SEED_TEMPLATE, seed_default_template
from apps.requirements.services import (
    mark_requirement_complete,
    onboarding_window_breached,
    recompute_all_statuses,
    reverse_waiver,
    sync_volunteer_requirements,
    waive_requirement,
)


def extract_row(html: str, instance) -> str:
    """
    The markup for one requirement's row on the volunteer page.

    Bounded by the *next* row rather than by a character count. A fixed-width slice
    overruns into the following requirement, so an assertion about which buttons a row
    offers ends up reading its neighbour's — which is exactly how a real bug hid.
    """
    marker = f'id="req-{instance.pk}"'
    assert marker in html, f"no row rendered for requirement {instance.pk}"
    start = html.index(marker)
    following = html.find('id="req-', start + len(marker))
    return html[start:following] if following != -1 else html[start:]


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


class RequirementRowActionTests(TenantTestCase):
    """
    The buttons on a requirement row, driven through HTTP.

    Two rules are being enforced here. Anything backed by a document is completed by
    recording that document, so it offers no "Mark complete" — otherwise the tick and
    the evidence can disagree. Anything *not* backed by a document keeps the button, or
    it could only ever be waived.
    """

    def setUp(self):
        super().setUp()
        seed_default_template()
        self.volunteer = self.make_volunteer(age=40)
        self.assign(self.volunteer, self.make_role())
        sync_volunteer_requirements(self.volunteer)
        self.client = self.signed_in_client()

    def instance_for(self, name: str):
        return self.volunteer.requirement_instances.get(definition__name=name)

    def volunteer_page(self) -> str:
        from django.urls import reverse

        response = self.client.get(reverse("org:volunteer_detail", args=[self.volunteer.pk]))
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def row_for(self, instance) -> str:
        """Just the markup for one requirement's row, and nothing of the next one."""
        return extract_row(self.volunteer_page(), instance)

    def test_a_document_backed_requirement_offers_no_mark_complete(self):
        row = self.row_for(self.instance_for("Confidentiality Agreement"))

        self.assertNotIn("Mark complete", row)
        self.assertIn("Add document", row)

    def test_a_requirement_needing_no_document_keeps_mark_complete(self):
        """
        The Interview has no document to record.

        Without the button it could only ever be waived, which is why the rule is "no
        tick where there is a document" rather than "no tick anywhere".
        """
        interview = self.instance_for("Interview")
        self.assertFalse(interview.definition.requires_document)

        row = self.row_for(interview)
        self.assertIn("Mark complete", row)

    def test_every_seeded_requirement_can_be_satisfied_somehow(self):
        """
        The guard on the rule above: no requirement may become a dead end.

        Each one needs either a document route or a completion button, or an admin has
        no way to satisfy it short of a waiver.

        A gated requirement is exempt while it waits — the refresher training offers no
        action until orientation is recorded, which is the point of the gate rather than
        a dead end. ``test_a_released_gate_offers_its_action`` covers the other half.
        """
        for instance in self.volunteer.requirement_instances.select_related("definition"):
            with self.subTest(requirement=instance.definition.name):
                self.assertTrue(
                    instance.definition.requires_document
                    or instance.definition.is_crc
                    or instance.definition.unmet_prerequisite(self.volunteer) is not None
                    or "Mark complete" in self.row_for(instance),
                )

    def test_a_released_gate_offers_its_action(self):
        """The other half: once the prerequisite is done, the dead end must open."""
        from apps.requirements.services import mark_requirement_complete

        orientation = self.instance_for("Plan to Protect orientation training")
        mark_requirement_complete(orientation, timezone.localdate())

        refresher = self.instance_for("Plan to Protect refresher training")
        self.assertEqual(refresher.status, RequirementStatus.NOT_STARTED)
        self.assertIn("Mark complete", self.row_for(refresher))

    def test_the_button_is_labelled_as_a_status_change(self):
        row = self.row_for(self.instance_for("Interview"))

        self.assertIn("Mark as in progress", row)
        self.assertNotIn(">Start<", row)


class MarkInProgressTests(TenantTestCase):
    """The htmx status change, which must not navigate anywhere."""

    def setUp(self):
        super().setUp()
        seed_default_template()
        self.volunteer = self.make_volunteer(age=40)
        self.assign(self.volunteer, self.make_role())
        sync_volunteer_requirements(self.volunteer)
        self.client = self.signed_in_client()
        self.instance = self.volunteer.requirement_instances.get(
            definition__name="Interview"
        )

    def url(self):
        from django.urls import reverse

        return reverse("requirements:instance_start", args=[self.instance.pk])

    def test_an_htmx_click_swaps_the_row_and_does_not_redirect(self):
        response = self.client.post(self.url(), HTTP_HX_REQUEST="true")

        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        # The row itself came back, not a whole page.
        self.assertIn(f'id="req-{self.instance.pk}"', html)
        self.assertNotIn("<!doctype html>", html.lower())
        self.assertIn("In progress", html)

        self.instance.refresh_from_db()
        self.assertEqual(self.instance.status, RequirementStatus.IN_PROGRESS)

    def test_the_swapped_row_no_longer_offers_the_button(self):
        html = self.client.post(self.url(), HTTP_HX_REQUEST="true").content.decode()

        self.assertNotIn("Mark as in progress", html)

    def test_it_still_works_without_htmx(self):
        """The button must degrade to an ordinary POST and redirect."""
        response = self.client.post(self.url())

        self.assertEqual(response.status_code, 302)
        self.instance.refresh_from_db()
        self.assertEqual(self.instance.status, RequirementStatus.IN_PROGRESS)

    def test_it_records_the_change_in_the_audit_trail(self):
        from apps.core.models import AuditEvent

        self.client.post(self.url(), HTTP_HX_REQUEST="true")

        self.assertTrue(
            AuditEvent.objects.filter(
                entity_type="RequirementInstance",
                entity_id=str(self.instance.pk),
                summary="Marked in progress",
            ).exists()
        )

    def test_a_get_is_refused(self):
        self.assertEqual(self.client.get(self.url()).status_code, 405)


class WaivedIsAlreadySatisfiedTests(TenantTestCase):
    """
    A waiver is the decision that a requirement is met.

    It counts as satisfied for compliance and it carries a reason and an audit entry, so
    "mark complete" must not sit beside it — clicking the obvious button should never
    overwrite a recorded decision.
    """

    def setUp(self):
        super().setUp()
        seed_default_template()
        self.volunteer = self.make_volunteer(age=40)
        self.assign(self.volunteer, self.make_role())
        sync_volunteer_requirements(self.volunteer)
        self.client = self.signed_in_client()

        # The waiting period needs no document, so before this change it kept the
        # button even once waived — which is exactly what was reported.
        self.instance = self.volunteer.requirement_instances.get(
            definition__name="Waiting period — 6 months regular attendance"
        )
        waive_requirement(
            self.instance, reason="Attending this church for seven years", waived_by="Pat Lee"
        )
        self.instance.refresh_from_db()

    def complete_url(self):
        from django.urls import reverse

        return reverse("requirements:instance_complete", args=[self.instance.pk])

    def test_a_waived_requirement_offers_no_completion(self):
        self.assertFalse(self.instance.can_mark_complete)

    def test_the_volunteer_page_does_not_offer_it(self):
        from django.urls import reverse

        html = self.client.get(
            reverse("org:volunteer_detail", args=[self.volunteer.pk])
        ).content.decode()

        row = extract_row(html, self.instance)
        self.assertIn("Waived", row)
        self.assertNotIn("Mark complete", row)

    def test_the_requirement_page_does_not_offer_it(self):
        from django.urls import reverse

        response = self.client.get(
            reverse("requirements:instance_detail", args=[self.instance.pk])
        )
        self.assertNotContains(response, "Mark complete")

    def test_reaching_the_url_directly_is_refused(self):
        """The interface hides it; the view must decline it too."""
        response = self.client.get(self.complete_url())
        self.assertEqual(response.status_code, 302)

        response = self.client.post(
            self.complete_url(), {"completed_on": timezone.localdate().isoformat(), "notes": ""}
        )
        self.assertEqual(response.status_code, 302)

        self.instance.refresh_from_db()
        self.assertEqual(self.instance.status, RequirementStatus.WAIVED)
        self.assertIn("seven years", self.instance.waived_reason)

    def test_the_refusal_explains_itself(self):
        response = self.client.get(self.complete_url(), follow=True)
        body = response.content.decode()

        self.assertIn("waived by Pat Lee", body)

    def test_a_document_backed_requirement_is_refused_with_its_own_reason(self):
        from django.urls import reverse

        confidentiality = self.volunteer.requirement_instances.get(
            definition__name="Confidentiality Agreement"
        )
        response = self.client.get(
            reverse("requirements:instance_complete", args=[confidentiality.pk]), follow=True
        )

        self.assertIn("Add document", response.content.decode())

    def test_a_waiver_still_counts_as_satisfied(self):
        """The premise behind hiding the button, asserted directly."""
        self.assertIn(RequirementStatus.WAIVED, RequirementStatus.satisfied_values())
        self.assertEqual(self.instance.bucket, "satisfied")


class WaiverReversalTests(TenantTestCase):
    """
    Undoing a waiver.

    Nothing in the policy makes a waiver permanent — Build Spec §4.1 asks only that it
    carry a reason and reach the audit trail — and a waiver is a judgement, which can be
    wrong. Reversing one is therefore allowed, takes a comment, and appends its own
    entry. That is a different thing from lifting a disqualification, which has no route
    at all; test_crc.py hunts for one.
    """

    def setUp(self):
        super().setUp()
        seed_default_template()
        self.role = self.make_role(name="Teacher")
        self.volunteer = self.make_volunteer(age=40)
        self.assign(self.volunteer, self.role)
        sync_volunteer_requirements(self.volunteer)

        self.instance = self.volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.INTERVIEW
        )
        waive_requirement(
            self.instance, reason="Interviewed at the district office", waived_by="Pat Lee"
        )
        self.instance.refresh_from_db()

    # -- Service ----------------------------------------------------------

    def test_reversing_returns_it_to_not_started(self):
        reverse_waiver(self.instance, reason="Waived the wrong volunteer", reversed_by="Sam")

        self.instance.refresh_from_db()
        self.assertEqual(self.instance.status, RequirementStatus.NOT_STARTED)

    def test_reversing_clears_the_waiver_from_the_record(self):
        """A row that is not waived must not still show waiver details."""
        reverse_waiver(self.instance, reason="Waived the wrong volunteer", reversed_by="Sam")

        self.instance.refresh_from_db()
        self.assertEqual(self.instance.waived_reason, "")
        self.assertEqual(self.instance.waived_by, "")
        self.assertIsNone(self.instance.waived_on)

    def test_something_started_before_the_waiver_returns_to_in_progress(self):
        self.instance.started_on = timezone.localdate() - datetime.timedelta(days=20)
        self.instance.save(update_fields=["started_on"])

        reverse_waiver(self.instance, reason="Waived by mistake entirely", reversed_by="Sam")

        self.instance.refresh_from_db()
        self.assertEqual(self.instance.status, RequirementStatus.IN_PROGRESS)

    def test_something_completed_before_the_waiver_returns_to_complete(self):
        self.instance.completed_on = timezone.localdate() - datetime.timedelta(days=10)
        self.instance.save(update_fields=["completed_on"])

        reverse_waiver(self.instance, reason="Waived by mistake entirely", reversed_by="Sam")

        self.instance.refresh_from_db()
        self.assertEqual(self.instance.status, RequirementStatus.COMPLETE)

    def test_a_completion_that_expired_while_waived_comes_back_overdue(self):
        """recompute() runs after the reversal, so the row reflects today."""
        self.instance.completed_on = timezone.localdate() - datetime.timedelta(days=400)
        self.instance.expires_on = timezone.localdate() - datetime.timedelta(days=35)
        self.instance.save(update_fields=["completed_on", "expires_on"])

        reverse_waiver(self.instance, reason="Waived by mistake entirely", reversed_by="Sam")

        self.instance.refresh_from_db()
        self.assertEqual(self.instance.status, RequirementStatus.OVERDUE)

    def test_a_reason_is_required(self):
        for empty in ("", "   "):
            with self.subTest(reason=empty), self.assertRaises(ValidationError):
                reverse_waiver(self.instance, reason=empty, reversed_by="Sam")

        self.instance.refresh_from_db()
        self.assertEqual(self.instance.status, RequirementStatus.WAIVED)

    def test_something_that_is_not_waived_cannot_be_reversed(self):
        other = self.volunteer.requirement_instances.exclude(pk=self.instance.pk).first()

        with self.assertRaises(ValidationError):
            reverse_waiver(other, reason="Nothing to undo here", reversed_by="Sam")

    # -- Audit ------------------------------------------------------------

    def test_the_comment_is_visible_in_the_audit_summary(self):
        """
        The summary, not just the detail.

        An audit entry's detail is recorded but not displayed, so a reason kept only
        there would be invisible to the reader it is written for.
        """
        from apps.core.models import AuditEvent

        reverse_waiver(
            self.instance, reason="Confused two volunteers named Joe", reversed_by="Sam Lee"
        )

        event = AuditEvent.objects.filter(action=AuditAction.WAIVER_REVERSED).get()
        self.assertIn("Confused two volunteers named Joe", event.summary)
        self.assertIn("Sam Lee", event.summary)

    def test_the_comment_fits_the_summary_whole(self):
        """The form's cap exists so nothing is silently truncated. Prove the cap works."""
        from apps.core.models import AuditEvent

        reason = "x" * WaiverReversalForm.MAX_REASON
        reverse_waiver(self.instance, reason=reason, reversed_by="Sam")

        event = AuditEvent.objects.filter(action=AuditAction.WAIVER_REVERSED).get()
        self.assertLessEqual(len(event.summary), 255)
        self.assertIn(reason, event.summary)

    def test_the_original_waiver_entry_is_left_alone(self):
        """Append, never amend — the trail is append-only."""
        from apps.core.models import AuditEvent

        original = AuditEvent.objects.filter(action=AuditAction.WAIVE).get()

        reverse_waiver(self.instance, reason="Waived the wrong volunteer", reversed_by="Sam")

        original.refresh_from_db()
        self.assertEqual(original.summary, "Waived by Pat Lee")
        self.assertEqual(AuditEvent.objects.filter(action=AuditAction.WAIVE).count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action=AuditAction.WAIVER_REVERSED).count(), 1)

    # -- Knock-on effects -------------------------------------------------

    def test_it_is_chased_again_afterwards(self):
        """A waived requirement is excluded from reminders; a reversed one is not."""
        from apps.notifications.services import find_due_reminders

        def chased() -> bool:
            return any(
                entry["instance"].pk == self.instance.pk
                for entry in find_due_reminders(self.tenant)
            )

        self.instance.due_on = timezone.localdate() - datetime.timedelta(days=1)
        self.instance.save(update_fields=["due_on"])

        self.assertFalse(chased(), "a waived requirement must not be chased")

        reverse_waiver(self.instance, reason="Waived the wrong volunteer", reversed_by="Sam")

        self.assertTrue(chased(), "a reversed requirement must be chased again")

    def test_it_counts_as_outstanding_again(self):
        self.assertEqual(self.instance.bucket, "satisfied")

        reverse_waiver(self.instance, reason="Waived the wrong volunteer", reversed_by="Sam")

        self.instance.refresh_from_db()
        self.assertEqual(self.instance.bucket, "outstanding")
        self.assertNotIn(self.instance.status, RequirementStatus.satisfied_values())

    def test_completion_is_offered_again(self):
        self.assertFalse(self.instance.can_mark_complete)

        reverse_waiver(self.instance, reason="Waived the wrong volunteer", reversed_by="Sam")

        self.instance.refresh_from_db()
        self.assertTrue(self.instance.can_mark_complete)


class WaiverReversalViewTests(TenantTestCase):
    """The reversal screen, driven through HTTP."""

    def setUp(self):
        super().setUp()
        seed_default_template()
        self.volunteer = self.make_volunteer(age=40)
        self.assign(self.volunteer, self.make_role())
        sync_volunteer_requirements(self.volunteer)
        self.client = self.signed_in_client()

        self.instance = self.volunteer.requirement_instances.get(
            definition__requirement_type=RequirementType.INTERVIEW
        )
        waive_requirement(self.instance, reason="Interviewed elsewhere", waived_by="Pat Lee")
        self.instance.refresh_from_db()

    def url(self, instance=None):
        from django.urls import reverse

        return reverse(
            "requirements:instance_reverse_waiver", args=[(instance or self.instance).pk]
        )

    def test_a_waived_row_offers_the_reversal(self):
        from django.urls import reverse

        html = self.client.get(
            reverse("org:volunteer_detail", args=[self.volunteer.pk])
        ).content.decode()

        row = extract_row(html, self.instance)
        self.assertIn("Reverse waiver", row)
        self.assertNotIn(">Waive<", row)

    def test_a_row_that_is_not_waived_does_not(self):
        from django.urls import reverse

        other = self.volunteer.requirement_instances.exclude(pk=self.instance.pk).first()
        html = self.client.get(
            reverse("org:volunteer_detail", args=[self.volunteer.pk])
        ).content.decode()

        row = extract_row(html, other)
        self.assertNotIn("Reverse waiver", row)

    def test_the_page_warns_what_reversing_does(self):
        response = self.client.get(self.url())

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "back in play")
        self.assertContains(response, "reminder emails")
        self.assertContains(response, "Pat Lee")

    def test_posting_reverses_it(self):
        response = self.client.post(
            self.url(), {"reason": "Waived the wrong volunteer", "reversed_by": "Sam Lee"}
        )

        self.assertEqual(response.status_code, 302)
        self.instance.refresh_from_db()
        self.assertEqual(self.instance.status, RequirementStatus.NOT_STARTED)

    def test_a_short_comment_is_refused(self):
        response = self.client.post(self.url(), {"reason": "oops", "reversed_by": "Sam"})

        self.assertEqual(response.status_code, 200)
        self.instance.refresh_from_db()
        self.assertEqual(self.instance.status, RequirementStatus.WAIVED)

    def test_a_comment_too_long_for_the_audit_summary_is_refused(self):
        response = self.client.post(
            self.url(),
            {"reason": "x" * (WaiverReversalForm.MAX_REASON + 1), "reversed_by": "Sam"},
        )

        self.assertEqual(response.status_code, 200)
        self.instance.refresh_from_db()
        self.assertEqual(self.instance.status, RequirementStatus.WAIVED)

    def test_the_url_is_refused_for_a_requirement_that_is_not_waived(self):
        other = self.volunteer.requirement_instances.exclude(pk=self.instance.pk).first()

        response = self.client.get(self.url(other))
        self.assertEqual(response.status_code, 302)

        response = self.client.post(
            self.url(other), {"reason": "Trying it on regardless", "reversed_by": "Sam"}
        )
        self.assertEqual(response.status_code, 302)
        # Nothing was written: no reversal entry exists for it.
        from apps.core.models import AuditEvent

        self.assertFalse(
            AuditEvent.objects.filter(
                action=AuditAction.WAIVER_REVERSED, entity_id=str(other.pk)
            ).exists()
        )
