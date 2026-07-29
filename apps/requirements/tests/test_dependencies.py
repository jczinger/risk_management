"""
Requirement dependencies (BUILD_NOTES §1.18).

Two capabilities: a requirement can be held not-applicable until its prerequisite is
complete, and its first deadline can be counted from the *prerequisite's* completion
date rather than from today. The driving case is refresher training, which is not owed
until orientation has happened and then falls due a year after it.

Structured like ``test_age_rules.py``, because the mechanism is the same one: a visible
``not_applicable`` instance with a stated reason, released by ``_activate``.
"""

from __future__ import annotations

import datetime

from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.core.tests.base import TenantTestCase
from apps.requirements.models import (
    Cadence,
    DependencyMode,
    RequirementDefinition,
    RequirementStatus,
    RequirementType,
)
from apps.requirements.seed import SEED_TEMPLATE, seed_default_template
from apps.requirements.services import (
    mark_requirement_complete,
    recompute_all_statuses,
    record_crc,
    reverse_waiver,
    sync_volunteer_requirements,
    waive_requirement,
)

ORIENTATION = "Plan to Protect orientation training"
REFRESHER = "Plan to Protect refresher training"


class DependencyBase(TenantTestCase):
    """A volunteer with the seeded template, so orientation gates the refresher."""

    def setUp(self):
        super().setUp()
        seed_default_template()
        self.volunteer = self.make_volunteer(age=40)
        self.assign(self.volunteer, self.make_role())
        sync_volunteer_requirements(self.volunteer)

    def instance_for(self, name: str):
        return self.volunteer.requirement_instances.get(definition__name=name)

    def complete_orientation(self, *, days_ago: int = 0):
        orientation = self.instance_for(ORIENTATION)
        mark_requirement_complete(
            orientation, timezone.localdate() - datetime.timedelta(days=days_ago)
        )
        return orientation


class DependencyConfigurationTests(TenantTestCase):
    """The definition side: validation, the offset, and the seeded wiring."""

    def setUp(self):
        super().setUp()
        seed_default_template()

    def test_the_seeded_reference_check_dependency_is_only_a_warning(self):
        """
        The upgrade-safety assertion.

        Every church already has this pair in their database. Gating is opt-in, so it
        must still behave exactly as it did before dependencies became load-bearing.
        """
        references = RequirementDefinition.objects.get(
            requirement_type=RequirementType.REFERENCE_CHECKS
        )
        self.assertIsNotNone(references.must_follow)
        self.assertEqual(references.dependency_mode, DependencyMode.WARN)
        self.assertFalse(references.is_gated)

    def test_the_seeded_refresher_is_gated_by_the_orientation(self):
        refresher = RequirementDefinition.objects.get(name=REFRESHER)
        self.assertTrue(refresher.is_gated)
        self.assertEqual(refresher.must_follow.name, ORIENTATION)

    def test_every_prerequisite_precedes_its_dependent_in_the_template(self):
        """
        Seeding resolves dependencies in one pass, so order in SEED_TEMPLATE is load
        bearing. A pure-data check — no database needed.
        """
        seen: set[str] = set()
        for entry in SEED_TEMPLATE:
            follows = entry.get("must_follow_key")
            if follows:
                self.assertIn(
                    follows,
                    seen,
                    f"'{entry['key']}' depends on '{follows}', which is listed after it",
                )
            seen.add(entry["key"])

    def test_the_offset_falls_back_to_the_cadence(self):
        """Why the refresher needs no explicit offset: annual already means 12 months."""
        refresher = RequirementDefinition.objects.get(name=REFRESHER)
        self.assertIsNone(refresher.due_months_after_prerequisite)
        self.assertEqual(refresher.cadence, Cadence.ANNUAL)
        self.assertEqual(refresher.prerequisite_offset_months, 12)

    def test_an_explicit_offset_wins(self):
        refresher = RequirementDefinition.objects.get(name=REFRESHER)
        refresher.due_months_after_prerequisite = 6
        refresher.save(update_fields=["due_months_after_prerequisite"])
        self.assertEqual(refresher.prerequisite_offset_months, 6)

    def test_a_one_time_dependent_has_no_offset(self):
        """No interval and no explicit months means no deadline, not an invented one."""
        orientation = RequirementDefinition.objects.get(name=ORIENTATION)
        gated = RequirementDefinition.objects.create(
            name="Shadowing shift",
            requirement_type=RequirementType.CUSTOM,
            cadence=Cadence.ONE_TIME,
            must_follow=orientation,
            dependency_mode=DependencyMode.GATE,
        )
        self.assertIsNone(gated.prerequisite_offset_months)

    def test_a_requirement_cannot_depend_on_itself(self):
        definition = RequirementDefinition.objects.get(name=REFRESHER)
        definition.must_follow = definition
        with self.assertRaises(ValidationError):
            definition.full_clean()

    def test_a_two_step_loop_is_refused(self):
        orientation = RequirementDefinition.objects.get(name=ORIENTATION)
        # The refresher already follows orientation; pointing orientation back at it
        # closes the loop.
        orientation.must_follow = RequirementDefinition.objects.get(name=REFRESHER)
        with self.assertRaises(ValidationError):
            orientation.full_clean()

    def test_a_three_step_loop_is_refused(self):
        first = RequirementDefinition.objects.create(
            name="Step one", requirement_type=RequirementType.CUSTOM
        )
        second = RequirementDefinition.objects.create(
            name="Step two", requirement_type=RequirementType.CUSTOM, must_follow=first
        )
        third = RequirementDefinition.objects.create(
            name="Step three", requirement_type=RequirementType.CUSTOM, must_follow=second
        )
        first.must_follow = third
        with self.assertRaises(ValidationError):
            first.full_clean()

    def test_gating_without_a_prerequisite_is_refused(self):
        definition = RequirementDefinition.objects.get(name=ORIENTATION)
        definition.dependency_mode = DependencyMode.GATE
        with self.assertRaises(ValidationError):
            definition.full_clean()

    def test_the_dropdown_cannot_offer_a_loop(self):
        """The form excludes everything downstream, not merely the record itself."""
        from apps.requirements.forms import RequirementDefinitionForm

        orientation = RequirementDefinition.objects.get(name=ORIENTATION)
        offered = RequirementDefinitionForm(instance=orientation).fields["must_follow"].queryset

        self.assertNotIn(orientation, offered)
        self.assertNotIn(RequirementDefinition.objects.get(name=REFRESHER), offered)


class GatedApplicabilityTests(DependencyBase):
    """While the prerequisite is outstanding."""

    def test_the_refresher_waits_for_the_orientation(self):
        refresher = self.instance_for(REFRESHER)

        self.assertEqual(refresher.status, RequirementStatus.NOT_APPLICABLE)
        self.assertEqual(
            refresher.not_applicable_reason,
            f"Not required until {ORIENTATION} is complete",
        )

    def test_a_gated_requirement_counts_as_satisfied(self):
        """
        The accepted consequence, asserted rather than left implicit.

        It is not owed yet, so the volunteer reads as compliant — the same trade already
        made for the under-18 criminal-record-check exemption.
        """
        self.assertEqual(self.instance_for(REFRESHER).bucket, "satisfied")

    def test_a_gated_requirement_offers_no_completion(self):
        self.assertFalse(self.instance_for(REFRESHER).can_mark_complete)

    def test_a_second_sync_does_not_release_the_gate(self):
        """
        The sharp edge.

        The reactivation branch of _reconcile_existing switches on any not-applicable
        instance whose role applies and which is not age-exempt. Without a third
        condition it un-gates everything on the very next sync.
        """
        sync_volunteer_requirements(self.volunteer)
        sync_volunteer_requirements(self.volunteer)

        self.assertEqual(self.instance_for(REFRESHER).status, RequirementStatus.NOT_APPLICABLE)

    def test_it_is_not_chased_while_gated(self):
        from apps.notifications.services import find_due_reminders

        refresher = self.instance_for(REFRESHER)
        self.assertFalse(
            any(e["instance"].pk == refresher.pk for e in find_due_reminders(self.tenant))
        )

    def test_an_advisory_dependency_does_not_gate(self):
        """The regression guard for the seeded pair: a warning must stay a warning."""
        references = self.instance_for("Reference checks")
        self.assertEqual(references.status, RequirementStatus.NOT_STARTED)

    def test_a_retired_prerequisite_releases_the_gate(self):
        """A church deactivating orientation must not freeze every refresher."""
        orientation = RequirementDefinition.objects.get(name=ORIENTATION)
        orientation.is_active = False
        orientation.save(update_fields=["is_active"])

        sync_volunteer_requirements(self.volunteer)

        self.assertEqual(self.instance_for(REFRESHER).status, RequirementStatus.NOT_STARTED)

    def test_the_age_exemption_wins_when_both_apply(self):
        """A gate is "not yet"; an age exemption is "not at all" — say the truer one."""
        minor = self.make_volunteer(first_name="Sam", last_name="Young", age=15)
        self.assign(minor, self.make_role(self.make_department("Youth"), "Helper"))

        crc = RequirementDefinition.objects.get(
            requirement_type=RequirementType.CRIMINAL_RECORD_CHECK
        )
        crc.must_follow = RequirementDefinition.objects.get(name=ORIENTATION)
        crc.dependency_mode = DependencyMode.GATE
        crc.save(update_fields=["must_follow", "dependency_mode"])

        sync_volunteer_requirements(minor)

        instance = minor.requirement_instances.get(definition=crc)
        self.assertEqual(instance.status, RequirementStatus.NOT_APPLICABLE)
        self.assertIn("Under 18", instance.not_applicable_reason)

    def test_turning_18_does_not_release_a_prerequisite_gate(self):
        """The nightly age scan bypasses sync, so it needs its own guard."""
        from apps.requirements.services import activate_turning_18_checks

        crc = RequirementDefinition.objects.get(
            requirement_type=RequirementType.CRIMINAL_RECORD_CHECK
        )
        crc.must_follow = RequirementDefinition.objects.get(name=ORIENTATION)
        crc.dependency_mode = DependencyMode.GATE
        crc.save(update_fields=["must_follow", "dependency_mode"])

        instance = self.volunteer.requirement_instances.get(definition=crc)
        instance.status = RequirementStatus.NOT_APPLICABLE
        instance.save(update_fields=["status"])

        activate_turning_18_checks()

        instance.refresh_from_db()
        self.assertEqual(instance.status, RequirementStatus.NOT_APPLICABLE)

    def test_a_chain_stays_blocked_at_its_first_unmet_step(self):
        """
        A → B → C. B is not-applicable *because* it is gated, which must not read as
        "satisfied" and release C.
        """
        refresher = RequirementDefinition.objects.get(name=REFRESHER)
        third = RequirementDefinition.objects.create(
            name="Advanced training",
            requirement_type=RequirementType.CUSTOM,
            cadence=Cadence.ANNUAL,
            must_follow=refresher,
            dependency_mode=DependencyMode.GATE,
        )
        sync_volunteer_requirements(self.volunteer)

        self.assertEqual(
            self.volunteer.requirement_instances.get(definition=third).status,
            RequirementStatus.NOT_APPLICABLE,
        )

        # Completing the head of the chain releases only the next step.
        mark_requirement_complete(self.instance_for(ORIENTATION), timezone.localdate())
        self.assertEqual(self.instance_for(REFRESHER).status, RequirementStatus.NOT_STARTED)
        self.assertEqual(
            self.volunteer.requirement_instances.get(definition=third).status,
            RequirementStatus.NOT_APPLICABLE,
        )

    def test_a_loop_written_straight_to_the_database_does_not_hang(self):
        """clean() refuses loops, but the seed writes with save(), which skips it."""
        orientation = RequirementDefinition.objects.get(name=ORIENTATION)
        refresher = RequirementDefinition.objects.get(name=REFRESHER)
        orientation.must_follow = refresher
        orientation.dependency_mode = DependencyMode.GATE
        orientation.save(update_fields=["must_follow", "dependency_mode"])

        # Must terminate rather than recurse forever.
        sync_volunteer_requirements(self.volunteer)
        self.assertIsNotNone(self.instance_for(REFRESHER))


class GateReleaseTests(DependencyBase):
    """Completing the prerequisite, through each path that can do it."""

    def test_completing_the_orientation_releases_the_refresher(self):
        self.complete_orientation()

        refresher = self.instance_for(REFRESHER)
        self.assertEqual(refresher.status, RequirementStatus.NOT_STARTED)
        self.assertEqual(refresher.not_applicable_reason, "")

    def test_the_refresher_falls_due_a_year_after_the_orientation(self):
        """The headline requirement."""
        completed_on = timezone.localdate() - datetime.timedelta(days=30)
        self.complete_orientation(days_ago=30)

        refresher = self.instance_for(REFRESHER)
        self.assertEqual(refresher.due_on, completed_on.replace(year=completed_on.year + 1))

    def test_the_deadline_counts_from_the_prerequisite_not_from_today(self):
        """Eight months on, the refresher is four months out — not twelve."""
        self.complete_orientation(days_ago=240)

        refresher = self.instance_for(REFRESHER)
        self.assertLess(refresher.due_on, timezone.localdate() + datetime.timedelta(days=150))
        self.assertGreater(refresher.due_on, timezone.localdate())

    def test_the_reason_names_the_prerequisite_and_its_date(self):
        self.complete_orientation()
        self.assertIn(ORIENTATION, self.instance_for(REFRESHER).due_reason)

    def test_a_long_backdated_prerequisite_is_overdue_at_once(self):
        """Switching a gate on can put someone straight into overdue. Say so out loud."""
        self.complete_orientation(days_ago=500)
        recompute_all_statuses()

        self.assertEqual(self.instance_for(REFRESHER).status, RequirementStatus.OVERDUE)

    def test_a_released_requirement_is_chased_again(self):
        from apps.notifications.services import find_due_reminders

        self.complete_orientation(days_ago=305)  # due in ~60 days, a default lead time
        recompute_all_statuses()

        refresher = self.instance_for(REFRESHER)
        chased = any(
            e["instance"].pk == refresher.pk for e in find_due_reminders(self.tenant)
        )
        self.assertTrue(chased)

    def test_a_document_on_the_prerequisite_releases_the_gate(self):
        """The second completion path: recording a document completes a requirement."""
        from apps.documents.models import DocumentKind
        from apps.documents.services import store_document

        from django.db import connection

        from apps.tenants.models import DocumentMode

        self.tenant.document_mode = DocumentMode.TRACK
        self.tenant.save(update_fields=["document_mode"])
        connection.set_tenant(self.tenant)

        orientation_def = RequirementDefinition.objects.get(name=ORIENTATION)
        orientation_def.requires_document = True
        orientation_def.save(update_fields=["requires_document"])

        store_document(
            volunteer=self.volunteer,
            title="Orientation certificate",
            kind=DocumentKind.TRAINING,
            physical_location="Binder",
            requirement_instance=self.instance_for(ORIENTATION),
        )

        self.assertEqual(self.instance_for(REFRESHER).status, RequirementStatus.NOT_STARTED)

    def test_a_cleared_criminal_record_check_releases_a_gate(self):
        """
        The third path, and the one a naive implementation misses: record_crc sets the
        status inline and never calls mark_requirement_complete.
        """
        from apps.requirements.models import CRCResult

        crc = RequirementDefinition.objects.get(
            requirement_type=RequirementType.CRIMINAL_RECORD_CHECK
        )
        gated = RequirementDefinition.objects.create(
            name="Post-clearance briefing",
            requirement_type=RequirementType.CUSTOM,
            cadence=Cadence.ONE_TIME,
            must_follow=crc,
            dependency_mode=DependencyMode.GATE,
        )
        sync_volunteer_requirements(self.volunteer)
        self.assertEqual(
            self.volunteer.requirement_instances.get(definition=gated).status,
            RequirementStatus.NOT_APPLICABLE,
        )

        record_crc(self.volunteer, result=CRCResult.CLEARED, report_date=timezone.localdate())

        self.assertEqual(
            self.volunteer.requirement_instances.get(definition=gated).status,
            RequirementStatus.NOT_STARTED,
        )

    def test_waiving_the_prerequisite_releases_the_gate_with_no_deadline(self):
        """
        A waiver is a decision that the prerequisite is not needed. Holding the
        refresher behind it forever would silently exempt someone from it.
        """
        waive_requirement(
            self.instance_for(ORIENTATION),
            reason="Completed at their previous church",
            waived_by="Pat Lee",
        )

        refresher = self.instance_for(REFRESHER)
        self.assertEqual(refresher.status, RequirementStatus.NOT_STARTED)
        self.assertIsNone(refresher.due_on)

    def test_reversing_that_waiver_re_imposes_the_gate(self):
        orientation = self.instance_for(ORIENTATION)
        waive_requirement(orientation, reason="Recorded in error", waived_by="Pat Lee")
        orientation.refresh_from_db()

        reverse_waiver(orientation, reason="Waived the wrong volunteer", reversed_by="Sam")

        self.assertEqual(self.instance_for(REFRESHER).status, RequirementStatus.NOT_APPLICABLE)

    def test_a_lapsed_prerequisite_does_not_re_gate(self):
        """
        A prerequisite that expired still happened.

        Re-gating on a lapse would push the dependent back to not-applicable, which
        buckets as *satisfied* — so a lapse would reduce the church's apparent workload.
        """
        orientation_def = RequirementDefinition.objects.get(name=ORIENTATION)
        orientation_def.cadence = Cadence.ANNUAL
        orientation_def.save(update_fields=["cadence"])

        self.complete_orientation(days_ago=400)
        recompute_all_statuses()
        self.assertEqual(self.instance_for(ORIENTATION).status, RequirementStatus.OVERDUE)

        sync_volunteer_requirements(self.volunteer)

        self.assertNotEqual(
            self.instance_for(REFRESHER).status, RequirementStatus.NOT_APPLICABLE
        )

    def test_completing_the_refresher_moves_it_to_its_own_clock(self):
        """The prerequisite seeds the first cycle only."""
        self.complete_orientation(days_ago=400)
        refresher = self.instance_for(REFRESHER)

        mark_requirement_complete(refresher, timezone.localdate())

        refresher.refresh_from_db()
        self.assertIsNone(refresher.due_on)
        self.assertEqual(
            refresher.expires_on,
            timezone.localdate().replace(year=timezone.localdate().year + 1),
        )

    def test_releasing_is_idempotent(self):
        self.complete_orientation()
        before = self.instance_for(REFRESHER).due_on

        sync_volunteer_requirements(self.volunteer)
        sync_volunteer_requirements(self.volunteer)

        self.assertEqual(self.instance_for(REFRESHER).due_on, before)

    def test_the_nightly_sweep_releases_and_ages_a_gate_in_one_run(self):
        """
        Sync must run before recompute, or a gate that opens onto a past deadline would
        not read as overdue until the following night.
        """
        from apps.core.tasks import sweep_tenant

        orientation = self.instance_for(ORIENTATION)
        # Bypass the services so nothing has reacted yet — as if the row were restored
        # from a backup, or edited directly.
        orientation.completed_on = timezone.localdate() - datetime.timedelta(days=500)
        orientation.status = RequirementStatus.COMPLETE
        orientation.save(update_fields=["completed_on", "status"])

        sweep_tenant(self.tenant)

        self.assertEqual(self.instance_for(REFRESHER).status, RequirementStatus.OVERDUE)

    def test_correcting_the_prerequisite_date_moves_the_deadline(self):
        """
        A derived value must not go stale.

        The gate opens once and sets a deadline from the orientation's date. If that
        date is later corrected — a typo, a document arriving with the real date — the
        refresher's deadline has to follow, or it shows one nobody can account for.
        """
        self.complete_orientation(days_ago=30)
        refresher = self.instance_for(REFRESHER)
        first_deadline = refresher.due_on

        orientation = self.instance_for(ORIENTATION)
        orientation.completed_on = timezone.localdate() - datetime.timedelta(days=400)
        orientation.save(update_fields=["completed_on"])
        sync_volunteer_requirements(self.volunteer)

        refresher.refresh_from_db()
        self.assertNotEqual(refresher.due_on, first_deadline)
        self.assertLess(refresher.due_on, timezone.localdate())

    def test_a_corrected_date_can_make_it_overdue_on_the_next_sweep(self):
        from apps.core.tasks import sweep_tenant

        self.complete_orientation(days_ago=30)

        orientation = self.instance_for(ORIENTATION)
        orientation.completed_on = timezone.localdate() - datetime.timedelta(days=550)
        orientation.save(update_fields=["completed_on"])

        sweep_tenant(self.tenant)

        self.assertEqual(self.instance_for(REFRESHER).status, RequirementStatus.OVERDUE)
