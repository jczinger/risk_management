"""
Nobody screens themselves.

Plan to Protect presumes the screener and the screened are two different people. Until
administrators were linked to their own volunteer records VMS had no way to say so: an
administrator could tick their own training, record their own criminal record check as
clear, and nothing anywhere would notice, because nothing knew it was them.

The rule and its one escape hatch live in :mod:`apps.core.access`; these tests are about
whether the rule actually holds on every path somebody might take to a record, which is a
different question from whether the function returns the right boolean.

Reading is deliberately untouched throughout. Hiding somebody's own screening status from
them would teach them to keep a second copy on a spreadsheet, which is worse.
"""

from __future__ import annotations

from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.utils import timezone

from apps.core import audit
from apps.core.access import may_record_against
from apps.core.tests.base import TenantTestCase


class SelfScreeningCase(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.seed()
        self.childrens = self.make_department("Children's Ministry")
        self.role = self.make_role(self.childrens, name="Sunday School Teacher")

        self.primary = self.make_admin(email="primary@test.ca")
        self.make_passkey(self.primary)

        self.dept_admin = self.make_department_admin(
            email="dept@test.ca", departments=[self.childrens]
        )
        # The department admin's own file, in their own department — the case the rule
        # exists for. Without a role they could not see it at all.
        self.own_file = self.make_own_file(self.dept_admin, role=self.role)

        self.colleague = self.make_volunteer(first_name="Other", last_name="Person")
        self.assign(self.colleague, self.role)


class TheRuleItself(SelfScreeningCase):
    def test_a_limited_admin_is_refused_on_their_own_file(self):
        allowed, why = may_record_against(self.dept_admin, self.own_file)
        self.assertFalse(allowed)
        self.assertIn("your own screening file", why)

    def test_a_limited_admin_is_fine_on_anyone_elses(self):
        allowed, _ = may_record_against(self.dept_admin, self.colleague)
        self.assertTrue(allowed)

    def test_a_primary_admin_is_refused_while_another_one_exists(self):
        """The same rule, not a weaker one. Seniority is not the point; a second pair of
        eyes is."""
        second = self.make_admin(email="second@test.ca")
        own = self.make_own_file(self.primary)

        allowed, why = may_record_against(self.primary, own)
        self.assertFalse(allowed)
        self.assertIn("another administrator", why)
        self.assertTrue(second.pk)

    def test_the_last_primary_admin_may_record_their_own(self):
        """
        The escape hatch, and the reason it has to exist.

        A church with one administrator has nobody else. Refusing would mean that
        administrator's own file could never be completed inside VMS at all, which just
        moves their screening onto paper where nothing tracks it.
        """
        self.dept_admin.is_active = False
        self.dept_admin.save(update_fields=["is_active"])
        own = self.make_own_file(self.primary)

        allowed, why = may_record_against(self.primary, own)
        self.assertTrue(allowed, why)

    def test_a_limited_admin_never_gets_the_hatch(self):
        """
        Even with no active unscoped admin left, which should be unreachable.

        A limited level is created *by* somebody with access to the whole church, so one
        existed at some point. If the data says otherwise something is wrong, and the
        safe reading of a broken state is not "help yourself".
        """
        self.primary.is_active = False
        self.primary.save(update_fields=["is_active"])
        self.forget_access(self.dept_admin)

        allowed, _ = may_record_against(self.dept_admin, self.own_file)
        self.assertFalse(allowed)


class EveryWritePathRefuses(SelfScreeningCase):
    """
    The part that matters. A rule that holds in one function and leaks through eleven
    views is not a rule.
    """

    def setUp(self):
        super().setUp()
        from apps.requirements.services import sync_volunteer_requirements

        sync_volunteer_requirements(self.own_file)
        sync_volunteer_requirements(self.colleague)
        self.client = self.signed_in_client(self.dept_admin)

    def _instance(self, volunteer, name="Interview"):
        return volunteer.requirement_instances.select_related("definition").get(
            definition__name__icontains=name
        )

    def test_reading_their_own_file_is_allowed(self):
        response = self.client.get(reverse("org:volunteer_detail", args=[self.own_file.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertIn("your own screening file", response.content.decode().lower())

    def test_the_action_buttons_are_not_offered(self):
        body = self.client.get(
            reverse("org:volunteer_detail", args=[self.own_file.pk])
        ).content.decode()
        self.assertNotIn(reverse("org:volunteer_edit", args=[self.own_file.pk]), body)

    def test_they_are_still_offered_on_a_colleague(self):
        """The negative control. A refusal that refuses everything proves nothing."""
        body = self.client.get(
            reverse("org:volunteer_detail", args=[self.colleague.pk])
        ).content.decode()
        self.assertIn(reverse("org:volunteer_edit", args=[self.colleague.pk]), body)

    def test_editing_their_own_details_is_refused(self):
        response = self.client.get(reverse("org:volunteer_edit", args=[self.own_file.pk]))
        self.assertEqual(response.status_code, 403)

    def test_deactivating_their_own_record_is_refused(self):
        response = self.client.get(reverse("org:volunteer_deactivate", args=[self.own_file.pk]))
        self.assertEqual(response.status_code, 403)

    def test_recalculating_their_own_requirements_is_refused(self):
        """
        Included even though it only re-derives state, because a uniform rule is worth
        more than the one exception somebody would have to remember.
        """
        response = self.client.post(reverse("org:volunteer_resync", args=[self.own_file.pk]))
        self.assertEqual(response.status_code, 403)

    def test_assigning_themselves_a_role_is_refused(self):
        """Which roles you hold decides which requirements apply to you."""
        second_role = self.make_role(self.childrens, name="Team Leader", is_leadership=True)
        response = self.client.post(
            reverse("org:assignment_create", args=[self.own_file.pk]),
            {"role": second_role.pk, "started_on": timezone.localdate().isoformat()},
        )
        self.assertEqual(response.status_code, 403)

    def test_ending_their_own_assignment_is_refused(self):
        assignment = self.own_file.assignments.get()
        response = self.client.post(
            reverse("org:assignment_end", args=[assignment.pk]),
            {"ended_on": timezone.localdate().isoformat()},
        )
        self.assertEqual(response.status_code, 403)

    def test_completing_their_own_requirement_is_refused(self):
        instance = self._instance(self.own_file)
        response = self.client.post(
            reverse("requirements:instance_complete", args=[instance.pk]),
            {"completed_on": timezone.localdate().isoformat()},
        )
        self.assertEqual(response.status_code, 403)
        instance.refresh_from_db()
        self.assertNotEqual(instance.status, "complete")

    def test_starting_their_own_requirement_is_refused(self):
        instance = self._instance(self.own_file)
        response = self.client.post(reverse("requirements:instance_start", args=[instance.pk]))
        self.assertEqual(response.status_code, 403)

    def test_waiving_their_own_requirement_is_refused(self):
        instance = self._instance(self.own_file)
        response = self.client.get(reverse("requirements:instance_waive", args=[instance.pk]))
        self.assertEqual(response.status_code, 403)

    def test_recording_their_own_criminal_record_check_is_refused(self):
        """The one that would matter most in a real church."""
        response = self.client.get(reverse("requirements:crc_create", args=[self.own_file.pk]))
        self.assertEqual(response.status_code, 403)

    def test_adding_a_document_to_their_own_file_is_refused(self):
        response = self.client.get(reverse("documents:create", args=[self.own_file.pk]))
        self.assertEqual(response.status_code, 403)

    def test_all_of_the_above_work_on_a_colleague(self):
        """
        One test, deliberately, standing in for thirteen negative controls.

        Without it every assertion above would still pass if the department admin had
        simply lost all access, which is a different bug wearing the same 403.
        """
        instance = self._instance(self.colleague)
        self.assertEqual(
            self.client.get(reverse("org:volunteer_edit", args=[self.colleague.pk])).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(
                reverse("requirements:instance_complete", args=[instance.pk])
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(reverse("requirements:crc_create", args=[self.colleague.pk])).status_code,
            200,
        )


class TheServiceLayerRefusesToo(SelfScreeningCase):
    """
    Reached without a view at all, the way ``RoleAssignment.clean()`` is.

    A rule enforced only at the edge is a rule with an inside, and the services here are
    callable from a management command or anything written later.
    """

    def setUp(self):
        super().setUp()
        from apps.requirements.services import sync_volunteer_requirements

        sync_volunteer_requirements(self.own_file)

    def acting_as(self, user):
        from django.test import RequestFactory

        request = RequestFactory().get("/")
        request.user = user
        return audit.acting_as(audit.actor_from_request(request))

    def test_mark_complete_refuses(self):
        from apps.requirements.services import mark_requirement_complete

        instance = self.own_file.requirement_instances.get(
            definition__name__icontains="Interview"
        )
        with self.acting_as(self.dept_admin):
            with self.assertRaises(PermissionDenied):
                mark_requirement_complete(instance, timezone.localdate())

    def test_record_crc_refuses(self):
        from apps.requirements.services import record_crc

        with self.acting_as(self.dept_admin):
            with self.assertRaises(PermissionDenied):
                record_crc(self.own_file, result="clear", report_date=timezone.localdate())

    def test_the_nightly_sweep_is_unaffected(self):
        """
        ``Actor.system()`` carries no user id, so it matches nobody's file. If this ever
        broke, the sweep would start refusing to touch administrators' records and the
        failure would be silent.
        """
        from apps.core.tasks import sweep_tenant

        with audit.acting_as(audit.Actor.system("nightly job")):
            sweep_tenant(self.tenant)  # Must not raise.

    def test_a_management_command_is_unaffected(self):
        from apps.requirements.services import mark_requirement_complete

        instance = self.own_file.requirement_instances.get(
            definition__name__icontains="Interview"
        )
        with audit.acting_as(audit.Actor.system("a command")):
            mark_requirement_complete(instance, timezone.localdate())
        instance.refresh_from_db()
        self.assertEqual(instance.status, "complete")
