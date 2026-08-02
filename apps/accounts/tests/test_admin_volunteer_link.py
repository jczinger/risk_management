"""
An administrator gets a screening file, and VMS refuses to guess whose it is.

The link is what makes "nobody screens themselves" expressible at all — see
:mod:`apps.org.tests.test_self_screening` for the rule it enables. These tests are about
how the link is made: automatically where that is safe, never where it involves a guess,
and never by the person it would let off the hook.
"""

from __future__ import annotations

from unittest import mock

from django.urls import reverse

from apps.core.tests.base import TenantTestCase
from apps.org.models import Volunteer


class AdminCreationCase(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.childrens = self.make_department("Children's Ministry")
        self.role = self.make_role(self.childrens, name="Helper")
        self.primary = self.make_admin(email="primary@test.ca")
        self.client = self.signed_in_client(self.primary)

    def invite(self, first="Brenda", last="Czinger", email="brenda@test.ca", **extra):
        from apps.core.models import AccessLevel

        data = {
            "first_name": first,
            "last_name": last,
            "email": email,
            "access_level": AccessLevel.objects.get(slug=AccessLevel.DEPARTMENT_ADMIN).pk,
            "departments": [self.childrens.pk],
        }
        data.update(extra)
        return self.client.post(reverse("accounts:admin_invite"), data)


class TheRecordAppearsOnItsOwn(AdminCreationCase):
    def test_a_new_administrator_gets_a_volunteer_record(self):
        self.invite()

        volunteer = Volunteer.objects.get(first_name="Brenda")
        self.assertEqual(volunteer.last_name, "Czinger")
        self.assertEqual(volunteer.email, "brenda@test.ca")
        self.assertIsNotNone(volunteer.user_id)

    def test_it_starts_with_no_ministry_role(self):
        """
        Intended, and worth pinning because the consequence is surprising: scope runs
        through role assignments, so until somebody gives them a role this record is
        invisible to every limited access level — including the new administrator's own.
        """
        self.invite()
        volunteer = Volunteer.objects.get(first_name="Brenda")
        self.assertEqual(volunteer.assignments.count(), 0)

    def test_an_existing_record_under_that_name_stops_it(self):
        """
        The collision case, and the reason this is not a one-liner. Two people can share
        a name, and attaching an administrator to somebody else's screening file — or
        merging two — has no undo.
        """
        already = self.make_volunteer(first_name="Brenda", last_name="Czinger")
        self.assign(already, self.role)

        self.invite()

        self.assertEqual(Volunteer.objects.filter(first_name="Brenda").count(), 1)
        already.refresh_from_db()
        self.assertIsNone(already.user_id)

    def test_the_collision_is_case_insensitive(self):
        self.make_volunteer(first_name="brenda", last_name="CZINGER")
        self.invite()
        self.assertEqual(Volunteer.objects.filter(last_name__iexact="czinger").count(), 1)

    def test_the_inviter_is_told_when_nothing_was_created(self):
        self.make_volunteer(first_name="Brenda", last_name="Czinger")
        response = self.invite()
        messages = [str(m) for m in response.context["messages"]]
        self.assertTrue(any("already has one under that name" in m for m in messages))


class AdminCreationIsAtomic(AdminCreationCase):
    def test_a_failure_part_way_leaves_no_account_behind(self):
        """
        This view was never atomic, and could already strand a ``User`` with no access
        level — the state the administrators list has a warning badge for. Adding a third
        write made it worth fixing rather than documenting.
        """
        before = self.count_users()

        with mock.patch(
            "apps.accounts.views.apply_grant", side_effect=RuntimeError("grant blew up")
        ):
            with self.assertRaises(RuntimeError):
                self.invite()

        self.assertEqual(self.count_users(), before)
        self.assertFalse(Volunteer.objects.filter(first_name="Brenda").exists())

    def count_users(self):
        from apps.accounts.models import User

        return User.objects.count()


class LinkingAnExistingRecord(AdminCreationCase):
    def setUp(self):
        super().setUp()
        self.make_volunteer(first_name="Brenda", last_name="Czinger")
        self.invite()
        from apps.accounts.models import User

        self.brenda = User.objects.get(first_name="Brenda")
        self.existing = Volunteer.objects.get(first_name="Brenda")

    def test_the_list_offers_the_choice(self):
        body = self.client.get(reverse("accounts:admin_list")).content.decode()
        self.assertIn("Possible existing record", body)
        self.assertIn("Create a separate one", body)

    def test_linking_attaches_the_existing_record(self):
        self.client.post(
            reverse("accounts:admin_link_volunteer", args=[self.brenda.pk]),
            {"volunteer": self.existing.pk},
        )
        self.existing.refresh_from_db()
        self.assertEqual(self.existing.user_id, self.brenda.pk)

    def test_creating_a_separate_one_leaves_the_original_alone(self):
        self.client.post(reverse("accounts:admin_create_volunteer", args=[self.brenda.pk]))

        self.existing.refresh_from_db()
        self.assertIsNone(self.existing.user_id)
        self.assertEqual(Volunteer.objects.filter(first_name="Brenda").count(), 2)

    def test_you_cannot_choose_your_own_screening_file(self):
        """
        The back door this closes.

        The link is what makes the self-screening rule enforceable, so being free to
        re-point your own link would be a way straight out of it: aim it at a stranger's
        record and your own becomes fair game again.
        """
        mine = self.make_volunteer(first_name="Test", last_name="Admin")
        second = self.make_admin(email="second@test.ca")

        self.client.post(
            reverse("accounts:admin_link_volunteer", args=[self.primary.pk]),
            {"volunteer": mine.pk},
        )

        mine.refresh_from_db()
        self.assertIsNone(mine.user_id)
        self.assertTrue(second.pk)

    def test_but_the_only_administrator_may_link_their_own(self):
        """Otherwise a single-administrator church could never have a file at all."""
        self.brenda.is_active = False
        self.brenda.save(update_fields=["is_active"])
        mine = self.make_volunteer(first_name="Test", last_name="Admin")

        self.client.post(
            reverse("accounts:admin_link_volunteer", args=[self.primary.pk]),
            {"volunteer": mine.pk},
        )

        mine.refresh_from_db()
        self.assertEqual(mine.user_id, self.primary.pk)

    def test_there_is_no_unlink_route(self):
        """Detaching is the same escape by another name, so it does not exist."""
        from django.urls import NoReverseMatch

        with self.assertRaises(NoReverseMatch):
            reverse("accounts:admin_unlink_volunteer", args=[self.brenda.pk])


class VolunteerToAdministrator(AdminCreationCase):
    def setUp(self):
        super().setUp()
        self.volunteer = self.make_volunteer(
            first_name="Dana", last_name="Reyes", email="dana@test.ca"
        )
        self.assign(self.volunteer, self.role)

    def test_the_button_is_offered_on_an_unlinked_file(self):
        body = self.client.get(
            reverse("org:volunteer_detail", args=[self.volunteer.pk])
        ).content.decode()
        self.assertIn(f"?volunteer={self.volunteer.pk}", body)

    def test_the_invite_form_is_prefilled(self):
        response = self.client.get(
            reverse("accounts:admin_invite") + f"?volunteer={self.volunteer.pk}"
        )
        self.assertEqual(response.context["form"].initial["first_name"], "Dana")
        self.assertEqual(response.context["form"].initial["email"], "dana@test.ca")

    def test_saving_links_the_two_rather_than_creating_a_second(self):
        self.invite(first="Dana", last="Reyes", email="dana@test.ca", volunteer=self.volunteer.pk)

        self.assertEqual(Volunteer.objects.filter(last_name="Reyes").count(), 1)
        self.volunteer.refresh_from_db()
        self.assertIsNotNone(self.volunteer.user_id)

    def test_a_disqualified_volunteer_is_refused(self):
        """
        Not asked for, and stated rather than hidden: somebody barred from every position
        of trust under the policy should not be administering the screening of others.
        """
        from apps.org.models import ScreeningBlock

        self.volunteer.set_screening_block(ScreeningBlock.DISQUALIFIED)

        response = self.client.get(
            reverse("accounts:admin_invite") + f"?volunteer={self.volunteer.pk}"
        )
        self.assertEqual(response.status_code, 403)

    def test_an_out_of_scope_volunteer_is_a_404_not_a_403(self):
        youth = self.make_department("Youth")
        scoped = self.make_department_admin(email="youth@test.ca", departments=[youth])
        self.grant_access(scoped, self.department_admin_level(), [youth])
        # Give them the ability to manage users, so the refusal under test is the scope
        # one rather than the capability one.
        level = self.department_admin_level()
        level.can_manage_users = True
        level.save(update_fields=["can_manage_users"])
        self.forget_access(scoped)

        client = self.signed_in_client(scoped)
        response = client.get(
            reverse("accounts:admin_invite") + f"?volunteer={self.volunteer.pk}"
        )
        self.assertEqual(response.status_code, 404)


class TheBackfillCommand(AdminCreationCase):
    def run_command(self, *args):
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        call_command("link_admin_volunteers", "--schema", self.tenant.schema_name, *args, stdout=out)
        return out.getvalue()

    def test_it_reports_without_writing(self):
        output = self.run_command()
        self.assertIn("would create a volunteer record", output)
        self.assertEqual(Volunteer.objects.count(), 0)

    def test_create_writes_the_records(self):
        self.run_command("--create")
        self.assertEqual(Volunteer.objects.filter(user_id=self.primary.pk).count(), 1)

    def test_it_refuses_to_guess_at_a_name_match(self):
        self.make_volunteer(first_name="Test", last_name="Admin")

        output = self.run_command("--create")

        self.assertIn("NOT created", output)
        self.assertFalse(Volunteer.objects.filter(user_id=self.primary.pk).exists())

    def test_it_is_idempotent(self):
        self.run_command("--create")
        self.run_command("--create")
        self.assertEqual(Volunteer.objects.filter(user_id=self.primary.pk).count(), 1)
