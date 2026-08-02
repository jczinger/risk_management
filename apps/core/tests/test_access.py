"""
Tests for access levels, capability gating and department scoping.

The most valuable test in here is the dullest: :class:`DefaultDenyTests` walks the
URLconf and refuses to let a view exist without declaring what it needs. Everything else
checks a rule; that one checks that nobody forgot to apply the rules at all.
"""

from __future__ import annotations

from django.urls import get_resolver, reverse

from apps.core.access import (
    Capability,
    has_capability,
    scope_department_ids,
    scope_volunteers,
)
from apps.core.models import AccessLevel, UserAccessGrant
from apps.core.seed import seed_access_levels
from apps.core.tests.base import TenantTestCase
from apps.org.models import Volunteer


def _leaf_views(resolver, prefix=""):
    """Every view function reachable through this resolver, with its pattern."""
    for entry in resolver.url_patterns:
        if hasattr(entry, "url_patterns"):
            yield from _leaf_views(entry, prefix + str(entry.pattern))
        else:
            yield prefix + str(entry.pattern), entry.callback


class DefaultDenyTests(TenantTestCase):
    """
    Every church-side view must declare what capability it needs.

    ``AccessGateMiddleware`` enforces this at runtime, which is the guarantee. This test
    is the fast feedback: it names the offending view at review time instead of leaving
    an administrator to discover a 403 in production. Both are worth having — the
    middleware sees views this test cannot, and this test catches somebody quietly adding
    a path to the middleware's exemption list.
    """

    def test_every_view_declares_a_capability_or_says_why_not(self):
        undeclared = [
            f"{pattern} -> {view.__module__}.{view.__qualname__}"
            for pattern, view in _leaf_views(get_resolver("config.urls_tenant"))
            if getattr(view, "vms_capabilities", None) is None
            and not getattr(view, "vms_public", False)
        ]
        self.assertEqual(
            undeclared,
            [],
            "These views are reachable without declaring a capability. Decorate each "
            "with requires(), open_to_any_signed_in_user() or public_view() from "
            "apps.core.access:\n  " + "\n  ".join(undeclared),
        )

    def test_no_view_asks_for_a_capability_that_does_not_exist(self):
        known = set(Capability.values)
        unknown = {
            f"{view.__qualname__}: {sorted(set(declared) - known)}"
            for _, view in _leaf_views(get_resolver("config.urls_tenant"))
            if (declared := getattr(view, "vms_capabilities", None)) and set(declared) - known
        }
        self.assertEqual(unknown, set())

    def test_every_capability_is_used_by_at_least_one_view(self):
        """A capability nothing checks is a promise the code does not keep."""
        used = set()
        for _, view in _leaf_views(get_resolver("config.urls_tenant")):
            used |= set(getattr(view, "vms_capabilities", None) or ())
        # MANAGE_USERS is reached through the accounts URLs, which are included in the
        # tenant URLconf, so everything should be covered.
        self.assertEqual(set(Capability.values) - used, set())


class AccessGateMiddlewareTests(TenantTestCase):
    """
    The runtime half of default-deny, tested directly against ``process_view``.

    The enumeration test above proves every view *we have* declares something. This
    proves that a view which does not is actually refused — the two are different
    claims, and only this one holds for a view added later.
    """

    def setUp(self):
        super().setUp()
        from django.test import RequestFactory

        from apps.core.middleware import AccessGateMiddleware

        self.gate = AccessGateMiddleware(lambda request: None)
        self.request = RequestFactory().get("/anything/")
        self.request.user = self.make_admin(email="gate@test.ca")

    def test_an_undeclared_view_is_refused(self):
        from django.core.exceptions import PermissionDenied

        def undeclared(request):
            return None

        with self.assertRaises(PermissionDenied):
            self.gate.process_view(self.request, undeclared, (), {})

    def test_a_declared_view_passes(self):
        from apps.core.access import requires

        @requires(Capability.VIEW_VOLUNTEERS)
        def declared(request):
            return None

        self.assertIsNone(self.gate.process_view(self.request, declared, (), {}))

    def test_a_view_open_to_any_signed_in_user_passes(self):
        from apps.core.access import open_to_any_signed_in_user

        @open_to_any_signed_in_user("a written reason")
        def own_account(request):
            return None

        self.assertIsNone(self.gate.process_view(self.request, own_account, (), {}))

    def test_a_public_view_passes(self):
        from apps.core.access import public_view

        @public_view("signing in")
        def sign_in(request):
            return None

        self.assertIsNone(self.gate.process_view(self.request, sign_in, (), {}))

    def test_the_health_check_passes_because_it_declares_itself_public(self):
        """
        There is no path-prefix exemption list any more: /healthz/ gets through the
        gate the same way every public page does, by the decorator on the view.
        """
        from django.test import RequestFactory

        from apps.core.views import healthz

        request = RequestFactory().get("/healthz/")
        request.user = self.request.user

        self.assertIsNone(self.gate.process_view(request, healthz, (), {}))

    def test_the_declaration_survives_the_decorators_stacked_above_it(self):
        """
        ``@never_cache`` and friends sit above ``@requires`` on several real views.

        Each wraps with ``functools.wraps``, which copies ``__dict__`` — so the attribute
        propagates. If that ever stopped being true, every one of those views would start
        returning 403 in production, so it is worth pinning.
        """
        from django.views.decorators.cache import never_cache

        from apps.core.access import requires

        @never_cache
        @requires(Capability.VIEW_VOLUNTEERS)
        def wrapped(request):
            return None

        self.assertEqual(wrapped.vms_capabilities, frozenset({Capability.VIEW_VOLUNTEERS}))


class CapabilityFieldTests(TenantTestCase):
    """The Capability enum and the AccessLevel columns must not drift apart."""

    def test_every_capability_has_a_matching_field(self):
        for capability in Capability.values:
            self.assertIn(f"can_{capability}", AccessLevel.CAPABILITY_FIELDS)

    def test_every_field_has_a_matching_capability(self):
        for field in AccessLevel.CAPABILITY_FIELDS:
            self.assertIn(field[len("can_") :], Capability.values)

    def test_every_field_exists_on_the_model(self):
        level = AccessLevel.objects.get(slug=AccessLevel.PRIMARY_ADMIN)
        for field in AccessLevel.CAPABILITY_FIELDS:
            self.assertIsInstance(getattr(level, field), bool)


class SeedTests(TenantTestCase):
    def test_both_built_in_levels_exist(self):
        slugs = set(AccessLevel.objects.values_list("slug", flat=True))
        self.assertIn(AccessLevel.PRIMARY_ADMIN, slugs)
        self.assertIn(AccessLevel.DEPARTMENT_ADMIN, slugs)

    def test_primary_admin_holds_everything_and_is_unscoped(self):
        level = AccessLevel.objects.get(slug=AccessLevel.PRIMARY_ADMIN)
        self.assertFalse(level.is_scoped)
        self.assertEqual(level.capabilities(), set(Capability.values))

    def test_department_admin_is_scoped_and_excludes_the_church_wide_capabilities(self):
        level = AccessLevel.objects.get(slug=AccessLevel.DEPARTMENT_ADMIN)
        self.assertTrue(level.is_scoped)
        for withheld in (
            Capability.MANAGE_ORG,
            Capability.MANAGE_REQUIREMENTS,
            Capability.VIEW_AUDIT,
            Capability.MANAGE_USERS,
        ):
            self.assertNotIn(withheld, level.capabilities())

    def test_reseeding_never_touches_a_level_a_church_has_edited(self):
        """
        The rule ``seed_default_template`` learned the hard way, and it matters more here.

        Re-granting a capability a church had deliberately removed would be a security
        regression that nobody would witness.
        """
        level = AccessLevel.objects.get(slug=AccessLevel.DEPARTMENT_ADMIN)
        level.name = "Ministry Leader"
        level.can_record_crc = False
        level.save()

        self.assertEqual(seed_access_levels(), 0)

        level.refresh_from_db()
        self.assertEqual(level.name, "Ministry Leader")
        self.assertFalse(level.can_record_crc)
        self.assertEqual(
            AccessLevel.objects.filter(slug=AccessLevel.DEPARTMENT_ADMIN).count(), 1
        )


class AuditCannotBeScopedTests(TenantTestCase):
    """
    A limited level cannot hold the audit trail, and the model is what refuses it.

    ``AuditEvent`` records no department and cannot be given one — its pointer to the
    affected row is a pair of strings. A partial filter would be worse than refusing,
    because it would look scoped while missing every requirement, document and
    criminal-record-check entry about the same person.
    """

    def test_a_scoped_level_refuses_the_audit_trail(self):
        from django.core.exceptions import ValidationError

        level = AccessLevel(name="Scoped auditor", slug="scoped-auditor", is_scoped=True)
        level.can_view_audit = True
        with self.assertRaises(ValidationError) as caught:
            level.clean()
        self.assertIn("can_view_audit", caught.exception.error_dict)

    def test_an_unscoped_level_may_hold_it(self):
        level = AccessLevel(name="Auditor", slug="auditor", is_scoped=False)
        level.can_view_audit = True
        level.clean()  # does not raise


class NoGrantTests(TenantTestCase):
    """An account with no access level can do nothing. Fail closed, by construction."""

    def test_an_account_without_a_grant_holds_no_capability(self):
        user = self.make_admin(email="ungranted@test.ca")
        UserAccessGrant.objects.filter(user_id=user.pk).delete()
        self.forget_access(user)

        for capability in Capability.values:
            self.assertFalse(has_capability(user, capability), capability)

    def test_an_account_without_a_grant_sees_no_volunteers(self):
        user = self.make_admin(email="ungranted@test.ca")
        UserAccessGrant.objects.filter(user_id=user.pk).delete()
        self.forget_access(user)

        self.assertEqual(scope_volunteers(Volunteer.objects.all(), user).count(), 0)

    def test_no_grant_is_not_the_same_answer_as_unscoped(self):
        """
        ``None`` means every department; an empty set means none.

        Conflating them is the mistake that would turn a half-finished grant into
        church-wide access, which is why ``is_scoped`` is an explicit flag.
        """
        user = self.make_admin(email="ungranted@test.ca")
        UserAccessGrant.objects.filter(user_id=user.pk).delete()
        self.forget_access(user)

        self.assertEqual(scope_department_ids(user), frozenset())
        self.assertIsNotNone(scope_department_ids(user))

    def test_a_scoped_level_with_no_departments_sees_nothing(self):
        children = self.make_department("Children's Ministry")
        role = self.make_role(department=children, name="Sunday School Teacher")
        volunteer = self.make_volunteer()
        self.assign(volunteer, role)

        user = self.make_department_admin(email="empty@test.ca", departments=[])
        self.assertEqual(scope_department_ids(user), frozenset())
        self.assertEqual(scope_volunteers(Volunteer.objects.all(), user).count(), 0)

    def test_no_user_at_all_means_unscoped(self):
        """
        The nightly sweep and the seeders pass no user and must see everything.

        Easy to confuse with the case above, and getting it wrong in the other direction
        would stop every church's reminder emails.
        """
        self.assertIsNone(scope_department_ids(None))


class TwoDepartmentCase(TenantTestCase):
    """
    A church with two departments and a volunteer in each, plus one in both.

    Children's Ministry: Jane (Sunday School), Both (Nursery)
    Youth:               Ravi (Youth Leader),  Both (Youth Helper)
    """

    def setUp(self):
        super().setUp()
        self.seed()
        self.childrens = self.make_department("Children's Ministry")
        self.youth = self.make_department("Youth")

        self.sunday_school = self.make_role(self.childrens, name="Sunday School Teacher")
        self.nursery = self.make_role(self.childrens, name="Nursery Helper")
        self.youth_leader = self.make_role(self.youth, name="Youth Leader")
        self.youth_helper = self.make_role(self.youth, name="Youth Helper")

        self.jane = self.make_volunteer(first_name="Jane", last_name="Doe")
        self.ravi = self.make_volunteer(first_name="Ravi", last_name="Patel")
        self.both = self.make_volunteer(first_name="Mia", last_name="Chen")

        self.assign(self.jane, self.sunday_school)
        self.assign(self.ravi, self.youth_leader)
        self.assign(self.both, self.nursery)
        self.assign(self.both, self.youth_helper)

        self.childrens_admin = self.make_department_admin(
            email="childrens@test.ca", departments=[self.childrens]
        )
        self.primary = self.make_admin(email="primary@test.ca")
        self.make_passkey(self.primary)


class ScopeTests(TwoDepartmentCase):
    def test_a_department_admin_sees_only_their_departments_volunteers(self):
        visible = scope_volunteers(Volunteer.objects.all(), self.childrens_admin)
        self.assertCountEqual(
            [v.pk for v in visible], [self.jane.pk, self.both.pk]
        )

    def test_an_unscoped_admin_sees_everyone(self):
        visible = scope_volunteers(Volunteer.objects.all(), self.primary)
        self.assertCountEqual(
            [v.pk for v in visible], [self.jane.pk, self.ravi.pk, self.both.pk]
        )

    def test_a_volunteer_whose_assignment_ended_is_still_visible(self):
        """
        Scope is "ever held a role here", not "holds one now".

        The department's admin keeps access to a file they worked on, because records
        involving minors are retained permanently and somebody may have to answer a
        question about a past volunteer years later.
        """
        assignment = self.jane.assignments.get(role=self.sunday_school)
        assignment.end()

        visible = scope_volunteers(Volunteer.objects.all(), self.childrens_admin)
        self.assertIn(self.jane.pk, [v.pk for v in visible])

    def test_a_volunteer_with_two_roles_in_one_department_appears_once(self):
        """
        Scoping joins through assignments, so without distinct() this row would double.

        Invisible until a real church has somebody holding two roles in one department,
        and then it shows up as a duplicate in the list and as a row that can appear on
        two pages of the same paginated result.
        """
        self.assign(self.jane, self.nursery)

        visible = scope_volunteers(Volunteer.objects.all(), self.childrens_admin)
        self.assertEqual([v.pk for v in visible].count(self.jane.pk), 1)


class ViewScopeTests(TwoDepartmentCase):
    """Out of scope is 404; missing capability is 403. Checked through the request stack."""

    def test_the_volunteer_list_shows_only_volunteers_in_scope(self):
        client = self.signed_in_client(self.childrens_admin)
        body = client.get(reverse("org:volunteer_list")).content.decode()

        self.assertIn("Doe", body)
        self.assertNotIn("Patel", body)

    def test_a_volunteer_outside_scope_is_404_not_403(self):
        """
        A 403 here would confirm the volunteer exists and is in another department.

        Walked over the id range that is a membership list for the church, including
        which ids are minors. The queryset is narrowed so the answer is indistinguishable
        from "no such record".
        """
        client = self.signed_in_client(self.childrens_admin)
        response = client.get(reverse("org:volunteer_detail", args=[self.ravi.pk]))
        self.assertEqual(response.status_code, 404)

    def test_a_volunteer_in_scope_opens_normally(self):
        client = self.signed_in_client(self.childrens_admin)
        response = client.get(reverse("org:volunteer_detail", args=[self.jane.pk]))
        self.assertEqual(response.status_code, 200)

    def test_a_shared_volunteer_is_reachable_from_either_department(self):
        client = self.signed_in_client(self.childrens_admin)
        response = client.get(reverse("org:volunteer_detail", args=[self.both.pk]))
        self.assertEqual(response.status_code, 200)

    def test_a_withheld_capability_is_403(self):
        client = self.signed_in_client(self.childrens_admin)
        for name in (
            "requirements:definition_list",
            "reporting:audit_trail",
            "reporting:email_log",
            "accounts:admin_list",
        ):
            with self.subTest(view=name):
                self.assertEqual(client.get(reverse(name)).status_code, 403)

    def test_the_department_list_hides_other_departments(self):
        client = self.signed_in_client(self.childrens_admin)
        body = client.get(reverse("org:department_list")).content.decode()

        self.assertIn("Children&#x27;s Ministry", body)
        self.assertNotIn("Youth", body)

    def test_a_department_outside_scope_is_404(self):
        client = self.signed_in_client(self.childrens_admin)
        response = client.get(reverse("org:department_detail", args=[self.youth.pk]))
        self.assertEqual(response.status_code, 404)

    def test_the_compliance_report_refuses_an_out_of_scope_department(self):
        """
        ``?department=`` fed a pk straight into the report before this change.

        The report lists every volunteer in that department against their screening
        status, and ``&format=pdf`` hands it over as a file.
        """
        client = self.signed_in_client(self.childrens_admin)
        url = reverse("reporting:compliance") + f"?department={self.youth.pk}"

        self.assertEqual(client.get(url).status_code, 404)
        self.assertEqual(client.get(url + "&format=pdf").status_code, 404)

    def test_an_out_of_scope_department_does_not_fall_back_to_church_wide(self):
        """
        The dangerous failure would be *widening*, not refusing.

        ``None`` means church-wide in this codebase, so returning it for a rejected pk
        would have answered a narrower question with a broader report.
        """
        client = self.signed_in_client(self.primary)
        body = client.get(
            reverse("reporting:compliance") + f"?department={self.childrens.pk}"
        ).content.decode()
        self.assertNotIn("Patel", body)

    def test_ending_an_assignment_in_another_department_is_404(self):
        """
        Scoped by the assignment's own department, not by its volunteer's.

        Mia is in the Children's admin's scope, so scoping this by volunteer would let
        them end her *Youth* assignment — which is a write into a department they do not
        administer.
        """
        youth_assignment = self.both.assignments.get(role=self.youth_helper)
        client = self.signed_in_client(self.childrens_admin)

        response = client.post(reverse("org:assignment_end", args=[youth_assignment.pk]))
        self.assertEqual(response.status_code, 404)

        youth_assignment.refresh_from_db()
        self.assertTrue(youth_assignment.is_active)

    def test_ending_an_assignment_in_their_own_department_works(self):
        nursery_assignment = self.both.assignments.get(role=self.nursery)
        client = self.signed_in_client(self.childrens_admin)

        client.post(reverse("org:assignment_end", args=[nursery_assignment.pk]))

        nursery_assignment.refresh_from_db()
        self.assertFalse(nursery_assignment.is_active)

    def test_ending_a_last_assignment_marks_the_volunteer_as_not_serving(self):
        """A volunteer must always belong to a department; the ended row is what keeps that true."""
        client = self.signed_in_client(self.primary)
        assignment = self.jane.assignments.get(role=self.sunday_school)

        client.post(reverse("org:assignment_end", args=[assignment.pk]))

        self.jane.refresh_from_db()
        self.assertFalse(self.jane.is_active)
        # And the association survives, so the department's admin can still open the file.
        self.assertIn(
            self.jane.pk,
            [v.pk for v in scope_volunteers(Volunteer.objects.all(), self.childrens_admin)],
        )


class DropdownLeakTests(TwoDepartmentCase):
    """
    A dropdown that lists every department is an org-chart leak with no view behind it.

    The results would be empty anyway once the list is scoped, which is exactly why this
    is easy to miss.
    """

    def test_the_volunteer_filter_offers_only_their_departments(self):
        from apps.org.forms import VolunteerFilterForm

        form = VolunteerFilterForm(user=self.childrens_admin)
        self.assertCountEqual(
            [d.pk for d in form.fields["department"].queryset], [self.childrens.pk]
        )
        self.assertCountEqual(
            [r.pk for r in form.fields["role"].queryset],
            [self.sunday_school.pk, self.nursery.pk],
        )

    def test_the_dashboard_filter_offers_only_their_departments(self):
        from apps.requirements.forms import RequirementFilterForm

        form = RequirementFilterForm(user=self.childrens_admin)
        self.assertCountEqual(
            [d.pk for d in form.fields["department"].queryset], [self.childrens.pk]
        )

    def test_intake_offers_only_roles_they_administer(self):
        from apps.org.forms import VolunteerForm

        form = VolunteerForm(user=self.childrens_admin)
        self.assertCountEqual(
            [r.pk for r in form.fields["starting_role"].queryset],
            [self.sunday_school.pk, self.nursery.pk],
        )

    def test_a_new_volunteer_must_be_given_a_starting_role(self):
        from apps.org.forms import VolunteerForm

        form = VolunteerForm(
            {"first_name": "New", "last_name": "Person"}, user=self.childrens_admin
        )
        self.assertFalse(form.is_valid())
        self.assertIn("starting_role", form.errors)

    def test_editing_a_volunteer_does_not_ask_for_a_starting_role(self):
        from apps.org.forms import VolunteerForm

        form = VolunteerForm(instance=self.jane, user=self.childrens_admin)
        self.assertNotIn("starting_role", form.fields)


class AggregateLeakTests(TwoDepartmentCase):
    """
    Counts leak too, and they survive a "can they open volunteer X?" test.

    None of these names anybody, so nothing here would fail a per-row check — while the
    dashboard quietly reports the shape of the whole church.
    """

    def test_the_headline_counts_only_their_departments(self):
        from apps.reporting.services import dashboard_headline

        headline = dashboard_headline(user=self.childrens_admin)
        self.assertEqual(headline["active_volunteers"], 2)
        self.assertEqual(headline["departments"], 1)
        self.assertEqual(headline["roles"], 2)

    def test_the_department_summary_lists_only_their_departments(self):
        from apps.reporting.services import build_department_summary

        summary = build_department_summary(user=self.childrens_admin)
        self.assertEqual([row["department"].pk for row in summary], [self.childrens.pk])

    def test_the_compliance_report_covers_only_their_volunteers(self):
        from apps.reporting.services import build_compliance_report

        report = build_compliance_report(user=self.childrens_admin)
        self.assertCountEqual(
            [row.volunteer.pk for row in report["rows"]], [self.jane.pk, self.both.pk]
        )


class EscalationTests(TwoDepartmentCase):
    """
    Nobody may grant access wider than their own.

    Checked at all three layers separately, because each covers a caller the others do
    not: the form queryset covers the UI, ``clean()`` covers a posted primary key that
    never saw the UI, and ``apply_grant`` covers a caller that never built a form.
    """

    def setUp(self):
        super().setUp()
        # A limited level that can also manage users — the only shape where escalation is
        # reachable at all. Not one of the built-ins.
        # Everything Department Admin holds, plus manage_users. It has to be a genuine
        # superset for `covers` to let it hand out Department Admin — which is the point of
        # `covers` not being an integer rank.
        self.limited_manager = AccessLevel.objects.create(
            name="Department Admin (manages users)",
            slug="dept-admin-manages-users",
            is_scoped=True,
            can_view_volunteers=True,
            can_edit_volunteers=True,
            can_manage_assignments=True,
            can_record_screening=True,
            can_record_crc=True,
            can_manage_users=True,
        )
        self.scoped_manager = self.make_admin(
            email="scoped-manager@test.ca", access_level=self.limited_manager
        )
        self.grant_access(self.scoped_manager, self.limited_manager, [self.childrens])
        self.make_passkey(self.scoped_manager)

    def test_the_form_does_not_offer_a_wider_level(self):
        from apps.core.forms import AccessGrantForm

        form = AccessGrantForm(granting_user=self.scoped_manager)
        offered = {level.slug for level in form.fields["access_level"].queryset}

        self.assertNotIn(AccessLevel.PRIMARY_ADMIN, offered)
        self.assertIn(self.limited_manager.slug, offered)

    def test_the_form_does_not_offer_departments_they_do_not_administer(self):
        from apps.core.forms import AccessGrantForm

        form = AccessGrantForm(granting_user=self.scoped_manager)
        self.assertCountEqual(
            [d.pk for d in form.fields["departments"].queryset], [self.childrens.pk]
        )

    def test_posting_a_wider_level_is_refused(self):
        """
        The narrowed queryset is the control here, not merely an affordance.

        ``ModelChoiceField`` validates a submitted primary key against its own queryset,
        so a hand-crafted POST naming Primary Admin never reaches ``clean()``.
        """
        from apps.core.forms import AccessGrantForm

        primary = AccessLevel.objects.get(slug=AccessLevel.PRIMARY_ADMIN)
        form = AccessGrantForm(
            {"access_level": primary.pk, "departments": []},
            granting_user=self.scoped_manager,
        )
        self.assertFalse(form.is_valid())
        self.assertIn("access_level", form.errors)

    def test_posting_a_department_they_do_not_administer_is_refused(self):
        from apps.core.forms import AccessGrantForm

        form = AccessGrantForm(
            {"access_level": self.limited_manager.pk, "departments": [self.youth.pk]},
            granting_user=self.scoped_manager,
        )
        self.assertFalse(form.is_valid())
        self.assertIn("departments", form.errors)

    def test_the_service_refuses_a_wider_level_with_no_form_involved(self):
        """
        The layer that covers a caller who never built a form.

        A command, a future API or a test taking a shortcut all reach ``apply_grant``
        directly, and the form's querysets protect none of them.
        """
        from apps.core.forms import AccessEscalationError, apply_grant

        primary = AccessLevel.objects.get(slug=AccessLevel.PRIMARY_ADMIN)
        victim = self.make_admin(email="target@test.ca")

        with self.assertRaises(AccessEscalationError):
            apply_grant(victim, primary, granted_by=self.scoped_manager)

    def test_the_service_refuses_departments_the_granter_does_not_administer(self):
        from apps.core.forms import AccessEscalationError, apply_grant

        victim = self.make_admin(email="target@test.ca")

        with self.assertRaises(AccessEscalationError):
            apply_grant(
                victim,
                self.limited_manager,
                [self.youth],
                granted_by=self.scoped_manager,
            )

    def test_the_service_allows_a_grant_within_the_granters_own_access(self):
        from apps.core.forms import apply_grant

        victim = self.make_admin(email="target@test.ca")
        grant = apply_grant(
            victim,
            self.department_admin_level(),
            [self.childrens],
            granted_by=self.scoped_manager,
        )
        self.assertEqual(grant.access_level, self.department_admin_level())

    def test_no_granter_skips_the_check(self):
        """
        Provisioning, the backfill and the repair command act for nobody.

        Each already requires shell access to the host, which is a stronger control than
        anything this function could add.
        """
        from apps.core.forms import apply_grant

        primary = AccessLevel.objects.get(slug=AccessLevel.PRIMARY_ADMIN)
        victim = self.make_admin(email="target@test.ca")
        grant = apply_grant(victim, primary)
        self.assertEqual(grant.access_level, primary)

    def test_an_unscoped_level_does_not_keep_departments(self):
        """They would be ignored, and a screen showing them would be lying."""
        from apps.core.forms import apply_grant

        primary = AccessLevel.objects.get(slug=AccessLevel.PRIMARY_ADMIN)
        victim = self.make_admin(email="target@test.ca")
        grant = apply_grant(victim, primary, [self.childrens])
        self.assertEqual(grant.departments.count(), 0)

    def test_a_level_cannot_be_built_with_a_capability_the_author_lacks(self):
        from apps.core.forms import AccessLevelForm

        form = AccessLevelForm(
            {
                "name": "Sneaky",
                "is_scoped": True,
                "is_active": True,
                # MANAGE_REQUIREMENTS is not held by limited_manager.
                "can_manage_requirements": True,
            },
            user=self.scoped_manager,
        )
        self.assertFalse(form.is_valid())
        self.assertTrue(
            any("do not hold yourself" in str(e) for e in form.errors.get("__all__", [])),
            form.errors,
        )

    def test_a_scoped_author_cannot_create_a_church_wide_level(self):
        from apps.core.forms import AccessLevelForm

        form = AccessLevelForm(
            {"name": "Everything", "is_scoped": False, "is_active": True, "can_view_volunteers": True},
            user=self.scoped_manager,
        )
        self.assertFalse(form.is_valid())
        self.assertIn("is_scoped", form.errors)

    def test_an_unscoped_manager_may_grant_anything(self):
        from apps.core.forms import AccessGrantForm

        form = AccessGrantForm(granting_user=self.primary)
        offered = {level.slug for level in form.fields["access_level"].queryset}
        self.assertIn(AccessLevel.PRIMARY_ADMIN, offered)

    def test_covers_is_not_a_rank(self):
        """
        Two levels can be genuinely incomparable, and forcing an order onto them is where
        escalation hides.
        """
        editor = AccessLevel.objects.create(
            name="Requirements Editor",
            slug="requirements-editor",
            is_scoped=False,
            can_manage_requirements=True,
        )
        self.assertFalse(editor.covers(self.limited_manager))
        self.assertFalse(self.limited_manager.covers(editor))


class LockoutGuardTests(TwoDepartmentCase):
    """
    A church must never lose its ability to change who can do what.

    The existing "last active administrator" guard is not enough any more: a church can
    have several administrators and still nobody who can reach the access screen.
    """

    def test_the_last_church_wide_manager_cannot_be_demoted(self):
        client = self.signed_in_client(self.primary)
        department_level = self.department_admin_level()

        response = client.post(
            reverse("accounts:admin_access", args=[self.primary.pk]),
            {"access_level": department_level.pk, "departments": [self.childrens.pk]},
        )
        self.assertEqual(response.status_code, 302)

        self.forget_access(self.primary)
        from apps.core.access import level_for

        self.assertEqual(level_for(self.primary).slug, AccessLevel.PRIMARY_ADMIN)

    def test_the_last_church_wide_manager_cannot_be_deactivated(self):
        client = self.signed_in_client(self.primary)
        other = self.make_admin(email="other@test.ca", access_level=self.department_admin_level())

        client.post(reverse("accounts:admin_toggle_active", args=[other.pk]))
        other.refresh_from_db()
        self.assertFalse(other.is_active, "a department admin may be deactivated")

        # Now the primary is the only one left who can manage access.
        second_primary = self.make_admin(email="second-primary@test.ca")
        client.post(reverse("accounts:admin_toggle_active", args=[second_primary.pk]))
        second_primary.refresh_from_db()
        self.assertFalse(
            second_primary.is_active,
            "another primary may be deactivated while one remains",
        )

    def test_demotion_is_allowed_once_somebody_else_can_manage_access(self):
        self.make_admin(email="cover@test.ca")  # another Primary Admin
        client = self.signed_in_client(self.primary)

        client.post(
            reverse("accounts:admin_access", args=[self.primary.pk]),
            {
                "access_level": self.department_admin_level().pk,
                "departments": [self.childrens.pk],
            },
        )

        self.forget_access(self.primary)
        from apps.core.access import level_for

        self.assertEqual(level_for(self.primary).slug, AccessLevel.DEPARTMENT_ADMIN)


class NavigationTests(TwoDepartmentCase):
    """A link nobody can follow is a support ticket per click."""

    def test_a_department_admin_sees_a_reduced_navigation(self):
        client = self.signed_in_client(self.childrens_admin)
        body = client.get(reverse("org:volunteer_list")).content.decode()

        self.assertIn("Volunteers", body)
        self.assertIn("Departments", body)
        self.assertNotIn("Audit trail", body)
        self.assertNotIn("Administrators", body)

    def test_a_primary_admin_sees_all_of_it(self):
        client = self.signed_in_client(self.primary)
        body = client.get(reverse("org:volunteer_list")).content.decode()

        for label in ("Volunteers", "Departments", "Requirements", "Audit trail", "Administrators"):
            with self.subTest(label=label):
                self.assertIn(label, body)

    def test_a_misspelled_guard_hides_its_link_rather_than_exposing_it(self):
        """
        ``KeyError`` is swallowed by the template engine into an empty string.

        That is the safe direction for navigation, and it is worth pinning because the
        opposite would make every typo a leak.
        """
        from django.template import Context, Template

        from apps.core.context_processors import CapabilityFlags

        class FakeRequest:
            user = self.primary

        rendered = Template("{% if can.view_volunteerz %}LEAKED{% endif %}").render(
            Context({"can": CapabilityFlags(FakeRequest())})
        )
        self.assertEqual(rendered, "")
