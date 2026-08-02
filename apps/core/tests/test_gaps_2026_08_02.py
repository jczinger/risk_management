"""
Four holes found while linking administrators to their volunteer records.

None of them was reachable through the UI in a way anybody would have noticed, which is
the point of writing them down here rather than only fixing them. Each test is named for
what the hole actually allowed, so a future reader can tell at a glance what breaks if
they undo the guard. See BUILD_NOTES §1.22.
"""

from __future__ import annotations

from unittest import mock

from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone

from apps.core import audit
from apps.core.models import AuditAction, AuditEvent
from apps.core.tests.base import TenantTestCase


class TheEncryptionKeyDownloadWasWideOpen(TenantTestCase):
    """
    D1, and the worst of the four.

    ``key_backup_download`` carried ``@open_to_any_signed_in_user``, so any signed-in
    administrator — including one on a limited level holding not a single capability —
    could GET it at any time, long after the backup step was finished, and receive the
    key that decrypts every volunteer record at the church. It wrote no audit entry, so
    ``docs/SECURITY.md``'s promise that "every key export writes an entry into that
    church's own audit trail" was not true of this route.
    """

    def setUp(self):
        super().setUp()
        self.childrens = self.make_department("Children's Ministry")
        self.primary = self.make_admin(email="primary@test.ca")
        self.make_passkey(self.primary)
        self.dept_admin = self.make_department_admin(
            email="dept@test.ca", departments=[self.childrens]
        )

    def pend_the_backup(self):
        """Put the church back into the pre-confirmation state the middleware traps on."""
        self.tenant.key_backup_confirmed_at = None
        self.tenant.save(update_fields=["key_backup_confirmed_at"])

    def test_a_limited_administrator_cannot_download_the_key(self):
        client = self.signed_in_client(self.dept_admin)
        response = client.get(reverse("tenants:key_backup_download"))
        self.assertEqual(response.status_code, 403)

    def test_an_administrator_who_runs_the_church_still_can(self):
        client = self.signed_in_client(self.primary)
        response = client.get(reverse("tenants:key_backup_download"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("Key (base64)", response.content.decode())

    def test_the_download_is_now_audited(self):
        client = self.signed_in_client(self.primary)
        client.get(reverse("tenants:key_backup_download"))

        entry = AuditEvent.objects.filter(action=AuditAction.KEY_BACKUP).latest("id")
        self.assertEqual(entry.summary, "Encryption key downloaded")

    def test_the_key_never_reaches_the_response_body_of_a_refused_request(self):
        """
        Belt to the braces. A 403 that still rendered the key in an error page would be
        the same leak with a different status code.
        """
        from apps.core.crypto import encode_key, unwrap_dek

        secret = encode_key(unwrap_dek(bytes(self.tenant.dek_wrapped)))
        client = self.signed_in_client(self.dept_admin)
        response = client.get(reverse("tenants:key_backup_download"))
        self.assertNotIn(secret, response.content.decode(errors="replace"))

    def test_the_setup_page_hides_the_key_from_someone_who_may_not_hold_it(self):
        """
        The page itself stays open, deliberately: ``ForceKeyBackupMiddleware`` redirects
        everybody here, so a limited admin trapped on it needs to be told what is going
        on rather than shown a wall. What they must not be shown is the key.
        """
        from apps.core.crypto import encode_key, unwrap_dek

        self.pend_the_backup()
        secret = encode_key(unwrap_dek(bytes(self.tenant.dek_wrapped)))

        client = self.signed_in_client(self.dept_admin)
        body = client.get(reverse("tenants:key_backup")).content.decode()

        self.assertNotIn(secret, body)
        self.assertIn("Someone else has to finish this step", body)

    def test_they_cannot_confirm_a_backup_they_never_saw(self):
        """The confirmation is a compliance record, and the form only checks a
        fingerprint that is on the page for everyone."""
        self.pend_the_backup()

        client = self.signed_in_client(self.dept_admin)
        client.post(
            reverse("tenants:key_backup"), {"fingerprint": self.tenant.dek_fingerprint}
        )

        self.tenant.refresh_from_db()
        self.assertTrue(self.tenant.key_backup_pending)


class CustomAccessLevelsSkippedReviewEntirely(TenantTestCase):
    """
    D2. ``Actor.needs_review`` compared the level's slug against ``"department-admin"``
    exactly, so a church that built its own limited level on the access-level screen —
    which the form exposes ``is_scoped`` precisely to allow — recorded work that never
    entered the review queue, while ``may_review`` still refused that person as a
    reviewer. A limited admin reviewed by nobody, reviewing nobody, silently.
    """

    def setUp(self):
        super().setUp()
        self.seed()
        self.youth = self.make_department("Youth")
        self.role = self.make_role(self.youth, name="Youth Leader")
        self.volunteer = self.make_volunteer(first_name="Alex", last_name="Kim")
        self.assign(self.volunteer, self.role)

        from apps.requirements.services import sync_volunteer_requirements

        sync_volunteer_requirements(self.volunteer)

        self.primary = self.make_admin(email="primary@test.ca")

    def a_church_built_level(self):
        from apps.core.models import AccessLevel

        return AccessLevel.objects.create(
            name="Youth Admin",
            slug="youth-admin",
            is_scoped=True,
            can_view_volunteers=True,
            can_record_screening=True,
        )

    def acting_as(self, user):
        request = RequestFactory().get("/")
        request.user = user
        return audit.acting_as(audit.actor_from_request(request))

    def test_their_work_is_queued_for_review(self):
        """The test that would have caught the hole the day it shipped."""
        from apps.requirements.services import mark_requirement_complete
        from apps.review.models import ReviewItem

        level = self.a_church_built_level()
        scoped = self.make_admin(email="youth-admin@test.ca", access_level=level)
        self.grant_access(scoped, level, [self.youth])

        instance = self.volunteer.requirement_instances.get(
            definition__name__icontains="Interview"
        )
        with self.acting_as(scoped):
            mark_requirement_complete(instance, timezone.localdate())

        self.assertEqual(ReviewItem.objects.pending().count(), 1)

    def test_the_gate_reads_the_same_flag_the_reviewer_test_reads(self):
        """
        The structural fix, and the reason the bug cannot come back in a new shape.
        "A scoped admin's work needs affirming" and "only an unscoped admin may affirm"
        are now two readings of one flag rather than two independent facts.
        """
        from apps.core.access import is_unscoped

        level = self.a_church_built_level()
        scoped = self.make_admin(email="youth2@test.ca", access_level=level)
        self.grant_access(scoped, level, [self.youth])

        request = RequestFactory().get("/")
        request.user = scoped
        actor = audit.actor_from_request(request)

        self.assertTrue(actor.needs_review)
        self.assertFalse(is_unscoped(scoped))

    def test_a_primary_admin_still_queues_nothing(self):
        from apps.requirements.services import mark_requirement_complete
        from apps.review.models import ReviewItem

        instance = self.volunteer.requirement_instances.get(
            definition__name__icontains="Interview"
        )
        with self.acting_as(self.primary):
            mark_requirement_complete(instance, timezone.localdate())

        self.assertEqual(ReviewItem.objects.pending().count(), 0)


class TheReviewGateFailedOpenOnError(TenantTestCase):
    """
    D3. ``_access_context`` swallowed any error resolving the acting user's grant and
    returned blanks — which made the actor look *unscoped*, which made ``needs_review``
    answer False. One transient database hiccup and a limited admin's entry was recorded
    as though somebody with church-wide responsibility had done it, with nothing to say
    so. ``apps.review.recording`` takes the opposite posture on the same class of
    problem, and deliberately raises.
    """

    def setUp(self):
        super().setUp()
        self.childrens = self.make_department("Children's Ministry")
        self.dept_admin = self.make_department_admin(
            email="dept@test.ca", departments=[self.childrens]
        )

    def actor_for(self, user):
        request = RequestFactory().get("/")
        request.user = user
        return audit.actor_from_request(request)

    def test_an_unresolvable_access_level_is_treated_as_needing_review(self):
        with mock.patch(
            "apps.core.access.grant_for", side_effect=RuntimeError("database hiccup")
        ):
            actor = self.actor_for(self.dept_admin)

        self.assertTrue(actor.access_level_unknown)
        self.assertTrue(actor.needs_review)

    def test_the_request_still_works(self):
        """Tolerant is the whole reason for the ``except``; it must stay tolerant."""
        with mock.patch(
            "apps.core.access.grant_for", side_effect=RuntimeError("database hiccup")
        ):
            actor = self.actor_for(self.dept_admin)

        self.assertEqual(actor.user_id, self.dept_admin.pk)

    def test_a_job_with_no_person_behind_it_still_queues_nothing(self):
        """
        The fail-closed rule must not catch the nightly sweep. ``Actor.system()`` has no
        user, so there is nobody to send anything back to.
        """
        self.assertFalse(audit.Actor.system("nightly job").needs_review)


class SelfAffirmationCouldBeUnlockedOnPurpose(TenantTestCase):
    """
    D4. ``may_review`` refuses self-affirmation only while somebody else could do it —
    an escape hatch for the church whose last other reviewer left. The hatch turned out
    to be openable deliberately: sit on a pile of your own unaffirmed entries, deactivate
    the only other church-wide administrator, and they all become yours to wave through.
    The existing guards protect against *lockout*, which is a different set of people.
    """

    def setUp(self):
        super().setUp()
        self.seed()
        self.childrens = self.make_department("Children's Ministry")
        self.role = self.make_role(self.childrens, name="Helper")
        self.volunteer = self.make_volunteer(first_name="Jo", last_name="Blake")
        self.assign(self.volunteer, self.role)

        from apps.requirements.services import sync_volunteer_requirements

        sync_volunteer_requirements(self.volunteer)

        self.first = self.make_admin(email="first@test.ca")
        self.second = self.make_admin(email="second@test.ca")
        self.make_passkey(self.first)

    def give_first_a_backlog(self):
        """
        Entries recorded by ``first`` and still pending.

        Written directly rather than through the writers, because a Primary Admin's own
        work is never queued — which is exactly how this backlog would arise in practice:
        they were on a limited level, recorded these, and were then promoted.
        """
        from apps.review.models import ReviewItem, ReviewKind

        instance = self.volunteer.requirement_instances.first()
        return ReviewItem.objects.create(
            volunteer=self.volunteer,
            kind=ReviewKind.REQUIREMENT_COMPLETION,
            entity_type="RequirementInstance",
            entity_id=str(instance.pk),
            entity_label="Jo Blake — Interview",
            recorded_by_user_id=self.first.pk,
            recorded_by_display="First Admin",
        )

    def test_deactivating_the_last_other_reviewer_is_refused(self):
        self.give_first_a_backlog()
        client = self.signed_in_client(self.first)

        response = client.post(
            reverse("accounts:admin_toggle_active", args=[self.second.pk]), follow=True
        )

        self.second.refresh_from_db()
        self.assertTrue(self.second.is_active)
        self.assertIn("awaiting review", response.content.decode())

    def test_it_is_allowed_once_the_queue_is_clear(self):
        client = self.signed_in_client(self.first)

        client.post(reverse("accounts:admin_toggle_active", args=[self.second.pk]))

        self.second.refresh_from_db()
        self.assertFalse(self.second.is_active)

    def test_a_third_reviewer_makes_it_fine_again(self):
        """The refusal is about being left alone with your own work, not about
        deactivations in general."""
        self.give_first_a_backlog()
        self.make_admin(email="third@test.ca")
        client = self.signed_in_client(self.first)

        client.post(reverse("accounts:admin_toggle_active", args=[self.second.pk]))

        self.second.refresh_from_db()
        self.assertFalse(self.second.is_active)
