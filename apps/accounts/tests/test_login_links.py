"""
Single-use sign-in links.

A link is the only way into an account that is not a passkey, so it is a bearer token
for an administrator account: whoever holds it holds the account, for as long as it
lives. Most of this file is about bounding that — single use, short life, and the same
refusal for every kind of failure.

The other half is the multi-tenant question. Sign-in happens in ``public``, before
anything knows which church the visitor belongs to, so the link carries its schema in a
signed payload. :class:`CrossSchemaTests` proves a link for one church cannot reach
another — including the strongest form of the attack, a *validly signed* payload with
the schema name swapped.
"""

from __future__ import annotations

import datetime
import hashlib
from unittest import mock

from django.core import mail, signing
from django.test import Client, override_settings
from django.urls import reverse
from django.utils import timezone
from django_tenants.utils import get_public_schema_name, schema_context, tenant_context

from apps.accounts import links as link_service
from apps.accounts.models import LinkPurpose, LoginLink, User
from apps.core.models import AuditAction, AuditEvent
from apps.core.tests.base import TenantTestCase


def payload_of(url: str) -> str:
    """The signed payload out of a link URL."""
    return url.rstrip("/").rsplit("/", 1)[-1]


class LinkIssueTests(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_admin(email="sam@church.ca")

    def test_only_the_hash_is_stored(self):
        """
        A live link is a credential. Storing it would mean a database dump handed the
        reader a working sign-in for every outstanding invite.
        """
        link, url = link_service.issue_link(self.admin, LinkPurpose.INVITE)

        secret = signing.loads(payload_of(url), salt=link_service.SIGNING_SALT)["token"]
        self.assertNotIn(secret, str(link.token_hash))
        self.assertEqual(link.token_hash, hashlib.sha256(secret.encode()).hexdigest())

        from django.db import connection

        with connection.cursor() as cursor:
            cursor.execute("SELECT token_hash FROM accounts_loginlink")
            (stored,) = cursor.fetchone()
        self.assertNotIn(secret, stored)

    def test_the_payload_names_the_schema_it_belongs_to(self):
        _, url = link_service.issue_link(self.admin, LinkPurpose.INVITE)

        data = signing.loads(payload_of(url), salt=link_service.SIGNING_SALT)
        self.assertEqual(data["schema"], self.tenant.schema_name)

    def test_two_links_never_collide(self):
        _, first = link_service.issue_link(self.admin, LinkPurpose.INVITE)
        _, second = link_service.issue_link(self.admin, LinkPurpose.INVITE)

        self.assertNotEqual(first, second)
        self.assertEqual(LoginLink.objects.count(), 2)

    @override_settings(VMS_INVITE_LINK_DAYS=7, VMS_RECOVERY_LINK_MINUTES=30)
    def test_the_two_purposes_get_different_lifetimes(self):
        invite, _ = link_service.issue_link(self.admin, LinkPurpose.INVITE)
        recovery, _ = link_service.issue_link(self.admin, LinkPurpose.RECOVERY)

        self.assertGreater(invite.expires_at, recovery.expires_at)
        self.assertLess(
            recovery.expires_at - timezone.now(), datetime.timedelta(minutes=31)
        )

    def test_issuing_is_audited(self):
        link_service.issue_link(self.admin, LinkPurpose.RECOVERY)

        event = AuditEvent.objects.filter(action=AuditAction.LINK_ISSUED).first()
        self.assertIsNotNone(event)
        self.assertIn("recovery", str(event.detail).lower())
        # The trail must not carry the link itself, or reading the trail would be a way
        # in rather than a record of one.
        self.assertNotIn("/accounts/link/", str(event.detail))


class LinkConsumeTests(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_admin(email="sam@church.ca")
        self.client = Client(HTTP_HOST=self.TEST_DOMAIN)

    def issue(self, purpose=LinkPurpose.INVITE):
        return link_service.issue_link(self.admin, purpose)

    def test_a_get_shows_a_confirmation_and_signs_in_nobody(self):
        """
        The fix for a real incident: a GET used to spend the link outright, so anything
        that merely fetched the URL — a chat app building a preview before the message
        was even sent — could burn it before the recipient ever saw it. A GET now only
        confirms the link still works.
        """
        _, url = self.issue()

        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)

        link = LoginLink.objects.get(user=self.admin)
        self.assertIsNone(link.consumed_at)

    def test_a_get_does_not_spend_it_for_a_later_post(self):
        _, url = self.issue()
        self.client.get(url)

        response = self.client.post(url, follow=True)

        self.assertEqual(int(self.client.session["_auth_user_id"]), self.admin.pk)
        self.assertEqual(response.request["PATH_INFO"], reverse("accounts:passkey_required"))

    def test_a_post_signs_you_in_and_lands_on_enrolment(self):
        _, url = self.issue()

        response = self.client.post(url, follow=True)

        self.assertEqual(int(self.client.session["_auth_user_id"]), self.admin.pk)
        self.assertEqual(response.request["PATH_INFO"], reverse("accounts:passkey_required"))

    def test_it_works_exactly_once(self):
        _, url = self.issue()
        self.client.post(url)

        second = Client(HTTP_HOST=self.TEST_DOMAIN)
        response = second.post(url)

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("_auth_user_id", second.session)

    def test_a_fetch_that_never_posts_leaves_the_link_alive_for_the_real_click(self):
        """
        The actual production scenario: something fetches the link (GET) well before
        the recipient clicks through. The recipient's own click must still work.
        """
        _, url = self.issue()

        prefetcher = Client(HTTP_HOST=self.TEST_DOMAIN)
        prefetcher.get(url)

        response = self.client.post(url, follow=True)

        self.assertEqual(int(self.client.session["_auth_user_id"]), self.admin.pk)

    def test_an_expired_row_is_refused_even_though_the_signature_is_good(self):
        """
        Two guards, both load-bearing. The signer's ``max_age`` is set from the *invite*
        window because the purpose cannot be read until the signature is checked, so a
        recovery link inside its seven days but past its thirty minutes is caught only
        by ``expires_at``.
        """
        link, url = self.issue(LinkPurpose.RECOVERY)
        LoginLink.objects.filter(pk=link.pk).update(
            expires_at=timezone.now() - datetime.timedelta(seconds=1)
        )

        response = self.client.get(url)

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_an_old_signature_is_refused_even_though_the_row_is_fresh(self):
        """The other half: a payload minted long ago cannot be replayed."""
        _, url = self.issue()

        stale = timezone.now() + datetime.timedelta(days=8)
        with mock.patch("django.core.signing.time.time", return_value=stale.timestamp()):
            response = self.client.get(url)

        self.assertEqual(response.status_code, 400)

    def test_a_tampered_payload_is_refused(self):
        _, url = self.issue()
        payload = payload_of(url)
        mangled = payload[:-4] + ("AAAA" if not payload.endswith("AAAA") else "BBBB")

        response = self.client.get(reverse("accounts:link_consume", args=[mangled]))

        self.assertEqual(response.status_code, 400)

    def test_an_unknown_token_is_refused(self):
        forged = signing.dumps(
            {"schema": self.tenant.schema_name, "token": "not-a-real-token"},
            salt=link_service.SIGNING_SALT,
        )

        response = self.client.get(reverse("accounts:link_consume", args=[forged]))

        self.assertEqual(response.status_code, 400)

    def test_every_failure_looks_the_same(self):
        """
        Expired, spent, forged and never-existed all render one page. Distinguishing
        them would tell whoever holds a stale link whether the account is real.
        """
        link, used = self.issue()
        self.client.post(used)

        forged = reverse(
            "accounts:link_consume",
            args=[
                signing.dumps(
                    {"schema": self.tenant.schema_name, "token": "nope"},
                    salt=link_service.SIGNING_SALT,
                )
            ],
        )
        _, expired_url = self.issue()
        LoginLink.objects.filter(token_hash__isnull=False).update(
            expires_at=timezone.now() - datetime.timedelta(seconds=1)
        )

        bodies = set()
        for target in (used, forged, expired_url, "/accounts/link/rubbish/"):
            fresh = Client(HTTP_HOST=self.TEST_DOMAIN)
            response = fresh.get(target)
            self.assertEqual(response.status_code, 400, target)
            bodies.add(response.content)

        self.assertEqual(len(bodies), 1, "the refusal pages differ from one another")

    def test_a_deactivated_admins_link_stops_working(self):
        _, url = self.issue()
        self.admin.is_active = False
        self.admin.save()

        response = self.client.post(url)

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_using_a_link_is_audited(self):
        _, url = self.issue()

        self.client.post(url)

        self.assertTrue(AuditEvent.objects.filter(action=AuditAction.LINK_USED).exists())
        login = AuditEvent.objects.filter(action=AuditAction.LOGIN).first()
        self.assertIn("sign-in link", login.summary)

    def test_the_row_survives_being_spent(self):
        """Consumed, not deleted — the trail should show that it was used, and when."""
        link, url = self.issue()

        self.client.post(url)

        link.refresh_from_db()
        self.assertIsNotNone(link.consumed_at)


class RecoveryNotificationTests(TenantTestCase):
    """Recovery is self-service, so it has to be loud."""

    def setUp(self):
        super().setUp()
        self.admin = self.make_admin(email="sam@church.ca")
        self.colleague = self.make_admin(email="jo@church.ca")
        self.client = Client(HTTP_HOST=self.TEST_DOMAIN)
        mail.outbox.clear()

    def test_using_a_recovery_link_tells_the_other_admins(self):
        _, url = link_service.issue_link(self.admin, LinkPurpose.RECOVERY)
        mail.outbox.clear()

        self.client.post(url)

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["jo@church.ca"])
        self.assertIn("recover", mail.outbox[0].subject.lower())

    def test_the_person_recovering_is_not_told_about_themselves(self):
        _, url = link_service.issue_link(self.admin, LinkPurpose.RECOVERY)
        mail.outbox.clear()

        self.client.post(url)

        self.assertNotIn("sam@church.ca", mail.outbox[0].to)

    def test_an_invite_link_tells_nobody(self):
        """A new account being set up is not news; a recovered one is."""
        _, url = link_service.issue_link(self.admin, LinkPurpose.INVITE)
        mail.outbox.clear()

        self.client.post(url)

        self.assertEqual(mail.outbox, [])


class SelfServiceNewDeviceLinkTests(TenantTestCase):
    """
    A signed-in admin minting their own link, to add a passkey on another device —
    the self-service half of what an admin does for someone else via
    ``admin_reissue_link``.
    """

    def setUp(self):
        super().setUp()
        self.admin = self.make_admin(email="sam@church.ca")
        self.make_passkey(self.admin)
        self.client = self.signed_in_client(self.admin)

    def test_a_signed_in_admin_can_mint_their_own_link(self):
        response = self.client.post(reverse("accounts:security_new_device_link"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/accounts/link/")
        link = LoginLink.objects.filter(user=self.admin).latest("created_at")
        self.assertEqual(link.purpose, LinkPurpose.RECOVERY)
        self.assertEqual(link.issued_by_id, self.admin.pk)

    def test_signing_out_is_required(self):
        anon = Client(HTTP_HOST=self.TEST_DOMAIN)

        response = anon.post(reverse("accounts:security_new_device_link"))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("accounts:login"), response.headers["Location"])

    def test_opening_the_self_issued_link_lands_on_the_security_page(self):
        """
        The point of the feature: it exists to add a passkey on the device that opens
        it, so landing on the dashboard instead would leave that a click away.
        """
        issued = self.client.post(reverse("accounts:security_new_device_link"))
        url = issued.context["url"]

        new_device = Client(HTTP_HOST=self.TEST_DOMAIN)
        response = new_device.post(url, follow=True)

        self.assertEqual(int(new_device.session["_auth_user_id"]), self.admin.pk)
        self.assertEqual(response.request["PATH_INFO"], reverse("accounts:security"))

    def test_the_other_admins_are_told_when_it_is_used(self):
        """
        Recovery's usual loudness applies here too: a link-based sign-in happened,
        regardless of who asked for the link, and colleagues should know in case it
        was not really the account holder who asked.
        """
        self.make_admin(email="jo@church.ca")

        issued = self.client.post(reverse("accounts:security_new_device_link"))
        mail.outbox.clear()  # drop the "here is your link" email issuing it just sent
        Client(HTTP_HOST=self.TEST_DOMAIN).post(issued.context["url"])

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["jo@church.ca"])


class RecoveryRequestTests(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_admin(email="sam@church.ca")
        self.client = Client(HTTP_HOST=self.TEST_DOMAIN)
        mail.outbox.clear()

    def test_a_known_address_gets_a_link(self):
        response = self.client.post(reverse("accounts:recover"), {"email": "sam@church.ca"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(LoginLink.objects.count(), 1)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["sam@church.ca"])

    def test_an_unknown_address_looks_identical(self):
        known = self.client.post(reverse("accounts:recover"), {"email": "sam@church.ca"})
        unknown = Client(HTTP_HOST=self.TEST_DOMAIN).post(
            reverse("accounts:recover"), {"email": "nobody@example.ca"}
        )

        self.assertEqual(known.content, unknown.content)
        self.assertEqual(LoginLink.objects.count(), 1, "no link for the unknown address")

    def test_the_address_is_matched_case_insensitively(self):
        self.client.post(reverse("accounts:recover"), {"email": "SAM@Church.CA"})

        self.assertEqual(LoginLink.objects.count(), 1)

    def test_a_deactivated_admin_gets_nothing_and_is_told_the_same(self):
        self.admin.is_active = False
        self.admin.save()

        response = self.client.post(reverse("accounts:recover"), {"email": "sam@church.ca"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(LoginLink.objects.count(), 0)

    def test_the_send_is_recorded_in_the_email_log(self):
        from apps.notifications.models import EmailLog, NotificationStatus

        self.client.post(reverse("accounts:recover"), {"email": "sam@church.ca"})

        entry = EmailLog.objects.first()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, NotificationStatus.SENT)

    def test_a_mail_failure_does_not_lose_the_link_or_500(self):
        """
        The link is valid whether or not the email arrived, and the operator can still
        hand one over from the command line. Failing the request would be worse.
        """
        from apps.notifications.providers import EmailSendError

        with mock.patch(
            "apps.notifications.providers.LocMemProvider.send",
            side_effect=EmailSendError("relay refused"),
        ):
            response = self.client.post(
                reverse("accounts:recover"), {"email": "sam@church.ca"}
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(LoginLink.objects.count(), 1)


class CrossSchemaTests(TenantTestCase):
    """
    A link belongs to one church, and only that church.

    The payload is signed for the same reason the tenant cookie is: consuming it calls
    ``bind_tenant()`` on the schema name inside, and nothing attacker-chosen may reach
    that function.
    """

    def setUp(self):
        super().setUp()
        from apps.tenants.services import provision_church

        self.mine = self.make_admin(email="sam@church.ca")
        with schema_context(get_public_schema_name()):
            self.other = provision_church(
                name="Other Church",
                schema_name="otherch",
                domain_name="",
                admin_email="admin@other.ca",
                admin_first_name="Other",
                admin_last_name="Admin",
                seed_template=False,
            ).tenant
        self.client = Client(HTTP_HOST=self.TEST_DOMAIN)

    def test_a_link_repointed_at_another_schema_finds_no_token(self):
        _, url = link_service.issue_link(self.mine, LinkPurpose.INVITE)
        secret = signing.loads(payload_of(url), salt=link_service.SIGNING_SALT)["token"]

        # A *validly signed* payload naming the other church — the strongest form of the
        # attack, and the one the signature alone cannot stop.
        repointed = signing.dumps(
            {"schema": "otherch", "token": secret}, salt=link_service.SIGNING_SALT
        )
        response = self.client.get(reverse("accounts:link_consume", args=[repointed]))

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_a_link_for_a_suspended_church_stops_working(self):
        with tenant_context(self.other):
            other_admin = User.objects.get(first_name="Other")
            _, url = link_service.issue_link(other_admin, LinkPurpose.INVITE)

        self.other.is_active = False
        with schema_context(get_public_schema_name()):
            self.other.save(update_fields=["is_active"])

        response = self.client.get(url)

        self.assertEqual(response.status_code, 400)

    def test_consuming_a_link_binds_the_request_to_that_church(self):
        """The signed-in user is the other church's admin, not anybody here."""
        with tenant_context(self.other):
            other_admin = User.objects.get(first_name="Other")
            _, url = link_service.issue_link(other_admin, LinkPurpose.INVITE)
            expected_pk = other_admin.pk

        self.client.post(url)

        self.assertEqual(int(self.client.session["_auth_user_id"]), expected_pk)
        from apps.tenants.routing import TENANT_COOKIE_NAME

        self.assertIn("otherch", self.client.cookies[TENANT_COOKIE_NAME].value)

    def test_no_two_accounts_share_a_session_auth_hash(self):
        """
        The reason the passwordless migration writes a *distinct* unusable password per
        row rather than one value everywhere.

        The session table is shared across schemas, so what stops a session from one
        church being replayed at another is Django's ``_auth_user_hash`` — an HMAC over
        the user's ``password`` column. Give every account the same unusable marker and
        that hash stops distinguishing them, and a session for user 5 here would
        validate as user 5 there. See apps/accounts/migrations/0002.
        """
        from django.contrib.auth.hashers import make_password

        with tenant_context(self.other):
            other_admin = User.objects.get(first_name="Other")
            theirs = other_admin.get_session_auth_hash()

        mine = self.mine.get_session_auth_hash()

        self.assertNotEqual(mine, theirs)
        self.assertNotEqual(self.mine.password, "")
        # And the generator itself is not a constant.
        self.assertNotEqual(make_password(None), make_password(None))

    def test_one_address_at_two_churches_gets_a_link_for_each(self):
        """
        Better than the password form managed: it resolved a duplicated address to the
        first church alphabetically and logged a warning, leaving the second account
        quietly unreachable.
        """
        shared = "shared@example.ca"
        self.make_admin(email=shared, first_name="Shared", last_name="One")
        with tenant_context(self.other):
            User.objects.create_user(email=shared, first_name="Shared", last_name="Two")

        mail.outbox.clear()
        self.client.post(reverse("accounts:recover"), {"email": shared})

        self.assertEqual(len(mail.outbox), 2)
        for schema in (self.tenant, self.other):
            with tenant_context(schema):
                # Filtered by purpose: provisioning a church already mints an invite for
                # its first admin, so a bare count would be measuring the fixture.
                self.assertEqual(
                    LoginLink.objects.filter(purpose=LinkPurpose.RECOVERY).count(), 1
                )
