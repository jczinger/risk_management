"""
The passkey enrolment gate.

A single-use link is spent the moment it is opened. An account that walks away from that
page without registering a passkey has to recover itself all over again next time — and
until it does, its entire security is a mailbox. So enrolment is enforced on every
request, not merely offered once.

These tests are the reason ``ForcePasskeyMiddleware`` is a middleware rather than a
redirect out of the link view: several of them navigate somewhere else on purpose.
"""

from __future__ import annotations

from django.test import Client
from django.urls import reverse

from apps.core.tests.base import TenantTestCase


class ForcedEnrolmentTests(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_admin(email="new@church.ca")
        self.client = self.signed_in_client(self.admin, with_passkey=False)

    def test_an_account_with_no_passkey_is_sent_to_enrolment(self):
        response = self.client.get(reverse("org:volunteer_list"))

        self.assertRedirects(
            response, reverse("accounts:passkey_required"), fetch_redirect_response=False
        )

    def test_every_page_bounces_back_not_just_the_first(self):
        """
        The point of the middleware. A one-off redirect would be escaped by typing any
        other URL into the address bar.
        """
        for url in (
            reverse("org:volunteer_list"),
            reverse("requirements:definition_list"),
            reverse("reporting:audit_trail"),
            reverse("accounts:security"),
            reverse("accounts:admin_list"),
            "/",
        ):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers["Location"], reverse("accounts:passkey_required"))

    def test_the_enrolment_page_itself_is_reachable(self):
        response = self.client.get(reverse("accounts:passkey_required"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Register a passkey")

    def test_signing_out_still_works(self):
        """
        Nobody may be trapped. Somebody who arrives on a browser that cannot do WebAuthn
        needs a way off this page, or the gate is worse than the state it prevents.
        """
        response = self.client.post(reverse("accounts:logout"))

        self.assertEqual(response.status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_the_webauthn_endpoints_are_reachable(self):
        """Otherwise the gate would block the one action that opens it."""
        response = self.client.post(reverse("accounts:webauthn_register_begin"))

        self.assertEqual(response.status_code, 200)

    def test_registering_a_passkey_opens_the_gate(self):
        self.make_passkey(self.admin)

        response = self.client.get(reverse("org:volunteer_list"))

        self.assertEqual(response.status_code, 200)

    def test_the_enrolment_page_redirects_away_once_there_is_a_passkey(self):
        self.make_passkey(self.admin)

        response = self.client.get(reverse("accounts:passkey_required"))

        self.assertEqual(response.status_code, 302)

    def test_an_anonymous_visitor_is_not_affected(self):
        anonymous = Client(HTTP_HOST=self.TEST_DOMAIN)

        response = anonymous.get(reverse("accounts:login"))

        self.assertEqual(response.status_code, 200)

    def test_the_health_check_is_not_affected(self):
        response = self.client.get("/healthz/")

        self.assertEqual(response.status_code, 200)


class GateOrderingTests(TenantTestCase):
    """
    Passkey enrolment comes before the encryption-key backup step.

    A brand-new church's first administrator trips both gates on the same request.
    Enrolling the passkey first is the right sequence — the key-backup page is a thing
    you do *as* that administrator, and until a passkey exists there is no durable
    "that administrator" to be.
    """

    def test_enrolment_wins_while_both_are_pending(self):
        self.tenant.key_backup_confirmed_at = None
        self.tenant.save(update_fields=["key_backup_confirmed_at"])

        admin = self.make_admin(email="firstever@church.ca")
        client = self.signed_in_client(admin, with_passkey=False)

        response = client.get(reverse("org:volunteer_list"))

        self.assertEqual(response.headers["Location"], reverse("accounts:passkey_required"))

    def test_key_backup_takes_over_once_a_passkey_exists(self):
        self.tenant.key_backup_confirmed_at = None
        self.tenant.save(update_fields=["key_backup_confirmed_at"])

        admin = self.make_admin(email="firstever@church.ca")
        client = self.signed_in_client(admin)

        response = client.get(reverse("org:volunteer_list"))

        self.assertEqual(response.headers["Location"], reverse("tenants:key_backup"))
