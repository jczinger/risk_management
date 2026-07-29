"""
Authentication tests (Build Spec §2, §10, as amended — see BUILD_NOTES §1.20).

Acceptance criterion covered: an administrator signs in with a passkey; an account with
no passkey can be given one through a single-use link and cannot reach anything else
until it has.

The passkey ceremonies are exercised through their service layer with the WebAuthn
verification stubbed, because a real assertion needs an authenticator to sign a
challenge — there is no way to produce one in-process. What *is* tested for real:
challenge issuance, single use, expiry, credential storage, sign-count handling, and the
rate limits.

Links have their own file, :mod:`apps.accounts.tests.test_login_links`, and the
enrolment gate has :mod:`apps.accounts.tests.test_forced_enrolment`.
"""

from __future__ import annotations

import datetime
import json
from unittest import mock

from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from apps.accounts import webauthn_service
from apps.accounts.models import Passkey, User, WebAuthnChallenge
from apps.core.models import AuditAction, AuditEvent
from apps.core.tests.base import TenantTestCase


class PasskeyRegistrationTests(TenantTestCase):
    """WebAuthn registration, with the cryptographic verification stubbed."""

    def setUp(self):
        super().setUp()
        self.admin = self.make_admin(email="admin@church.ca")
        # No passkey to start with: several of these count the rows, and this class is
        # about the act of acquiring the first one. The WebAuthn endpoints are exempt
        # from the enrolment gate, so an account without one can still reach them.
        self.client = self.signed_in_client(self.admin, with_passkey=False)

    def test_begin_registration_issues_a_challenge(self):
        response = self.client.post(reverse("accounts:webauthn_register_begin"))

        self.assertEqual(response.status_code, 200)
        options = json.loads(response.content)
        self.assertIn("challenge", options)
        self.assertIn("rp", options)
        self.assertEqual(options["rp"]["id"], "testserver")
        self.assertTrue(options["user"]["id"])
        # The address must not be leaked into the handle the authenticator stores.
        self.assertNotIn("admin@church.ca", options["user"]["id"])

        challenge = WebAuthnChallenge.objects.get()
        self.assertEqual(challenge.purpose, WebAuthnChallenge.PURPOSE_REGISTER)
        self.assertEqual(challenge.user, self.admin)

    def test_finish_registration_stores_the_credential(self):
        webauthn_service.begin_registration(_fake_request(self.admin), self.admin)

        verified = mock.Mock(
            credential_id=b"credential-id-bytes",
            credential_public_key=b"public-key-bytes",
            sign_count=0,
        )
        with mock.patch.object(
            webauthn_service, "verify_registration_response", return_value=verified
        ):
            passkey = webauthn_service.finish_registration(
                _fake_request(self.admin), self.admin, "{}", label="work laptop"
            )

        self.assertEqual(passkey.user, self.admin)
        self.assertEqual(bytes(passkey.public_key), b"public-key-bytes")
        self.assertEqual(passkey.label, "work laptop")
        self.assertTrue(self.admin.has_passkey)

    def test_a_challenge_is_single_use(self):
        webauthn_service.begin_registration(_fake_request(self.admin), self.admin)
        verified = mock.Mock(
            credential_id=b"cred-1", credential_public_key=b"pk", sign_count=0
        )

        with mock.patch.object(
            webauthn_service, "verify_registration_response", return_value=verified
        ):
            webauthn_service.finish_registration(_fake_request(self.admin), self.admin, "{}")

            # Replaying the same challenge must fail.
            with self.assertRaises(webauthn_service.WebAuthnError):
                webauthn_service.finish_registration(_fake_request(self.admin), self.admin, "{}")

    def test_an_expired_challenge_is_refused(self):
        webauthn_service.begin_registration(_fake_request(self.admin), self.admin)
        WebAuthnChallenge.objects.update(
            created_at=timezone.now() - datetime.timedelta(minutes=10)
        )

        with self.assertRaises(webauthn_service.WebAuthnError):
            webauthn_service.finish_registration(_fake_request(self.admin), self.admin, "{}")

    def test_a_failed_verification_is_reported_not_stored(self):
        webauthn_service.begin_registration(_fake_request(self.admin), self.admin)

        with mock.patch.object(
            webauthn_service,
            "verify_registration_response",
            side_effect=ValueError("attestation invalid"),
        ):
            with self.assertRaises(webauthn_service.WebAuthnError):
                webauthn_service.finish_registration(_fake_request(self.admin), self.admin, "{}")

        self.assertEqual(Passkey.objects.count(), 0)

    def test_the_same_credential_cannot_be_registered_twice(self):
        verified = mock.Mock(credential_id=b"cred-1", credential_public_key=b"pk", sign_count=0)

        with mock.patch.object(
            webauthn_service, "verify_registration_response", return_value=verified
        ):
            webauthn_service.begin_registration(_fake_request(self.admin), self.admin)
            webauthn_service.finish_registration(_fake_request(self.admin), self.admin, "{}")

            webauthn_service.begin_registration(_fake_request(self.admin), self.admin)
            with self.assertRaises(webauthn_service.WebAuthnError):
                webauthn_service.finish_registration(_fake_request(self.admin), self.admin, "{}")

        self.assertEqual(Passkey.objects.count(), 1)

    def test_the_passkey_label_is_encrypted(self):
        from django.db import connection

        _register(self.admin, b"cred-label", label="Priya's iPhone")

        with connection.cursor() as cursor:
            cursor.execute("SELECT label FROM accounts_passkey ORDER BY id DESC LIMIT 1")
            (stored,) = cursor.fetchone()

        self.assertTrue(stored.startswith("v1."))
        self.assertNotIn("Priya", stored)


class PasskeyAuthenticationTests(TenantTestCase):
    """Signing in with a passkey."""

    def setUp(self):
        super().setUp()
        self.admin = self.make_admin(email="admin@church.ca")
        self.passkey = _register(self.admin, b"cred-auth", label="laptop")

    def _client(self):
        from django.test import Client

        return Client(HTTP_HOST=self.TEST_DOMAIN)

    def test_begin_authentication_needs_no_username(self):
        """
        Discoverable credentials are what make "click sign in, touch the sensor" work with
        nothing typed first.
        """
        client = self._client()
        response = client.post(reverse("accounts:webauthn_auth_begin"))

        self.assertEqual(response.status_code, 200)
        options = json.loads(response.content)
        self.assertIn("challenge", options)
        # No credential list at all, so the browser offers whichever passkey it holds.
        self.assertFalse(options.get("allowCredentials"))

    def test_a_successful_assertion_signs_the_user_in_in_one_step(self):
        """
        A passkey already proves possession of an unlocked device, so there is nothing to
        ask for afterwards — which is what makes it viable as the only way in.
        """
        client = self._client()
        client.post(reverse("accounts:webauthn_auth_begin"))

        credential = json.dumps({"id": self.passkey.credential_id})
        verified = mock.Mock(new_sign_count=1)

        with mock.patch.object(
            webauthn_service, "verify_authentication_response", return_value=verified
        ):
            response = client.post(
                reverse("accounts:webauthn_auth_finish"),
                data=credential,
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(json.loads(response.content)["ok"])
        self.assertEqual(int(client.session["_auth_user_id"]), self.admin.pk)

        event = AuditEvent.objects.filter(action=AuditAction.LOGIN).first()
        self.assertIn("passkey", event.summary)

    def test_the_sign_counter_is_advanced(self):
        client = self._client()
        client.post(reverse("accounts:webauthn_auth_begin"))

        with mock.patch.object(
            webauthn_service,
            "verify_authentication_response",
            return_value=mock.Mock(new_sign_count=7),
        ):
            client.post(
                reverse("accounts:webauthn_auth_finish"),
                data=json.dumps({"id": self.passkey.credential_id}),
                content_type="application/json",
            )

        self.passkey.refresh_from_db()
        self.assertEqual(self.passkey.sign_count, 7)
        self.assertIsNotNone(self.passkey.last_used_at)

    def test_an_unknown_credential_is_refused_without_revealing_why(self):
        client = self._client()
        client.post(reverse("accounts:webauthn_auth_begin"))

        response = client.post(
            reverse("accounts:webauthn_auth_finish"),
            data=json.dumps({"id": "not-a-registered-credential"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("_auth_user_id", client.session)

    def test_a_deactivated_admins_passkey_stops_working(self):
        self.admin.is_active = False
        self.admin.save()

        client = self._client()
        client.post(reverse("accounts:webauthn_auth_begin"))

        with mock.patch.object(
            webauthn_service,
            "verify_authentication_response",
            return_value=mock.Mock(new_sign_count=1),
        ):
            response = client.post(
                reverse("accounts:webauthn_auth_finish"),
                data=json.dumps({"id": self.passkey.credential_id}),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("_auth_user_id", client.session)

    def test_a_deactivated_passkey_stops_working(self):
        self.passkey.is_active = False
        self.passkey.save()

        client = self._client()
        client.post(reverse("accounts:webauthn_auth_begin"))
        response = client.post(
            reverse("accounts:webauthn_auth_finish"),
            data=json.dumps({"id": self.passkey.credential_id}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)


class PasskeyRemovalTests(TenantTestCase):
    """
    Removing a passkey, including the last one.

    This used to be refused unless a password and an authenticator app remained. Neither
    exists now, and the guard went with them: an account with no passkey is not locked
    out, it is one email away from a new one. What replaces the guard is the enrolment
    gate — see :mod:`apps.accounts.tests.test_forced_enrolment`.
    """

    def test_the_last_passkey_can_be_removed(self):
        admin = self.make_admin(email="passkeyonly@church.ca")
        passkey = _register(admin, b"cred-only")

        webauthn_service.remove_passkey(admin, passkey.pk)

        passkey.refresh_from_db()
        self.assertFalse(passkey.is_active)
        self.assertFalse(admin.has_passkey)

    def test_a_passkey_can_be_removed_when_another_remains(self):
        admin = self.make_admin(email="two@church.ca")
        first = _register(admin, b"cred-a")
        _register(admin, b"cred-b")

        webauthn_service.remove_passkey(admin, first.pk)

        first.refresh_from_db()
        self.assertFalse(first.is_active)
        self.assertTrue(admin.has_passkey)

    def test_removal_is_a_soft_delete(self):
        """The audit trail refers to passkeys, so the rows have to survive."""
        admin = self.make_admin(email="soft@church.ca")
        passkey = _register(admin, b"cred-soft")

        webauthn_service.remove_passkey(admin, passkey.pk)

        self.assertTrue(Passkey.objects.filter(pk=passkey.pk).exists())

    def test_the_last_active_admin_cannot_be_deactivated(self):
        """A church locking itself out entirely is not a state worth allowing."""
        admin = self.make_admin(email="only@church.ca")
        other = self.make_admin(email="other@church.ca")
        other.is_active = False
        other.save()

        client = self.signed_in_client(admin)
        response = client.post(reverse("accounts:admin_toggle_active", args=[other.pk]))
        self.assertEqual(response.status_code, 302)

        # And nobody can deactivate themselves.
        client.post(reverse("accounts:admin_toggle_active", args=[admin.pk]))
        admin.refresh_from_db()
        self.assertTrue(admin.is_active)


class RateLimitTests(TenantTestCase):
    """
    The passkey endpoints are metered per source (Build Spec §6).

    They were not, before. That was defensible while a rate-limited password form stood
    beside them; it is not now they are the only interactive way in, and a ``finish``
    call with an unknown credential costs a scan across every church's schema.
    """

    @override_settings(LOGIN_RATELIMIT="3/5m")
    def test_repeated_passkey_attempts_start_being_refused(self):
        from django.core.cache import cache
        from django.test import Client

        cache.clear()
        client = Client(HTTP_HOST=self.TEST_DOMAIN)

        statuses = [
            client.post(reverse("accounts:webauthn_auth_begin")).status_code
            for _ in range(8)
        ]

        self.assertIn(429, statuses, "expected the passkey endpoint to start refusing")
        self.assertEqual(statuses[0], 200, "the first attempt must still work")
        cache.clear()

    @override_settings(LOGIN_RATELIMIT="3/5m")
    def test_the_finish_endpoint_is_metered_too(self):
        """
        Metering only ``begin`` would leave the expensive half open: ``finish`` is the
        one that scans every schema for an unrecognised credential.
        """
        from django.core.cache import cache
        from django.test import Client

        cache.clear()
        client = Client(HTTP_HOST=self.TEST_DOMAIN)

        statuses = [
            client.post(
                reverse("accounts:webauthn_auth_finish"),
                data=json.dumps({"id": "nope"}),
                content_type="application/json",
            ).status_code
            for _ in range(8)
        ]

        self.assertIn(429, statuses)
        cache.clear()

    @override_settings(VMS_RECOVERY_RATELIMIT="2/1h")
    def test_link_requests_are_refused_after_a_few(self):
        """Each request that lands sends real mail, so this limit protects an inbox."""
        from django.core.cache import cache
        from django.test import Client

        cache.clear()
        self.make_admin(email="admin@church.ca")
        client = Client(HTTP_HOST=self.TEST_DOMAIN)

        limited = False
        for _ in range(6):
            response = client.post(
                reverse("accounts:recover"), {"email": "admin@church.ca"}
            )
            if b"Too many requests" in response.content:
                limited = True
                break

        self.assertTrue(limited, "expected the recovery form to start refusing")
        cache.clear()


class AdminManagementTests(TenantTestCase):
    """Adding and retiring a church's administrators."""

    def setUp(self):
        super().setUp()
        self.admin = self.make_admin(email="first@church.ca")
        self.client = self.signed_in_client(self.admin)

    def test_adding_an_admin_mints_a_link_and_shows_it(self):
        response = self.client.post(
            reverse("accounts:admin_invite"),
            {"first_name": "Sam", "last_name": "Lee", "email": "sam@church.ca"},
        )
        self.assertEqual(response.status_code, 200)

        added = User.objects.get(first_name="Sam")
        self.assertTrue(added.is_active)
        self.assertFalse(added.has_usable_password())
        self.assertEqual(added.login_links.count(), 1)

        # Shown on screen, not merely emailed — the inviting admin may need to hand it
        # over another way, and an invite that silently failed to arrive is worse than
        # one the sender can see.
        self.assertContains(response, "/accounts/link/")

    def test_a_duplicate_address_is_refused(self):
        response = self.client.post(
            reverse("accounts:admin_invite"),
            {"first_name": "Another", "last_name": "Person", "email": "FIRST@church.ca"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already exists")

    def test_all_admins_have_equal_permissions(self):
        """Build Spec §2: no roles within a church, by design."""
        second = self.make_admin(email="second@church.ca")
        client = self.signed_in_client(second)

        for url in (
            reverse("org:volunteer_list"),
            reverse("requirements:definition_list"),
            reverse("reporting:audit_trail"),
            reverse("accounts:admin_list"),
        ):
            with self.subTest(url=url):
                self.assertEqual(client.get(url).status_code, 200)

    def test_an_admin_is_deactivated_never_deleted(self):
        second = self.make_admin(email="second@church.ca")
        self.client.post(reverse("accounts:admin_toggle_active", args=[second.pk]))

        second.refresh_from_db()
        self.assertFalse(second.is_active)
        self.assertTrue(User.objects.filter(pk=second.pk).exists())


class PasswordRemovalTests(TenantTestCase):
    """
    Nothing can sign in with a password, and the upgrade left nothing that could.
    """

    def test_a_new_account_gets_an_unusable_password(self):
        admin = self.make_admin(email="fresh@church.ca")

        self.assertFalse(admin.has_usable_password())
        self.assertTrue(admin.password.startswith("!"))

    def test_a_password_passed_to_create_user_is_ignored(self):
        """
        Django's own plumbing passes one positionally in places we do not control.
        Honouring it would put a working credential back into a system with nothing to
        check it against; raising would turn a harmless no-op into a crash.
        """
        admin = User.objects.create_user(
            email="ignored@church.ca", password="SomePassword!2026", first_name="I", last_name="G"
        )

        self.assertFalse(admin.has_usable_password())
        self.assertFalse(admin.check_password("SomePassword!2026"))

    def test_the_migration_gives_every_row_a_distinct_marker(self):
        """
        The defect this exists to catch: ``.update(password=make_password(None))``
        writes **one** generated value to every row.

        Django derives a session's ``_auth_user_hash`` from the ``password`` column, and
        the session table is shared across schemas. Identical passwords therefore mean
        identical session hashes, so a session for user 5 at one church would validate
        as user 5 at another — the exact cross-tenant hole the signed tenant cookie is
        designed not to open. Calling the migration function directly is the only way to
        reach it: in tests the schema is built fresh, so it otherwise runs on no rows.
        """
        import importlib

        module = importlib.import_module(
            "apps.accounts.migrations.0002_login_links_no_passwords"
        )

        for i in range(3):
            self.make_admin(email=f"row{i}@church.ca")

        module.make_every_password_unusable(_AppsShim(), None)

        stored = list(User.objects.values_list("password", flat=True))
        self.assertEqual(len(stored), 3)
        for value in stored:
            self.assertTrue(value.startswith("!"), value[:8])
        self.assertEqual(len(set(stored)), 3, "every row got the same unusable password")


class _AppsShim:
    """Stands in for the migration's historical app registry."""

    @staticmethod
    def get_model(app_label, model_name):
        return User



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_request(user=None):
    """
    A minimal request object for the WebAuthn service.

    The service needs a session (to key challenges), ``is_secure()`` and ``get_host()``.
    Building one by hand keeps these tests at the service layer rather than routing every
    ceremony through the client.
    """
    from django.contrib.sessions.backends.db import SessionStore
    from django.test import RequestFactory

    request = RequestFactory().post("/")
    request.session = SessionStore()
    request.session.create()
    request.user = user
    return request


def _register(user, credential_id: bytes, label: str = "") -> Passkey:
    """Register a passkey with the WebAuthn verification stubbed out."""
    request = _fake_request(user)
    webauthn_service.begin_registration(request, user)

    verified = mock.Mock(
        credential_id=credential_id,
        credential_public_key=b"public-key-" + credential_id,
        sign_count=0,
    )
    with mock.patch.object(
        webauthn_service, "verify_registration_response", return_value=verified
    ):
        return webauthn_service.finish_registration(request, user, "{}", label=label)
