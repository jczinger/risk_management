"""
Authentication tests (Build Spec §1, §2, §10).

Acceptance criteria covered:

* "Admin logs in with a passkey; fallback password+TOTP works; passwordless-only account
  possible."

The passkey ceremonies are exercised through their service layer with the WebAuthn
verification stubbed, because a real assertion needs an authenticator to sign a challenge —
there is no way to produce one in-process. What *is* tested for real: challenge issuance,
single use, expiry, credential storage, sign-count handling, the lockout guards, and that a
passkey login does not additionally demand a TOTP code.
"""

from __future__ import annotations

import datetime
import json
from unittest import mock

from django.conf import settings
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from apps.accounts import totp as totp_service
from apps.accounts import webauthn_service
from apps.accounts.models import Passkey, User, WebAuthnChallenge
from apps.core.models import AuditAction, AuditEvent
from apps.core.tests.base import TenantTestCase

PASSWORD = "CorrectHorse!Battery9"


class PasswordAndTOTPTests(TenantTestCase):
    """The fallback path: password alone is never enough."""

    def setUp(self):
        super().setUp()
        self.admin = self.make_admin(email="admin@church.ca", password=PASSWORD)
        self.client_host = {"HTTP_HOST": self.TEST_DOMAIN}

    def _client(self):
        from django.test import Client

        return Client(**self.client_host)

    def test_authenticate_works_through_the_blind_index(self):
        self.assertEqual(authenticate(username="admin@church.ca", password=PASSWORD), self.admin)
        self.assertEqual(authenticate(username="ADMIN@CHURCH.CA", password=PASSWORD), self.admin)
        self.assertIsNone(authenticate(username="admin@church.ca", password="wrong"))
        self.assertIsNone(authenticate(username="nobody@church.ca", password=PASSWORD))

    def test_password_alone_does_not_sign_you_in(self):
        """
        The whole point of the fallback being a fallback. A correct password gets you to the
        second factor, not into the system.
        """
        client = self._client()
        response = client.post(
            reverse("accounts:login"), {"email": "admin@church.ca", "password": PASSWORD}
        )

        self.assertEqual(response.status_code, 302)
        self.assertFalse(response.wsgi_request.user.is_authenticated)
        # No TOTP yet, so enrolment is mandatory before anything else.
        self.assertIn(reverse("accounts:totp_setup_required"), response["Location"])

    def test_totp_enrolment_is_required_then_completes_the_login(self):
        import pyotp

        client = self._client()
        client.post(reverse("accounts:login"), {"email": "admin@church.ca", "password": PASSWORD})

        response = client.get(reverse("accounts:totp_setup_required"))
        self.assertEqual(response.status_code, 200)
        secret = response.context["secret"]
        self.assertTrue(response.context["mandatory"])

        response = client.post(
            reverse("accounts:totp_setup_required"), {"code": pyotp.TOTP(secret).now()}
        )
        self.assertEqual(response.status_code, 302)

        self.admin.refresh_from_db()
        self.assertTrue(self.admin.has_totp)
        self.assertEqual(int(client.session["_auth_user_id"]), self.admin.pk)

    def test_full_password_plus_totp_login(self):
        import pyotp

        secret = totp_service.generate_secret()
        totp_service.confirm_enrolment(self.admin, secret, pyotp.TOTP(secret).now())

        client = self._client()
        response = client.post(
            reverse("accounts:login"), {"email": "admin@church.ca", "password": PASSWORD}
        )
        self.assertIn(reverse("accounts:totp_verify"), response["Location"])
        self.assertNotIn("_auth_user_id", client.session)

        response = client.post(
            reverse("accounts:totp_verify"), {"code": pyotp.TOTP(secret).now()}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(int(client.session["_auth_user_id"]), self.admin.pk)

    def test_signing_in_returns_you_to_the_page_you_were_sent_from(self):
        """
        The ``?next=`` path, which is how anyone reaching a page while signed out
        arrives at the login form.

        Every other test here posts to a bare login URL, so ``next`` was empty and the
        redirect helper short-circuited before it validated anything. That hid a
        ``TypeError`` — ``url_has_allowed_host_and_scheme`` takes ``require_https``, not
        the ``require_secure`` of the long-removed ``is_safe_url()`` — and the result was
        a 500 for anyone who did not navigate to the login page directly.
        """
        import pyotp

        secret = totp_service.generate_secret()
        totp_service.confirm_enrolment(self.admin, secret, pyotp.TOTP(secret).now())

        client = self._client()
        target = reverse("org:volunteer_list")

        response = client.post(
            f"{reverse('accounts:login')}?next={target}",
            {"email": "admin@church.ca", "password": PASSWORD},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn(f"next={target}", response["Location"])

        response = client.post(
            f"{reverse('accounts:totp_verify')}?next={target}",
            {"code": pyotp.TOTP(secret).now()},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], target)
        self.assertEqual(int(client.session["_auth_user_id"]), self.admin.pk)

    def test_next_cannot_be_used_as_an_open_redirect(self):
        """An off-site ``next`` is discarded, not followed."""
        import pyotp

        secret = totp_service.generate_secret()
        totp_service.confirm_enrolment(self.admin, secret, pyotp.TOTP(secret).now())

        for hostile in (
            "https://evil.example.com/",
            "//evil.example.com/",
            "http://evil.example.com/steal",
        ):
            with self.subTest(next=hostile):
                client = self._client()
                client.post(
                    reverse("accounts:login"),
                    {"email": "admin@church.ca", "password": PASSWORD, "next": hostile},
                )
                response = client.post(
                    reverse("accounts:totp_verify"),
                    {"code": pyotp.TOTP(secret).now(), "next": hostile},
                )

                self.assertEqual(response.status_code, 302)
                self.assertEqual(response["Location"], settings.LOGIN_REDIRECT_URL)

    def test_a_wrong_totp_code_does_not_sign_you_in(self):
        import pyotp

        secret = totp_service.generate_secret()
        totp_service.confirm_enrolment(self.admin, secret, pyotp.TOTP(secret).now())

        client = self._client()
        client.post(reverse("accounts:login"), {"email": "admin@church.ca", "password": PASSWORD})
        response = client.post(reverse("accounts:totp_verify"), {"code": "000000"})

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", client.session)

    def test_the_totp_step_cannot_be_reached_without_the_password_step(self):
        """Guards against skipping straight to the second factor."""
        client = self._client()
        response = client.get(reverse("accounts:totp_verify"))
        self.assertRedirects(response, reverse("accounts:login"), fetch_redirect_response=False)

    def test_the_pending_login_expires(self):
        import pyotp

        secret = totp_service.generate_secret()
        totp_service.confirm_enrolment(self.admin, secret, pyotp.TOTP(secret).now())

        client = self._client()
        client.post(reverse("accounts:login"), {"email": "admin@church.ca", "password": PASSWORD})

        # Age the pending marker past the timeout.
        session = client.session
        session[totp_service.PENDING_STARTED_KEY] = (
            timezone.now() - datetime.timedelta(seconds=totp_service.PENDING_TIMEOUT_SECONDS + 10)
        ).isoformat()
        session.save()

        response = client.post(reverse("accounts:totp_verify"), {"code": pyotp.TOTP(secret).now()})
        self.assertRedirects(response, reverse("accounts:login"), fetch_redirect_response=False)
        self.assertNotIn("_auth_user_id", client.session)

    def test_totp_accepts_the_adjacent_time_step(self):
        import pyotp

        secret = totp_service.generate_secret()
        totp = pyotp.TOTP(secret)
        previous = totp.at(timezone.now() - datetime.timedelta(seconds=30))
        self.assertTrue(totp_service.verify_code(secret, previous))

    def test_totp_rejects_a_far_off_code(self):
        import pyotp

        secret = totp_service.generate_secret()
        old = pyotp.TOTP(secret).at(timezone.now() - datetime.timedelta(minutes=10))
        self.assertFalse(totp_service.verify_code(secret, old))

    def test_totp_secret_is_encrypted_at_rest(self):
        import pyotp
        from django.db import connection

        secret = totp_service.generate_secret()
        totp_service.confirm_enrolment(self.admin, secret, pyotp.TOTP(secret).now())

        with connection.cursor() as cursor:
            cursor.execute("SELECT totp_secret FROM accounts_user WHERE id = %s", [self.admin.pk])
            (stored,) = cursor.fetchone()

        self.assertTrue(stored.startswith("v1."))
        self.assertNotIn(secret, stored)

    def test_the_error_message_does_not_reveal_whether_an_account_exists(self):
        """
        A different message for "no such user" would let anyone enumerate a church's staff.
        """
        client = self._client()
        no_user = client.post(
            reverse("accounts:login"), {"email": "nobody@church.ca", "password": PASSWORD}
        )
        wrong_password = client.post(
            reverse("accounts:login"), {"email": "admin@church.ca", "password": "wrong-password"}
        )

        self.assertContains(no_user, "was not recognised")
        self.assertContains(wrong_password, "was not recognised")

    def test_a_deactivated_admin_cannot_sign_in(self):
        """
        And gets the same generic message as any other failure — a distinct "deactivated"
        reply would confirm to a guesser that the address is real.
        """
        self.admin.is_active = False
        self.admin.save()

        client = self._client()
        response = client.post(
            reverse("accounts:login"), {"email": "admin@church.ca", "password": PASSWORD}
        )
        self.assertContains(response, "was not recognised")
        self.assertNotIn("_auth_user_id", client.session)

    def test_a_failed_attempt_is_audited_without_recording_the_address_tried(self):
        client = self._client()
        client.post(
            reverse("accounts:login"), {"email": "someone@else.ca", "password": "wrong"}
        )

        event = AuditEvent.objects.filter(action=AuditAction.LOGIN_FAILED).first()
        self.assertIsNotNone(event)
        self.assertNotIn("someone@else.ca", json.dumps(event.detail_data))
        self.assertNotIn("someone@else.ca", event.summary)

    def test_a_successful_login_is_audited(self):
        import pyotp

        secret = totp_service.generate_secret()
        totp_service.confirm_enrolment(self.admin, secret, pyotp.TOTP(secret).now())

        client = self._client()
        client.post(reverse("accounts:login"), {"email": "admin@church.ca", "password": PASSWORD})
        client.post(reverse("accounts:totp_verify"), {"code": pyotp.TOTP(secret).now()})

        event = AuditEvent.objects.filter(action=AuditAction.LOGIN).first()
        self.assertIsNotNone(event)
        self.assertIn("authenticator", event.summary)

        self.admin.refresh_from_db()
        self.assertIsNotNone(self.admin.last_login_at)

    # The suite hashes with MD5 for speed, so this one test restores the production
    # hasher — Argon2 is a PRD §5 requirement, not an implementation detail.
    @override_settings(
        PASSWORD_HASHERS=["django.contrib.auth.hashers.Argon2PasswordHasher"]
    )
    def test_passwords_are_hashed_with_argon2(self):
        from django.db import connection

        admin = self.make_admin(email="argon@church.ca", password=PASSWORD)

        with connection.cursor() as cursor:
            cursor.execute("SELECT password FROM accounts_user WHERE id = %s", [admin.pk])
            (stored,) = cursor.fetchone()

        self.assertTrue(stored.startswith("argon2$argon2id$"))
        self.assertNotIn(PASSWORD, stored)

    def test_argon2_is_the_configured_production_hasher(self):
        """Guards the settings themselves, which the test settings deliberately override."""
        from config.settings import base

        self.assertEqual(
            base.PASSWORD_HASHERS[0], "django.contrib.auth.hashers.Argon2PasswordHasher"
        )


class PasswordlessAccountTests(TenantTestCase):
    """Build Spec §10: a passwordless-only account must be possible."""

    def test_an_account_can_exist_with_no_usable_password(self):
        admin = User.objects.create_user(
            email="passkeyonly@church.ca", password=None, first_name="P", last_name="K"
        )

        self.assertFalse(admin.has_usable_password())
        self.assertTrue(admin.is_passwordless)
        self.assertIsNone(authenticate(username="passkeyonly@church.ca", password=""))

    def test_a_passwordless_account_cannot_be_signed_into_with_a_password(self):
        User.objects.create_user(
            email="passkeyonly@church.ca", password=None, first_name="P", last_name="K"
        )
        from django.test import Client

        client = Client(HTTP_HOST=self.TEST_DOMAIN)
        response = client.post(
            reverse("accounts:login"),
            {"email": "passkeyonly@church.ca", "password": "anything-at-all"},
        )

        self.assertContains(response, "was not recognised")
        self.assertNotIn("_auth_user_id", client.session)


class PasskeyRegistrationTests(TenantTestCase):
    """WebAuthn registration, with the cryptographic verification stubbed."""

    def setUp(self):
        super().setUp()
        self.admin = self.make_admin(email="admin@church.ca", password=PASSWORD)
        self.client = self.signed_in_client(self.admin)

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
        self.admin = self.make_admin(email="admin@church.ca", password=PASSWORD)
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

    def test_a_successful_assertion_signs_the_user_in_with_no_totp_step(self):
        """
        A passkey already proves possession of an unlocked device, so it is not additionally
        prompted for a code — that is the point of it being the primary method.
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
        self.assertNotIn(totp_service.PENDING_SESSION_KEY, client.session)

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


class LockoutGuardTests(TenantTestCase):
    """Removing your last way in should not be possible by accident."""

    def test_the_last_passkey_cannot_be_removed_without_a_fallback(self):
        admin = User.objects.create_user(
            email="passkeyonly@church.ca", password=None, first_name="P", last_name="K"
        )
        passkey = _register(admin, b"cred-only")

        with self.assertRaises(ValidationError):
            webauthn_service.remove_passkey(admin, passkey.pk)

        passkey.refresh_from_db()
        self.assertTrue(passkey.is_active)

    def test_the_last_passkey_can_be_removed_when_password_and_totp_exist(self):
        import pyotp

        admin = self.make_admin(email="both@church.ca", password=PASSWORD)
        secret = totp_service.generate_secret()
        totp_service.confirm_enrolment(admin, secret, pyotp.TOTP(secret).now())
        passkey = _register(admin, b"cred-both")

        webauthn_service.remove_passkey(admin, passkey.pk)
        passkey.refresh_from_db()
        self.assertFalse(passkey.is_active)

    def test_a_passkey_can_always_be_removed_when_another_remains(self):
        admin = User.objects.create_user(
            email="two@church.ca", password=None, first_name="T", last_name="W"
        )
        first = _register(admin, b"cred-a")
        _register(admin, b"cred-b")

        webauthn_service.remove_passkey(admin, first.pk)
        first.refresh_from_db()
        self.assertFalse(first.is_active)

    def test_totp_cannot_be_removed_from_a_password_only_account(self):
        import pyotp

        admin = self.make_admin(email="pw@church.ca", password=PASSWORD)
        secret = totp_service.generate_secret()
        totp_service.confirm_enrolment(admin, secret, pyotp.TOTP(secret).now())

        with self.assertRaises(ValidationError):
            totp_service.disable_totp(admin)

    def test_the_last_active_admin_cannot_be_deactivated(self):
        """A church locking itself out entirely is not a state worth allowing."""
        admin = self.make_admin(email="only@church.ca", password=PASSWORD)
        other = self.make_admin(email="other@church.ca", password=PASSWORD)
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
    """Login is rate limited per address and per source (Build Spec §6)."""

    @override_settings(LOGIN_RATELIMIT="3/5m")
    def test_repeated_failures_start_being_refused(self):
        from django.core.cache import cache
        from django.test import Client

        cache.clear()
        self.make_admin(email="admin@church.ca", password=PASSWORD)
        client = Client(HTTP_HOST=self.TEST_DOMAIN)

        limited = False
        for _ in range(12):
            response = client.post(
                reverse("accounts:login"),
                {"email": "admin@church.ca", "password": "wrong-password"},
            )
            if b"Too many sign-in attempts" in response.content:
                limited = True
                break

        self.assertTrue(limited, "expected the login form to start refusing attempts")
        cache.clear()


class AdminManagementTests(TenantTestCase):
    """Adding and retiring a church's administrators."""

    def setUp(self):
        super().setUp()
        self.admin = self.make_admin(email="first@church.ca", password=PASSWORD)
        self.client = self.signed_in_client(self.admin)

    def test_an_admin_can_be_added_passwordless(self):
        response = self.client.post(
            reverse("accounts:admin_invite"),
            {"first_name": "Sam", "last_name": "Lee", "email": "sam@church.ca", "password": ""},
        )
        self.assertEqual(response.status_code, 302)

        added = User.objects.get(email_index__isnull=False, first_name="Sam")
        self.assertTrue(added.is_passwordless)
        self.assertTrue(added.is_active)

    def test_a_duplicate_address_is_refused(self):
        response = self.client.post(
            reverse("accounts:admin_invite"),
            {
                "first_name": "Another",
                "last_name": "Person",
                "email": "FIRST@church.ca",
                "password": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already exists")

    def test_all_admins_have_equal_permissions(self):
        """Build Spec §2: no roles within a church, by design."""
        second = self.make_admin(email="second@church.ca", password=PASSWORD)
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
        second = self.make_admin(email="second@church.ca", password=PASSWORD)
        self.client.post(reverse("accounts:admin_toggle_active", args=[second.pk]))

        second.refresh_from_db()
        self.assertFalse(second.is_active)
        self.assertTrue(User.objects.filter(pk=second.pk).exists())


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
