"""
One hostname, many churches: routing by the address you sign in with.

The original design gave every church its own subdomain, which django-tenants resolves
from the Host header. These tests cover the alternative added afterwards — a single
shared hostname, where sign-in decides the schema and a signed cookie carries the
choice (see :mod:`apps.tenants.routing`).

The security question this file exists to answer is *what stops the cookie from being
a key to any church?* Three tests answer it directly:

* the cookie is signed, so it cannot be forged;
* a valid cookie for a church you have no session in gets you the login page, not data;
* signing out drops it.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import Client
from django_tenants.utils import get_public_schema_name, schema_context, tenant_context

from apps.tenants.models import Tenant
from apps.tenants.routing import (
    TENANT_COOKIE_NAME,
    find_login_targets,
    find_passkey_target,
    sign_schema_name,
)
from apps.tenants.services import provision_church
from apps.tenants.tests.test_console import PLATFORM_HOST, ConsoleTestCase

LOGIN_URL = "/accounts/login/"
PASSWORD = "SharedHostPass!2026"


class SharedHostTestCase(ConsoleTestCase):
    """The platform hostname, plus two churches reachable only through it."""

    def setUp(self):
        super().setUp()
        self.alpha = self._provision("alpha", "Alpha Church")
        self.beta = self._provision("beta", "Beta Church")

    def _provision(self, code: str, name: str) -> Tenant:
        result = provision_church(
            name=name,
            schema_name=code,
            domain_name=f"{code}.testserver",
            admin_email=f"admin@{code}.ca",
            admin_first_name="Alex",
            admin_last_name="Admin",
            admin_password=PASSWORD,
        )
        # Otherwise ForceKeyBackupMiddleware redirects every authenticated request to
        # the key-backup gate, which is a different test's subject.
        result.tenant.confirm_key_backup("test setup")
        return result.tenant

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def anon() -> Client:
        """An unauthenticated browser pointed at the shared hostname."""
        return Client(HTTP_HOST=PLATFORM_HOST)

    def signed_in_at(self, tenant: Tenant) -> Client:
        """A browser holding both a session in ``tenant`` and the cookie naming it."""
        client = self.anon()
        with tenant_context(tenant):
            user = get_user_model().objects.get(email_index__isnull=False)
            client.force_login(user)
        client.cookies[TENANT_COOKIE_NAME] = sign_schema_name(tenant.schema_name)
        return client

    @staticmethod
    def cookie_value(response) -> str | None:
        morsel = response.cookies.get(TENANT_COOKIE_NAME)
        return None if morsel is None else morsel.value


class AddressRoutingTests(SharedHostTestCase):
    """The address decides the church."""

    def test_an_address_routes_to_its_own_church(self):
        response = self.anon().post(
            LOGIN_URL, {"email": "admin@alpha.ca", "password": PASSWORD}
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.cookie_value(response), sign_schema_name("alpha"))

    def test_two_addresses_route_to_two_different_churches(self):
        first = self.anon().post(LOGIN_URL, {"email": "admin@alpha.ca", "password": PASSWORD})
        second = self.anon().post(LOGIN_URL, {"email": "admin@beta.ca", "password": PASSWORD})

        self.assertEqual(self.cookie_value(first), sign_schema_name("alpha"))
        self.assertEqual(self.cookie_value(second), sign_schema_name("beta"))
        self.assertNotEqual(self.cookie_value(first), self.cookie_value(second))

    def test_the_super_admin_lands_in_the_console_with_no_church_cookie(self):
        response = self.anon().post(
            LOGIN_URL, {"email": "operator@platform.ca", "password": "OperatorPass!2026"}
        )

        self.assertEqual(response.status_code, 302)
        # Cleared rather than set: the console *is* the no-cookie state.
        self.assertIn(self.cookie_value(response), (None, ""))

    def test_an_unknown_address_sets_no_cookie(self):
        response = self.anon().post(
            LOGIN_URL, {"email": "nobody@nowhere.ca", "password": PASSWORD}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.cookie_value(response))

    def test_a_wrong_password_is_refused_generically_and_sets_no_cookie(self):
        response = self.anon().post(
            LOGIN_URL, {"email": "admin@alpha.ca", "password": "not the password"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.cookie_value(response))
        self.assertContains(response, "was not recognised")

    def test_the_form_does_not_reveal_that_an_address_exists_at_another_church(self):
        """A wrong password and an unknown address must be indistinguishable."""
        wrong_password = self.anon().post(
            LOGIN_URL, {"email": "admin@alpha.ca", "password": "not the password"}
        )
        unknown_address = self.anon().post(
            LOGIN_URL, {"email": "nobody@nowhere.ca", "password": "not the password"}
        )

        self.assertEqual(wrong_password.status_code, unknown_address.status_code)
        self.assertContains(wrong_password, "was not recognised")
        self.assertContains(unknown_address, "was not recognised")

    def test_an_address_at_a_suspended_church_cannot_sign_in(self):
        Tenant.objects.filter(pk=self.beta.pk).update(is_active=False)

        response = self.anon().post(LOGIN_URL, {"email": "admin@beta.ca", "password": PASSWORD})

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.cookie_value(response))

    def test_a_deactivated_admin_cannot_sign_in(self):
        with tenant_context(self.alpha):
            get_user_model().objects.update(is_active=False)

        response = self.anon().post(LOGIN_URL, {"email": "admin@alpha.ca", "password": PASSWORD})

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.cookie_value(response))


class CookieIntegrityTests(SharedHostTestCase):
    """The cookie selects a schema. It must not be able to grant one."""

    def test_the_cookie_is_signed_rather_than_a_bare_schema_name(self):
        response = self.anon().post(LOGIN_URL, {"email": "admin@alpha.ca", "password": PASSWORD})

        value = self.cookie_value(response)
        self.assertNotEqual(value, "alpha")
        self.assertTrue(value.startswith("alpha:"), value)

    def test_a_forged_cookie_is_ignored_and_cleared(self):
        client = self.anon()
        client.cookies[TENANT_COOKIE_NAME] = "beta"  # unsigned

        response = client.get("/", follow=False)

        # Falls back to the hostname, which resolves to the public console, so an
        # anonymous visitor is sent to sign in rather than into Beta Church.
        self.assertEqual(response.status_code, 302)
        self.assertIn(LOGIN_URL, response["Location"])
        self.assertEqual(self.cookie_value(response), "")

    def test_a_tampered_signature_is_ignored(self):
        client = self.anon()
        client.cookies[TENANT_COOKIE_NAME] = sign_schema_name("alpha")[:-1] + "x"

        response = client.get("/")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.cookie_value(response), "")

    def test_a_valid_cookie_for_a_church_you_have_no_session_in_gives_nothing(self):
        """
        The isolation guarantee, restated for shared hosting.

        Swapping the cookie moves the request to another church's schema — and the
        session that authorises anything does not exist over there, so the visitor
        arrives anonymous. A cookie is a pointer, not a credential.
        """
        client = self.signed_in_at(self.alpha)
        client.cookies[TENANT_COOKIE_NAME] = sign_schema_name("beta")

        response = client.get("/")

        self.assertEqual(response.status_code, 302)
        self.assertIn(LOGIN_URL, response["Location"])

    def test_a_cookie_naming_a_suspended_church_is_dropped(self):
        client = self.signed_in_at(self.alpha)
        Tenant.objects.filter(pk=self.alpha.pk).update(is_active=False)

        response = client.get("/")

        self.assertEqual(self.cookie_value(response), "")

    def test_a_cookie_naming_a_church_that_does_not_exist_is_dropped(self):
        client = self.anon()
        client.cookies[TENANT_COOKIE_NAME] = sign_schema_name("nosuchchurch")

        response = client.get("/")

        self.assertEqual(self.cookie_value(response), "")

    def test_signing_out_drops_the_church_cookie(self):
        client = self.signed_in_at(self.alpha)

        response = client.post("/accounts/logout/")

        self.assertEqual(self.cookie_value(response), "")


class BoundRequestTests(SharedHostTestCase):
    """With a cookie and a matching session, the request really is inside that church."""

    def test_the_church_app_is_served_on_the_shared_hostname(self):
        response = self.signed_in_at(self.alpha).get("/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alpha Church")

    def test_each_browser_sees_only_its_own_church(self):
        alpha_page = self.signed_in_at(self.alpha).get("/")
        beta_page = self.signed_in_at(self.beta).get("/")

        self.assertContains(alpha_page, "Alpha Church")
        self.assertNotContains(alpha_page, "Beta Church")
        self.assertContains(beta_page, "Beta Church")
        self.assertNotContains(beta_page, "Alpha Church")

    def test_volunteers_created_under_one_cookie_are_invisible_under_the_other(self):
        with tenant_context(self.alpha):
            from apps.org.models import Volunteer

            Volunteer.objects.create(first_name="Alpha", last_name="Volunteer")

        beta_page = self.signed_in_at(self.beta).get("/org/volunteers/")

        self.assertEqual(beta_page.status_code, 200)
        self.assertNotContains(beta_page, "Alpha Volunteer")

    def test_the_console_is_still_reachable_without_a_cookie(self):
        response = self.client.get("/")  # ConsoleTestCase signs the operator in

        self.assertEqual(response.status_code, 200)


class LookupTests(SharedHostTestCase):
    """The cross-schema searches underneath the routing."""

    def test_find_login_targets_locates_the_owning_schema(self):
        targets = find_login_targets("admin@beta.ca")

        self.assertEqual([t.schema_name for t in targets], ["beta"])
        self.assertEqual(targets[0].label, "Beta Church")

    def test_find_login_targets_is_case_insensitive(self):
        self.assertEqual(
            [t.schema_name for t in find_login_targets("ADMIN@Beta.CA")],
            ["beta"],
        )

    def test_find_login_targets_finds_the_super_admin_in_public(self):
        targets = find_login_targets("operator@platform.ca")

        self.assertEqual([t.schema_name for t in targets], [get_public_schema_name()])
        self.assertTrue(targets[0].is_public)

    def test_find_login_targets_returns_nothing_for_an_unknown_address(self):
        self.assertEqual(find_login_targets("nobody@nowhere.ca"), [])
        self.assertEqual(find_login_targets(""), [])

    def test_find_login_targets_skips_suspended_churches(self):
        Tenant.objects.filter(pk=self.beta.pk).update(is_active=False)

        self.assertEqual(find_login_targets("admin@beta.ca"), [])

    def test_the_same_address_at_two_churches_resolves_deterministically(self):
        """
        Ordered by church name, so the outcome is stable rather than row-order luck.

        Recorded in BUILD_NOTES.md as a known limitation: one address should belong to
        one church.
        """
        with tenant_context(self.beta):
            get_user_model().objects.create_user(
                email="admin@alpha.ca", password=PASSWORD, first_name="Also", last_name="Alex"
            )

        targets = find_login_targets("admin@alpha.ca")

        self.assertEqual([t.schema_name for t in targets], ["alpha", "beta"])

        response = self.anon().post(LOGIN_URL, {"email": "admin@alpha.ca", "password": PASSWORD})
        self.assertEqual(self.cookie_value(response), sign_schema_name("alpha"))

    def test_the_blind_index_differs_per_schema(self):
        """
        Why the lookup has to visit every schema instead of consulting one index.

        The index key mixes in the schema name specifically so a dump cannot correlate
        one person across churches.
        """
        from apps.core.blind_index import email_index

        with tenant_context(self.alpha):
            in_alpha = email_index("admin@alpha.ca")
        with tenant_context(self.beta):
            in_beta = email_index("admin@alpha.ca")
        with schema_context(get_public_schema_name()):
            in_public = email_index("admin@alpha.ca")

        self.assertEqual(len({in_alpha, in_beta, in_public}), 3)

    def test_find_passkey_target_returns_nothing_for_an_unknown_credential(self):
        self.assertIsNone(find_passkey_target("no-such-credential"))
        self.assertIsNone(find_passkey_target(""))

    def test_find_passkey_target_locates_the_owning_schema(self):
        from apps.accounts.models import Passkey

        with tenant_context(self.beta):
            user = get_user_model().objects.get(email_index__isnull=False)
            Passkey.objects.create(
                user=user, credential_id="cred-in-beta", public_key=b"\x01\x02", sign_count=0
            )

        target = find_passkey_target("cred-in-beta")

        self.assertIsNotNone(target)
        self.assertEqual(target.schema_name, "beta")


class AuditOutsideATenantTests(SharedHostTestCase):
    """
    The audit trail is a tenant table, and sign-in happens before a tenant is known.

    Before shared hosting this only bit the operator's console; now every mistyped
    password on the shared page goes through the public schema, so recording has to
    degrade to a log line instead of raising ``UndefinedTable``.
    """

    def test_recording_in_the_public_schema_is_a_no_op(self):
        from apps.core import audit
        from apps.core.models import AuditAction

        with schema_context(get_public_schema_name()):
            self.assertIsNone(
                audit.record(AuditAction.LOGIN_FAILED, "User", summary="Sign-in attempt failed")
            )

    def test_recording_inside_a_church_still_writes(self):
        from apps.core import audit
        from apps.core.models import AuditAction, AuditEvent

        with tenant_context(self.alpha):
            event = audit.record(AuditAction.LOGIN_FAILED, "User", summary="Attempt")
            self.assertIsNotNone(event)
            self.assertTrue(AuditEvent.objects.filter(pk=event.pk).exists())

    def test_a_failed_sign_in_on_the_shared_page_does_not_error(self):
        response = self.anon().post(LOGIN_URL, {"email": "admin@alpha.ca", "password": "wrong"})

        self.assertEqual(response.status_code, 200)


class SubdomainStillWorksTests(SharedHostTestCase):
    """Adding shared hosting must not break the per-church hostnames."""

    def test_a_church_hostname_still_resolves_without_any_cookie(self):
        client = Client(HTTP_HOST="alpha.testserver")
        with tenant_context(self.alpha):
            client.force_login(get_user_model().objects.get(email_index__isnull=False))

        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alpha Church")

    def test_signing_in_on_a_church_hostname_sets_no_cookie(self):
        response = Client(HTTP_HOST="alpha.testserver").post(
            LOGIN_URL, {"email": "admin@alpha.ca", "password": PASSWORD}
        )

        self.assertEqual(response.status_code, 302)
        self.assertIsNone(self.cookie_value(response))

    def test_an_unknown_hostname_is_still_refused(self):
        response = Client(HTTP_HOST="stray.testserver").get("/")

        self.assertEqual(response.status_code, 404)
