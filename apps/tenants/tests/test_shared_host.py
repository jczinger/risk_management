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
RECOVER_URL = "/accounts/recover/"


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
            self.give_passkey(user)
            client.force_login(user)
        client.cookies[TENANT_COOKIE_NAME] = sign_schema_name(tenant.schema_name)
        return client

    def link_for(self, tenant: Tenant) -> str:
        """A fresh sign-in link for a church's admin."""
        from apps.accounts.links import issue_link
        from apps.accounts.models import LinkPurpose

        with tenant_context(tenant):
            user = get_user_model().objects.get(email_index__isnull=False)
            _, url = issue_link(user, LinkPurpose.RECOVERY)
        return url

    @staticmethod
    def cookie_value(response) -> str | None:
        morsel = response.cookies.get(TENANT_COOKIE_NAME)
        return None if morsel is None else morsel.value


class AddressRoutingTests(SharedHostTestCase):
    """
    The address decides the church.

    It used to do so through the password form. Now it does so twice over: the recovery
    form finds every schema holding an address, and the link it sends carries its schema
    in the signed payload. Consuming one is what sets the cookie.
    """

    def test_a_link_pins_the_browser_to_its_own_church(self):
        response = self.anon().get(self.link_for(self.alpha))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.cookie_value(response), sign_schema_name("alpha"))

    def test_two_links_pin_to_two_different_churches(self):
        first = self.anon().get(self.link_for(self.alpha))
        second = self.anon().get(self.link_for(self.beta))

        self.assertEqual(self.cookie_value(first), sign_schema_name("alpha"))
        self.assertEqual(self.cookie_value(second), sign_schema_name("beta"))
        self.assertNotEqual(self.cookie_value(first), self.cookie_value(second))

    def test_the_super_admins_link_lands_in_the_console_with_no_church_cookie(self):
        from apps.accounts.links import issue_link
        from apps.accounts.models import LinkPurpose

        with schema_context(get_public_schema_name()):
            _, url = issue_link(self.operator, LinkPurpose.RECOVERY)

        response = self.anon().get(url)

        self.assertEqual(response.status_code, 302)
        # Cleared rather than set: the console *is* the no-cookie state, so a stale
        # church cookie must not survive the operator signing in.
        self.assertIn(self.cookie_value(response), (None, ""))

    def test_a_stale_church_cookie_is_cleared_by_the_operators_link(self):
        from apps.accounts.links import issue_link
        from apps.accounts.models import LinkPurpose

        with schema_context(get_public_schema_name()):
            _, url = issue_link(self.operator, LinkPurpose.RECOVERY)

        client = self.anon()
        client.cookies[TENANT_COOKIE_NAME] = sign_schema_name("alpha")
        response = client.get(url)

        self.assertEqual(self.cookie_value(response), "")

    def test_requesting_a_link_for_an_unknown_address_sets_no_cookie(self):
        response = self.anon().post(RECOVER_URL, {"email": "nobody@nowhere.ca"})

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.cookie_value(response))

    def test_the_recovery_form_does_not_reveal_that_an_address_exists_at_a_church(self):
        """
        The enumeration guarantee, carried over from the password form. This form is
        reachable by anyone, so a distinct "no such account" would map out who
        administers which church.
        """
        known = self.anon().post(RECOVER_URL, {"email": "admin@alpha.ca"})
        unknown = self.anon().post(RECOVER_URL, {"email": "nobody@nowhere.ca"})

        self.assertEqual(known.status_code, unknown.status_code)
        self.assertEqual(known.content, unknown.content)

    def test_an_address_at_a_suspended_church_gets_no_link(self):
        from apps.accounts.models import LinkPurpose, LoginLink

        Tenant.objects.filter(pk=self.beta.pk).update(is_active=False)

        response = self.anon().post(RECOVER_URL, {"email": "admin@beta.ca"})

        self.assertEqual(response.status_code, 200)
        with tenant_context(self.beta):
            # Filtered by purpose: provisioning already minted an invite for this admin,
            # so a bare exists() would only be measuring the fixture.
            self.assertFalse(LoginLink.objects.filter(purpose=LinkPurpose.RECOVERY).exists())

    def test_a_deactivated_admin_gets_no_link(self):
        from apps.accounts.models import LinkPurpose, LoginLink

        with tenant_context(self.alpha):
            get_user_model().objects.update(is_active=False)

        response = self.anon().post(RECOVER_URL, {"email": "admin@alpha.ca"})

        self.assertEqual(response.status_code, 200)
        with tenant_context(self.alpha):
            self.assertFalse(LoginLink.objects.filter(purpose=LinkPurpose.RECOVERY).exists())


class CookieIntegrityTests(SharedHostTestCase):
    """The cookie selects a schema. It must not be able to grant one."""

    def test_the_cookie_is_signed_rather_than_a_bare_schema_name(self):
        response = self.anon().get(self.link_for(self.alpha))

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

        This is no longer the limitation it was. The password form had to *pick* one of
        these and picked the first, leaving the other account quietly unreachable;
        recovery issues a link into each, so both remain usable.
        """
        with tenant_context(self.beta):
            get_user_model().objects.create_user(
                email="admin@alpha.ca", first_name="Also", last_name="Alex"
            )

        targets = find_login_targets("admin@alpha.ca")

        self.assertEqual([t.schema_name for t in targets], ["alpha", "beta"])

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


class PreSignInDisclosureTests(SharedHostTestCase):
    """
    A signed-out visitor must not be told which church this browser belongs to.

    The tenant cookie outlives the session, so someone returning to the sign-in page —
    or picking up a shared machine — still resolves to a church. The schema stays bound
    (the second-factor step needs it), but nothing on the page may name the church.
    """

    def pinned_to_alpha(self) -> Client:
        """Anonymous, but carrying a valid cookie for Alpha Church."""
        client = self.anon()
        client.cookies[TENANT_COOKIE_NAME] = sign_schema_name("alpha")
        return client

    def test_the_sign_in_page_does_not_name_the_church(self):
        response = self.pinned_to_alpha().get(LOGIN_URL)

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Alpha Church")

    def test_the_browser_tab_title_does_not_name_the_church(self):
        """The <title> is the easy one to miss — it is not visible in the page body."""
        html = self.pinned_to_alpha().get(LOGIN_URL).content.decode()
        title = html.split("<title>", 1)[1].split("</title>", 1)[0]

        self.assertNotIn("Alpha", title)

    def test_the_recovery_pages_do_not_name_the_church(self):
        client = self.pinned_to_alpha()

        for url in (RECOVER_URL, "/accounts/link/rubbish/"):
            with self.subTest(url=url):
                response = client.get(url)
                self.assertNotContains(response, "Alpha Church", status_code=response.status_code)

    def test_asking_for_a_link_does_not_name_the_church(self):
        client = self.pinned_to_alpha()

        response = client.post(RECOVER_URL, {"email": "admin@alpha.ca"})

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Alpha Church")

    def test_the_church_appears_once_signed_in(self):
        """The other half of the rule: suppressed before sign-in, shown after."""
        response = self.signed_in_at(self.alpha).get("/")

        self.assertContains(response, "Alpha Church")

    def test_signing_out_stops_showing_the_church_again(self):
        client = self.signed_in_at(self.alpha)
        self.assertContains(client.get("/"), "Alpha Church")

        client.post("/accounts/logout/")

        self.assertNotContains(client.get(LOGIN_URL), "Alpha Church")


class AuditOutsideATenantTests(SharedHostTestCase):
    """
    The audit trail is a tenant table, and sign-in happens before a tenant is known.

    Before shared hosting this only bit the operator's console; now every refused
    sign-in link on the shared page goes through the public schema, so recording has to
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

    def test_a_refused_link_on_the_shared_page_does_not_error(self):
        """
        The live path to this: ``link_consume`` audits a failure while still bound to
        ``public``, because a bad payload never reveals which church to bind to.
        """
        response = self.anon().get("/accounts/link/not-a-real-payload/")

        self.assertEqual(response.status_code, 400)

    def test_asking_for_a_link_on_the_shared_page_does_not_error(self):
        response = self.anon().post(RECOVER_URL, {"email": "nobody@nowhere.ca"})

        self.assertEqual(response.status_code, 200)


class SubdomainStillWorksTests(SharedHostTestCase):
    """Adding shared hosting must not break the per-church hostnames."""

    def test_a_church_hostname_still_resolves_without_any_cookie(self):
        client = Client(HTTP_HOST="alpha.testserver")
        with tenant_context(self.alpha):
            user = get_user_model().objects.get(email_index__isnull=False)
            self.give_passkey(user)
            client.force_login(user)

        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Alpha Church")

    def test_a_link_used_on_a_church_hostname_still_sets_its_cookie(self):
        """
        Harmless, and simpler than suppressing it. The cookie is host-only, so one set
        on ``alpha.testserver`` is never sent to the shared address in the first place.
        """
        response = Client(HTTP_HOST="alpha.testserver").get(self.link_for(self.alpha))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.cookie_value(response), sign_schema_name("alpha"))

    def test_an_unknown_hostname_is_still_refused(self):
        response = Client(HTTP_HOST="stray.testserver").get("/")

        self.assertEqual(response.status_code, 404)
