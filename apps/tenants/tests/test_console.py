"""
Super-admin console tests.

The console is the operator's whole interface, so the flows through it deserve the same
attention as the service layer underneath: onboarding a church through the form, the one-time
key display, settings changes, key re-import, and the guard that keeps church admins out.

``TransactionTestCase`` because provisioning creates schemas with DDL.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import Client, override_settings
from django.urls import reverse
from django_tenants.utils import get_public_schema_name, schema_context, tenant_context

from apps.core.crypto import encode_key, generate_dek, key_fingerprint, wrap_dek
from apps.core.keys import forget_cached_keys
from apps.tenants.models import DocumentMode, Domain, Tenant
from apps.tenants.tests.test_isolation import ProvisioningTestCase

PLATFORM_HOST = "platform.testserver"

#: The console lives in the public URLconf, while ROOT_URLCONF is the tenant one. Requests
#: are routed correctly at runtime — django-tenants sets request.urlconf per request — but
#: reverse() outside a request has to be told which URLconf to look in.
CONSOLE_URLCONF = "config.urls_public"


def console_url(name: str, *args) -> str:
    """Reverse a super-admin console URL."""
    return reverse(name, args=args, urlconf=CONSOLE_URLCONF)


class ConsoleTestCase(ProvisioningTestCase):
    """A public-schema tenant row, a hostname for it, and a signed-in super-admin."""

    def setUp(self):
        super().setUp()
        public = get_public_schema_name()

        self.platform = Tenant.objects.filter(schema_name=public).first()
        if self.platform is None:
            self.platform = Tenant(schema_name=public, name="VMS Platform")
            dek = generate_dek()
            self.platform.dek_wrapped = wrap_dek(dek)
            self.platform.dek_fingerprint = key_fingerprint(dek)
            self.platform.auto_create_schema = False
            self.platform.save()
        elif not self.platform.dek_wrapped:
            dek = generate_dek()
            self.platform.dek_wrapped = wrap_dek(dek)
            self.platform.dek_fingerprint = key_fingerprint(dek)
            self.platform.save(update_fields=["dek_wrapped", "dek_fingerprint"])

        forget_cached_keys()
        Domain.objects.get_or_create(
            domain=PLATFORM_HOST, defaults={"tenant": self.platform, "is_primary": True}
        )

        with schema_context(public):
            self.operator = get_user_model().objects.create_superuser(
                email="operator@platform.ca",
                password="OperatorPass!2026",
                first_name="Platform",
                last_name="Operator",
            )

        self.client = Client(HTTP_HOST=PLATFORM_HOST)
        with schema_context(public):
            self.client.force_login(self.operator)

    def tearDown(self):
        # Keep the shared public-schema fixtures from leaking between tests.
        with schema_context(get_public_schema_name()):
            get_user_model().objects.filter(email_index__isnull=False).delete()
        Domain.objects.filter(domain=PLATFORM_HOST).delete()
        super().tearDown()

    def _drop_test_schemas(self):
        """Never drop the public row; ProvisioningTestCase's version would try."""
        for tenant in list(Tenant.objects.exclude(schema_name=get_public_schema_name())):
            schema = tenant.schema_name
            Domain.objects.filter(tenant=tenant).delete()
            Tenant.objects.filter(pk=tenant.pk).delete()
            with connection.cursor() as cursor:
                cursor.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


class AccessControlTests(ConsoleTestCase):
    """Only the platform super-admin gets in."""

    def test_the_operator_can_reach_the_console(self):
        response = self.client.get(console_url("tenants:church_list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Churches")

    def test_an_anonymous_visitor_is_redirected(self):
        response = Client(HTTP_HOST=PLATFORM_HOST).get(console_url("tenants:church_list"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/accounts/login/", response["Location"])

    def test_a_non_superuser_in_the_public_schema_is_refused(self):
        with schema_context(get_public_schema_name()):
            ordinary = get_user_model().objects.create_user(
                email="ordinary@platform.ca", password="OrdinaryPass!2026"
            )
            client = Client(HTTP_HOST=PLATFORM_HOST)
            client.force_login(ordinary)

        response = client.get(console_url("tenants:church_list"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/accounts/login/", response["Location"])


class OnboardingThroughTheConsoleTests(ConsoleTestCase):
    """Provisioning a church through the form, not the CLI."""

    def _form_data(self, **overrides):
        data = {
            "name": "Console Church",
            "schema_name": "consolech",
            "domain_name": "consolech.testserver",
            "document_mode": DocumentMode.STORE,
            "reminder_lead_days": "60,30,7",
            "contact_name": "Church Contact",
            "contact_email": "contact@consolechurch.ca",
            "admin_first_name": "Sam",
            "admin_last_name": "Lee",
            "admin_email": "sam@consolechurch.ca",
            "admin_password": "",
            "seed_template": "on",
        }
        data.update(overrides)
        return data

    def test_the_form_renders(self):
        response = self.client.get(console_url("tenants:church_create"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Onboard a church")
        self.assertContains(response, "encryption key once")

    def test_provisioning_through_the_form_creates_everything(self):
        response = self.client.post(console_url("tenants:church_create"), self._form_data())
        self.assertEqual(response.status_code, 302)

        church = Tenant.objects.get(schema_name="consolech")
        self.assertEqual(church.name, "Console Church")
        self.assertEqual(church.document_mode, DocumentMode.STORE)
        self.assertTrue(church.dek_wrapped)
        self.assertTrue(church.key_backup_pending)

        with tenant_context(church):
            from apps.accounts.models import User
            from apps.requirements.models import RequirementDefinition

            self.assertEqual(User.objects.count(), 1)
            self.assertEqual(RequirementDefinition.objects.count(), 14)

        self.assertRedirects(
            response,
            console_url("tenants:church_key_shown", church.pk),
            fetch_redirect_response=False,
        )

    def test_the_key_is_shown_once_then_not_again(self):
        self.client.post(console_url("tenants:church_create"), self._form_data())
        church = Tenant.objects.get(schema_name="consolech")

        first = self.client.get(console_url("tenants:church_key_shown", church.pk))
        self.assertEqual(first.status_code, 200)
        shown_key = first.context["dek_b64"]
        self.assertContains(first, shown_key)
        self.assertContains(first, church.dek_fingerprint)

        # Second visit: the session stash is gone, so it redirects instead of re-displaying.
        second = self.client.get(console_url("tenants:church_key_shown", church.pk))
        self.assertEqual(second.status_code, 302)
        self.assertNotIn(shown_key.encode(), second.content)

    def test_the_key_is_not_passed_through_the_url(self):
        """It must not land in a proxy log or the browser's history."""
        response = self.client.post(console_url("tenants:church_create"), self._form_data())
        church = Tenant.objects.get(schema_name="consolech")

        self.assertNotIn("dek", response["Location"])
        self.assertEqual(response["Location"], console_url("tenants:church_key_shown", church.pk))

    def test_the_hostname_defaults_from_the_short_code(self):
        from django.conf import settings

        self.client.post(console_url("tenants:church_create"), self._form_data(domain_name=""))
        church = Tenant.objects.get(schema_name="consolech")

        self.assertEqual(
            church.primary_domain.domain, f"consolech.{settings.VMS_BASE_DOMAIN}"
        )

    def test_a_duplicate_short_code_is_rejected_by_the_form(self):
        self.client.post(console_url("tenants:church_create"), self._form_data())
        response = self.client.post(
            console_url("tenants:church_create"),
            self._form_data(domain_name="other.testserver"),
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already uses this short code")
        self.assertEqual(Tenant.objects.filter(schema_name="consolech").count(), 1)

    def test_a_duplicate_hostname_is_rejected_by_the_form(self):
        self.client.post(console_url("tenants:church_create"), self._form_data())
        response = self.client.post(
            console_url("tenants:church_create"),
            self._form_data(schema_name="another", domain_name="consolech.testserver"),
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already routes to another church")

    def test_a_reserved_short_code_is_rejected(self):
        response = self.client.post(
            console_url("tenants:church_create"), self._form_data(schema_name="admin")
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "reserved")

    # The suite runs with validators off for speed; this restores the production set, because
    # "a weak temporary password is refused" is a real behaviour worth locking down.
    @override_settings(
        AUTH_PASSWORD_VALIDATORS=[
            {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
             "OPTIONS": {"min_length": 12}},
            {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
            {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
        ]
    )
    def test_a_weak_admin_password_is_rejected(self):
        for weak in ("password", "short", "123456789012"):
            with self.subTest(password=weak):
                response = self.client.post(
                    console_url("tenants:church_create"),
                    self._form_data(admin_password=weak),
                )
                self.assertEqual(response.status_code, 200)
                self.assertFalse(Tenant.objects.filter(schema_name="consolech").exists())

    def test_the_production_settings_configure_password_validators(self):
        """Guards the settings themselves, since the test settings deliberately empty them."""
        from config.settings import base

        names = {v["NAME"].rsplit(".", 1)[-1] for v in base.AUTH_PASSWORD_VALIDATORS}
        self.assertIn("MinimumLengthValidator", names)
        self.assertIn("CommonPasswordValidator", names)
        self.assertIn("NumericPasswordValidator", names)

    def test_bad_reminder_lead_times_are_rejected(self):
        for value in ("sixty", "60,60", "-5", "400"):
            with self.subTest(value=value):
                response = self.client.post(
                    console_url("tenants:church_create"),
                    self._form_data(reminder_lead_days=value),
                )
                self.assertEqual(response.status_code, 200)
                self.assertFalse(Tenant.objects.filter(schema_name="consolech").exists())

    def test_seeding_can_be_declined(self):
        data = self._form_data()
        data.pop("seed_template")
        self.client.post(console_url("tenants:church_create"), data)

        church = Tenant.objects.get(schema_name="consolech")
        with tenant_context(church):
            from apps.requirements.models import RequirementDefinition

            self.assertEqual(RequirementDefinition.objects.count(), 0)


class ChurchManagementTests(ConsoleTestCase):
    """Viewing and adjusting a church after onboarding."""

    def setUp(self):
        super().setUp()
        from apps.tenants.services import provision_church

        self.result = provision_church(
            name="Managed Church",
            schema_name="managedch",
            domain_name="managedch.testserver",
            admin_email="admin@managed.ca",
            admin_password="ManagedPass!2026",
        )
        self.church = self.result.tenant

    def test_the_list_shows_the_church_and_flags_a_pending_key_backup(self):
        response = self.client.get(console_url("tenants:church_list"))

        self.assertContains(response, "Managed Church")
        self.assertContains(response, "managedch")
        self.assertContains(response, "not yet backed up their encryption key")

    def test_the_detail_page_shows_the_registry_and_the_key_fingerprint(self):
        response = self.client.get(console_url("tenants:church_detail", self.church.pk))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Managed Church")
        self.assertContains(response, self.church.dek_fingerprint)
        self.assertContains(response, "export_tenant_key")
        # The raw key must never appear here.
        self.assertNotContains(response, self.result.dek_b64)

    def test_the_detail_page_says_the_console_does_not_browse_church_data(self):
        response = self.client.get(console_url("tenants:church_detail", self.church.pk))
        self.assertContains(response, "does not browse")

    def test_settings_can_be_changed(self):
        response = self.client.post(
            console_url("tenants:church_settings", self.church.pk),
            {
                "name": "Managed Church (renamed)",
                "contact_name": "New Contact",
                "contact_email": "new@managed.ca",
                "document_mode": DocumentMode.TRACK,
                "reminder_lead_days": "90,30",
                "notifications_enabled": "on",
                "is_active": "on",
                "notes": "Operator note",
            },
        )
        self.assertEqual(response.status_code, 302)

        self.church.refresh_from_db()
        self.assertEqual(self.church.name, "Managed Church (renamed)")
        self.assertEqual(self.church.document_mode, DocumentMode.TRACK)
        self.assertEqual(self.church.lead_days, [90, 30])

    def test_a_document_mode_change_is_audited_in_the_churchs_own_trail(self):
        from apps.core.models import AuditAction, AuditEvent

        self.client.post(
            console_url("tenants:church_settings", self.church.pk),
            {
                "name": "Managed Church",
                "contact_name": "",
                "contact_email": "",
                "document_mode": DocumentMode.LINK,
                "reminder_lead_days": "60,30,7",
                "notifications_enabled": "on",
                "is_active": "on",
                "notes": "",
            },
        )

        with tenant_context(self.church):
            event = AuditEvent.objects.filter(
                action=AuditAction.UPDATE, entity_type="Church"
            ).first()
            self.assertIsNotNone(event)
            self.assertIn("link", event.summary)

    def test_a_church_can_be_deactivated_without_touching_its_data(self):
        self.client.post(
            console_url("tenants:church_settings", self.church.pk),
            {
                "name": "Managed Church",
                "contact_name": "",
                "contact_email": "",
                "document_mode": DocumentMode.STORE,
                "reminder_lead_days": "60,30,7",
                "notifications_enabled": "on",
                "notes": "",
            },
        )

        self.church.refresh_from_db()
        self.assertFalse(self.church.is_active)

        # Its schema and records are untouched.
        with tenant_context(self.church):
            from apps.requirements.models import RequirementDefinition

            self.assertEqual(RequirementDefinition.objects.count(), 14)

    def test_the_console_is_not_reachable_from_a_church_hostname(self):
        """
        The console lives in the public schema. A request on a church's hostname routes to the
        tenant URLconf, where these paths do not exist.
        """
        client = Client(HTTP_HOST="managedch.testserver")
        response = client.get("/churches/new/")
        self.assertEqual(response.status_code, 404)


class KeyRestoreTests(ConsoleTestCase):
    """Break-glass key re-import through the console."""

    def setUp(self):
        super().setUp()
        from apps.tenants.services import provision_church

        self.result = provision_church(
            name="Restore Church",
            schema_name="restorech",
            domain_name="restorech.testserver",
            admin_email="admin@restore.ca",
            admin_password="RestorePass!2026",
        )
        self.church = self.result.tenant

    def test_the_correct_key_is_accepted(self):
        original = bytes(self.church.dek_wrapped)

        response = self.client.post(
            console_url("tenants:church_restore_key", self.church.pk),
            {"dek_b64": self.result.dek_b64},
        )
        self.assertEqual(response.status_code, 302)

        self.church.refresh_from_db()
        # Re-wrapped, so the stored bytes change while the key material does not.
        self.assertNotEqual(bytes(self.church.dek_wrapped), original)
        self.assertEqual(self.church.dek_fingerprint, self.result.dek_fingerprint)

    def test_the_wrong_key_is_refused_and_nothing_changes(self):
        original = bytes(self.church.dek_wrapped)

        response = self.client.post(
            console_url("tenants:church_restore_key", self.church.pk),
            {"dek_b64": encode_key(generate_dek())},
        )
        self.assertEqual(response.status_code, 302)

        self.church.refresh_from_db()
        self.assertEqual(bytes(self.church.dek_wrapped), original)

    def test_malformed_key_material_is_refused(self):
        original = bytes(self.church.dek_wrapped)

        self.client.post(
            console_url("tenants:church_restore_key", self.church.pk),
            {"dek_b64": "this is not base64 at all !!"},
        )

        self.church.refresh_from_db()
        self.assertEqual(bytes(self.church.dek_wrapped), original)


class KeyBackupGateTests(ConsoleTestCase):
    """The church-side gate, driven through HTTP."""

    def setUp(self):
        super().setUp()
        from apps.tenants.services import provision_church

        self.result = provision_church(
            name="Gate Church",
            schema_name="gatech",
            domain_name="gatech.testserver",
            admin_email="admin@gate.ca",
            admin_password="GatePass!2026",
        )
        self.church = self.result.tenant

        self.church_client = Client(HTTP_HOST="gatech.testserver")
        with tenant_context(self.church):
            from apps.accounts.models import User

            self.church_client.force_login(User.objects.get())

    def test_confirming_requires_both_the_checkbox_and_the_fingerprint(self):
        # Neither: refused.
        response = self.church_client.post("/key-backup/", {})
        self.assertEqual(response.status_code, 200)
        self.church.refresh_from_db()
        self.assertTrue(self.church.key_backup_pending)

        # Checkbox but a wrong fingerprint: refused.
        response = self.church_client.post(
            "/key-backup/", {"confirmed": "on", "fingerprint_check": "zzzz"}
        )
        self.assertEqual(response.status_code, 200)
        self.church.refresh_from_db()
        self.assertTrue(self.church.key_backup_pending)

    def test_confirming_with_the_right_fingerprint_releases_the_gate(self):
        response = self.church_client.post(
            "/key-backup/",
            {"confirmed": "on", "fingerprint_check": self.church.dek_fingerprint[-4:]},
        )
        self.assertEqual(response.status_code, 302)

        self.church.refresh_from_db()
        self.assertFalse(self.church.key_backup_pending)
        self.assertIsNotNone(self.church.key_backup_confirmed_at)
        self.assertTrue(self.church.key_backup_confirmed_by)

    def test_the_confirmation_is_audited(self):
        from apps.core.models import AuditAction, AuditEvent

        self.church_client.post(
            "/key-backup/",
            {"confirmed": "on", "fingerprint_check": self.church.dek_fingerprint[-4:]},
        )

        with tenant_context(self.church):
            event = AuditEvent.objects.filter(action=AuditAction.KEY_BACKUP).first()
            self.assertIsNotNone(event)
            self.assertIn("confirmed", event.summary.lower())

    def test_the_key_can_be_downloaded_as_a_file(self):
        response = self.church_client.get("/key-backup/download/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain; charset=utf-8")
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertIn("gatech", response["Content-Disposition"])

        body = response.content.decode()
        self.assertIn(self.result.dek_b64, body)
        self.assertIn(self.church.dek_fingerprint, body)
        self.assertIn("KEEP THIS SAFE AND OFFLINE", body)
        # Never cached anywhere.
        self.assertIn("no-store", response["Cache-Control"])

    def test_the_gate_does_not_block_signing_out(self):
        response = self.church_client.post("/accounts/logout/")
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("/key-backup/", response["Location"])

    def test_visiting_the_gate_after_confirming_redirects_away(self):
        self.church.confirm_key_backup(by="tester")
        response = self.church_client.get("/key-backup/")
        self.assertEqual(response.status_code, 302)
