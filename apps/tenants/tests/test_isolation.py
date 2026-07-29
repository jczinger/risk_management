"""
Multi-tenancy tests.

The headline acceptance criterion (Build Spec §10): two churches provisioned, and their
data provably isolated — a cross-schema read must fail rather than quietly return the other
church's volunteers.

These use ``TransactionTestCase`` because provisioning creates schemas with DDL, which does
not survive the transaction rollback a plain ``TestCase`` relies on.
"""

from __future__ import annotations

from django.db import connection
from django.test import TransactionTestCase
from django_tenants.utils import schema_context, tenant_context

from apps.core.crypto import DecryptionError, decode_key, generate_dek, key_fingerprint
from apps.core.keys import forget_cached_keys, override_key
from apps.tenants.models import DocumentMode, Domain, Tenant
from apps.tenants.services import ProvisioningError, provision_church, rotate_key_from_escrow


class ProvisioningTestCase(TransactionTestCase):
    """
    Base for tests that really provision churches.

    ``TransactionTestCase`` rather than ``TestCase``: creating a schema is DDL, and a
    transaction rollback would not undo it cleanly.

    Both hooks force the connection back to ``public``. Creating a tenant is only legal
    from there, and any test that leaves the connection bound to a church — including one
    that fails part-way — would otherwise break every test after it.
    """

    def setUp(self):
        super().setUp()
        connection.set_schema_to_public()
        forget_cached_keys()
        # Rate-limit counters live in LocMemCache, which is per *process*, not per test.
        # Without this a class that posts the recovery form a few times trips its own
        # limit partway through and the failure lands on whichever test ran last —
        # order-dependent, and misleading about which behaviour broke.
        from django.core.cache import cache

        cache.clear()

    def tearDown(self):
        connection.set_schema_to_public()
        forget_cached_keys()
        self._drop_test_schemas()
        super().tearDown()

    @staticmethod
    def _drop_test_schemas():
        """Remove every church created by the test, schema and registry row alike."""
        for tenant in list(Tenant.objects.exclude(schema_name="public")):
            schema = tenant.schema_name
            Domain.objects.filter(tenant=tenant).delete()
            Tenant.objects.filter(pk=tenant.pk).delete()
            with connection.cursor() as cursor:
                cursor.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


class ProvisioningTests(ProvisioningTestCase):
    """Standing up a church end to end."""

    def _provision(self, code="alpha", name="Alpha Church", **extra):
        defaults = {
            "name": name,
            "schema_name": code,
            "domain_name": f"{code}.testserver",
            "admin_email": f"admin@{code}.ca",
            "admin_first_name": "Alex",
            "admin_last_name": "Admin",
        }
        defaults.update(extra)
        return provision_church(**defaults)

    def test_provisioning_creates_schema_key_admin_and_template(self):
        result = self._provision()

        self.assertEqual(result.tenant.schema_name, "alpha")
        self.assertEqual(result.seeded_requirements, 14)
        self.assertTrue(result.dek_b64)
        self.assertEqual(len(decode_key(result.dek_b64)), 32)
        self.assertEqual(result.dek_fingerprint, key_fingerprint(decode_key(result.dek_b64)))

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s", ["alpha"]
            )
            self.assertIsNotNone(cursor.fetchone())

        with tenant_context(result.tenant):
            from apps.accounts.models import User
            from apps.requirements.models import RequirementDefinition

            self.assertEqual(User.objects.count(), 1)
            self.assertEqual(RequirementDefinition.objects.count(), 14)

    def test_raw_key_is_never_stored(self):
        """
        The database holds only the wrapped key. A dump of the registry yields nothing
        usable without PLATFORM_MASTER_KEY.
        """
        result = self._provision()

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT dek_wrapped, dek_fingerprint FROM public.tenants_tenant WHERE id = %s",
                [result.tenant.pk],
            )
            wrapped, fingerprint = cursor.fetchone()

        self.assertNotIn(result.dek_b64.encode(), bytes(wrapped))
        self.assertNotEqual(bytes(wrapped), decode_key(result.dek_b64))
        self.assertEqual(fingerprint, result.dek_fingerprint)

    def test_new_church_starts_with_key_backup_pending(self):
        result = self._provision()
        self.assertTrue(result.tenant.key_backup_pending)
        self.assertIsNone(result.tenant.key_backup_confirmed_at)

    def test_confirming_the_backup_clears_the_gate(self):
        result = self._provision()
        result.tenant.confirm_key_backup(by="Alex Admin")
        result.tenant.refresh_from_db()

        self.assertFalse(result.tenant.key_backup_pending)
        self.assertEqual(result.tenant.key_backup_confirmed_by, "Alex Admin")

    def test_duplicate_short_code_is_refused(self):
        self._provision(code="alpha")
        with self.assertRaises(ProvisioningError):
            self._provision(code="alpha", domain_name="alpha2.testserver")

    def test_duplicate_hostname_is_refused(self):
        self._provision(code="alpha")
        with self.assertRaises(ProvisioningError):
            self._provision(code="beta", domain_name="alpha.testserver")

    def test_reserved_short_code_is_refused(self):
        from django.core.exceptions import ValidationError

        with self.assertRaises(ValidationError):
            self._provision(code="public")

    def test_invalid_short_code_is_refused(self):
        from django.core.exceptions import ValidationError

        for code in ["With Space", "1leading", "a", "has_underscore", "has-dash", "with.dot"]:
            with self.subTest(code=code), self.assertRaises(ValidationError):
                self._provision(code=code, domain_name="whatever.testserver")

    def test_short_code_is_normalised_to_lower_case(self):
        """
        Mixed case is accepted and folded rather than rejected: the code becomes a Postgres
        schema name and a DNS label, both of which are effectively case-insensitive, so
        refusing "FirstOAC" would be pedantry.
        """
        result = self._provision(code="MixedCase", domain_name="mixedcase.testserver")
        self.assertEqual(result.tenant.schema_name, "mixedcase")

    def test_the_first_admin_is_passwordless_and_gets_a_link(self):
        """
        Every account is passwordless now — there is no other kind. What replaces the
        temporary password is a single-use link, minted inside the church's own schema
        so that the schema name baked into it is the right one.
        """
        result = self._provision()

        self.assertIn("/accounts/link/", result.invite_url)

        with tenant_context(result.tenant):
            from apps.accounts.models import LinkPurpose, LoginLink, User

            admin = User.objects.get()
            self.assertFalse(admin.has_usable_password())

            link = LoginLink.objects.get()
            self.assertEqual(link.user, admin)
            self.assertEqual(link.purpose, LinkPurpose.INVITE)
            self.assertIsNone(link.consumed_at)

    def test_seeding_can_be_skipped(self):
        result = self._provision(seed_template=False)
        self.assertEqual(result.seeded_requirements, 0)

        with tenant_context(result.tenant):
            from apps.requirements.models import RequirementDefinition

            self.assertEqual(RequirementDefinition.objects.count(), 0)

    def test_document_mode_is_recorded_per_church(self):
        result = self._provision(document_mode=DocumentMode.TRACK)
        self.assertEqual(result.tenant.document_mode, DocumentMode.TRACK)

    def test_provisioning_failure_leaves_nothing_behind(self):
        """
        Provisioning is one transaction. A failure part-way must not leave an orphan schema
        or a half-built church.

        The failure is forced *after* the schema has been created and migrated — a blank
        admin address, which the user manager refuses — because that is the case worth
        proving. Postgres rolls DDL back with everything else, so the schema goes too.
        """
        before = Tenant.objects.count()
        with self.assertRaises(ValueError):
            self._provision(code="beta", admin_email="")

        self.assertEqual(Tenant.objects.count(), before)
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s", ["beta"]
            )
            self.assertIsNone(cursor.fetchone())


class TenantIsolationTests(ProvisioningTestCase):
    """Two churches, and no path between them."""

    def setUp(self):
        super().setUp()
        self.alpha = provision_church(
            name="Alpha Church",
            schema_name="alpha",
            domain_name="alpha.testserver",
            admin_email="admin@alpha.ca",
        )
        self.beta = provision_church(
            name="Beta Church",
            schema_name="beta",
            domain_name="beta.testserver",
            admin_email="admin@beta.ca",
        )

    def _add_volunteer(self, tenant, first_name, last_name, **extra):
        with tenant_context(tenant):
            from apps.org.models import Volunteer

            return Volunteer.objects.create(first_name=first_name, last_name=last_name, **extra)

    def test_each_church_has_its_own_schema(self):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT schema_name FROM information_schema.schemata "
                "WHERE schema_name IN ('alpha', 'beta') ORDER BY schema_name"
            )
            self.assertEqual([r[0] for r in cursor.fetchall()], ["alpha", "beta"])

    def test_volunteers_are_invisible_across_churches(self):
        self._add_volunteer(self.alpha.tenant, "Alpha", "Person")
        self._add_volunteer(self.beta.tenant, "Beta", "Person")

        from apps.org.models import Volunteer

        with tenant_context(self.alpha.tenant):
            names = list(Volunteer.objects.values_list("first_name", flat=True))
            self.assertEqual(names, ["Alpha"])

        with tenant_context(self.beta.tenant):
            names = list(Volunteer.objects.values_list("first_name", flat=True))
            self.assertEqual(names, ["Beta"])

    def test_a_volunteer_id_from_one_church_does_not_resolve_in_the_other(self):
        """
        The direct attack: take a primary key seen in one church and look it up in another.
        Separate schemas mean separate id sequences and separate tables, so the lookup finds
        nothing rather than someone else's record.
        """
        alpha_volunteer = self._add_volunteer(self.alpha.tenant, "Alpha", "Person")

        from apps.org.models import Volunteer

        with tenant_context(self.beta.tenant):
            self.assertFalse(Volunteer.objects.filter(pk=alpha_volunteer.pk).exists())

    def test_admins_are_scoped_to_their_own_church(self):
        from apps.accounts.models import User

        with tenant_context(self.alpha.tenant):
            self.assertEqual(User.objects.count(), 1)
            self.assertEqual(User.objects.get().email, "admin@alpha.ca")

        with tenant_context(self.beta.tenant):
            self.assertEqual(User.objects.count(), 1)
            self.assertEqual(User.objects.get().email, "admin@beta.ca")

    def test_each_church_gets_a_distinct_encryption_key(self):
        self.assertNotEqual(self.alpha.dek_b64, self.beta.dek_b64)
        self.assertNotEqual(self.alpha.dek_fingerprint, self.beta.dek_fingerprint)

    def test_one_churchs_key_cannot_decrypt_anothers_data(self):
        """
        The encryption-side guarantee. Even if schema separation were bypassed — a bad raw
        query, a botched restore — the ciphertext is still unreadable with the wrong key.
        """
        volunteer = self._add_volunteer(
            self.alpha.tenant, "Alpha", "Person", phone="250-555-0101"
        )

        with connection.cursor() as cursor:
            cursor.execute("SELECT phone FROM alpha.org_volunteer WHERE id = %s", [volunteer.pk])
            (ciphertext,) = cursor.fetchone()

        from apps.core.crypto import decrypt_text

        # Right key: readable.
        self.assertEqual(decrypt_text(ciphertext, decode_key(self.alpha.dek_b64)), "250-555-0101")
        # Other church's key: refused.
        with self.assertRaises(DecryptionError):
            decrypt_text(ciphertext, decode_key(self.beta.dek_b64))
        # An unrelated key: refused.
        with self.assertRaises(DecryptionError):
            decrypt_text(ciphertext, generate_dek())

    def test_audit_trails_are_separate(self):
        from apps.core.models import AuditEvent

        with tenant_context(self.alpha.tenant):
            alpha_count = AuditEvent.objects.count()
            alpha_labels = set(AuditEvent.objects.values_list("entity_label", flat=True))

        with tenant_context(self.beta.tenant):
            beta_labels = set(AuditEvent.objects.values_list("entity_label", flat=True))

        self.assertGreater(alpha_count, 0)
        self.assertIn("Alpha Church", alpha_labels)
        self.assertNotIn("Beta Church", alpha_labels)
        self.assertIn("Beta Church", beta_labels)
        self.assertNotIn("Alpha Church", beta_labels)

    def test_requirement_edits_do_not_cross_churches(self):
        from apps.requirements.models import RequirementDefinition

        with tenant_context(self.alpha.tenant):
            definition = RequirementDefinition.objects.get(name="Code of Conduct")
            definition.name = "Alpha's own Code of Conduct"
            definition.save()

        with tenant_context(self.beta.tenant):
            self.assertTrue(
                RequirementDefinition.objects.filter(name="Code of Conduct").exists()
            )
            self.assertFalse(
                RequirementDefinition.objects.filter(name="Alpha's own Code of Conduct").exists()
            )

    def test_public_schema_holds_no_church_data(self):
        """The operator's console must have nothing to leak."""
        self._add_volunteer(self.alpha.tenant, "Alpha", "Person")

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
            )
            tables = {r[0] for r in cursor.fetchall()}

        for church_table in (
            "org_volunteer",
            "org_roleassignment",
            "requirements_requirementinstance",
            "requirements_crcrecord",
            "documents_document",
            "core_auditevent",
        ):
            self.assertNotIn(church_table, tables, f"{church_table} must not exist in public")

    def test_requests_to_an_unknown_hostname_are_refused(self):
        from django.test import Client

        response = Client().get("/", HTTP_HOST="notachurch.testserver")
        self.assertEqual(response.status_code, 404)

    def _client_for(self, result):
        """A signed-in client for a church, past the mandatory key-backup gate."""
        from django.test import Client

        result.tenant.confirm_key_backup(by="test")
        client = Client(HTTP_HOST=result.domain.domain)

        # force_login looks the user up, and User is a tenant table — so the login has to
        # happen with that church bound, exactly as a real request would.
        with tenant_context(result.tenant):
            from apps.accounts.models import User

            user = User.objects.get()
            _give_passkey(user)
            client.force_login(user)
        return client

    def test_a_new_church_is_held_at_the_key_backup_gate(self):
        """
        PRD §5 requires the church's admin to be *forced* to take an offline copy of the key.
        Until they confirm, every other page redirects there.
        """
        from django.test import Client

        client = Client(HTTP_HOST="alpha.testserver")
        with tenant_context(self.alpha.tenant):
            from apps.accounts.models import User

            user = User.objects.get()
            # Past the passkey gate, which sits in front of this one on purpose.
            _give_passkey(user)
            client.force_login(user)

        self.assertTrue(self.alpha.tenant.key_backup_pending)

        response = client.get("/org/volunteers/")
        self.assertRedirects(response, "/key-backup/", fetch_redirect_response=False)

        # The gate page itself is reachable, and shows the key.
        response = client.get("/key-backup/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.alpha.dek_b64)

        # Confirming releases the gate.
        self.alpha.tenant.confirm_key_backup(by="Alex Admin")
        self.assertEqual(client.get("/org/volunteers/").status_code, 200)

    def test_a_request_binds_only_the_addressed_church(self):
        from django.test import Client

        self._add_volunteer(self.alpha.tenant, "Alpha", "Person")
        client = self._client_for(self.alpha)

        response = client.get("/org/volunteers/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Person, Alpha")

        # The same session presented to the other church must not be honoured. Sessions
        # live in the tenant schema, so the cookie means nothing over there.
        cross = Client(HTTP_HOST="beta.testserver")
        cross.cookies = client.cookies
        response = cross.get("/org/volunteers/")
        self.assertIn(response.status_code, (302, 403, 404))


class KeyEscrowTests(ProvisioningTestCase):
    """Break-glass key handling (PRD §5)."""

    def setUp(self):
        super().setUp()
        self.result = provision_church(
            name="Gamma Church",
            schema_name="gamma",
            domain_name="gamma.testserver",
            admin_email="admin@gamma.ca",
        )

    def test_reimporting_the_correct_key_succeeds_and_data_stays_readable(self):
        tenant = self.result.tenant
        with tenant_context(tenant):
            from apps.org.models import Volunteer

            volunteer = Volunteer.objects.create(
                first_name="Gamma", last_name="Person", phone="250-555-7777"
            )

        rotate_key_from_escrow(tenant, self.result.dek_b64)

        with tenant_context(tenant):
            volunteer.refresh_from_db()
            self.assertEqual(volunteer.phone, "250-555-7777")

    def test_reimporting_the_wrong_key_is_refused_before_any_damage(self):
        """
        A fingerprint mismatch must be rejected. Re-wrapping the wrong key would make every
        encrypted value in that church unreadable — the exact disaster escrow exists to
        prevent.
        """
        from apps.core.crypto import encode_key

        tenant = self.result.tenant
        original_wrapped = bytes(tenant.dek_wrapped)

        with self.assertRaises(ProvisioningError) as caught:
            rotate_key_from_escrow(tenant, encode_key(generate_dek()))

        self.assertIn("fingerprint mismatch", str(caught.exception).lower())
        tenant.refresh_from_db()
        self.assertEqual(bytes(tenant.dek_wrapped), original_wrapped)

    def test_export_command_writes_an_audit_entry_in_the_churchs_own_trail(self):
        from io import StringIO

        from django.core.management import call_command

        from apps.core.models import AuditAction, AuditEvent

        out = StringIO()
        call_command(
            "export_tenant_key", "gamma", "--i-am-the-platform-operator", stdout=out
        )

        self.assertIn(self.result.dek_b64, out.getvalue())

        with tenant_context(self.result.tenant):
            event = AuditEvent.objects.filter(action=AuditAction.KEY_BACKUP).first()
            self.assertIsNotNone(event)
            self.assertIn("exported", event.summary.lower())

    def test_export_command_refuses_without_the_acknowledgement(self):
        """Printing key material takes a deliberate flag, not a bare command."""
        from django.core.management import call_command
        from django.core.management.base import CommandError

        with self.assertRaises(CommandError):
            call_command("export_tenant_key", "gamma")


def _give_passkey(user):
    """A registered passkey, without the WebAuthn ceremony."""
    import secrets

    from apps.accounts.models import Passkey

    return Passkey.objects.create(
        user=user, credential_id=secrets.token_urlsafe(24), public_key=b"not-a-real-key"
    )
