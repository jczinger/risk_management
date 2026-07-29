"""
The pg_dump acceptance test.

Build Spec §10: "A raw ``pg_dump`` inspected manually shows **no** readable DOB, address,
phone, email, file contents, or notes."

This automates that inspection. It seeds a volunteer with distinctive marker strings in every
field the PRD classifies as sensitive, runs a real ``pg_dump`` against the test database, and
greps the output for each marker. Anything found is a leak.

It also asserts the *other* half of the classification: the fields the PRD deliberately keeps
plaintext — names, department, role, requirement type, status, dates, the CRC flag, birth year
and month — must be present. That direction matters too. If someone "hardened" the system by
encrypting names, the compliance report and the volunteer search would silently stop working,
and this test says so.

These are ``TransactionTestCase``-based on purpose. ``pg_dump`` opens its own connection, so it
can only see **committed** rows — under a normal ``TestCase`` the data would sit inside an
open transaction and the dump would come back empty, making the leak check pass vacuously.
``test_the_dump_does_contain_the_rows_so_the_test_is_meaningful`` guards against exactly that.

Skipped when ``pg_dump`` is not on PATH.
"""

from __future__ import annotations

import datetime
import shutil
import subprocess
import unittest

from django.conf import settings
from django.db import connection
from django.test import TransactionTestCase
from django.utils import timezone
from django_tenants.utils import tenant_context

from apps.core.keys import forget_cached_keys
from apps.requirements.models import CRCResult
from apps.requirements.services import (
    mark_requirement_complete,
    record_convictions,
    record_crc,
    record_discretionary_override,
    sync_volunteer_requirements,
)
from apps.tenants.models import Domain, Tenant
from apps.tenants.services import provision_church

#: One unmistakable marker per sensitive field. Chosen so a false positive is impossible —
#: none of these could appear in schema DDL, a Django table name or a seeded requirement.
MARKERS = {
    "date_of_birth": "1977-04-13",
    "email": "leakcanary.email@example.invalid",
    "phone": "250-555-0LEAK",
    "address": "9999 Leakcanary Avenue, Nowhere BC",
    "emergency_contact": "Leakcanary Emergency Contact, sibling, 250-555-9998",
    "medical_notes": "LEAKCANARY-MEDICAL severe reaction to shellfish",
    "volunteer_notes": "LEAKCANARY-NOTE prefers Sunday mornings only",
    "requirement_notes": "LEAKCANARY-REQNOTE referee said she was excellent with children",
    "crc_notes": "LEAKCANARY-CRCNOTE spoke to the detachment about the delay",
    "conviction_description": "LEAKCANARY-CONVICTION details as disclosed at interview",
    "override_reasoning": "LEAKCANARY-REASONING single offence, disclosed voluntarily",
    "override_mitigation": "LEAKCANARY-MITIGATION never alone with children, reviewed yearly",
    "waiver_reason": "LEAKCANARY-WAIVER held at the district office instead",
    "document_bytes": "LEAKCANARY-FILE-CONTENTS-INSIDE-THE-PDF",
    "document_filename": "leakcanary-jane-smith-crc.pdf",
    "admin_email": "leakcanary.admin@example.invalid",
    "email_body_marker": "Leakcanary",
}


@unittest.skipUnless(shutil.which("pg_dump"), "pg_dump is not installed")
class DumpLeakageTests(TransactionTestCase):
    """Seed markers, dump the database, and grep for anything readable."""

    SCHEMA = "leakcanary"
    HOSTNAME = "leakcanary.testserver"

    def setUp(self):
        super().setUp()
        connection.set_schema_to_public()
        forget_cached_keys()

        # A really provisioned church, committed, so pg_dump can see it.
        self.result = provision_church(
            name="Leakcanary Church",
            schema_name=self.SCHEMA,
            domain_name=self.HOSTNAME,
            admin_email=MARKERS["admin_email"],
        )
        self.tenant = self.result.tenant
        connection.set_tenant(self.tenant)

        from apps.org.models import Role

        self.department = self._make_department()
        self.role = Role.objects.create(
            department=self.department,
            name="Sunday School Teacher",
        )

    def tearDown(self):
        from pathlib import Path

        from apps.documents.models import Document

        with tenant_context(self.tenant):
            for document in Document.objects.exclude(encrypted_file=""):
                if document.encrypted_file:
                    Path(document.encrypted_file.path).unlink(missing_ok=True)

        connection.set_schema_to_public()
        forget_cached_keys()
        Domain.objects.filter(tenant=self.tenant).delete()
        Tenant.objects.filter(pk=self.tenant.pk).delete()
        with connection.cursor() as cursor:
            cursor.execute(f'DROP SCHEMA IF EXISTS "{self.SCHEMA}" CASCADE')
        super().tearDown()

    def _make_department(self):
        from apps.org.models import Department

        return Department.objects.create(name="Children's Ministry")

    def _seed_sensitive_data(self):
        """Write a marker into every field the PRD classifies as sensitive."""
        from apps.org.models import RoleAssignment, Volunteer

        volunteer = Volunteer.objects.create(
            first_name="Leakcanary",
            last_name="Testsubject",
            date_of_birth=datetime.date.fromisoformat(MARKERS["date_of_birth"]),
            email=MARKERS["email"],
            phone=MARKERS["phone"],
            address=MARKERS["address"],
            emergency_contact=MARKERS["emergency_contact"],
            medical_notes=MARKERS["medical_notes"],
            notes=MARKERS["volunteer_notes"],
        )
        RoleAssignment.objects.create(volunteer=volunteer, role=self.role)
        sync_volunteer_requirements(volunteer)

        # Requirement notes (reference-check content lives here).
        references = volunteer.requirement_instances.get(
            definition__requirement_type="reference_checks"
        )
        mark_requirement_complete(
            references, timezone.localdate(), notes=MARKERS["requirement_notes"]
        )

        # A waiver reason.
        from apps.requirements.services import waive_requirement

        interview = volunteer.requirement_instances.get(definition__requirement_type="interview")
        waive_requirement(
            interview, reason=MARKERS["waiver_reason"], waived_by="Pastor Leakcanary"
        )

        # A criminal record check with notes, a discretionary conviction, and an override.
        crc = record_crc(
            volunteer,
            result=CRCResult.NOT_CLEAR,
            report_date=timezone.localdate(),
            notes=MARKERS["crc_notes"],
        )
        record_convictions(
            crc,
            [
                {
                    "category": "Theft or fraud",
                    "is_automatic_disqualifier": False,
                    "description": MARKERS["conviction_description"],
                }
            ],
        )
        from apps.requirements.models import DiscretionaryOverride

        record_discretionary_override(
            crc,
            conviction=crc.convictions.first(),
            decision=DiscretionaryOverride.Decision.APPROVED_WITH_CONDITIONS,
            decided_by="Board of Elders",
            reasoning=MARKERS["override_reasoning"],
            mitigation_steps=MARKERS["override_mitigation"],
        )

        # A stored document whose plaintext contains a marker.
        from django.core.files.uploadedfile import SimpleUploadedFile

        from apps.documents.models import DocumentKind
        from apps.documents.services import store_document
        from apps.tenants.models import DocumentMode

        self.tenant.document_mode = DocumentMode.STORE
        self.tenant.save(update_fields=["document_mode"])
        connection.set_tenant(self.tenant)

        pdf = (
            b"%PDF-1.7\n" + MARKERS["document_bytes"].encode() + b"\ntrailer<<>>\n%%EOF\n"
        )
        self.document = store_document(
            volunteer=volunteer,
            title="Clearance letter",
            kind=DocumentKind.CRC,
            upload=SimpleUploadedFile(MARKERS["document_filename"], pdf),
        )

        # A reminder digest, so the email log carries an encrypted recipient and body.
        from apps.notifications.services import send_digest

        send_digest(
            self.tenant,
            [
                {
                    "instance": references,
                    "kind": "lead_time",
                    "lead_days": 30,
                    "due_date": timezone.localdate(),
                }
            ],
        )

        return volunteer

    def _dump(self) -> str:
        """Run pg_dump against the test database and return the SQL as text."""
        db = settings.DATABASES["default"]
        command = [
            "pg_dump",
            "--host", db["HOST"],
            "--port", str(db["PORT"]),
            "--username", db["USER"],
            "--dbname", connection.settings_dict["NAME"],
            "--no-owner",
            "--no-privileges",
            # Plain SQL with COPY data, i.e. what an attacker with credentials would take.
            "--format", "plain",
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            env={"PGPASSWORD": db["PASSWORD"], "PATH": "/usr/bin:/bin:/usr/local/bin"},
            check=False,
            timeout=180,
        )
        if result.returncode != 0:
            self.skipTest(f"pg_dump failed: {result.stderr.decode()[:400]}")
        return result.stdout.decode("utf-8", errors="replace")

    def test_no_sensitive_value_appears_in_a_database_dump(self):
        """
        The headline acceptance criterion. Every sensitive marker must be absent from the
        dump — and if one is present, the failure message names exactly which field leaked.
        """
        self._seed_sensitive_data()
        dump = self._dump()

        leaked = [
            field
            for field, marker in MARKERS.items()
            # The volunteer's *name* is plaintext by design, and it appears inside the digest
            # body, so this marker is checked separately rather than as a leak.
            if field != "email_body_marker" and marker in dump
        ]
        self.assertEqual(
            leaked,
            [],
            "These sensitive fields are readable in a raw pg_dump: " + ", ".join(leaked),
        )

    def test_the_dump_does_contain_the_rows_so_the_test_is_meaningful(self):
        """
        Guards the test itself. If the dump were empty — wrong database, failed command — the
        leak check above would pass vacuously. This confirms the volunteer's row is really in
        there, found via a field that is plaintext by design.
        """
        self._seed_sensitive_data()
        dump = self._dump()

        self.assertIn("org_volunteer", dump)
        self.assertIn("Leakcanary", dump, "the seeded row is not in the dump at all")
        self.assertIn("COPY", dump)

    def test_deliberately_plaintext_fields_are_present_and_queryable(self):
        """
        The other half of the classification (PRD §5). These stay in the clear on purpose so
        the app can search, sort and report. Encrypting them would break the volunteer list
        and the compliance report.
        """
        self._seed_sensitive_data()
        dump = self._dump()

        for expected, why in [
            ("Leakcanary", "first name — the volunteer list is searched by name"),
            ("Testsubject", "last name — same"),
            ("Sunday School Teacher", "role name — reports group by it"),
            ("1977", "birth year — the age rules must be queryable"),
            ("not_clear", "CRC result flag — the compliance report shows it"),
            ("reference_checks", "requirement type — reports filter on it"),
        ]:
            with self.subTest(field=why):
                self.assertIn(expected, dump, f"expected plaintext {why}")

    def test_the_document_on_disk_is_also_unreadable(self):
        """
        A dump is not the only exfiltration route. The media volume must be ciphertext too,
        or the encryption is only half applied.
        """
        from pathlib import Path

        self._seed_sensitive_data()
        path = Path(self.document.encrypted_file.path)
        on_disk = path.read_bytes()

        self.assertNotIn(MARKERS["document_bytes"].encode(), on_disk)
        self.assertNotIn(b"%PDF", on_disk)
        self.assertNotIn(MARKERS["document_filename"], str(path))

        path.unlink(missing_ok=True)

    def test_no_account_carries_a_usable_password(self):
        """
        There are no passwords to leak. Every account holds Django's unusable marker, so
        the ``password`` column can appear in a dump without being worth anything.

        The marker must still be *distinct per row*: Django derives a session's
        ``_auth_user_hash`` from this column, and identical values across churches would
        let one church's session validate as another's user. See
        apps/accounts/migrations/0002.
        """
        from apps.accounts.models import User

        self._seed_sensitive_data()

        with tenant_context(self.tenant):
            passwords = list(User.objects.values_list("password", flat=True))

        self.assertTrue(passwords)
        for stored in passwords:
            self.assertTrue(stored.startswith("!"), stored[:8])
        self.assertEqual(len(set(passwords)), len(passwords))

    def test_a_live_sign_in_link_is_not_recoverable_from_the_dump(self):
        """
        A link is a bearer token for an administrator account. Provisioning mints one,
        so a dump taken before it is used must not contain anything that works.
        """
        from apps.accounts.links import SIGNING_SALT
        from django.core import signing

        self._seed_sensitive_data()
        dump = self._dump()

        secret = signing.loads(
            self.result.invite_url.rstrip("/").rsplit("/", 1)[-1], salt=SIGNING_SALT
        )["token"]
        self.assertNotIn(secret, dump)
        self.assertNotIn(self.result.invite_url, dump)

    def test_the_encryption_key_is_not_recoverable_from_the_dump(self):
        """
        The tenant key is stored wrapped under PLATFORM_MASTER_KEY, which lives in the
        environment. A dump plus the wrapped key alone must not be enough.
        """
        self._seed_sensitive_data()
        dump = self._dump()

        self.assertNotIn(self.result.dek_b64, dump)
        self.assertNotIn(settings.PLATFORM_MASTER_KEY, dump)
