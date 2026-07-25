"""
Confirm every church's encryption key still works.

Run after a restore, after rotating ``PLATFORM_MASTER_KEY``, or any time you want assurance
that the data is actually readable. Checking "did the restore succeed?" by looking at row
counts is not enough — a restore onto a host with the wrong master key looks perfectly
healthy until somebody opens a volunteer's record.

For each church this unwraps the DEK, confirms the fingerprint matches what is recorded, and
decrypts one real encrypted value end to end.
"""

from django.core.management.base import BaseCommand, CommandError
from django_tenants.utils import get_public_schema_name, tenant_context

from apps.core.crypto import DecryptionError, key_fingerprint, unwrap_dek
from apps.core.keys import forget_cached_keys
from apps.tenants.models import Tenant


class Command(BaseCommand):
    help = "Verify that every church's data-encryption key unwraps and decrypts real data."

    def add_arguments(self, parser):
        parser.add_argument(
            "--code",
            help="Check only this church's short code. Default: all of them.",
        )
        parser.add_argument(
            "--quiet",
            action="store_true",
            help="Print only failures. Exit code is still 0 on success, 1 on any failure.",
        )

    def handle(self, *args, **options):
        forget_cached_keys()

        tenants = Tenant.objects.all()
        if options["code"]:
            tenants = tenants.filter(schema_name=options["code"])
            if not tenants.exists():
                raise CommandError(f"No church with short code '{options['code']}'.")

        failures = []
        checked = 0

        for tenant in tenants:
            checked += 1
            problem = self._check(tenant, quiet=options["quiet"])
            if problem:
                failures.append((tenant, problem))

        self.stdout.write("")
        if failures:
            self.stdout.write(
                self.style.ERROR(f"{len(failures)} of {checked} church(es) FAILED verification:")
            )
            for tenant, problem in failures:
                self.stdout.write(self.style.ERROR(f"  {tenant.schema_name}: {problem}"))
            self.stdout.write("")
            self.stdout.write(
                "A key failure almost always means PLATFORM_MASTER_KEY does not match the "
                "one these records were encrypted under. Retrieve the right value from "
                "Keeper Security, or re-import the church's own key from escrow."
            )
            raise SystemExit(1)

        self.stdout.write(
            self.style.SUCCESS(f"All {checked} church(es) verified: keys unwrap and data decrypts.")
        )

    def _check(self, tenant: Tenant, *, quiet: bool) -> str | None:
        """Return None when the church verifies, or a description of what went wrong."""
        label = f"{tenant.schema_name} ({tenant.name})"

        if not tenant.dek_wrapped:
            return "no encryption key stored"

        # 1. Does the wrapped key open under the current master key?
        try:
            dek = unwrap_dek(bytes(tenant.dek_wrapped))
        except DecryptionError as exc:
            return f"key will not unwrap — {exc}"
        except Exception as exc:  # noqa: BLE001
            return f"key unwrap failed — {exc}"

        # 2. Does it match the fingerprint recorded at provisioning?
        fingerprint = key_fingerprint(dek)
        if tenant.dek_fingerprint and fingerprint != tenant.dek_fingerprint:
            return (
                f"fingerprint mismatch — recorded {tenant.dek_fingerprint}, "
                f"key in use is {fingerprint}"
            )

        # 3. Can it actually decrypt stored data? The public schema holds the super-admin;
        #    a church schema holds volunteers and admins.
        if tenant.schema_name == get_public_schema_name():
            problem = self._decrypt_sample_users(tenant)
        else:
            problem = self._decrypt_sample_tenant_data(tenant)
        if problem:
            return problem

        if not quiet:
            self.stdout.write(f"  OK  {label} — key {fingerprint}")
        return None

    def _decrypt_sample_users(self, tenant) -> str | None:
        from apps.accounts.models import User

        with tenant_context(tenant):
            user = User.objects.first()
            if user is None:
                return None
            try:
                # Touching the attribute is what triggers decryption.
                _ = user.email
            except DecryptionError as exc:
                return f"stored account data will not decrypt — {exc}"
        return None

    def _decrypt_sample_tenant_data(self, tenant) -> str | None:
        from apps.org.models import Volunteer

        with tenant_context(tenant):
            problem = self._decrypt_sample_users(tenant)
            if problem:
                return problem

            volunteer = Volunteer.objects.exclude(phone="").first() or Volunteer.objects.first()
            if volunteer is None:
                # A church with no volunteers yet is not a failure; the key checks above
                # already confirmed it unwraps.
                return None
            try:
                _ = (volunteer.phone, volunteer.address, volunteer.date_of_birth)
            except DecryptionError as exc:
                return f"volunteer data will not decrypt — {exc}"
        return None
