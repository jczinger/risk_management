"""CLI provisioning, for the first church and for scripted setups."""

from django.core.management.base import BaseCommand, CommandError

from apps.tenants.models import DocumentMode
from apps.tenants.services import ProvisioningError, provision_church


class Command(BaseCommand):
    help = "Provision a church: schema, encryption key, first admin, seed template."

    def add_arguments(self, parser):
        parser.add_argument("--name", required=True, help="The church's full name.")
        parser.add_argument(
            "--code",
            required=True,
            help="Short code: lowercase letters/digits. Becomes the database schema.",
        )
        parser.add_argument(
            "--domain",
            default="",
            help=(
                "Give this church a hostname of its own. Omit for the normal case: the "
                "church signs in at the shared address and is selected by email."
            ),
        )
        parser.add_argument("--admin-email", required=True)
        parser.add_argument("--admin-first-name", default="")
        parser.add_argument("--admin-last-name", default="")
        parser.add_argument(
            "--admin-password",
            help="Omit for a passkey-only admin account.",
        )
        parser.add_argument(
            "--document-mode",
            choices=DocumentMode.values,
            default=DocumentMode.STORE,
        )
        parser.add_argument("--reminder-lead-days", default="60,30,7")
        parser.add_argument(
            "--no-seed",
            action="store_true",
            help="Skip the 14-item Plan to Protect template.",
        )

    def handle(self, *args, **options):
        domain = options["domain"]

        try:
            result = provision_church(
                name=options["name"],
                schema_name=options["code"],
                domain_name=domain,
                admin_email=options["admin_email"],
                admin_first_name=options["admin_first_name"],
                admin_last_name=options["admin_last_name"],
                admin_password=options["admin_password"],
                document_mode=options["document_mode"],
                reminder_lead_days=options["reminder_lead_days"],
                seed_template=not options["no_seed"],
            )
        except (ProvisioningError, Exception) as exc:  # noqa: BLE001
            raise CommandError(str(exc)) from exc

        self.stdout.write(self.style.SUCCESS(f"\nProvisioned: {result.tenant.name}"))
        self.stdout.write(f"  Schema:              {result.tenant.schema_name}")
        self.stdout.write(
            f"  Signs in at:         {result.tenant.url}"
            + ("" if result.domain else "   (shared address; selected by email)")
        )
        self.stdout.write(f"  First admin:         {result.admin_email}")
        self.stdout.write(f"  Requirements seeded: {result.seeded_requirements}")
        self.stdout.write(f"  Key fingerprint:     {result.dek_fingerprint}")

        self.stdout.write(self.style.MIGRATE_HEADING("\nDATA ENCRYPTION KEY (shown once)"))
        self.stdout.write(f"  {result.dek_b64}\n")
        self.stdout.write(
            self.style.WARNING(
                "Copy this into Keeper Security now, under this church's name and the\n"
                "fingerprint above. It is not stored anywhere in retrievable form other\n"
                "than wrapped by PLATFORM_MASTER_KEY.\n\n"
                "The church's own admin will separately be required to save a copy at\n"
                "first sign-in before they can use the system."
            )
        )
