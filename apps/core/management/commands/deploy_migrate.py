"""
Idempotent deploy step: prepare the public schema and every tenant schema.

Run by the ``migrate`` service in docker-compose.yml, which web/worker/beat all wait
on. Safe to re-run, so a redeploy needs no special handling.
"""

from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import connection
from django.db.utils import OperationalError, ProgrammingError


class Command(BaseCommand):
    help = "Migrate the public schema, then every tenant schema."

    def add_arguments(self, parser):
        parser.add_argument(
            "--collectstatic",
            action="store_true",
            help=(
                "Also run collectstatic. Not needed for the Docker deployment, where static "
                "files are built into the image; useful when running against a bare host."
            ),
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.MIGRATE_HEADING("Migrating public schema"))
        call_command("migrate_schemas", "--shared", verbosity=1, interactive=False)

        # migrate_schemas --tenant needs the tenant table to exist, which the shared
        # pass above guarantees. On a brand-new database there are simply no rows.
        from apps.tenants.models import Tenant

        try:
            count = Tenant.objects.count()
        except (OperationalError, ProgrammingError) as exc:
            raise SystemExit(f"Could not read the church registry after migrating: {exc}") from exc

        if count:
            self.stdout.write(
                self.style.MIGRATE_HEADING(f"Migrating {count} tenant schema(s)")
            )
            call_command("migrate_schemas", "--tenant", verbosity=1, interactive=False)
        else:
            self.stdout.write("No churches provisioned yet; nothing to migrate per-tenant.")

        if options["collectstatic"]:
            self.stdout.write(self.style.MIGRATE_HEADING("Collecting static files"))
            call_command("collectstatic", interactive=False, verbosity=0)

        self.stdout.write(
            self.style.SUCCESS(f"Deploy migration complete (schema: {connection.schema_name}).")
        )
