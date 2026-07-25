"""
Export a church's DEK for the operator's escrow (PRD §5).

This is the break-glass companion to ``restore`` in the console: it unwraps a key so
the operator can place it in Keeper Security. Running it is a privileged act, so it
requires an explicit acknowledgement flag and writes an audit entry into the
church's own trail — the church can see that their key was exported, and when.
"""

from django.core.management.base import BaseCommand, CommandError
from django_tenants.utils import schema_context

from apps.core import audit
from apps.core.crypto import encode_key, unwrap_dek
from apps.tenants.models import Tenant


class Command(BaseCommand):
    help = "Print a church's data-encryption key so it can be placed in escrow."

    def add_arguments(self, parser):
        parser.add_argument("code", help="The church's short code (schema name).")
        parser.add_argument(
            "--i-am-the-platform-operator",
            action="store_true",
            dest="acknowledged",
            help="Required. Confirms you intend to display sensitive key material.",
        )
        parser.add_argument(
            "--reason",
            default="escrow backup",
            help="Recorded in the church's audit trail.",
        )

    def handle(self, *args, **options):
        if not options["acknowledged"]:
            raise CommandError(
                "This prints key material that decrypts a church's personal data.\n"
                "Re-run with --i-am-the-platform-operator to confirm."
            )

        try:
            tenant = Tenant.objects.get(schema_name=options["code"])
        except Tenant.DoesNotExist as exc:
            raise CommandError(f"No church with short code '{options['code']}'.") from exc

        if not tenant.dek_wrapped:
            raise CommandError(f"'{tenant.name}' has no encryption key stored.")

        dek = unwrap_dek(bytes(tenant.dek_wrapped))

        from apps.core.models import AuditAction

        with schema_context(tenant.schema_name):
            audit.record(
                AuditAction.KEY_BACKUP,
                "Church",
                entity_id=tenant.pk,
                entity_label=tenant.name,
                summary="Encryption key exported by platform operator",
                detail={"reason": options["reason"], "key_fingerprint": tenant.dek_fingerprint},
                actor=audit.Actor.system("platform operator (CLI)"),
            )

        self.stdout.write(self.style.MIGRATE_HEADING(f"\n{tenant.name} — data encryption key"))
        self.stdout.write(f"  Short code:  {tenant.schema_name}")
        self.stdout.write(f"  Fingerprint: {tenant.dek_fingerprint}")
        self.stdout.write(f"  Key:         {encode_key(dek)}\n")
        self.stdout.write(
            self.style.WARNING(
                "An audit entry recording this export has been written to the church's "
                "own trail. Clear your terminal scrollback when finished."
            )
        )
