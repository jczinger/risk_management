"""
Give existing administrators the screening file they should already have had.

An administrator is a person who serves, and Plan to Protect screens people who serve —
so from 2026-08-02 a new administrator gets a volunteer record at the moment their
account is made. This command is the same thing for the accounts that already existed.

**A command rather than a migration, and that is the inverse of the access-level
backfill.** That one *had* to be a migration: ``has_capability`` fails closed, so any gap
between ``migrate`` and the backfill would have locked every administrator at every
church out of everything, and only migration ordering could rule that out. Nothing here
is like that. A missing volunteer record locks nobody out of anything; it just means one
administrator's own screening is not being tracked yet. And a migration would have to
write ``Volunteer.email``, which is encrypted, so it would need the tenant's data key —
exactly what ``UserManager.use_in_migrations = False`` exists to keep out of migrations.

Reports by default. ``--create`` is the only thing that writes.

It never guesses. Where a volunteer already exists under the administrator's name it
creates nothing and says so, because two people can share a name and there is no way to
un-merge two screening files. Resolve those from the administrators list, which offers
the choice explicitly.
"""

from django_tenants.utils import schema_context

from apps.core import audit
from apps.core.management.tenant_command import TenantSchemasCommand
from apps.core.models import AuditAction


class Command(TenantSchemasCommand):
    help = "Report or create the volunteer records belonging to a church's administrators."

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            "--create",
            action="store_true",
            help=(
                "Actually create the missing records. Without this the command only "
                "reports, which is also how you answer 'who has no file yet?'."
            ),
        )

    def handle(self, *args, **options):
        schema = (options["schema"] or "").strip().lower()
        for name in self._schemas(schema):
            with schema_context(name):
                self._church(name, create=options["create"])

    def _church(self, schema: str, *, create: bool) -> None:
        from apps.accounts.models import User
        from apps.org.models import Volunteer

        self.stdout.write(self.style.MIGRATE_HEADING(schema))

        # ``.defer("email")`` for the same reason ``access_levels`` does it: a repair tool
        # should not need the tenant's data key to tell an operator what state they are
        # in. The addresses are only read on the branch that actually creates a record.
        admins = list(User.objects.defer("email").order_by("last_name", "first_name"))
        linked = set(
            Volunteer.objects.filter(user_id__in=[a.pk for a in admins]).values_list(
                "user_id", flat=True
            )
        )

        made = skipped = 0
        for admin in admins:
            name = admin.get_full_name() or f"user #{admin.pk}"

            if admin.pk in linked:
                self.stdout.write(f"  {name}: has a volunteer record")
                continue

            matches = list(
                Volunteer.objects.possible_matches_for(admin.first_name, admin.last_name)
            )
            if matches:
                skipped += 1
                which = ", ".join(f"#{v.pk} {v.full_name}" for v in matches)
                self.stdout.write(
                    self.style.WARNING(
                        f"  {name}: NOT created — a record already exists under that "
                        f"name ({which}). Link or separate it from the administrators "
                        "list."
                    )
                )
                continue

            if not create:
                self.stdout.write(f"  {name}: would create a volunteer record")
                continue

            fresh = User.objects.get(pk=admin.pk)  # Re-read *with* the encrypted address.
            volunteer = Volunteer.objects.create(
                first_name=fresh.first_name,
                last_name=fresh.last_name,
                email=fresh.email,
                user_id=fresh.pk,
            )
            audit.record(
                AuditAction.CREATE,
                "Volunteer",
                entity_id=volunteer.pk,
                entity_label=volunteer.full_name,
                summary="Volunteer record created for a screening administrator",
            )
            made += 1
            self.stdout.write(self.style.SUCCESS(f"  {name}: created record #{volunteer.pk}"))

        if made:
            self.stdout.write(
                f"  {made} record(s) created. Each has no ministry role yet, so it is "
                "visible only to administrators who see the whole church until you give "
                "them one."
            )
        if skipped:
            self.stdout.write(f"  {skipped} left for a human to decide on.")
        if not create and not made:
            self.stdout.write("  Nothing written. Re-run with --create to act on the above.")
