"""
Report who holds which access level, and repair a church that has nobody in charge.

Two jobs, deliberately in one command, because they are the same question asked in two
moods. With no ``--email`` it *reports*: run it straight after deploying the access-level
change to confirm every existing administrator came out of the backfill as a Primary
Admin, before signing out of a session you might not get back.

With ``--email`` it *repairs*: makes that person a Primary Admin. This is the answer to
"the last Primary Admin left and nobody can reach the administrators screen", which the
in-app lockout guard is designed to prevent but which a database restore or a botched
migration could still produce. Like ``issue_magic_link``, it needs shell access to the
host, and it writes what it did into the church's own audit trail.

It never demotes anybody and never overwrites an existing grant — a church that has
deliberately put someone on a limited level must not have that undone by an operator
running a repair tool.
"""

from django.core.management.base import CommandError
from django_tenants.utils import schema_context

from apps.core import audit
from apps.core.management.tenant_command import TenantSchemasCommand
from apps.core.models import AuditAction, UserAccessGrant
from apps.core.seed import grant_primary_admin, seed_access_levels


class Command(TenantSchemasCommand):
    help = "Show or repair the access levels held by a church's administrators."

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            "--email",
            default="",
            help=(
                "Make this administrator a Primary Admin. Requires --schema, so that a "
                "repair cannot be aimed at the wrong church by accident."
            ),
        )
        parser.add_argument(
            "--seed",
            action="store_true",
            help="Also create any missing built-in access level. Never edits an existing one.",
        )

    def handle(self, *args, **options):
        schema = (options["schema"] or "").strip().lower()
        email = (options["email"] or "").strip()

        if email and not schema:
            raise CommandError("--email needs --schema, so the repair lands on one church only.")

        for name in self._schemas(schema):
            with schema_context(name):
                if options["seed"]:
                    created = seed_access_levels()
                    if created:
                        self.stdout.write(f"{name}: seeded {created} access level(s)")
                if email:
                    self._repair(name, email)
                self._report(name)

    def _repair(self, schema: str, email: str) -> None:
        # Imported here: the blind index derives its key from the bound schema, so this
        # has to resolve inside the schema_context rather than at module scope.
        from apps.accounts.models import User
        from apps.core.blind_index import email_index, normalise_email

        user = User.objects.filter(email_index=email_index(normalise_email(email))).first()
        if user is None:
            raise CommandError(f"No account with that address in '{schema}'.")

        if grant_primary_admin(user.pk, granted_by_display="operator repair"):
            audit.record(
                AuditAction.ACCESS_CHANGED,
                "User",
                entity_id=user.pk,
                entity_label=user.get_full_name() or f"user #{user.pk}",
                summary="Granted Primary Admin from the command line",
            )
            self.stdout.write(self.style.SUCCESS(f"{schema}: {email} is now a Primary Admin"))
        else:
            # Not an error: the operator asked for an outcome that already holds.
            self.stdout.write(f"{schema}: {email} already holds an access level; left alone")

    def _report(self, schema: str) -> None:
        from apps.accounts.models import User

        grants = {
            g.user_id: g
            for g in UserAccessGrant.objects.select_related("access_level").prefetch_related(
                "departments"
            )
        }
        # ``email`` is deferred deliberately. It is the one encrypted column on this
        # model, so fetching it would make the report need the church's DEK — and this
        # command exists for the moment something has gone wrong, which is exactly when
        # a key may be missing or mismatched. Names are plaintext by design (PRD §5),
        # so the report reads fine without it.
        users = (
            User.objects.filter(is_active=True)
            .defer("email")
            .order_by("last_name", "first_name")
        )

        self.stdout.write(self.style.MIGRATE_HEADING(f"\n{schema}"))
        if not users:
            self.stdout.write("  (no active administrators)")
            return

        unscoped_managers = 0
        for user in users:
            grant = grants.get(user.pk)
            name = user.get_full_name() or f"user #{user.pk}"
            if grant is None:
                # The state the backfill exists to prevent. Loud, because this account
                # can currently do nothing at all.
                self.stdout.write(self.style.ERROR(f"  {name}: NO ACCESS LEVEL"))
                continue

            level = grant.access_level
            where = "all departments"
            if level.is_scoped:
                departments = sorted(d.name for d in grant.departments.all())
                where = ", ".join(departments) if departments else "no departments — sees nothing"
            self.stdout.write(f"  {name}: {level.name} ({where})")

            if not level.is_scoped and level.can_manage_users:
                unscoped_managers += 1

        if unscoped_managers == 0:
            self.stdout.write(
                self.style.ERROR(
                    "  ^ nobody here can manage administrators church-wide. "
                    "Repair with --email."
                )
            )
