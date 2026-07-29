"""
Mint a sign-in link from the command line.

This is the operator's break-glass, and the only way in when email is not configured or
is not working. It needs shell access to the host, which is a stronger control than any
password would have been — but it also means anyone with that access can sign in as any
administrator, so the issue is written into the church's own audit trail where they can
see it.
"""

from django.core.management.base import BaseCommand, CommandError
from django_tenants.utils import schema_context

from apps.accounts.links import describe_lifetime, issue_link
from apps.accounts.models import LinkPurpose, User
from apps.tenants.routing import find_login_targets


class Command(BaseCommand):
    help = "Issue a single-use sign-in link for an administrator, and print it."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True, help="The administrator's address.")
        parser.add_argument(
            "--schema",
            default="",
            help=(
                "Only issue a link in this schema. Omit to issue one everywhere the "
                "address is found, which is what you want if somebody administers two "
                "churches."
            ),
        )
        parser.add_argument(
            "--purpose",
            choices=LinkPurpose.values,
            default=LinkPurpose.RECOVERY,
            help=(
                "recovery (default, short-lived) or invite (long-lived, for an account "
                "that has never been signed into)."
            ),
        )

    def handle(self, *args, **options):
        email = options["email"]
        wanted = (options["schema"] or "").strip().lower()
        purpose = options["purpose"]

        targets = find_login_targets(email)
        if wanted:
            targets = [t for t in targets if t.schema_name == wanted]

        if not targets:
            # Said plainly. Unlike the web form, there is nobody to hide the answer from
            # here — the person running this already has the database.
            raise CommandError(
                f"No active account for that address"
                + (f" in schema '{wanted}'." if wanted else " in any schema.")
            )

        for target in targets:
            with schema_context(target.schema_name):
                user = User.objects.filter(pk=target.user_pk, is_active=True).first()
                if user is None:
                    continue
                _, url = issue_link(user, purpose)

            self.stdout.write(self.style.MIGRATE_HEADING(f"\n{target.label}"))
            self.stdout.write(f"  schema:  {target.schema_name}")
            self.stdout.write(f"  expires: {describe_lifetime(purpose)} from now, single use")
            self.stdout.write(f"  {url}\n")

        self.stdout.write(
            self.style.WARNING(
                "\nUsing this link signs the holder in and sends them to register a "
                "passkey.\nIt is recorded in the audit trail of the church it belongs to."
            )
        )
