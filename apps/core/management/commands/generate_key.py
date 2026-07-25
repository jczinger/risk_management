"""Generate key material for .env, without touching the database."""

from django.core.management.base import BaseCommand
from django.utils.crypto import get_random_string

from apps.core.crypto import encode_key, generate_dek


class Command(BaseCommand):
    help = "Print a fresh PLATFORM_MASTER_KEY (and optionally a DJANGO_SECRET_KEY)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--secret-key",
            action="store_true",
            help="Also print a DJANGO_SECRET_KEY.",
        )
        parser.add_argument(
            "--quiet",
            action="store_true",
            help="Print only the key value, for piping into a config file.",
        )

    def handle(self, *args, **options):
        master = encode_key(generate_dek())

        if options["quiet"]:
            self.stdout.write(master)
            return

        self.stdout.write(self.style.MIGRATE_HEADING("PLATFORM_MASTER_KEY"))
        self.stdout.write(f"PLATFORM_MASTER_KEY={master}\n")

        if options["secret_key"]:
            chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^&*(-_=+)"
            self.stdout.write(self.style.MIGRATE_HEADING("DJANGO_SECRET_KEY"))
            self.stdout.write(f"DJANGO_SECRET_KEY={get_random_string(64, chars)}\n")

        self.stdout.write(
            self.style.WARNING(
                "\nThe master key wraps every church's data-encryption key. Store a "
                "copy in Keeper Security BEFORE provisioning any church — losing it "
                "means no tenant key can be unwrapped, and every encrypted field "
                "becomes unreadable."
            )
        )
