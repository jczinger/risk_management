"""
Create the platform super-admin and the public schema's Tenant row.

django-tenants needs a Tenant row for the ``public`` schema itself so that requests
to the platform domain resolve. This command sets that up and creates the operator's
account, and is safe to re-run.
"""

import os

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django_tenants.utils import get_public_schema_name, schema_context

from apps.accounts.models import User
from apps.core.blind_index import email_index
from apps.core.keys import forget_cached_keys
from apps.tenants.models import Domain, Tenant


class Command(BaseCommand):
    help = "Create the public-schema tenant row and the platform super-admin account."

    def add_arguments(self, parser):
        parser.add_argument("--email", help="Super-admin email. Or set VMS_SUPERADMIN_EMAIL.")
        parser.add_argument("--first-name", default="")
        parser.add_argument("--last-name", default="")
        parser.add_argument(
            "--password",
            help=(
                "Optional. Or set VMS_SUPERADMIN_PASSWORD. Omit for a passkey-only "
                "account, which then needs a passkey registered before first sign-in."
            ),
        )
        parser.add_argument(
            "--domain",
            help="Hostname for the platform itself. Defaults to VMS_BASE_DOMAIN.",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        from django.conf import settings

        email = options["email"] or os.environ.get("VMS_SUPERADMIN_EMAIL", "")
        if not email:
            raise CommandError("Pass --email or set VMS_SUPERADMIN_EMAIL.")

        password = options["password"] or os.environ.get("VMS_SUPERADMIN_PASSWORD") or None
        domain_name = (options["domain"] or settings.VMS_BASE_DOMAIN).strip().lower()
        public = get_public_schema_name()

        # 1. The public schema's own Tenant row.
        #
        # It holds no church data, but it does hold the super-admin account — whose
        # email address is encrypted like everyone else's — so it needs a DEK of its
        # own. ForceKeyBackupMiddleware skips the public schema, so no backup gate
        # applies; the operator's copy of PLATFORM_MASTER_KEY is what protects it.
        tenant = Tenant.objects.filter(schema_name=public).first()
        if tenant is None:
            tenant = Tenant(
                schema_name=public,
                name="VMS Platform",
                notifications_enabled=False,
            )
            tenant.assign_new_dek()
            # A class attribute, not a field: the public schema already exists, so
            # saving must not try to create it.
            tenant.auto_create_schema = False
            tenant.save()
            self.stdout.write(
                self.style.SUCCESS(
                    f"Created public tenant row ('{public}'), key fingerprint "
                    f"{tenant.dek_fingerprint}."
                )
            )
        else:
            self.stdout.write(f"Public tenant row already present ('{public}').")
            if not tenant.dek_wrapped:
                # An older deployment, or a row created before this step existed.
                tenant.assign_new_dek()
                tenant.auto_create_schema = False
                tenant.save(update_fields=["dek_wrapped", "dek_fingerprint"])
                forget_cached_keys(public)
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Assigned a platform encryption key ({tenant.dek_fingerprint})."
                    )
                )

        # 2. A hostname for the platform domain.
        domain, domain_created = Domain.objects.get_or_create(
            domain=domain_name,
            defaults={"tenant": tenant, "is_primary": True},
        )
        if domain_created:
            self.stdout.write(self.style.SUCCESS(f"Platform hostname: {domain_name}"))
        elif domain.tenant_id != tenant.pk:
            raise CommandError(
                f"Hostname '{domain_name}' already routes to '{domain.tenant.name}'."
            )

        # 3. The operator's account, in the public schema.
        with schema_context(public):
            existing = User.objects.filter(email_index=email_index(email)).first()
            if existing:
                changed = []
                if not existing.is_superuser:
                    existing.is_superuser = True
                    changed.append("is_superuser")
                if not existing.is_staff:
                    existing.is_staff = True
                    changed.append("is_staff")
                if password:
                    existing.set_password(password)
                    changed.append("password")
                if changed:
                    existing.save(update_fields=changed)
                    self.stdout.write(
                        self.style.SUCCESS(f"Updated super-admin ({', '.join(changed)}).")
                    )
                else:
                    self.stdout.write("Super-admin already present and correct.")
            else:
                User.objects.create_superuser(
                    email=email,
                    password=password,
                    first_name=options["first_name"],
                    last_name=options["last_name"],
                )
                self.stdout.write(self.style.SUCCESS(f"Created super-admin {email}."))
                if not password:
                    self.stdout.write(
                        self.style.WARNING(
                            "No password was set, so this account can only sign in with "
                            "a passkey. Register one from the sign-in page on "
                            f"https://{domain_name}/accounts/login/ — or re-run this "
                            "command with --password to add a fallback."
                        )
                    )

        self.stdout.write(self.style.SUCCESS("Bootstrap complete."))
