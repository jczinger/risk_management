"""
Shared base for commands that walk every church's schema.

Both church-maintenance commands take the same ``--schema`` argument and resolve it
the same way; keeping that in one place means the next such command cannot resolve
schemas subtly differently.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django_tenants.utils import get_public_schema_name, schema_context


class TenantSchemasCommand(BaseCommand):
    """A command that runs per church: ``--schema`` narrows it to one."""

    def add_arguments(self, parser):
        parser.add_argument(
            "--schema",
            default="",
            help="Only look at this church. Omit to cover every active church.",
        )

    def _schemas(self, schema: str) -> list[str]:
        from apps.tenants.models import Tenant

        public = get_public_schema_name()
        with schema_context(public):
            names = list(
                Tenant.objects.filter(is_active=True)
                .exclude(schema_name=public)
                .order_by("name", "schema_name")
                .values_list("schema_name", flat=True)
            )
        if not schema:
            return names
        if schema not in names:
            raise CommandError(f"No active church uses the schema '{schema}'.")
        return [schema]
