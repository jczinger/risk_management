from django.apps import AppConfig


class TenantsConfig(AppConfig):
    """Public-schema church registry and provisioning."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.tenants"
    label = "tenants"
    verbose_name = "Tenants"

    def ready(self):
        # Signal handlers live in a submodule; importing here wires them up.
        from . import signals  # noqa: F401
