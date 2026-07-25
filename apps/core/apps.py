from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Shared primitives: encryption, audit trail, base models."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core"
    label = "core"
    verbose_name = "Core"
