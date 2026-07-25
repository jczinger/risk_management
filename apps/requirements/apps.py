from django.apps import AppConfig


class RequirementsConfig(AppConfig):
    """The screening requirement engine."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.requirements"
    label = "requirements"
    verbose_name = "Requirements"

    def ready(self):
        # Signal handlers live in a submodule; importing here wires them up.
        from . import signals  # noqa: F401
