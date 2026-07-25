from django.apps import AppConfig


class ReportingConfig(AppConfig):
    """Compliance reports and the audit viewer."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.reporting"
    label = "reporting"
    verbose_name = "Reporting"
