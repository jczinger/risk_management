from django.apps import AppConfig


class OrgConfig(AppConfig):
    """Departments, roles and volunteer records."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.org"
    label = "org"
    verbose_name = "Org"
