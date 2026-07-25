from django.apps import AppConfig


class NotificationsConfig(AppConfig):
    """Renewal reminders and the email provider."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.notifications"
    label = "notifications"
    verbose_name = "Notifications"
