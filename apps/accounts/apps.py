from django.apps import AppConfig


class AccountsConfig(AppConfig):
    """Screening-admin accounts, passkeys and TOTP."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.accounts"
    label = "accounts"
    verbose_name = "Accounts"

    def ready(self):
        # Signal handlers live in a submodule; importing here wires them up.
        from . import signals  # noqa: F401
