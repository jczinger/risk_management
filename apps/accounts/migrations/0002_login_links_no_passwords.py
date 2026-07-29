"""
Passkeys only, with a single-use emailed link as the way in and back.

**This migration is one-way.** It removes every TOTP secret and replaces every password
hash with Django's unusable marker. Neither can be reconstructed, so ``reverse`` restores
the columns but not their contents — an account that had a password before will not have
one afterwards, which is the point of the change rather than a shortcoming of it.

Runs once in ``public`` and once in every church schema, because ``apps.accounts`` is in
both SHARED_APPS and TENANT_APPS.
"""

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


def make_every_password_unusable(apps, schema_editor):
    """
    Overwrite each stored hash with an unusable marker — **a distinct one per row.**

    The obvious version of this, ``.update(password=make_password(None))``, is wrong in
    a way that is easy to miss: it writes one generated value to every row. Django
    derives a session's ``_auth_user_hash`` from the user's ``password`` field, so
    identical passwords mean identical session hashes, and a session belonging to user
    5 at one church would then validate as user 5 at another. That is precisely the
    cross-tenant hole the signed tenant cookie is designed not to open (see
    :mod:`apps.tenants.routing`). ``make_password(None)`` per row keeps each one
    distinct — 40 random characters behind the ``!`` prefix.

    ``update()`` on a queryset, rather than ``save()``, because ``User.save()``
    recomputes the schema-salted ``email_index`` and this migration runs in every
    schema.
    """
    from django.contrib.auth.hashers import make_password

    User = apps.get_model("accounts", "User")
    for pk in User.objects.values_list("pk", flat=True):
        User.objects.filter(pk=pk).update(password=make_password(None))


def noop(apps, schema_editor):
    """Nothing to undo. The hashes and secrets are gone for good."""


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="LoginLink",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("token_hash", models.CharField(db_index=True, editable=False, max_length=64, unique=True)),
                (
                    "purpose",
                    models.CharField(
                        choices=[("invite", "First sign-in"), ("recovery", "Account recovery")],
                        max_length=16,
                    ),
                ),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("expires_at", models.DateTimeField(editable=False)),
                ("consumed_at", models.DateTimeField(blank=True, editable=False, null=True)),
                (
                    "issued_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="accounts.user",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="login_links",
                        to="accounts.user",
                    ),
                ),
            ],
            options={
                "verbose_name": "sign-in link",
                "ordering": ("-created_at",),
            },
        ),
        migrations.RemoveField(model_name="user", name="totp_secret"),
        migrations.RemoveField(model_name="user", name="totp_confirmed_at"),
        migrations.RunPython(make_every_password_unusable, noop),
    ]
