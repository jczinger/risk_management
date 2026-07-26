"""
Collapse ``Role.leadership`` from a three-way choice into a plain flag.

The old field offered Director / Secretary / none. The distinction never did anything:
the requirement engine only ever asked "is this a leadership role at all?"
(``applies_to = leadership``), and Director vs Secretary showed up in exactly one badge.
A church that wants the distinction can say so in the role's own name.

Existing rows are preserved: anything that was Director or Secretary becomes True.
"""

from django.db import migrations, models


def flag_existing_leadership_roles(apps, schema_editor):
    Role = apps.get_model("org", "Role")
    Role.objects.exclude(leadership="none").update(is_leadership=True)


def restore_leadership_choice(apps, schema_editor):
    """
    Reverse as far as the data allows.

    A flagged role becomes a Director, because the two original values cannot be told
    apart once collapsed. Recorded here rather than left implicit so anyone rolling back
    knows the Secretary label is gone for good.
    """
    Role = apps.get_model("org", "Role")
    Role.objects.filter(is_leadership=True).update(leadership="director")


class Migration(migrations.Migration):
    dependencies = [("org", "0001_initial")]

    operations = [
        migrations.AddField(
            model_name="role",
            name="is_leadership",
            field=models.BooleanField(
                default=False,
                db_index=True,
                verbose_name="leadership role",
                help_text=(
                    "Tick for directors, coordinators and other leadership positions. "
                    "They are screened exactly like any other volunteer (Build Spec §3); "
                    "this only lets requirements target leadership roles. It grants no "
                    "access to anything."
                ),
            ),
        ),
        migrations.RunPython(flag_existing_leadership_roles, restore_leadership_choice),
        migrations.RemoveField(model_name="role", name="leadership"),
    ]
