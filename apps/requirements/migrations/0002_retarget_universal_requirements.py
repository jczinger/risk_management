"""
Retarget requirements that pointed at the two role flags being removed.

``applies_to = personal_info`` and ``applies_to = trust`` matched roles by
``Role.handles_personal_info`` / ``Role.is_position_of_trust``. Both flags are gone —
every role is now treated as both — so those definitions become ``all``, which is what
they had come to mean in practice.

This must run **before** ``org.0003`` drops the columns, otherwise the requirement
engine would spend the gap unable to match a role it is still asked about. The
dependency below enforces the order.

Widening the target means volunteers who were not previously covered will pick these
requirements up. That is the point of the change, and it happens on the next
reconcile — the nightly sweep, or ``sync_volunteer_requirements`` on the next edit of a
volunteer.
"""

from django.db import migrations, models

RETIRED = {"personal_info", "trust"}


def retarget_to_all_roles(apps, schema_editor):
    Definition = apps.get_model("requirements", "RequirementDefinition")
    Definition.objects.filter(applies_to__in=RETIRED).update(applies_to="all")


def noop_reverse(apps, schema_editor):
    """
    Not reversible in any meaningful way.

    Once retargeted there is no record of which definitions were "personal information"
    and which were "positions of trust", and the role flags they read are gone too.
    Leaving them as ``all`` on the way back is the honest outcome; a church that wants
    the distinction again would re-target the definitions by hand.
    """


class Migration(migrations.Migration):
    dependencies = [("requirements", "0001_initial")]

    operations = [
        migrations.RunPython(retarget_to_all_roles, noop_reverse),
        migrations.AlterField(
            model_name="requirementdefinition",
            name="applies_to",
            field=models.CharField(
                choices=[
                    ("all", "Everyone"),
                    ("specific", "Only the selected roles"),
                    ("leadership", "Roles flagged as leadership"),
                ],
                default="all",
                max_length=16,
            ),
        ),
    ]
