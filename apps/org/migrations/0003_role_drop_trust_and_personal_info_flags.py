"""
Drop ``Role.handles_personal_info`` and ``Role.is_position_of_trust``.

Every role in this system is both, so neither was a meaningful choice — and offering
them as ticks invited a church to untick one and screen someone less than the policy
requires. See BUILD_NOTES.md §1.14.

No data migration: the columns carried no information that survives the change. What
*did* need migrating is the requirement definitions that targeted these flags, handled
in ``requirements.0002``, which this migration depends on so it cannot run first and
leave the engine pointing at columns that no longer exist.
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("org", "0002_role_leadership_is_a_flag"),
        ("requirements", "0002_retarget_universal_requirements"),
    ]

    operations = [
        migrations.RemoveField(model_name="role", name="handles_personal_info"),
        migrations.RemoveField(model_name="role", name="is_position_of_trust"),
    ]
