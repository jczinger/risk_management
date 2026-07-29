"""
Add the ``waiver_reversed`` audit action.

Choices only — no data changes and nothing to reverse. Existing entries keep their
actions, and the audit trail's filter dropdown is built from ``AuditAction.choices``, so
the new option appears there on its own.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='auditevent',
            name='action',
            field=models.CharField(choices=[('create', 'Created'), ('update', 'Updated'), ('deactivate', 'Deactivated'), ('reactivate', 'Reactivated'), ('status_change', 'Status changed'), ('waive', 'Waived'), ('waiver_reversed', 'Waiver reversed'), ('upload', 'Document uploaded'), ('download', 'Document viewed'), ('login', 'Signed in'), ('login_failed', 'Sign-in failed'), ('logout', 'Signed out'), ('crc_recorded', 'Criminal record check recorded'), ('disqualified', 'Permanently disqualified'), ('override', 'Leadership override recorded'), ('key_backup', 'Encryption key backed up'), ('notify', 'Notification sent'), ('seed', 'Template seeded')], db_index=True, max_length=32),
        ),
    ]
