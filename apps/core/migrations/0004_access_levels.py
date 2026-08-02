"""
Access levels, and the grant that ties one to an administrator.

Runs **only** in tenant schemas: ``apps.core`` is in TENANT_APPS alone, so
``migrate_schemas --shared`` skips it. That is what lets ``departments`` reference
``org_department``, which exists in a tenant schema and nowhere else.

Note what is *not* here: any dependency on ``AUTH_USER_MODEL``. The administrator is
referenced by a plain unique integer, not a foreign key, because a relation to
``accounts.User`` would give ``User`` a reverse accessor that Django's cascade
collector walks on every delete — including in ``public``, where this table does not
exist. See the ``UserAccessGrant`` docstring for the full reasoning.
"""

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_audit_sign_in_links'),
        ('org', '0003_role_drop_trust_and_personal_info_flags'),
    ]

    operations = [
        migrations.CreateModel(
            name='AccessLevel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('name', models.CharField(max_length=150, unique=True)),
                ('slug', models.SlugField(editable=False, max_length=60, unique=True)),
                ('description', models.TextField(blank=True, help_text='Shown to whoever is choosing an access level for an administrator.')),
                ('is_scoped', models.BooleanField(default=True, help_text='When set, someone holding this level sees only volunteers who have served in the departments they are given. When unset, they see the whole church.', verbose_name='limited to particular departments')),
                ('is_builtin', models.BooleanField(default=False, editable=False, help_text='Seeded by VMS. Cannot be removed, though its capabilities can be changed.')),
                ('is_active', models.BooleanField(default=True, help_text='Unset instead of deleting, so administrators who held it still resolve.')),
                ('can_view_volunteers', models.BooleanField(default=True, help_text='Read the volunteer file, the dashboard, reports and stored documents.', verbose_name='see volunteer records')),
                ('can_edit_volunteers', models.BooleanField(default=False, help_text='Create a volunteer, correct their details, and mark them as no longer serving.', verbose_name='add and edit volunteers')),
                ('can_manage_assignments', models.BooleanField(default=False, help_text='Put a volunteer into a role and end an assignment. On a limited level this also adds that volunteer to what the holder can see, permanently.', verbose_name='assign volunteers to ministry roles')),
                ('can_record_screening', models.BooleanField(default=False, help_text='Mark requirements complete, record documents, waive a requirement, and record a leadership override.', verbose_name='record screening progress')),
                ('can_record_crc', models.BooleanField(default=False, help_text="Record a check's outcome, and the convictions behind a Not Clear result. Recording a disqualifying conviction is permanent and cannot be undone.", verbose_name='record criminal record checks')),
                ('can_manage_org', models.BooleanField(default=False, help_text="Add and edit the church's departments and the roles within them.", verbose_name='create departments and ministry roles')),
                ('can_manage_requirements', models.BooleanField(default=False, help_text='Change what this church requires of its volunteers, and of which roles.', verbose_name='define requirements')),
                ('can_view_audit', models.BooleanField(default=False, help_text='The trail and the sent-email log. Cannot be combined with a level limited to particular departments: an audit entry does not record a department, so there is nothing to limit it by.', verbose_name='read the audit trail')),
                ('can_manage_users', models.BooleanField(default=False, help_text='Invite and deactivate administrators, and edit access levels. Nobody can grant an access level wider than their own.', verbose_name='manage administrators and access levels')),
            ],
            options={
                'verbose_name': 'access level',
                'verbose_name_plural': 'access levels',
                'ordering': ('is_scoped', 'name'),
            },
        ),
        migrations.CreateModel(
            name='UserAccessGrant',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user_id', models.IntegerField(db_index=True, help_text="The administrator's primary key in this schema's accounts_user table.", unique=True)),
                ('granted_by_display', models.CharField(blank=True, max_length=150)),
                ('access_level', models.ForeignKey(help_text='What this administrator may do.', on_delete=django.db.models.deletion.PROTECT, related_name='grants', to='core.accesslevel')),
                ('departments', models.ManyToManyField(blank=True, help_text='Only used when the access level is limited to particular departments. A limited level with no departments selected sees nothing.', related_name='access_grants', to='org.department')),
            ],
            options={
                'verbose_name': 'access grant',
                'verbose_name_plural': 'access grants',
            },
        ),
    ]
