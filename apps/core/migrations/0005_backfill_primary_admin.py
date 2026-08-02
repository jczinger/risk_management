"""
Create the two built-in access levels, and make every existing administrator a Primary
Admin.

**This has to be a migration, not a management command, and the reason is the whole
risk of this change.** ``has_capability`` fails closed: an account with no grant can do
nothing at all. So in the window between ``migrate`` finishing and a backfill command
being run by hand, every administrator at every church would be locked out of
everything — including the screen they would need in order to fix it. Only a migration
guarantees the ordering, because ``migrate_schemas --tenant`` runs it in the same pass
that created the tables.

Two traps are worth naming, because both are silent:

* ``UserManager.use_in_migrations`` is ``False`` — "the blind index needs a key;
  migrations must not." So this uses the historical model, and reads **only** ``pk``.
  Touching ``email`` would attempt a decrypt with no key available.
* This also runs against a brand-new schema during ``provision_church``, *before* that
  church's first administrator exists. It grants nothing there, and provisioning does
  its own grant afterwards. Both paths have to be idempotent, and they are:
  ``grant_primary_admin`` skips anyone who already holds a level.

Reverse is a no-op. Removing the grants would lock every church out, which is not a
sensible thing for a downgrade to do; drop the tables in ``0004`` instead.
"""

from __future__ import annotations

from django.db import migrations


# Written out here rather than imported from ``apps.core.seed``, because a data
# migration records what happened at a point in history and must keep working even after
# the live seeder changes. The two will drift, and that is correct: a church created
# today gets these values, and ``seed_access_levels`` will not revise them afterwards.
#
# Both levels are created, not just the one being granted. Otherwise every church that
# already exists would come out of this deploy with nowhere to put a department admin,
# and the feature would need an operator to run a command before anyone could use it.
LEVELS = (
    {
        "slug": "primary-admin",
        "name": "Primary Admin",
        "description": (
            "Full access to this church, and the reviewer of anyone on a limited access "
            "level."
        ),
        "is_scoped": False,
        "capabilities": (
            "can_view_volunteers",
            "can_edit_volunteers",
            "can_manage_assignments",
            "can_record_screening",
            "can_record_crc",
            "can_manage_org",
            "can_manage_requirements",
            "can_view_audit",
            "can_manage_users",
        ),
    },
    {
        "slug": "department-admin",
        "name": "Department Admin",
        "description": (
            "The screening work for particular departments. Sees only volunteers who "
            "have served in those departments. Everything they record is affirmed by a "
            "Primary Admin."
        ),
        "is_scoped": True,
        "capabilities": (
            "can_view_volunteers",
            "can_edit_volunteers",
            "can_manage_assignments",
            "can_record_screening",
            "can_record_crc",
        ),
    },
)

ALL_CAPABILITIES = (
    "can_view_volunteers",
    "can_edit_volunteers",
    "can_manage_assignments",
    "can_record_screening",
    "can_record_crc",
    "can_manage_org",
    "can_manage_requirements",
    "can_view_audit",
    "can_manage_users",
)


def backfill(apps, schema_editor):
    AccessLevel = apps.get_model("core", "AccessLevel")
    UserAccessGrant = apps.get_model("core", "UserAccessGrant")
    # Historical model: a plain manager, no blind index, no encryption.
    User = apps.get_model("accounts", "User")

    levels = {}
    for spec in LEVELS:
        existing = AccessLevel.objects.filter(slug=spec["slug"]).first()
        if existing is not None:
            levels[spec["slug"]] = existing
            continue
        granted = set(spec["capabilities"])
        levels[spec["slug"]] = AccessLevel.objects.create(
            slug=spec["slug"],
            name=spec["name"],
            description=spec["description"],
            is_scoped=spec["is_scoped"],
            is_builtin=True,
            **{field: field in granted for field in ALL_CAPABILITIES},
        )

    level = levels["primary-admin"]
    already = set(UserAccessGrant.objects.values_list("user_id", flat=True))
    UserAccessGrant.objects.bulk_create(
        [
            UserAccessGrant(
                user_id=pk,
                access_level=level,
                granted_by_display="access levels introduced",
            )
            # Only `pk` — see the module docstring.
            for pk in User.objects.values_list("pk", flat=True)
            if pk not in already
        ]
    )


def noop(apps, schema_editor):
    """Deliberately does nothing. See the module docstring."""


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0004_access_levels"),
        # The historical accounts model must exist before this reads from it. Both apps
        # migrate per-schema, so the ordering holds inside every church.
        ("accounts", "0002_login_links_no_passwords"),
    ]

    operations = [migrations.RunPython(backfill, noop)]
