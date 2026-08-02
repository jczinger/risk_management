"""
The two access levels every church starts with.

**Primary Admin** is what every screening admin was before 2026-07-29: everything,
church-wide, and the reviewer of everybody else's work. **Department Admin** is the
first scoped level — the screening work for their own departments, reviewed by a
Primary Admin. See BUILD_NOTES §1.21.

Modelled on :func:`apps.requirements.seed.seed_default_template`, including the rule
that function learned the hard way: **there is no second pass.** An existing level is
left entirely alone, its capabilities included. That matters more here than it does for
requirements. There, re-seeding over an admin's edit was a workflow annoyance; here it
would silently re-grant a capability a church had deliberately removed, which is a
security regression that nobody would see happen.

Matched on ``slug`` rather than ``name``, because a church renaming "Department Admin"
to "Ministry Leader" is expected, and a seeder matching on the display name would then
cheerfully create a second one.
"""

from __future__ import annotations

import logging

from .access import on_public_schema
from .models import AccessLevel

logger = logging.getLogger("vms.core")


#: Capabilities held by each built-in level. Anything absent is False, so adding a new
#: capability to ``AccessLevel`` does not quietly widen a level that already exists.
BUILTIN_LEVELS: tuple[dict, ...] = (
    {
        "slug": AccessLevel.PRIMARY_ADMIN,
        "name": "Primary Admin",
        "description": (
            "Full access to this church: every volunteer, every department, the audit "
            "trail, and the administrators list. Primary Admins also review and affirm "
            "the work of anyone on a limited access level."
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
        "slug": AccessLevel.DEPARTMENT_ADMIN,
        "name": "Department Admin",
        "description": (
            "The screening work for particular departments. Sees only volunteers who "
            "have served in those departments, and can add volunteers, assign them to "
            "roles, and record their screening. Everything they record is affirmed by a "
            "Primary Admin. Does not include the audit trail, the church's requirement "
            "definitions, creating departments, or managing administrators."
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


def seed_access_levels() -> int:
    """
    Create any missing built-in access level in the current tenant schema.

    Returns how many were created. Safe to re-run, and re-running never modifies an
    existing row — see the module docstring for why that rule is absolute here.

    Must be called inside a tenant schema. Unlike the requirement template, which a
    church may decline, this is unconditional: a church with no access levels has no
    administrator who can do anything.
    """
    created = 0

    for spec in BUILTIN_LEVELS:
        if AccessLevel.objects.filter(slug=spec["slug"]).exists():
            continue

        granted = set(spec["capabilities"])
        unknown = granted - set(AccessLevel.CAPABILITY_FIELDS)
        if unknown:
            # A capability was renamed on the model but not here. Fail loudly rather
            # than silently seeding a level that is missing it.
            raise ValueError(f"Unknown capabilities in the {spec['slug']} seed: {sorted(unknown)}")

        AccessLevel.objects.create(
            slug=spec["slug"],
            name=spec["name"],
            description=spec["description"],
            is_scoped=spec["is_scoped"],
            is_builtin=True,
            **{field: field in granted for field in AccessLevel.CAPABILITY_FIELDS},
        )
        created += 1

    if created:
        logger.info("Seeded %d access levels", created)
    return created


def primary_admin_level() -> AccessLevel:
    """
    The church's Primary Admin level, seeding it first if somehow absent.

    Used by provisioning and by the backfill, both of which need the level to exist
    before they can grant it and neither of which has anywhere sensible to fail.
    """
    level = AccessLevel.objects.filter(slug=AccessLevel.PRIMARY_ADMIN).first()
    if level is None:
        seed_access_levels()
        level = AccessLevel.objects.get(slug=AccessLevel.PRIMARY_ADMIN)
    return level


def grant_primary_admin(user_id: int, *, granted_by_display: str = "") -> bool:
    """
    Make one administrator a Primary Admin, unless they already hold a level.

    Returns whether a grant was created. Never overwrites an existing grant: a church
    that has deliberately put someone on a limited level must not have that undone by
    provisioning, a re-run backfill, or the repair command.

    Does nothing in the ``public`` schema, and that is correct rather than defensive.
    The platform super-admin holds no access level by design — the console is gated on
    ``is_superuser`` and knows nothing about capabilities — and ``core_useraccessgrant``
    does not exist there to hold one anyway.
    """
    from .models import UserAccessGrant

    if on_public_schema():
        return False

    if UserAccessGrant.objects.filter(user_id=user_id).exists():
        return False

    UserAccessGrant.objects.create(
        user_id=user_id,
        access_level=primary_admin_level(),
        granted_by_display=granted_by_display,
    )
    return True
