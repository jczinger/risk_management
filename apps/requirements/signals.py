"""
Keeps requirement instances in step with the org model.

A volunteer's requirement list is derived from their roles, so it has to be
recalculated whenever an assignment starts or ends, or a role's flags change. Doing
it with signals means no view can forget to.
"""

from __future__ import annotations

import logging

from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.org.models import Role, RoleAssignment, Volunteer

logger = logging.getLogger("vms.requirements")


@receiver(post_save, sender=RoleAssignment)
def resync_on_assignment_change(sender, instance: RoleAssignment, **kwargs):
    """Recalculate the volunteer's requirements when they take on or leave a role."""
    from .services import sync_volunteer_requirements

    # Deferred to commit so the assignment is visible to the queries the sync runs.
    transaction.on_commit(lambda: _safe_sync(instance.volunteer))


@receiver(post_save, sender=Volunteer)
def resync_on_volunteer_change(sender, instance: Volunteer, created: bool, **kwargs):
    """
    Recalculate when a volunteer's own details change.

    The date of birth is the reason: recording it for the first time is what reveals
    whether the criminal record check applies.
    """
    if created:
        # A brand-new volunteer has no roles yet, so there is nothing to derive.
        return
    transaction.on_commit(lambda: _safe_sync(instance))


@receiver(post_save, sender=Role)
def resync_on_role_flag_change(sender, instance: Role, created: bool, **kwargs):
    """
    Recalculate for everyone in a role whose flags changed.

    Ticking "handles personal information" on a role should immediately require the
    Confidentiality Agreement of everyone serving in it.
    """
    if created:
        return

    def _resync_role_holders():
        volunteers = Volunteer.objects.filter(
            assignments__role=instance, assignments__is_active=True, is_active=True
        ).distinct()
        for volunteer in volunteers:
            _safe_sync(volunteer)

    transaction.on_commit(_resync_role_holders)


def _safe_sync(volunteer: Volunteer) -> None:
    """
    Run the sync, logging rather than raising.

    A signal failure must not turn a successful role assignment into a 500 — the
    nightly sweep re-runs the same reconciliation for everyone, so a missed sync is
    self-healing within a day.
    """
    from .services import sync_volunteer_requirements

    try:
        sync_volunteer_requirements(volunteer, quiet=True)
    except Exception:  # noqa: BLE001
        logger.exception("Failed to resync requirements for volunteer %s", volunteer.pk)
