"""
Scheduled work.

One nightly sweep, fanned out over churches. Per church, in order:

1. Reconcile every volunteer's requirement list against their current roles and age.
2. Activate the criminal record check for anyone who has turned 18.
3. Recompute every requirement's status against today's date.
4. Send that church's single reminder digest.

The order matters: activation must precede the status recompute, or a newly activated
requirement with a past deadline would not be marked overdue until the following night.

One church failing must not stop the others, so each is wrapped individually. A church
that fails is logged and picked up by the next run.
"""

from __future__ import annotations

import datetime
import logging

from celery import shared_task
from django.utils import timezone
from django_tenants.utils import get_public_schema_name, tenant_context

from apps.core import audit

logger = logging.getLogger("vms.tasks")


def sweep_all_tenants(as_of: datetime.date | None = None) -> dict:
    """Run the nightly sweep for every active church. Returns a per-church summary."""
    from apps.tenants.models import Tenant

    as_of = as_of or timezone.localdate()
    public = get_public_schema_name()
    results: dict[str, dict] = {}

    tenants = Tenant.objects.filter(is_active=True).exclude(schema_name=public)

    for tenant in tenants:
        try:
            results[tenant.schema_name] = sweep_tenant(tenant, as_of=as_of)
        except Exception:  # noqa: BLE001 - one church must not take down the rest
            logger.exception("Nightly sweep failed for tenant %s", tenant.schema_name)
            results[tenant.schema_name] = {"error": True}

    logger.info("Nightly sweep complete over %d church(es)", len(results))
    return results


def sweep_tenant(tenant, as_of: datetime.date | None = None) -> dict:
    """Run the nightly sweep for one church, inside its schema."""
    from apps.notifications.services import process_tenant_reminders
    from apps.org.models import Volunteer
    from apps.requirements.services import (
        activate_turning_18_checks,
        recompute_all_statuses,
        sync_volunteer_requirements,
    )

    as_of = as_of or timezone.localdate()

    with tenant_context(tenant), audit.acting_as(audit.Actor.system("nightly job")):
        synced = 0
        for volunteer in Volunteer.objects.active().iterator(chunk_size=200):
            result = sync_volunteer_requirements(volunteer, as_of=as_of, quiet=True)
            synced += result["created"] + result["updated"] + result["retired"]

        activated = activate_turning_18_checks(as_of)
        recomputed = recompute_all_statuses(as_of)
        reminders = process_tenant_reminders(tenant, as_of)

    summary = {
        "instances_changed": synced,
        "crc_activated_on_18": len(activated),
        "statuses_recomputed": recomputed,
        **reminders,
    }
    logger.info("Sweep %s: %s", tenant.schema_name, summary)
    return summary


@shared_task(name="apps.core.tasks.nightly_sweep")
def nightly_sweep(as_of_iso: str | None = None) -> dict:
    """
    Celery entry point for the nightly sweep.

    ``as_of_iso`` exists so the sweep can be replayed for a specific date when
    diagnosing a missed reminder.
    """
    as_of = datetime.date.fromisoformat(as_of_iso) if as_of_iso else None
    return sweep_all_tenants(as_of)


@shared_task(name="apps.core.tasks.sweep_one_tenant")
def sweep_one_tenant(schema_name: str, as_of_iso: str | None = None) -> dict:
    """Sweep a single church, for manual re-runs."""
    from apps.tenants.models import Tenant

    tenant = Tenant.objects.get(schema_name=schema_name)
    as_of = datetime.date.fromisoformat(as_of_iso) if as_of_iso else None
    return sweep_tenant(tenant, as_of=as_of)
