"""
Celery application.

The beat schedule is static and lives here rather than in the database: with
schema-per-tenant there is no single place a DB-backed schedule could live, and
the nightly jobs fan out over tenants themselves.
"""

import os

from celery import Celery
from celery.schedules import crontab
from django.conf import settings

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.prod")

app = Celery("vms")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


@app.on_after_configure.connect
def setup_periodic_tasks(sender, **_kwargs):
    hour = settings.VMS_NIGHTLY_HOUR

    # One nightly pass per tenant: recompute every requirement's status and
    # expiry, apply the turning-18 CRC activation, then send that tenant's
    # single reminder digest.
    sender.add_periodic_task(
        crontab(hour=hour, minute=0),
        nightly_compliance_sweep.s(),
        name="nightly compliance sweep (all tenants)",
    )


@app.task(name="config.nightly_compliance_sweep")
def nightly_compliance_sweep():
    """Fan the nightly work out across every active tenant."""
    # Imported lazily so the module is importable before Django apps are ready.
    from apps.core.tasks import sweep_all_tenants

    return sweep_all_tenants()
