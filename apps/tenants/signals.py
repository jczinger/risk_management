"""Provisioning observability."""

import logging

from django.dispatch import receiver
from django_tenants.signals import post_schema_sync, schema_migrated

logger = logging.getLogger("vms.tenants")


@receiver(post_schema_sync)
def log_schema_created(sender, tenant, **kwargs):
    """Record schema creation. Deliberately logs no church contact details."""
    logger.info("Tenant schema created: %s", tenant.schema_name)


@receiver(schema_migrated)
def log_schema_migrated(sender, schema_name, **kwargs):
    logger.info("Tenant schema migrated: %s", schema_name)
