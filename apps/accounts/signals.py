"""
Authentication auditing for events Django raises itself.

The views audit their own successes and failures, but ``user_login_failed`` also fires
for anything that authenticates outside those views (a management command, the Django
admin), so it is worth catching centrally.
"""

from __future__ import annotations

import logging

from django.contrib.auth.signals import user_login_failed
from django.dispatch import receiver

logger = logging.getLogger("vms.accounts")


@receiver(user_login_failed)
def log_failed_login(sender, credentials=None, request=None, **kwargs):
    """
    Log a failed authentication without recording the credentials.

    Django passes the attempted credentials; they are deliberately not logged. An
    attempted address is unverified personal information, and putting it in the log
    would undo the point of encrypting the column.
    """
    from apps.core.audit import _client_ip  # noqa: PLC0415 - avoids an import cycle

    ip = _client_ip(request) if request is not None else "unknown"
    logger.info("Authentication failed from %s", ip)
