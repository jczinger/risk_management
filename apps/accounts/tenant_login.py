"""
Signing in when the church is not known until the address is typed.

On a church's own subdomain the schema is already bound by the time the login form is
submitted, and authentication is the ordinary Django call. On the **shared hostname**
it is not: the request arrives in the ``public`` schema, and the only clue to which
church the person belongs to is the address they just entered.

:func:`authenticate_across_schemas` closes that gap. It finds every schema holding
that address, tries the password in each, and — on success — leaves the connection
bound to the matching schema so the rest of the request (session included) happens
inside the right church.

See :mod:`apps.tenants.routing` for the cookie that carries the choice forward.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from django.contrib.auth import authenticate
from django.db import connection
from django_tenants.utils import get_public_schema_name, schema_context

from apps.tenants.routing import LoginTarget, bind_public, bind_tenant, find_login_targets

logger = logging.getLogger("vms.accounts")


@dataclass(frozen=True)
class Resolved:
    """A successful authentication, and where it happened."""

    user: object
    #: The schema that was switched to, or None when the request was already bound to
    #: the right one (the per-subdomain path, where nothing needed resolving).
    target: LoginTarget | None


def authenticate_across_schemas(request, email: str, password: str) -> Resolved | None:
    """
    Authenticate, resolving the church from the address when necessary.

    Returns None for every failure — no such address, wrong password, deactivated
    account, suspended church — because the sign-in form must not distinguish between
    them.

    On success the connection is left bound to the user's schema. That binding is
    intentional and must not be unwound by the caller: the session is written during
    response processing, and it belongs in the church's own schema.
    """
    if connection.schema_name != get_public_schema_name():
        # Already inside a church, via its own hostname. Nothing to resolve.
        user = authenticate(request, username=email, password=password)
        return Resolved(user, None) if user is not None else None

    return _resolve_from_public(request, email, password)


def _resolve_from_public(request, email: str, password: str) -> Resolved | None:
    targets = find_login_targets(email)

    if not targets:
        # No account anywhere. Still run one authentication attempt so the response
        # time matches a real address: Django's ModelBackend hashes the password
        # against a throwaway user when the lookup misses, and skipping that here
        # would turn the form into a timing oracle for which addresses exist.
        authenticate(request, username=email, password=password)
        return None

    matched: list[tuple[LoginTarget, object]] = []
    for target in targets:
        with schema_context(target.schema_name):
            user = authenticate(request, username=email, password=password)
        if user is not None:
            matched.append((target, user))

    if not matched:
        return None

    if len(matched) > 1:
        # The same address and the same password at two churches. Rare and almost
        # certainly a mistake, but it has to resolve to exactly one schema. Ordering
        # in find_login_targets is deterministic, so the choice is at least stable
        # rather than dependent on row order — and it is logged so the operator can
        # see it happened. Recorded in BUILD_NOTES.md as a known limitation.
        logger.warning(
            "Sign-in address matched %d schemas (%s); using %s",
            len(matched),
            ", ".join(t.schema_name for t, _ in matched),
            matched[0][0].schema_name,
        )

    target, _ = matched[0]

    if target.is_public:
        bind_public(request)
    else:
        bind_tenant(request, target.tenant)

    # Re-fetch inside the now-bound schema. The instance from the schema_context above
    # is correct, but re-reading it here means any later save() is unambiguously
    # writing to the schema the connection is actually pointing at.
    from .models import User

    user = User.objects.filter(pk=target.user_pk, is_active=True).first()
    if user is None:  # pragma: no cover - only reachable on a concurrent deactivation
        return None

    return Resolved(user, target)
