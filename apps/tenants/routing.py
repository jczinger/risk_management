"""
Choosing a church when every church shares one hostname.

The original design routed on the hostname: ``firstoac.vms.example.ca`` selected the
``firstoac`` schema, which django-tenants does out of the box. That needs a DNS entry
and a certificate per church. This module adds the alternative the operator asked for —
**one hostname for everybody, and the church is chosen by the address you sign in
with**.

How it works, and why this shape:

* Sign-in happens in the ``public`` schema, because at that point nobody knows which
  church the visitor belongs to. :func:`find_login_targets` searches public *and* every
  active church for the submitted address.
* On success the response carries a **signed cookie naming the schema**. Every later
  request is bound to that schema by :class:`apps.core.middleware.VMSTenantMiddleware`
  before anything else runs.
* Crucially the *session* still lives inside the church's own schema. That is what
  keeps the isolation guarantee in docs/SECURITY.md true: swapping the tenant cookie
  for another church's name does not carry your session with it, because the session
  row does not exist over there. You land back at the login page, not in someone
  else's data. The cookie selects a schema; it grants nothing.

The cookie is **host-only** (no ``domain`` attribute), so it is never sent to a church
subdomain. Hostname routing therefore still works untouched wherever a Domain row
exists, and the two schemes cannot fight over the same request.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from django.conf import settings
from django.core.signing import BadSignature, Signer
from django.db import connection
from django.urls import set_urlconf
from django_tenants.utils import get_public_schema_name, schema_context

logger = logging.getLogger("vms.tenants")

#: Names the schema the browser is currently signed in to. Signed, not encrypted —
#: a schema name is not a secret, but it must not be forgeable, or an unauthenticated
#: visitor could aim requests at an arbitrary schema.
TENANT_COOKIE_NAME = "vms_tenant"

_SIGNER_SALT = "vms.tenant-selection.v1"


def _signer() -> Signer:
    return Signer(salt=_SIGNER_SALT)


# ---------------------------------------------------------------------------
# The cookie
# ---------------------------------------------------------------------------


def sign_schema_name(schema_name: str) -> str:
    """The cookie value for ``schema_name``. Exposed so tests can forge a *valid* one."""
    return _signer().sign(schema_name)


def read_tenant_cookie(request) -> str | None:
    """Return the schema name the browser claims, or None if absent or tampered with."""
    raw = request.COOKIES.get(TENANT_COOKIE_NAME)
    if not raw:
        return None
    try:
        return _signer().unsign(raw)
    except BadSignature:
        # Either a forgery attempt or a SECRET_KEY rotation. Both are handled the
        # same way: ignore it and fall through to the login page.
        logger.warning("Discarded a tenant cookie with a bad signature")
        return None


def set_tenant_cookie(response, schema_name: str):
    """Pin this browser to ``schema_name`` for subsequent requests."""
    response.set_cookie(
        TENANT_COOKIE_NAME,
        sign_schema_name(schema_name),
        max_age=settings.SESSION_COOKIE_AGE,
        secure=getattr(settings, "SESSION_COOKIE_SECURE", False),
        httponly=True,
        samesite=getattr(settings, "SESSION_COOKIE_SAMESITE", "Lax"),
        # No `domain`: host-only, so it never leaks to a church subdomain.
    )
    return response


def clear_tenant_cookie(response):
    response.delete_cookie(
        TENANT_COOKIE_NAME,
        samesite=getattr(settings, "SESSION_COOKIE_SAMESITE", "Lax"),
    )
    return response


# ---------------------------------------------------------------------------
# Binding a schema to the current request
# ---------------------------------------------------------------------------


def resolve_tenant(schema_name: str):
    """
    Look up an active church by schema name, from the public schema.

    Returns None for the public schema itself, for an unknown name, and for a
    suspended church — the caller treats all three as "no tenant", which is what
    sends the visitor back to sign-in rather than into a schema they should not
    reach.
    """
    from .models import Tenant

    if not schema_name or schema_name == get_public_schema_name():
        return None

    with schema_context(get_public_schema_name()):
        return Tenant.objects.filter(schema_name=schema_name, is_active=True).first()


def bind_tenant(request, tenant) -> None:
    """
    Point the connection, the request and the URLconf at ``tenant``.

    Deliberately *not* a context manager. The binding has to outlive the view: the
    session is written during response processing, and it must land in the church's
    schema rather than wherever the request happened to start.

    The URLconf is set explicitly rather than through django-tenants'
    ``setup_url_routing``, which only *assigns* ``request.urlconf`` for the public
    schema and otherwise leaves it alone. That is fine at the top of the stack, where
    it starts unset — but sign-in switches public → tenant partway through a request,
    and there the stale public URLconf would survive. ``set_urlconf`` is what makes
    ``reverse()`` agree with the change for the rest of the request.
    """
    request.tenant = tenant
    connection.set_tenant(tenant)
    request.urlconf = settings.ROOT_URLCONF
    set_urlconf(request.urlconf)


def bind_public(request) -> None:
    """Point everything back at the public schema and the console URLconf."""
    connection.set_schema_to_public()
    request.tenant = connection.tenant
    request.urlconf = settings.PUBLIC_SCHEMA_URLCONF
    set_urlconf(request.urlconf)


# ---------------------------------------------------------------------------
# Finding which schema an address belongs to
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LoginTarget:
    """One place a submitted email address was found."""

    schema_name: str
    #: The Tenant row, or None when the match is the platform super-admin in public.
    tenant: object | None
    user_pk: int

    @property
    def is_public(self) -> bool:
        return self.tenant is None

    @property
    def label(self) -> str:
        return getattr(self.tenant, "name", "") or "the platform console"


def find_login_targets(email: str) -> list[LoginTarget]:
    """
    Every schema holding an active user with this address.

    There is no global index to consult, and that is by design: the blind index mixes
    the schema name into its key derivation precisely so a dump cannot be used to
    correlate one person across churches (see apps/core/blind_index.py). The cost is
    that this lookup has to visit each schema and recompute the hash under that
    schema's own salt. At district scale — tens of churches — that is a handful of
    indexed primary-key lookups, and it happens once per sign-in attempt, not per
    request.

    No decryption is involved: only ``email_index`` is compared, so this never needs a
    church's DEK.

    Ordered deterministically — public first, then churches by name — so a sign-in is
    reproducible rather than depending on row order.
    """
    from apps.core.blind_index import normalise_email

    from .models import Tenant

    normalised = normalise_email(email)
    if not normalised:
        return []

    public = get_public_schema_name()
    targets: list[LoginTarget] = []

    with schema_context(public):
        tenants = list(
            Tenant.objects.filter(is_active=True)
            .exclude(schema_name=public)
            .order_by("name", "schema_name")
        )
        user_pk = _find_user_pk(normalised)
        if user_pk is not None:
            targets.append(LoginTarget(public, None, user_pk))

    for tenant in tenants:
        with schema_context(tenant.schema_name):
            user_pk = _find_user_pk(normalised)
        if user_pk is not None:
            targets.append(LoginTarget(tenant.schema_name, tenant, user_pk))

    return targets


def _find_user_pk(normalised_email: str) -> int | None:
    """
    The active user with this address in the *currently bound* schema, if any.

    Must be called inside a ``schema_context``: ``email_index`` derives its key from
    ``connection.tenant.schema_name``, so calling it under the wrong schema silently
    computes a hash that matches nothing.
    """
    from apps.accounts.models import User
    from apps.core.blind_index import email_index

    return (
        User.objects.filter(email_index=email_index(normalised_email), is_active=True)
        .values_list("pk", flat=True)
        .first()
    )


def find_passkey_target(credential_id: str):
    """
    The schema holding an active passkey with this credential id.

    The mirror image of :func:`find_login_targets` for the passkey path. A
    discoverable-credential sign-in sends no address at all — the browser just offers a
    credential — so the only handle on "which church is this?" is the credential id
    itself. It is unique, opaque and plaintext, so searching for it across schemas
    leaks nothing that the assertion does not already carry.

    Returns a :class:`LoginTarget` whose ``user_pk`` owns the passkey, or None.
    """
    from apps.accounts.models import Passkey

    from .models import Tenant

    if not credential_id:
        return None

    public = get_public_schema_name()

    with schema_context(public):
        tenants = list(
            Tenant.objects.filter(is_active=True)
            .exclude(schema_name=public)
            .order_by("name", "schema_name")
        )
        owner = (
            Passkey.objects.filter(credential_id=credential_id, is_active=True)
            .values_list("user_id", flat=True)
            .first()
        )
        if owner is not None:
            return LoginTarget(public, None, owner)

    for tenant in tenants:
        with schema_context(tenant.schema_name):
            owner = (
                Passkey.objects.filter(credential_id=credential_id, is_active=True)
                .values_list("user_id", flat=True)
                .first()
            )
        if owner is not None:
            return LoginTarget(tenant.schema_name, tenant, owner)

    return None
