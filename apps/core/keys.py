"""
Resolves *which* data-encryption key applies to the work in front of us.

Encrypted model fields never take a key argument — they ask this module. That
keeps a single choke point for key selection, so there is exactly one place where
"whose data is this?" is decided.

The key comes from ``connection.tenant``, which django-tenants populates from the
request hostname (web) or from ``tenant_context()`` (Celery, management commands).
Touching an encrypted field with no tenant in scope is a bug, and raises.
"""

from __future__ import annotations

import contextlib
import hashlib
import threading

from django.db import connection

from .crypto import DecryptionError, unwrap_dek

# Unwrapping is an AES operation per call, and encrypted fields are touched in
# loops (a compliance report decrypts hundreds of values). Cache the unwrapped
# DEK per process, keyed by schema and validated against a digest of the wrapped
# bytes so a re-keyed tenant is never served a stale key.
_cache: dict[str, tuple[str, bytes]] = {}
_cache_lock = threading.Lock()

# Set by override_key(); used by tests and by the provisioning flow, which holds a
# brand-new DEK that is not yet readable from connection.tenant.
_override = threading.local()


class NoTenantKeyError(RuntimeError):
    """No tenant DEK is available in the current execution context."""


def _digest(wrapped: bytes) -> str:
    return hashlib.sha256(bytes(wrapped)).hexdigest()


def get_current_key() -> bytes:
    """
    Return the DEK for the schema in scope.

    Raises :class:`NoTenantKeyError` when nothing is bound or the schema has no key —
    better a loud failure than silently writing one church's data under another's key.

    Note that the ``public`` schema has a key too. It stores no church data, but it does
    hold the platform super-admin's account, whose email address is encrypted like
    everyone else's; ``bootstrap_superadmin`` assigns it.
    """
    forced = getattr(_override, "key", None)
    if forced is not None:
        return forced

    tenant = getattr(connection, "tenant", None)
    if tenant is None:
        raise NoTenantKeyError(
            "No tenant is bound to this connection, so no encryption key can be "
            "resolved. Wrap the operation in django_tenants.utils.tenant_context()."
        )

    schema = getattr(tenant, "schema_name", None) or getattr(connection, "schema_name", None)
    if not schema:
        raise NoTenantKeyError("The bound tenant has no schema name.")

    wrapped = getattr(tenant, "dek_wrapped", None)

    # django-tenants binds a lightweight FakeTenant for schema_context(), which carries
    # only the schema name. In that case fall back to the cache, then to the registry.
    if not wrapped:
        cached = _cache.get(schema)
        if cached is not None:
            return cached[1]
        wrapped = _lookup_wrapped_key(schema)

    if not wrapped:
        raise NoTenantKeyError(
            f"Schema '{schema}' has no encryption key stored, so encrypted fields "
            "cannot be read or written. If this is a new deployment, run "
            "`manage.py bootstrap_superadmin`; if it is a church, its key is missing "
            "and must be restored from escrow."
        )

    digest = _digest(wrapped)
    cached = _cache.get(schema)
    if cached is not None and cached[0] == digest:
        return cached[1]

    dek = unwrap_dek(bytes(wrapped))
    with _cache_lock:
        _cache[schema] = (digest, dek)
    return dek


def _lookup_wrapped_key(schema_name: str) -> bytes | None:
    """
    Read a schema's wrapped key from the registry in the public schema.

    ``tenants_tenant`` lives in ``public``, which is always on the search path, so this
    resolves from inside a tenant schema too. Raw SQL rather than the ORM to keep this
    free of any import-order dependency on the apps registry — this runs from inside a
    model field.
    """
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT dek_wrapped FROM public.tenants_tenant WHERE schema_name = %s",
            [schema_name],
        )
        row = cursor.fetchone()

    if not row or not row[0]:
        return None
    return bytes(row[0])


def has_current_key() -> bool:
    """True when :func:`get_current_key` would succeed. Never raises."""
    try:
        get_current_key()
    except (NoTenantKeyError, DecryptionError):
        return False
    return True


@contextlib.contextmanager
def override_key(key: bytes | None):
    """
    Force a specific DEK for the duration of the block.

    Used by tenant provisioning (the DEK exists in memory before the Tenant row is
    readable) and by tests. Restores the previous value on exit, including on error.
    """
    previous = getattr(_override, "key", None)
    _override.key = key
    try:
        yield
    finally:
        _override.key = previous


def forget_cached_keys(schema_name: str | None = None) -> None:
    """Drop cached DEKs. Call after re-keying a tenant, and between tests."""
    with _cache_lock:
        if schema_name is None:
            _cache.clear()
        else:
            _cache.pop(schema_name, None)
