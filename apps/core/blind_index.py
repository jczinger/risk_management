"""
Blind indexes: exact-match lookup over an encrypted value.

The problem: an admin signs in with an email address, so the app must be able to
find a user *by* email. But randomized AES-GCM ciphertext never matches itself, and
the acceptance criteria require that a ``pg_dump`` expose no readable address.

The solution: alongside the encrypted address, store a keyed hash of its normalised
form. Equality lookups hit the hash; the hash is not reversible without the key,
which lives in the environment rather than the database.

Properties and their limits:

* Exact match only. No prefix, substring, ordering or range queries.
* Deterministic *within a schema*, because the derivation mixes in the schema name.
  So a dump cannot be used to correlate the same person across two churches.
* Offline guessing is possible for a low-entropy value if the attacker also steals
  ``PLATFORM_MASTER_KEY`` — at which point they could decrypt everything anyway.
  Against the actual threat model (a database dump alone) the hash reveals nothing.

Only use this where an exact lookup is genuinely required. Everything else stays
either plaintext-by-design or encrypted-and-unsearchable.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.db import connection

from .crypto import get_master_key

_HKDF_SALT = b"vms:blind-index:v1"


def _index_key(domain: str) -> bytes:
    """
    Derive the HMAC key for one index.

    ``domain`` names the index (e.g. ``"user-email"``), and the current schema is
    folded in so the same address yields different hashes in different churches.
    """
    schema = getattr(getattr(connection, "tenant", None), "schema_name", "public")
    info = f"{domain}|{schema}".encode()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=info,
    ).derive(get_master_key())


def normalise_email(email: str) -> str:
    """
    Canonical form for email indexing.

    Lowercased and stripped. The local part is *not* otherwise altered — dots and
    plus-addressing are meaningful at some providers, so two spellings are treated
    as two addresses.
    """
    return (email or "").strip().lower()


def email_index(email: str, domain: str = "user-email") -> str:
    """Return the blind index for an email address, or ``""`` for an empty input."""
    normalised = normalise_email(email)
    if not normalised:
        return ""
    return blind_index(normalised, domain)


def blind_index(value: str, domain: str) -> str:
    """Keyed hash of ``value``, hex encoded (64 chars)."""
    return hmac.new(_index_key(domain), value.encode("utf-8"), hashlib.sha256).hexdigest()
