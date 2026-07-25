"""
Application-level encryption for VMS.

Threat model (PRD §5, Build Spec §6): the primary concern is a **database dump**.
Transparent disk/tablespace encryption does not help there, because a dump is
produced by an authenticated client and comes out as plaintext. So sensitive
columns are encrypted by the application before they are ever handed to Postgres.

Key hierarchy
-------------
    PLATFORM_MASTER_KEY  (env var, 32 bytes, never in the database)
        wraps
    tenant DEK           (32 bytes, one per church, stored wrapped on Tenant)
        encrypts
    field ciphertext     (per-value random nonce)

The DEK is also handed to the church admin once at provisioning (forced backup
step) and escrowed by the platform operator in Keeper Security. That is a
deliberate trade-off recorded in PRD §5: the operator can technically decrypt a
tenant's data, in exchange for a guarantee that no church can lose its own
records.

Cipher choice
-------------
AES-256-GCM with a fresh 12-byte random nonce per value. Randomized, i.e. the
same plaintext encrypts differently every time, so ciphertext leaks nothing —
which is exactly why encrypted fields are NOT queryable. Anything the app has to
search, sort, filter or report on must stay plaintext; see
``apps.core.fields`` and the field-by-field split in the PRD.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

# --- Format constants -------------------------------------------------------

DEK_SIZE = 32  # AES-256
NONCE_SIZE = 12  # GCM standard; 96-bit nonces are the fast path
TOKEN_PREFIX = "v1"
TOKEN_SEP = "."

# Additional authenticated data. Binds a ciphertext to its purpose so a wrapped
# DEK can never be fed to the field decryptor or vice versa. Bumping the version
# here would require a re-encryption migration.
_AAD_FIELD = b"vms:v1:field"
_AAD_DEK = b"vms:v1:dek"


class EncryptionError(Exception):
    """Base class for encryption failures."""


class DecryptionError(EncryptionError):
    """
    Ciphertext could not be authenticated and decrypted.

    In practice this means one of: the wrong PLATFORM_MASTER_KEY, a DEK restored
    from the wrong escrow entry, or tampered-with data. All three are serious, so
    this is raised loudly rather than being swallowed into a blank value.
    """


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------


def generate_dek() -> bytes:
    """Return a fresh 32-byte data-encryption key."""
    return secrets.token_bytes(DEK_SIZE)


def encode_key(key: bytes) -> str:
    """Render key material for display/escrow (base64, padded)."""
    return base64.b64encode(key).decode("ascii")


def decode_key(encoded: str) -> bytes:
    """Parse base64 key material, rejecting anything that isn't 32 bytes."""
    try:
        key = base64.b64decode(encoded.strip(), validate=True)
    except Exception as exc:  # noqa: BLE001 - any parse failure is the same answer
        raise EncryptionError("Key is not valid base64.") from exc
    if len(key) != DEK_SIZE:
        raise EncryptionError(f"Key must be {DEK_SIZE} bytes; got {len(key)}.")
    return key


def key_fingerprint(key: bytes) -> str:
    """
    Short, non-reversible identifier for a key.

    Lets an admin confirm the key they backed up matches the one in use, and lets
    the audit trail record *which* key was involved, without ever storing the key.
    """
    return hashlib.sha256(b"vms:fingerprint:" + key).hexdigest()[:16]


def get_master_key() -> bytes:
    """
    Return the platform master key from the environment.

    Absence is a hard error: booting without it would mean either storing tenant
    DEKs in the clear or silently failing to encrypt.
    """
    raw = getattr(settings, "PLATFORM_MASTER_KEY", "") or ""
    if not raw:
        raise ImproperlyConfigured(
            "PLATFORM_MASTER_KEY is not set. Generate one with "
            "`python manage.py generate_key` and add it to .env. Without it, no "
            "tenant key can be unwrapped."
        )
    try:
        return decode_key(raw)
    except EncryptionError as exc:
        raise ImproperlyConfigured(f"PLATFORM_MASTER_KEY is malformed: {exc}") from exc


# ---------------------------------------------------------------------------
# Primitive seal / open
# ---------------------------------------------------------------------------


def _seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def _open(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) <= NONCE_SIZE:
        raise DecryptionError("Ciphertext is too short to contain a nonce and tag.")
    nonce, body = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, body, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "Authentication failed. The key in use does not match the key this "
            "data was encrypted with, or the data has been altered."
        ) from exc


# ---------------------------------------------------------------------------
# DEK wrapping (stored on the Tenant row in the public schema)
# ---------------------------------------------------------------------------


def wrap_dek(dek: bytes, master_key: bytes | None = None) -> bytes:
    """Encrypt a tenant DEK under the platform master key."""
    if len(dek) != DEK_SIZE:
        raise EncryptionError(f"DEK must be {DEK_SIZE} bytes; got {len(dek)}.")
    return _seal(master_key or get_master_key(), dek, _AAD_DEK)


def unwrap_dek(wrapped: bytes, master_key: bytes | None = None) -> bytes:
    """Recover a tenant DEK from its wrapped form."""
    if not wrapped:
        raise DecryptionError("Tenant has no wrapped encryption key stored.")
    return _open(master_key or get_master_key(), bytes(wrapped), _AAD_DEK)


# ---------------------------------------------------------------------------
# Field-level encryption
# ---------------------------------------------------------------------------


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """Seal raw bytes (used for uploaded document contents)."""
    return _seal(key, plaintext, _AAD_FIELD)


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    """Open bytes sealed by :func:`encrypt_bytes`."""
    return _open(key, bytes(blob), _AAD_FIELD)


def encrypt_text(plaintext: str, key: bytes) -> str:
    """
    Seal a string into a printable token: ``v1.<base64url nonce+ct+tag>``.

    The token is stored in a plain ``text`` column, so a ``pg_dump`` shows only
    the version tag and base64 noise.
    """
    blob = _seal(key, plaintext.encode("utf-8"), _AAD_FIELD)
    body = base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")
    return f"{TOKEN_PREFIX}{TOKEN_SEP}{body}"


def decrypt_text(token: str, key: bytes) -> str:
    """Open a token produced by :func:`encrypt_text`."""
    if not is_ciphertext(token):
        raise DecryptionError("Value is not a recognised VMS ciphertext token.")
    body = token.split(TOKEN_SEP, 1)[1]
    padding = "=" * (-len(body) % 4)
    try:
        blob = base64.urlsafe_b64decode(body + padding)
    except Exception as exc:  # noqa: BLE001
        raise DecryptionError("Ciphertext token is not valid base64.") from exc
    return _open(key, blob, _AAD_FIELD).decode("utf-8")


def is_ciphertext(value: object) -> bool:
    """
    True if ``value`` looks like a VMS ciphertext token.

    Used to tell an already-encrypted value from a plaintext one, which keeps
    fields idempotent when a model instance is saved twice without reloading.
    """
    return isinstance(value, str) and value.startswith(TOKEN_PREFIX + TOKEN_SEP)
