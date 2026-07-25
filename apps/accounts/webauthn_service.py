"""
WebAuthn (passkey) ceremonies.

Passkeys are the **primary** sign-in method (Build Spec §1). A passkey proves
possession of the device and, with user verification, that the person unlocked it —
so a passkey login is not additionally prompted for TOTP. The password path is the
fallback, and *that* is what requires a second factor.

Two ceremonies, each in two halves:

* **Registration** — ``begin_registration`` issues a challenge, the browser asks the
  authenticator to create a credential, ``finish_registration`` verifies it and stores
  the public key.
* **Authentication** — ``begin_authentication`` issues a challenge,
  ``finish_authentication`` verifies the signature against a stored public key.

Challenges are stored server-side (:class:`~apps.accounts.models.WebAuthnChallenge`),
single-use, and expire after five minutes. They are not kept in the session because
the login ceremony starts before there is a user to attach a session to, and because
single-use is easier to guarantee with a row than with a session key.

Discoverable credentials (resident keys) are requested, which is what makes
"click sign in, touch the sensor" work with no username typed first.
"""

from __future__ import annotations

import base64
import json
import logging

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .models import Passkey, User, WebAuthnChallenge

logger = logging.getLogger("vms.accounts")


class WebAuthnError(Exception):
    """A ceremony could not be completed."""


def expected_origin(request) -> str:
    """
    The origin the browser will report.

    Built from the request rather than configured, so it is correct for each tenant
    subdomain. ``SECURE_PROXY_SSL_HEADER`` makes ``is_secure()`` reflect the scheme the
    *browser* used, not the plain HTTP hop from Nginx Proxy Manager.
    """
    scheme = "https" if request.is_secure() else "http"
    return f"{scheme}://{request.get_host()}"


def rp_id() -> str:
    """
    The Relying Party ID.

    Set to the base domain so a passkey registered on one church's subdomain still
    works if that church is later moved, and so the platform domain and tenant
    subdomains share credentials for the same person.
    """
    return settings.WEBAUTHN_RP_ID


def _user_handle(user: User) -> bytes:
    """
    Stable, opaque user handle.

    The authenticator stores this and may show it to the user, so it must not be the
    email address — that would leak the address to any device the passkey syncs to.
    The primary key plus the schema is stable and meaningless outside VMS.
    """
    from django.db import connection

    schema = getattr(connection, "schema_name", "public")
    return f"{schema}:{user.pk}".encode()


def _prune_challenges() -> None:
    """Drop challenges that are spent or expired. Cheap, and keeps the table small."""
    cutoff = timezone.now() - timezone.timedelta(minutes=10)
    WebAuthnChallenge.objects.filter(created_at__lt=cutoff).delete()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def begin_registration(request, user: User) -> str:
    """Return the JSON options for ``navigator.credentials.create()``."""
    _prune_challenges()

    existing = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(p.credential_id))
        for p in user.passkeys.filter(is_active=True)
    ]

    options = generate_registration_options(
        rp_id=rp_id(),
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=_user_handle(user),
        user_name=user.email,
        user_display_name=user.get_full_name() or user.email,
        # Registering the same authenticator twice is refused by the browser rather
        # than silently creating a duplicate credential.
        exclude_credentials=existing,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    WebAuthnChallenge.objects.create(
        challenge=options.challenge,
        purpose=WebAuthnChallenge.PURPOSE_REGISTER,
        user=user,
        session_key=request.session.session_key or "",
    )

    return options_to_json(options)


def finish_registration(request, user: User, credential_json: str, label: str = "") -> Passkey:
    """Verify a registration response and store the credential."""
    challenge = (
        WebAuthnChallenge.objects.filter(
            user=user, purpose=WebAuthnChallenge.PURPOSE_REGISTER, consumed_at__isnull=True
        )
        .order_by("-created_at")
        .first()
    )
    if challenge is None or not challenge.is_usable:
        raise WebAuthnError("That registration attempt has expired. Please start again.")

    try:
        verified = verify_registration_response(
            credential=credential_json,
            expected_challenge=bytes(challenge.challenge),
            expected_origin=expected_origin(request),
            expected_rp_id=rp_id(),
            require_user_verification=False,
        )
    except Exception as exc:  # noqa: BLE001 - library raises many specific types
        logger.warning("Passkey registration failed for user %s: %s", user.pk, exc)
        raise WebAuthnError(f"This passkey could not be registered: {exc}") from exc
    finally:
        challenge.consume()

    credential_id = bytes_to_base64url(verified.credential_id)

    if Passkey.objects.filter(credential_id=credential_id).exists():
        raise WebAuthnError("That passkey is already registered.")

    transports = ""
    try:
        parsed = json.loads(credential_json)
        transports = ",".join(parsed.get("response", {}).get("transports", []) or [])[:100]
    except (ValueError, AttributeError):
        pass

    passkey = Passkey.objects.create(
        user=user,
        credential_id=credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count or 0,
        label=(label or "").strip()[:100],
        transports=transports,
    )
    logger.info("Passkey registered for user %s", user.pk)
    return passkey


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def begin_authentication(request, user: User | None = None) -> str:
    """
    Return the JSON options for ``navigator.credentials.get()``.

    With no ``user``, no ``allowCredentials`` list is sent, so the browser offers
    whichever discoverable passkey it holds for this Relying Party — the passwordless
    "just sign in" flow.
    """
    _prune_challenges()

    allow = []
    if user is not None:
        allow = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(p.credential_id))
            for p in user.passkeys.filter(is_active=True)
        ]
        if not allow:
            raise WebAuthnError("This account has no passkey registered.")

    options = generate_authentication_options(
        rp_id=rp_id(),
        allow_credentials=allow or None,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    if not request.session.session_key:
        request.session.create()

    WebAuthnChallenge.objects.create(
        challenge=options.challenge,
        purpose=WebAuthnChallenge.PURPOSE_AUTHENTICATE,
        user=user,
        session_key=request.session.session_key,
    )

    return options_to_json(options)


def finish_authentication(request, credential_json: str) -> User:
    """
    Verify an assertion and return the authenticated user.

    Raises :class:`WebAuthnError` for every failure mode with a message safe to show —
    deliberately not distinguishing "no such credential" from "bad signature", so the
    page cannot be used to enumerate who has a passkey.
    """
    challenge = (
        WebAuthnChallenge.objects.filter(
            purpose=WebAuthnChallenge.PURPOSE_AUTHENTICATE,
            session_key=request.session.session_key or "",
            consumed_at__isnull=True,
        )
        .order_by("-created_at")
        .first()
    )
    if challenge is None or not challenge.is_usable:
        raise WebAuthnError("That sign-in attempt has expired. Please try again.")

    try:
        parsed = json.loads(credential_json)
        credential_id = parsed["id"]
    except (ValueError, KeyError, TypeError) as exc:
        challenge.consume()
        raise WebAuthnError("The browser sent an unreadable passkey response.") from exc

    passkey = Passkey.objects.filter(credential_id=credential_id, is_active=True).first()
    if passkey is None:
        challenge.consume()
        raise WebAuthnError("Sign-in failed. That passkey is not registered here.")

    try:
        verified = verify_authentication_response(
            credential=credential_json,
            expected_challenge=bytes(challenge.challenge),
            expected_origin=expected_origin(request),
            expected_rp_id=rp_id(),
            credential_public_key=bytes(passkey.public_key),
            credential_current_sign_count=passkey.sign_count,
            require_user_verification=False,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Passkey assertion failed for credential %s: %s", credential_id[:12], exc)
        raise WebAuthnError("Sign-in failed. Please try again.") from exc
    finally:
        challenge.consume()

    # Some authenticators legitimately always report 0; only a *decrease* from a
    # non-zero counter indicates a cloned credential.
    if verified.new_sign_count:
        passkey.sign_count = verified.new_sign_count
    passkey.last_used_at = timezone.now()
    passkey.save(update_fields=["sign_count", "last_used_at"])

    user = passkey.user
    if not user.is_active:
        raise WebAuthnError("This account has been deactivated.")

    return user


def remove_passkey(user: User, passkey_id: int) -> None:
    """
    Remove a passkey, refusing to lock the user out.

    If this is their last passkey and they have no working password + TOTP fallback,
    removing it would leave no way in at all.
    """
    passkey = user.passkeys.filter(pk=passkey_id, is_active=True).first()
    if passkey is None:
        raise ValidationError("That passkey was not found on your account.")

    remaining = user.passkeys.filter(is_active=True).exclude(pk=passkey.pk).count()
    if remaining == 0 and not user.can_remove_last_passkey:
        raise ValidationError(
            "This is your only passkey, and you have no password with an "
            "authenticator app set up as a fallback. Add one of those first, or "
            "register a second passkey — otherwise you would be locked out."
        )

    passkey.is_active = False
    passkey.save(update_fields=["is_active"])


def b64_snippet(value: bytes) -> str:
    """Short, log-safe rendering of a credential id."""
    return base64.urlsafe_b64encode(value)[:12].decode("ascii")
