"""
TOTP second factor for the password fallback path.

The password route is the fallback (Build Spec §1), and it is the route that needs a
second factor — a passkey already binds the login to a device the user unlocked. So:
password alone is never sufficient; password + TOTP is.

The shared secret is stored encrypted on the user row and read only to verify a code.
"""

from __future__ import annotations

import base64
import io

import pyotp
import qrcode
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone

#: Accept the adjacent time steps as well, so a slightly-off device clock still works.
#: One step either side of a 30-second window is the usual compromise.
VALID_WINDOW = 1


def generate_secret() -> str:
    """A fresh base32 TOTP secret."""
    return pyotp.random_base32()


def provisioning_uri(user, secret: str) -> str:
    """
    The ``otpauth://`` URI an authenticator app scans.

    The issuer is the app name plus the church, so a person administering two churches
    sees two clearly distinguishable entries.
    """
    from django.db import connection

    tenant = getattr(connection, "tenant", None)
    church = getattr(tenant, "name", "") if tenant else ""
    issuer = f"VMS — {church}" if church and church != "VMS Platform" else "VMS"

    return pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=issuer)


def qr_data_uri(uri: str) -> str:
    """
    Render the provisioning URI as an inline PNG data URI.

    Inline rather than a served image so the secret never appears in a URL, a proxy
    log, or the browser's image cache as a separately fetchable resource.
    """
    image = qrcode.make(uri, box_size=6, border=2)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def verify_code(secret: str, code: str) -> bool:
    """Check a six-digit code against the secret."""
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit():
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=VALID_WINDOW)


def confirm_enrolment(user, secret: str, code: str) -> None:
    """
    Complete TOTP enrolment.

    Requires a working code first, so nobody can lock themselves behind a secret their
    app never actually stored.
    """
    if not verify_code(secret, code):
        raise ValidationError(
            "That code was not accepted. Check the time on your device and try the "
            "current code."
        )
    user.totp_secret = secret
    user.totp_confirmed_at = timezone.now()
    user.save(update_fields=["totp_secret", "totp_confirmed_at"])


def disable_totp(user) -> None:
    """
    Turn off TOTP, refusing if it would leave the account with no second factor.

    A password-only account is not acceptable, so TOTP can only be removed if a passkey
    exists or the password itself is removed.
    """
    if user.has_usable_password() and not user.has_passkey:
        raise ValidationError(
            "Removing your authenticator app would leave this account protected by a "
            "password alone. Register a passkey first."
        )
    user.totp_secret = ""
    user.totp_confirmed_at = None
    user.save(update_fields=["totp_secret", "totp_confirmed_at"])


#: Session key holding the half-authenticated user id between the password step and
#: the TOTP step. Deliberately not a real login — ``request.user`` stays anonymous
#: until the second factor succeeds.
PENDING_SESSION_KEY = "vms_totp_pending_user"
PENDING_STARTED_KEY = "vms_totp_pending_at"

#: How long the second-factor step stays open.
PENDING_TIMEOUT_SECONDS = getattr(settings, "VMS_TOTP_PENDING_TIMEOUT", 300)
