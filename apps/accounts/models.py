"""
Accounts for the two kinds of human who use VMS.

* **Screening admins** — live in their church's tenant schema. All of them hold
  equal permissions within that church (Build Spec §2).
* **The platform super-admin** — lives in the ``public`` schema, provisions
  churches, and does not browse church data day to day.

Both are the same model class; which schema the row lands in is what distinguishes
them, because ``apps.accounts`` is listed in both SHARED_APPS and TENANT_APPS.

Email handling deserves a note. The address is *encrypted*, per PRD §5 and the
acceptance criterion that a ``pg_dump`` show no readable email. Since login has to
find a user by address, a keyed blind index (``email_index``) sits alongside it and
carries the uniqueness constraint. See :mod:`apps.core.blind_index`.
"""

from __future__ import annotations

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from apps.core.blind_index import email_index, normalise_email
from apps.core.fields import EncryptedCharField, EncryptedEmailField


class UserManager(BaseUserManager):
    """
    Manager that looks users up through the blind index.

    ``get_by_natural_key`` is what Django's ModelBackend calls, so overriding it is
    what makes an encrypted username field workable.
    """

    use_in_migrations = False  # The blind index needs a key; migrations must not.

    def get_by_natural_key(self, username: str):
        return self.get(email_index=email_index(username or ""))

    def _create(self, email: str, password: str | None, **extra):
        email = normalise_email(email)
        if not email:
            raise ValueError("An email address is required.")
        user = self.model(email=email, **extra)
        # Set explicitly rather than relying on save(): the index must be present
        # before the unique constraint is checked.
        user.email_index = email_index(email)
        if password:
            user.set_password(password)
        else:
            # Passwordless-by-design account: a passkey is the only way in. Django
            # renders an unusable hash, which set_password(None) produces.
            user.set_unusable_password()
        user.full_clean(exclude=["password"], validate_unique=False)
        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str | None = None, **extra):
        extra.setdefault("is_staff", False)
        extra.setdefault("is_superuser", False)
        return self._create(email, password, **extra)

    def create_superuser(self, email: str, password: str | None = None, **extra):
        """
        Create a platform super-admin.

        Intended for the ``public`` schema. Called by ``createsuperuser`` and by the
        ``bootstrap_superadmin`` management command.
        """
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        extra.setdefault("is_active", True)
        if not extra["is_staff"] or not extra["is_superuser"]:
            raise ValueError("A super-admin must have is_staff and is_superuser set.")
        return self._create(email, password, **extra)


class User(AbstractBaseUser, PermissionsMixin):
    """A screening admin, or the platform super-admin."""

    # Encrypted; not queryable. Use email_index for lookups.
    email = EncryptedEmailField(
        verbose_name="email address",
        max_length=254,
        help_text="Used to sign in and to receive renewal reminders.",
    )
    # Keyed hash of the normalised address. Carries the uniqueness guarantee.
    email_index = models.CharField(max_length=64, unique=True, editable=False, db_index=True)

    # Names are plaintext by design (PRD §5) so lists can be sorted and searched.
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)

    is_active = models.BooleanField(
        default=True,
        help_text="Unset instead of deleting, so the audit trail keeps resolving.",
    )
    is_staff = models.BooleanField(
        default=False,
        help_text="Access to the Django admin. Only the platform super-admin has this.",
    )

    date_joined = models.DateTimeField(default=timezone.now)
    last_login_at = models.DateTimeField(null=True, blank=True)

    # --- Second factor state ---------------------------------------------
    #
    # TOTP is the fallback path's second factor, required whenever a password is
    # used. A passkey already proves possession of the device, so a passkey login
    # does not additionally prompt for TOTP.
    totp_secret = EncryptedCharField(
        max_length=64,
        blank=True,
        default="",
        editable=False,
        verbose_name="TOTP secret",
        help_text="Base32 shared secret. Encrypted; only ever read to verify a code.",
    )
    totp_confirmed_at = models.DateTimeField(null=True, blank=True, editable=False)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]
    EMAIL_FIELD = "email"

    class Meta:
        ordering = ("last_name", "first_name")
        verbose_name = "user"
        verbose_name_plural = "users"

    def __str__(self):
        return self.get_full_name() or self.email or f"user #{self.pk}"

    def save(self, *args, **kwargs):
        """
        Keep ``email_index`` in lockstep with ``email``.

        The index is only recomputed when the address itself is being written. That matters
        for more than speed: the index derivation mixes in the current schema name, so
        recomputing it during an unrelated partial save — ``save(update_fields=["last_login"])``
        while bound to a different schema, say — would write an index derived from the wrong
        salt and make the account unfindable at sign-in.
        """
        update_fields = kwargs.get("update_fields")
        touching_email = update_fields is None or "email" in set(update_fields)

        if touching_email:
            self.email = normalise_email(self.email) if self.email else self.email
            expected = email_index(self.email or "")
            if self.email_index != expected:
                self.email_index = expected
                if update_fields is not None:
                    kwargs["update_fields"] = set(update_fields) | {"email_index"}

        return super().save(*args, **kwargs)

    def clean(self):
        super().clean()
        if not normalise_email(self.email or ""):
            raise ValidationError({"email": "An email address is required."})

    def get_full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()

    def get_short_name(self) -> str:
        return self.first_name or self.get_full_name()

    # -- Capability flags used by templates and views ---------------------

    @property
    def has_passkey(self) -> bool:
        return self.passkeys.filter(is_active=True).exists()

    @property
    def has_totp(self) -> bool:
        return bool(self.totp_secret) and self.totp_confirmed_at is not None

    @property
    def is_passwordless(self) -> bool:
        """True when the only way into this account is a passkey."""
        return not self.has_usable_password()

    @property
    def can_remove_last_passkey(self) -> bool:
        """
        Guard against locking oneself out.

        Removing the final passkey is only safe if a password *and* a confirmed TOTP
        device remain as a way back in.
        """
        return self.has_usable_password() and self.has_totp


class Passkey(models.Model):
    """
    One registered WebAuthn credential (a passkey).

    Stores only what the WebAuthn verification needs. The credential's private key
    never leaves the user's device, so nothing here is a secret that would matter in
    a database dump — but the label a user gives it can be identifying, so it is
    encrypted.
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="passkeys")

    # Base64url credential id as returned by the authenticator. Queryable by
    # necessity: it is the lookup key during assertion, and it is opaque random
    # bytes rather than personal information.
    credential_id = models.CharField(max_length=512, unique=True, editable=False, db_index=True)
    public_key = models.BinaryField(editable=False)

    # Replay protection. Some authenticators always report 0, which is legal.
    sign_count = models.PositiveBigIntegerField(default=0)

    label = EncryptedCharField(
        max_length=100,
        blank=True,
        default="",
        help_text="A name for this device, e.g. 'work laptop'.",
    )
    transports = models.CharField(max_length=100, blank=True, editable=False)
    is_discoverable = models.BooleanField(default=True, editable=False)

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    last_used_at = models.DateTimeField(null=True, blank=True, editable=False)

    class Meta:
        ordering = ("-created_at",)
        verbose_name = "passkey"

    def __str__(self):
        return f"Passkey for {self.user_id} ({self.credential_id[:12]}…)"


class WebAuthnChallenge(models.Model):
    """
    A pending WebAuthn challenge.

    Held server-side rather than in the session so that the registration and
    assertion ceremonies work identically for an anonymous visitor (login) and a
    signed-in user (enrolment), and so a challenge can be single-use.
    """

    PURPOSE_REGISTER = "register"
    PURPOSE_AUTHENTICATE = "authenticate"
    PURPOSE_CHOICES = [
        (PURPOSE_REGISTER, "Register a passkey"),
        (PURPOSE_AUTHENTICATE, "Authenticate with a passkey"),
    ]

    challenge = models.BinaryField(editable=False)
    purpose = models.CharField(max_length=16, choices=PURPOSE_CHOICES)
    # Null for a discoverable-credential login, where the user is not yet known.
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, null=True, blank=True, related_name="webauthn_challenges"
    )
    session_key = models.CharField(max_length=64, blank=True, db_index=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False, db_index=True)
    consumed_at = models.DateTimeField(null=True, blank=True, editable=False)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.purpose} challenge {self.pk}"

    @property
    def is_expired(self) -> bool:
        return (timezone.now() - self.created_at).total_seconds() > 300

    @property
    def is_usable(self) -> bool:
        return self.consumed_at is None and not self.is_expired

    def consume(self) -> None:
        self.consumed_at = timezone.now()
        self.save(update_fields=["consumed_at"])
