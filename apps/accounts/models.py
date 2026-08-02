"""
Accounts for the two kinds of human who use VMS.

* **Screening admins** — live in their church's tenant schema. What each of them may do
  is set by their **access level** (:class:`apps.core.models.AccessLevel`). Build Spec §2
  used to say they all held equal permissions; amended 2026-07-29 at the owner's
  direction, and what used to be true of everybody is now true of a *Primary Admin*. See
  BUILD_NOTES §1.21.
* **The platform super-admin** — lives in the ``public`` schema, provisions
  churches, and does not browse church data day to day.

Both are the same model class; which schema the row lands in is what distinguishes
them, because ``apps.accounts`` is listed in both SHARED_APPS and TENANT_APPS.

Email handling deserves a note. The address is *encrypted*, per PRD §5 and the
acceptance criterion that a ``pg_dump`` show no readable email. Since login has to
find a user by address, a keyed blind index (``email_index``) sits alongside it and
carries the uniqueness constraint. See :mod:`apps.core.blind_index`.

Nobody here has a password. Every account is created with an unusable one and signs in
with a passkey; :class:`LoginLink` covers the two moments a passkey is not available
yet — the first sign-in, and recovery after losing one. ``AbstractBaseUser`` is still
the base class because it supplies ``last_login`` and the session-auth plumbing, so the
``password`` column survives holding Django's unusable marker. See BUILD_NOTES §1.20.
"""

from __future__ import annotations

import logging

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from apps.core.blind_index import email_index, normalise_email
from apps.core.fields import EncryptedCharField, EncryptedEmailField

logger = logging.getLogger("vms.accounts")


def _warn_if_password(password: str | None) -> None:
    """Say so loudly when a caller still thinks passwords work."""
    if password:
        logger.warning(
            "A password was supplied when creating a user and has been ignored; "
            "accounts sign in with a passkey."
        )


class UserManager(BaseUserManager):
    """
    Manager that looks users up through the blind index.

    ``get_by_natural_key`` is what Django's ModelBackend calls, so overriding it is
    what makes an encrypted username field workable.
    """

    use_in_migrations = False  # The blind index needs a key; migrations must not.

    def get_by_natural_key(self, username: str):
        return self.get(email_index=email_index(username or ""))

    def _create(self, email: str, **extra):
        email = normalise_email(email)
        if not email:
            raise ValueError("An email address is required.")
        user = self.model(email=email, **extra)
        # Set explicitly rather than relying on save(): the index must be present
        # before the unique constraint is checked.
        user.email_index = email_index(email)
        # Every account is passkey-only. Django renders an unusable hash, which nothing
        # can ever match, so the password column exists but is never a way in.
        user.set_unusable_password()
        user.full_clean(exclude=["password"], validate_unique=False)
        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str | None = None, **extra):
        """
        Create a screening admin.

        ``password`` is accepted and **ignored**: Django's own plumbing passes it
        positionally in places we do not control. Rejecting it would turn a no-op into a
        crash; silently honouring it would put a working password back into a system
        that no longer has a password sign-in to check it against.
        """
        _warn_if_password(password)
        extra.setdefault("is_staff", False)
        extra.setdefault("is_superuser", False)
        return self._create(email, **extra)

    def create_superuser(self, email: str, password: str | None = None, **extra):
        """
        Create a platform super-admin.

        Intended for the ``public`` schema. Called by ``createsuperuser`` and by the
        ``bootstrap_superadmin`` management command. ``password`` is ignored, as above —
        use ``manage.py issue_magic_link`` to get the new account signed in once.
        """
        _warn_if_password(password)
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        extra.setdefault("is_active", True)
        if not extra["is_staff"] or not extra["is_superuser"]:
            raise ValueError("A super-admin must have is_staff and is_superuser set.")
        return self._create(email, **extra)


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

    @property
    def display_name(self) -> str:
        """The name for audit labels and bylines — never blank, names are optional."""
        return self.get_full_name() or "administrator"

    # -- Capability flags used by templates and views ---------------------

    @property
    def has_passkey(self) -> bool:
        return self.passkeys.filter(is_active=True).exists()


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


class LinkPurpose(models.TextChoices):
    INVITE = "invite", "First sign-in"
    RECOVERY = "recovery", "Account recovery"


class LoginLink(models.Model):
    """
    A single-use link that signs somebody in once, so they can enrol a passkey.

    This is the only way into an account that does not involve a passkey, and it exists
    for exactly two moments: the first sign-in after an account is created, and the
    recovery that follows a lost passkey or a lost device.

    Only the SHA-256 of the secret is stored. A database dump therefore yields no usable
    link, which matters more here than for most tables — a live link is a bearer token
    for an administrator account. The hash needs no encryption: it is derived from 256
    bits of randomness and identifies nobody, the same argument that leaves
    ``Passkey.credential_id`` in plaintext.

    Expiry is recorded on the row as well as being baked into the signed payload. The two
    are set from the same value, so they cannot disagree; keeping the row copy means an
    administrator reading the table can see when a link dies, and a clock change on the
    signer cannot silently extend one.
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="login_links")

    #: SHA-256 hex of the secret handed out in the URL. Never the secret itself.
    token_hash = models.CharField(max_length=64, unique=True, editable=False, db_index=True)
    purpose = models.CharField(max_length=16, choices=LinkPurpose.choices)

    #: The administrator who issued it. Null when it came from the command line.
    issued_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    expires_at = models.DateTimeField(editable=False)
    consumed_at = models.DateTimeField(null=True, blank=True, editable=False)

    class Meta:
        ordering = ("-created_at",)
        verbose_name = "sign-in link"

    def __str__(self):
        return f"{self.get_purpose_display()} link for {self.user_id}"

    @property
    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at

    @property
    def is_usable(self) -> bool:
        return self.consumed_at is None and not self.is_expired

    def consume(self) -> None:
        self.consumed_at = timezone.now()
        self.save(update_fields=["consumed_at"])
