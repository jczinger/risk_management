"""
Encrypted model fields.

All of them store a ``v1.<base64>`` token in an ordinary ``text`` column, so a
``pg_dump`` of the database reveals nothing but the version tag and noise. The key
comes from :mod:`apps.core.keys` — the field never takes one.

Consequences of randomized encryption, which callers must design around:

* **Not queryable.** ``filter(email="x@y.ca")`` cannot match, because the same
  address encrypts differently every time. Ordering and ``icontains`` are equally
  meaningless. Anything that needs to be searched, sorted or reported on stays
  plaintext — that split is specified field-by-field in the PRD §5.
* **Not indexable** in any useful way, so these fields carry no db_index.
* **~1.4x storage** plus 28 bytes of nonce/tag per value.

Empty values pass through unencrypted. ``NULL`` stays ``NULL`` and ``""`` stays
``""``, which keeps ``blank=True`` semantics and ``__isnull`` / ``__exact=""``
filtering working. This leaks only the distinction "set vs not set", which the app
already exposes through requirement statuses.
"""

from __future__ import annotations

import datetime

from django.core.exceptions import ValidationError
from django.db import models

from .crypto import decrypt_text, encrypt_text, is_ciphertext
from .keys import get_current_key


class EncryptedFieldMixin:
    """
    Turns any text-backed field into a transparently encrypted one.

    Encryption happens in ``get_prep_value`` (on the way to the database) and
    decryption in ``from_db_value`` (on the way back), so model code, forms and
    templates all deal in ordinary Python values.
    """

    # Ciphertext is always text, regardless of what the logical type is.
    def db_type(self, connection):  # noqa: D102
        return "text"

    def get_internal_type(self):  # noqa: D102
        # Report as TextField so Django's lookups/migrations treat it as text.
        return "TextField"

    # -- Python value <-> stored string --------------------------------------

    def to_storage_string(self, value) -> str:
        """Serialise the Python value to the string that will be encrypted."""
        return str(value)

    def from_storage_string(self, value: str):
        """Rebuild the Python value from the decrypted string."""
        return value

    # -- Django field plumbing ----------------------------------------------

    def get_prep_value(self, value):
        if value is None:
            return None
        # Re-saving a model instance must not double-encrypt.
        if is_ciphertext(value):
            return value
        if value == "":
            return ""
        return encrypt_text(self.to_storage_string(value), get_current_key())

    def from_db_value(self, value, expression, connection):
        if value is None or value == "":
            return value
        if not is_ciphertext(value):
            # Pre-encryption rows, or a value written by something that bypassed
            # the field. Hand it back as-is rather than failing the whole query.
            return self.from_storage_string(value)
        return self.from_storage_string(decrypt_text(value, get_current_key()))

    def to_python(self, value):
        if value is None or value == "":
            return value
        if is_ciphertext(value):
            return self.from_storage_string(decrypt_text(value, get_current_key()))
        return self.from_storage_string(value)

    def value_to_string(self, obj):
        """Serialise for dumpdata — emits *plaintext*, so treat dumps as sensitive."""
        value = self.value_from_object(obj)
        return "" if value is None else self.to_storage_string(value)


class EncryptedTextField(EncryptedFieldMixin, models.TextField):
    """Long free text: notes, reference-check content, medical details."""


class EncryptedCharField(EncryptedFieldMixin, models.TextField):
    """
    Short strings: address lines, phone numbers, emergency contacts.

    Declared as ``text`` in the database because a ``max_length`` sized for the
    plaintext would truncate the ciphertext. ``max_length`` is still honored as a
    *form/validation* limit on the plaintext.
    """

    def __init__(self, *args, max_length: int | None = 255, **kwargs):
        self.plaintext_max_length = max_length
        # Keep max_length off the model field so migrations don't size the column.
        kwargs.pop("max_length", None)
        super().__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        if self.plaintext_max_length is not None:
            kwargs["max_length"] = self.plaintext_max_length
        return name, path, args, kwargs

    def formfield(self, **kwargs):
        kwargs.setdefault("max_length", self.plaintext_max_length)
        kwargs.setdefault("widget", None)
        return models.CharField(
            max_length=self.plaintext_max_length,
            blank=self.blank,
            null=self.null,
            verbose_name=self.verbose_name,
            help_text=self.help_text,
        ).formfield(**{k: v for k, v in kwargs.items() if v is not None})


class EncryptedEmailField(EncryptedCharField):
    """
    Email address, decrypted only at send time.

    Because it is not queryable, anything that needs to find a user by email —
    login, for one — must use a separate blind index or a plaintext column. Tenant
    admin logins deliberately use a plaintext ``email`` on the user model for that
    reason; this field is for *volunteer* addresses, which are only ever read back
    for display and for addressing mail.
    """

    def __init__(self, *args, max_length: int | None = 254, **kwargs):
        super().__init__(*args, max_length=max_length, **kwargs)

    def formfield(self, **kwargs):
        from django import forms

        defaults = {
            "form_class": forms.EmailField,
            "max_length": self.plaintext_max_length,
            "required": not self.blank,
            "label": self.verbose_name.capitalize() if self.verbose_name else None,
            "help_text": self.help_text,
        }
        defaults.update(kwargs)
        form_class = defaults.pop("form_class")
        return form_class(**{k: v for k, v in defaults.items() if v is not None})


class EncryptedDateField(EncryptedFieldMixin, models.TextField):
    """
    A full date, encrypted.

    Used for a volunteer's complete date of birth. The *coarse* parts needed to
    drive the age rules — birth year and birth month — are stored separately in
    plaintext integer columns so they can be queried; see PRD §5 and the
    ``Volunteer`` model.
    """

    def to_storage_string(self, value) -> str:
        if isinstance(value, datetime.datetime):
            value = value.date()
        if isinstance(value, datetime.date):
            return value.isoformat()
        return str(value)

    def from_storage_string(self, value: str):
        if isinstance(value, datetime.date):
            return value
        try:
            return datetime.date.fromisoformat(value)
        except ValueError as exc:
            raise ValidationError(f"Stored value is not an ISO date: {exc}") from exc

    def formfield(self, **kwargs):
        from django import forms

        defaults = {
            "form_class": forms.DateField,
            "required": not self.blank,
            "help_text": self.help_text,
            "widget": forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        }
        defaults.update(kwargs)
        form_class = defaults.pop("form_class")
        return form_class(**defaults)
