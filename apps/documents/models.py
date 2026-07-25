"""
Clearance documents, in whichever of the three modes the church chose.

Build Spec §5 gives every church one of three postures, set at provisioning:

* ``store`` — we hold the file. The bytes are **encrypted with the church's DEK**
  before they touch the disk, and the file on the media volume is unreadable without
  the key. Serving it decrypts in memory; nothing plaintext is ever written down.
* ``link`` — the church keeps files in its own system; we hold a URL and the dates.
* ``track`` — paper in a locked cabinet; we hold only the fact and the dates.

One model covers all three, because a church can change mode and the records that
already exist must stay readable. Which fields are populated is what differs.
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
import uuid

from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from django.utils import timezone

from apps.core.fields import EncryptedCharField, EncryptedTextField
from apps.core.models import NoDeleteModel, TimeStampedModel
from apps.org.models import Volunteer
from apps.requirements.models import CRCRecord, RequirementInstance

#: What an admin may upload (Build Spec §5). Deliberately narrow: these are
#: clearance letters and scans, and every additional type is another parser to
#: worry about.
ALLOWED_CONTENT_TYPES = {
    "application/pdf": ".pdf",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/heic": ".heic",
    "image/tiff": ".tif",
}

ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".heic", ".tif", ".tiff"}

#: Magic bytes, checked against the declared content type. A browser-supplied
#: Content-Type is a hint, not a fact.
MAGIC_SIGNATURES = {
    b"%PDF-": "application/pdf",
    b"\xff\xd8\xff": "image/jpeg",
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"II*\x00": "image/tiff",
    b"MM\x00*": "image/tiff",
}


class DocumentKind(models.TextChoices):
    """What the document is evidence of."""

    CRC = "crc", "Criminal record check clearance"
    APPLICATION = "application", "Application form"
    REFERENCE = "reference", "Reference check"
    AGREEMENT = "agreement", "Signed agreement"
    TRAINING = "training", "Training certificate"
    INTERVIEW = "interview", "Interview record"
    APPROVAL = "approval", "Leadership approval"
    OTHER = "other", "Other"


def encrypted_upload_path(instance: "Document", filename: str) -> str:
    """
    Where the sealed bytes live on the media volume.

    The stored name is a random UUID with a ``.enc`` suffix — the original filename
    is itself potentially identifying ("john-smith-crc.pdf"), so it is kept in an
    encrypted column instead of on the filesystem. Files are foldered by year to keep
    directory sizes sane over a decade of use.
    """
    return f"documents/{timezone.now():%Y}/{uuid.uuid4().hex}.enc"


class Document(TimeStampedModel, NoDeleteModel):
    """
    A document, a link to one, or the record that one exists on paper.

    Permanent, like everything else attached to a volunteer file. Superseding a
    document (a renewed clearance letter) links the new one to the old rather than
    replacing it.
    """

    volunteer = models.ForeignKey(Volunteer, on_delete=models.PROTECT, related_name="documents")
    requirement_instance = models.ForeignKey(
        RequirementInstance,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="documents",
    )
    crc_record = models.ForeignKey(
        CRCRecord,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="documents",
    )

    kind = models.CharField(max_length=16, choices=DocumentKind.choices, default=DocumentKind.OTHER)
    #: The mode in force when this record was made. Kept per-document so a church
    #: switching modes does not make its existing records inconsistent.
    mode = models.CharField(max_length=8, db_index=True)

    title = models.CharField(
        max_length=200,
        help_text="A short label, e.g. 'CRC clearance letter 2026'. Avoid personal details.",
    )
    document_date = models.DateField(
        null=True, blank=True, help_text="The date on the document itself."
    )

    # --- store mode -------------------------------------------------------
    #: Sealed bytes. The file at this path is AES-256-GCM ciphertext; opening it
    #: outside the app yields noise.
    encrypted_file = models.FileField(
        upload_to=encrypted_upload_path, blank=True, null=True, max_length=255
    )
    original_filename = EncryptedCharField(
        max_length=255, blank=True, default="", help_text="Encrypted."
    )
    content_type = models.CharField(max_length=100, blank=True)
    byte_size = models.PositiveIntegerField(null=True, blank=True)
    #: SHA-256 of the *plaintext*, for integrity checks and duplicate detection.
    #: A hash is not reversible, and the file contents are not low-entropy, so this
    #: is safe to keep in the clear.
    plaintext_sha256 = models.CharField(max_length=64, blank=True, db_index=True)

    # --- link mode --------------------------------------------------------
    external_url = models.URLField(
        max_length=500,
        blank=True,
        help_text="Where this document lives in the church's own document store.",
    )

    # --- track mode -------------------------------------------------------
    physical_location = models.CharField(
        max_length=200,
        blank=True,
        help_text="Where the hard copy is filed, e.g. 'Office cabinet 2, folder B'.",
    )

    notes = EncryptedTextField(blank=True, default="", help_text="Encrypted.")

    superseded_by = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="supersedes"
    )
    is_current = models.BooleanField(default=True, db_index=True)

    uploaded_by = models.CharField(max_length=150, blank=True)

    class Meta:
        ordering = ("-document_date", "-created_at")
        indexes = [
            models.Index(fields=["volunteer", "kind"]),
            models.Index(fields=["kind", "is_current"]),
        ]

    def __str__(self):
        return f"{self.title} ({self.volunteer.display_name})"

    def get_absolute_url(self):
        return reverse("documents:detail", args=[self.pk])

    def clean(self):
        super().clean()
        from apps.tenants.models import DocumentMode

        errors = {}
        if self.mode == DocumentMode.LINK and not self.external_url:
            errors["external_url"] = "A link is required in link-tracking mode."
        if self.mode == DocumentMode.STORE and not self.encrypted_file:
            errors["encrypted_file"] = "Attach the file, or switch this church to link/track mode."
        if errors:
            raise ValidationError(errors)

    @property
    def has_file(self) -> bool:
        return bool(self.encrypted_file)

    @property
    def display_filename(self) -> str:
        """
        A safe filename for the download response.

        Falls back to a generated name so a download never leaks a filename that was
        never captured, and never emits an empty ``filename=""``.
        """
        name = (self.original_filename or "").strip()
        if name:
            return os.path.basename(name)[:120]
        extension = ALLOWED_CONTENT_TYPES.get(self.content_type) or (
            mimetypes.guess_extension(self.content_type or "") or ".bin"
        )
        return f"document-{self.pk}{extension}"

    def supersede_with(self, replacement: "Document") -> None:
        """Mark this document as replaced, keeping both."""
        self.superseded_by = replacement
        self.is_current = False
        self.save(update_fields=["superseded_by", "is_current", "updated_at"])


def sniff_content_type(head: bytes) -> str | None:
    """Identify a file from its leading bytes, ignoring what the browser claimed."""
    for signature, content_type in MAGIC_SIGNATURES.items():
        if head.startswith(signature):
            return content_type
    # HEIC/HEIF carry their brand at offset 4 inside the ftyp box.
    if len(head) >= 12 and head[4:8] == b"ftyp" and head[8:12] in (b"heic", b"heix", b"mif1"):
        return "image/heic"
    return None


def plaintext_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
